# =====================================================================
# PACKET FORMATS  (all multi-byte fields big-endian, struct ">")
# =====================================================================
#
# ---- FULL PACKET ON AIR ----
#
# | version | key_id | sender_id | run_id | tx_counter |   ciphertext   |
# |   1 B   |  1 B   |    1 B    |  2 B   |    4 B     |    variable    |
# |<------- outer header, 9 B, cleartext, ">BBBHI" --->|<- encrypted -->|
#
# ---- CIPHERTEXT ----
#
# ciphertext = AES-CTR( | inner packet | CRC-32 (4 B) | )
# CRC-32 computed over: | outer header | inner packet |
#
# ---- IV (16 B) ----
#
# | run_id | sender_id | tx_counter | block counter |
# |  2 B   |    1 B    |    4 B     |  9 B (zeros)  |
#
# ---- INNER: ADVERTISEMENT (ptype 0), 5 B ----
#
# | ptype=0 | dest=255 | src_id | hop | parent_id |
# |   1 B   |   1 B    |  1 B   | 1 B |    1 B    |
#
# on air: 9 + 5 + 4 = 18 B
#
# ---- INNER: DATA (ptype 2), 7 B header + payload ----
#
# | ptype=2 | dest_id | origin_id | seq | ttl | sensor_code | payload  |
# |   1 B   |   1 B   |    1 B    | 2 B | 1 B |     1 B     | variable |
#
# ---- PAYLOADS ----
#
# code 1 DHT11 | temp C (f32) | humidity % (f32) |   8 B -> on air 28 B
# code 2 DS18  | temp C (f32) |                     4 B -> on air 24 B
# code 3 GPS   | lon (f32) | lat (f32) |           8 B -> on air 28 B
# code 4 Smoke | 0/1 (u8) |                        1 B -> on air 21 B
# code 5 Accel | magnitude m/s^2 (f32) |           4 B -> on air 24 B
#
# codes 0 and 6..255 = invalid, reject
# =====================================================================

import _thread
import time
import network, espnow, struct
import random
from cryptolib import aes            # use "from ucryptolib import aes" on older builds
from binascii import crc32


# =====================================================================
# CONFIGURATION
# =====================================================================

# Device Identification
DEVICE_ID = 7
IS_ROOT = False

# Radio
CHANNEL = 1                          # all devices speak on same channel

# Run
RUN_ID = 1                           # Part of outer packet, specifies the run. Change by hand every run, same on all boards

# Neighbor table
RSSI_SMOOTHING = 0.3                 # srssi = (0.3 * new reading) + (0.7 * old average)
NEIGHBOR_TIMEOUT_MS = 15000         # 3 x advertisement interval (5 s), no advert for that long -> neighbor is dead
EXPIRY_CHECK_MS = 1000              # how often rx thread looks for dead neighbors
RSS_THRESHOLD = -85                  # dBm, smoothed RSSI below this -> link too weak, not a parent candidate (tune in lab)
SWITCH_MARGIN_DB = 5                 # hysteresis: switch to same-hop candidate only if srssi >= current + 5 dB
PRINT_TABLE_MS = 5000                # how often rx thread prints the neighbor table (demo)

# Duplicate cache
DUP_EXPIRY_MS = 60000               # > max packet lifetime (TTL 10 hops x ~1 s), with margin
DUP_MAX = 200                        # bound: ~10 sources x 1 pkt/10 s x 60 s, with headroom

# Forwarding queue
QUEUE_MAX = 20                       # bound for tx_queue, overflow is counted as queue_drops

KEY_ID = 1 # what key we use in tx_thread

# AES tx counter persistence
CTR_FILE = "ctr.txt"                 # file on the board's flash, holds highest reserved tx_counter
CTR_STEP = 256                       # save to flash once per 256 packets, not every packet
CTR_MAX = 0xFFFFFFFF                 # tx_counter field is 4 bytes, never wrap around (spec)
# =====================================================================
# ADVERTISEMENTS STAFF
# =====================================================================

ADV_INTERVAL_MS = 5000
ADV_JITTER_MS = 500

# =====================================================================
# SEND OWN DATA STAFF
# =====================================================================

INITIAL_TTL = 10                     # spec suggested value
SENSOR_QUEUE_MAX = 5                 # finished readings waiting for tx_thread

# sensor_queue: finished readings from teammates' sensor code
#   item = (sensor_code, payload_bytes), payload packed as in the PAYLOADS table
sensor_queue = []

# =====================================================================
# PROTOCOL CONSTANTS
# =====================================================================

# Packet Types
PTYPE_ADV = 0
PTYPE_DATA = 2

# Special IDs
BCAST_ID = 255                       # broadcast destination / no parent / no route
BCAST = b'\xff' * 6                  # Broadcast MAC address

# Outer packet stuff
VERSION = 1                          # Protocol version, will always be 1
OUTER_HDR_FRMT = ">BBBHI"            # outer header format: version | key_id | sender_id | run_id | tx_counter
OUTER_HDR_LEN = struct.calcsize(OUTER_HDR_FRMT)   # 9 bytes
CRC_LEN = 4
MIN_CT_LEN = 5 + CRC_LEN             # smallest ciphertext: advert (5) + crc (4)

# Data packet stuff
DATA_HDR_LEN = 7                     # ptype | dest | origin | seq(2) | ttl | sensor_code
PAYLOAD_LEN = {1: 8, 2: 4, 3: 8, 4: 1, 5: 4}      # Sensor types and their payload lengths
UNITS = {1: ("C", "%"), 2: ("C",), 3: ("deg lon", "deg lat"), 4: ("smoke",), 5: ("m/s^2",)}

# Keys
# TODO: move to separate local file later, use random keys, never print them
keychain = {
    1: bytes.fromhex("11" * 16),
    2: bytes.fromhex("22" * 16),
    3: bytes.fromhex("33" * 16),
}


# =====================================================================
# SHARED STATE (guarded by lock)
# =====================================================================

lock = _thread.allocate_lock()       # guards every shared variable between threads

e = None                             # ESP-NOW object, created once in setup(), shared by threads

# routing state
# neighbors: neighbor table, updated from every valid advert (Task 1)
#   key   = neighbor ID (int, = advert src_id)
#   value = {
#       "hop":       advertised hop count to root (0 = root, 255 = no route)
#       "parent":    neighbor's own parent ID (255 = none)
#       "rssi":      last raw RSSI in dBm (for logs/demo)
#       "srssi":     smoothed RSSI, EMA with RSSI_SMOOTHING (used for parent choice)
#       "last_seen": time.ticks_ms() of last advert (for expiry, use ticks_diff)
#   }
#   example: {3: {"hop": 1, "parent": 0, "rssi": -68, "srssi": -70.2, "last_seen": 123456}}
neighbors = {}
parent_id = BCAST_ID                 # 255 means no parent
my_hop = 0 if IS_ROOT else BCAST_ID  # My Metric (hop count to the root), 255 = no route

# data handling
# dup_cache: data packets already handled (Task 3), stops repeat forwarding/delivery
#   key   = (origin_id, seq)  -> unique sample ID, never changes along the path
#   value = time.ticks_ms() when first accepted (for expiry)
#   - lookup before payload validation, insert ONLY after validation passes
#   - reset together with logs between runs
#   example: {(4, 17): 123456, (9, 3): 123890}
dup_cache = {}                       # This and TTL will stop the loops

# tx_queue: relayed data waiting for tx_thread
#   item = bytearray copy of inner packet, ttl already decremented,
#          dest is filled in by tx_thread at send time (current parent)
tx_queue = []

# counters
seq = 0                              # seq num of the data packet created by this device

# tx_counter: AES encryption counter for THIS board (goes into outer header + IV)
#   - +1 for EVERY packet this board encrypts: adverts, own data, relayed data
#   - never reuse a value with the same key, even after reboot
#     (same IV -> same keystream -> encryption broken)
#   - persisted in flash (ctr.txt): setup() loads it and reserves +256 ahead,
#     next_tx_counter() saves the new limit each time that block is used up
#   - loaded in setup() BEFORE any thread sends
#   - delete ctr.txt ONLY when installing a new key
#   - not the same as seq (seq = own sensor samples, never changes when relayed)
#   - RUN_ID is NOT stored: set it by hand per run, same on all boards
tx_counter = 0
ctr_limit = 0                        # highest tx_counter already reserved in flash
ctr_lock = _thread.allocate_lock()   # own small lock for the counter: flash write is slow, don't block main lock

stats = {                            # for logs
    "adv_sent": 0, "data_originated": 0, "data_relayed": 0,
    "queue_drops": 0, "no_route_drops": 0, "integrity_fail": 0,
    "bad_packet": 0, "acq_fail": 0, "delivered": 0,
    "duplicate": 0, "ttl_drop": 0, "neighbor_expired": 0,
    "no_rssi": 0,
}


# =====================================================================
# AES TX COUNTER (persistent)
# =====================================================================

def load_counter():                  # Last reserved tx_counter from flash, 0 if no file yet
    try:
        with open(CTR_FILE) as f:
            return int(f.read())     # empty/corrupt file -> ValueError -> board stops (safer than reusing IVs)
    except OSError:                  # no file: this key was never used on this board
        return 0

def save_counter(value):             # Writes reserved limit to flash
    with open(CTR_FILE, "w") as f:
        f.write(str(value))

def next_tx_counter():               # Called by tx_thread before EVERY encryption, None = exhausted
    global tx_counter, ctr_limit
    with ctr_lock:
        if tx_counter >= CTR_MAX:
            return None              # used up -> don't send, install new key
        if tx_counter >= ctr_limit:  # reserved block used up
            ctr_limit += CTR_STEP
            save_counter(ctr_limit)  # flash write, once per 256 packets
        tx_counter += 1              # RAM only, every packet
        return tx_counter


# =====================================================================
# SETUP
# =====================================================================

def init_espnow():                   # Creates connection object
    sta = network.WLAN(network.STA_IF)
    sta.active(True)
    sta.config(channel=CHANNEL)
    esp = espnow.ESPNow()
    esp.active(True)
    esp.add_peer(BCAST)              # only peer we ever register
    return esp

def setup():                         # Runs once at boot, BEFORE any thread starts
    global e, tx_counter, ctr_limit
    e = init_espnow()                # both threads use this same object

    # AES counter: continue where we left off, reserve first block right away
    tx_counter = load_counter()
    ctr_limit = tx_counter + CTR_STEP
    save_counter(ctr_limit)


# =====================================================================
# HELPERS
# =====================================================================

def count_stat(name):                # Used to safely increment some statistics
    with lock:
        stats[name] += 1

def print_neighbors():
    now = time.ticks_ms()

    # copy fast under lock
    snapshot = []
    with lock:
        for nid in neighbors:
            nb = neighbors[nid]
            snapshot.append((nid, nb["hop"], nb["parent"], nb["rssi"], nb["srssi"], nb["last_seen"]))
        par = parent_id
        hop = my_hop

    # print slowly outside lock
    print(f"--- neighbors | me={DEVICE_ID} parent={par} hop={hop} ---")
    snapshot.sort()                  # sort by neighbor id
    for entry in snapshot:
        nid, nb_hop, nb_parent, rssi, srssi, last_seen = entry
        age = time.ticks_diff(now, last_seen)
        print(f"id={nid:3d} hop={nb_hop:3d} parent={nb_parent:3d} rssi={rssi:4d} srssi={srssi:6.1f} age={age:5d}ms")


# =====================================================================
# OUTER PACKET / CRYPTO
# =====================================================================

def strip_outer_header(full_msg):    # Does what name says, None if packet is bad
    if full_msg is None or len(full_msg) < OUTER_HDR_LEN + MIN_CT_LEN:
        return None
    header = full_msg[:OUTER_HDR_LEN]
    ciphertext = full_msg[OUTER_HDR_LEN:]
    version, key_id, sender_id, run_id, tx_ctr = struct.unpack(OUTER_HDR_FRMT, header)
    if version != VERSION or key_id not in keychain or run_id != RUN_ID or sender_id == DEVICE_ID or sender_id == BCAST_ID:
        return None
    return key_id, sender_id, run_id, tx_ctr, ciphertext, header

def get_initial_counter_value(run_id, sender_id, tx_ctr):   # Obtains IV (init vector) for AES from given components
    return struct.pack(">HBI", run_id, sender_id, tx_ctr) + b"\x00" * 9

def decrypt_ct(ciphertext, key_id, iv):   # Returns decrypted inner packet + crc
    key = keychain[key_id]
    cipher = aes(key, 6, iv)         # AES object for given key and iv, 6 = CTR mode, single use
    return cipher.decrypt(ciphertext)

def check_crc(crc_bytes_material, rcv_crc):   # takes rcv crc, calculates crc from raw bytes and compares them
    rcv_crc = struct.unpack(">I", rcv_crc)[0]
    return rcv_crc == (crc32(crc_bytes_material) & 0xFFFFFFFF)


# =====================================================================
# NEIGHBOR TABLE
# =====================================================================

def usable(nb, now):                 # can this neighbor be my parent?
    if (time.ticks_diff(now, nb["last_seen"]) > NEIGHBOR_TIMEOUT_MS   # stale
            or nb["hop"] >= BCAST_ID - 1                              # no route, or hop+1 hits 255
            or nb["parent"] == DEVICE_ID                              # routes through me
            or nb["srssi"] < RSS_THRESHOLD):                          # too weak
        return False
    return True

def select_parent(reason):
    global parent_id, my_hop
    if IS_ROOT:
        return
    now = time.ticks_ms()
    with lock:
        old_parent = parent_id
        old_hop = my_hop

        # best usable neighbor: lowest hop, then strongest srssi, then lowest id
        best = None
        best_key = None
        parent_ok = False
        for nid in neighbors:
            nb = neighbors[nid]
            if not usable(nb, now):
                continue
            if nid == parent_id:
                parent_ok = True
            key = (nb["hop"], -nb["srssi"], nid)   # smaller tuple = better
            if best is None or key < best_key:
                best = nid
                best_key = key
        # decide
        if best is None:
            parent_id = BCAST_ID
        elif not parent_ok:
            parent_id = best
        else:
            b = neighbors[best]
            p = neighbors[parent_id]
            if b["hop"] < p["hop"]:
                parent_id = best     # shorter path
            elif b["hop"] == p["hop"] and b["srssi"] >= p["srssi"] + SWITCH_MARGIN_DB:
                parent_id = best     # same hop, clearly stronger
            # else keep current parent

        if parent_id == BCAST_ID:
            my_hop = BCAST_ID
            par_srssi = 0
        else:
            my_hop = neighbors[parent_id]["hop"] + 1
            par_srssi = neighbors[parent_id]["srssi"]     # for the log, spec wants RSS too

    if parent_id != old_parent or my_hop != old_hop:   # log outside lock
        print(f"PARENT CHANGE t={time.ticks_ms()} {old_parent} -> {parent_id}, hop {old_hop} -> {my_hop}, srssi {par_srssi:.1f}, reason: {reason}")



def update_neighbor(src_id, adv_hop, adv_parent, rssi):
    """Insert or overwrite the neighbor entry from a valid advertisement."""
    now = time.ticks_ms()            # Last Adv time from neighbor, used for aging
    with lock:
        nb = neighbors.get(src_id)
        if nb is None:
            srssi = rssi             # first reading starts the average
        else:
            srssi = RSSI_SMOOTHING * rssi + (1 - RSSI_SMOOTHING) * nb["srssi"]
        # always overwrite: the table holds the neighbor's CURRENT state,
        # even when the new hop is worse than the old one
        neighbors[src_id] = {
            "hop": adv_hop,
            "parent": adv_parent,
            "rssi": rssi,            # for logs, decisions are based on srssi
            "srssi": srssi,
            "last_seen": now,
        }

def expire_neighbors():
    """Remove neighbors with no advert for NEIGHBOR_TIMEOUT_MS. Returns list of removed IDs."""
    now = time.ticks_ms()
    expired = []
    with lock:
        for nid in list(neighbors):  # list(): can't delete while iterating
            if time.ticks_diff(now, neighbors[nid]["last_seen"]) > NEIGHBOR_TIMEOUT_MS:
                del neighbors[nid]
                expired.append(nid)
                stats["neighbor_expired"] += 1   # already holding lock, so no count_stat()
    for nid in expired:              # print outside the lock, printing is slow
        print(f"NEIGHBOR EXPIRED t={now} id={nid}")
    return expired


# =====================================================================
# DUPLICATE CACHE
# =====================================================================

def is_duplicate(cache_key):         # Read only lookup, an expired entry counts as not seen
    now = time.ticks_ms()
    with lock:
        return (cache_key in dup_cache and
                time.ticks_diff(now, dup_cache[cache_key]) <= DUP_EXPIRY_MS)

def purge_dup_cache():               # Removes expired entries and keeps cache below DUP_MAX
    now = time.ticks_ms()
    with lock:
        for key in list(dup_cache):  # list(): can't delete while iterating
            if time.ticks_diff(now, dup_cache[key]) > DUP_EXPIRY_MS:
                del dup_cache[key]
        while len(dup_cache) >= DUP_MAX:   # still full -> drop oldest
            oldest = min(dup_cache, key=dup_cache.get)
            del dup_cache[oldest]

def remember_packet(cache_key):      # Insert, ONLY after packet passed validation
    purge_dup_cache()
    with lock:
        dup_cache[cache_key] = time.ticks_ms()


# =====================================================================
# PAYLOAD VALIDATION
# =====================================================================

def finite(x):                       # False for NaN and +/-inf
    return x == x and abs(x) != float("inf")   # NaN != NaN

def decode_payload(code, payload):
    """Check sensor code, exact length and value ranges.
    Returns tuple of decoded values, or None if anything is invalid."""
    if code not in PAYLOAD_LEN or len(payload) != PAYLOAD_LEN[code]:
        return None                  # unknown code or wrong length
    if code == 1:                    # DHT11: temp C, humidity %
        t, h = struct.unpack(">ff", payload)
        if finite(t) and finite(h) and 0 <= h <= 100:
            return (t, h)
    elif code == 2:                  # DS18: temp C
        (t,) = struct.unpack(">f", payload)
        if finite(t):
            return (t,)
    elif code == 3:                  # GPS: lon, lat
        lon, lat = struct.unpack(">ff", payload)
        if finite(lon) and finite(lat) and -180 <= lon <= 180 and -90 <= lat <= 90:
            return (lon, lat)
    elif code == 4:                  # smoke: 0/1
        if payload[0] in (0, 1):
            return (payload[0],)
    elif code == 5:                  # accel magnitude m/s^2
        (a,) = struct.unpack(">f", payload)
        if finite(a) and a >= 0:
            return (a,)
    return None                      # value out of range


# =====================================================================
# RECEIVE SIDE
# =====================================================================

def handle_advert(inner_pkt, sender_id, rssi):
    # inner advert: ptype(1) | dest_id(1) | src_id(1) | hop(1) | parent_id(1)
    # exact length first, so indexing below can't raise IndexError
    if len(inner_pkt) != 5:
        count_stat("bad_packet")
        return
    rcv_dest_id = inner_pkt[1]       # always 255 (broadcast) for adverts
    rcv_src_id = inner_pkt[2]        # the advertiser = key of the neighbor table
    rcv_hop = inner_pkt[3]           # advertiser's distance to root (255 = no route)
    rcv_parent = inner_pkt[4]        # advertiser's own parent (255 = none)

    # malformed: wrong destination, claims to be me, or inner src
    # doesn't match the outer sender (spec's consistency check)
    if rcv_dest_id != BCAST_ID or rcv_src_id == DEVICE_ID or rcv_src_id != sender_id:
        count_stat("bad_packet")
        return

    # no RSSI means we can't use this link, skip it (packet itself is fine, so not bad_packet)
    if rssi is None:
        count_stat("no_rssi")
        return

    # Process ALL valid adverts, even weak ones or from our children:
    # the RSS threshold and "parent == me" checks belong in select_parent().
    update_neighbor(rcv_src_id, rcv_hop, rcv_parent, rssi)
    select_parent(f"advert from {rcv_src_id}")

def handle_data(inner_pkt):
    # inner data: ptype(1) | dest_id(1) | origin_id(1) | seq(2) | ttl(1) | sensor_code(1) | payload
    if len(inner_pkt) < DATA_HDR_LEN:
        count_stat("bad_packet")
        return
    rcv_dest_id     = inner_pkt[1]
    rcv_origin_id   = inner_pkt[2]
    rcv_seq_num     = (inner_pkt[3] << 8) | inner_pkt[4]   # 2 bytes, big-endian
    rcv_ttl         = inner_pkt[5]
    rcv_sensor_code = inner_pkt[6]
    rcv_payload     = inner_pkt[DATA_HDR_LEN:]

    # DV filter: addressed to another board -> ignore silently
    # (not a bad packet, don't count, don't cache)
    if rcv_dest_id != DEVICE_ID:
        return

    # duplicate lookup before validation, no point validating a copy we already handled
    cache_key = (rcv_origin_id, rcv_seq_num)
    if is_duplicate(cache_key):
        count_stat("duplicate")
        return

    # sensor code + exact length + value ranges
    values = decode_payload(rcv_sensor_code, rcv_payload)
    if values is None:
        count_stat("bad_packet")
        return

    # relay with no transmissions left must discard, root may still accept it
    # checked BEFORE caching, so this dead copy doesn't block a later good one
    if not IS_ROOT and rcv_ttl == 0:
        count_stat("ttl_drop")
        return

    # valid -> remember it
    remember_packet(cache_key)

    if IS_ROOT:
        # root: log it, don't forward
        # line: DELIVERED,time_ms,origin,seq,sensor_code,value unit[,value unit]
        count_stat("delivered")
        now = time.ticks_ms()
        units = UNITS[rcv_sensor_code]
        line = f"DELIVERED,{now},{rcv_origin_id},{rcv_seq_num},{rcv_sensor_code}"
        for i in range(len(values)):         # each value with its unit
            line += f",{values[i]:.3f} {units[i]}"
        print(line)
    else:
        # relay: push to queue, tx_thread fills dest + encrypts + sends
        fwd = bytearray(inner_pkt)   # mutable copy: ptype|dest|origin|seq|ttl|code|payload
        fwd[5] = rcv_ttl - 1         # TTL for the next transmission
        with lock:
            queued = len(tx_queue) < QUEUE_MAX
            if queued:
                tx_queue.append(fwd)
        if not queued:
            count_stat("queue_drops")   # spec: bound the queue, count overflow

def rx_thread():                     # Main/receive thread: receive, parse, update neighbors, expire, queue data
    last_expiry_check = time.ticks_ms()
    last_table_print = time.ticks_ms()
    while True:
        mac_addr, full_msg = e.recv(100)

        # periodic jobs, run also on timeouts so they work even when it's quiet
        now = time.ticks_ms()
        if time.ticks_diff(now, last_table_print) >= PRINT_TABLE_MS:     # neighbor table for demo
            last_table_print = now
            print_neighbors()
        if time.ticks_diff(now, last_expiry_check) >= EXPIRY_CHECK_MS:   # remove dead neighbors
            last_expiry_check = now
            expired = expire_neighbors()
            if parent_id in expired:
                select_parent("parent expired")

        if full_msg is None:         # timeout, nothing received
            continue

        # RSSI lookup right away, the next packet from this sender overwrites it.
        # MAC is used ONLY for this lookup, never as routing state
        try:
            rssi = e.peers_table[mac_addr][0]
        except KeyError:
            rssi = None              # firmware has no entry for this sender

        # outer header
        full_msg = bytes(full_msg)
        outer = strip_outer_header(full_msg)
        if outer is None:
            count_stat("bad_packet")
            continue
        key_id, sender_id, run_id, rx_ctr, ciphertext, outer_header = outer   # ciphertext = inner + crc (encrypted)

        # decrypt + integrity check
        iv = get_initial_counter_value(run_id, sender_id, rx_ctr)
        decrypted_inner_msg = decrypt_ct(ciphertext, key_id, iv)
        rcv_crc = decrypted_inner_msg[-CRC_LEN:]
        inner_pkt = decrypted_inner_msg[:-CRC_LEN]
        if not check_crc(outer_header + inner_pkt, rcv_crc):
            count_stat("integrity_fail")
            continue

        # dispatch by packet type
        rcv_ptype = inner_pkt[0]
        if rcv_ptype == PTYPE_ADV:
            handle_advert(inner_pkt, sender_id, rssi)
        elif rcv_ptype == PTYPE_DATA:
            handle_data(inner_pkt)
        else:
            count_stat("bad_packet") # unknown ptype


# =====================================================================
# SEND SIDE (later)
# =====================================================================
def send_adv():
    with lock:
        this_parent_id = parent_id
        this_hop = my_hop
    inner = bytes([PTYPE_ADV, BCAST_ID, DEVICE_ID, this_hop, this_parent_id])
    ctr = next_tx_counter()
    if ctr is None: return
    header = struct.pack(OUTER_HDR_FRMT, VERSION, KEY_ID, DEVICE_ID, RUN_ID, ctr)
    crc = struct.pack(">I", crc32(header+inner) & 0xFFFFFFFF)
    iv = get_initial_counter_value(RUN_ID, DEVICE_ID, ctr)
    ciphertext = aes(keychain[KEY_ID], 6, iv).encrypt(inner + crc)
    packet = header + ciphertext   
    count_stat("adv_sent")
    try:
        e.send(BCAST, packet, False)
    except OSError as err:
        print("ADVERTISEMENT FAILED", err)    

def relay_msg():
    with lock:
        if not tx_queue:
            return
        forward = tx_queue.pop(0)
        parent = parent_id
    if parent == BCAST_ID:
        count_stat("no_route_drops")
        print(f"NO ROUTE t={time.ticks_ms()} dropped relay origin={forward[2]} seq={(forward[3] << 8) | forward[4]}")
        return
    forward[1] = parent
    ctr = next_tx_counter()
    if ctr is None:
        return
    header = struct.pack(OUTER_HDR_FRMT, VERSION, KEY_ID, DEVICE_ID, RUN_ID, ctr)
    new_crc = struct.pack(">I", crc32(header + forward) & 0xFFFFFFFF) 
    iv = get_initial_counter_value(RUN_ID, DEVICE_ID, ctr)
    ciphertext = aes(keychain[KEY_ID], 6, iv).encrypt(forward + new_crc)
    packet = header + ciphertext
    count_stat("data_relayed")
    try:
        e.send(BCAST, packet, False)
    except OSError as err:
        print("RELAYING FAILED", err)    

def put_reading(code, payload): # USE THIS TO SAVE READINGS FROM THE SENSOR    
    if decode_payload(code, payload) is None:
        count_stat("acq_fail")
        print(f"ACQ FAIL code={code}")
        return
    with lock:
        queued = len(sensor_queue) < SENSOR_QUEUE_MAX
        if queued:
            sensor_queue.append((code, payload))
    if not queued:
        count_stat("queue_drops")

def send_data():
    global seq
    with lock:
        if not sensor_queue:
            return
        code, payload = sensor_queue.pop(0)
        seq += 1 
        my_seq = seq
        parent = parent_id
    print(f"GENERATED,{time.ticks_ms()},{DEVICE_ID},{my_seq},{code}")  # source log for PDR
    remember_packet((DEVICE_ID, my_seq)) # mark own packet as seen
    if parent == BCAST_ID: # spec: count + log, no buffering
        count_stat("no_route_drops")
        print(f"NO ROUTE t={time.ticks_ms()} dropped own origin={DEVICE_ID} seq={my_seq}")
        return
    inner = struct.pack(">BBBHBB", PTYPE_DATA, parent, DEVICE_ID, my_seq, INITIAL_TTL - 1, code) + payload
    ctr = next_tx_counter()
    if ctr is None: return
    header = struct.pack(OUTER_HDR_FRMT, VERSION, KEY_ID, DEVICE_ID, RUN_ID, ctr)
    new_crc = struct.pack(">I", crc32(header + inner) & 0xFFFFFFFF) 
    iv = get_initial_counter_value(RUN_ID, DEVICE_ID, ctr)
    ciphertext = aes(keychain[KEY_ID], 6, iv).encrypt(inner + new_crc)
    packet = header + ciphertext
    count_stat("data_originated")
    try:
        e.send(BCAST, packet, False)
    except OSError as err:
        print("DATA SEND FAILED", err)   

def tx_thread():                     # Send thread: adverts, own data, forwarding queue
    next_adv = time.ticks_ms()
    while True:
        now = time.ticks_ms()
        if time.ticks_diff(now, next_adv) >= 0:
            send_adv()
            next_adv = time.ticks_add(now, ADV_INTERVAL_MS + random.randint(0, ADV_JITTER_MS))
        # to add, send own data
        # to add, relay message
        if not IS_ROOT:
            send_data()
            if len(tx_queue) > 0:
                relay_msg()
        time.sleep_ms(20)

    # TODO: if parent_id == 255 when sending data (own or from tx_queue) -> drop it,
    #       count_stat("no_route_drops") and print it. Spec: count + log, no retries, no buffering
    return

def sensor_thread():                 # Sensor reading, so slow sensors don't block sending
    return


# =====================================================================
# START
# =====================================================================

def main():
    setup()                          # radio first, threads need it
    # _thread.start_new_thread(tx_thread, ())   # send thread, later
    _thread.start_new_thread(tx_thread, ())  
    rx_thread()                      # main thread = receive loop


# program is not started yet (prototype stage)
main()

# Still open on the network side (small):

# Print stats every ~30 s; overhead and drop counts come from it.
# Add time.ticks_ms() to PARENT CHANGE, NEIGHBOR EXPIRED and NO ROUTE, for convergence and recovery times.
# Keys: a separate local file with one random key, and a placeholder for submission.
# Config: MODE and DATA_INTERVAL_MS