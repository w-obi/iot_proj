# =====================================================================
# Project: Distance Vector Routing with ESP32 and MicroPython
# =====================================================================

import _thread
import time
import network, espnow, struct
import random
import math
from cryptolib import aes            # use "from ucryptolib import aes" on older builds
from binascii import crc32

# =====================================================================
# CONFIGURATION
# =====================================================================

# Protocol Mode: "DV" or "FLOODING" (Task 5)
ROUTING_MODE = "DV"

# Device Identification
DEVICE_ID = 7
IS_ROOT = False

# Radio
CHANNEL = 1                          

# Run & Security
RUN_ID = 1                           
KEY_ID = 1                           

# Import external keys to satisfy V-A (Do not hardcode keys in main script)
try:
    import keys
    keychain = keys.keychain
except ImportError:
    print("WARNING: keys.py not found. Using fallback placeholder key.")
    keychain = {1: bytes.fromhex("11" * 16)}

# Timing & Intervals
ADV_INTERVAL_MS = 5000               # 5 seconds
ADV_JITTER_MS = 500
DATA_INTERVAL_MS = 10000             # 10 seconds (Task 3)
DATA_JITTER_MS = 1000
STATS_INTERVAL_MS = 30000            # Print logs every 30 seconds

# Enabled Sensors list (1: DHT11, 2: DS18, 3: GPS, 4: Smoke, 5: Accel)
ENABLED_SENSORS = [1, 5]             

# Neighbor table & Parent Selection (Task 1 & 2)
RSSI_SMOOTHING = 0.3                 
NEIGHBOR_TIMEOUT_MS = 15000         
EXPIRY_CHECK_MS = 1000              
RSS_THRESHOLD = -85                  
SWITCH_MARGIN_DB = 5                 
PRINT_TABLE_MS = 5000                

# Duplicate cache & Queues
DUP_EXPIRY_MS = 60000               
DUP_MAX = 200                        
QUEUE_MAX = 20                       
INITIAL_TTL = 10                     
SENSOR_QUEUE_MAX = 5                 

# AES tx counter persistence
CTR_FILE = "ctr.txt"                 
CTR_STEP = 256                       
CTR_MAX = 0xFFFFFFFF                 

# =====================================================================
# PROTOCOL CONSTANTS
# =====================================================================

PTYPE_ADV = 0
PTYPE_DATA = 2
BCAST_ID = 255                       
BCAST = b'\xff' * 6                  

VERSION = 1                          
OUTER_HDR_FRMT = ">BBBHI"            
OUTER_HDR_LEN = struct.calcsize(OUTER_HDR_FRMT)   
CRC_LEN = 4
MIN_CT_LEN = 5 + CRC_LEN             

DATA_HDR_LEN = 7                     
PAYLOAD_LEN = {1: 8, 2: 4, 3: 8, 4: 1, 5: 4}      
UNITS = {1: ("C", "%"), 2: ("C",), 3: ("deg lon", "deg lat"), 4: ("smoke",), 5: ("m/s^2",)}

# =====================================================================
# SHARED STATE & THREADING
# =====================================================================

lock = _thread.allocate_lock()       
e = None                             

neighbors = {}
parent_id = BCAST_ID                 
my_hop = 0 if IS_ROOT else BCAST_ID  

dup_cache = {}                       
tx_queue = []                        # Item format: (bytearray_inner_packet, send_time_ms)
sensor_queue = []

seq = 0                              
tx_counter = 0
ctr_limit = 0                        
ctr_lock = _thread.allocate_lock()   

# Error injection hook for Demo (Task 3)
CORRUPT_NEXT_TX = False 

stats = {                            
    "adv_sent": 0, "data_originated": 0, "data_relayed": 0,
    "queue_drops": 0, "no_route_drops": 0, "integrity_fail": 0,
    "bad_packet": 0, "acq_fail": 0, "delivered": 0,
    "duplicate": 0, "ttl_drop": 0, "neighbor_expired": 0,
    "no_rssi": 0,
}

# =====================================================================
# AES TX COUNTER & CRYPTO
# =====================================================================

def load_counter():                  
    try:
        with open(CTR_FILE) as f:
            return int(f.read())     
    except OSError:                  
        return 0

def save_counter(value):             
    with open(CTR_FILE, "w") as f:
        f.write(str(value))

def next_tx_counter():               
    global tx_counter, ctr_limit
    with ctr_lock:
        if tx_counter >= CTR_MAX:
            return None              
        if tx_counter >= ctr_limit:  
            ctr_limit += CTR_STEP
            save_counter(ctr_limit)  
        tx_counter += 1              
        return tx_counter

def get_initial_counter_value(run_id, sender_id, tx_ctr):   
    return struct.pack(">HBI", run_id, sender_id, tx_ctr) + b"\x00" * 9

def decrypt_ct(ciphertext, key_id, iv):   
    key = keychain[key_id]
    cipher = aes(key, 6, iv)         
    return cipher.decrypt(ciphertext)

def check_crc(crc_bytes_material, rcv_crc):   
    rcv_crc = struct.unpack(">I", rcv_crc)[0]
    return rcv_crc == (crc32(crc_bytes_material) & 0xFFFFFFFF)

def inject_error_hook():
    """Call this function manually via REPL to corrupt the next packet for the demo."""
    global CORRUPT_NEXT_TX
    CORRUPT_NEXT_TX = True
    print("HOOK: Next transmitted packet will have a flipped bit!")

# =====================================================================
# SETUP & HELPERS
# =====================================================================

def init_espnow():                   
    sta = network.WLAN(network.STA_IF)
    sta.active(True)
    sta.config(channel=CHANNEL)
    esp = espnow.ESPNow()
    esp.active(True)
    esp.add_peer(BCAST)              
    return esp

def setup():                         
    global e, tx_counter, ctr_limit
    e = init_espnow()                
    tx_counter = load_counter()
    ctr_limit = tx_counter + CTR_STEP
    save_counter(ctr_limit)

def count_stat(name):                
    with lock:
        stats[name] += 1

def print_metrics():
    now = time.ticks_ms()
    print(f"--- STATS t={now} mode={ROUTING_MODE} ---")
    with lock:
        items = list(stats.items())
    log_line = " ".join([f"{k}:{v}" for k,v in items])
    print(log_line)

def print_neighbors():
    now = time.ticks_ms()
    snapshot = []
    with lock:
        for nid, nb in neighbors.items():
            snapshot.append((nid, nb["hop"], nb["parent"], nb["rssi"], nb["srssi"], nb["last_seen"]))
        par = parent_id
        hop = my_hop
    print(f"--- neighbors | me={DEVICE_ID} parent={par} hop={hop} ---")
    snapshot.sort()                  
    for entry in snapshot:
        nid, nb_hop, nb_parent, rssi, srssi, last_seen = entry
        age = time.ticks_diff(now, last_seen)
        print(f"id={nid:3d} hop={nb_hop:3d} parent={nb_parent:3d} rssi={rssi:4d} srssi={srssi:6.1f} age={age:5d}ms")

# =====================================================================
# NEIGHBOR TABLE (DV Mode Only)
# =====================================================================

def usable(nb, now):                 
    if (time.ticks_diff(now, nb["last_seen"]) > NEIGHBOR_TIMEOUT_MS   
            or nb["hop"] >= BCAST_ID - 1                              
            or nb["parent"] == DEVICE_ID                              
            or nb["srssi"] < RSS_THRESHOLD):                          
        return False
    return True

def select_parent(reason):
    if ROUTING_MODE == "FLOODING" or IS_ROOT:
        return
    global parent_id, my_hop
    now = time.ticks_ms()
    with lock:
        old_parent = parent_id
        old_hop = my_hop

        best = None
        best_key = None
        parent_ok = False
        for nid, nb in neighbors.items():
            if not usable(nb, now): continue
            if nid == parent_id: parent_ok = True
            key = (nb["hop"], -nb["srssi"], nid)   
            if best is None or key < best_key:
                best = nid
                best_key = key
                
        if best is None:
            parent_id = BCAST_ID
        elif not parent_ok:
            parent_id = best
        else:
            b = neighbors[best]
            p = neighbors[parent_id]
            if b["hop"] < p["hop"]:
                parent_id = best     
            elif b["hop"] == p["hop"] and b["srssi"] >= p["srssi"] + SWITCH_MARGIN_DB:
                parent_id = best     

        if parent_id == BCAST_ID:
            my_hop = BCAST_ID
            par_srssi = 0
        else:
            my_hop = neighbors[parent_id]["hop"] + 1
            par_srssi = neighbors[parent_id]["srssi"]     

    if parent_id != old_parent or my_hop != old_hop:   
        print(f"PARENT CHANGE t={now} {old_parent} -> {parent_id}, hop {old_hop} -> {my_hop}, srssi {par_srssi:.1f}, reason: {reason}")

def update_neighbor(src_id, adv_hop, adv_parent, rssi):
    if ROUTING_MODE == "FLOODING": return
    now = time.ticks_ms()            
    with lock:
        nb = neighbors.get(src_id)
        srssi = rssi if nb is None else RSSI_SMOOTHING * rssi + (1 - RSSI_SMOOTHING) * nb["srssi"]
        neighbors[src_id] = {
            "hop": adv_hop, "parent": adv_parent, "rssi": rssi, "srssi": srssi, "last_seen": now,
        }

def expire_neighbors():
    now = time.ticks_ms()
    expired = []
    with lock:
        for nid in list(neighbors):  
            if time.ticks_diff(now, neighbors[nid]["last_seen"]) > NEIGHBOR_TIMEOUT_MS:
                del neighbors[nid]
                expired.append(nid)
                stats["neighbor_expired"] += 1   
    for nid in expired:              
        print(f"NEIGHBOR EXPIRED t={now} id={nid}")
    return expired

# =====================================================================
# DUPLICATE CACHE & PACKET PARSING
# =====================================================================

def is_duplicate(cache_key):         
    now = time.ticks_ms()
    with lock:
        return (cache_key in dup_cache and
                time.ticks_diff(now, dup_cache[cache_key]) <= DUP_EXPIRY_MS)

def purge_dup_cache():               
    now = time.ticks_ms()
    with lock:
        for key in list(dup_cache):  
            if time.ticks_diff(now, dup_cache[key]) > DUP_EXPIRY_MS:
                del dup_cache[key]
        while len(dup_cache) >= DUP_MAX:   
            oldest = min(dup_cache, key=dup_cache.get)
            del dup_cache[oldest]

def remember_packet(cache_key):      
    purge_dup_cache()
    with lock:
        dup_cache[cache_key] = time.ticks_ms()

def finite(x):                       
    return x == x and abs(x) != float("inf")   

def decode_payload(code, payload):
    if code not in PAYLOAD_LEN or len(payload) != PAYLOAD_LEN[code]: return None                  
    if code == 1:                    
        t, h = struct.unpack(">ff", payload)
        if finite(t) and finite(h) and 0 <= h <= 100: return (t, h)
    elif code == 2:                  
        (t,) = struct.unpack(">f", payload)
        if finite(t): return (t,)
    elif code == 3:                  
        lon, lat = struct.unpack(">ff", payload)
        if finite(lon) and finite(lat) and -180 <= lon <= 180 and -90 <= lat <= 90: return (lon, lat)
    elif code == 4:                  
        if payload[0] in (0, 1): return (payload[0],)
    elif code == 5:                  
        (a,) = struct.unpack(">f", payload)
        if finite(a) and a >= 0: return (a,)
    return None                      

def strip_outer_header(full_msg):    
    if full_msg is None or len(full_msg) < OUTER_HDR_LEN + MIN_CT_LEN: return None
    header = full_msg[:OUTER_HDR_LEN]
    ciphertext = full_msg[OUTER_HDR_LEN:]
    version, key_id, sender_id, run_id, tx_ctr = struct.unpack(OUTER_HDR_FRMT, header)
    if version != VERSION or key_id not in keychain or run_id != RUN_ID or sender_id == DEVICE_ID or sender_id == BCAST_ID:
        return None
    return key_id, sender_id, run_id, tx_ctr, ciphertext, header

# =====================================================================
# RECEIVE HANDLERS
# =====================================================================

def handle_advert(inner_pkt, sender_id, rssi):
    if len(inner_pkt) != 5:
        count_stat("bad_packet")
        return
    rcv_dest_id, rcv_src_id, rcv_hop, rcv_parent = inner_pkt[1:5]
    if rcv_dest_id != BCAST_ID or rcv_src_id == DEVICE_ID or rcv_src_id != sender_id:
        count_stat("bad_packet")
        return
    if rssi is None:
        count_stat("no_rssi")
        return
    update_neighbor(rcv_src_id, rcv_hop, rcv_parent, rssi)
    select_parent(f"advert from {rcv_src_id}")

def handle_data(inner_pkt):
    if len(inner_pkt) < DATA_HDR_LEN:
        count_stat("bad_packet")
        return
    rcv_dest_id     = inner_pkt[1]
    rcv_origin_id   = inner_pkt[2]
    rcv_seq_num     = (inner_pkt[3] << 8) | inner_pkt[4]
    rcv_ttl         = inner_pkt[5]
    rcv_sensor_code = inner_pkt[6]
    rcv_payload     = inner_pkt[DATA_HDR_LEN:]

    # Routing Filter: DV vs Flooding
    if ROUTING_MODE == "DV":
        if not IS_ROOT and rcv_dest_id != DEVICE_ID: return
    else:
        if rcv_dest_id != BCAST_ID: return

    cache_key = (rcv_origin_id, rcv_seq_num)
    if is_duplicate(cache_key):
        count_stat("duplicate")
        return

    values = decode_payload(rcv_sensor_code, rcv_payload)
    if values is None:
        count_stat("bad_packet")
        return

    if not IS_ROOT and rcv_ttl == 0:
        count_stat("ttl_drop")
        return

    remember_packet(cache_key)

    if IS_ROOT:
        count_stat("delivered")
        now = time.ticks_ms()
        units = UNITS[rcv_sensor_code]
        line = f"DELIVERED,{now},{rcv_origin_id},{rcv_seq_num},{rcv_sensor_code}"
        for i in range(len(values)):         
            line += f",{values[i]:.3f} {units[i]}"
        print(line)
    else:
        # Relay Handling
        fwd = bytearray(inner_pkt)   
        fwd[5] = rcv_ttl - 1         
        if ROUTING_MODE == "DV":
            fwd[1] = parent_id       
            delay = 0                # DV has no delay
        else:
            fwd[1] = BCAST_ID        
            delay = random.randint(50, 150) # Flooding uses jitter
            
        with lock:
            queued = len(tx_queue) < QUEUE_MAX
            if queued:
                tx_queue.append((fwd, time.ticks_add(time.ticks_ms(), delay)))
        if not queued:
            count_stat("queue_drops")   

# =====================================================================
# THREAD 1: RECEIVE THREAD (Main Loop)
# =====================================================================

def rx_thread():                     
    last_expiry_check = time.ticks_ms()
    last_table_print = time.ticks_ms()
    last_stat_print = time.ticks_ms()
    
    while True:
        mac_addr, full_msg = e.recv(100)
        now = time.ticks_ms()
        
        # Periodic Tasks
        if ROUTING_MODE == "DV" and time.ticks_diff(now, last_table_print) >= PRINT_TABLE_MS:     
            last_table_print = now
            print_neighbors()
            
        if time.ticks_diff(now, last_stat_print) >= STATS_INTERVAL_MS:
            last_stat_print = now
            print_metrics()
            
        if ROUTING_MODE == "DV" and time.ticks_diff(now, last_expiry_check) >= EXPIRY_CHECK_MS:   
            last_expiry_check = now
            expired = expire_neighbors()
            if parent_id in expired:
                select_parent("parent expired")

        if full_msg is None:         
            continue

        try:
            rssi = e.peers_table[mac_addr][0]
        except KeyError:
            rssi = None              

        full_msg = bytes(full_msg)
        outer = strip_outer_header(full_msg)
        if outer is None:
            count_stat("bad_packet")
            continue
            
        key_id, sender_id, run_id, rx_ctr, ciphertext, outer_header = outer   

        iv = get_initial_counter_value(run_id, sender_id, rx_ctr)
        decrypted_inner_msg = decrypt_ct(ciphertext, key_id, iv)
        rcv_crc = decrypted_inner_msg[-CRC_LEN:]
        inner_pkt = decrypted_inner_msg[:-CRC_LEN]
        
        if not check_crc(outer_header + inner_pkt, rcv_crc):
            count_stat("integrity_fail")
            continue

        rcv_ptype = inner_pkt[0]
        if rcv_ptype == PTYPE_ADV:
            handle_advert(inner_pkt, sender_id, rssi)
        elif rcv_ptype == PTYPE_DATA:
            handle_data(inner_pkt)
        else:
            count_stat("bad_packet") 

# =====================================================================
# THREAD 2: WORKER THREAD (Transmissions & Relays)
# =====================================================================

def encrypt_and_send(header, inner, is_adv=False):
    """Utility to handle encryption, error injection, and actual transmission."""
    global CORRUPT_NEXT_TX
    ctr = next_tx_counter()
    if ctr is None: return
    
    header_packed = struct.pack(OUTER_HDR_FRMT, VERSION, KEY_ID, DEVICE_ID, RUN_ID, ctr)
    crc = struct.pack(">I", crc32(header_packed + inner) & 0xFFFFFFFF)
    iv = get_initial_counter_value(RUN_ID, DEVICE_ID, ctr)
    ciphertext = aes(keychain[KEY_ID], 6, iv).encrypt(inner + crc)
    
    # Error Injection (Task 3)
    if CORRUPT_NEXT_TX:
        ct_arr = bytearray(ciphertext)
        ct_arr[0] ^= 0x01 # Flip a bit
        ciphertext = bytes(ct_arr)
        CORRUPT_NEXT_TX = False
        print("-> INJECTED 1-BIT ERROR INTO CIPHERTEXT")
        
    packet = header_packed + ciphertext
    
    if is_adv:
        count_stat("adv_sent")
    else:
        # Caller handles relay vs origination stat counting
        pass
        
    try:
        e.send(BCAST, packet, False)
    except OSError as err:
        print("TRANSMIT FAILED", err)  

def send_adv():
    if ROUTING_MODE == "FLOODING": return
    with lock:
        this_parent_id = parent_id
        this_hop = my_hop
    inner = bytes([PTYPE_ADV, BCAST_ID, DEVICE_ID, this_hop, this_parent_id])
    encrypt_and_send(None, inner, is_adv=True)

def relay_msg():
    with lock:
        if not tx_queue: return
        now = time.ticks_ms()
        # Scan queue for items whose delay timer has expired
        ready_idx = -1
        for i in range(len(tx_queue)):
            if time.ticks_diff(now, tx_queue[i][1]) >= 0:
                ready_idx = i
                break
        if ready_idx == -1: return
        forward, _ = tx_queue.pop(ready_idx)
        parent = parent_id

    if ROUTING_MODE == "DV":
        if parent == BCAST_ID:
            count_stat("no_route_drops")
            print(f"NO ROUTE t={time.ticks_ms()} dropped relay origin={forward[2]} seq={(forward[3] << 8) | forward[4]}")
            return
        forward[1] = parent
        
    count_stat("data_relayed")
    encrypt_and_send(None, forward, is_adv=False)

def send_data():
    global seq
    with lock:
        if not sensor_queue: return
        code, payload = sensor_queue.pop(0)
        seq += 1 
        my_seq = seq
        parent = parent_id
        
    now = time.ticks_ms()
    print(f"GENERATED,{now},{DEVICE_ID},{my_seq},{code}")  
    remember_packet((DEVICE_ID, my_seq)) 
    
    if ROUTING_MODE == "DV":
        if parent == BCAST_ID: 
            count_stat("no_route_drops")
            print(f"NO ROUTE t={now} dropped own origin={DEVICE_ID} seq={my_seq}")
            return
        dest = parent
    else:
        dest = BCAST_ID

    inner = struct.pack(">BBBHBB", PTYPE_DATA, dest, DEVICE_ID, my_seq, INITIAL_TTL - 1, code) + payload
    count_stat("data_originated")
    encrypt_and_send(None, inner, is_adv=False)

def tx_thread():                     
    next_adv = time.ticks_ms()
    while True:
        now = time.ticks_ms()
        if ROUTING_MODE == "DV" and time.ticks_diff(now, next_adv) >= 0:
            send_adv()
            next_adv = time.ticks_add(now, ADV_INTERVAL_MS + random.randint(0, ADV_JITTER_MS))
            
        if not IS_ROOT:
            send_data()
            relay_msg()
            
        time.sleep_ms(20)

# =====================================================================
# THREAD 3: SENSOR ACQUISITION THREAD (Task 3)
# =====================================================================

def acquire_sensor_data(code):
    """
    Simulates hardware reads based on the PDF requirements without blocking rx/tx threads.
    In real hardware, you would replace these with actual driver reads.
    """
    if code == 1: # DHT11: Temp, Hum
        return struct.pack(">ff", 22.5, 45.0) 
        
    elif code == 2: # DS18: Temp (Respects 750ms conversion delay)
        time.sleep_ms(750) 
        return struct.pack(">f", 23.1)
        
    elif code == 3: # GPS: Lon, Lat
        return struct.pack(">ff", -122.4194, 37.7749) 
        
    elif code == 4: # Smoke: 0/1
        return struct.pack(">B", 0) 
        
    elif code == 5: # Accel: Magnitude average over 2 seconds
        accel_sum = 0.0
        # 10 samples over 2 seconds (200ms per sample)
        for _ in range(10):
            x, y, z = 0.2, 0.1, 9.8 
            accel_sum += math.sqrt(x*x + y*y + z*z)
            time.sleep_ms(200) # This sleep DOES NOT block networking threads
        avg_a = accel_sum / 10.0
        return struct.pack(">f", avg_a)
        
    return None

def put_reading(code, payload): 
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

def sensor_thread():                 
    if IS_ROOT: return # Root doesn't generate data
    next_read = time.ticks_ms()
    
    while True:
        now = time.ticks_ms()
        if time.ticks_diff(now, next_read) >= 0:
            for code in ENABLED_SENSORS:
                payload = acquire_sensor_data(code)
                if payload:
                    put_reading(code, payload)
            
            # Schedule next reading
            next_read = time.ticks_add(now, DATA_INTERVAL_MS + random.randint(0, DATA_JITTER_MS))
        time.sleep_ms(100)


# =====================================================================
# STARTUP
# =====================================================================

def main():
    setup()                          
    print(f"BOOTUP: Device {DEVICE_ID}, Root={IS_ROOT}, Mode={ROUTING_MODE}")
    _thread.start_new_thread(tx_thread, ())  
    _thread.start_new_thread(sensor_thread, ())
    rx_thread()                      # Main thread becomes receive loop

main()