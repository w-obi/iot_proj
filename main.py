# main.py
import _thread
import time
import network, espnow, struct, random

import config
import shared
import crypto
import routing
import sensors

def print_metrics():
    now = time.ticks_ms()
    with shared.lock: items = list(shared.stats.items())
    print(f"--- STATS t={now} mode={config.ROUTING_MODE} ---")
    print(" ".join([f"{k}:{v}" for k,v in items]))

def init_espnow():                   
    sta = network.WLAN(network.STA_IF)
    sta.active(True)
    sta.config(channel=config.CHANNEL)
    shared.e = espnow.ESPNow()
    shared.e.active(True)
    shared.e.add_peer(config.BCAST)              

def handle_advert(inner_pkt, sender_id, rssi):
    if len(inner_pkt) != 5: return shared.count_stat("bad_packet")
    rcv_dest_id, rcv_src_id, rcv_hop, rcv_parent = inner_pkt[1:5]
    if rcv_dest_id != config.BCAST_ID or rcv_src_id == config.DEVICE_ID or rcv_src_id != sender_id:
        return shared.count_stat("bad_packet")
    if rssi is None: return shared.count_stat("no_rssi")
    routing.update_neighbor(rcv_src_id, rcv_hop, rcv_parent, rssi)
    routing.select_parent(f"advert from {rcv_src_id}")

def handle_data(inner_pkt):
    if len(inner_pkt) < config.DATA_HDR_LEN: return shared.count_stat("bad_packet")
    dest_id, origin_id = inner_pkt[1], inner_pkt[2]
    seq_num = (inner_pkt[3] << 8) | inner_pkt[4]
    ttl, code = inner_pkt[5], inner_pkt[6]
    
    if config.ROUTING_MODE == "DV" and not config.IS_ROOT and dest_id != config.DEVICE_ID: return
    if config.ROUTING_MODE == "FLOODING" and dest_id != config.BCAST_ID: return

    cache_key = (origin_id, seq_num)
    if routing.is_duplicate(cache_key): return shared.count_stat("duplicate")
    
    values = sensors.decode_payload(code, inner_pkt[config.DATA_HDR_LEN:])
    if values is None: return shared.count_stat("bad_packet")
    if not config.IS_ROOT and ttl == 0: return shared.count_stat("ttl_drop")
    routing.remember_packet(cache_key)

    if config.IS_ROOT:
        shared.count_stat("delivered")
        units = sensors.UNITS[code]
        line = f"DELIVERED,{time.ticks_ms()},{origin_id},{seq_num},{code}"
        for i in range(len(values)): line += f",{values[i]:.3f} {units[i]}"
        print(line)
    else:
        fwd = bytearray(inner_pkt)   
        fwd[5] = ttl - 1         
        if config.ROUTING_MODE == "DV": fwd[1], delay = shared.parent_id, 0
        else: fwd[1], delay = config.BCAST_ID, random.randint(50, 150) 
            
        with shared.lock:
            if len(shared.tx_queue) < config.QUEUE_MAX:
                shared.tx_queue.append((fwd, time.ticks_add(time.ticks_ms(), delay)))
            else: shared.count_stat("queue_drops")   

def rx_thread():                     
    last_exp, last_stat = time.ticks_ms(), time.ticks_ms()
    while True:
        mac_addr, full_msg = shared.e.recv(100)
        now = time.ticks_ms()
            
        if time.ticks_diff(now, last_stat) >= config.STATS_INTERVAL_MS:
            last_stat = now
            print_metrics()
            
        if config.ROUTING_MODE == "DV" and time.ticks_diff(now, last_exp) >= config.EXPIRY_CHECK_MS:   
            last_exp = now
            if shared.parent_id in routing.expire_neighbors(): routing.select_parent("parent expired")

        if full_msg is None: continue
        try: rssi = shared.e.peers_table[mac_addr][0]
        except KeyError: rssi = None              

        res = crypto.decrypt_and_verify(bytes(full_msg))
        if res is None:
            shared.count_stat("integrity_fail")
            continue
        inner_pkt, sender_id = res

        if inner_pkt[0] == config.PTYPE_ADV: handle_advert(inner_pkt, sender_id, rssi)
        elif inner_pkt[0] == config.PTYPE_DATA: handle_data(inner_pkt)
        else: shared.count_stat("bad_packet") 

def send_packet(inner, is_adv=False):
    packet = crypto.encrypt_and_pack(inner)
    if packet is None: return
    if is_adv: shared.count_stat("adv_sent")
    try: shared.e.send(config.BCAST, packet, False)
    except OSError: pass

def tx_thread():                     
    next_adv = time.ticks_ms()
    while True:
        now = time.ticks_ms()
        if config.ROUTING_MODE == "DV" and time.ticks_diff(now, next_adv) >= 0:
            with shared.lock: p, h = shared.parent_id, shared.my_hop
            send_packet(bytes([config.PTYPE_ADV, config.BCAST_ID, config.DEVICE_ID, h, p]), is_adv=True)
            next_adv = time.ticks_add(now, config.ADV_INTERVAL_MS + random.randint(0, config.ADV_JITTER_MS))
            
        if not config.IS_ROOT:
            # Own Data
            with shared.lock:
                if shared.sensor_queue:
                    code, payload = shared.sensor_queue.pop(0)
                    shared.seq += 1 
                    my_seq, parent = shared.seq, shared.parent_id
                    print(f"GENERATED,{now},{config.DEVICE_ID},{my_seq},{code}")  
                    routing.remember_packet((config.DEVICE_ID, my_seq)) 
                    
                    if config.ROUTING_MODE == "DV" and parent == config.BCAST_ID: 
                        shared.count_stat("no_route_drops")
                    else:
                        dest = parent if config.ROUTING_MODE == "DV" else config.BCAST_ID
                        inner = struct.pack(">BBBHBB", config.PTYPE_DATA, dest, config.DEVICE_ID, my_seq, config.INITIAL_TTL-1, code) + payload
                        shared.count_stat("data_originated")
                        send_packet(inner)

            # Relay Data
            with shared.lock:
                ready_idx = next((i for i, item in enumerate(shared.tx_queue) if time.ticks_diff(now, item[1]) >= 0), -1)
                if ready_idx != -1:
                    forward, _ = shared.tx_queue.pop(ready_idx)
                    parent = shared.parent_id
                    
                    if config.ROUTING_MODE == "DV" and parent == config.BCAST_ID:
                        shared.count_stat("no_route_drops")
                    else:
                        if config.ROUTING_MODE == "DV": forward[1] = parent
                        shared.count_stat("data_relayed")
                        send_packet(forward)
                        
        time.sleep_ms(20)

def sensor_thread():                 
    if config.IS_ROOT: return
    next_read = time.ticks_ms()
    while True:
        now = time.ticks_ms()
        if time.ticks_diff(now, next_read) >= 0:
            for code in config.ENABLED_SENSORS:
                payload = sensors.acquire_sensor_data(code)
                if payload:
                    with shared.lock:
                        if len(shared.sensor_queue) < config.SENSOR_QUEUE_MAX: shared.sensor_queue.append((code, payload))
                        else: shared.count_stat("queue_drops")
            next_read = time.ticks_add(now, config.DATA_INTERVAL_MS + random.randint(0, config.DATA_JITTER_MS))
        time.sleep_ms(100)

def inject_error_hook():
    shared.CORRUPT_NEXT_TX = True
    print("HOOK: Next transmitted packet will have a flipped bit!")

def main():
    init_espnow()
    crypto.init_crypto()
    print(f"BOOT: Dev={config.DEVICE_ID}, Root={config.IS_ROOT}, Mode={config.ROUTING_MODE}")
    _thread.start_new_thread(tx_thread, ())  
    _thread.start_new_thread(sensor_thread, ())
    rx_thread()                      

if __name__ == "__main__":
    main()