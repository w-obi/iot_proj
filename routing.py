# routing.py
import time
import config
import shared

def usable(nb, now):                 
    if (time.ticks_diff(now, nb["last_seen"]) > config.NEIGHBOR_TIMEOUT_MS   
            or nb["hop"] >= config.BCAST_ID - 1                              
            or nb["parent"] == config.DEVICE_ID                              
            or nb["srssi"] < config.RSS_THRESHOLD):                          
        return False
    return True

def select_parent(reason):
    if config.ROUTING_MODE == "FLOODING" or config.IS_ROOT: return
    now = time.ticks_ms()
    with shared.lock:
        old_parent = shared.parent_id
        old_hop = shared.my_hop
        best = None
        best_key = None
        parent_ok = False
        
        for nid, nb in shared.neighbors.items():
            if not usable(nb, now): continue
            if nid == shared.parent_id: parent_ok = True
            key = (nb["hop"], -nb["srssi"], nid)   
            if best is None or key < best_key:
                best, best_key = nid, key
                
        if best is None:
            shared.parent_id = config.BCAST_ID
        elif not parent_ok:
            shared.parent_id = best
        else:
            b = shared.neighbors[best]
            p = shared.neighbors[shared.parent_id]
            if b["hop"] < p["hop"] or (b["hop"] == p["hop"] and b["srssi"] >= p["srssi"] + config.SWITCH_MARGIN_DB):
                shared.parent_id = best     

        if shared.parent_id == config.BCAST_ID:
            shared.my_hop, par_srssi = config.BCAST_ID, 0
        else:
            shared.my_hop = shared.neighbors[shared.parent_id]["hop"] + 1
            par_srssi = shared.neighbors[shared.parent_id]["srssi"]     

    if shared.parent_id != old_parent or shared.my_hop != old_hop:   
        print(f"PARENT CHANGE t={now} {old_parent} -> {shared.parent_id}, hop {old_hop} -> {shared.my_hop}, srssi {par_srssi:.1f}, reason: {reason}")

def update_neighbor(src_id, adv_hop, adv_parent, rssi):
    if config.ROUTING_MODE == "FLOODING": return
    now = time.ticks_ms()            
    with shared.lock:
        nb = shared.neighbors.get(src_id)
        srssi = rssi if nb is None else config.RSSI_SMOOTHING * rssi + (1 - config.RSSI_SMOOTHING) * nb["srssi"]
        shared.neighbors[src_id] = {"hop": adv_hop, "parent": adv_parent, "rssi": rssi, "srssi": srssi, "last_seen": now}

def expire_neighbors():
    now = time.ticks_ms()
    expired = []
    with shared.lock:
        for nid in list(shared.neighbors):  
            if time.ticks_diff(now, shared.neighbors[nid]["last_seen"]) > config.NEIGHBOR_TIMEOUT_MS:
                del shared.neighbors[nid]
                expired.append(nid)
                shared.stats["neighbor_expired"] += 1   
    for nid in expired: print(f"NEIGHBOR EXPIRED t={now} id={nid}")
    return expired

def is_duplicate(cache_key):         
    now = time.ticks_ms()
    with shared.lock:
        return cache_key in shared.dup_cache and time.ticks_diff(now, shared.dup_cache[cache_key]) <= config.DUP_EXPIRY_MS

def remember_packet(cache_key):      
    now = time.ticks_ms()
    with shared.lock:
        for key in list(shared.dup_cache):  
            if time.ticks_diff(now, shared.dup_cache[key]) > config.DUP_EXPIRY_MS: del shared.dup_cache[key]
        while len(shared.dup_cache) >= config.DUP_MAX:   
            del shared.dup_cache[min(shared.dup_cache, key=shared.dup_cache.get)]
        shared.dup_cache[cache_key] = time.ticks_ms()