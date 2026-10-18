# shared.py
import _thread
import config

# Global Locks and Radio Object
lock = _thread.allocate_lock()       
e = None                             

# Routing State
neighbors = {}
parent_id = config.BCAST_ID                 
my_hop = 0 if config.IS_ROOT else config.BCAST_ID  

# Queues & Caches
dup_cache = {}                       
tx_queue = []                        
sensor_queue = []

# Sequence & State
seq = 0                              
CORRUPT_NEXT_TX = False 

# Metrics
stats = {                            
    "adv_sent": 0, "data_originated": 0, "data_relayed": 0,
    "queue_drops": 0, "no_route_drops": 0, "integrity_fail": 0,
    "bad_packet": 0, "acq_fail": 0, "delivered": 0,
    "duplicate": 0, "ttl_drop": 0, "neighbor_expired": 0,
    "no_rssi": 0,
}

def count_stat(name):                
    with lock:
        stats[name] += 1