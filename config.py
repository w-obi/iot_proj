# config.py
import struct

ROUTING_MODE = "DV"                  # "DV" or "FLOODING"
DEVICE_ID = 7
IS_ROOT = False
CHANNEL = 1                          
RUN_ID = 1                           
KEY_ID = 1                           

ADV_INTERVAL_MS = 5000               
ADV_JITTER_MS = 500
DATA_INTERVAL_MS = 10000             
DATA_JITTER_MS = 1000
STATS_INTERVAL_MS = 30000            

ENABLED_SENSORS = [1, 5]             

RSSI_SMOOTHING = 0.3                 
NEIGHBOR_TIMEOUT_MS = 15000         
EXPIRY_CHECK_MS = 1000              
RSS_THRESHOLD = -85                  
SWITCH_MARGIN_DB = 5                 
PRINT_TABLE_MS = 5000                

DUP_EXPIRY_MS = 60000               
DUP_MAX = 200                        
QUEUE_MAX = 20                       
INITIAL_TTL = 10                     
SENSOR_QUEUE_MAX = 5                 

CTR_FILE = "ctr.txt"                 
CTR_STEP = 256                       
CTR_MAX = 0xFFFFFFFF                 

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