# sensors.py
import struct
import time
import math
import config

PAYLOAD_LEN = {1: 8, 2: 4, 3: 8, 4: 1, 5: 4}      
UNITS = {1: ("C", "%"), 2: ("C",), 3: ("deg lon", "deg lat"), 4: ("smoke",), 5: ("m/s^2",)}

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

def acquire_sensor_data(code):
    if code == 1: 
        return struct.pack(">ff", 22.5, 45.0) 
    elif code == 2: 
        time.sleep_ms(750) 
        return struct.pack(">f", 23.1)
    elif code == 3: 
        return struct.pack(">ff", -122.4194, 37.7749) 
    elif code == 4: 
        return struct.pack(">B", 0) 
    elif code == 5: 
        accel_sum = 0.0
        for _ in range(10):
            x, y, z = 0.2, 0.1, 9.8 
            accel_sum += math.sqrt(x*x + y*y + z*z)
            time.sleep_ms(200) 
        avg_a = accel_sum / 10.0
        return struct.pack(">f", avg_a)
    return None