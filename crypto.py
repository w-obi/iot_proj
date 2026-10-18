# crypto.py
import struct
from cryptolib import aes
from binascii import crc32
import _thread

import config
import shared
import keys

tx_counter = 0
ctr_limit = 0                        
ctr_lock = _thread.allocate_lock()   

def load_counter():                  
    try:
        with open(config.CTR_FILE) as f:
            return int(f.read())     
    except OSError:                  
        return 0

def save_counter(value):             
    with open(config.CTR_FILE, "w") as f:
        f.write(str(value))

def init_crypto():
    global tx_counter, ctr_limit
    tx_counter = load_counter()
    ctr_limit = tx_counter + config.CTR_STEP
    save_counter(ctr_limit)

def next_tx_counter():               
    global tx_counter, ctr_limit
    with ctr_lock:
        if tx_counter >= config.CTR_MAX: return None              
        if tx_counter >= ctr_limit:  
            ctr_limit += config.CTR_STEP
            save_counter(ctr_limit)  
        tx_counter += 1              
        return tx_counter

def get_iv(run_id, sender_id, tx_ctr):   
    return struct.pack(">HBI", run_id, sender_id, tx_ctr) + b"\x00" * 9

def encrypt_and_pack(inner_pkt):
    ctr = next_tx_counter()
    if ctr is None: return None
    
    header = struct.pack(config.OUTER_HDR_FRMT, config.VERSION, config.KEY_ID, config.DEVICE_ID, config.RUN_ID, ctr)
    crc = struct.pack(">I", crc32(header + inner_pkt) & 0xFFFFFFFF)
    iv = get_iv(config.RUN_ID, config.DEVICE_ID, ctr)
    ciphertext = aes(keys.keychain[config.KEY_ID], 6, iv).encrypt(inner_pkt + crc)
    
    if shared.CORRUPT_NEXT_TX:
        ct_arr = bytearray(ciphertext)
        ct_arr[0] ^= 0x01 # Flip bit
        ciphertext = bytes(ct_arr)
        shared.CORRUPT_NEXT_TX = False
        print("-> INJECTED 1-BIT ERROR INTO CIPHERTEXT")
        
    return header + ciphertext

def decrypt_and_verify(full_msg):
    if full_msg is None or len(full_msg) < config.OUTER_HDR_LEN + config.MIN_CT_LEN: return None
    header = full_msg[:config.OUTER_HDR_LEN]
    ciphertext = full_msg[config.OUTER_HDR_LEN:]
    version, key_id, sender_id, run_id, rx_ctr = struct.unpack(config.OUTER_HDR_FRMT, header)
    
    if version != config.VERSION or key_id not in keys.keychain or run_id != config.RUN_ID or sender_id == config.DEVICE_ID:
        return None
        
    iv = get_iv(run_id, sender_id, rx_ctr)
    decrypted = aes(keys.keychain[key_id], 6, iv).decrypt(ciphertext)
    rcv_crc_bytes = decrypted[-config.CRC_LEN:]
    inner_pkt = decrypted[:-config.CRC_LEN]
    
    rcv_crc = struct.unpack(">I", rcv_crc_bytes)[0]
    if rcv_crc != (crc32(header + inner_pkt) & 0xFFFFFFFF):
        return None # Integrity fail
        
    return inner_pkt, sender_id