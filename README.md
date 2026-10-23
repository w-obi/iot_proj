# ESP32 Distance Vector & Flooding Routing Protocol

This project implements a multi-hop wireless sensor network using ESP32 microcontrollers over ESP-NOW. It features a self-healing **Distance Vector (DV) routing protocol** and a **Duplicate-Suppressed Flooding** baseline. The network consists of one **Root node** (Device ID 0, the data sink) and multiple **Non-root nodes** (Device IDs 1-254, which act as both sensors and relays).

## File Structure

The project uses a clean 2-file architecture to comply with security requirements while keeping flashing simple:

- `keys.py`: Contains the Pre-Shared Keys (PSK). **(Fulfills Section V-A requirement to keep keys out of the main logic/logs).**
- `DvRoutingProject.py`: Contains configuration, multithreading, routing logic, crypto functions, and sensor emulation.

## Project Overview & Protocol Architecture

### Types of Transmissions

To bypass ESP-NOW peer-limit restrictions, **all physical transmissions are sent as MAC-layer broadcasts** (`FF:FF:FF:FF:FF:FF`). Filtering and routing are handled at the application layer. There are two types of application-layer packets:

1. **Advertisements (`ptype = 0`)**
   - **When it is used:** Broadcasted periodically (every ~5 seconds) by all devices in DV Mode.
   - **Purpose:** Neighbor discovery and route building. It tells nearby devices: _"I am Node X, my current parent is Node Y, and I am Z hops away from the root."_ Devices use this to calculate the shortest, strongest path to the root.
2. **Sensor Data (`ptype = 2`)**
   - **When it is used:** Generated periodically (every ~10 seconds) by non-root nodes, or forwarded instantly when received from a child node.
   - **Purpose:** Delivers sensor readings (Temperature, Humidity, GPS, Smoke, or Accelerometer) to the Root.
   - **Routing:** In DV mode, the `dest_id` is set to the device's chosen parent (so only the parent processes it). In Flooding mode, `dest_id` is set to `255` (Broadcast), so every node that hears it relays it exactly once.

### Secure Packet Format

#### 1. Full "On-Air" Packet Structure

Every packet transmitted over ESP-NOW follows this top-level envelope structure:

| Outer Header (Cleartext) | Ciphertext (AES-CTR Encrypted)   |
| :----------------------- | :------------------------------- |
| **9 Bytes**              | **Inner Packet + 4-Byte CRC-32** |

#### 2. Outer Header (9 Bytes, `>BBBHI`)

This cleartext header contains the metadata required for the receiver to construct the AES-CTR Initialization Vector (IV) and decrypt the payload.

- **`version` (1 Byte):** Protocol version (always `1`).
- **`key_id` (1 Byte):** Identifies which Pre-Shared Key (PSK) to use.
- **`sender_id` (1 Byte):** The physical device ID transmitting this hop.
- **`run_id` (2 Bytes):** Unique network-wide session ID.
- **`tx_counter` (4 Bytes):** Strictly increasing counter to prevent IV reuse/replay attacks.

#### 3. Cryptographic Layer & IV

- **AES Initialization Vector (16 Bytes):** Constructed using `run_id` (2B) + `sender_id` (1B) + `tx_counter` (4B) + Padding (9 bytes of `0x00`).
- **Integrity (CRC-32):** Computed over the _Outer Header + Plaintext Inner Packet_. The 4-byte CRC is appended to the inner packet _before_ AES encryption.

---

#### 4. Inner Packet: Advertisement (`ptype = 0`)

**Length: 5 Bytes** (Excluding CRC and Outer Header)
Advertisements are used in Distance Vector mode to build routing tables.

| Field       | Size   | Description                                     |
| :---------- | :----- | :---------------------------------------------- |
| `ptype`     | 1 Byte | Always `0` for Advertisements.                  |
| `dest_id`   | 1 Byte | Always `255` (Broadcast destination).           |
| `src_id`    | 1 Byte | ID of the device advertising the route.         |
| `hop`       | 1 Byte | Distance to the root (`255` = no route).        |
| `parent_id` | 1 Byte | The advertiser's current parent (`255` = none). |

---

#### 5. Inner Packet: Sensor Data (`ptype = 2`)

**Length: 7 Bytes Header + Variable Payload**
Data packets carry sensor readings from the origin node to the root.

| Field         | Size     | Description                                                        |
| :------------ | :------- | :----------------------------------------------------------------- |
| `ptype`       | 1 Byte   | Always `2` for Data.                                               |
| `dest_id`     | 1 Byte   | Parent ID (DV Mode) or `255` (Flooding Mode).                      |
| `origin_id`   | 1 Byte   | The ID of the device that originally generated the data.           |
| `seq`         | 2 Bytes  | Sequence number from the origin node (used for duplicate caching). |
| `ttl`         | 1 Byte   | Time-To-Live. Decrements every hop. Drops at `0`.                  |
| `sensor_code` | 1 Byte   | Identifies the payload type (1-5).                                 |
| `payload`     | Variable | The actual sensor data (see table below).                          |

#### 6. Sensor Payload Specifications

The `payload` field dynamically changes size based on the `sensor_code`.

| Code | Sensor Type | Payload SizeAll transmissions are wrapped in a mandatory security envelope to prevent eavesdropping and data corruption:

- **Outer Header (9 Bytes, Cleartext):**
  `[ Version (1B) | Key ID (1B) | Sender ID (1B) | Run ID (2B) | TX Counter (4B) ]`
  _Used by the receiver to identify the sender and generate the initialization vector (IV) for decryption._
- **Inner Payload (Variable Length, Ciphertext):**
  `AES-CTR Encrypted [ Inner Packet (Advert or Data) | CRC-32 Checksum (4B) ]`
  _Ensures that routing data and sensor readings are strictly confidential and immediately drops corrupted/tampered packets._

|   #   | Sensor / Type      |  Size   | Format (Big-Endian)                                |
| :---: | :----------------- | :-----: | :------------------------------------------------- |
| **1** | DHT11 (Temp & Hum) | 8 Bytes | `Temperature C (float32)` + `Humidity % (float32)` |
| **2** | DS18 (Temp)        | 4 Bytes | `Temperature C (float32)`                          |
| **3** | GPS (Lon & Lat)    | 8 Bytes | `Longitude (float32)` + `Latitude (float32)`       |
| **4** | Smoke Detector     | 1 Byte  | `0` (No Smoke) or `1` (Smoke Detected)             |
| **5** | Accelerometer      | 4 Bytes | `Magnitude avg m/s² (float32)`                     |

## Code Mapping to PDF Tasks

### Task 1: Neighbor Discovery

- **`send_adv()`**: Broadcasts periodic advertisements containing `hop` and `parent_id`.
- **`handle_advert()`**: Parses incoming packets. Rejects loops and packets with no RSSI.
- **`update_neighbor()`**: Implements the 0.3 Exponential Moving Average (EMA) for smoothed RSSI.
- **`expire_neighbors()`**: Uses `time.ticks_diff()` to safely remove neighbors unseen for > 15 seconds.

### Task 2: Parent Selection

- **`usable()`**: Filters out stale neighbors, neighbors without routes (`hop == 255`), and links below `-85 dBm`.
- **`select_parent()`**: Evaluates candidates. Applies the **5 dB hysteresis margin** (`SWITCH_MARGIN_DB`) to prevent parent oscillation. Breaks ties using the smallest hop count, then strongest RSSI.

### Task 3: Data Generation and Delivery

- **`acquire_sensor_data()` / `sensor_thread()`**: Gathers data. Implements the required 2-second sleep for the accelerometer and 750ms delay for the DS18 **without** blocking the radio, thanks to the threaded design.
- **`send_data()`**: Formats the packet into the strict 7-byte header (`ptype|dest|origin|seq|ttl|code`) + variable payload.
- **`is_duplicate()` & `remember_packet()`**: Manages the bounded duplicate cache (prevents looping).

### Task 4: Threaded Operation

- **`rx_thread()`**: The main execution loop. Only handles receiving, decrypting, and parsing.
- **`tx_thread()`**: Handles all transmissions (adverts, own data, and forwarding queue).
- **`sensor_thread()`**: Ensures long sensor reads never block ESP-NOW network events.
- **`lock`**: Protects shared dictionaries (`neighbors`, `tx_queue`, `dup_cache`) to prevent race conditions.

### Task 5: Flooding Baseline

- **`ROUTING_MODE` variable**: Switches between `"DV"` and `"FLOODING"`.
- **In Flooding Mode**:
  - `send_adv()` is bypassed.
  - Packets are sent to `dest_id = 255`.
  - `tx_queue` delays rebroadcasts using `random.randint(50, 150)` ms to prevent packet collisions.

### Section V-A: Security & Integrity

- **`keys.py`**: Ensures PSK separation.
- **`next_tx_counter()`**: Persists the AES counter to `ctr.txt` in blocks of 256. Prevents IV reuse across reboots without burning out the ESP32 flash memory.
- **`check_crc()`**: Computes CRC-32 over the outer header + plaintext inner packet.

---

## Important Compliance Notes (From the PDF)

1.  **Never hard-code routes**: Routes are built strictly from `handle_advert()`.
2.  **No Unicast Peers**: The code uses ONLY the broadcast MAC address (`b'\xff' * 6`). Filtering is done at the application layer via `dest_id`.
3.  **End-to-End Delivery Proof**: Delivery is ONLY counted when `DELIVERED` prints at the Root node. `e.send()` returning `True` does not count.
4.  **No Invalid Data Transmissions**: Failed sensor reads generate logs but _do not_ result in a packet transmission.

---

## How to Conduct the Lab Experiments

### Setup & Preparation

1. Ensure all ESP32 boards have ESP-NOW flashed and MicroPython installed.
2. Upload `keys.py` to **all** boards.
3. Open your main script in Thonny. Change `ROUTING_MODE = "DV"`.
4. For each board, change `DEVICE_ID` (0 to 10). For the Root board only, set `IS_ROOT = True` and `DEVICE_ID = 0`.
5. Upload the script to the corresponding boards.

### Phase 1: Stable Topology (Distance Vector)

1. Power on the Root. Power on Node 1 (close to root) and Node 2 (further away).
2. **Observe**: In Node 2's console, you should see `PARENT CHANGE` as it discovers Node 1, calculates the hops, and begins routing data through it.
3. **Observe**: The Root console will print `DELIVERED` lines with the sensor readings.

### Phase 2: Failure Recovery (Distance Vector)

1. With the network stable, physically unplug/power off Node 1.
2. **Observe**: In Node 2's console, after ~15 seconds, you will see `NEIGHBOR EXPIRED` for Node 1, followed by `NO ROUTE` drops, until it finds an alternative path. Record this time gap for your "Convergence/Recovery Time" metric.

### Phase 3: Error Injection Demo (Security Verification)

1. Go to the Thonny REPL (shell) for any transmitting non-root Node.
2. Type: `inject_error_hook()` and press Enter.
3. The console will print `-> INJECTED 1-BIT ERROR INTO CIPHERTEXT`.
4. Look at the receiving board's console; you will see the `integrity_fail` counter tick up. The packet is silently dropped without altering the routing state.

### Phase 4: Flooding Baseline & Data Collection

1. Change `ROUTING_MODE = "FLOODING"` in the main script. Flash to all boards and reset.
2. Run the network for **at least 5 minutes**.
3. Copy the output from the Root node's console into a text file.
4. The system automatically prints standard CSV lines:
   - `GENERATED, time, origin, seq, sensor_code` (From senders)
   - `DELIVERED, time, origin, seq, sensor_code, value...` (From root)
5. **Data Analysis**: You can copy these logs into Excel or a Python script to calculate:
   - **PDR (Packet Delivery Ratio)** = Total `DELIVERED` unique packets / Total `GENERATED` packets.
   - **Overhead** = Check the periodic `--- STATS ---` printout for `adv_sent` + `data_relayed` + `data_originated`. Divide that sum by total unique `DELIVERED` packets.
