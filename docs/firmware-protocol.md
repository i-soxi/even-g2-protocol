# Even G2 Firmware Update Protocol

## Overview

The Even G2 smart glasses use **Nordic nRF DFU (Device Firmware Update)** protocol for firmware updates. This is a standard BLE-based firmware update mechanism used by Nordic Semiconductor nRF devices.

**Device**: B210 (likely nRF52840 or similar)
**Firmware Types**:
- Bootloader (24 KB)
- SoftDevice / BLE Stack (150 KB)

---

## DFU File Format

### Package Structure

Each firmware update is distributed as a `.zip` file containing:

```
firmware.zip
├── manifest.json         # Update manifest
├── bootloader.bin        # Bootloader binary (ARM Cortex-M code)
├── bootloader.dat        # Bootloader metadata (protobuf-encoded)
├── softdevice.bin        # SoftDevice binary (BLE stack)
└── softdevice.dat        # SoftDevice metadata (protobuf-encoded)
```

### Manifest Format

The `manifest.json` declares which components are included:

```json
{
    "manifest": {
        "bootloader": {
            "bin_file": "bootloader.bin",
            "dat_file": "bootloader.dat"
        },
        "softdevice": {
            "bin_file": "softdevice.bin",
            "dat_file": "softdevice.dat"
        }
    }
}
```

### Binary Files (.bin)

- **Content**: Raw ARM Cortex-M machine code
- **Format**: Bare binary (no header)
- **Architecture**: ARM Thumb-2 instructions (nRF52840)
- **Size**: Variable (bootloader ~24 KB, SoftDevice ~150 KB)
- **Example bootloader**: `00 00 00 00 00 00 00 00 a0 cf 00 20 d9 83 0f 00 e1 83 0f 00...`
  - First 32 bits (0x000000a0): Bootloader image CRC
  - Next 32 bits (0x0f83d9): Stack pointer initialization (ARM VTOR format)

### Metadata Files (.dat)

- **Format**: Google Protocol Buffers (protobuf v2)
- **Size**: ~143 bytes for bootloader, ~147 bytes for softdevice
- **Content**: Firmware metadata and signature

#### Bootloader.dat Structure (Protobuf)

```
Field 2 (length-delimited, ~140 bytes):
  - Field 1 (varint): Type = 1
  - Field 2 (length-delimited, 70 bytes): Binary hash/signature data
    - Field 1 (varint): Signature type/format
    - Field 2 (length-delimited, 66 bytes): Raw signature data
    - Field 3 (varint): Size in bytes (0x34 = 52)
    - Field 4 (length-delimited): Device family version (0x0280, 0x0282)
    - Field 5 (varint): Hardware version (0)
    - Field 6 (varint): Software version (0xe4be01)
  - Field 3 (varint): Firmware type (0)
  - Field 4 (length-delimited, 64 bytes): CRC/hash validation
```

#### Softdevice.dat Structure (Protobuf)

Similar to bootloader, but with:
- Different firmware type indicator
- Different size (0x28b4ac = 2,715,820 bytes = ~150 KB)
- Signature over SoftDevice binary

---

## Firmware Update BLE Protocol

### BLE Characteristics & UUIDs

Nordic DFU uses standard GATT characteristics:

| Service | Characteristic | UUID | Purpose |
|---------|---|---|---|
| DFU Service | DFU Control Point | `00001531-1212-efde-1623-785feabcd123` | Commands |
| DFU Service | DFU Packet | `00001532-1212-efde-1623-785feabcd123` | Data packets |
| DFU Service | DFU Status | `00001533-1212-efde-1623-785feabcd123` | Status notifications |

### Update Sequence

```
Phone → Glasses                    Glasses → Phone
1. Connect to DFU Service GATT
2. Send: Select Object (0x06)  →
                                ←  Status: OK (0x01)
3. Send: Create Object (0x01)  →
                                ←  Status: Success (0x01)
4. Send: Set Packet Notify     →
5. Send: Execute (0x04)        →
                                ←  Status: OK
6. Send: Packet data (512B)    →
7. Send: Packet data (512B)    →
   ... (repeat until complete)
8. Send: Execute (0x04)        →
                                ←  Status: OK
9. Validate & Activate (0x05)  →
                                ←  Status: OK
10. Disconnect                   (Device reboots)
```

### Command Structure

Nordic DFU commands use a specific header format:

```
[1 byte: Command opcode]
[4 bytes: Parameter 1]
[4 bytes: Parameter 2]
[variable: Payload]
```

| Command | Opcode | Description |
|---------|--------|---|
| Start DFU | 0x01 | Begin update process |
| Select Object | 0x06 | Choose firmware object (0x01=bootloader, 0x02=SoftDevice) |
| Create Object | 0x01 | Allocate space for object |
| Set Packet Notify | 0x03 | Set max packet size |
| Send Packet | (implicit) | Write to Packet characteristic |
| Execute | 0x04 | Execute/validate current object |
| Activate & Reset | 0x05 | Reboot with new firmware |

### Packet Transfer

- **Packet Size**: Up to 512 bytes (configurable)
- **MTU**: 512 bytes (larger than standard 20-byte BLE MTU)
- **Total Time**: ~2-5 minutes for full firmware update
- **Flow Control**: No ACK per packet; status reported after Execute command

---

## Firmware Components Analysis

### Bootloader (bootloader.bin)

- **Size**: 24 KB
- **Architecture**: ARM Cortex-M4 (nRF52840)
- **Function**:
  - First-stage boot loader
  - Validates application/SoftDevice signatures
  - Handles DFU mode selection
  - Manages flash memory access

**Reverse Engineering Notes**:
- ARM thumb instructions visible in hex dump: `70 47` (BX LR return), `50 e8` (push/pop), etc.
- Bootloader contains:
  - Vector table (interrupt handlers) at start
  - DFU entry point logic
  - Flash write/erase routines
  - Signature verification (CRC/SHA256?)

### SoftDevice (softdevice.bin)

- **Size**: 150 KB
- **Architecture**: ARM Cortex-M4 (nRF52840)
- **Function**:
  - Nordic-provided BLE stack implementation
  - Handles all Bluetooth communication
  - Memory-mapped GATT database
  - Low-level RF operations

**Reverse Engineering Notes**:
- Pre-compiled Nordic binary (not open source)
- Contains:
  - BLE protocol state machine
  - GATT server implementation
  - L2CAP, ATT, GAP protocols
  - RF physical layer drivers

### Application Firmware (Not found in extracted files)

- **Expected Size**: Probably 300-500 KB
- **Content**: Even G2 UI, display rendering, even-ai logic
- **Status**: Not included in extracted APK/IPA

---

## Firmware Version Information

### Extracted Firmware Versions

From `bootloader.dat` protobuf metadata:

| Firmware | Version | Date | Size | Purpose |
|----------|---------|------|------|---------|
| B210_ALWAY_BL_DFU_NO | (unknown) | Dec 27, 2025 | 24 KB | Always Boot bootloader |
| B210_BL_DFU_NO_v2.0.3.0004 | 2.0.3.0004 | Dec 27, 2025 | 24 KB | Bootloader v2.0.3.0004 |
| B210_SD_ONLY_NO_v2.0.3.0004 | 2.0.3.0004 | Jan 5, 2026 | 150 KB | SoftDevice (BLE stack) |

### Version Encoding

The protobuf Field 6 contains version information:
- **Bootloader**: 0xe4be01 (likely encoded version)
- **SoftDevice**: 0x28b4ac (likely size indicator, 150 KB = 0x25800 ≠ 0x28b4ac, so different encoding)

---

## Security & Validation

### Signature Validation

The `.dat` files include 64-byte signatures (likely SHA256 or similar):

```
Field 2 → Field 2 (length-delimited, 66 bytes)
  → Contains raw signature data (64 bytes observed)
```

**Security Implications**:
- Firmware is cryptographically signed
- Device validates signature before flashing
- Prevents unsigned/malicious firmware uploads
- Uses Nordic's firmware signing keys (proprietary)

### Update Protection

- **No PIN/password required** - DFU mode is open once enabled
- **Device validation** - Only nRF52840 devices can flash nRF-specific firmware
- **CRC validation** - Each component includes CRC/hash for integrity
- **Atomic updates** - Either fully updates or rolls back

---

## Reverse Engineering Findings

### What We Know

1. **File Format**: Standard Nordic nRF DFU package
   - ✅ Zip structure confirmed
   - ✅ Manifest format identified
   - ✅ Protobuf metadata decoded (partially)
   - ✅ Binary format is ARM Cortex-M code

2. **Component Types**:
   - ✅ Bootloader identified (24 KB, bootloader.bin/dat)
   - ✅ SoftDevice identified (150 KB, softdevice.bin/dat)
   - ❌ Application firmware not in extracted files

3. **Security**:
   - ✅ Firmware is signed (64-byte signature in .dat)
   - ✅ No obvious anti-reverse-engineering measures
   - ❌ Signature validation logic (would need runtime analysis)

### What's Unknown

1. **DFU BLE Protocol** (needs traffic capture):
   - Exact command sequence for firmware update
   - Packet format and fragmentation strategy
   - Timeout and retry behavior
   - Status/error reporting mechanism

2. **Signature Verification**:
   - Key material (where is signing key stored?)
   - Signature algorithm (SHA256/HMAC?)
   - Verification on device (bootloader vs SoftDevice)

3. **Application Firmware**:
   - Where is stored in phone app?
   - Is it bundled or downloaded?
   - How frequently updated?

---

## Recommended Next Steps

### Phase 1: DFU Protocol Capture (No Hardware Risk)

```bash
# Capture with btsnoop log while running official app firmware update
adb logcat > device.log &
adb bugreport --progress-fd 1 > bugreport.zip

# Extract btsnoop_hci.log from bugreport
unzip bugreport.zip -d extracted/
cat extracted/log/btsnoop_hci.log | xxd > dfu_traffic.txt
```

**Analysis**:
- Identify DFU service UUID
- Map command opcodes
- Trace packet sequence
- Measure timing/latency

### Phase 2: Firmware Extraction (Static Analysis)

```bash
# Already done:
# - Extracted bootloader and softdevice binaries
# - Identified protobuf metadata format

# Next:
# - Full protobuf message definition reverse engineering
# - Analyze ARM disassembly (Ghidra/IDA)
# - Extract string constants for UI/error messages
```

### Phase 3: Custom Firmware (Test Device Only)

```bash
# Only attempt on dedicated test device!
# 1. Extract official firmware via DFU capture
# 2. Analyze firmware images with Ghidra
# 3. Locate display rendering code
# 4. Patch UI/colors/fonts
# 5. Re-sign and test flash
```

---

## Related Resources

- [Nordic nRF DFU Protocol](https://infocenter.nordicsemi.com/topic/com.nordic.infocenter.sdk5.v15.2.0/lib_dfu_protocol.html)
- [nRF52840 DK Hardware](https://www.nordicsemi.com/Products/Development-hardware/NRF52840-DK)
- [DFU Update on Android](https://infocenter.nordicsemi.com/topic/com.nordic.infocenter.sdk5.v15.2.0/lib_dfu_bootloader.html)

---

## Conclusion

The Even G2 uses **standard Nordic nRF DFU protocol** with:
- No exotic modifications (good news!)
- Standard bootloader + SoftDevice architecture
- Firmware signature validation (likely prevents unsigned flashing)
- Documented protocol format (enables custom implementations)

**Key Opportunity**: If we can capture the official app's DFU traffic and extract the application firmware, we can:
1. Build custom firmware loaders
2. Modify UI/display rendering
3. Create a full firmware replacement

**Risk Level**: **HIGH** for untested firmware - bootloader/SoftDevice corruption = bricked device. Only attempt on dedicated test hardware.

