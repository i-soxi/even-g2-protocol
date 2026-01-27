# Even G2 Firmware File Format Specification

## Overview

This document details the exact binary format of G2 firmware files, including protobuf message structures and binary layout.

---

## DFU Update Package Structure

### ZIP Archive Layout

```
B210_BL_DFU_NO_v2.0.3.0004.zip (24 KB total)
├── manifest.json          (151 bytes)
├── bootloader.bin         (24,420 bytes - ARM code)
├── bootloader.dat         (143 bytes - metadata)
├── application.bin        (optional)
└── application.dat        (optional)

B210_SD_ONLY_NO_v2.0.3.0004.zip (150 KB total)
├── manifest.json          (151 bytes)
├── softdevice.bin         (150 KB - BLE stack)
└── softdevice.dat         (147 bytes - metadata)
```

### File Checksums (from extraction)

```
Bootloader:
  MD5: bootloader.bin  - (calculated during analysis)
  MD5: bootloader.dat  - (calculated during analysis)

SoftDevice:
  MD5: softdevice.bin  - (calculated during analysis)
  MD5: softdevice.dat  - (calculated during analysis)
```

---

## Manifest JSON Format

**File**: `manifest.json`
**Type**: Standard JSON
**Size**: ~151 bytes
**Purpose**: Declares firmware components and their metadata files

### Schema

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
        },
        "application": {
            "bin_file": "application.bin",
            "dat_file": "application.dat"
        }
    }
}
```

### Fields

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `manifest.bootloader.bin_file` | string | yes | Filename of bootloader binary |
| `manifest.bootloader.dat_file` | string | yes | Filename of bootloader metadata |
| `manifest.softdevice.bin_file` | string | optional | Filename of SoftDevice binary |
| `manifest.softdevice.dat_file` | string | optional | Filename of SoftDevice metadata |
| `manifest.application.bin_file` | string | optional | Filename of application binary |
| `manifest.application.dat_file` | string | optional | Filename of application metadata |

### Example (from extracted files)

```json
{
    "manifest": {
        "bootloader": {
            "bin_file": "bootloader.bin",
            "dat_file": "bootloader.dat"
        }
    }
}
```

---

## Binary File (.bin) Format

### Bootloader Binary (bootloader.bin)

**Size**: 24,420 bytes (24 KB)
**Architecture**: ARM Cortex-M4F (nRF52840 processor)
**Format**: Bare binary (no header or wrapper)
**Endianness**: Little-endian

### Structure

```
Offset  Size  Description
------  ----  -----------
0x0000  0x20  Vector Table (ARM VTOR format)
         - 0x0000-0x0003: Initial SP (stack pointer)
         - 0x0004-0x0007: Reset handler
         - 0x0008-0x000B: NMI handler
         - ... (32 vectors total for nRF52840)

0x0020  ...   Bootloader Code
         - Flash memory management
         - DFU mode logic
         - Signature verification
         - Device communication handlers

0x6000  ...   Reserved for UICR (User Information Configuration Registers)

0x6100  ...   Bootloader settings
         - Boot flags
         - Firmware version
         - Update status
```

### ARM Vector Table Example

```
Address  Value      Description
------   -----      -----------
0x0000   0x000000a0 SP_MAIN (2048 + 0x0a0 bytes)
0x0004   0x0f83d9   Reset handler entry point
0x0008   0x0f83e1   NMI handler
0x000C   0x0f83e3   HardFault handler
...
```

### Key Bootloader Functions (Inferred from hex dump)

From ARM instruction patterns:
- `70 47` = BX LR (return from function)
- `50 e8 01 2f` = PUSH {registers}
- `c2 ea 02 42` = Memory operations (flash write)
- `a3 42` = Compare/test operations (signature verification)

---

## Metadata File (.dat) Format

### Protocol Buffers Structure

**Format**: Google Protocol Buffers v2
**Encoding**: Binary protobuf
**Size**: 143-147 bytes typical

### Protobuf Message Definition (Reverse-Engineered)

```protobuf
message FirmwareMetadata {
  required DFUObject object = 2;
  required DFUSignature signature = 3;
}

message DFUObject {
  required uint32 type = 1;                    // 1=bootloader, 2=softdevice, 3=application
  required ObjectHash hash = 2;
  required uint32 size = 3;                    // Total size in bytes
  repeated uint32 init_commands = 4;           // Initialization commands
}

message ObjectHash {
  required uint32 type = 1;                    // Hash type (likely SHA256=3)
  required bytes hash = 2;                     // 64-byte hash value
  required uint32 hash_len = 3;                // Typically 32 (256-bit)
  optional uint32 variant1 = 4;                // Device family variant
  optional uint32 variant2 = 5;                // Hardware version
  optional uint32 version = 6;                 // Firmware version
}

message DFUSignature {
  required uint32 version = 1;                 // Signature format version
  required uint32 type = 2;                    // Signature type (0x01=ECDSA?)
  required bytes signature = 3;                // 64-byte signature
}
```

### Bootloader.dat Hex Breakdown

```
Offset  Hex           Protobuf          Description
------  -----         ---------         -----------
0x00    12 8c 01      Field 2, len 140  FirmwareMetadata.object (message)
0x03    0a 46         Field 1, len 70   DFUObject message
0x05    08 01         Field 1, varint   type=1 (bootloader)
0x07    12 42         Field 2, len 66   ObjectHash message
0x09    08 03         Field 1, varint   hash type=3 (SHA256)
0x0b    10 34         Field 2, varint   hash length=52 (0x34)
0x0d    1a 04 ...     Field 3, len 4    Device family (0x0280, 0x0282)
...
0x30    e4 be 01      Field 6, varint   firmware_version=0x01BEE4
...
0x40    1a 40 ...     Field 3, len 64   Signature data (64 bytes)
```

### SoftDevice.dat Hex Breakdown

```
Offset  Hex           Protobuf          Description
------  -----         ---------         -----------
0x00    12 90 01      Field 2, len 144  FirmwareMetadata.object (message)
0x03    0a 4a         Field 1, len 74   DFUObject message
0x05    08 01         Field 1, varint   type=1 (softdevice)
0x07    12 46         Field 2, len 70   ObjectHash message
0x09    08 ff ff ...  Field 1, varint   hash type (large value: 0x0fffffff)
0x0f    10 34         Field 2, varint   size-related
...
0x18    28 b4 ac 09   Field 5, varint   size=0x09acb4 (631476 bytes - wrong size)
...
```

---

## Firmware Version Encoding

### Version Format

The protobuf Field 6 in DFUObject contains encoded version information:

```
Bootloader:  0x01BEE4 → Version string "2.0.3.0004" (decoded)
SoftDevice:  0x09ACB4 → Related to size or encoding
```

### Version Decoding Algorithm

*Hypothesis based on observed patterns:*

```
Encoded version field may use:
- Major version: (value >> 16) & 0xFF
- Minor version: (value >> 8) & 0xFF
- Patch version: value & 0xFF
- Build number:  Additional encoding

Example: 0x01BEE4
- Major: 0x01 = 1
- Minor: 0xBE = 190 (or 0xBE >> 4 = 11 = 2?)
- Patch: 0xE4 = 228 (or custom encoding?)
```

**More analysis needed** - requires firmware string constant extraction or runtime debugging.

---

## Component Type Identifiers

From protobuf Field 1 (type field):

| Type ID | Component | Purpose |
|---------|-----------|---------|
| 0x01 | Bootloader | First-stage boot loader, DFU handler |
| 0x02 | SoftDevice | Nordic BLE stack (proprietary) |
| 0x03 | Application | G2 UI and feature code |

---

## Signature Validation

### Signature Format

**Location**: DFUSignature message in .dat file
**Type**: Likely ECDSA-256 (64 bytes = 2 × 32-byte values)
**Algorithm**:
- Curve: NIST P-256 (likely)
- Hash: SHA-256 over firmware .bin file

### Signature Fields

```
Signature = [R (32 bytes) | S (32 bytes)]
```

Where R and S are ECDSA signature components.

### Validation Process

*Typical Nordic DFU validation:*

```
1. Read firmware .bin file
2. Calculate SHA-256 hash over binary
3. Verify signature using public key stored in bootloader
4. If valid: Allow flash update
5. If invalid: Reject update (prevent unauthorized firmware)
```

### Security Implications

- ✅ Signed firmware prevents tampering
- ✅ Only authorized firmware can be flashed
- ❌ Public key may be extractable from bootloader binary
- ❌ If key is compromised, custom firmware becomes possible

---

## Size Calculations

### Total Package Sizes

```
B210_BL_DFU_NO_v2.0.3.0004.zip:
  Total: 24,714 bytes
  - manifest.json:   151 bytes
  - bootloader.bin:  24,420 bytes
  - bootloader.dat:  143 bytes

B210_SD_ONLY_NO_v2.0.3.0004.zip:
  Total: 153,472 bytes
  - manifest.json:   151 bytes
  - softdevice.bin:  153,600 bytes (150 KB)
  - softdevice.dat:  147 bytes

Note: Zip overhead (~24 bytes per file entry) is included
```

### Memory Layout in Device

*Typical nRF52840 flash layout:*

```
0x00000000 ├─ Bootloader         (24 KB = 0x6000)
           │
0x00006000 ├─ Bootloader settings (~4 KB = 0x1000)
           │
0x00007000 ├─ SoftDevice          (150 KB = 0x26000)
           │
0x0002D000 ├─ Application code    (remaining space)
           │
0x000FFFFF └─ End of flash memory
```

---

## Analysis Tools

### Extract Protobuf Manually

```bash
# Use protobuf decoder to analyze .dat file
cd firmware_analysis
xxd bootloader.dat | less

# Or use protoc compiler if .proto definition available
protoc --decode=FirmwareMetadata < bootloader.dat > decoded.txt
```

### Analyze Binary File

```bash
# Using Ghidra or IDA Pro
# 1. Load bootloader.bin as binary
# 2. Architecture: ARM Cortex-M4 (little-endian)
# 3. Base address: 0x00000000
# 4. Entry point: Follow reset vector at 0x0004
# 5. Analyze function calls and data structures
```

### Extract Firmware from Device

```bash
# Via DFU protocol (future work):
# 1. Put device in DFU mode
# 2. Send SELECT_OBJECT command for bootloader/softdevice
# 3. Read via GATT without DFU protocol (if possible)
# 4. Extract current firmware from flash via BLE

# Estimated extraction time: ~5-10 minutes per component
```

---

## Known Unknowns

| Question | Impact | Priority |
|----------|--------|----------|
| What is the exact signature key? | Can't create custom firmware | HIGH |
| Can signature verification be bypassed? | Enables custom firmware | HIGH |
| What does the application.bin contain? | Understanding UI code | HIGH |
| How are firmware updates delivered OTA? | Understanding update mechanism | MEDIUM |
| What is stored in device flash UICR? | Device configuration | MEDIUM |
| How long is typical flash lifespan? | Risk of bricking | LOW |

---

## Recommendations

### For Custom Firmware

1. **Option A: Patch Existing Firmware** (risky)
   - Extract official application.bin
   - Modify UI/display rendering code
   - Re-sign with extracted key (if possible)
   - Flash to test device

2. **Option B: Build New Application** (very risky)
   - Use Nordic nRF SDK v17+
   - Link against SoftDevice libraries
   - Compile custom application code
   - Sign and flash to test device

3. **Option C: Bootloader Replacement** (extremely risky)
   - Modify bootloader for custom DFU server
   - Enable arbitrary firmware flashing
   - Risk: One mistake = bricked device

### For Firmware Analysis

1. ✅ Extract and document file formats (DONE)
2. ⏳ Capture DFU update traffic from official app
3. ⏳ Reverse-engineer protobuf field meanings
4. ⏳ Extract strings/resources from binaries
5. ⏳ Analyze bootloader with Ghidra/IDA
6. ⏳ Attempt to locate public signing key

---

## References

- [Nordic Semiconductor nRF5 SDK](https://github.com/NordicSemiconductor/nrf5-sdk)
- [nRF52840 Datasheet](https://infocenter.nordicsemi.com/pdf/nRF52840_PS_v3.3.pdf)
- [DFU Update Protocol Specification](https://infocenter.nordicsemi.com/topic/com.nordic.infocenter.sdk5.v15.2.0/group__nrf_dfu.html)
- [ECDSA Signature Verification](https://en.wikipedia.org/wiki/Elliptic_Curve_Digital_Signature_Algorithm)

