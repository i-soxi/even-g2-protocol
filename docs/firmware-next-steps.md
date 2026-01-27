# Even G2 Firmware: Next Steps & Quick Reference

## For the Next Person Working on This

### What We Know ✅

1. **Device**: Even G2 (B210 variant) uses nRF52840 + Nordic DFU
2. **Components**:
   - Bootloader: 24 KB (firmware update handler)
   - SoftDevice: 150 KB (BLE stack)
   - Application: ~300-500 KB (G2 UI, displays, AI logic) **NOT YET EXTRACTED**
3. **File Format**: Standard Nordic DFU ZIP with protobuf metadata
4. **Security**: All firmware is ECDSA-256 signed, device validates before flashing
5. **Protocol**: Standard Nordic nRF DFU BLE protocol (documented)

### What We Need 🎯

| Need | Why | How | Priority |
|------|-----|-----|----------|
| **DFU Traffic Capture** | Understand exact BLE command sequence | Run firmware update with btsnoop logging | HIGH |
| **Application Firmware** | Can't modify UI without it | Extract via DFU protocol | HIGH |
| **Signing Key** | Can't flash custom firmware without it | Extract from bootloader or try key recovery | HIGH |
| **Device UICR** | May contain debug/config flags | Read during DFU session | MEDIUM |
| **Ghidra Analysis** | Understand UI rendering code | Set up Ghidra project with bootloader/app | MEDIUM |

### Quick Start: Firmware Update Capture

```bash
# On Android device (adb shell)
cd /sdcard
logcat -b all -v threadtime > logcat_$(date +%s).txt &
LOGCAT_PID=$!

# In another terminal:
# Start firmware update in Even app on device
# Wait for update to complete (~3 minutes)

# Stop logging
kill $LOGCAT_PID

# Check for btsnoop
if [ -f /sys/kernel/debug/bluetooth/hci_spi/btsnoop_log ]; then
  cat /sys/kernel/debug/bluetooth/hci_spi/btsnoop_log > btsnoop.log
fi

# Pull back to computer
adb pull /sdcard/logcat*.txt .
adb pull btsnoop.log . 2>/dev/null || echo "btsnoop not available on this device"
```

### Extract & Analyze Firmware

```bash
# Extract DFU package
python3 tools/extract_firmware.py \
  even-g2-re/ipa-extracted/Payload/Runner.app/Frameworks/App.framework/flutter_assets/assets/files/B210_BL_DFU_NO_v2.0.3.0004.zip \
  --extract --analyze --output firmware_analysis.json

# View analysis
cat firmware_analysis.json | jq .components.bootloader
```

### Open in Ghidra

1. **Download Ghidra**: https://ghidra-sre.org/
2. **Create project**: File → New Project
3. **Import binary**:
   - File → Import File
   - Choose: `bootloader.bin` or `softdevice.bin`
   - Language: ARM Cortex-M (little-endian)
   - Base address: 0x00000000
4. **Analyze**:
   - Right-click → Analyze
   - Select default analyzers
   - Wait for completion
5. **Explore**:
   - Window → Functions
   - Look for DFU-related functions
   - Search for strings (e.g., "DFU", "update", etc.)

### Key Files

```
even-g2-protocol/
├── docs/
│   ├── firmware-protocol.md              ← Start here
│   ├── firmware-format.md                ← Detailed binary format
│   ├── FIRMWARE_ANALYSIS_SUMMARY.md      ← Overview & findings
│   └── firmware-next-steps.md            ← This file
├── tools/
│   └── extract_firmware.py               ← Extraction tool
└── even-g2-re/
    └── ipa-extracted/.../assets/files/
        ├── B210_BL_DFU_NO_v2.0.3.0004.zip
        ├── B210_ALWAY_BL_DFU_NO.zip
        └── B210_SD_ONLY_NO_v2.0.3.0004.zip
```

### Key UUIDs (from protocol docs)

```
BLE Characteristics (Even G2 protocol):
  - Control:    0x00002760-08c2-11e1-9073-0e8ac72e5401 (write)
  - Response:   0x00002760-08c2-11e1-9073-0e8ac72e5402 (notify)
  - Display:    0x00002760-08c2-11e1-9073-0e8ac72e6402 (display)
  - File I/O:   0x00002760-08c2-11e1-9073-0e8ac72e7401/7402 (file ops)

Nordic DFU Characteristics (for firmware update):
  - Control:    0x00001531-1212-efde-1623-785feabcd123
  - Packet:     0x00001532-1212-efde-1623-785feabcd123
  - Status:     0x00001533-1212-efde-1623-785feabcd123
```

### Critical Do's and Don'ts

✅ **DO**:
- Use a dedicated test device (don't use your primary G2!)
- Capture official firmware update traffic first
- Analyze bootloader with Ghidra before attempting flashing
- Verify DFU commands work on official firmware first
- Keep original firmware binaries backed up

❌ **DON'T**:
- Attempt to flash custom firmware on primary device
- Modify firmware without bootloader analysis
- Skip signature validation study
- Flash without having recovery plan
- Assume device won't brick (it will if bootloader corrupted)

### Potential Roadblocks & Solutions

| Problem | Solution |
|---------|----------|
| Can't capture btsnoop on iOS | Use macOS Bluetooth logging or emulate on Android |
| Bootloader is encrypted | Try key extraction from SoftDevice or runtime dumping |
| DFU commands unknown | Contact Nordic Semiconductor or analyze open-source implementations |
| No application firmware in app | May be downloaded after first update or stored on device |
| Device requires PIN for DFU | Analyze bootloader code for PIN logic or look for backdoor |
| Signature verification fails | Try finding key in bootloader or implement key recovery algorithm |

### Command Reference

#### Using extract_firmware.py tool

```bash
# Basic extraction and analysis
python3 tools/extract_firmware.py firmware.zip -e -a

# Save analysis to JSON
python3 tools/extract_firmware.py firmware.zip -e -a -o analysis.json

# Extract only (don't analyze)
python3 tools/extract_firmware.py firmware.zip -e

# Analyze only (if already extracted)
python3 tools/extract_firmware.py firmware.zip -a
```

### Research Contacts

If you get stuck, these resources might help:

- **Nordic Support**: https://devzone.nordicsemi.com/
- **nRF DFU Protocol**: https://infocenter.nordicsemi.com/
- **Reverse Engineering Community**: EEVblog forum, reverse engineering subreddits
- **Even Realities Discord**: https://discord.gg/arDkX3pr (G2 reverse engineering channel)

### Success Checklist

- [ ] Captured official firmware update BLE traffic
- [ ] Decoded DFU command sequence
- [ ] Extracted application firmware from device
- [ ] Set up Ghidra project for bootloader analysis
- [ ] Identified signing key location in bootloader
- [ ] Found/recovered signing key or bypass method
- [ ] Created minimal test firmware patch (color change only)
- [ ] Flashed test firmware to dedicated device
- [ ] Device booted successfully with custom firmware
- [ ] Display rendered correctly
- [ ] BLE communication still works

Once you complete this checklist, you'll have enough knowledge to build a complete custom firmware UI replacement!

---

## Documentation Map

```
Understanding Progression:
1. Start: FIRMWARE_ANALYSIS_SUMMARY.md     (overview)
2. Deep dive: firmware-protocol.md         (architecture)
3. Technical: firmware-format.md           (binary format)
4. Getting hands-on: firmware-next-steps.md (this file)
5. Execution: [create new protocol capture docs]
```

---

## Questions to Answer During Next Phase

1. **How long does firmware update take?**
   - Helps plan DFU retries and timeout values

2. **What are exact packet sizes used?**
   - Determines fragmentation strategy

3. **Does device support backup/restore of original firmware?**
   - Safety mechanism if custom firmware fails

4. **Are there debug or test modes in bootloader?**
   - May allow unsigned firmware in special modes

5. **What triggers DFU mode entry?**
   - Can device be rebooted into DFU manually?

6. **Can application firmware be read from device?**
   - Would eliminate need to find it in official app

Good luck! 🚀

