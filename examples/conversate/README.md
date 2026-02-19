# Conversate Example (Even G2)

This example demonstrates real-time text rendering on Even G2 using the
proprietary Conversate service (`0x0B20`).

Unlike `teleprompter`, this path is optimized for incremental ASR-style
updates (partial → final), mimicking live speech transcription behavior.

---

## Quick Start

From repository root:

```bash
cd examples/conversate
pip install -r requirements.txt

# Display a single sentence
python conversate.py "Hello from Conversate!"

# Demo incremental rendering (ASR-style)
python conversate.py --demo

# Demo with custom timing
python conversate.py --demo --delay 0.6 --min-delay 0.05
```

---

## Service Information

Observed working configuration:

- Service: `0x0B20`
- Frame prefix: `AA 21`
- CRC: CRC16-CCITT-FALSE (calculated over the entire frame excluding the leading `AA 21` and excluding the CRC field itself)
- Write characteristic: `00002760-08c2-11e1-9073-0e8ac72e5401`
- Notify characteristic: `00002760-08c2-11e1-9073-0e8ac72e5402`

This differs from the Teleprompter service and is not interchangeable.

---

## Frame Structure (Observed Working Form)

### Observed Behavior (Firmware v2.0.7.12)

The structure below was derived from empirically captured frames and
verified working packets on Even G2 firmware v2.0.7.12 (Feb 2026).

### ASCII Protocol Diagram

```
+-------------------------------------------------------------+
| AA 21 | seq | len | 01 01 0B 20                            |
+-------------------------------------------------------------+
| 08 05                                                   |
| 10 update_id                                            |
| 3A 22                                                   |
|    0A 1E <30-byte UTF-8 text field>                     |
|    10 flag (00=partial, 01=final)                       |
+-------------------------------------------------------------+
| CRC16-CCITT-FALSE (lo hi)                               |
+-------------------------------------------------------------+
```

Header:

```
AA 21 <seq> <len> 01 01 0B 20
```

Payload:

```
08 05                     # message type = 5
10 <update_id>            # update id (varint)
3a 22                     # nested message (length=0x22)
   0a 1e <30B text>       # fixed 30-byte UTF-8 field
   10 <flag>              # 0x00 = partial, 0x01 = final
```

Followed by:

```
<crc_lo> <crc_hi>
```

---

## Text Field Rules

- Fixed length: 30 bytes
- UTF-8 truncated safely if longer
- Padding:
  - Space (`0x20`) recommended
  - Zero padding (`0x00`) works but not required

---

## Partial / Final Semantics

| Flag | Meaning |
|------|--------|
| `0x00` | Partial update (rewrite bottom line) |
| `0x01` | Finalized line |

### Observed Behavior

- Partial frames overwrite the currently active (bottom) line.
- Final frames commit the line to the device buffer.
- Confirmed on firmware v2.0.7.12.

---

## Line Buffer Behavior

### Observed Behavior (Firmware v2.0.7.12)

Testing on Even G2 firmware v2.0.7.12 (Feb 2026):

- Device retains maximum **2 finalized lines**
- Sending a third finalized line removes the oldest
- Partial updates affect only the most recent line

Example:

```
final: Line 1
final: Line 2
final: Line 3
```

Result:

```
Line 2
Line 3
```

This suggests an internal 2-line rolling buffer.

Behavior verified on a single device (R unit). Additional hardware variants may differ.

### Spec Proposal (Community Discussion)

Proposed abstract behavior for implementation consistency:

- Device maintains N finalized lines (observed N=2 on v2.0.7.12)
- Partial updates modify only the newest line
- Final updates push into a rolling buffer
- Oldest finalized line is dropped when capacity is exceeded

Note: N may vary by firmware version.

---

## Update ID Behavior

- Incrementing `update_id` per frame ensures reliable redraw
- Reusing the same ID may cause frames to be ignored
- Values tested in range `0x41`–`0x7F`
- Appears to be treated as a small varint counter

---

## Timing Considerations

Stable rendering observed with:

```
--delay 0.6
--min-delay 0.05
```

Too-fast bursts may cause dropped updates.

### Line Buffer Verification Command

To reproduce and verify rolling buffer behavior:

```bash
python conversate.py --line-test 3 --delay 0.8
```

Expected result (firmware v2.0.7.12):

- Only the last two finalized lines remain visible.

---

## Design Intent

Conversate is suited for:

- Real-time ASR streaming
- Partial → Final text confirmation
- Rolling subtitle-style display
- Low-latency incremental rendering

This implementation avoids device-specific hardcoded constants.

---

## Status

This implementation is based on reverse-engineering and empirical testing.

Behavior described here is:

- Observed on Even G2 firmware v2.0.7.12 (Feb 2026)
- Not officially documented
- Subject to firmware changes

Contributions and verification from other firmware versions are welcome.