# Navigation Protocol

This document describes the turn-by-turn navigation format for Even G2 glasses, including distance, instructions, ETA, and maneuver icons.

## Overview

Navigation data is transmitted on Service `0x0820` (Dashboard & Navigation) via BLE Handle `0x0842`. The format uses protobuf encoding with specific field tags for each navigation element.

## BLE Characteristics

| Handle | Direction | Purpose |
|--------|-----------|---------|
| `0x0842` | Phone → Glasses | Navigation commands (Write) |
| `0x0844` | Glasses → Phone | Acknowledgments (Notify) |
| `0x0864` | Glasses → Phone | Map rendering data |

## Packet Structure

### Navigation Update (Service 0x0820)

```
[AA 21] [Seq] [Len] [01 01] [08 20] [NavPayload...] [CRC:2 LE]
```

### Navigation Payload (Protobuf)

```
Field 08: Navigation state/mode
Field 12: Nested navigation message
  ├─ Field 04 (20): Distance to maneuver ("86 m")
  ├─ Field 1a: Instruction text ("Turn left")
  ├─ Field 22: Time remaining ("7 min")
  ├─ Field 2a: Total distance ("701 m")
  ├─ Field 32: ETA string ("ETA: 13:07")
  ├─ Field 3a: Current speed ("0.0 km/h")
  └─ Field 40: Maneuver icon type
```

### Field Descriptions

| Protobuf Tag | Field | Type | Description |
|--------------|-------|------|-------------|
| `08` | State | varint | Navigation mode (07 = active navigation) |
| `12 04` / `20` | Distance | string | Distance to next maneuver |
| `1a` | Instruction | string | Turn instruction text |
| `22` | TimeRemaining | string | Estimated time to destination |
| `2a` | TotalDistance | string | Total remaining distance |
| `32` | ETA | string | Arrival time (formatted) |
| `3a` | Speed | string | Current speed |
| `40` | IconType | varint | Maneuver icon identifier |

## Example: Full Navigation Packet

### Raw Packet

```
aa21413f0101082008072a39080412043836206d1a095475726e206c6566742205
37206d696e2a05373031206d320a4554413a2031333a30373a08302e30206b6d2f
6840011768
```

### Decoded

```
Header:
  Prefix:     aa21 (write command)
  Sequence:   41
  Length:     3f (63 bytes)
  Packet:     01 01 (single packet)
  Service:    08 20 (Navigation)

Payload:
  State:      08 07 (active navigation)
  Container:  2a 39 (nested message, 57 bytes)

Navigation Fields:
  Distance:    08 04 12 04 "86 m"
  Instruction: 1a 09 "Turn left"
  Time:        22 05 "7 min"
  TotalDist:   2a 05 "701 m"
  ETA:         32 0a "ETA: 13:07"
  Speed:       3a 08 "0.0 km/h"
  Icon:        40 01

CRC: 1768
```

## Icon Types

Based on captured traffic, the `IconType` field (tag `40`) indicates the maneuver type:

| Value | Maneuver |
|-------|----------|
| `01` | Turn left |
| `02` | Turn right (assumed) |
| `03` | Straight/Continue (assumed) |
| `04` | U-turn (assumed) |

*Note: Only `01` (turn left) was directly captured. Other values are inferred from typical navigation patterns.*

## Dashboard Widget

Navigation can also appear as a dashboard widget with simplified data:

```
Service: 0x0820
Subtype: 02 (widget mode vs 07 for active navigation)

Example:
aa213e13010108200802220d080112064f66666963651a01029a79

Decoded:
  Service: 0820
  Mode: 02 (dashboard widget)
  Content: "Office" (destination/calendar location)
```

## Implementation

### Building a Navigation Packet (Python)

```python
import struct

def build_navigation_packet(
    distance: str,
    instruction: str,
    time_remaining: str,
    total_distance: str,
    eta: str,
    speed: str,
    icon_type: int = 1,
    sequence: int = 0
) -> bytes:
    """Build a G2 navigation packet."""

    # Build protobuf payload
    def encode_string(tag: int, value: str) -> bytes:
        data = value.encode('utf-8')
        return bytes([tag, len(data)]) + data

    nav_fields = b''
    nav_fields += bytes([0x08, 0x04])  # Distance container
    nav_fields += encode_string(0x12, distance)
    nav_fields += encode_string(0x1a, instruction)
    nav_fields += encode_string(0x22, time_remaining)
    nav_fields += encode_string(0x2a, total_distance)
    nav_fields += encode_string(0x32, eta)
    nav_fields += encode_string(0x3a, speed)
    nav_fields += bytes([0x40, icon_type])

    # Wrap in container
    payload = bytes([0x08, 0x07, 0x2a, len(nav_fields)]) + nav_fields

    # Build packet header
    service = bytes([0x08, 0x20])
    pkt_info = bytes([0x01, 0x01])  # Single packet
    length = len(pkt_info) + len(service) + len(payload)

    header = bytes([0xaa, 0x21, sequence, length])

    # Calculate CRC (CRC-16/CCITT on payload only)
    full_payload = pkt_info + service + payload
    crc = crc16_ccitt(full_payload)

    return header + full_payload + struct.pack('<H', crc)


def crc16_ccitt(data: bytes) -> int:
    """CRC-16/CCITT calculation."""
    crc = 0xFFFF
    for byte in data:
        crc ^= byte << 8
        for _ in range(8):
            if crc & 0x8000:
                crc = (crc << 1) ^ 0x1021
            else:
                crc <<= 1
            crc &= 0xFFFF
    return crc
```

### Swift Implementation

```swift
struct G2Navigation {
    let distance: String      // "86 m"
    let instruction: String   // "Turn left"
    let timeRemaining: String // "7 min"
    let totalDistance: String // "701 m"
    let eta: String          // "ETA: 13:07"
    let speed: String        // "0.0 km/h"
    let iconType: UInt8      // 1 = left turn

    func buildPacket(sequence: UInt8) -> Data {
        var navFields = Data()

        // Distance container
        navFields.append(contentsOf: [0x08, 0x04])
        navFields.append(encodeString(tag: 0x12, value: distance))
        navFields.append(encodeString(tag: 0x1a, value: instruction))
        navFields.append(encodeString(tag: 0x22, value: timeRemaining))
        navFields.append(encodeString(tag: 0x2a, value: totalDistance))
        navFields.append(encodeString(tag: 0x32, value: eta))
        navFields.append(encodeString(tag: 0x3a, value: speed))
        navFields.append(contentsOf: [0x40, iconType])

        // Wrap in container
        var payload = Data([0x08, 0x07, 0x2a, UInt8(navFields.count)])
        payload.append(navFields)

        // Build packet
        let service = Data([0x08, 0x20])
        let pktInfo = Data([0x01, 0x01])
        let fullPayload = pktInfo + service + payload

        var packet = Data([0xaa, 0x21, sequence, UInt8(fullPayload.count)])
        packet.append(fullPayload)

        // Add CRC
        let crc = crc16CCITT(fullPayload)
        packet.append(contentsOf: [UInt8(crc & 0xFF), UInt8(crc >> 8)])

        return packet
    }

    private func encodeString(tag: UInt8, value: String) -> Data {
        let utf8 = value.utf8
        return Data([tag, UInt8(utf8.count)]) + Data(utf8)
    }
}
```

## Map Rendering

Full map rendering data is transmitted on Handle `0x0864` as bitmap/image data:

- Multiple packets with same sequence, incrementing serial number
- Contains turn arrow overlays and route visualization
- Large payloads (observed: 500+ bytes across multiple packets)

*Full map rendering protocol not yet documented.*

## Integration with Apple Maps

To integrate with Apple Maps on iOS:

1. Use `MKDirections` to get route steps
2. Extract maneuver type, distance, and instructions
3. Convert to G2 navigation format
4. Send packets on `0x0842` characteristic

```swift
func sendNavigationStep(_ step: MKRoute.Step) {
    let nav = G2Navigation(
        distance: formatDistance(step.distance),
        instruction: step.instructions,
        timeRemaining: formatTime(remainingTime),
        totalDistance: formatDistance(remainingDistance),
        eta: formatETA(arrivalTime),
        speed: formatSpeed(currentSpeed),
        iconType: mapManeuverToIcon(step.maneuverType)
    )

    let packet = nav.buildPacket(sequence: nextSequence())
    bleManager.write(packet, to: g2WriteCharacteristic)
}
```

## Capture Method

Navigation data was captured using:
- iOS device with Bluetooth logging profile
- Apple PacketLogger during active Google Maps navigation
- Handle filter: `btatt.handle == 0x0842`

## Contributing

If you capture additional navigation states (rerouting, arrival, highway mode), please contribute packet dumps with context about the navigation scenario.
