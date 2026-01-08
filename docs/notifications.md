# Notification Protocol

This document describes the full notification format for Even G2 glasses, including message body, title, actions, and timestamps.

## Overview

Notifications are transmitted on a separate BLE characteristic (Handle `0x0021`) from the main G2 protocol. The format follows an ANCS-like (Apple Notification Center Service) structure with field-length-value encoding.

## BLE Characteristics

| Handle | Purpose |
|--------|---------|
| `0x001b` | Notification metadata/control |
| `0x001e` | Notification request |
| `0x0021` | Full notification data |

## Packet Structure

### Full Notification (Handle 0x0021)

```
[00] [NotifID:2 LE] [Type:2 LE] [00 00]
[BundleLen:2 LE] [BundleID:UTF8]
[01] [Len:2 LE] [Title:UTF8]
[02] [Len:2 LE] [Subtitle:UTF8]
[03] [Len:2 LE] [Body:UTF8]
[04] [Len:2 LE] [InternalID:UTF8]
[05] [Len:2 LE] [Timestamp:ISO8601]
[06] [Len:2 LE] [Action1:UTF8]
[07] [Len:2 LE] [Action2:UTF8]
```

### Field Descriptions

| Field | ID | Description |
|-------|-----|-------------|
| NotifID | Header | 2-byte little-endian notification identifier |
| Type | Header | Notification type (0x02 observed for standard notifications) |
| BundleID | - | App bundle identifier (e.g., `com.apple.mobilephone`) |
| Title | 01 | Primary title or sender name |
| Subtitle | 02 | Secondary text (may be empty) |
| Body | 03 | Main notification content, supports emoji/UTF-8 |
| InternalID | 04 | Internal reference ID as string |
| Timestamp | 05 | ISO 8601 format: `YYYYMMDDTHHmmss` |
| Action1 | 06 | Primary action button text |
| Action2 | 07 | Secondary action button text |

### App Name Response

When the app display name is requested:

```
[01] [BundleID:UTF8] [00 00] [07] [Len:2 LE] [DisplayName:UTF8]
```

## Examples

### Incoming Phone Call

```
Raw: 0027020000001500636f6d2e6170706c652e6d6f62696c6570686f6e65
     0111002b31202836363229203234312d36303030
     0209005370616d205269736b
     030d00496e636f6d696e672043616c6c
     0402003133
     050f003230323630313038543132353933
     060600416e73776572
     0707004465636c696e65

Decoded:
  NotifID:   0x0027
  Type:      0x0002
  BundleID:  com.apple.mobilephone
  Title:     +1 (662) 241-6000
  Subtitle:  Spam Risk
  Body:      Incoming Call
  ID:        13
  Timestamp: 20260108T125937
  Action1:   Answer
  Action2:   Decline
```

### Missed Call

```
Decoded:
  NotifID:   0x0028
  BundleID:  com.apple.mobilephone
  Title:     Spam Risk
  Subtitle:  (empty)
  Body:      Missed Call
  ID:        11
  Timestamp: 20260108T125947
  Action1:   Dial
  Action2:   Clear
```

### Location Update (Life360)

```
Decoded:
  NotifID:   0x002f
  BundleID:  com.life360.safetymap
  Title:     Hope
  Subtitle:  (empty)
  Body:      📍 Arrived at Home
  ID:        20
  Timestamp: 20260108T131921
  Action1:   (empty)
  Action2:   Clear
```

## Implementation Notes

### Parsing (Python)

```python
def parse_notification(data: bytes) -> dict:
    """Parse notification from Handle 0x0021"""
    result = {}
    pos = 0

    # Header
    result['notif_id'] = int.from_bytes(data[1:3], 'little')
    result['type'] = int.from_bytes(data[3:5], 'little')
    pos = 6

    # Bundle ID
    bundle_len = int.from_bytes(data[pos:pos+2], 'little')
    pos += 2
    result['bundle_id'] = data[pos:pos+bundle_len].decode('utf-8')
    pos += bundle_len

    # Fields 01-07
    field_names = ['title', 'subtitle', 'body', 'internal_id',
                   'timestamp', 'action1', 'action2']

    for i, name in enumerate(field_names, start=1):
        if pos >= len(data):
            break
        field_id = data[pos]
        if field_id != i:
            continue
        pos += 1
        field_len = int.from_bytes(data[pos:pos+2], 'little')
        pos += 2
        if field_len > 0:
            result[name] = data[pos:pos+field_len].decode('utf-8')
        else:
            result[name] = ''
        pos += field_len

    return result
```

### Swift Implementation

```swift
struct G2Notification {
    let notifId: UInt16
    let bundleId: String
    let title: String
    let subtitle: String
    let body: String
    let timestamp: String
    let action1: String
    let action2: String
}

func parseNotification(data: Data) -> G2Notification? {
    guard data.count > 6 else { return nil }

    let notifId = data.subdata(in: 1..<3).withUnsafeBytes {
        $0.load(as: UInt16.self)
    }

    var pos = 6

    // Parse bundle ID
    let bundleLen = Int(data[pos]) | (Int(data[pos+1]) << 8)
    pos += 2
    let bundleId = String(data: data.subdata(in: pos..<pos+bundleLen), encoding: .utf8) ?? ""
    pos += bundleLen

    // Parse remaining fields...
    // (Similar field-length-value parsing)

    return G2Notification(...)
}
```

## Relationship to G2 Protocol

Notifications received on Handle `0x0021` are forwarded to the glasses display via the G2 protocol Service `0x0401`. The Even app processes the ANCS-like notification and reformats it for the glasses display system.

## Capture Method

Notifications were captured using:
- iOS device with Bluetooth logging profile
- Apple PacketLogger
- Handle filter: `btatt.handle == 0x0021`

## Contributing

If you capture additional notification types (calendar events, messages, etc.), please contribute packet dumps following the format above.
