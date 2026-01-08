# Gesture Callbacks

This document describes gesture detection from Even G2 glasses BLE traffic, including tap, swipe, and long press events.

## Overview

Gestures are transmitted as part of status packets on Service `0x0101`, except for long press which uses Service `0x0D01`. Events are embedded within protobuf-encoded payloads and identified by specific byte patterns.

## Gesture Types

### Tap (Single/Double)

**Service:** `0x0101`
**Pattern:** `320b...06 0801 1202 1001`

```
Raw packet fragment:
...320b...060801120210011803...

Decoded:
  Service: 0x0101 (Status)
  Gesture: Tap
  Counter: Increments with each tap
```

**Important:** Single tap and double tap are **NOT distinguishable** at the protocol level. Both produce identical packets. The Even app likely implements double-tap detection through timing logic in software.

### Swipe Forward

**Service:** `0x0101`
**Pattern:** `320d...08 0801 1204 0801 10XX`

```
Raw packet fragment:
aa12170f01010101...320d...08080112040801100b...

Decoded:
  Service: 0x0101 (Status)
  Gesture: Swipe
  Direction: 0x01 (Forward)
  Counter: 0x0b (11) - increments per gesture
```

The key identifier is `1204 0801` where `0801` indicates forward direction.

### Swipe Backward

**Service:** `0x0101`
**Pattern:** `320d...08 0801 1204 0802 10XX`

```
Raw packet fragment:
aa12170f01010101...320d...08080112040802100c...

Decoded:
  Service: 0x0101 (Status)
  Gesture: Swipe
  Direction: 0x02 (Backward)
  Counter: 0x0c (12) - increments per gesture
```

The key identifier is `1204 0802` where `0802` indicates backward direction.

### Long Press

**Service:** `0x0D01`
**Pattern:** `aa12XX0a01010d0108011a0408011003`

```
Full packet:
aa12XX0a01010d0108011a0408011003YYYY

Decoded:
  Service: 0x0D01 (Acknowledgment/Control)
  Event: Long Press
  Action: Triggers Even AI on-device
```

**Note:** Long press is primarily handled on-device to activate Even AI. The BLE packet serves as a notification to the phone app. In some capture sessions, long press events did not appear in BLE traffic at all, suggesting the glasses may handle them entirely locally when AI mode is active.

## Detection Algorithm

### Pattern Matching (Python)

```python
def detect_gesture(packet_hex: str) -> str | None:
    """Detect gesture type from G2 packet hex string."""

    # Long press (service 0d01)
    if "01010d01" in packet_hex and "1a0408011003" in packet_hex:
        return "long_press"

    # Check for gesture patterns in status packets (service 0101)
    if "320d" in packet_hex:
        if "12040801" in packet_hex:
            return "swipe_forward"
        elif "12040802" in packet_hex:
            return "swipe_backward"

    if "320b" in packet_hex and "08011202" in packet_hex:
        return "tap"

    return None
```

### Swift Implementation

```swift
enum G2Gesture {
    case tap
    case swipeForward
    case swipeBackward
    case longPress
}

func parseGesture(from data: Data) -> G2Gesture? {
    let hex = data.map { String(format: "%02x", $0) }.joined()

    // Long press (service 0d01)
    if hex.contains("01010d01") && hex.contains("1a0408011003") {
        return .longPress
    }

    // Swipe gestures (service 0101, pattern 320d)
    if hex.contains("320d") {
        if hex.contains("12040801") {
            return .swipeForward
        } else if hex.contains("12040802") {
            return .swipeBackward
        }
    }

    // Tap gesture (service 0101, pattern 320b)
    if hex.contains("320b") && hex.contains("08011202") {
        return .tap
    }

    return nil
}
```

## Gesture Counter

Each gesture packet includes a counter byte at position `10XX` that increments with each gesture event. This can be used to:

1. Detect missed gestures (gaps in sequence)
2. Debounce rapid repeated gestures
3. Track gesture frequency for analytics

## Timing Characteristics

From capture analysis:

| Gesture | Typical Packet Delay | Notes |
|---------|---------------------|-------|
| Tap | ~50-100ms | Near-instant response |
| Swipe | ~50-100ms | Near-instant response |
| Long Press | ~500-800ms | Delay for press duration detection |

## Implementation Notes

### Double-Tap Detection

Since single and double taps are identical at the protocol level, implement double-tap detection in your app:

```swift
class GestureHandler {
    private var lastTapTime: Date?
    private let doubleTapThreshold: TimeInterval = 0.3

    func handleTap() {
        let now = Date()

        if let lastTap = lastTapTime,
           now.timeIntervalSince(lastTap) < doubleTapThreshold {
            // Double tap detected
            onDoubleTap()
            lastTapTime = nil
        } else {
            // Schedule single tap (may be cancelled by double tap)
            lastTapTime = now
            DispatchQueue.main.asyncAfter(deadline: .now() + doubleTapThreshold) {
                if self.lastTapTime != nil {
                    self.onSingleTap()
                    self.lastTapTime = nil
                }
            }
        }
    }
}
```

### Glasses Sleep Behavior

The glasses enter sleep mode after approximately 10-15 seconds of inactivity. When sleeping:

- Gesture packets are not transmitted
- Wake the display before expecting gesture events
- Consider implementing a keep-alive mechanism if continuous gesture input is required

## Capture Method

Gestures were captured using:
- iOS device with Bluetooth logging profile
- Apple PacketLogger
- Isolated gesture testing with 5-second intervals between actions
- Handle filter: `btatt.handle == 0x0844` (notify characteristic)

## Contributing

If you discover additional gesture types or patterns (e.g., multi-finger gestures, pressure sensitivity), please contribute packet dumps with timestamps and actions performed.
