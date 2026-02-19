import sys
import asyncio
import binascii
import argparse
from bleak import BleakScanner, BleakClient


# ====== Config (keep unit-agnostic) ======
#
# If you hardcode UUIDs and they are wrong for your unit, nothing will display.
# We therefore auto-detect the best WRITE/NOTIFY characteristics from GATT.
#
WRITE_UUID = None
NOTIFY_UUID = None
NAME_FILTER = "Even"  # Substring to match the device name during scanning

# Preferred pairs (Even proprietary service first, then fallbacks)
PREFERRED_WRITE_NOTIFY_PAIRS = [
    ("00002760-08c2-11e1-9073-0e8ac72e5401", "00002760-08c2-11e1-9073-0e8ac72e5402"),
    ("00002760-08c2-11e1-9073-0e8ac72e0001", "00002760-08c2-11e1-9073-0e8ac72e0002"),
    ("6e400002-b5a3-f393-e0a9-e50e24dcca9e", "6e400003-b5a3-f393-e0a9-e50e24dcca9e"),
]
# ======================================

# ---- Conversate/HUD text update (protobuf-ish payload) ----
# We avoid hardcoding a captured full frame (BASE_HEX) so it can work across units.
# Observed working structure for HUD text updates:
#   service: 0x0B20
#   payload: 08 05 10 <update_id> 3a 22 0a 1e <text:30bytes padded> 10 <flag>
# NOTE: 0x22 and 0x1e are values observed in working frames. We keep them as defaults but expose CLI knobs.

HUD_SERVICE_HI = 0x0B
HUD_SERVICE_LO = 0x20
HUD_TEXT_FIELD_LEN = 0x1E  # 30 bytes fixed field
HUD_EMBEDDED_LEN = 0x22    # observed constant in working frames

# ---- Conversate init frames (captured) ----
INIT_1 = bytes.fromhex(
    "aa212a1801010b20080110351a100801120a0801100118002001280018006362"
)

INIT_2 = bytes.fromhex(
    "aa212d0901010b2008ff0110385200f383"
)
# -----------------------------------------------


def _encode_utf8_fixed(text: str, field_len: int, pad_byte: int) -> bytes:
    """Encode text as UTF-8 but fit into `field_len` bytes.

    - Truncates safely at UTF-8 character boundaries.
    - Pads with `pad_byte` to exactly `field_len` bytes.
    """
    raw = text.encode("utf-8")
    if len(raw) > field_len:
        # truncate safely (avoid splitting multibyte sequences)
        out = bytearray()
        for ch in text:
            b = ch.encode("utf-8")
            if len(out) + len(b) > field_len:
                break
            out += b
        raw = bytes(out)
    if len(raw) < field_len:
        raw = raw + bytes([pad_byte]) * (field_len - len(raw))
    return raw


def _crc16_ccitt_false(data: bytes) -> int:
    """CRC-16/CCITT-FALSE (poly=0x1021, init=0xFFFF, xorout=0x0000)."""
    crc = 0xFFFF
    for byte in data:
        crc ^= byte << 8
        for _ in range(8):
            if crc & 0x8000:
                crc = ((crc << 1) ^ 0x1021) & 0xFFFF
            else:
                crc = (crc << 1) & 0xFFFF
    return crc & 0xFFFF


def build_frame(
    text: str,
    seq: int,
    *,
    pad_byte: int = 0x20,
    tail_flag_value: int = 0x01,
    update_id: int = 0x41,
    service_hi: int = HUD_SERVICE_HI,
    service_lo: int = HUD_SERVICE_LO,
) -> bytes:
    """Build a Conversate/HUD text update frame.

    This example intentionally avoids generated `*_pb2.py` files to stay runnable like
    `examples/teleprompter`. The payload is a protobuf wire-format message that has
    been observed to work on multiple G2 units.

    Wire payload structure (observed):
      08 05                     # type = 5
      10 <update_id>            # update_id (varint)
      3a 22                     # nested message length = 0x22 (34 bytes)
         0a 1e <30 bytes text>  # fixed-length text field (30 bytes)
         10 <flag>              # is_final flag (0 = partial, 1 = final)

    Frame format:
      header(8) = AA 21 <seq> <len=payload+2> 01 01 <service_hi> <service_lo>
      payload   = protobuf wire payload (above)
      crc(2)    = CRC16-CCITT-FALSE over payload only, little-endian

    Note: The length byte includes 2 bytes for the service id (0x0B20), matching
    captured frames. The CRC does NOT include the service bytes.
    """

    # Fixed-size UTF-8 field (30 bytes)
    fixed_text = _encode_utf8_fixed(text, HUD_TEXT_FIELD_LEN, pad_byte)

    # Keep update_id in the single-byte varint range (matches observed behavior)
    update_id &= 0x7F
    tail_flag_value &= 0xFF

    # Hand-built protobuf wire payload (no generated pb2 required)
    payload = bytearray()
    payload += b"\x08\x05"  # field 1 (type) = 5
    payload += b"\x10" + bytes([update_id])  # field 2 (update_id)
    payload += b"\x3a\x22"  # field 7 (len-delimited) length=0x22
    payload += b"\x0a\x1e"  # nested field 1 (text) length=0x1e
    payload += fixed_text
    payload += b"\x10" + bytes([tail_flag_value])  # nested field 2 (is_final)

    header = bytes([
        0xAA,
        0x21,
        seq & 0xFF,
        (len(payload) + 2) & 0xFF,  # +2 for service bytes
        0x01,
        0x01,
        service_hi & 0xFF,
        service_lo & 0xFF,
    ])

    crc = _crc16_ccitt_false(bytes(payload))
    frame = bytearray(header)
    frame += payload
    frame += crc.to_bytes(2, "little")
    return bytes(frame)


def verify_frame_crc(frame: bytes) -> tuple[int, int, bool]:
    """Return (got, want, ok) for CRC16-CCITT-FALSE.

    CRC is computed over the wire payload only (after the 8-byte header),
    and the trailer is little-endian.
    """
    if len(frame) < 10:
        return (0, 0, False)
    payload = frame[8:-2]
    got = _crc16_ccitt_false(payload)
    want = int.from_bytes(frame[-2:], "little")
    return (got, want, got == want)


# Helper to send a sequence of texts (with partial/final flag) with incrementing seq.
async def send_text_sequence(
    client: BleakClient,
    write_uuid: str,
    updates: list[tuple[str, bool]],
    start_seq: int,
    delay_s: float,
    *,
    pad_byte: int,
    min_delay_s: float,
    partial_flag: int,
    final_flag: int,
    start_update_id: int,
    update_id_step: int,
    service_hi: int,
    service_lo: int,
) -> int:
    """Send a sequence of text updates (text, is_final), incrementing seq each time. Returns next seq."""
    seq = start_seq & 0xFF
    update_id = start_update_id & 0x7F
    for t, is_final in updates:
        flag = final_flag if is_final else partial_flag
        print(f"  [tail-flag] value=0x{flag:02x} ({'final' if is_final else 'partial'})")
        print(f"  [update-id] value=0x{update_id:02x}")
        frame = build_frame(
            t,
            seq=seq,
            pad_byte=pad_byte,
            tail_flag_value=flag,
            update_id=update_id,
            service_hi=service_hi,
            service_lo=service_lo,
        )
        print(f"Sending generated frame (seq={seq}) for text: {t!r}")
        print(frame.hex())
        got, want, ok = verify_frame_crc(frame)
        print(f"  [crc] got=0x{got:04x} want=0x{want:04x} ok={ok}")
        chunks = await write_gatt_char_chunked(client, write_uuid, frame, response=False)
        print(f"  wrote {len(frame)} bytes in {chunks} chunk(s)")
        if min_delay_s > 0:
            await asyncio.sleep(min_delay_s)
        await asyncio.sleep(delay_s)
        seq = (seq + 1) & 0xFF
        update_id = (update_id + update_id_step) & 0x7F
    return seq


async def find_even():
    print("Scanning for Even G2...")
    devices = await BleakScanner.discover(timeout=8.0)

    for d in devices:
        if d.name and NAME_FILTER in d.name:
            print(f"Found: {d.name} ({d.address})")
            return d.address

    return None


def notify_handler(sender, data):
    print(f"[NOTIFY] {sender}: {data.hex()}")


def _has_method(obj, name: str) -> bool:
    return callable(getattr(obj, name, None))


def _pick_write_notify_uuids(services) -> tuple[str, str] | tuple[None, None]:
    """Pick best WRITE/NOTIFY characteristic UUIDs from discovered services."""
    available = set()
    for service in services:
        for ch in service.characteristics:
            available.add(ch.uuid.lower())

    for w, n in PREFERRED_WRITE_NOTIFY_PAIRS:
        if w.lower() in available and n.lower() in available:
            return (w, n)

    # last resort: first write-without-response + first notify
    write_candidate = None
    notify_candidate = None
    for service in services:
        for ch in service.characteristics:
            props = set([p.lower() for p in ch.properties])
            if write_candidate is None and ("write-without-response" in props or "write" in props):
                write_candidate = ch.uuid
            if notify_candidate is None and "notify" in props:
                notify_candidate = ch.uuid
    return (write_candidate, notify_candidate)


def _hex(b: bytes) -> str:
    return b.hex()


def _unhex(s: str) -> bytes:
    return bytes.fromhex(s)


def _get_chunk_size(client: BleakClient) -> int:
    """Return a safe GATT write chunk size.

    CoreBluetooth will often accept >20B writes, but on some devices/firmwares
    long writes on a write-without-response characteristic can be dropped.
    Chunking makes behavior consistent.

    ATT payload size is (MTU - 3).
    """
    mtu = getattr(client, "mtu_size", None)
    if isinstance(mtu, int) and mtu > 23:
        return max(20, mtu - 3)
    return 20


async def write_gatt_char_chunked(
    client: BleakClient,
    char_uuid: str,
    data: bytes,
    *,
    response: bool = False,
    inter_chunk_delay_s: float = 0.01,
):
    """Write `data` by splitting into chunks.

    This avoids silent truncation/drops on some stacks when writing >20 bytes
    to write-without-response characteristics.
    """
    chunk_size = _get_chunk_size(client)
    total = len(data)
    off = 0
    n = 0
    while off < total:
        chunk = data[off: off + chunk_size]
        await client.write_gatt_char(char_uuid, chunk, response=response)
        off += len(chunk)
        n += 1
        if off < total:
            await asyncio.sleep(inter_chunk_delay_s)
    return n


async def main():
    parser = argparse.ArgumentParser(description="Send text to Even G2 HUD")
    parser.add_argument("text", nargs="?", help="Text to display")
    parser.add_argument("--demo", action="store_true", help="Send a fixed progressive sequence demo")
    parser.add_argument("--delay", type=float, default=0.6, help="Delay seconds between frames (default: 0.6)")
    parser.add_argument("--pad-zero", action="store_true", help="Pad the fixed-length UTF-8 field with \\x00 instead of spaces")
    parser.add_argument("--min-delay", type=float, default=0.0, help="Additional delay after each write chunked call (default: 0.0)")
    parser.add_argument("--partial-flag", type=lambda s: int(s, 0), default=0x00, help="Tail protobuf flag value for partial updates (default: 0x00)")
    parser.add_argument("--final-flag", type=lambda s: int(s, 0), default=0x01, help="Tail protobuf flag value for final update (default: 0x01)")
    parser.add_argument("--start-update-id", type=lambda s: int(s, 0), default=0x41, help="Start value for update-id field (default: 0x41)")
    parser.add_argument("--update-id-step", type=lambda s: int(s, 0), default=0x01, help="Increment for update-id per frame (default: 0x01)")
    parser.add_argument("--service", default="0x0b20", help="HUD service as hex (default: 0x0b20)")
    parser.add_argument(
        "--line-test",
        type=int,
        default=0,
        help="If >0, send N final lines (Line 1..N) to test multi-line buffer behavior"
    )
    args = parser.parse_args()

    svc = int(args.service, 0)
    service_hi = (svc >> 8) & 0xFF
    service_lo = svc & 0xFF

    if not args.demo and not args.text and not (args.line_test and args.line_test > 0):
        print('Usage: python conversate.py "text to display"')
        print('       python conversate.py --demo')
        print('       python conversate.py --demo --delay 1.0')
        print('       python conversate.py --demo --delay 0.6 --partial-flag 0x00 --final-flag 0x01')
        print('       python conversate.py --demo --delay 0.6 --start-update-id 0x41 --update-id-step 0x01')
        print('       python conversate.py --demo --service 0x0b20 --field-len 0x1e --embedded-len 0x22')
        return

    pad_byte = 0x00 if args.pad_zero else 0x20
    min_delay_s = max(0.0, args.min_delay)

    if args.line_test and args.line_test > 0:
        # Send N final-only lines to test device-side multi-line buffer depth
        updates = [(f"Line {i}", True) for i in range(1, args.line_test + 1)]

    elif args.demo:
        # Two-sentence demo that mimics real ASR behavior:
        # - sentence 1: partials -> final
        # - sentence 2: partials -> final
        updates = [
            ("Hello", False),
            ("Hello Even", False),
            ("Hello Even How", False),
            ("Hello Even How are", False),
            ("Hello Even How are you?", True),

            ("I am fine", False),
            ("I am fine, thanks", False),
            ("I am fine, thanks!", True),
        ]

    else:
        # Single-shot: treat as a final update
        updates = [(args.text, True)]

    address = await find_even()

    if not address:
        print("Even G2 not found.")
        return

    async with BleakClient(address) as client:
        print("Connected.")
        print("MTU:", getattr(client, "mtu_size", None), "chunk_size:", _get_chunk_size(client))

        # --- Fetch GATT services (handle Bleak version differences) ---
        if _has_method(client, "get_services"):
            services = await client.get_services()
        else:
            # some versions populate `client.services` automatically after connect
            services = client.services
            if services is None:
                await asyncio.sleep(0.5)
                services = client.services

        if services is None:
            raise RuntimeError("Could not fetch GATT services from device")

        print("=== SERVICE / CHARACTERISTIC LIST ===")
        for service in services:
            print("SERVICE:", service.uuid)
            for ch in service.characteristics:
                print("  CHAR:", ch.uuid, ch.properties)

        global WRITE_UUID, NOTIFY_UUID
        WRITE_UUID, NOTIFY_UUID = _pick_write_notify_uuids(services)

        if not WRITE_UUID:
            raise RuntimeError("No writable characteristic found")

        print("Selected WRITE_UUID:", WRITE_UUID)
        print("Selected NOTIFY_UUID:", NOTIFY_UUID)

        # Enable notifications (if available)
        if NOTIFY_UUID:
            try:
                await client.start_notify(NOTIFY_UUID, notify_handler)
                print("Notify enabled.")
            except Exception as e:
                print("Notify setup failed (continuing):", e)

        # --- Initialize Conversate mode ---
        try:
            print("Sending INIT_1:", _hex(INIT_1))
            c1 = await write_gatt_char_chunked(client, WRITE_UUID, INIT_1, response=False)
            print(f"  INIT_1 wrote {len(INIT_1)} bytes in {c1} chunk(s)")
            await asyncio.sleep(0.3)

            print("Sending INIT_2:", _hex(INIT_2))
            c2 = await write_gatt_char_chunked(client, WRITE_UUID, INIT_2, response=False)
            print(f"  INIT_2 wrote {len(INIT_2)} bytes in {c2} chunk(s)")
            await asyncio.sleep(0.3)

        except Exception as e:
            print("INIT write failed:", repr(e))

        # Start seq right after INIT_2's sequence (more principled than relying on a captured frame)
        next_seq = (INIT_2[2] + 1) & 0xFF

        try:
            next_seq = await send_text_sequence(
                client,
                WRITE_UUID,
                updates,
                start_seq=next_seq,
                delay_s=args.delay,
                pad_byte=pad_byte,
                min_delay_s=min_delay_s,
                partial_flag=args.partial_flag,
                final_flag=args.final_flag,
                start_update_id=args.start_update_id,
                update_id_step=args.update_id_step,
                service_hi=service_hi,
                service_lo=service_lo,
            )
            print("Sent.")
        except Exception as e:
            print("Generated frame write failed:", repr(e))

        await asyncio.sleep(2)


if __name__ == "__main__":
    asyncio.run(main())
