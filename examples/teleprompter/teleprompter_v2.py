#!/usr/bin/env python3
"""
Even G2 Teleprompter v2 — Display Text + Mic Audio Capture

Connects to BOTH arms of the G2 glasses (dual-BLE), subscribes to all 4
notification channels per arm, authenticates, displays text on the glasses,
and captures microphone audio from the display channel.

AUDIO DISCOVERY (2026-02-27):
    G2 mic audio streams on the DISPLAY notify characteristic (0x6402),
    LEFT arm only — NOT the audio channel (0x7402).
    
    Packets are 205 bytes: 5 × 40-byte LC3 frames + 4 metadata + 1 counter.
    Rate: 20.1 pkts/sec, bitrate ~32 kbps, codec LC3 @ 16kHz 10ms frames.
    
    Dashboard service 07-01 field f3.f1 signals mic state:
        f3.f1=1  →  mic ACTIVE (audio starts ~100-400ms later)
        f3.f1=3  →  mic INACTIVE (audio stops)
    
    Counter (byte[204]) is monotonic across mic ON/OFF gaps — no lost packets.
    
    Mic trigger command is mediated by Even Hub Flutter SDK (bridge.audioControl).
    We cannot trigger mic directly yet, but can capture the stream when active.

Usage:
    python teleprompter_v2.py "Hello world!"
    python teleprompter_v2.py "Line one\\nLine two" --mic
    python teleprompter_v2.py "Long text" --mic --save mic_out
    python teleprompter_v2.py --mic-only --duration 60
    python teleprompter_v2.py "Text" --duration 30 --verbose

Requirements:
    pip install bleak

BLE Architecture:
    G2 glasses are TWO BLE peripherals (Left + Right arm).
    Each exposes 4 services with write + notify characteristics:
      System   0x1001 → 0x0001 (write) / 0x0002 (notify)
      Protocol 0x5450 → 0x5401 (write) / 0x5402 (notify)
      Display  0x6450 → 0x6401 (write) / 0x6402 (notify) ★ carries audio
      Audio    0x7450 → 0x7401 (write) / 0x7402 (notify)   not used for mic
"""

import asyncio
import argparse
import ctypes
import json
import os
import struct
import sys
import time
import wave
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime
from pathlib import Path

try:
    import pyarrow as pa
    import pyarrow.parquet as pq
    HAS_PARQUET = True
except ImportError:
    HAS_PARQUET = False

try:
    from bleak import BleakClient, BleakScanner
except ImportError:
    print("Install bleak: pip install bleak")
    sys.exit(1)


# =============================================================================
# BLE UUIDs
# =============================================================================

UUID_BASE = "00002760-08c2-11e1-9073-0e8ac72e{:04x}"

WRITE_SYSTEM   = UUID_BASE.format(0x0001)
WRITE_PROTOCOL = UUID_BASE.format(0x5401)
WRITE_DISPLAY  = UUID_BASE.format(0x6401)
WRITE_AUDIO    = UUID_BASE.format(0x7401)

NOTIFY_SYSTEM   = UUID_BASE.format(0x0002)
NOTIFY_PROTOCOL = UUID_BASE.format(0x5402)
NOTIFY_DISPLAY  = UUID_BASE.format(0x6402)  # ★ Audio arrives here
NOTIFY_AUDIO    = UUID_BASE.format(0x7402)  # NOT used for mic

SERVICE_NAMES = {
    (0x80, 0x00): "Auth/Sync",
    (0x80, 0x20): "Auth Data",
    (0x80, 0x01): "Auth Response",
    (0x01, 0x01): "Event Stream",
    (0x04, 0x20): "Display Wake",
    (0x06, 0x20): "Teleprompter",
    (0x07, 0x00): "Dashboard ACK",
    (0x07, 0x01): "Dashboard Resp",
    (0x09, 0x01): "DevInfo Response",
    (0x0B, 0x20): "Conversate/Audio",
    (0x0D, 0x01): "Config Response",
    (0x0E, 0x20): "Display Config",
}


# =============================================================================
# ANSI Colors
# =============================================================================

RST  = "\033[0m"
DIM  = "\033[2m"
BOLD = "\033[1m"
RED  = "\033[91m"
GRN  = "\033[92m"
YEL  = "\033[93m"
BLU  = "\033[94m"
MAG  = "\033[95m"
CYN  = "\033[96m"

# Channel UUID → short name mapping for logs
CHANNEL_NAMES = {
    "0002": "system",
    "5402": "protocol",
    "6402": "display",
    "7402": "audio",
    "0001": "system_w",
    "5401": "protocol_w",
    "6401": "display_w",
    "7401": "audio_w",
}


# =============================================================================
# BLE Packet Logger — btsnoop-style full capture
# =============================================================================

class BLELogger:
    """Logs every BLE packet (TX and RX) with timestamps, arm, channel, raw hex.

    Saves:
        out/<ts>/btsnoop.parquet     — columnar Parquet (compact, queryable)
        out/<ts>/btsnoop.jsonl       — one JSON object per packet (fallback)
        out/<ts>/btsnoop.log         — human-readable text log
        out/<ts>/btsnoop.bin         — raw binary packets with 16-byte headers
        out/<ts>/audio_*.bin/wav     — audio recordings
        out/<ts>/session.json        — session summary
    """

    def __init__(self, out_dir: str):
        self.out_dir = Path(out_dir)
        self.out_dir.mkdir(parents=True, exist_ok=True)
        self.start_time = time.time()
        self._packets: list[dict] = []
        self._count = 0

        # Open log files
        self._jsonl = open(self.out_dir / "btsnoop.jsonl", "w")
        self._log = open(self.out_dir / "btsnoop.log", "w")
        self._bin = open(self.out_dir / "btsnoop.bin", "wb")

        # Write bin header (magic + version)
        self._bin.write(b"BTSNOOP_G2\x01\x00")

        self._log.write(f"# G2 BLE Packet Capture\n")
        self._log.write(f"# Started: {datetime.now().isoformat()}\n")
        self._log.write(f"# Format: [elapsed] [dir] [arm] [channel] [size] [hex] [decode]\n")
        self._log.write(f"{'='*120}\n")

    def _elapsed(self) -> float:
        return time.time() - self.start_time

    def log_rx(self, arm: str, channel: str, data: bytes, decode: str = ""):
        """Log an incoming notification (glasses → phone)."""
        self._log_packet("RX", arm, channel, data, decode)

    def log_tx(self, arm: str, channel: str, data: bytes, decode: str = ""):
        """Log an outgoing write (phone → glasses)."""
        self._log_packet("TX", arm, channel, data, decode)

    def _log_packet(self, direction: str, arm: str, channel: str, data: bytes, decode: str):
        elapsed = self._elapsed()
        self._count += 1
        seq = self._count

        # Determine if this is a framed protocol packet
        svc_name = ""
        svc_hex = ""
        if len(data) >= 8 and data[0] == 0xAA:
            svc = (data[6], data[7])
            svc_hex = f"{data[6]:02X}-{data[7]:02X}"
            svc_name = SERVICE_NAMES.get(svc, svc_hex)

        # JSON record
        record = {
            "seq": seq,
            "t": round(elapsed, 6),
            "dir": direction,
            "arm": arm,
            "ch": channel,
            "len": len(data),
            "hex": data.hex(),
            "svc": svc_hex,
            "svc_name": svc_name,
            "decode": decode,
        }
        self._packets.append(record)
        self._jsonl.write(json.dumps(record) + "\n")
        self._jsonl.flush()

        # Human-readable log
        dir_arrow = "←" if direction == "RX" else "→"
        hex_preview = data.hex()[:80]
        if len(data.hex()) > 80:
            hex_preview += "..."
        svc_label = f" [{svc_name}]" if svc_name else ""
        dec_label = f"  // {decode}" if decode else ""
        self._log.write(
            f"[{elapsed:9.4f}] {direction} {dir_arrow} [{arm}] {channel:10s} "
            f"{len(data):4d}B{svc_label}  {hex_preview}{dec_label}\n"
        )
        self._log.flush()

        # Binary: [8B timestamp_us LE][2B len LE][1B dir][1B arm][4B reserved][data]
        ts_us = int(elapsed * 1_000_000)
        hdr = struct.pack("<QHBBxxxx",
            ts_us,
            len(data),
            0x00 if direction == "RX" else 0x01,
            ord('L') if arm == "L" else ord('R') if arm == "R" else 0x3F,
        )
        self._bin.write(hdr + data)
        self._bin.flush()

    def save_parquet(self):
        """Save packets as a Parquet file (compact columnar format).

        Parquet is ~5-10× smaller than JSONL for large captures and
        supports efficient column-based queries via pandas/DuckDB.
        """
        if not HAS_PARQUET:
            return False
        if not self._packets:
            return False

        # Build columnar arrays from packet records
        cols = {
            "seq":      pa.array([p["seq"] for p in self._packets], type=pa.uint32()),
            "t":        pa.array([p["t"] for p in self._packets], type=pa.float64()),
            "dir":      pa.array([p["dir"] for p in self._packets], type=pa.string()),
            "arm":      pa.array([p["arm"] for p in self._packets], type=pa.string()),
            "ch":       pa.array([p["ch"] for p in self._packets], type=pa.string()),
            "len":      pa.array([p["len"] for p in self._packets], type=pa.uint16()),
            "hex":      pa.array([p["hex"] for p in self._packets], type=pa.string()),
            "svc":      pa.array([p["svc"] for p in self._packets], type=pa.string()),
            "svc_name": pa.array([p["svc_name"] for p in self._packets], type=pa.string()),
            "decode":   pa.array([p["decode"] for p in self._packets], type=pa.string()),
        }
        table = pa.table(cols)
        out_path = self.out_dir / "btsnoop.parquet"
        pq.write_table(table, out_path, compression="zstd")
        return True

    def close(self):
        """Flush and close all log files. Writes Parquet if available."""
        # Write compact Parquet before closing
        parquet_ok = self.save_parquet()
        self._jsonl.close()
        self._log.close()
        self._bin.close()
        if parquet_ok:
            pq_path = self.out_dir / "btsnoop.parquet"
            pq_size = pq_path.stat().st_size
            jsonl_path = self.out_dir / "btsnoop.jsonl"
            jsonl_size = jsonl_path.stat().st_size if jsonl_path.exists() else 0
            ratio = f"{jsonl_size / pq_size:.1f}×" if pq_size > 0 else "?"
            print(f"  {GRN}Parquet:{RST} {BOLD}{pq_path}{RST} "
                  f"({pq_size:,}B vs {jsonl_size:,}B JSONL = {ratio} smaller)")

    @property
    def count(self) -> int:
        return self._count

    @property
    def packets(self) -> list[dict]:
        return self._packets

    def write_summary(self, session_data: dict):
        """Write session.json summary (and dashboard.parquet if available)."""
        session_data["total_logged_packets"] = self._count
        session_data["parquet"] = HAS_PARQUET
        with open(self.out_dir / "session.json", "w") as f:
            json.dump(session_data, f, indent=2, default=str)

        # Save dashboard log as Parquet too (if there are entries)
        dash = session_data.get("dashboard_log", [])
        if HAS_PARQUET and dash:
            try:
                dcols = {
                    "t":    pa.array([d.get("t", 0.0) for d in dash], type=pa.float64()),
                    "page": pa.array([str(d.get("page", "")) for d in dash], type=pa.string()),
                    "mic":  pa.array([d.get("mic", "") for d in dash], type=pa.string()),
                    "f3":   pa.array([json.dumps(d.get("f3", {}), default=str) for d in dash], type=pa.string()),
                }
                pq.write_table(pa.table(dcols), self.out_dir / "dashboard.parquet", compression="zstd")
            except Exception:
                pass  # non-critical


# =============================================================================
# CRC-16/CCITT
# =============================================================================

def crc16_ccitt(data: bytes, init: int = 0xFFFF) -> int:
    crc = init
    for byte in data:
        crc ^= byte << 8
        for _ in range(8):
            crc = ((crc << 1) ^ 0x1021) if crc & 0x8000 else (crc << 1)
            crc &= 0xFFFF
    return crc


def add_crc(packet: bytes) -> bytes:
    """Append CRC-16 over payload (bytes after 8-byte header), little-endian."""
    crc = crc16_ccitt(packet[8:])
    return packet + bytes([crc & 0xFF, (crc >> 8) & 0xFF])


# =============================================================================
# Protobuf Helpers
# =============================================================================

def encode_varint(value: int) -> bytes:
    result = []
    while value > 0x7F:
        result.append((value & 0x7F) | 0x80)
        value >>= 7
    result.append(value & 0x7F)
    return bytes(result)


def decode_varint(data, offset):
    result = 0
    shift = 0
    while offset < len(data):
        b = data[offset]
        result |= (b & 0x7F) << shift
        offset += 1
        if not (b & 0x80):
            break
        shift += 7
    return result, offset


def decode_protobuf_fields(data):
    """Decode protobuf into {field_number: value} dict."""
    fields = {}
    offset = 0
    while offset < len(data):
        try:
            tag, offset = decode_varint(data, offset)
        except:
            break
        fnum = tag >> 3
        wtype = tag & 0x07
        if fnum == 0:
            break
        if wtype == 0:
            val, offset = decode_varint(data, offset)
            fields[fnum] = val
        elif wtype == 2:
            length, offset = decode_varint(data, offset)
            if offset + length > len(data):
                break
            fields[fnum] = data[offset:offset + length]
            offset += length
        elif wtype == 5:
            if offset + 4 <= len(data):
                fields[fnum] = struct.unpack('<I', data[offset:offset + 4])[0]
            offset += 4
        elif wtype == 1:
            if offset + 8 <= len(data):
                fields[fnum] = struct.unpack('<Q', data[offset:offset + 8])[0]
            offset += 8
        else:
            break
    return fields


# =============================================================================
# Packet Builder
# =============================================================================

class PacketBuilder:
    """Builds G2 protocol packets with auto-incrementing sequence."""

    def __init__(self, start_seq=1, start_msg_id=0x14):
        self.seq = start_seq
        self.msg_id = start_msg_id

    def _next_seq(self):
        s = self.seq
        self.seq = (self.seq + 1) & 0xFF
        return s

    def _next_msg_id(self):
        m = self.msg_id
        self.msg_id += 1
        return m

    def build(self, svc_hi: int, svc_lo: int, payload: bytes) -> bytes:
        """Build a framed packet: [AA][21][seq][len][01][01][svc_hi][svc_lo][payload][crc16]"""
        seq = self._next_seq()
        header = bytes([0xAA, 0x21, seq, len(payload) + 2, 0x01, 0x01, svc_hi, svc_lo])
        return add_crc(header + payload)

    # ── Authentication ────────────────────────────────────────────────────

    def build_auth_sequence(self) -> list[bytes]:
        """Build the 7-packet auth handshake."""
        timestamp = int(time.time())
        ts_varint = encode_varint(timestamp)
        txid = bytes([0xE8, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x01])

        packets = []

        packets.append(add_crc(bytes([
            0xAA, 0x21, self._next_seq(), 0x0C, 0x01, 0x01, 0x80, 0x00,
            0x08, 0x04, 0x10, 0x0C, 0x1A, 0x04, 0x08, 0x01, 0x10, 0x04
        ])))

        packets.append(add_crc(bytes([
            0xAA, 0x21, self._next_seq(), 0x0A, 0x01, 0x01, 0x80, 0x20,
            0x08, 0x05, 0x10, 0x0E, 0x22, 0x02, 0x08, 0x02
        ])))

        payload3 = (bytes([0x08, 0x80, 0x01, 0x10, 0x0F, 0x82, 0x08, 0x11, 0x08])
                     + ts_varint + bytes([0x10]) + txid)
        packets.append(add_crc(bytes([
            0xAA, 0x21, self._next_seq(), len(payload3) + 2, 0x01, 0x01, 0x80, 0x20
        ]) + payload3))

        packets.append(add_crc(bytes([
            0xAA, 0x21, self._next_seq(), 0x0C, 0x01, 0x01, 0x80, 0x00,
            0x08, 0x04, 0x10, 0x10, 0x1A, 0x04, 0x08, 0x01, 0x10, 0x04
        ])))
        packets.append(add_crc(bytes([
            0xAA, 0x21, self._next_seq(), 0x0C, 0x01, 0x01, 0x80, 0x00,
            0x08, 0x04, 0x10, 0x11, 0x1A, 0x04, 0x08, 0x01, 0x10, 0x04
        ])))

        packets.append(add_crc(bytes([
            0xAA, 0x21, self._next_seq(), 0x0A, 0x01, 0x01, 0x80, 0x20,
            0x08, 0x05, 0x10, 0x12, 0x22, 0x02, 0x08, 0x01
        ])))

        payload7 = (bytes([0x08, 0x80, 0x01, 0x10, 0x13, 0x82, 0x08, 0x11, 0x08])
                     + ts_varint + bytes([0x10]) + txid)
        packets.append(add_crc(bytes([
            0xAA, 0x21, self._next_seq(), len(payload7) + 2, 0x01, 0x01, 0x80, 0x20
        ]) + payload7))

        return packets

    # ── Heartbeat ─────────────────────────────────────────────────────────

    def build_heartbeat(self) -> bytes:
        """SyncMessage type=0x0E — keeps BLE connection alive."""
        ts_varint = encode_varint(int(time.time()))
        txid = bytes([0xE8, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x01])
        payload = bytes([0x08, 0x0E, 0x10, 0x14, 0x82, 0x08, 0x11, 0x08]) + ts_varint + bytes([0x10]) + txid
        return self.build(0x80, 0x00, payload)

    # ── Display Config ────────────────────────────────────────────────────

    def build_display_config(self) -> bytes:
        """Service 0x0E-20: Display configuration."""
        config = bytes.fromhex(
            "0801121308021090" "4E1D00E094442500" "000000280030001213"
            "0803100D0F1D0040" "8D44250000000028" "0030001212080410"
            "001D0000884225" "00000000280030" "001212080510001D"
            "00009242250000" "A242280030001212" "080610001D0000C6"
            "42250000C4422800" "30001800"
        )
        msg_id = self._next_msg_id()
        payload = bytes([0x08, 0x02, 0x10]) + encode_varint(msg_id) + bytes([0x22, 0x6A]) + config
        return self.build(0x0E, 0x20, payload)

    # ── Teleprompter Init ─────────────────────────────────────────────────

    def build_teleprompter_init(self, total_lines: int = 10, manual: bool = True) -> bytes:
        """Service 0x06-20 type=1: Initialize teleprompter."""
        mode = 0x00 if manual else 0x01
        content_height = max(1, (total_lines * 2665) // 140)

        display = (
            bytes([0x08, 0x01, 0x10, 0x00, 0x18, 0x00, 0x20, 0x8B, 0x02])
            + bytes([0x28]) + encode_varint(content_height)
            + bytes([0x30, 0xE6, 0x01])
            + bytes([0x38, 0x8E, 0x0A])
            + bytes([0x40, 0x05, 0x48, mode])
        )

        msg_id = self._next_msg_id()
        settings = bytes([0x08, 0x01, 0x12, len(display)]) + display
        payload = bytes([0x08, 0x01, 0x10]) + encode_varint(msg_id) + bytes([0x1A, len(settings)]) + settings
        return self.build(0x06, 0x20, payload)

    # ── Content Page ──────────────────────────────────────────────────────

    def build_content_page(self, page_num: int, text: str) -> bytes:
        """Service 0x06-20 type=3: Content page."""
        text_bytes = ("\n" + text).encode('utf-8')

        inner = (
            bytes([0x08]) + encode_varint(page_num)
            + bytes([0x10, 0x0A])
            + bytes([0x1A]) + encode_varint(len(text_bytes)) + text_bytes
        )

        msg_id = self._next_msg_id()
        content = bytes([0x2A]) + encode_varint(len(inner)) + inner
        payload = bytes([0x08, 0x03, 0x10]) + encode_varint(msg_id) + content
        return self.build(0x06, 0x20, payload)

    # ── Marker / Sync ────────────────────────────────────────────────────

    def build_marker(self) -> bytes:
        """Service 0x06-20 type=255: Mid-stream marker."""
        msg_id = self._next_msg_id()
        payload = bytes([0x08, 0xFF, 0x01, 0x10]) + encode_varint(msg_id) + bytes([0x6A, 0x04, 0x08, 0x00, 0x10, 0x06])
        return self.build(0x06, 0x20, payload)

    def build_sync(self) -> bytes:
        """Service 0x80-00 type=14: Sync/trigger."""
        msg_id = self._next_msg_id()
        payload = bytes([0x08, 0x0E, 0x10]) + encode_varint(msg_id) + bytes([0x6A, 0x00])
        return self.build(0x80, 0x00, payload)

    # ── Audio Control (experimental) ──────────────────────────────────────

    def build_audio_control(self, enable: bool) -> list[bytes]:
        """Build multiple mic trigger attempts.

        The exact BLE command to trigger the mic is not yet known.
        The Flutter SDK mediates via bridge.audioControl(true/false).
        We try several approaches; the mic may also be activated via
        Even Hub or by exiting quiet mode on the glasses.

        Returns a list of (description, packet, target_channel, arm_hint) tuples.
        """
        flag = 0x01 if enable else 0x00
        attempts = []

        # 1. AudioControl{isOpen} on Conversate service (0x0B-20)
        attempts.append((
            "AudioControl on 0x0B-20",
            self.build(0x0B, 0x20, bytes([0x08, flag])),
            "protocol", "both"
        ))

        # 2. Dashboard page request with f3.f1=1 (seen before audio starts)
        attempts.append((
            "Dashboard f3.f1=1 on 0x07-20",
            self.build(0x07, 0x20, bytes([0x08, 0x01, 0x10, 0x05, 0x1A, 0x02, 0x08, flag])),
            "protocol", "both"
        ))

        # 3. Method=9 AudioControl wrapper (EvenAppMethod style)
        attempts.append((
            "Method=9 AudioControl",
            self.build(0x0B, 0x20, bytes([0x08, 0x09, 0x12, 0x02, 0x08, flag])),
            "protocol", "both"
        ))

        # 4. Raw G1-style [0x0E, 0x01] on audio write (0x7401)
        attempts.append((
            "G1-style on 0x7401",
            bytes([0x0E, flag]),
            "audio", "left"  # mic is on left arm
        ))

        # 5. Display config with mic flag (0x0E-20)
        attempts.append((
            "DispConfig f1=1 on 0x0E-20",
            self.build(0x0E, 0x20, bytes([0x08, flag])),
            "protocol", "both"
        ))

        return attempts


# =============================================================================
# Text Formatter
# =============================================================================

def format_text(text: str, chars_per_line: int = 25, lines_per_page: int = 10) -> list[str]:
    """Word-wrap text into pages of lines."""
    text = text.replace("\\n", "\n")

    wrapped = []
    for line in text.split("\n"):
        if not line.strip():
            wrapped.append("")
            continue
        words = line.split()
        current = ""
        for word in words:
            if len(current) + len(word) + 1 > chars_per_line:
                if current:
                    wrapped.append(current.strip())
                current = word + " "
            else:
                current += word + " "
        if current.strip():
            wrapped.append(current.strip())

    if not wrapped:
        wrapped = [text]

    while len(wrapped) < lines_per_page:
        wrapped.append(" ")

    pages = []
    for i in range(0, len(wrapped), lines_per_page):
        page_lines = wrapped[i:i + lines_per_page]
        while len(page_lines) < lines_per_page:
            page_lines.append(" ")
        pages.append("\n".join(page_lines) + " \n")

    while len(pages) < 14:
        pages.append("\n".join([" "] * lines_per_page) + " \n")

    return pages


# =============================================================================
# Audio Collector — LC3 stream from display channel
# =============================================================================

AUDIO_PKT_SIZE = 205       # Fixed: 204 data + 1 counter
LC3_FRAME_SIZE = 40         # 40 bytes per LC3 frame
LC3_FRAMES_PER_PKT = 5     # 5 frames per BLE packet
LC3_FRAME_MS = 10           # 10ms per frame
AUDIO_SAMPLE_RATE = 16000   # 16 kHz
AUDIO_BITRATE_BPS = 32000   # 32 kbps


def is_audio_packet(data: bytes) -> bool:
    """Detect if a display-channel notification is mic audio.

    Audio packets are:
    - Exactly 205 bytes
    - No 0xAA framing header (raw data, not protocol-framed)
    - High entropy (compressed LC3 codec output)
    - Byte[204] = sequential counter
    """
    return len(data) == AUDIO_PKT_SIZE and data[0] != 0xAA


class AudioCollector:
    """Collects LC3 compressed audio from the display channel.

    Audio format (confirmed by binary analysis):
        Packet:  205 bytes total
        Data:    Bytes[0..199]  = 5 × 40-byte LC3 frames (200 bytes)
        Meta:    Bytes[200..203] = metadata/flags
                   [200] variable, [201] always 0x00,
                   [202] flags (5 unique values), [203] mostly 0xFF
        Counter: Byte[204] = sequential packet counter (0x00..0xFF, wraps)

        Rate: 20.1 packets/sec  →  5 × 10ms = 50ms audio per packet
        Codec: LC3 @ 32 kbps, 16 kHz, 10ms frames
        Channel: LEFT arm display notify (0x6402)
    """

    def __init__(self):
        self.packets: list[tuple[float, bytes]] = []  # (timestamp, raw 205-byte packet)
        self.start_time: float | None = None
        self.last_seq: int = -1
        self.dropped: int = 0
        self.mic_active: bool = False  # tracked via dashboard f3.f1

    @property
    def count(self) -> int:
        return len(self.packets)

    @property
    def data_bytes(self) -> int:
        """Total bytes of LC3 codec data (excluding counters and metadata)."""
        return self.count * LC3_FRAME_SIZE * LC3_FRAMES_PER_PKT

    @property
    def duration_sec(self) -> float:
        """Estimated audio duration from packet count (50ms per packet)."""
        return self.count * LC3_FRAMES_PER_PKT * LC3_FRAME_MS / 1000.0

    @property
    def wall_duration_sec(self) -> float:
        """Wall-clock duration from first to last packet."""
        if len(self.packets) < 2:
            return 0.0
        return self.packets[-1][0] - self.packets[0][0]

    def on_audio_data(self, elapsed: float, data: bytes, arm: str) -> bool:
        """Process an incoming audio packet. Returns True if accepted."""
        if not is_audio_packet(data):
            return False

        seq = data[204]

        if self.start_time is None:
            self.start_time = elapsed
            self.last_seq = (seq - 1) & 0xFF

        # Check for dropped packets via sequential counter
        expected = (self.last_seq + 1) & 0xFF
        if seq != expected and self.last_seq >= 0:
            gap = (seq - expected) & 0xFF
            self.dropped += gap
        self.last_seq = seq

        self.packets.append((elapsed, bytes(data)))
        return True

    def save_lc3_bin(self, path: str):
        """Save raw LC3 frames to binary file (counter + metadata stripped).

        Each packet contributes 200 bytes (5 × 40-byte LC3 frames).
        The metadata bytes [200..203] and counter byte [204] are stripped.
        """
        if not self.packets:
            return
        with open(path, "wb") as f:
            for _, data in self.packets:
                f.write(data[:LC3_FRAME_SIZE * LC3_FRAMES_PER_PKT])

    def save_full_bin(self, path: str):
        """Save full 205-byte packets (including metadata + counter)."""
        if not self.packets:
            return
        with open(path, "wb") as f:
            for _, data in self.packets:
                f.write(data)

    def save_raw_codec(self, path: str):
        """Save 204-byte codec data per packet (metadata kept, counter stripped)."""
        if not self.packets:
            return
        with open(path, "wb") as f:
            for _, data in self.packets:
                f.write(data[:204])

    def summary(self) -> str:
        """Human-readable capture summary."""
        if not self.packets:
            return "No audio captured"

        lines = [
            f"Packets:   {self.count} ({self.dropped} dropped)",
            f"LC3 data:  {self.data_bytes:,} bytes",
            f"Duration:  {self.duration_sec:.1f}s (codec) / {self.wall_duration_sec:.1f}s (wall)",
            f"Rate:      {self.count / self.wall_duration_sec:.1f} pkts/sec" if self.wall_duration_sec > 0 else "",
            f"Bitrate:   ~{AUDIO_BITRATE_BPS / 1000:.0f} kbps (LC3 @ {AUDIO_SAMPLE_RATE}Hz, {LC3_FRAME_MS}ms frames)",
            f"Counter:   last={self.last_seq}",
        ]
        return "\n".join(l for l in lines if l)


# =============================================================================
# G2 Glass Connection
# =============================================================================

class G2Connection:
    """Manages dual-arm BLE connection to Even G2 glasses."""

    def __init__(self, verbose: bool = False, logger: BLELogger | None = None):
        self.left_client: BleakClient | None = None
        self.right_client: BleakClient | None = None
        self.builder = PacketBuilder()
        self.verbose = verbose
        self.logger = logger
        self.audio = AudioCollector()          # per-recording (may be reset)
        self._session_audio = AudioCollector()  # session-wide (NEVER reset)
        self.packet_count = 0
        self.start_time = datetime.now()
        self.mic_state: str = "unknown"  # "active", "inactive", "unknown"
        self._dashboard_log: list[dict] = []

    # ── Notification Handlers ─────────────────────────────────────────────

    def _elapsed(self) -> float:
        return (datetime.now() - self.start_time).total_seconds()

    def _make_display_handler(self, arm: str):
        """Display channel handler — detects and captures audio packets."""
        def handler(sender, data: bytearray):
            self.packet_count += 1
            elapsed = self._elapsed()
            raw = bytes(data)

            # Always feed session-wide collector (never reset)
            self._session_audio.on_audio_data(elapsed, raw, arm)

            if self.audio.on_audio_data(elapsed, raw, arm):
                # Audio packet accepted (per-recording collector)
                n = self._session_audio.count  # use session count for display
                decode_str = f"AUDIO pkt#{n} seq={data[204]} meta={data[200:204].hex()}"
                if self.logger:
                    self.logger.log_rx(arm, "display", raw, decode_str)
                if n == 1:
                    print(f"\n  {MAG}{BOLD}{'═'*56}{RST}")
                    print(f"  {MAG}{BOLD}★ AUDIO STREAM DETECTED at {elapsed:.1f}s [{arm}] ★{RST}")
                    print(f"  {MAG}{BOLD}  Channel: display (0x6402), {AUDIO_PKT_SIZE}B packets{RST}")
                    print(f"  {MAG}{BOLD}  Codec: LC3 32kbps 16kHz, 5×{LC3_FRAME_SIZE}B frames/pkt{RST}")
                    print(f"  {MAG}{BOLD}{'═'*56}{RST}\n")
                elif n % 20 == 0:
                    dur = elapsed - (self._session_audio.start_time or elapsed)
                    print(f"  {MAG}♪ {n} pkts, {dur:.1f}s, "
                          f"{self._session_audio.data_bytes:,}B LC3, "
                          f"dropped={self._session_audio.dropped}{RST}")
            else:
                # Regular display data (not audio) — ALWAYS log
                decode_str = ""
                if len(data) >= 8 and data[0] == 0xAA:
                    svc = (data[6], data[7])
                    decode_str = SERVICE_NAMES.get(svc, f"svc={data[6]:02X}-{data[7]:02X}")
                else:
                    decode_str = f"non-framed {len(data)}B first={data[0]:02X}" if data else "empty"
                if self.logger:
                    self.logger.log_rx(arm, "display", raw, decode_str)
                # Print to console
                print(f"  {BLU}[{elapsed:7.1f}s] [{arm}] DISPLAY {len(data)}B  {decode_str}  {data.hex()[:60]}{RST}")
        return handler

    def _make_protocol_handler(self, arm: str):
        """Protocol channel handler — tracks auth, events, dashboard mic state."""
        def handler(sender, data: bytearray):
            self.packet_count += 1
            elapsed = self._elapsed()
            raw = bytes(data)
            decode_str = ""

            if len(data) >= 8 and data[0] == 0xAA:
                svc = (data[6], data[7])
                name = SERVICE_NAMES.get(svc, f"0x{data[6]:02X}-{data[7]:02X}")
                payload = data[8:-2] if len(data) > 10 else b""
                decode_str = name

                # Dashboard — track mic state via f3.f1
                if svc == (0x07, 0x01) and payload:
                    fields = decode_protobuf_fields(payload)
                    f3_raw = fields.get(3, b"")
                    f3 = decode_protobuf_fields(f3_raw) if isinstance(f3_raw, (bytes, bytearray)) else {}
                    f3_f1 = f3.get(1, None)

                    old_state = self.mic_state
                    if f3_f1 == 1:
                        self.mic_state = "active"
                    elif f3_f1 == 3:
                        self.mic_state = "inactive"

                    page = fields.get(2, "?")
                    self._dashboard_log.append({
                        "t": elapsed, "page": page, "f3": f3,
                        "mic": self.mic_state
                    })

                    decode_str = f"Dashboard p{page} f3.f1={f3_f1} mic={self.mic_state}"
                    for k, v in sorted(fields.items()):
                        if isinstance(v, (bytes, bytearray)):
                            decode_str += f" f{k}={decode_protobuf_fields(v)}"
                        else:
                            decode_str += f" f{k}={v}"

                    state_icon = {
                        "active": f"{GRN}● MIC ON{RST}",
                        "inactive": f"{RED}○ MIC OFF{RST}",
                    }.get(self.mic_state, f"{DIM}? UNKNOWN{RST}")

                    if self.mic_state != old_state or self.verbose:
                        print(f"  {CYN}[{elapsed:7.1f}s] [{arm}] Dashboard p{page} "
                              f"f3.f1={f3_f1}  {state_icon}{RST}")

                # Event stream
                elif svc == (0x01, 0x01) and payload:
                    fields = decode_protobuf_fields(payload)
                    decode_str = f"Event: {fields}"
                    print(f"  {RED}{BOLD}★ EVENT [{elapsed:7.1f}s] [{arm}]{RST}")
                    for k, v in sorted(fields.items()):
                        if isinstance(v, (bytes, bytearray)):
                            sub = decode_protobuf_fields(v)
                            print(f"    f{k}: {sub}")
                        else:
                            print(f"    f{k}: {v}")

                # ALL other protocol packets — always print now
                else:
                    if payload:
                        try:
                            fields = decode_protobuf_fields(payload)
                            decode_str = f"{name}: {fields}"
                        except:
                            decode_str = name
                    print(f"  {DIM}[{elapsed:7.1f}s] [{arm}] {name:18s} {len(data)}B  {payload.hex()[:60]}{RST}")
            else:
                decode_str = f"non-framed {len(data)}B"
                print(f"  {DIM}[{elapsed:7.1f}s] [{arm}] PROTO-RAW {len(data)}B  {data.hex()[:60]}{RST}")

            if self.logger:
                self.logger.log_rx(arm, "protocol", raw, decode_str)
        return handler

    def _make_audio_handler(self, arm: str):
        """Audio channel (0x7402) — monitor only, mic doesn't use this."""
        def handler(sender, data: bytearray):
            self.packet_count += 1
            elapsed = self._elapsed()
            raw = bytes(data)
            decode_str = f"AUDIO_CH {len(data)}B"
            if self.logger:
                self.logger.log_rx(arm, "audio", raw, decode_str)
            # This would be surprising — log it prominently
            print(f"\n  {MAG}{BOLD}★★ AUDIO CHANNEL [{elapsed:7.1f}s] [{arm}] "
                  f"{len(data)}B ★★{RST}  {data.hex()[:80]}")
        return handler

    def _make_system_handler(self, arm: str):
        """System channel (0x0002) — always log to file, console if verbose."""
        def handler(sender, data: bytearray):
            self.packet_count += 1
            elapsed = self._elapsed()
            raw = bytes(data)
            decode_str = ""
            if len(data) >= 8 and data[0] == 0xAA:
                svc = (data[6], data[7])
                decode_str = SERVICE_NAMES.get(svc, f"svc={data[6]:02X}-{data[7]:02X}")
            if self.logger:
                self.logger.log_rx(arm, "system", raw, decode_str)
            if self.verbose:
                print(f"  {DIM}[{elapsed:7.1f}s] [{arm}] SYSTEM {len(data)}B  {decode_str}  {data.hex()[:40]}{RST}")
        return handler

    # ── Connection ────────────────────────────────────────────────────────

    async def scan(self) -> tuple:
        """Scan for G2 glasses, return (left_device, right_device)."""
        print(f"\n  Scanning for Even G2 glasses...")
        devices = await BleakScanner.discover(timeout=10.0)
        g2 = [d for d in devices if d.name and "G2" in d.name]

        if not g2:
            print(f"  {RED}No G2 devices found! Make sure glasses are on.{RST}")
            return None, None

        for d in g2:
            lr = "L" if "_L_" in (d.name or "") else "R" if "_R_" in (d.name or "") else "?"
            print(f"  Found: {d.name}  [{lr}]")

        left = next((d for d in g2 if "_L_" in (d.name or "")), None)
        right = next((d for d in g2 if "_R_" in (d.name or "")), None)

        if not left and not right:
            return g2[0], None

        return left, right

    async def connect(self, left_dev, right_dev) -> bool:
        """Connect to one or both arms, subscribe all channels."""
        self.start_time = datetime.now()

        async def _connect_arm(device, label) -> BleakClient | None:
            if device is None:
                return None
            print(f"\n  Connecting {label} arm: {BOLD}{device.name}{RST}")
            client = BleakClient(device)
            await client.connect()
            if not client.is_connected:
                print(f"    {RED}Failed!{RST}")
                return None
            print(f"    {GRN}Connected!{RST} MTU={client.mtu_size}")

            channels = [
                ("system",   NOTIFY_SYSTEM,   self._make_system_handler(label)),
                ("protocol", NOTIFY_PROTOCOL, self._make_protocol_handler(label)),
                ("display",  NOTIFY_DISPLAY,  self._make_display_handler(label)),
                ("audio",    NOTIFY_AUDIO,    self._make_audio_handler(label)),
            ]
            ok = 0
            for name, uuid, cb in channels:
                try:
                    await client.start_notify(uuid, cb)
                    ok += 1
                except Exception as e:
                    if self.verbose:
                        print(f"    {DIM}✗ {name}: {e}{RST}")
            print(f"    Subscribed {ok}/4 channels")
            return client

        self.left_client = await _connect_arm(left_dev, "L")
        self.right_client = await _connect_arm(right_dev, "R")

        if not self.left_client and not self.right_client:
            print(f"\n  {RED}No connections!{RST}")
            return False

        arms = []
        if self.left_client:
            arms.append("L")
        if self.right_client:
            arms.append("R")
        print(f"\n  {GRN}Connected to {'+'.join(arms)} arm(s){RST}")
        return True

    async def disconnect(self):
        """Disconnect both arms."""
        for client in [self.left_client, self.right_client]:
            if client and client.is_connected:
                try:
                    await client.disconnect()
                except:
                    pass

    # ── Write Helpers ─────────────────────────────────────────────────────

    async def _write(self, char_uuid: str, data: bytes, target: str = "both"):
        """Write to one or both arms.

        target: "both", "left", "right"
        """
        # Determine channel name from UUID
        uuid_suffix = char_uuid.split("0e8ac72e")[-1].rstrip("}") if "0e8ac72e" in char_uuid else "?"
        ch_name = CHANNEL_NAMES.get(uuid_suffix, uuid_suffix)

        clients = []
        arm_labels = []
        if target in ("both", "left") and self.left_client and self.left_client.is_connected:
            clients.append(self.left_client)
            arm_labels.append("L")
        if target in ("both", "right") and self.right_client and self.right_client.is_connected:
            clients.append(self.right_client)
            arm_labels.append("R")
        if not clients:
            # Fallback to whatever is connected
            for c, label in [(self.left_client, "L"), (self.right_client, "R")]:
                if c and c.is_connected:
                    clients.append(c)
                    arm_labels.append(label)
                    break

        # Decode for log
        decode_str = ""
        if len(data) >= 8 and data[0] == 0xAA:
            svc = (data[6], data[7])
            decode_str = SERVICE_NAMES.get(svc, f"svc={data[6]:02X}-{data[7]:02X}")

        for client, arm in zip(clients, arm_labels):
            if self.logger:
                self.logger.log_tx(arm, ch_name, data, decode_str)
            await client.write_gatt_char(char_uuid, data, response=False)

    async def write_protocol(self, data: bytes, target: str = "both"):
        await self._write(WRITE_PROTOCOL, data, target)

    async def write_audio(self, data: bytes, target: str = "left"):
        await self._write(WRITE_AUDIO, data, target)

    async def write_display(self, data: bytes, target: str = "left"):
        await self._write(WRITE_DISPLAY, data, target)

    # ── Auth ──────────────────────────────────────────────────────────────

    async def authenticate(self):
        """Send 7-packet auth handshake to both arms."""
        print(f"\n  Authenticating...")
        for pkt in self.builder.build_auth_sequence():
            await self.write_protocol(pkt)
            await asyncio.sleep(0.1)
        await asyncio.sleep(0.5)
        print(f"  {GRN}Auth complete{RST}")

    # ── Heartbeat ─────────────────────────────────────────────────────────

    async def send_heartbeat(self):
        """Send a keepalive heartbeat to both arms."""
        pkt = self.builder.build_heartbeat()
        await self.write_protocol(pkt)

    # ── Display Text ──────────────────────────────────────────────────────

    async def display_text(self, text: str):
        """Send text to the glasses display via teleprompter protocol."""
        pages = format_text(text)
        total_lines = len(text.replace("\\n", "\n").split("\n"))
        print(f"\n  Displaying text ({len(pages)} pages, ~{total_lines} lines)...")

        await self.write_protocol(self.builder.build_display_config())
        await asyncio.sleep(0.3)

        await self.write_protocol(self.builder.build_teleprompter_init(total_lines))
        await asyncio.sleep(0.5)

        for i in range(min(10, len(pages))):
            await self.write_protocol(self.builder.build_content_page(i, pages[i]))
            await asyncio.sleep(0.05)

        await self.write_protocol(self.builder.build_marker())
        await asyncio.sleep(0.1)

        for i in range(10, min(12, len(pages))):
            await self.write_protocol(self.builder.build_content_page(i, pages[i]))
            await asyncio.sleep(0.05)

        await self.write_protocol(self.builder.build_sync())
        await asyncio.sleep(0.1)

        for i in range(12, len(pages)):
            await self.write_protocol(self.builder.build_content_page(i, pages[i]))
            await asyncio.sleep(0.05)

        print(f"  {GRN}Text sent!{RST} Check your glasses.")

    # ── Audio Control ─────────────────────────────────────────────────────

    async def try_enable_mic(self) -> bool:
        """Attempt to enable the microphone via multiple experimental approaches.

        The exact BLE command to trigger the G2 mic is not yet reverse-engineered.
        The Flutter SDK mediates via bridge.audioControl(true/false).
        We try several approaches in sequence, checking after each if audio starts.

        Returns True if audio stream was detected.
        """
        print(f"\n  {CYN}{BOLD}Attempting mic activation...{RST}")

        approaches = self.builder.build_audio_control(enable=True)

        for i, (desc, pkt, channel, arm_hint) in enumerate(approaches, 1):
            print(f"  {CYN}  [{i}/{len(approaches)}] {desc}{RST}")

            try:
                if channel == "audio":
                    await self.write_audio(pkt, target=arm_hint)
                elif channel == "display":
                    await self.write_display(pkt, target=arm_hint)
                else:
                    await self.write_protocol(pkt, target=arm_hint)
                await asyncio.sleep(0.5)
            except Exception as e:
                print(f"      {RED}Error: {e}{RST}")

            if self._session_audio.count > 0:
                print(f"  {GRN}{BOLD}★ Audio started after: {desc} ★{RST}")
                return True

        # Wait a bit more — audio can start with a delay
        print(f"  {DIM}  Waiting 3s for delayed start...{RST}")
        await asyncio.sleep(3.0)

        if self._session_audio.count > 0:
            print(f"  {GRN}{BOLD}★ Audio detected after delay! ★{RST}")
            return True

        print(f"\n  {YEL}No mic trigger approach worked.{RST}")
        print(f"  {YEL}Mic is listening — activate via:{RST}")
        print(f"    • Exit quiet mode (touch both arms → release)")
        print(f"    • Even Hub AI button")
        print(f"    • Long press R1 ring")
        return False

    async def try_disable_mic(self):
        """Attempt to disable the microphone."""
        approaches = self.builder.build_audio_control(enable=False)
        for desc, pkt, channel, arm_hint in approaches:
            try:
                if channel == "audio":
                    await self.write_audio(pkt, target=arm_hint)
                else:
                    await self.write_protocol(pkt, target=arm_hint)
            except:
                pass
            await asyncio.sleep(0.1)


# =============================================================================
# LC3 Decoder (inline — uses liblc3 via ctypes)
# =============================================================================

LC3_PCM_FORMAT_S16 = 0


def find_liblc3():
    """Locate liblc3 shared library."""
    candidates = [
        "/opt/homebrew/lib/liblc3.dylib",
        "/opt/homebrew/lib/liblc3.1.dylib",
        "/opt/homebrew/Cellar/liblc3/1.1.3/lib/liblc3.1.dylib",
        "/usr/local/lib/liblc3.dylib",
        "liblc3.so",
        "liblc3.dylib",
    ]
    for path in candidates:
        try:
            return ctypes.CDLL(path)
        except OSError:
            continue
    return None


def decode_lc3_to_wav(lc3_bin_path: str, wav_path: str) -> bool:
    """Decode an LC3 .bin file to a WAV file. Returns True on success."""
    lib = find_liblc3()
    if lib is None:
        print(f"  {YEL}liblc3 not found — skipping auto-decode.{RST}")
        print(f"  {DIM}Install with: brew install liblc3{RST}")
        print(f"  {DIM}Then decode manually: python tools/decode_lc3.py {lc3_bin_path}{RST}")
        return False

    dt_us, sr_hz, frame_bytes = 10000, AUDIO_SAMPLE_RATE, LC3_FRAME_SIZE
    pcm_samples = sr_hz * dt_us // 1_000_000  # 160

    # Setup ctypes signatures
    lib.lc3_decoder_size.restype = ctypes.c_uint
    lib.lc3_decoder_size.argtypes = [ctypes.c_int, ctypes.c_int]
    lib.lc3_setup_decoder.restype = ctypes.c_void_p
    lib.lc3_setup_decoder.argtypes = [
        ctypes.c_int, ctypes.c_int, ctypes.c_int, ctypes.c_void_p
    ]
    lib.lc3_decode.restype = ctypes.c_int
    lib.lc3_decode.argtypes = [
        ctypes.c_void_p, ctypes.c_void_p, ctypes.c_int,
        ctypes.c_int, ctypes.c_void_p, ctypes.c_int
    ]

    dec_size = lib.lc3_decoder_size(dt_us, sr_hz)
    if dec_size == 0:
        return False
    dec_mem = ctypes.create_string_buffer(dec_size)
    decoder = lib.lc3_setup_decoder(dt_us, sr_hz, 0, dec_mem)
    if not decoder:
        return False

    data = Path(lc3_bin_path).read_bytes()
    n_frames = len(data) // frame_bytes
    pcm_buf = (ctypes.c_int16 * pcm_samples)()
    all_pcm = bytearray()
    ok = err = 0

    for i in range(n_frames):
        in_buf = ctypes.create_string_buffer(
            bytes(data[i * frame_bytes:(i + 1) * frame_bytes]), frame_bytes
        )
        ret = lib.lc3_decode(decoder, in_buf, frame_bytes,
                             LC3_PCM_FORMAT_S16, pcm_buf, 1)
        if ret >= 0:
            ok += 1
        else:
            err += 1
        all_pcm.extend(bytes(pcm_buf))

    with wave.open(wav_path, "wb") as wf:
        wf.setnchannels(1)
        wf.setsampwidth(2)
        wf.setframerate(sr_hz)
        wf.writeframes(bytes(all_pcm))

    duration = len(all_pcm) / (sr_hz * 2)
    print(f"  {GRN}Decoded:{RST} {BOLD}{wav_path}{RST} "
          f"({n_frames} frames, {duration:.1f}s, {ok} ok / {err} err)")
    return True


# =============================================================================
# Interactive Stdin Reader
# =============================================================================

async def wait_for_enter(prompt: str = "") -> str:
    """Wait for user to press Enter, non-blocking in asyncio."""
    loop = asyncio.get_event_loop()
    if prompt:
        print(prompt, end="", flush=True)
    return await loop.run_in_executor(None, sys.stdin.readline)


# =============================================================================
# Results Saving
# =============================================================================

def save_results(g2: G2Connection, args, out_dir: Path, ts_str: str):
    """Save captured audio data and session metadata to out_dir."""

    # Use session-wide collector for totals (never reset, unlike per-recording g2.audio)
    sa = g2._session_audio

    print(f"\n{'═'*60}")
    print(f"  {BOLD}SESSION RESULTS{RST}")
    print(f"{'─'*60}")
    print(f"  Output dir:        {out_dir}/")
    print(f"  Total BLE packets: {g2.packet_count}")
    print(f"  Logged packets:    {g2.logger.count if g2.logger else 'N/A'}")
    print(f"  Mic state:         {g2.mic_state}")
    print(f"  Dashboard events:  {len(g2._dashboard_log)}")

    if sa.count > 0:
        print(f"\n  {MAG}{BOLD}Audio Capture (session total):{RST}")
        for line in sa.summary().split("\n"):
            print(f"    {line}")

        # Save LC3 frames (5×40B per packet, no metadata/counter)
        lc3_path = str(out_dir / "audio_lc3.bin")
        sa.save_lc3_bin(lc3_path)
        lc3_size = sa.count * LC3_FRAME_SIZE * LC3_FRAMES_PER_PKT
        print(f"\n  {GRN}Saved:{RST}")
        print(f"    LC3 frames:   {BOLD}{lc3_path}{RST} ({lc3_size:,} bytes)")

        # Save raw codec data (204B per packet, no counter)
        raw_path = str(out_dir / "audio_raw.bin")
        sa.save_raw_codec(raw_path)
        raw_size = sa.count * 204
        print(f"    Raw codec:    {BOLD}{raw_path}{RST} ({raw_size:,} bytes)")

        # Save full packets (205B each)
        full_path = str(out_dir / "audio_full.bin")
        sa.save_full_bin(full_path)
        full_size = sa.count * AUDIO_PKT_SIZE
        print(f"    Full packets: {BOLD}{full_path}{RST} ({full_size:,} bytes)")

        # Auto-decode LC3 → WAV
        wav_path = str(out_dir / "audio.wav")
        print(f"\n  {BOLD}Decoding LC3 → WAV...{RST}")
        if not decode_lc3_to_wav(lc3_path, wav_path):
            print(f"\n  {BOLD}Manual decode:{RST}")
            print(f"    python tools/decode_lc3.py {lc3_path}")
    else:
        print(f"\n  {YEL}No audio captured.{RST}")
        print(f"  The mic was not activated during this session.")
        print(f"  Try running with --mic and activating via Even Hub or quiet mode exit.")

    # Save session JSON
    json_path = str(out_dir / "session.json")
    session = {
        "tool": "teleprompter_v2",
        "timestamp": ts_str,
        "out_dir": str(out_dir),
        "total_packets": g2.packet_count,
        "logged_packets": g2.logger.count if g2.logger else 0,
        "mic_state": g2.mic_state,
        "audio": {
            "packets": sa.count,
            "dropped": sa.dropped,
            "duration_codec_sec": sa.duration_sec,
            "duration_wall_sec": sa.wall_duration_sec,
            "data_bytes": sa.data_bytes,
            "timestamps": [t for t, _ in sa.packets],
        },
        "dashboard_log": g2._dashboard_log,
        "text": args.text if hasattr(args, 'text') and args.text else None,
        "log_files": {
            "btsnoop_parquet": str(out_dir / "btsnoop.parquet") if HAS_PARQUET else None,
            "btsnoop_jsonl": str(out_dir / "btsnoop.jsonl"),
            "btsnoop_log": str(out_dir / "btsnoop.log"),
            "btsnoop_bin": str(out_dir / "btsnoop.bin"),
            "dashboard_parquet": str(out_dir / "dashboard.parquet") if HAS_PARQUET else None,
        },
    }

    # Write summary via logger too
    if g2.logger:
        g2.logger.write_summary(session)
    else:
        with open(json_path, "w") as f:
            json.dump(session, f, indent=2, default=str)

    print(f"\n  {GRN}Log files:{RST}")
    if HAS_PARQUET:
        print(f"    btsnoop.parquet {BOLD}{out_dir / 'btsnoop.parquet'}{RST}  ← primary (compact)")
        if g2._dashboard_log:
            print(f"    dashboard.parquet {BOLD}{out_dir / 'dashboard.parquet'}{RST}")
    print(f"    btsnoop.jsonl   {BOLD}{out_dir / 'btsnoop.jsonl'}{RST}")
    print(f"    btsnoop.log     {BOLD}{out_dir / 'btsnoop.log'}{RST}")
    print(f"    btsnoop.bin     {BOLD}{out_dir / 'btsnoop.bin'}{RST}")
    print(f"    session.json    {BOLD}{out_dir / 'session.json'}{RST}")
    print(f"{'═'*60}\n")


# =============================================================================
# Main
# =============================================================================

async def run(args):
    ts_str = datetime.now().strftime("%Y%m%d_%H%M%S")

    # Create output directory
    out_dir = Path("out") / ts_str
    out_dir.mkdir(parents=True, exist_ok=True)
    print(f"\n  {BOLD}Output → {out_dir}/{RST}")

    # Start BLE packet logger
    logger = BLELogger(str(out_dir))
    g2 = G2Connection(verbose=args.verbose, logger=logger)

    # Scan
    left_dev, right_dev = await g2.scan()
    if not left_dev and not right_dev:
        logger.close()
        return

    # Connect
    if not await g2.connect(left_dev, right_dev):
        logger.close()
        return

    recording = False
    recording_num = 0

    try:
        # Authenticate
        await g2.authenticate()

        # Display text (unless --mic-only)
        if args.text and not args.mic_only:
            await g2.display_text(args.text)

        # ── Interactive mic mode ──────────────────────────────────────
        if args.mic or args.mic_only:
            if args.trigger:
                await g2.try_enable_mic()
            else:
                print(f"\n  {GRN}{BOLD}LISTENING for mic audio on display channel...{RST}")
                print(f"  {DIM}Audio arrives as {AUDIO_PKT_SIZE}B packets on 0x6402 (LEFT arm){RST}")
                print(f"  {DIM}Activate mic via Even Hub UI on glasses / quiet mode exit / R1 ring{RST}")

            # Interactive recording loop
            print(f"\n  {BOLD}{'═'*50}{RST}")
            print(f"  {BOLD}  ⏺  Press ENTER to start/stop recording{RST}")
            print(f"  {BOLD}  ⏏  Type 'q' + ENTER to quit{RST}")
            print(f"  {BOLD}  📁  All traffic logged to {out_dir}/{RST}")
            print(f"  {BOLD}{'═'*50}{RST}\n")

            # Heartbeat task
            async def heartbeat_loop():
                while True:
                    await asyncio.sleep(8.0)
                    try:
                        await g2.send_heartbeat()
                    except Exception:
                        break

            hb_task = asyncio.create_task(heartbeat_loop())

            try:
                while True:
                    if not recording:
                        line = await wait_for_enter(
                            f"  {GRN}⏺  Press ENTER to start recording (q to quit): {RST}"
                        )
                        if line.strip().lower() == 'q':
                            break

                        # Start recording — reset audio collector
                        recording = True
                        recording_num += 1
                        g2.audio = AudioCollector()
                        rec_start = time.time()
                        print(f"\n  {RED}{BOLD}● RECORDING #{recording_num}{RST}")
                        print(f"  {DIM}  Capturing audio... press ENTER to stop{RST}\n")

                        # Also attempt trigger if requested
                        if args.trigger and recording_num == 1:
                            await g2.try_enable_mic()

                    else:
                        line = await wait_for_enter(
                            f"  {RED}■  Press ENTER to stop recording: {RST}"
                        )

                        # Stop recording
                        recording = False
                        rec_dur = time.time() - rec_start
                        print(f"\n  {GRN}{BOLD}⏹  Recording #{recording_num} stopped{RST} ({rec_dur:.1f}s)")

                        if g2.audio.count > 0:
                            print(f"  {MAG}  {g2.audio.count} packets, "
                                  f"{g2.audio.data_bytes:,}B LC3, "
                                  f"{g2.audio.duration_sec:.1f}s audio{RST}")

                            # Save this recording into out_dir
                            rec_prefix = f"rec{recording_num}"
                            lc3_path = str(out_dir / f"{rec_prefix}_lc3.bin")
                            g2.audio.save_lc3_bin(lc3_path)
                            print(f"  {GRN}  Saved: {BOLD}{lc3_path}{RST}")

                            raw_path = str(out_dir / f"{rec_prefix}_raw.bin")
                            g2.audio.save_raw_codec(raw_path)

                            full_path = str(out_dir / f"{rec_prefix}_full.bin")
                            g2.audio.save_full_bin(full_path)

                            # Auto-decode to WAV
                            wav_path = str(out_dir / f"{rec_prefix}.wav")
                            decode_lc3_to_wav(lc3_path, wav_path)
                            print()
                        else:
                            print(f"  {YEL}  No audio packets captured.{RST}")
                            print(f"  {DIM}  Make sure mic is active on the glasses.{RST}\n")

                        if line.strip().lower() == 'q':
                            break

            finally:
                hb_task.cancel()
                try:
                    await hb_task
                except asyncio.CancelledError:
                    pass

        # ── Non-mic mode (display only) ───────────────────────────────
        else:
            duration = args.duration
            print(f"\n  {DIM}Monitoring for {duration}s (Ctrl+C to stop)...{RST}\n")

            hb_interval = 8.0
            elapsed = 0.0
            while elapsed < duration:
                sleep_time = min(hb_interval, duration - elapsed)
                await asyncio.sleep(sleep_time)
                elapsed += sleep_time
                if elapsed < duration:
                    await g2.send_heartbeat()

    except asyncio.CancelledError:
        pass

    finally:
        if args.mic or args.mic_only:
            await g2.try_disable_mic()

        # Save final session summary
        save_results(g2, args, out_dir, ts_str)
        logger.close()
        await g2.disconnect()
        print(f"  Disconnected.")


def main():
    parser = argparse.ArgumentParser(
        description="Even G2 Teleprompter v2 — Display Text + Mic Audio Capture",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Audio Architecture:
  G2 mic audio streams on the DISPLAY channel (0x6402), LEFT arm only.
  Packets are 205 bytes: 5 × 40-byte LC3 frames + metadata + counter.
  Rate: 20 pkts/sec, ~32 kbps, LC3 codec @ 16kHz, 10ms frames.
  Dashboard f3.f1=1 → mic ON, f3.f1=3 → mic OFF.

Examples:
  %(prog)s "Hello world!"                         Display text
  %(prog)s "Notes here" --mic                      Display + listen for audio
  %(prog)s "Notes" --mic --trigger                 Display + attempt mic trigger
  %(prog)s --mic-only --duration 60                Listen for audio only, 60s
  %(prog)s --mic-only --trigger --save recording   Trigger mic, save as recording_*
  %(prog)s "Text" --mic --save session1 -v         Verbose, custom output prefix
        """,
    )

    parser.add_argument("text", nargs="?", default=None,
                        help="Text to display (use \\\\n for newlines)")
    parser.add_argument("--mic", action="store_true",
                        help="Enable mic audio capture (listens on display channel)")
    parser.add_argument("--mic-only", action="store_true",
                        help="Skip display, only capture mic audio")
    parser.add_argument("--trigger", action="store_true",
                        help="Attempt to trigger mic via BLE (experimental)")
    parser.add_argument("--save", metavar="PREFIX",
                        help="Output file prefix (default: teleprompter_TIMESTAMP)")
    parser.add_argument("--duration", type=int, default=5,
                        help="Seconds to stay connected (default: 5, min 15 with --mic)")
    parser.add_argument("--verbose", "-v", action="store_true",
                        help="Show all protocol notifications")

    args = parser.parse_args()

    if not args.text and not args.mic and not args.mic_only:
        parser.print_help()
        print(f"\n{YEL}Provide text, --mic, or --mic-only{RST}")
        sys.exit(1)

    print(f"\n{BOLD}═══ Even G2 Teleprompter v2 ═══{RST}")
    print(f"{'─'*60}")
    if args.text and not args.mic_only:
        preview = args.text[:60] + ("..." if len(args.text) > 60 else "")
        print(f"  Text:     {preview}")
    if args.mic or args.mic_only:
        print(f"  Mic:      {GRN}LISTENING{RST} on display channel (0x6402)")
        print(f"  Codec:    LC3 @ 32kbps, 16kHz, {LC3_FRAME_SIZE}B × {LC3_FRAMES_PER_PKT} frames/pkt")
        print(f"  Record:   {CYN}INTERACTIVE{RST} — press ENTER to start/stop")
        if args.trigger:
            print(f"  Trigger:  {YEL}EXPERIMENTAL{RST} (will attempt BLE mic activation)")
    if not (args.mic or args.mic_only):
        print(f"  Duration: {args.duration}s")
    fmt = f"{GRN}Parquet + JSONL{RST}" if HAS_PARQUET else f"{YEL}JSONL only{RST} (pip install pyarrow for Parquet)"
    print(f"  Logging:  {GRN}ALL BLE traffic{RST} → out/<timestamp>/  [{fmt}]")
    print(f"{'─'*60}")

    try:
        asyncio.run(run(args))
    except KeyboardInterrupt:
        print(f"\n{YEL}Interrupted{RST}")


if __name__ == "__main__":
    main()
