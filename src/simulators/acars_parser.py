"""
SkyGuard — ACARS Message Parser
================================
Simulates the Aircraft Communications Addressing and Reporting System (ACARS)
message protocol used for ground-to-air and air-to-ground datalink.

ACARS message structure (simplified):
  SOH  : 0x01  (Start of Header)
  Mode : 1 byte ('2' for VHF, '.')
  ADDR : 7 chars aircraft registration (e.g. 'F-GKXL  ')
  ACK  : 1 byte (acknowledgement char)
  LABEL: 2 chars message type label
  BI   : 1 byte block identifier
  STX  : 0x02  (Start of Text)
  TEXT : variable length message body
  ETX  : 0x17  (End of Text) — or 0x03 for last block
  DEL  : 0x7F  (Delete — used as separator in some implementations)

Reference: ARINC Specification 618 (structure publicly documented).
This parser is used as a fuzzing target for property-based security tests.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from enum import Enum
from typing import Any


# ---------------------------------------------------------------------------
# Protocol constants
# ---------------------------------------------------------------------------

SOH = 0x01
STX = 0x02
ETX = 0x17
ETX_LAST = 0x03
DEL = 0x7F

# Known ACARS label types (subset relevant to security testing)
LABEL_REGISTRY: dict[str, str] = {
    "5Z": "ATIS broadcast",
    "H1": "ACARS position report",
    "RA": "ATC clearance",
    "SA": "Digital ATIS",
    "10": "Off-block time",
    "11": "Take-off time",
    "12": "Landing time",
    "13": "On-block time",
    "Q0": "SATCOM logon",
    "QS": "SATCOM logoff",
    "5U": "Oceanic clearance",
    "M1": "Engine ACARS",
    "SQ": "ATC datalink",
    "_d": "ACARS acknowledgement",
    "__": "Free text",
}

# Max safe lengths — a parser must enforce these
MAX_TEXT_LENGTH  = 220   # ARINC 618 limit
MAX_LABEL_LENGTH = 2
VALID_MODES      = frozenset(b"2.")
ADDR_PATTERN     = re.compile(r"^[A-Z0-9]{1,2}-[A-Z0-9]{3,5}\s*$")


# ---------------------------------------------------------------------------
# Data structures
# ---------------------------------------------------------------------------

class ParseStatus(Enum):
    OK             = "ok"
    MALFORMED      = "malformed"
    UNKNOWN_LABEL  = "unknown_label"
    TEXT_TOO_LONG  = "text_too_long"
    BAD_PARITY     = "bad_parity"
    INVALID_ADDR   = "invalid_addr"
    TRUNCATED      = "truncated"


@dataclass
class ACARSMessage:
    """Parsed representation of one ACARS message."""
    mode:       str
    address:    str
    ack:        str
    label:      str
    block_id:   str
    text:       str
    raw:        bytes
    status:     ParseStatus           = ParseStatus.OK
    anomalies:  list[str]             = field(default_factory=list)
    metadata:   dict[str, Any]        = field(default_factory=dict)

    @property
    def label_name(self) -> str:
        return LABEL_REGISTRY.get(self.label, f"Unknown ({self.label!r})")

    @property
    def is_valid(self) -> bool:
        return self.status == ParseStatus.OK and not self.anomalies


# ---------------------------------------------------------------------------
# Parser — the system under test for fuzzing
# ---------------------------------------------------------------------------

class ACARSParser:
    """
    Parses raw ACARS byte frames into ACARSMessage objects.

    This is deliberately written to be slightly too lenient in some areas
    so that security tests can catch real issues (e.g. overly long text
    accepted without truncation, unknown labels passed through silently).
    The test suite is expected to surface these as findings.
    """

    def parse(self, raw: bytes) -> ACARSMessage:
        anomalies: list[str] = []
        status = ParseStatus.OK

        # ── Minimum length check ──────────────────────────────────────────
        if len(raw) < 13:
            return ACARSMessage(
                mode="?", address="?", ack="?", label="??",
                block_id="?", text="", raw=raw,
                status=ParseStatus.TRUNCATED,
                anomalies=["Frame too short to parse"],
            )

        # ── SOH ───────────────────────────────────────────────────────────
        if raw[0] != SOH:
            anomalies.append(f"Missing SOH: got 0x{raw[0]:02x}")
            status = ParseStatus.MALFORMED

        # ── Mode ──────────────────────────────────────────────────────────
        mode = chr(raw[1]) if raw[1] in VALID_MODES else chr(raw[1])
        if raw[1] not in VALID_MODES:
            anomalies.append(f"Unknown mode byte: 0x{raw[1]:02x}")

        # ── Aircraft address (7 chars) ────────────────────────────────────
        try:
            address = raw[2:9].decode("ascii")
        except UnicodeDecodeError:
            address = raw[2:9].hex()
            anomalies.append("Non-ASCII bytes in aircraft address field")
            status = ParseStatus.INVALID_ADDR

        if not ADDR_PATTERN.match(address) and ParseStatus.INVALID_ADDR != status:
            anomalies.append(f"Address format unexpected: {address!r}")

        # ── ACK character ─────────────────────────────────────────────────
        ack = chr(raw[9]) if 0x20 <= raw[9] <= 0x7E else f"0x{raw[9]:02x}"

        # ── Label (2 chars) ───────────────────────────────────────────────
        try:
            label = raw[10:12].decode("ascii")
        except UnicodeDecodeError:
            label = raw[10:12].hex()
            anomalies.append("Non-ASCII label bytes")
            status = ParseStatus.MALFORMED

        if label not in LABEL_REGISTRY:
            anomalies.append(f"Unknown ACARS label: {label!r}")
            if status == ParseStatus.OK:
                status = ParseStatus.UNKNOWN_LABEL

        # ── Block ID ──────────────────────────────────────────────────────
        block_id = chr(raw[12]) if 0x41 <= raw[12] <= 0x5A else str(raw[12])

        # ── STX ───────────────────────────────────────────────────────────
        stx_pos = raw.find(STX, 13)
        if stx_pos == -1:
            return ACARSMessage(
                mode=mode, address=address, ack=ack, label=label,
                block_id=block_id, text="", raw=raw,
                status=ParseStatus.MALFORMED,
                anomalies=anomalies + ["Missing STX — cannot locate message body"],
            )

        # ── Text body ─────────────────────────────────────────────────────
        etx_pos = raw.find(ETX, stx_pos)
        if etx_pos == -1:
            etx_pos = raw.find(ETX_LAST, stx_pos)

        if etx_pos == -1:
            text_raw = raw[stx_pos + 1:]
            anomalies.append("Missing ETX — message may be truncated")
            status = ParseStatus.TRUNCATED
        else:
            text_raw = raw[stx_pos + 1:etx_pos]

        try:
            text = text_raw.decode("ascii", errors="replace")
        except Exception:
            text = text_raw.hex()
            anomalies.append("Text body contains non-ASCII data")

        # ── Length enforcement ────────────────────────────────────────────
        # SECURITY NOTE: this is the intentionally lax check — it flags but
        # does not reject.  Property-based tests should catch that the parser
        # returns status OK for oversized text, which is a finding.
        if len(text) > MAX_TEXT_LENGTH:
            anomalies.append(
                f"Text exceeds ARINC 618 max ({len(text)} > {MAX_TEXT_LENGTH} chars)"
            )
            status = ParseStatus.TEXT_TOO_LONG

        return ACARSMessage(
            mode=mode,
            address=address.strip(),
            ack=ack,
            label=label,
            block_id=block_id,
            text=text,
            raw=raw,
            status=status,
            anomalies=anomalies,
            metadata={"label_name": LABEL_REGISTRY.get(label, "Unknown")},
        )

    def parse_batch(self, frames: list[bytes]) -> list[ACARSMessage]:
        return [self.parse(f) for f in frames]


# ---------------------------------------------------------------------------
# Message builders — normal traffic generators
# ---------------------------------------------------------------------------

class ACARSMessageBuilder:
    """Builds well-formed ACARS frames for normal traffic simulation."""

    def __init__(self, aircraft_id: str = "F-GKXA ") -> None:
        self.aircraft_id = aircraft_id[:7].ljust(7)
        self._block_counter = 0

    def _next_block_id(self) -> bytes:
        b = bytes([0x41 + (self._block_counter % 26)])
        self._block_counter += 1
        return b

    def build(self, label: str, text: str, ack: str = "!") -> bytes:
        """Construct a valid ACARS frame."""
        if len(label) != 2:
            raise ValueError("ACARS label must be exactly 2 characters")
        if len(text) > MAX_TEXT_LENGTH:
            raise ValueError(f"Text too long: {len(text)} > {MAX_TEXT_LENGTH}")

        frame = bytes([SOH])
        frame += b"2"
        frame += self.aircraft_id.encode("ascii")
        frame += ack.encode("ascii")[:1]
        frame += label.encode("ascii")
        frame += self._next_block_id()
        frame += bytes([STX])
        frame += text.encode("ascii")
        frame += bytes([ETX_LAST])
        return frame

    def position_report(self, lat: float, lon: float, alt: int, spd: int) -> bytes:
        text = f"POSN{lat:+.4f}{lon:+.4f}ALT{alt:05d}SPD{spd:03d}"
        return self.build("H1", text)

    def atis_request(self, airport_icao: str) -> bytes:
        return self.build("SA", f"ATIS REQ {airport_icao.upper()[:4]}")

    def free_text(self, message: str) -> bytes:
        return self.build("__", message[:MAX_TEXT_LENGTH])


# ---------------------------------------------------------------------------
# Attack scenario builders
# ---------------------------------------------------------------------------

class ACARSAttackBuilder:
    """
    Constructs malformed or malicious ACARS frames for security testing.

    Each method documents the attack vector and its ED-202A threat category.
    """

    def oversized_text(self, length: int = 1000) -> bytes:
        """
        Buffer overflow attempt: text field exceeds ARINC 618 maximum.
        Threat category: T1 — Denial of Service via resource exhaustion.
        """
        frame = bytes([SOH, ord("2")])
        frame += b"F-GKXA "
        frame += b"!"
        frame += b"H1"
        frame += b"A"
        frame += bytes([STX])
        frame += b"X" * length      # intentionally exceeds MAX_TEXT_LENGTH
        frame += bytes([ETX_LAST])
        return frame

    def null_byte_injection(self) -> bytes:
        """
        Inject null bytes into text field — may confuse C-string parsers.
        Threat category: T2 — Data integrity compromise.
        """
        frame = bytes([SOH, ord("2")])
        frame += b"F-GKXA "
        frame += b"!"
        frame += b"RA"              # ATC clearance label — high impact if corrupted
        frame += b"B"
        frame += bytes([STX])
        frame += b"CLX DIRECT " + b"\x00" * 5 + b" WAYPNT"
        frame += bytes([ETX_LAST])
        return frame

    def malformed_address(self, address: bytes = b"\xff" * 7) -> bytes:
        """
        Non-ASCII or binary aircraft registration field.
        Threat category: T2 — Identity spoofing via address field manipulation.
        """
        frame = bytes([SOH, ord("2")])
        frame += address[:7].ljust(7, b"\x00")
        frame += b"!"
        frame += b"5U"
        frame += b"C"
        frame += bytes([STX])
        frame += b"OCEANIC CLEARANCE REQUEST"
        frame += bytes([ETX_LAST])
        return frame

    def missing_etx(self) -> bytes:
        """
        No ETX terminator — parser must handle gracefully.
        Threat category: T1 — Denial of Service via malformed framing.
        """
        frame = bytes([SOH, ord("2")])
        frame += b"F-GKXB "
        frame += b"!"
        frame += b"H1"
        frame += b"D"
        frame += bytes([STX])
        frame += b"POSITION REPORT WITHOUT TERMINATOR"
        # deliberately omit ETX
        return frame

    def label_injection(self, injected_label: bytes = b";\x00") -> bytes:
        """
        Non-printable or binary label field.
        Threat category: T3 — Command injection via label field.
        """
        frame = bytes([SOH, ord("2")])
        frame += b"F-GKXC "
        frame += b"!"
        frame += injected_label[:2].ljust(2, b"\x00")
        frame += b"E"
        frame += bytes([STX])
        frame += b"INJECTED COMMAND"
        frame += bytes([ETX_LAST])
        return frame

    def replay_clearance(
        self, original: bytes, mutate_ack: bool = True
    ) -> bytes:
        """
        Retransmit an ATC clearance with a different ACK char.
        Threat category: T4 — Replay attack on safety-critical instruction.
        """
        frame = bytearray(original)
        if mutate_ack and len(frame) > 9:
            frame[9] = (frame[9] + 1) % 0x7E or 0x21
        return bytes(frame)
