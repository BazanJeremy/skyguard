"""
ACARS Message Parser
=====================
Simulates a ground-to-air ACARS (Aircraft Communications Addressing
and Reporting System) message parser.

ACARS messages carry operational data: ATIS, METAR, crew messages,
fuel uplift orders, departure clearances (PDC), and OOOI events.

Security relevance:
  - ACARS is transmitted over VHF/HF radio with no authentication
  - No encryption on legacy VHF ACARS (ARINC 618)
  - An attacker with a VHF transmitter can inject arbitrary messages
  - Downstream parsers must be resilient to malformed/malicious input

This module intentionally implements a parser with testable weaknesses
for SkyGuard's Hypothesis-based fuzzing suite.

References:
  - ARINC 618: Air/Ground Character-Oriented Protocol Specification
  - ARINC 620: Datalink Ground System Standard
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from enum import Enum
from typing import Optional


# ─────────────────────────────────────────────────────────────────────────────
# Message type taxonomy
# ─────────────────────────────────────────────────────────────────────────────


class AcarsMessageType(str, Enum):
    ATIS = "ATIS"  # Automatic Terminal Info Service
    METAR = "METAR"  # Meteorological report
    PDC = "PDC"  # Pre-Departure Clearance
    FUEL = "FUEL"  # Fuel uplift order
    OOOI = "OOOI"  # Out/Off/On/In event
    FREE_TEXT = "FREE_TEXT"  # Crew free text message
    ATC_CLEARANCE = "ATC_CLEARANCE"  # ATC route clearance (CPDLC-lite)
    UNKNOWN = "UNKNOWN"


# ─────────────────────────────────────────────────────────────────────────────
# Parsed message models
# ─────────────────────────────────────────────────────────────────────────────


@dataclass
class AcarsHeader:
    """ARINC 618 message header fields."""

    mode: str  # Single character: '2' (air-ground) or '.' etc.
    aircraft_id: str  # 7-char ICAO aircraft registration (e.g. "FHBXA")
    technical_ack: str  # '!' = no ack, space = ack required
    label: str  # 2-char message label (e.g. "H1" = free text)
    block_id: str  # 1-char sequence counter (0-9 A-Z)
    msg_number: str  # 4-char message number (e.g. "M01A")
    flight_id: str  # 6-char flight number (e.g. "AF447 ")


@dataclass
class AcarsMessage:
    """A fully parsed ACARS message."""

    raw: str
    header: AcarsHeader
    msg_type: AcarsMessageType
    body: str
    checksum: Optional[str]
    is_valid: bool
    parse_errors: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "aircraft_id": self.header.aircraft_id,
            "flight_id": self.header.flight_id.strip(),
            "label": self.header.label,
            "msg_type": self.msg_type.value,
            "body_length": len(self.body),
            "body_preview": self.body[:80],
            "checksum": self.checksum,
            "is_valid": self.is_valid,
            "parse_errors": self.parse_errors,
        }


# ─────────────────────────────────────────────────────────────────────────────
# Message type classifier
# ─────────────────────────────────────────────────────────────────────────────

# Label-to-type mapping (ARINC 618 Appendix A, subset)
_LABEL_TYPE_MAP: dict[str, AcarsMessageType] = {
    "H1": AcarsMessageType.FREE_TEXT,
    "QS": AcarsMessageType.OOOI,
    "Q0": AcarsMessageType.OOOI,
    "SA": AcarsMessageType.ATIS,
    "D0": AcarsMessageType.PDC,
    "70": AcarsMessageType.METAR,
    "FN": AcarsMessageType.FUEL,
    "CF": AcarsMessageType.ATC_CLEARANCE,
}

_BODY_PATTERNS: list[tuple[re.Pattern, AcarsMessageType]] = [
    (re.compile(r"^PDC\s"), AcarsMessageType.PDC),
    (re.compile(r"^METAR\s"), AcarsMessageType.METAR),
    (re.compile(r"^ATIS\s"), AcarsMessageType.ATIS),
    (re.compile(r"^FUEL\s"), AcarsMessageType.FUEL),
]


def _classify(label: str, body: str) -> AcarsMessageType:
    if label in _LABEL_TYPE_MAP:
        return _LABEL_TYPE_MAP[label]
    for pattern, msg_type in _BODY_PATTERNS:
        if pattern.match(body.strip()):
            return msg_type
    return AcarsMessageType.UNKNOWN


# ─────────────────────────────────────────────────────────────────────────────
# Parser
# ─────────────────────────────────────────────────────────────────────────────

# Minimum message length: mode(1) + acid(7) + ack(1) + label(2) + block(1) +
#                         msgnum(4) + flight(6) = 22 chars before body
_MIN_HEADER_LEN = 22
_MAX_BODY_LEN = 220  # ARINC 618 §5.1: max 220 characters per message

# Characters permitted in aircraft registration (ICAO Doc 8585)
_ACID_PATTERN = re.compile(r"^[A-Z0-9\-]{2,7}$")


class AcarsParser:
    """
    Parses raw ACARS message strings into structured AcarsMessage objects.

    Known weaknesses (intentional, for fuzzing):
      - No authentication: any sender can forge aircraft ID
      - Body length limit enforced but not cryptographically bound
      - Checksum is CRC-16 but not verified by default (flag available)
      - Null bytes in body not rejected (potential downstream crashes)
    """

    def __init__(self, verify_checksum: bool = False) -> None:
        self.verify_checksum = verify_checksum
        self._parse_count = 0
        self._error_count = 0

    def parse(self, raw: str) -> AcarsMessage:
        """
        Parse a raw ACARS string.

        Args:
            raw: The raw ACARS message string.

        Returns:
            AcarsMessage — always returns a result; errors collected in
            parse_errors field rather than raising.
        """
        self._parse_count += 1
        errors: list[str] = []

        # ── Guard: minimum length ─────────────────────────────────────────
        if len(raw) < _MIN_HEADER_LEN:
            self._error_count += 1
            return self._error_message(
                raw, f"Message too short: {len(raw)} < {_MIN_HEADER_LEN}"
            )

        # ── Extract header fields ─────────────────────────────────────────
        try:
            mode = raw[0]
            aircraft_id = raw[1:8].strip()
            technical_ack = raw[8]
            label = raw[9:11]
            block_id = raw[11]
            msg_number = raw[12:16]
            flight_id = raw[16:22]
        except IndexError as exc:
            self._error_count += 1
            return self._error_message(raw, f"Header extraction failed: {exc}")

        # ── Validate aircraft ID ──────────────────────────────────────────
        if not _ACID_PATTERN.match(aircraft_id.replace("-", "")):
            errors.append(
                f"Suspicious aircraft ID: {aircraft_id!r} — "
                "may indicate spoofed/injected message."
            )

        # ── Extract body and optional checksum ───────────────────────────
        remainder = raw[22:]

        # ACARS checksum: last 3 chars if message ends with '*' + 2 hex digits
        checksum: Optional[str] = None
        if len(remainder) >= 3 and remainder[-3] == "*":
            checksum = remainder[-2:]
            body = remainder[:-3]
        else:
            body = remainder

        # ── Body length check ─────────────────────────────────────────────
        if len(body) > _MAX_BODY_LEN:
            errors.append(
                f"Body exceeds ARINC 618 limit: {len(body)} > {_MAX_BODY_LEN} chars. "
                "Possible buffer overflow attempt."
            )
            # NOTE: We truncate rather than reject — this is the intentional
            # weakness that Hypothesis tests should detect.
            body = body[:_MAX_BODY_LEN]

        # ── Null byte detection ───────────────────────────────────────────
        if "\x00" in body:
            errors.append(
                "Null byte (\\x00) detected in message body. "
                "May cause C-string termination in downstream ARINC avionics units."
            )

        # ── Classify message type ─────────────────────────────────────────
        msg_type = _classify(label, body)

        header = AcarsHeader(
            mode=mode,
            aircraft_id=aircraft_id,
            technical_ack=technical_ack,
            label=label,
            block_id=block_id,
            msg_number=msg_number,
            flight_id=flight_id,
        )

        is_valid = len(errors) == 0
        if not is_valid:
            self._error_count += 1

        return AcarsMessage(
            raw=raw,
            header=header,
            msg_type=msg_type,
            body=body,
            checksum=checksum,
            is_valid=is_valid,
            parse_errors=errors,
        )

    @staticmethod
    def _error_message(raw: str, reason: str) -> AcarsMessage:
        dummy_header = AcarsHeader(
            mode="?",
            aircraft_id="UNKNOWN",
            technical_ack="?",
            label="??",
            block_id="?",
            msg_number="????",
            flight_id="??????",
        )
        return AcarsMessage(
            raw=raw,
            header=dummy_header,
            msg_type=AcarsMessageType.UNKNOWN,
            body="",
            checksum=None,
            is_valid=False,
            parse_errors=[reason],
        )

    @property
    def stats(self) -> dict:
        return {
            "total_parsed": self._parse_count,
            "total_errors": self._error_count,
            "error_rate": (
                self._error_count / self._parse_count if self._parse_count > 0 else 0.0
            ),
        }


# ─────────────────────────────────────────────────────────────────────────────
# Message factory — generates realistic ACARS messages for simulation
# ─────────────────────────────────────────────────────────────────────────────


class AcarsMessageFactory:
    """Generates realistic ACARS messages for bus simulation."""

    @staticmethod
    def free_text(
        aircraft: str = "FHBXA1", flight: str = "AF447 ", text: str = ""
    ) -> str:
        body = text or "CREW MSG: REQUESTING WEATHER UPDATE FOR DEST"
        return f"2{aircraft:<7}!H10M01A{flight}{body}"

    @staticmethod
    def oooi_off(
        aircraft: str = "FHBXA1", flight: str = "AF447 ", fuel_kg: int = 18500
    ) -> str:
        body = f"QS OFF/0830 FUEL/{fuel_kg:05d}"
        return f"2{aircraft:<7}!QS0O01A{flight}{body}"

    @staticmethod
    def pdc(aircraft: str = "FHBXA1", flight: str = "AF447 ") -> str:
        body = (
            "PDC AF447 EGLL 280830\n"
            "CLRD TO LFPG VIA WOBUN2F\n"
            "INIT CLB 5000FT THEN CLB VIA SID\n"
            "SQUAWK 4271"
        )
        return f"2{aircraft:<7}!D00M02A{flight}{body}"

    @staticmethod
    def metar(aircraft: str = "FHBXA1", flight: str = "AF447 ") -> str:
        body = "METAR LFPG 281200Z 27015KT 9999 FEW035 12/04 Q1018 NOSIG"
        return f"2{aircraft:<7}!700M03A{flight}{body}"

    @staticmethod
    def fuel_order(
        aircraft: str = "FHBXA1", flight: str = "AF447 ", uplift_kg: int = 22000
    ) -> str:
        body = f"FUEL UPLIFT REQ {uplift_kg:05d}KG LFPG GATE B32"
        return f"2{aircraft:<7}!FN0M04A{flight}{body}"
