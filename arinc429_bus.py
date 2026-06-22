"""
SkyGuard — ARINC 429 Bus Simulator
===================================
Simulates the ARINC 429 avionics data bus protocol used on commercial
aircraft (A320, B737, and most airliners still in service).

ARINC 429 frame structure (32 bits, transmitted LSB first on wire):
  Bits  1-8  : Label     (octal address, identifies the data type)
  Bits  9-10 : SDI       (Source/Destination Identifier)
  Bits 11-29 : Data      (BNR, BCD, or discrete depending on label)
  Bits 30-31 : SSM       (Sign/Status Matrix — validity and sign)
  Bit  32    : Parity    (odd parity over bits 1-31)

Reference: ARINC Specification 429 Part 1 (publicly documented structure).
This simulator is for cybersecurity QA testing only — not for flight use.
"""

from __future__ import annotations

import random
import struct
from dataclasses import dataclass, field
from enum import IntEnum
from typing import Iterator


# ---------------------------------------------------------------------------
# Enumerations
# ---------------------------------------------------------------------------

class SSM(IntEnum):
    """Sign/Status Matrix values for BNR (binary) words."""
    PLUS_NORTH_RIGHT_TO = 0b00   # Positive / North / Right / To
    NO_COMPUTED_DATA    = 0b01   # NCD — data unavailable
    FUNCTIONAL_TEST     = 0b10   # Test mode
    FAILURE_WARNING     = 0b11   # Data invalid / source failed


class SDI(IntEnum):
    """Source/Destination Identifier — which LRU the word targets."""
    ALL    = 0b00
    RCVR_1 = 0b01
    RCVR_2 = 0b10
    RCVR_3 = 0b11


# ---------------------------------------------------------------------------
# Well-known ARINC 429 labels (octal → decimal)
# Subset relevant to cybersecurity testing scenarios.
# ---------------------------------------------------------------------------

LABEL_CATALOG: dict[int, dict] = {
    # label (decimal) : {name, unit, bnr_range, resolution}
    0o101: {"name": "Computed Airspeed",    "unit": "knots",   "min": 0,      "max": 450,   "resolution": 0.25},
    0o102: {"name": "Mach Number",          "unit": "mach",    "min": 0.0,    "max": 1.0,   "resolution": 0.001},
    0o103: {"name": "Maximum Airspeed",     "unit": "knots",   "min": 0,      "max": 450,   "resolution": 0.25},
    0o203: {"name": "Baro Altitude",        "unit": "feet",    "min": -2000,  "max": 50000, "resolution": 4.0},
    0o206: {"name": "Baro Corrected Alt",   "unit": "feet",    "min": -2000,  "max": 50000, "resolution": 4.0},
    0o310: {"name": "True Heading",         "unit": "degrees", "min": 0.0,    "max": 360.0, "resolution": 0.0055},
    0o311: {"name": "Magnetic Heading",     "unit": "degrees", "min": 0.0,    "max": 360.0, "resolution": 0.0055},
    0o312: {"name": "True Track Angle",     "unit": "degrees", "min": 0.0,    "max": 360.0, "resolution": 0.0055},
    0o313: {"name": "Drift Angle",          "unit": "degrees", "min": -90.0,  "max": 90.0,  "resolution": 0.0055},
    0o324: {"name": "Pitch Attitude",       "unit": "degrees", "min": -90.0,  "max": 90.0,  "resolution": 0.0055},
    0o325: {"name": "Roll Attitude",        "unit": "degrees", "min": -180.0, "max": 180.0, "resolution": 0.0055},
    0o361: {"name": "Ground Speed",         "unit": "knots",   "min": 0,      "max": 1000,  "resolution": 0.5},
    0o362: {"name": "Wind Speed",           "unit": "knots",   "min": 0,      "max": 250,   "resolution": 0.5},
    0o365: {"name": "Total Air Temperature","unit": "celsius",  "min": -100.0, "max": 60.0,  "resolution": 0.25},
}


# ---------------------------------------------------------------------------
# Core data structures
# ---------------------------------------------------------------------------

@dataclass
class ARINC429Word:
    """
    Represents a single ARINC 429 32-bit word.

    Attributes
    ----------
    label       Octal label number (8 bits, identifies data type)
    sdi         Source/Destination Identifier (2 bits)
    data_raw    Raw 19-bit data field value (unsigned integer)
    ssm         Sign/Status Matrix (2 bits)
    parity      Computed odd parity bit
    raw_word    Full 32-bit frame as integer
    """
    label:    int
    sdi:      SDI      = SDI.ALL
    data_raw: int      = 0
    ssm:      SSM      = SSM.PLUS_NORTH_RIGHT_TO
    parity:   int      = 0
    raw_word: int      = 0

    @property
    def label_name(self) -> str:
        info = LABEL_CATALOG.get(self.label)
        return info["name"] if info else f"Unknown (0o{self.label:03o})"

    @property
    def is_valid(self) -> bool:
        return self.ssm not in (SSM.FAILURE_WARNING, SSM.NO_COMPUTED_DATA)

    @property
    def parity_ok(self) -> bool:
        # Odd parity: total number of 1-bits across all 32 bits must be odd.
        return bin(self.raw_word).count("1") % 2 == 1


@dataclass
class BusFrame:
    """A timestamped collection of ARINC 429 words — one bus transmission."""
    words:     list[ARINC429Word] = field(default_factory=list)
    timestamp: float              = 0.0
    bus_id:    str                = "BUS-1"
    corrupted: bool               = False


# ---------------------------------------------------------------------------
# Encoding / decoding
# ---------------------------------------------------------------------------

def encode_word(
    label:    int,
    data_raw: int,
    sdi:      SDI = SDI.ALL,
    ssm:      SSM = SSM.PLUS_NORTH_RIGHT_TO,
) -> ARINC429Word:
    """
    Encode a 32-bit ARINC 429 word from its fields.

    Layout (bit 1 = LSB of transmitted byte):
      [parity|ssm1|ssm0|d18..d0|sdi1|sdi0|lbl7..lbl0]
      bit32  31   30   29..11   10   9    8..1
    """
    label_masked = label & 0xFF
    sdi_masked   = (int(sdi) & 0x3) << 8
    data_masked  = (data_raw & 0x7FFFF) << 10
    ssm_masked   = (int(ssm) & 0x3) << 29

    word_no_parity = label_masked | sdi_masked | data_masked | ssm_masked
    parity_bit     = _compute_parity(word_no_parity) << 31
    raw_word       = word_no_parity | parity_bit

    return ARINC429Word(
        label=label,
        sdi=sdi,
        data_raw=data_raw,
        ssm=ssm,
        parity=parity_bit >> 31,
        raw_word=raw_word,
    )


def decode_word(raw: int) -> ARINC429Word:
    """Decode a 32-bit integer into an ARINC429Word."""
    label    = raw & 0xFF
    sdi_val  = (raw >> 8)  & 0x3
    data_raw = (raw >> 10) & 0x7FFFF
    ssm_val  = (raw >> 29) & 0x3
    parity   = (raw >> 31) & 0x1

    return ARINC429Word(
        label=label,
        sdi=SDI(sdi_val),
        data_raw=data_raw,
        ssm=SSM(ssm_val),
        parity=parity,
        raw_word=raw,
    )


def encode_bnr_value(label: int, value: float) -> ARINC429Word:
    """
    Encode a real-world engineering value into BNR (Binary) format.
    Uses the resolution and range from LABEL_CATALOG.
    Raises ValueError if label unknown or value out of range.
    """
    info = LABEL_CATALOG.get(label)
    if not info:
        raise ValueError(f"Label 0o{label:03o} not in catalog")

    lo, hi, res = info["min"], info["max"], info["resolution"]
    if not (lo <= value <= hi):
        raise ValueError(
            f"Value {value} out of range [{lo}, {hi}] for {info['name']}"
        )

    data_raw = int(round(value / res))
    ssm = SSM.PLUS_NORTH_RIGHT_TO if value >= 0 else SSM.PLUS_NORTH_RIGHT_TO
    return encode_word(label, data_raw, ssm=ssm)


def decode_bnr_value(word: ARINC429Word) -> float | None:
    """
    Decode BNR data to engineering value using LABEL_CATALOG resolution.
    Returns None if word SSM indicates invalid data.
    """
    if not word.is_valid:
        return None
    info = LABEL_CATALOG.get(word.label)
    if not info:
        return None
    return word.data_raw * info["resolution"]


# ---------------------------------------------------------------------------
# Scenario generators — normal flight data
# ---------------------------------------------------------------------------

class NormalFlightScenario:
    """
    Generates realistic ARINC 429 bus frames for a normal cruise scenario.
    Values reflect typical A320 cruise at FL350, Mach 0.78.
    """

    CRUISE_VALUES: dict[int, float] = {
        0o101: 280.0,    # CAS ~280 kt
        0o102: 0.78,     # Mach 0.78
        0o203: 35000.0,  # Baro altitude 35 000 ft
        0o310: 087.0,    # True heading 087°
        0o324: 2.5,      # Pitch +2.5°
        0o325: 0.3,      # Roll ~0° (slight bank)
        0o361: 460.0,    # Ground speed 460 kt
        0o365: -56.0,    # TAT -56°C at FL350
    }

    def generate_frame(self, timestamp: float = 0.0, jitter: float = 0.01) -> BusFrame:
        """Generate one bus frame with small random jitter on each value."""
        words = []
        for label, base_value in self.CRUISE_VALUES.items():
            info   = LABEL_CATALOG[label]
            jitter_val = base_value * (1 + random.uniform(-jitter, jitter))
            clamped    = max(info["min"], min(info["max"], jitter_val))
            word       = encode_bnr_value(label, clamped)
            words.append(word)
        return BusFrame(words=words, timestamp=timestamp, bus_id="BUS-1")

    def stream(self, count: int = 50, interval: float = 0.1) -> Iterator[BusFrame]:
        """Yield `count` consecutive frames spaced by `interval` seconds."""
        for i in range(count):
            yield self.generate_frame(timestamp=i * interval)


# ---------------------------------------------------------------------------
# Attack / anomaly scenario generators
# ---------------------------------------------------------------------------

class OutOfRangeInjector:
    """
    Scenario: attacker injects a word whose data value exceeds the physical
    maximum for that label.  A robust parser must reject this; a naive one
    may propagate the value to flight displays.

    Cyber relevance: ARINC 429 has no authentication — any LRU on the bus
    can transmit.  A compromised LRU (e.g. via maintenance port) could
    inject malformed data.
    """

    def inject(self, label: int, multiplier: float = 2.5) -> ARINC429Word:
        """
        Build a word whose data_raw encodes a value `multiplier × max_range`.
        Bypasses encode_bnr_value validation intentionally.
        """
        info     = LABEL_CATALOG.get(label)
        if not info:
            raise ValueError(f"Unknown label 0o{label:03o}")
        bad_val  = info["max"] * multiplier
        data_raw = int(round(bad_val / info["resolution"])) & 0x7FFFF
        return encode_word(label, data_raw, ssm=SSM.PLUS_NORTH_RIGHT_TO)

    def batch(self, count: int = 10) -> list[ARINC429Word]:
        """Inject out-of-range values across a random selection of labels."""
        labels = random.choices(list(LABEL_CATALOG.keys()), k=count)
        return [self.inject(lbl) for lbl in labels]


class ParityCorruptionInjector:
    """
    Scenario: flip one or more bits in a valid word to corrupt parity.
    A parser that skips parity checking will silently accept corrupt data.

    Cyber relevance: demonstrates importance of integrity validation even
    on a physically isolated bus (ARINC 429 is point-to-point but multi-
    receiver wiring can be tapped in maintenance scenarios).
    """

    def corrupt(self, word: ARINC429Word, flip_bits: int = 1) -> ARINC429Word:
        """Return a new word with `flip_bits` random bits flipped."""
        raw = word.raw_word
        positions = random.sample(range(32), flip_bits)
        for pos in positions:
            raw ^= (1 << pos)
        return decode_word(raw)

    def corrupt_frame(self, frame: BusFrame, ratio: float = 0.3) -> BusFrame:
        """Corrupt `ratio` of words in a frame. Returns a new BusFrame."""
        corrupted_words = []
        for word in frame.words:
            if random.random() < ratio:
                corrupted_words.append(self.corrupt(word))
            else:
                corrupted_words.append(word)
        return BusFrame(
            words=corrupted_words,
            timestamp=frame.timestamp,
            bus_id=frame.bus_id,
            corrupted=True,
        )


class SSMSpoofingInjector:
    """
    Scenario: force SSM to FUNCTIONAL_TEST or NO_COMPUTED_DATA on critical
    labels to deny flight systems valid data (availability attack).

    Alternatively, force SSM to PLUS_NORTH_RIGHT_TO on a FAILURE_WARNING
    word to make bad data appear valid (integrity attack).

    Cyber relevance: mapped to ED-202A threat category T3 — data
    manipulation by compromised onboard network equipment.
    """

    def spoof_validity(
        self, word: ARINC429Word, target_ssm: SSM = SSM.NO_COMPUTED_DATA
    ) -> ARINC429Word:
        """Replace SSM with `target_ssm`, recompute parity."""
        return encode_word(word.label, word.data_raw, word.sdi, target_ssm)

    def denial_of_data_attack(self, frame: BusFrame) -> BusFrame:
        """Set all critical navigation labels to NO_COMPUTED_DATA."""
        critical = {0o203, 0o310, 0o324, 0o325, 0o361}
        new_words = []
        for w in frame.words:
            if w.label in critical:
                new_words.append(self.spoof_validity(w, SSM.NO_COMPUTED_DATA))
            else:
                new_words.append(w)
        return BusFrame(
            words=new_words,
            timestamp=frame.timestamp,
            bus_id=frame.bus_id,
            corrupted=True,
        )


class ReplayAttackGenerator:
    """
    Scenario: capture a sequence of valid frames and retransmit them later
    to confuse avionics about the aircraft's current state.

    Cyber relevance: ARINC 429 has no sequence numbers or timestamps in the
    protocol itself — all anti-replay protection must be at the application
    layer.  This scenario demonstrates that gap.
    """

    def __init__(self) -> None:
        self._captured: list[BusFrame] = []

    def capture(self, frames: list[BusFrame]) -> None:
        self._captured = list(frames)

    def replay(self, offset_seconds: float = 30.0) -> list[BusFrame]:
        """Return captured frames with timestamps shifted forward."""
        if not self._captured:
            raise RuntimeError("No frames captured yet — call capture() first")
        return [
            BusFrame(
                words=f.words,
                timestamp=f.timestamp + offset_seconds,
                bus_id=f.bus_id + "-REPLAY",
                corrupted=True,
            )
            for f in self._captured
        ]


# ---------------------------------------------------------------------------
# Bus validator — the system under test
# ---------------------------------------------------------------------------

@dataclass
class ValidationResult:
    word:          ARINC429Word
    parity_ok:     bool
    range_ok:      bool
    ssm_valid:     bool
    anomaly_flags: list[str] = field(default_factory=list)

    @property
    def is_safe(self) -> bool:
        return self.parity_ok and self.range_ok and self.ssm_valid


class ARINC429Validator:
    """
    Validates incoming ARINC 429 words against protocol rules.
    This is the component under test — its robustness is what we verify.
    """

    def validate(self, word: ARINC429Word) -> ValidationResult:
        flags: list[str] = []

        parity_ok = word.parity_ok
        if not parity_ok:
            flags.append("PARITY_ERROR")

        ssm_valid = word.ssm not in (SSM.FAILURE_WARNING, SSM.NO_COMPUTED_DATA)
        if not ssm_valid:
            flags.append(f"SSM_INVALID:{word.ssm.name}")

        range_ok = True
        info = LABEL_CATALOG.get(word.label)
        if info:
            eng_val = decode_bnr_value(word)
            if eng_val is not None:
                if not (info["min"] <= eng_val <= info["max"]):
                    range_ok = False
                    flags.append(
                        f"OUT_OF_RANGE:{eng_val:.2f} (expected [{info['min']},{info['max']}])"
                    )
        else:
            flags.append("UNKNOWN_LABEL")

        return ValidationResult(
            word=word,
            parity_ok=parity_ok,
            range_ok=range_ok,
            ssm_valid=ssm_valid,
            anomaly_flags=flags,
        )

    def validate_frame(self, frame: BusFrame) -> list[ValidationResult]:
        return [self.validate(w) for w in frame.words]

    def anomaly_count(self, results: list[ValidationResult]) -> int:
        return sum(1 for r in results if not r.is_safe)


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _compute_parity(word: int) -> int:
    """
    Compute odd parity over bits 0-30 (bit 31 is the parity bit itself).
    ARINC 429 uses odd parity: total number of 1-bits including parity = odd.
    """
    data_bits = word & 0x7FFFFFFF
    ones = bin(data_bits).count("1")
    return 0 if ones % 2 == 1 else 1


def frame_to_bytes(frame: BusFrame) -> bytes:
    """Serialize a BusFrame to raw bytes (4 bytes per word, big-endian)."""
    return b"".join(struct.pack(">I", w.raw_word) for w in frame.words)


def bytes_to_words(data: bytes) -> list[ARINC429Word]:
    """Deserialize raw bytes into ARINC429Words."""
    if len(data) % 4 != 0:
        raise ValueError("Data length must be a multiple of 4 bytes")
    count = len(data) // 4
    raws  = struct.unpack(f">{count}I", data)
    return [decode_word(r) for r in raws]
