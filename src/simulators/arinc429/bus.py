"""
ARINC 429 Bus Simulator
========================
Simulates an avionics data bus transmitting labeled parameters
during normal flight phases, with built-in fault injection support.

This is the primary data source for SkyGuard's threat detection:
  - Normal mode: produces a realistic stream of correlated parameters
  - Fault injection: introduces specific anomalies for security testing

Fault injection categories (inspired by ARINC 429 threat taxonomy):
  - RANGE_VIOLATION   : value outside certified operating range
  - PARITY_CORRUPTION : bit flip in parity bit → data integrity failure
  - SSM_SPOOF         : valid data with forged SSM (e.g. FAILURE_WARNING on good data)
  - LABEL_INJECTION   : unknown/undocumented label injected on bus
  - REPLAY_ATTACK     : identical word repeated at wrong rate (freeze attack)
  - SILENT_CORRUPTION : value within range but physically implausible
"""

from __future__ import annotations

import random
import time
from dataclasses import dataclass
from enum import Enum
from typing import Generator, Optional

from .codec import decode, Arinc429Word, encoder
from .labels import SSM, get_label, DataFormat


# ─────────────────────────────────────────────────────────────────────────────
# Flight phase model
# ─────────────────────────────────────────────────────────────────────────────


class FlightPhase(str, Enum):
    GROUND = "GROUND"
    TAKEOFF = "TAKEOFF"
    CLIMB = "CLIMB"
    CRUISE = "CRUISE"
    DESCENT = "DESCENT"
    APPROACH = "APPROACH"
    LANDING = "LANDING"


# Realistic parameter ranges per flight phase
PHASE_PARAMETERS: dict[FlightPhase, dict[str, tuple[float, float]]] = {
    FlightPhase.GROUND: {
        "203": (0, 50),  # Altitude ft
        "210": (0, 30),  # TAS kt
        "211": (0, 30),  # IAS kt
        "212": (0.0, 0.05),  # Mach
        "313": (0, 360),  # Heading deg
        "324": (0, 10),  # Ground speed kt
        "100": (18, 22),  # N1 % (idle)
        "164": (200, 400),  # Fuel flow kg/h
        "270": (7, 7),  # Gear down (0b111)
        "177": (0, 5),  # Flaps
    },
    FlightPhase.TAKEOFF: {
        "203": (0, 500),
        "210": (100, 200),
        "211": (100, 200),
        "212": (0.15, 0.30),
        "313": (0, 360),
        "324": (80, 200),
        "100": (90, 102),  # N1 TOGA
        "164": (5_000, 8_000),
        "270": (7, 7),  # Gear down initially
        "177": (15, 20),
    },
    FlightPhase.CLIMB: {
        "203": (1_000, 35_000),
        "210": (250, 450),
        "211": (250, 320),
        "212": (0.40, 0.78),
        "313": (0, 360),
        "324": (300, 500),
        "100": (85, 95),
        "164": (2_500, 5_000),
        "270": (0, 0),  # Gear up
        "177": (0, 5),
    },
    FlightPhase.CRUISE: {
        "203": (35_000, 42_000),
        "210": (450, 520),
        "211": (260, 310),
        "212": (0.78, 0.86),
        "313": (0, 360),
        "324": (450, 550),
        "100": (82, 90),
        "164": (2_000, 3_500),
        "270": (0, 0),
        "177": (0, 0),
    },
    FlightPhase.DESCENT: {
        "203": (2_000, 35_000),
        "210": (300, 480),
        "211": (250, 320),
        "212": (0.50, 0.82),
        "313": (0, 360),
        "324": (300, 480),
        "100": (40, 70),  # Idle/flight idle
        "164": (500, 1_500),
        "270": (0, 0),
        "177": (0, 5),
    },
    FlightPhase.APPROACH: {
        "203": (0, 5_000),
        "210": (130, 200),
        "211": (130, 200),
        "212": (0.18, 0.30),
        "313": (0, 360),
        "324": (120, 200),
        "100": (50, 75),
        "164": (800, 2_000),
        "270": (7, 7),  # Gear down
        "177": (25, 40),
    },
    FlightPhase.LANDING: {
        "203": (0, 200),
        "210": (120, 160),
        "211": (120, 160),
        "212": (0.16, 0.24),
        "313": (0, 360),
        "324": (100, 160),
        "100": (50, 70),
        "164": (600, 1_200),
        "270": (7, 7),
        "177": (35, 45),
    },
}


# ─────────────────────────────────────────────────────────────────────────────
# Fault injection types
# ─────────────────────────────────────────────────────────────────────────────


class FaultType(str, Enum):
    RANGE_VIOLATION = "RANGE_VIOLATION"
    PARITY_CORRUPTION = "PARITY_CORRUPTION"
    SSM_SPOOF = "SSM_SPOOF"
    LABEL_INJECTION = "LABEL_INJECTION"
    REPLAY_ATTACK = "REPLAY_ATTACK"
    SILENT_CORRUPTION = "SILENT_CORRUPTION"


@dataclass
class InjectedFault:
    """Describes a fault that was injected into the bus stream."""

    fault_type: FaultType
    label_octal: str
    original_value: Optional[float]
    injected_value: Optional[float]
    raw_word: int
    description: str


@dataclass
class BusFrame:
    """A single bus transmission event."""

    word: Arinc429Word
    timestamp_ms: float
    phase: FlightPhase
    fault: Optional[InjectedFault] = None

    @property
    def is_faulted(self) -> bool:
        return self.fault is not None


# ─────────────────────────────────────────────────────────────────────────────
# Bus Simulator
# ─────────────────────────────────────────────────────────────────────────────


class Arinc429BusSimulator:
    """
    Simulates an ARINC 429 data bus for a commercial aircraft.

    Usage:
        bus = Arinc429BusSimulator(phase=FlightPhase.CRUISE)
        for frame in bus.stream(count=100):
            print(frame.word.to_dict())

    Fault injection:
        bus.inject_fault(FaultType.RANGE_VIOLATION, label="210")
    """

    def __init__(
        self,
        phase: FlightPhase = FlightPhase.CRUISE,
        seed: Optional[int] = None,
    ) -> None:
        self.phase = phase
        self._rng = random.Random(seed)
        self._pending_faults: list[tuple[FaultType, Optional[str]]] = []
        self._last_words: dict[str, int] = {}  # for replay attack simulation
        self._frame_count: int = 0
        self._t0 = time.monotonic()

    def set_phase(self, phase: FlightPhase) -> None:
        """Change the active flight phase."""
        self.phase = phase

    def inject_fault(
        self,
        fault_type: FaultType,
        label: Optional[str] = None,
    ) -> None:
        """
        Queue a fault for injection on the next transmission.

        Args:
            fault_type: Category of fault to inject.
            label: Specific label to target (random if None).
        """
        self._pending_faults.append((fault_type, label))

    def _pick_label(self, label: Optional[str] = None) -> str:
        """Pick a label to target (random from current phase if not specified)."""
        if label:
            return label
        phase_labels = list(PHASE_PARAMETERS[self.phase].keys())
        return self._rng.choice(phase_labels)

    def _normal_value(self, label_octal: str) -> float:
        """Generate a realistic value for a label in the current phase."""
        lo, hi = PHASE_PARAMETERS[self.phase].get(label_octal, (0.0, 1.0))
        ld = get_label(label_octal)
        if ld.fmt == DataFormat.DIS:
            return float(int(self._rng.uniform(lo, hi)))
        return round(self._rng.uniform(lo, hi), 3)

    def _build_normal_frame(self, label_octal: str) -> BusFrame:
        """Build a fault-free frame for the given label."""
        value = self._normal_value(label_octal)
        ld = get_label(label_octal)
        if ld.fmt == DataFormat.DIS:
            raw = encoder.encode_discrete(label_octal, int(value))
        else:
            raw = encoder.encode_bnr(label_octal, value)
        word = decode(raw)
        self._last_words[label_octal] = raw
        return BusFrame(
            word=word,
            timestamp_ms=(time.monotonic() - self._t0) * 1000,
            phase=self.phase,
        )

    # ── Fault builders ────────────────────────────────────────────────────

    def _fault_range_violation(self, label_octal: str) -> BusFrame:
        """Inject a value significantly outside the certified range."""
        ld = get_label(label_octal)
        original = self._normal_value(label_octal)
        # Choose above max or below min
        if self._rng.random() > 0.5:
            bad_value = ld.range_max * self._rng.uniform(1.05, 2.0)
        else:
            bad_value = (
                ld.range_min - abs(ld.range_min) * self._rng.uniform(0.1, 1.0) - 1.0
            )

        raw = encoder.encode_bnr(label_octal, bad_value, _override_range_check=True)
        word = decode(raw)

        fault = InjectedFault(
            fault_type=FaultType.RANGE_VIOLATION,
            label_octal=label_octal,
            original_value=original,
            injected_value=bad_value,
            raw_word=raw,
            description=(
                f"{ld.name}: injected {bad_value:.2f} {ld.unit} "
                f"(certified range: [{ld.range_min}, {ld.range_max}]). "
                f"Potential: sensor spoofing / data injection attack."
            ),
        )
        return BusFrame(
            word=word,
            timestamp_ms=(time.monotonic() - self._t0) * 1000,
            phase=self.phase,
            fault=fault,
        )

    def _fault_parity_corruption(self, label_octal: str) -> BusFrame:
        """Flip the parity bit — simulates data integrity attack."""
        value = self._normal_value(label_octal)
        ld = get_label(label_octal)
        raw = encoder.encode_bnr(label_octal, value)
        corrupted = raw ^ (1 << 31)  # flip parity bit
        word = decode(corrupted)

        fault = InjectedFault(
            fault_type=FaultType.PARITY_CORRUPTION,
            label_octal=label_octal,
            original_value=value,
            injected_value=value,
            raw_word=corrupted,
            description=(
                f"{ld.name}: parity bit flipped. "
                f"Word 0x{raw:08X} → 0x{corrupted:08X}. "
                f"Attack: MitM bit-flip to bypass integrity check."
            ),
        )
        return BusFrame(
            word=word,
            timestamp_ms=(time.monotonic() - self._t0) * 1000,
            phase=self.phase,
            fault=fault,
        )

    def _fault_ssm_spoof(self, label_octal: str) -> BusFrame:
        """
        Send valid data with a spoofed SSM (FAILURE_WARNING on good data).
        This tricks downstream systems into ignoring valid sensor data.
        """
        value = self._normal_value(label_octal)
        ld = get_label(label_octal)
        raw = encoder.encode_bnr(label_octal, value, ssm=SSM.FAILURE_WARNING)
        word = decode(raw)

        fault = InjectedFault(
            fault_type=FaultType.SSM_SPOOF,
            label_octal=label_octal,
            original_value=value,
            injected_value=value,
            raw_word=raw,
            description=(
                f"{ld.name}: SSM forged to FAILURE_WARNING with valid data {value:.2f} {ld.unit}. "
                f"Attack: causes FMS/autopilot to reject valid sensor, switch to backup. "
                f"If backup is also attacked: loss of redundancy."
            ),
        )
        return BusFrame(
            word=word,
            timestamp_ms=(time.monotonic() - self._t0) * 1000,
            phase=self.phase,
            fault=fault,
        )

    def _fault_silent_corruption(self, label_octal: str) -> BusFrame:
        """
        Value within certified range but physically implausible.
        Example: IAS=310kt while altitude=100ft (impossible in landing config).
        Hardest to detect: passes all format checks.
        """
        ld = get_label(label_octal)
        original = self._normal_value(label_octal)
        # Send a value from a *different* phase range (still in certified range)
        other_phases = [p for p in FlightPhase if p != self.phase]
        alt_phase = self._rng.choice(other_phases)
        alt_lo, alt_hi = PHASE_PARAMETERS.get(alt_phase, {}).get(
            label_octal, (ld.range_min, ld.range_max)
        )
        bad_value = round(self._rng.uniform(alt_lo, alt_hi), 3)

        raw = encoder.encode_bnr(label_octal, bad_value)
        word = decode(raw)

        fault = InjectedFault(
            fault_type=FaultType.SILENT_CORRUPTION,
            label_octal=label_octal,
            original_value=original,
            injected_value=bad_value,
            raw_word=raw,
            description=(
                f"{ld.name}: value {bad_value:.2f} {ld.unit} is within range but implausible "
                f"for phase {self.phase.value} (expected ~{original:.2f}). "
                f"Attack: cross-parameter inconsistency — only detectable by sensor fusion."
            ),
        )
        return BusFrame(
            word=word,
            timestamp_ms=(time.monotonic() - self._t0) * 1000,
            phase=self.phase,
            fault=fault,
        )

    def _fault_replay_attack(self, label_octal: str) -> BusFrame:
        """
        Resend the last observed word for a label (freeze attack).
        Simulates a MitM attacker replaying stale data to mask changes.
        """
        ld = get_label(label_octal)
        if label_octal not in self._last_words:
            # No previous word; generate one to freeze
            normal = self._build_normal_frame(label_octal)
            self._last_words[label_octal] = normal.word.raw_word

        frozen_raw = self._last_words[label_octal]
        word = decode(frozen_raw)
        current_expected = self._normal_value(label_octal)

        fault = InjectedFault(
            fault_type=FaultType.REPLAY_ATTACK,
            label_octal=label_octal,
            original_value=current_expected,
            injected_value=word.value,
            raw_word=frozen_raw,
            description=(
                f"{ld.name}: stale value {word.value:.2f} {ld.unit} replayed "
                f"(expected ~{current_expected:.2f}). "
                f"Attack: data freeze — aircraft appears to have constant {ld.name.lower()}."
            ),
        )
        return BusFrame(
            word=word,
            timestamp_ms=(time.monotonic() - self._t0) * 1000,
            phase=self.phase,
            fault=fault,
        )

    def _build_faulted_frame(self, fault_type: FaultType, label_octal: str) -> BusFrame:
        """Dispatch to the correct fault builder."""
        builders = {
            FaultType.RANGE_VIOLATION: self._fault_range_violation,
            FaultType.PARITY_CORRUPTION: self._fault_parity_corruption,
            FaultType.SSM_SPOOF: self._fault_ssm_spoof,
            FaultType.SILENT_CORRUPTION: self._fault_silent_corruption,
            FaultType.REPLAY_ATTACK: self._fault_replay_attack,
        }
        return builders[fault_type](label_octal)

    # ── Public interface ──────────────────────────────────────────────────

    def transmit_one(self, label_octal: Optional[str] = None) -> BusFrame:
        """Transmit a single ARINC 429 word."""
        self._frame_count += 1

        # Consume pending fault if any
        if self._pending_faults:
            fault_type, target_label = self._pending_faults.pop(0)
            resolved_label = target_label or self._pick_label()
            return self._build_faulted_frame(fault_type, resolved_label)

        # Normal transmission
        target = label_octal or self._pick_label()
        return self._build_normal_frame(target)

    def stream(
        self,
        count: int = 100,
        labels: Optional[list[str]] = None,
    ) -> Generator[BusFrame, None, None]:
        """
        Generate a stream of bus frames.

        Args:
            count: Number of words to generate.
            labels: Labels to cycle through (all phase labels if None).
        """
        active_labels = labels or list(PHASE_PARAMETERS[self.phase].keys())
        for i in range(count):
            label = active_labels[i % len(active_labels)]
            yield self.transmit_one(label)

    def burst_all_labels(self) -> list[BusFrame]:
        """Transmit one word for every registered label in the current phase."""
        phase_labels = list(PHASE_PARAMETERS[self.phase].keys())
        return [self.transmit_one(lbl) for lbl in phase_labels]
