"""
ARINC 429 Label Registry
========================
Defines the avionics data labels simulated by SkyGuard.

Each ARINC 429 word is 32 bits:
  [31-30] Parity (bit 32) + SSM (bits 30-29)
  [28-11] Data field (BNR: 19 bits signed; BCD: packed digits)
  [10-9]  SDI (Source/Destination Identifier)
  [8-1]   Label (octal, transmitted LSB-first)

Reference: ARINC Specification 429 Part 1, §2
"""

from dataclasses import dataclass
from enum import Enum


class DataFormat(str, Enum):
    BNR = "BNR"  # Binary (signed integer / float)
    BCD = "BCD"  # Binary Coded Decimal
    DIS = "DIS"  # Discrete (bit flags)


class SSM(int, Enum):
    """Sign/Status Matrix — encodes data validity and sign."""

    PLUS_NORTH_EAST_RIGHT_TO = 0b00  # Positive / valid / normal
    NO_COMPUTED_DATA = 0b01  # NCD — sensor not computing
    FUNCTIONAL_TEST = 0b10  # Test mode
    FAILURE_WARNING = 0b11  # Fault condition


@dataclass(frozen=True)
class LabelDef:
    """Specification for a single ARINC 429 label."""

    octal: str  # Octal label code (e.g. "203")
    decimal: int  # Decimal equivalent
    name: str  # Human-readable parameter name
    unit: str  # Engineering unit
    fmt: DataFormat
    range_min: float  # Minimum valid value
    range_max: float  # Maximum valid value
    resolution: float  # LSB value (BNR only)
    description: str  # Parameter context for AI agents


# ─────────────────────────────────────────────────────────────────────────────
# Standard ARINC 429 labels used in SkyGuard simulation
# Sources: ARINC 429 Part 2 (equipment standards) + ARINC 700-series specs
# ─────────────────────────────────────────────────────────────────────────────

LABEL_REGISTRY: dict[str, LabelDef] = {
    # ── Navigation & Air Data ─────────────────────────────────────────────
    "203": LabelDef(
        octal="203",
        decimal=131,
        name="Baro Corrected Altitude",
        unit="ft",
        fmt=DataFormat.BNR,
        range_min=-1_200.0,
        range_max=99_900.0,
        resolution=0.125,
        description="Barometric altitude corrected for local QNH. "
        "Critical for TCAS and terrain avoidance (GPWS).",
    ),
    "206": LabelDef(
        octal="206",
        decimal=134,
        name="Pressure Altitude",
        unit="ft",
        fmt=DataFormat.BNR,
        range_min=-1_200.0,
        range_max=99_900.0,
        resolution=0.125,
        description="Raw pressure altitude (FL reference). "
        "Used by transponder for ACAS interrogation responses.",
    ),
    "210": LabelDef(
        octal="210",
        decimal=136,
        name="True Airspeed",
        unit="kt",
        fmt=DataFormat.BNR,
        range_min=0.0,
        range_max=1_000.0,
        resolution=0.0625,
        description="True airspeed computed by Air Data Computer (ADC). "
        "Tampering can trigger over-speed warnings or suppress them.",
    ),
    "211": LabelDef(
        octal="211",
        decimal=137,
        name="Indicated Airspeed",
        unit="kt",
        fmt=DataFormat.BNR,
        range_min=0.0,
        range_max=500.0,
        resolution=0.0625,
        description="IAS displayed to pilots. "
        "Critical: erroneous IAS was a factor in multiple fatal accidents.",
    ),
    "212": LabelDef(
        octal="212",
        decimal=138,
        name="Mach Number",
        unit="Mach",
        fmt=DataFormat.BNR,
        range_min=0.0,
        range_max=2.0,
        resolution=0.000488,
        description="Current Mach number from ADC. "
        "Used by autothrottle and overspeed protection systems.",
    ),
    "313": LabelDef(
        octal="313",
        decimal=203,
        name="Magnetic Heading",
        unit="deg",
        fmt=DataFormat.BNR,
        range_min=0.0,
        range_max=360.0,
        resolution=0.00549,
        description="Aircraft magnetic heading from IRS/AHRS. "
        "Spoofing this value could cause navigation deviations.",
    ),
    "314": LabelDef(
        octal="314",
        decimal=204,
        name="True Heading",
        unit="deg",
        fmt=DataFormat.BNR,
        range_min=0.0,
        range_max=360.0,
        resolution=0.00549,
        description="True heading. Used in FMS for track computation.",
    ),
    "324": LabelDef(
        octal="324",
        decimal=212,
        name="Ground Speed",
        unit="kt",
        fmt=DataFormat.BNR,
        range_min=0.0,
        range_max=1_000.0,
        resolution=0.0625,
        description="GPS/IRS ground speed. "
        "FMS uses this for fuel and ETA calculations.",
    ),
    "310": LabelDef(
        octal="310",
        decimal=200,
        name="Latitude",
        unit="deg",
        fmt=DataFormat.BNR,
        range_min=-90.0,
        range_max=90.0,
        resolution=0.000021,
        description="Aircraft latitude from GPS/IRS. "
        "Injection attacks could feed false position to FMS.",
    ),
    "311": LabelDef(
        octal="311",
        decimal=201,
        name="Longitude",
        unit="deg",
        fmt=DataFormat.BNR,
        range_min=-180.0,
        range_max=180.0,
        resolution=0.000021,
        description="Aircraft longitude from GPS/IRS.",
    ),
    # ── Engine Data ───────────────────────────────────────────────────────
    "100": LabelDef(
        octal="100",
        decimal=64,
        name="Engine N1 Speed (Eng 1)",
        unit="%",
        fmt=DataFormat.BNR,
        range_min=0.0,
        range_max=120.0,
        resolution=0.0037,
        description="Fan speed (N1) for engine 1. "
        "FADEC uses this for thrust limiting and overspeed protection.",
    ),
    "101": LabelDef(
        octal="101",
        decimal=65,
        name="Engine N2 Speed (Eng 1)",
        unit="%",
        fmt=DataFormat.BNR,
        range_min=0.0,
        range_max=120.0,
        resolution=0.0037,
        description="Core speed (N2) for engine 1.",
    ),
    "164": LabelDef(
        octal="164",
        decimal=116,
        name="Fuel Flow (Eng 1)",
        unit="kg/h",
        fmt=DataFormat.BNR,
        range_min=0.0,
        range_max=15_000.0,
        resolution=0.5,
        description="Fuel flow rate for engine 1. "
        "Used by FMS for fuel planning and ECAM alerts.",
    ),
    # ── Discrete / Status ─────────────────────────────────────────────────
    "270": LabelDef(
        octal="270",
        decimal=184,
        name="Landing Gear Position",
        unit="discrete",
        fmt=DataFormat.DIS,
        range_min=0,
        range_max=7,
        resolution=1.0,
        description="3-bit discrete: bit0=nose, bit1=left main, bit2=right main. "
        "0=up/locked, 1=down/locked. Used by GPWS and ACARS.",
    ),
    "177": LabelDef(
        octal="177",
        decimal=127,
        name="Flap Position",
        unit="deg",
        fmt=DataFormat.BNR,
        range_min=0.0,
        range_max=45.0,
        resolution=0.022,
        description="Leading/trailing edge flap position. "
        "Used for take-off config warnings.",
    ),
}


def get_label(octal_code: str) -> LabelDef:
    """Retrieve a label definition by its octal code."""
    if octal_code not in LABEL_REGISTRY:
        raise KeyError(
            f"Unknown ARINC 429 label: {octal_code!r}. "
            f"Available: {sorted(LABEL_REGISTRY.keys())}"
        )
    return LABEL_REGISTRY[octal_code]


def all_labels() -> list[LabelDef]:
    """Return all registered label definitions."""
    return list(LABEL_REGISTRY.values())
