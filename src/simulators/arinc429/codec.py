"""
ARINC 429 Frame Encoder / Decoder
==================================
Implements the 32-bit ARINC 429 word format:

  Bit 32 (MSB)  : Parity (odd parity over bits 1-32)
  Bits 31-30    : SSM (Sign/Status Matrix)
  Bits 29-11    : Data field (19 bits for BNR/BCD)
  Bits 10-9     : SDI (Source/Destination Identifier)
  Bits 8-1 (LSB): Label (8-bit octal, transmitted LSB-first)

Reference: ARINC Specification 429-17 Part 1, Section 2.
"""

from __future__ import annotations

import struct
from dataclasses import dataclass
from typing import Optional

from .labels import DataFormat, LabelDef, SSM, get_label


# ─────────────────────────────────────────────────────────────────────────────
# ARINC 429 Word
# ─────────────────────────────────────────────────────────────────────────────

@dataclass
class Arinc429Word:
    """A decoded ARINC 429 32-bit word."""
    label_octal: str
    label_def: LabelDef
    value: float             # Decoded engineering value
    ssm: SSM
    sdi: int                 # 0-3
    raw_word: int            # Original 32-bit integer
    parity_ok: bool

    @property
    def is_valid(self) -> bool:
        """True when word is valid: parity OK, SSM indicates normal data."""
        return (
            self.parity_ok
            and self.ssm == SSM.PLUS_NORTH_EAST_RIGHT_TO
        )

    @property
    def in_range(self) -> bool:
        """True when decoded value is within the label's certified range."""
        ld = self.label_def
        return ld.range_min <= self.value <= ld.range_max

    def to_dict(self) -> dict:
        return {
            "label_octal": self.label_octal,
            "parameter": self.label_def.name,
            "unit": self.label_def.unit,
            "value": self.value,
            "ssm": self.ssm.name,
            "sdi": self.sdi,
            "parity_ok": self.parity_ok,
            "is_valid": self.is_valid,
            "in_range": self.in_range,
            "raw_word_hex": f"0x{self.raw_word:08X}",
        }


# ─────────────────────────────────────────────────────────────────────────────
# Encoder
# ─────────────────────────────────────────────────────────────────────────────

class Arinc429Encoder:
    """Encodes engineering values into ARINC 429 32-bit words."""

    @staticmethod
    def _octal_to_bits(octal_str: str) -> int:
        """
        Convert octal label string to 8-bit integer, reversing bit order.
        ARINC 429 transmits label bits 1-8 (LSB first in the standard),
        so label 203 octal = 0b10000011 → transmitted as 0b11000001.
        """
        decimal = int(octal_str, 8)
        # Reverse the 8 bits (ARINC labels are LSB-first on the bus)
        reversed_bits = int(f"{decimal:08b}"[::-1], 2)
        return reversed_bits

    @staticmethod
    def _compute_odd_parity(word: int) -> int:
        """Return the bit value needed to make the 32-bit word odd parity."""
        # Count set bits in bits 1-31 (bit 32 is the parity bit)
        count = bin(word & 0x7FFFFFFF).count("1")
        return 0 if (count % 2 == 1) else 1

    def encode_bnr(
        self,
        label_octal: str,
        value: float,
        ssm: SSM = SSM.PLUS_NORTH_EAST_RIGHT_TO,
        sdi: int = 0,
        _override_range_check: bool = False,
    ) -> int:
        """
        Encode a BNR (binary) value into a 32-bit ARINC 429 word.

        Args:
            label_octal: Octal label code (e.g. "203")
            value: Engineering value to encode
            ssm: Sign/Status Matrix (default: valid positive)
            sdi: Source/Destination Identifier (0-3)
            _override_range_check: If True, encodes out-of-range values
                                   (used by fault injection tests)
        Returns:
            32-bit integer representing the ARINC 429 word
        """
        ld = get_label(label_octal)

        if not _override_range_check:
            if not (ld.range_min <= value <= ld.range_max):
                raise ValueError(
                    f"Label {label_octal} ({ld.name}): value {value} {ld.unit} "
                    f"is outside certified range [{ld.range_min}, {ld.range_max}]."
                )

        # BNR: 19-bit two's complement signed integer
        # Resolution defines the LSB weight
        raw_int = int(value / ld.resolution)
        # Clamp to 19-bit signed range [-2^18, 2^18-1]
        raw_int = max(-262144, min(262143, raw_int))
        # Encode as 19-bit two's complement
        if raw_int < 0:
            raw_int = (1 << 19) + raw_int
        data_bits = raw_int & 0x7FFFF  # 19 bits

        # Assemble word (bits numbered 1=LSB, 32=MSB in ARINC convention)
        label_bits = self._octal_to_bits(label_octal)     # bits 1-8
        sdi_bits = (sdi & 0b11) << 8                       # bits 9-10
        data_shifted = data_bits << 10                      # bits 11-29
        ssm_bits = (ssm.value & 0b11) << 29                # bits 30-31

        word = label_bits | sdi_bits | data_shifted | ssm_bits

        # Compute and set parity (bit 32)
        parity = self._compute_odd_parity(word)
        word |= (parity << 31)

        return word

    def encode_discrete(
        self,
        label_octal: str,
        bit_flags: int,
        ssm: SSM = SSM.PLUS_NORTH_EAST_RIGHT_TO,
        sdi: int = 0,
    ) -> int:
        """Encode a discrete (bit flag) word."""
        ld = get_label(label_octal)
        label_bits = self._octal_to_bits(label_octal)
        sdi_bits = (sdi & 0b11) << 8
        data_shifted = (bit_flags & 0x7FFFF) << 10
        ssm_bits = (ssm.value & 0b11) << 29
        word = label_bits | sdi_bits | data_shifted | ssm_bits
        parity = self._compute_odd_parity(word)
        word |= (parity << 31)
        return word


# ─────────────────────────────────────────────────────────────────────────────
# Decoder
# ─────────────────────────────────────────────────────────────────────────────

class Arinc429Decoder:
    """Decodes 32-bit ARINC 429 words into engineering values."""

    @staticmethod
    def _reverse_label_bits(byte: int) -> int:
        """Reverse 8 bits to recover octal label from transmitted form."""
        return int(f"{byte:08b}"[::-1], 2)

    @staticmethod
    def _check_odd_parity(word: int) -> bool:
        """Verify odd parity across all 32 bits."""
        return bin(word).count("1") % 2 == 1

    def decode(self, raw_word: int) -> Arinc429Word:
        """
        Decode a 32-bit ARINC 429 word.

        Raises:
            KeyError: If the label is not in the registry.
        """
        # Extract fields
        label_transmitted = raw_word & 0xFF
        label_decimal = self._reverse_label_bits(label_transmitted)
        label_octal = f"{label_decimal:03o}"

        sdi = (raw_word >> 8) & 0b11
        data_raw = (raw_word >> 10) & 0x7FFFF   # 19 bits
        ssm_raw = (raw_word >> 29) & 0b11
        parity_ok = self._check_odd_parity(raw_word)

        ssm = SSM(ssm_raw)
        ld = get_label(label_octal)

        # Decode value depending on format
        if ld.fmt == DataFormat.BNR:
            # Two's complement 19-bit signed
            if data_raw & (1 << 18):  # sign bit set
                signed = data_raw - (1 << 19)
            else:
                signed = data_raw
            value = signed * ld.resolution
        elif ld.fmt == DataFormat.DIS:
            value = float(data_raw)
        else:
            # BCD: interpret digits packed in data_raw
            value = float(data_raw)  # simplified for simulation

        return Arinc429Word(
            label_octal=label_octal,
            label_def=ld,
            value=value,
            ssm=ssm,
            sdi=sdi,
            raw_word=raw_word,
            parity_ok=parity_ok,
        )


# ─────────────────────────────────────────────────────────────────────────────
# Module-level convenience instances
# ─────────────────────────────────────────────────────────────────────────────

encoder = Arinc429Encoder()
decoder = Arinc429Decoder()


def encode(label_octal: str, value: float, **kwargs) -> int:
    """Convenience wrapper: encode a BNR value to a 32-bit word."""
    ld = get_label(label_octal)
    if ld.fmt == DataFormat.DIS:
        return encoder.encode_discrete(label_octal, int(value), **kwargs)
    return encoder.encode_bnr(label_octal, value, **kwargs)


def decode(raw_word: int) -> Arinc429Word:
    """Convenience wrapper: decode a 32-bit word."""
    return decoder.decode(raw_word)
