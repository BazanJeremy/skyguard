"""
ACARS Parser Fuzzing Tests — Property-Based with Hypothesis
============================================================
Uses Hypothesis to generate thousands of adversarial ACARS messages
and verify parser invariants (it should never crash).

This is the SkyGuard equivalent of a protocol fuzzing campaign.
In a regulated context (DO-326A §6.3), this satisfies the requirement:
"Test the security functions with boundary and invalid inputs."

Note: property-based testing is rarely seen in day-to-day QA suites.
It exercises advanced test design beyond happy-path checks.
"""

import string

import pytest
from hypothesis import given, settings, HealthCheck
from hypothesis import strategies as st

from src.simulators.acars.parser import (
    AcarsParser,
    AcarsMessageFactory,
    AcarsMessageType,
    _MIN_HEADER_LEN,
    _MAX_BODY_LEN,
)

pytestmark = pytest.mark.fuzzing  # applied to all tests in this module


# ─────────────────────────────────────────────────────────────────────────────
# Strategies — composable generators for ACARS message components
# ─────────────────────────────────────────────────────────────────────────────

# Valid ACARS aircraft ID characters
acid_chars = st.text(
    alphabet=string.ascii_uppercase + string.digits + "-",
    min_size=2,
    max_size=7,
)

# Message labels (2 chars)
label_strategy = st.text(
    alphabet=string.ascii_uppercase + string.digits,
    min_size=2,
    max_size=2,
)

# Body: anything printable + some nasty chars
body_strategy = st.text(
    alphabet=st.characters(
        whitelist_categories=("Lu", "Ll", "Nd", "Zs", "Po", "Pd"),
        whitelist_characters="\n\r\t\x00",
    ),
    min_size=0,
    max_size=500,  # intentionally over the 220-char limit
)


# A complete "valid-looking" ACARS header prefix
@st.composite
def acars_header(draw) -> str:
    mode = draw(st.sampled_from(["2", ".", " ", "?"]))
    acid = draw(acid_chars).ljust(7)[:7]
    ack = draw(st.sampled_from(["!", " ", "?"]))
    label = draw(label_strategy)
    block = draw(
        st.text(alphabet=string.digits + string.ascii_uppercase, min_size=1, max_size=1)
    )
    msgnum = draw(
        st.text(alphabet=string.ascii_uppercase + string.digits, min_size=4, max_size=4)
    )
    flight = draw(
        st.text(
            alphabet=string.ascii_uppercase + string.digits + " ",
            min_size=6,
            max_size=6,
        )
    )
    return f"{mode}{acid}{ack}{label}{block}{msgnum}{flight}"


@st.composite
def arbitrary_acars_message(draw) -> str:
    header = draw(acars_header())
    body = draw(body_strategy)
    return header + body


# ─────────────────────────────────────────────────────────────────────────────
# Property tests
# ─────────────────────────────────────────────────────────────────────────────

parser = AcarsParser()


class TestAcarsParserProperties:
    """
    Core invariant: the ACARS parser MUST NEVER raise an unhandled exception,
    regardless of the input. All errors must be captured in parse_errors.

    This mirrors the avionics requirement for fault tolerance in parsers
    that process externally-sourced (untrusted) data over the ACARS link.
    """

    @given(raw=arbitrary_acars_message())
    @settings(max_examples=1000, suppress_health_check=[HealthCheck.too_slow])
    def test_parser_never_crashes(self, raw: str):
        """
        CRITICAL PROPERTY: parser.parse() must never raise.
        A crash in an ACARS parser on an avionics unit is a safety event.
        """
        try:
            parser.parse(raw)
        except Exception as exc:
            pytest.fail(f"Parser raised {type(exc).__name__}: {exc}\nInput: {raw!r}")

    @given(raw=arbitrary_acars_message())
    @settings(max_examples=500, suppress_health_check=[HealthCheck.too_slow])
    def test_parser_always_returns_acars_message(self, raw: str):
        """Parser must always return an AcarsMessage, never None."""
        from src.simulators.acars.parser import AcarsMessage

        result = parser.parse(raw)
        assert result is not None
        assert isinstance(result, AcarsMessage)

    @given(raw=arbitrary_acars_message())
    @settings(max_examples=500, suppress_health_check=[HealthCheck.too_slow])
    def test_body_never_exceeds_max_length(self, raw: str):
        """
        Even if the input body is over 220 chars, the parsed body
        must be capped. No buffer overflow surface area.
        """
        result = parser.parse(raw)
        assert len(result.body) <= _MAX_BODY_LEN, (
            f"Body length {len(result.body)} exceeds ARINC 618 limit {_MAX_BODY_LEN}. "
            f"Potential buffer overflow attack vector."
        )

    @given(raw=st.text(min_size=0, max_size=21))
    @settings(max_examples=200)
    def test_short_message_always_invalid(self, raw: str):
        """Any message shorter than the header is always invalid."""
        result = parser.parse(raw)
        assert not result.is_valid
        assert len(result.parse_errors) > 0

    @given(raw=arbitrary_acars_message())
    @settings(max_examples=500, suppress_health_check=[HealthCheck.too_slow])
    def test_parse_errors_is_always_a_list(self, raw: str):
        """parse_errors must always be a list (never None)."""
        result = parser.parse(raw)
        assert isinstance(result.parse_errors, list)

    @given(raw=arbitrary_acars_message())
    @settings(max_examples=300, suppress_health_check=[HealthCheck.too_slow])
    def test_msg_type_is_always_valid_enum(self, raw: str):
        """msg_type must always be a valid AcarsMessageType member."""
        result = parser.parse(raw)
        assert result.msg_type in AcarsMessageType, (
            f"Invalid msg_type: {result.msg_type!r}"
        )

    @given(
        raw=st.builds(
            lambda body: "2FHBXA1 !H10M01AAF447 " + body,
            body=st.text(
                alphabet=st.sampled_from("\x00\x01\x02\x03"),
                min_size=1,
                max_size=50,
            ),
        )
    )
    @settings(max_examples=200)
    def test_null_bytes_flagged_not_crashed(self, raw: str):
        """
        Null bytes in body should be detected and flagged, not cause a crash.
        Null bytes can terminate C strings in downstream avionics units.
        """
        result = parser.parse(raw)
        if "\x00" in raw[_MIN_HEADER_LEN:]:
            null_errors = [
                e for e in result.parse_errors if "null" in e.lower() or "\\x00" in e
            ]
            assert null_errors, (
                "Null byte in body not flagged in parse_errors. "
                "Security finding: avionics C-string termination risk."
            )

    @given(
        body=st.text(
            alphabet=string.printable,
            min_size=_MAX_BODY_LEN + 1,
            max_size=_MAX_BODY_LEN * 3,
        )
    )
    @settings(max_examples=100)
    def test_oversized_body_flagged(self, body: str):
        """Messages over 220 chars should flag an error AND truncate the body."""
        raw = "2FHBXA1 !H10M01AAF447 " + body
        result = parser.parse(raw)
        # Body must be truncated
        assert len(result.body) <= _MAX_BODY_LEN
        # AND the oversize must be flagged
        overflow_errors = [
            e
            for e in result.parse_errors
            if "exceed" in e.lower() or "overflow" in e.lower() or "limit" in e.lower()
        ]
        assert overflow_errors, (
            "Oversized body not flagged in parse_errors. "
            "Security finding: attacker can send unlimited data."
        )


# ─────────────────────────────────────────────────────────────────────────────
# Known-input tests (deterministic — for CI regression)
# ─────────────────────────────────────────────────────────────────────────────


class TestAcarsParserKnownInputs:
    def setup_method(self):
        self.parser = AcarsParser()

    def test_valid_free_text_message(self):
        raw = AcarsMessageFactory.free_text()
        result = self.parser.parse(raw)
        assert result.msg_type == AcarsMessageType.FREE_TEXT
        assert result.is_valid
        assert result.header.aircraft_id == "FHBXA1"
        assert not result.parse_errors

    def test_valid_pdc_message(self):
        raw = AcarsMessageFactory.pdc()
        result = self.parser.parse(raw)
        assert result.msg_type == AcarsMessageType.PDC
        assert result.is_valid
        assert "CLRD TO" in result.body

    def test_valid_metar_message(self):
        raw = AcarsMessageFactory.metar()
        result = self.parser.parse(raw)
        assert result.msg_type == AcarsMessageType.METAR
        assert result.is_valid

    def test_valid_oooi_message(self):
        raw = AcarsMessageFactory.oooi_off(fuel_kg=18500)
        result = self.parser.parse(raw)
        assert result.msg_type == AcarsMessageType.OOOI
        assert result.is_valid
        assert "18500" in result.body

    def test_valid_fuel_order(self):
        raw = AcarsMessageFactory.fuel_order(uplift_kg=22000)
        result = self.parser.parse(raw)
        assert result.msg_type == AcarsMessageType.FUEL
        assert result.is_valid

    def test_empty_message_is_invalid(self):
        result = self.parser.parse("")
        assert not result.is_valid
        assert result.parse_errors

    def test_spoofed_aircraft_id_flagged(self):
        """Aircraft ID with only spaces should trigger a warning."""
        raw = "2        !H10M01AAF447 SOME MESSAGE TEXT"
        result = self.parser.parse(raw)
        # Spaces stripped → empty → fails regex → error flagged
        suspicious = [
            e
            for e in result.parse_errors
            if "aircraft" in e.lower() or "suspicious" in e.lower()
        ]
        assert suspicious, "Spoofed aircraft ID not detected"

    def test_parser_stats_track_errors(self):
        p = AcarsParser()
        p.parse(AcarsMessageFactory.free_text())  # valid
        p.parse("")  # invalid
        p.parse("short")  # invalid
        assert p.stats["total_parsed"] == 3
        assert p.stats["total_errors"] == 2
        assert p.stats["error_rate"] == pytest.approx(2 / 3)

    def test_to_dict_has_required_keys(self):
        raw = AcarsMessageFactory.free_text()
        result = self.parser.parse(raw)
        d = result.to_dict()
        required = {
            "aircraft_id",
            "flight_id",
            "msg_type",
            "body_length",
            "body_preview",
            "is_valid",
            "parse_errors",
        }
        assert required.issubset(d.keys())
