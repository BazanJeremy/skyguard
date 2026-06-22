"""
SkyGuard — Property-Based Fuzzing Tests (ACARS)
=================================================
Uses Hypothesis to generate thousands of arbitrary inputs and verify that
the ACARS parser never crashes, always returns a typed result, and correctly
enforces its length constraints.

This is the component that demonstrates serious QA craft:
"I don't just test what I know — I let the machine find what I don't know."

Run: pytest tests/fuzzing/ -v --hypothesis-show-statistics
     (Hypothesis runs 100 examples per test by default; --hypothesis-seed=0 for reproducibility)
"""

import string
from hypothesis import given, settings, HealthCheck
from hypothesis import strategies as st

from src.simulators.acars_parser import (
    ACARSMessageBuilder,
    ACARSParser,
    ParseStatus,
    MAX_TEXT_LENGTH,
    SOH, STX, ETX_LAST,
)


parser = ACARSParser()


# ─────────────────────────────────────────────────────────────────
# Strategy helpers
# ─────────────────────────────────────────────────────────────────

# A valid-looking ACARS frame built from hypothesis-generated fields
@st.composite
def acars_frame(draw) -> bytes:
    """Generate a structurally plausible ACARS frame with random field values."""
    mode     = draw(st.sampled_from(b"2."))
    addr     = draw(st.binary(min_size=7, max_size=7))
    ack      = draw(st.integers(min_value=0x20, max_value=0x7E))
    label    = draw(st.binary(min_size=2, max_size=2))
    block_id = draw(st.integers(min_value=0x41, max_value=0x5A))
    text     = draw(st.binary(min_size=0, max_size=300))

    return (
        bytes([SOH, mode])
        + addr
        + bytes([ack])
        + label
        + bytes([block_id, STX])
        + text
        + bytes([ETX_LAST])
    )


@st.composite
def arbitrary_bytes(draw) -> bytes:
    """Completely arbitrary byte sequences — no structure assumed."""
    return draw(st.binary(min_size=0, max_size=512))


# ─────────────────────────────────────────────────────────────────
# Properties
# ─────────────────────────────────────────────────────────────────

class TestACARSParserNeverCrashes:
    @given(data=arbitrary_bytes())
    @settings(max_examples=500, suppress_health_check=[HealthCheck.too_slow])
    def test_parser_never_raises_on_arbitrary_bytes(self, data: bytes):
        """
        Property: the parser must NEVER raise an unhandled exception,
        regardless of input content.
        """
        try:
            result = parser.parse(data)
            assert result is not None
        except Exception as exc:
            raise AssertionError(
                f"Parser raised {type(exc).__name__} on input {data!r}: {exc}"
            ) from exc

    @given(frame=acars_frame())
    @settings(max_examples=300, suppress_health_check=[HealthCheck.too_slow])
    def test_parser_never_raises_on_structured_frames(self, frame: bytes):
        """
        Property: structured but randomised ACARS frames must never crash the parser.
        """
        try:
            result = parser.parse(frame)
            assert result is not None
        except Exception as exc:
            raise AssertionError(
                f"Parser raised {type(exc).__name__} on structured frame: {exc}"
            ) from exc


class TestACARSParserReturnType:
    @given(data=arbitrary_bytes())
    @settings(max_examples=200)
    def test_result_has_status(self, data: bytes):
        """Property: every parse result has a valid ParseStatus."""
        result = parser.parse(data)
        assert isinstance(result.status, ParseStatus)

    @given(data=arbitrary_bytes())
    @settings(max_examples=200)
    def test_result_text_is_always_string(self, data: bytes):
        """Property: text field is always a str, never bytes or None."""
        result = parser.parse(data)
        assert isinstance(result.text, str)

    @given(data=arbitrary_bytes())
    @settings(max_examples=200)
    def test_result_anomalies_is_always_list(self, data: bytes):
        """Property: anomalies is always a list (may be empty)."""
        result = parser.parse(data)
        assert isinstance(result.anomalies, list)


class TestACARSParserLengthEnforcement:
    @given(text_length=st.integers(min_value=MAX_TEXT_LENGTH + 1, max_value=2000))
    @settings(max_examples=50)
    def test_oversized_text_always_flagged(self, text_length: int):
        """
        Property: any text body longer than MAX_TEXT_LENGTH must produce
        a status of TEXT_TOO_LONG.

        FINDING: if this test fails, the parser is silently accepting
        oversized payloads — a potential buffer overflow vector.
        """
        builder = ACARSMessageBuilder()
        frame   = (
            bytes([SOH, ord("2")])
            + b"F-GKXA "
            + b"!"
            + b"H1"
            + b"A"
            + bytes([STX])
            + b"X" * text_length
            + bytes([ETX_LAST])
        )
        result = parser.parse(frame)
        assert result.status == ParseStatus.TEXT_TOO_LONG, (
            f"Parser accepted {text_length}-char text without raising TEXT_TOO_LONG"
        )

    @given(text=st.text(alphabet=string.printable, max_size=MAX_TEXT_LENGTH))
    @settings(max_examples=100)
    def test_valid_length_text_is_accepted(self, text: str):
        """
        Property: any text body within the limit and using printable ASCII
        must be accepted with status OK (assuming a well-formed frame).
        """
        builder = ACARSMessageBuilder()
        try:
            frame = builder.build("H1", text[:MAX_TEXT_LENGTH])
        except ValueError:
            return   # builder's own validation caught it — acceptable
        result = parser.parse(frame)
        assert result.status == ParseStatus.OK, (
            f"Valid-length text rejected unexpectedly: {result.status} — {result.anomalies}"
        )


class TestACARSParserIdemPotence:
    @given(frame=acars_frame())
    @settings(max_examples=100)
    def test_parsing_same_frame_twice_gives_same_result(self, frame: bytes):
        """
        Property: the parser is stateless — parsing the same frame twice
        must produce identical results.
        """
        result1 = parser.parse(frame)
        result2 = parser.parse(frame)
        assert result1.status   == result2.status
        assert result1.label    == result2.label
        assert result1.text     == result2.text
        assert result1.anomalies == result2.anomalies


class TestACARSParserBatchConsistency:
    @given(frames=st.lists(arbitrary_bytes(), min_size=1, max_size=20))
    @settings(max_examples=50)
    def test_batch_count_matches_input(self, frames: list[bytes]):
        """
        Property: parse_batch must return exactly as many results as inputs.
        """
        results = parser.parse_batch(frames)
        assert len(results) == len(frames)

    @given(frames=st.lists(acars_frame(), min_size=1, max_size=10))
    @settings(max_examples=50)
    def test_batch_matches_individual_parses(self, frames: list[bytes]):
        """
        Property: batch parsing must produce the same results as individual parsing.
        """
        batch_results = parser.parse_batch(frames)
        for frame, batch_msg in zip(frames, batch_results):
            individual_msg = parser.parse(frame)
            assert batch_msg.status == individual_msg.status
            assert batch_msg.text   == individual_msg.text
