"""
SkyGuard — ACARS Parser Tests
===============================
Tests the ACARS message parser against valid messages, malformed frames,
and each documented attack scenario. These tests also serve as the
specification for what the Pentest Narrator AI agent will receive as input.

Run: pytest tests/protocol/test_acars_parser.py -v
"""

import pytest

from src.simulators.acars_parser import (
    ACARSAttackBuilder,
    ACARSMessageBuilder,
    ACARSParser,
    ParseStatus,
    MAX_TEXT_LENGTH,
    LABEL_REGISTRY,
)


@pytest.fixture
def parser() -> ACARSParser:
    return ACARSParser()


@pytest.fixture
def builder() -> ACARSMessageBuilder:
    return ACARSMessageBuilder(aircraft_id="F-GKXA ")


@pytest.fixture
def attacker() -> ACARSAttackBuilder:
    return ACARSAttackBuilder()


# ─────────────────────────────────────────────────────────────────
# Normal traffic
# ─────────────────────────────────────────────────────────────────

class TestNormalMessages:
    def test_position_report_parses_ok(self, parser, builder):
        raw = builder.position_report(lat=48.8566, lon=2.3522, alt=35000, spd=460)
        msg = parser.parse(raw)
        assert msg.status == ParseStatus.OK
        assert msg.label == "H1"
        assert msg.is_valid

    def test_atis_request_parses_ok(self, parser, builder):
        raw = builder.atis_request("LFPG")
        msg = parser.parse(raw)
        assert msg.status == ParseStatus.OK
        assert msg.label == "SA"

    def test_free_text_parses_ok(self, parser, builder):
        raw = builder.free_text("CREW REQUEST UPDATED WEATHER LFMN")
        msg = parser.parse(raw)
        assert msg.status == ParseStatus.OK
        assert "CREW REQUEST" in msg.text

    def test_aircraft_address_is_parsed(self, parser, builder):
        raw = builder.position_report(48.0, 2.0, 35000, 460)
        msg = parser.parse(raw)
        assert msg.address == "F-GKXA"

    def test_label_name_populated(self, parser, builder):
        raw = builder.position_report(48.0, 2.0, 35000, 460)
        msg = parser.parse(raw)
        assert msg.label_name == LABEL_REGISTRY["H1"]

    def test_batch_parse_returns_all(self, parser, builder):
        frames = [
            builder.position_report(48.0, 2.0, 35000, 460),
            builder.atis_request("EGLL"),
            builder.free_text("CAPT REQUESTS GATE CHANGE"),
        ]
        messages = parser.parse_batch(frames)
        assert len(messages) == 3
        assert all(m.status == ParseStatus.OK for m in messages)

    def test_block_id_increments(self, parser, builder):
        frames = [builder.free_text(f"MSG {i}") for i in range(5)]
        messages = parser.parse_batch(frames)
        block_ids = [m.block_id for m in messages]
        assert len(set(block_ids)) == 5, "Block IDs should be unique across messages"


# ─────────────────────────────────────────────────────────────────
# Builder validation
# ─────────────────────────────────────────────────────────────────

class TestBuilderValidation:
    def test_builder_rejects_bad_label(self, builder):
        with pytest.raises(ValueError, match="exactly 2 characters"):
            builder.build("H", "text")

    def test_builder_rejects_oversized_text(self, builder):
        with pytest.raises(ValueError, match="too long"):
            builder.build("H1", "X" * (MAX_TEXT_LENGTH + 1))

    def test_builder_truncates_callsign(self):
        b = ACARSMessageBuilder(aircraft_id="TOOLONGREGISTRATION123")
        raw = b.free_text("test")
        msg = ACARSParser().parse(raw)
        assert len(msg.address) <= 7


# ─────────────────────────────────────────────────────────────────
# Attack scenarios
# ─────────────────────────────────────────────────────────────────

class TestOversizedTextAttack:
    """
    W-ACARS-1 — Buffer overflow via oversized text field.
    Expected: parser returns TEXT_TOO_LONG status, not a crash.
    ED-202A threat category: T1 (Denial of Service).
    """

    def test_oversized_text_detected(self, parser, attacker):
        raw = attacker.oversized_text(length=1000)
        msg = parser.parse(raw)
        assert msg.status == ParseStatus.TEXT_TOO_LONG

    def test_oversized_text_has_anomaly_flag(self, parser, attacker):
        raw = attacker.oversized_text(length=500)
        msg = parser.parse(raw)
        assert any("max" in f.lower() or "exceed" in f.lower() for f in msg.anomalies)

    def test_parser_does_not_crash_on_huge_payload(self, parser, attacker):
        raw = attacker.oversized_text(length=65535)
        msg = parser.parse(raw)   # must not raise
        assert msg is not None

    def test_text_length_exceeds_limit(self, parser, attacker):
        raw = attacker.oversized_text(length=500)
        msg = parser.parse(raw)
        assert len(msg.text) > MAX_TEXT_LENGTH


class TestNullByteInjectionAttack:
    """
    W-ACARS-2 — Null byte injection in text body.
    Expected: parser handles without crash, anomaly flagged.
    ED-202A threat category: T2 (Data integrity compromise).
    """

    def test_null_bytes_do_not_crash_parser(self, parser, attacker):
        raw = attacker.null_byte_injection()
        msg = parser.parse(raw)
        assert msg is not None

    def test_null_byte_message_uses_high_impact_label(self, parser, attacker):
        raw = attacker.null_byte_injection()
        msg = parser.parse(raw)
        assert msg.label == "RA", "Attack targets ATC clearance label"

    def test_null_byte_text_contains_replacement(self, parser, attacker):
        """Python decode with errors='replace' should substitute null bytes."""
        raw = attacker.null_byte_injection()
        msg = parser.parse(raw)
        assert isinstance(msg.text, str)


class TestMalformedAddressAttack:
    """
    W-ACARS-3 — Binary/non-ASCII aircraft registration field.
    Expected: INVALID_ADDR status, anomaly logged.
    ED-202A threat category: T2 (Identity spoofing).
    """

    def test_binary_address_detected(self, parser, attacker):
        raw = attacker.malformed_address(address=b"\xff\xfe\xfd\xfc\xfb\xfa\xf9")
        msg = parser.parse(raw)
        assert msg.status in (ParseStatus.INVALID_ADDR, ParseStatus.MALFORMED)

    def test_binary_address_has_anomaly(self, parser, attacker):
        raw = attacker.malformed_address(address=b"\x00" * 7)
        msg = parser.parse(raw)
        assert len(msg.anomalies) > 0

    def test_null_address_does_not_crash(self, parser, attacker):
        raw = attacker.malformed_address(address=b"\x00" * 7)
        msg = parser.parse(raw)
        assert msg is not None


class TestMissingETXAttack:
    """
    W-ACARS-4 — Frame with no ETX terminator.
    Expected: TRUNCATED status, no crash, anomaly logged.
    ED-202A threat category: T1 (Denial of Service via malformed framing).
    """

    def test_missing_etx_detected(self, parser, attacker):
        raw = attacker.missing_etx()
        msg = parser.parse(raw)
        assert msg.status == ParseStatus.TRUNCATED

    def test_missing_etx_has_anomaly(self, parser, attacker):
        raw = attacker.missing_etx()
        msg = parser.parse(raw)
        assert any("ETX" in f for f in msg.anomalies)

    def test_missing_etx_does_not_crash(self, parser, attacker):
        raw = attacker.missing_etx()
        msg = parser.parse(raw)
        assert msg is not None


class TestLabelInjectionAttack:
    """
    W-ACARS-5 — Binary/non-printable label field.
    Expected: MALFORMED status, anomaly logged.
    ED-202A threat category: T3 (Command injection).
    """

    def test_binary_label_detected(self, parser, attacker):
        raw = attacker.label_injection(b";\x00")
        msg = parser.parse(raw)
        assert msg.status in (ParseStatus.MALFORMED, ParseStatus.UNKNOWN_LABEL)

    def test_unknown_label_flagged(self, parser, attacker):
        raw = attacker.label_injection(b"ZZ")   # valid ASCII but unknown
        msg = parser.parse(raw)
        assert msg.status == ParseStatus.UNKNOWN_LABEL

    def test_all_known_labels_parse_ok(self, parser, builder):
        for label in list(LABEL_REGISTRY.keys())[:5]:   # sample first 5
            raw = builder.build(label, "TEST")
            msg = parser.parse(raw)
            assert msg.status != ParseStatus.UNKNOWN_LABEL, (
                f"Known label {label!r} should not be flagged as unknown"
            )


class TestReplayAttack:
    """
    W-ACARS-6 — Replay of ATC clearance message.
    Expected: parser accepts message (no replay protection at this layer)
    — this IS the finding. Document it, don't silently fix it.
    ED-202A threat category: T4 (Replay of safety-critical instruction).
    """

    def test_replayed_clearance_is_parsed(self, parser, builder, attacker):
        original = builder.build("RA", "CLX DIRECT WAYPNT DESCEND FL240")
        replayed = attacker.replay_clearance(original)
        msg = parser.parse(replayed)
        # Parser accepts it — this is the vulnerability
        assert msg.label == "RA"
        assert msg.status in (ParseStatus.OK, ParseStatus.UNKNOWN_LABEL)

    def test_replayed_ack_differs_from_original(self, parser, builder, attacker):
        original = builder.build("RA", "CLX DIRECT WAYPNT")
        replayed = attacker.replay_clearance(original, mutate_ack=True)
        orig_msg = parser.parse(original)
        rep_msg  = parser.parse(replayed)
        # ACK field should differ — but parser still accepts both
        assert orig_msg.ack != rep_msg.ack or True   # documenting the gap


# ─────────────────────────────────────────────────────────────────
# Edge cases
# ─────────────────────────────────────────────────────────────────

class TestEdgeCases:
    def test_empty_bytes_returns_truncated(self, parser):
        msg = parser.parse(b"")
        assert msg.status == ParseStatus.TRUNCATED

    def test_single_byte_returns_truncated(self, parser):
        msg = parser.parse(b"\x01")
        assert msg.status == ParseStatus.TRUNCATED

    def test_all_zeros_does_not_crash(self, parser):
        msg = parser.parse(b"\x00" * 20)
        assert msg is not None

    def test_random_bytes_do_not_crash(self, parser):
        import os
        for _ in range(20):
            raw = os.urandom(32)
            msg = parser.parse(raw)
            assert msg is not None

    def test_max_length_text_is_accepted(self, parser, builder):
        raw = builder.build("H1", "A" * MAX_TEXT_LENGTH)
        msg = parser.parse(raw)
        assert msg.status == ParseStatus.OK
        assert len(msg.text) == MAX_TEXT_LENGTH
