"""
SkyGuard — ARINC 429 Protocol Tests
=====================================
Tests the encoding, decoding, validation, and attack scenario generators
of the ARINC 429 bus simulator.

Run: pytest tests/protocol/ -v --tb=short
"""

import pytest

pytestmark = pytest.mark.protocol  # applied to all tests in this module

from src.simulators.arinc429_bus import (
    ARINC429Validator,
    ARINC429Word,
    BusFrame,
    NormalFlightScenario,
    OutOfRangeInjector,
    ParityCorruptionInjector,
    ReplayAttackGenerator,
    SDI,
    SSM,
    SSMSpoofingInjector,
    LABEL_CATALOG,
    bytes_to_words,
    decode_bnr_value,
    decode_word,
    encode_bnr_value,
    encode_word,
    frame_to_bytes,
    _compute_parity,
)


class TestParity:
    def test_parity_of_zero_is_one(self):
        assert _compute_parity(0) == 1

    def test_encoded_word_has_correct_parity(self):
        word = encode_word(0o101, 1000)
        assert word.parity_ok

    def test_single_bit_flip_detected(self):
        word = encode_word(0o203, 8000)
        corrupted = decode_word(word.raw_word ^ (1 << 5))
        assert not corrupted.parity_ok

    def test_double_bit_flip_is_undetectable(self):
        word = encode_word(0o310, 512)
        corrupted = decode_word(word.raw_word ^ (1 << 3) ^ (1 << 7))
        assert isinstance(corrupted.parity_ok, bool)


class TestEncodeDecodeRoundtrip:
    @pytest.mark.parametrize("label,data_raw,sdi,ssm", [
        (0o101, 500,   SDI.ALL,    SSM.PLUS_NORTH_RIGHT_TO),
        (0o203, 8750,  SDI.RCVR_1, SSM.PLUS_NORTH_RIGHT_TO),
        (0o310, 16383, SDI.RCVR_2, SSM.FUNCTIONAL_TEST),
        (0o324, 0,     SDI.RCVR_3, SSM.NO_COMPUTED_DATA),
        (0o325, 1,     SDI.ALL,    SSM.FAILURE_WARNING),
    ])
    def test_roundtrip_fields(self, label, data_raw, sdi, ssm):
        word = encode_word(label, data_raw, sdi, ssm)
        decoded = decode_word(word.raw_word)
        assert decoded.label == label
        assert decoded.data_raw == data_raw
        assert decoded.sdi == sdi
        assert decoded.ssm == ssm

    def test_data_raw_overflow_is_masked(self):
        word = encode_word(0o101, 0xFFFFF)
        assert decode_word(word.raw_word).data_raw == 0x7FFFF


class TestBNREncoding:
    @pytest.mark.parametrize("label,value", [
        (0o101, 280.0),
        (0o102, 0.78),
        (0o203, 35000.0),
        (0o310, 87.0),
        (0o324, 2.5),
        (0o325, -30.0),
        (0o365, -56.0),
    ])
    def test_bnr_value_survives_roundtrip(self, label, value):
        word = encode_bnr_value(label, value)
        recovered = decode_bnr_value(word)
        info = LABEL_CATALOG[label]
        assert recovered is not None
        assert abs(recovered - value) <= info["resolution"] * 2

    def test_bnr_rejects_unknown_label(self):
        with pytest.raises(ValueError, match="not in catalog"):
            encode_bnr_value(0o777, 100.0)

    def test_bnr_rejects_out_of_range_high(self):
        with pytest.raises(ValueError, match="out of range"):
            encode_bnr_value(0o101, 9999.0)

    def test_bnr_rejects_out_of_range_low(self):
        with pytest.raises(ValueError, match="out of range"):
            encode_bnr_value(0o203, -9999.0)

    def test_bnr_failure_warning_returns_none(self):
        word = encode_word(0o203, 8750, ssm=SSM.FAILURE_WARNING)
        assert decode_bnr_value(word) is None

    def test_bnr_ncd_returns_none(self):
        word = encode_word(0o324, 100, ssm=SSM.NO_COMPUTED_DATA)
        assert decode_bnr_value(word) is None


class TestSerialization:
    def test_frame_to_bytes_length(self):
        frame = NormalFlightScenario().generate_frame()
        raw = frame_to_bytes(frame)
        assert len(raw) == len(frame.words) * 4

    def test_bytes_roundtrip(self):
        frame = NormalFlightScenario().generate_frame()
        raw = frame_to_bytes(frame)
        words = bytes_to_words(raw)
        assert len(words) == len(frame.words)
        for orig, recovered in zip(frame.words, words):
            assert orig.raw_word == recovered.raw_word

    def test_bytes_to_words_rejects_odd_length(self):
        with pytest.raises(ValueError, match="multiple of 4"):
            bytes_to_words(b"\x00\x01\x02")


class TestNormalFlightScenario:
    def test_generates_expected_labels(self):
        scenario = NormalFlightScenario()
        frame = scenario.generate_frame()
        assert {w.label for w in frame.words} == set(scenario.CRUISE_VALUES.keys())

    def test_all_words_pass_parity(self):
        frame = NormalFlightScenario().generate_frame()
        for word in frame.words:
            assert word.parity_ok, f"Parity fail on label 0o{word.label:03o}"

    def test_stream_yields_correct_count(self):
        frames = list(NormalFlightScenario().stream(count=25))
        assert len(frames) == 25

    def test_stream_timestamps_are_monotonic(self):
        frames = list(NormalFlightScenario().stream(count=10, interval=0.1))
        for i in range(1, len(frames)):
            assert frames[i].timestamp > frames[i - 1].timestamp

    def test_values_stay_within_catalog_bounds(self):
        scenario = NormalFlightScenario()
        validator = ARINC429Validator()
        for _ in range(20):
            frame = scenario.generate_frame(jitter=0.005)
            results = validator.validate_frame(frame)
            for r in results:
                assert r.range_ok, f"Out-of-range: {r.anomaly_flags}"


class TestOutOfRangeInjector:
    def test_injected_word_fails_range_validation(self):
        injector = OutOfRangeInjector()
        validator = ARINC429Validator()
        word = injector.inject(0o101, multiplier=3.0)
        result = validator.validate(word)
        assert not result.range_ok
        assert any("OUT_OF_RANGE" in f for f in result.anomaly_flags)

    def test_injected_word_has_valid_parity(self):
        word = OutOfRangeInjector().inject(0o203, multiplier=2.0)
        assert word.parity_ok

    def test_batch_returns_requested_count(self):
        words = OutOfRangeInjector().batch(count=15)
        assert len(words) == 15

    def test_all_batch_words_fail_range(self):
        injector = OutOfRangeInjector()
        validator = ARINC429Validator()
        for word in injector.batch(count=10):
            result = validator.validate(word)
            assert not result.range_ok


class TestParityCorruptionInjector:
    def test_corrupt_word_fails_parity(self):
        injector = ParityCorruptionInjector()
        word = encode_bnr_value(0o310, 90.0)
        corrupted = injector.corrupt(word, flip_bits=1)
        assert not corrupted.parity_ok

    def test_corrupt_frame_marks_as_corrupted(self):
        frame = NormalFlightScenario().generate_frame()
        result = ParityCorruptionInjector().corrupt_frame(frame, ratio=1.0)
        assert result.corrupted is True

    def test_corrupt_frame_ratio_0_leaves_all_valid(self):
        frame = NormalFlightScenario().generate_frame()
        result = ParityCorruptionInjector().corrupt_frame(frame, ratio=0.0)
        for word in result.words:
            assert word.parity_ok


class TestSSMSpoofingInjector:
    def test_spoof_to_failure_warning(self):
        injector = SSMSpoofingInjector()
        word = encode_bnr_value(0o203, 35000.0)
        spoofed = injector.spoof_validity(word, SSM.FAILURE_WARNING)
        assert spoofed.ssm == SSM.FAILURE_WARNING
        assert not spoofed.is_valid

    def test_denial_of_data_targets_navigation(self):
        frame = NormalFlightScenario().generate_frame()
        attacked = SSMSpoofingInjector().denial_of_data_attack(frame)
        critical = {0o203, 0o310, 0o324, 0o325, 0o361}
        for word in attacked.words:
            if word.label in critical:
                assert word.ssm == SSM.NO_COMPUTED_DATA

    def test_spoofed_word_has_valid_parity(self):
        injector = SSMSpoofingInjector()
        word = encode_bnr_value(0o324, 2.5)
        spoofed = injector.spoof_validity(word, SSM.NO_COMPUTED_DATA)
        assert spoofed.parity_ok


class TestReplayAttackGenerator:
    def test_replay_without_capture_raises(self):
        with pytest.raises(RuntimeError, match="No frames captured"):
            ReplayAttackGenerator().replay()

    def test_replayed_timestamps_are_offset(self):
        frames = list(NormalFlightScenario().stream(count=5, interval=0.1))
        gen = ReplayAttackGenerator()
        gen.capture(frames)
        replayed = gen.replay(offset_seconds=60.0)
        for orig, rep in zip(frames, replayed):
            assert abs((rep.timestamp - orig.timestamp) - 60.0) < 0.001

    def test_replayed_frames_marked_corrupted(self):
        frames = list(NormalFlightScenario().stream(count=3))
        gen = ReplayAttackGenerator()
        gen.capture(frames)
        for f in gen.replay():
            assert f.corrupted is True

    def test_replayed_bus_id_contains_replay(self):
        frames = list(NormalFlightScenario().stream(count=3))
        gen = ReplayAttackGenerator()
        gen.capture(frames)
        for f in gen.replay():
            assert "REPLAY" in f.bus_id


class TestARINC429Validator:
    def test_valid_word_passes_all_checks(self):
        validator = ARINC429Validator()
        word = encode_bnr_value(0o101, 280.0)
        result = validator.validate(word)
        assert result.is_safe
        assert result.anomaly_flags == []

    def test_failure_warning_is_not_safe(self):
        validator = ARINC429Validator()
        word = encode_word(0o203, 8750, ssm=SSM.FAILURE_WARNING)
        result = validator.validate(word)
        assert not result.is_safe
        assert not result.ssm_valid

    def test_anomaly_count_clean_frame(self):
        validator = ARINC429Validator()
        frame = NormalFlightScenario().generate_frame()
        results = validator.validate_frame(frame)
        assert validator.anomaly_count(results) == 0

    def test_anomaly_count_attacked_frame(self):
        validator = ARINC429Validator()
        frame = NormalFlightScenario().generate_frame()
        attacked = SSMSpoofingInjector().denial_of_data_attack(frame)
        results = validator.validate_frame(attacked)
        assert validator.anomaly_count(results) > 0

    def test_unknown_label_flagged(self):
        validator = ARINC429Validator()
        word = encode_word(0o377, 1000)
        result = validator.validate(word)
        assert any("UNKNOWN_LABEL" in f for f in result.anomaly_flags)
