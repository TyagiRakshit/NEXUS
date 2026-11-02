import math
import os
from pathlib import Path

import pytest

from app.anomaly_detection import (
    FEATURE_NAMES,
    FeatureDataError,
    ModelUnavailable,
    detect_flows,
    explain_detection,
    fit_feature_normalizer,
    flow_to_raw_features,
    map_risk,
    train_detector,
)
from app.pcap_analysis import FlowSummary
from app.pcap_analysis import analyze_pcap
from fixtures.phase4_expectations import (
    EXPECTED_DETECTION_RESULTS,
    EXPECTED_DOCUMENTATION_HOSTS,
    EXPECTED_MIXED_DETECTION_RESULTS,
    EXPECTED_MIXED_FIXTURE_BYTES,
    EXPECTED_MIXED_FLOW_COUNT,
    EXPECTED_MIXED_PACKET_COUNT,
    EXPECTED_MODEL_THRESHOLD,
    EXPECTED_NORMAL_FLOW_COUNT,
    EXPECTED_NORMAL_NUMERIC_RANGES,
    EXPECTED_NORMAL_PACKET_COUNT,
    EXPECTED_UNUSUAL_FLOWS,
    EXPECTED_UNUSUAL_PACKET_COUNT,
)


def flow(
    *,
    protocol: str = "TCP",
    source_port: int | None = 51000,
    destination_port: int | None = 443,
    packet_count: int = 2,
    byte_count: int = 108,
    duration_seconds: float = 1.0,
    packets_per_second: float = 2.0,
    bytes_per_second: float = 108.0,
) -> FlowSummary:
    return FlowSummary(
        protocol=protocol,
        source_ip="192.0.2.10",
        source_port=source_port,
        destination_ip="198.51.100.20",
        destination_port=destination_port,
        packet_count=packet_count,
        byte_count=byte_count,
        duration_seconds=duration_seconds,
        packets_per_second=packets_per_second,
        bytes_per_second=bytes_per_second,
    )


def test_feature_schema_and_protocol_port_indicators_are_exact() -> None:
    assert FEATURE_NAMES == (
        "packet_count",
        "byte_count",
        "duration_seconds",
        "packets_per_second",
        "bytes_per_second",
        "protocol_tcp",
        "protocol_udp",
        "protocol_icmp_or_icmpv6",
        "protocol_other",
        "source_port_present",
        "destination_port_present",
    )

    assert flow_to_raw_features(flow()).as_tuple() == (
        2.0,
        108.0,
        1.0,
        2.0,
        108.0,
        1.0,
        0.0,
        0.0,
        0.0,
        1.0,
        1.0,
    )
    assert flow_to_raw_features(
        flow(protocol="icmpv6", source_port=None, destination_port=None)
    ).as_tuple()[5:] == (0.0, 0.0, 1.0, 0.0, 0.0, 0.0)
    assert flow_to_raw_features(flow(protocol="GRE")).as_tuple()[5:9] == (
        0.0,
        0.0,
        0.0,
        1.0,
    )


def test_training_only_log_normalization_uses_population_standard_deviation() -> None:
    lower = flow(
        packet_count=1,
        byte_count=1,
        duration_seconds=1.0,
        packets_per_second=1.0,
        bytes_per_second=1.0,
    )
    upper = flow(
        packet_count=3,
        byte_count=3,
        duration_seconds=3.0,
        packets_per_second=3.0,
        bytes_per_second=3.0,
    )

    normalizer = fit_feature_normalizer((upper, lower))

    assert normalizer.transform(lower)[:5] == pytest.approx((-1.0,) * 5)
    assert normalizer.transform(upper)[:5] == pytest.approx((1.0,) * 5)
    assert normalizer.transform(flow(packet_count=7))[:1] == pytest.approx((3.0,))


def test_zero_variance_falls_back_to_one_and_ranges_are_raw() -> None:
    sample = flow()
    normalizer = fit_feature_normalizer((sample, sample))

    assert normalizer.standard_deviations == (1.0,) * 5
    assert normalizer.transform(sample)[:5] == pytest.approx((0.0,) * 5)
    assert normalizer.reference.numeric_ranges == (
        (2.0, 2.0),
        (108.0, 108.0),
        (1.0, 1.0),
        (2.0, 2.0),
        (108.0, 108.0),
    )
    assert normalizer.reference.protocols == ("TCP",)
    assert normalizer.reference.port_presence == ((1.0, 1.0),)


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("packet_count", -1),
        ("byte_count", -1),
        ("duration_seconds", -0.1),
        ("packets_per_second", math.inf),
        ("bytes_per_second", math.nan),
    ],
)
def test_invalid_numeric_features_fail_before_normalization(
    field: str, value: float
) -> None:
    values = {field: value}

    with pytest.raises(FeatureDataError, match="Synthetic training data is insufficient"):
        flow_to_raw_features(flow(**values))


def test_empty_training_fails_and_reordering_is_stable() -> None:
    with pytest.raises(FeatureDataError, match="Synthetic training data is insufficient"):
        fit_feature_normalizer(())

    first = flow(packet_count=1, protocol="UDP")
    second = flow(packet_count=4, protocol="TCP")
    forward = fit_feature_normalizer((first, second))
    reverse = fit_feature_normalizer((second, first))

    assert forward == reverse


def flow_dict(item: FlowSummary) -> dict[str, object]:
    return {
        "protocol": item.protocol,
        "source_ip": item.source_ip,
        "source_port": item.source_port,
        "destination_ip": item.destination_ip,
        "destination_port": item.destination_port,
        "packet_count": item.packet_count,
        "byte_count": item.byte_count,
        "duration_seconds": item.duration_seconds,
        "packets_per_second": item.packets_per_second,
        "bytes_per_second": item.bytes_per_second,
    }


@pytest.mark.skipif(
    "NEXUS_TEST_PHASE4_NORMAL_PCAP_PATH" not in os.environ
    or "NEXUS_TEST_PHASE4_UNUSUAL_PCAP_PATH" not in os.environ,
    reason="real Phase 4 TShark integration fixtures are not mounted",
)
def test_real_phase4_fixtures_produce_exact_metadata_only_flows() -> None:
    normal = analyze_pcap(Path(os.environ["NEXUS_TEST_PHASE4_NORMAL_PCAP_PATH"]))
    unusual = analyze_pcap(Path(os.environ["NEXUS_TEST_PHASE4_UNUSUAL_PCAP_PATH"]))

    assert normal.packet_count == EXPECTED_NORMAL_PACKET_COUNT
    assert len(normal.flows) == EXPECTED_NORMAL_FLOW_COUNT
    assert unusual.packet_count == EXPECTED_UNUSUAL_PACKET_COUNT
    assert [flow_dict(item) for item in unusual.flows] == EXPECTED_UNUSUAL_FLOWS

    observed_hosts = {
        host
        for item in (*normal.flows, *unusual.flows)
        for host in (item.source_ip, item.destination_ip)
    }
    assert observed_hosts == EXPECTED_DOCUMENTATION_HOSTS
    assert fit_feature_normalizer(normal.flows).reference.numeric_ranges == (
        EXPECTED_NORMAL_NUMERIC_RANGES
    )


def training_flows(count: int = 32) -> tuple[FlowSummary, ...]:
    return tuple(
        FlowSummary(
            protocol="UDP" if index % 4 == 0 else "TCP",
            source_ip=("192.0.2.10", "198.51.100.20", "203.0.113.30")[
                index % 3
            ],
            source_port=40000 + index,
            destination_ip=("198.51.100.20", "203.0.113.30", "192.0.2.10")[
                index % 3
            ],
            destination_port=(53, 80, 443, 123)[index % 4],
            packet_count=2 + index % 3,
            byte_count=(84, 108, 162, 216)[index % 4],
            duration_seconds=float(1 + index % 4),
            packets_per_second=(0.5, 1.0, 2.0, 4.0)[index % 4],
            bytes_per_second=(27.0, 54.0, 84.0, 168.0)[index % 4],
        )
        for index in range(count)
    )


def test_detector_uses_exact_parameters_and_native_offset_threshold() -> None:
    detector = train_detector(training_flows())

    assert detector.parameters == {
        "n_estimators": 100,
        "max_samples": 32,
        "contamination": 0.05,
        "max_features": 1.0,
        "bootstrap": False,
        "random_state": 42,
        "n_jobs": 1,
    }
    assert detector.training_flow_count == 32
    assert detector.model_threshold == round(-detector.model.offset_, 6)


def test_detector_requires_32_valid_training_flows() -> None:
    with pytest.raises(FeatureDataError, match="Synthetic training data is insufficient"):
        train_detector(training_flows(31))


def test_seeded_training_and_detection_are_repeatable_after_input_reordering() -> None:
    training = training_flows()
    replay = (
        flow(packet_count=12, byte_count=648, packets_per_second=12.0),
        flow(protocol="ICMP", source_port=None, destination_port=None),
    )

    first = detect_flows(train_detector(training), replay)
    second = detect_flows(train_detector(tuple(reversed(training))), replay)

    assert first == second
    assert tuple(item.flow for item in first) == replay
    assert detect_flows(train_detector(training), ()) == ()


@pytest.mark.parametrize(
    ("score", "threshold", "risk_score", "risk_level", "unusual", "flagged"),
    [
        (0.499999, 0.5, 20, "Low", False, False),
        (0.5, 0.5, 20, "Low", False, False),
        (0.500001, 0.5, 90, "High", True, True),
        (0.549999, 0.5, 90, "High", True, True),
        (0.55, 0.5, 90, "High", True, True),
    ],
)
def test_risk_mapping_flags_every_positive_rounded_margin_high(
    score: float,
    threshold: float,
    risk_score: int,
    risk_level: str,
    unusual: bool,
    flagged: bool,
) -> None:
    decision = map_risk(score, threshold)

    assert decision.risk_score == risk_score
    assert decision.risk_level == risk_level
    assert decision.is_statistically_unusual is unusual
    assert decision.alert_flagged is flagged


def test_explanations_use_only_training_metadata_ranges_and_three_item_limit() -> None:
    reference = fit_feature_normalizer(training_flows()).reference
    unusual = flow(
        packet_count=12,
        byte_count=648,
        duration_seconds=45.0,
        packets_per_second=12.0,
        bytes_per_second=648.0,
    )

    assert explain_detection(unusual, reference, is_unusual=True) == (
        "Packet count 12 is above synthetic training range 2 to 4.",
        "Byte count 648 is above synthetic training range 84 to 216.",
        "Duration seconds 45 is above synthetic training range 1 to 4.",
    )
    assert explain_detection(flow(), reference, is_unusual=False) == (
        "No metadata feature is outside the synthetic training range.",
    )
    assert explain_detection(flow(), reference, is_unusual=True) == (
        "Combined metadata pattern is unusual relative to the synthetic training fixture.",
    )


def test_model_library_failures_are_sanitized(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class BrokenModel:
        def __init__(self, **_kwargs: object) -> None:
            pass

        def fit(self, _values: object) -> None:
            raise RuntimeError("private model internals and local path")

    monkeypatch.setattr("app.anomaly_detection.IsolationForest", BrokenModel)

    with pytest.raises(ModelUnavailable) as raised:
        train_detector(training_flows())

    assert str(raised.value) == "Offline anomaly detection is unavailable."


@pytest.mark.skipif(
    "NEXUS_TEST_PHASE4_NORMAL_PCAP_PATH" not in os.environ
    or "NEXUS_TEST_PHASE4_UNUSUAL_PCAP_PATH" not in os.environ,
    reason="real Phase 4 TShark integration fixtures are not mounted",
)
def test_real_replay_scores_against_native_threshold_and_flags_high_alerts() -> None:
    normal = analyze_pcap(Path(os.environ["NEXUS_TEST_PHASE4_NORMAL_PCAP_PATH"]))
    unusual = analyze_pcap(Path(os.environ["NEXUS_TEST_PHASE4_UNUSUAL_PCAP_PATH"]))

    detector = train_detector(normal.flows)
    results = detect_flows(detector, unusual.flows)
    repeated_detector = train_detector(normal.flows)
    repeated_results = detect_flows(repeated_detector, unusual.flows)

    assert detector.model_threshold == EXPECTED_MODEL_THRESHOLD
    assert repeated_detector.model_threshold == detector.model_threshold
    assert repeated_results == results
    assert [
        {
            "anomaly_score": item.anomaly_score,
            "risk_score": item.risk_score,
            "risk_level": item.risk_level,
            "is_statistically_unusual": item.is_statistically_unusual,
            "alert_flagged": item.alert_flagged,
            "explanations": item.explanations,
        }
        for item in results
    ] == EXPECTED_DETECTION_RESULTS
    assert sum(item.alert_flagged for item in results) == 1


@pytest.mark.skipif(
    "NEXUS_TEST_PHASE4_NORMAL_PCAP_PATH" not in os.environ,
    reason="real Phase 4 TShark integration fixture is not mounted",
)
def test_real_normal_training_calibration_limits_statistical_unusualness() -> None:
    normal = analyze_pcap(Path(os.environ["NEXUS_TEST_PHASE4_NORMAL_PCAP_PATH"]))

    detector = train_detector(normal.flows)
    training_scores = tuple(
        round(-float(value), 6)
        for value in detector.model.score_samples(detector.training_vectors)
    )

    assert sum(score > detector.model_threshold for score in training_scores) <= 3


@pytest.mark.skipif(
    "NEXUS_TEST_PHASE4_NORMAL_PCAP_PATH" not in os.environ
    or "NEXUS_TEST_PHASE4_MIXED_PCAP_PATH" not in os.environ,
    reason="real Phase 4 mixed integration fixture is not mounted",
)
def test_real_mixed_fixture_keeps_normal_flows_low_and_flags_three_icmp_flows() -> None:
    normal = analyze_pcap(Path(os.environ["NEXUS_TEST_PHASE4_NORMAL_PCAP_PATH"]))
    mixed_path = Path(os.environ["NEXUS_TEST_PHASE4_MIXED_PCAP_PATH"])
    mixed = analyze_pcap(mixed_path)

    detector = train_detector(normal.flows)
    results = detect_flows(detector, mixed.flows)
    repeated = detect_flows(train_detector(normal.flows), mixed.flows)

    assert mixed_path.stat().st_size == EXPECTED_MIXED_FIXTURE_BYTES
    assert mixed.packet_count == EXPECTED_MIXED_PACKET_COUNT
    assert len(mixed.flows) == EXPECTED_MIXED_FLOW_COUNT
    assert repeated == results
    assert {
        endpoint
        for flow in mixed.flows
        for endpoint in (flow.source_ip, flow.destination_ip)
    } == EXPECTED_DOCUMENTATION_HOSTS
    assert [
        (
            item.flow.protocol,
            item.anomaly_score,
            item.risk_level,
            item.alert_flagged,
        )
        for item in results
    ] == EXPECTED_MIXED_DETECTION_RESULTS
    assert sum(item.risk_level == "Low" for item in results) == 9
    assert sum(item.risk_level == "High" for item in results) == 3
    assert sum(item.alert_flagged for item in results) == 3
    assert [item.flow.protocol for item in results if item.alert_flagged] == [
        "ICMP",
        "ICMP",
        "ICMP",
    ]
