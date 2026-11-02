import math
from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
from pathlib import Path
from uuid import uuid4

import pytest

from app.adaptive_baseline import (
    capture_digest,
    classify_capture_window,
    classify_count,
    classify_log_metric,
    classify_protocol_share,
    classify_training_range,
    proposed_numeric_update,
    proposed_share_update,
    build_adaptive_host_profiles,
    decide_host,
    ScoredObservation,
    ScoredObservationRegistry,
    ObservationNotFound,
    ObservationExpired,
    ObservationCapacityExceeded,
    AdaptiveBaselineStore,
    AdaptiveCapacityExceeded,
    AdaptiveHostNotFound,
)
from app.pcap_analysis import AnalysisResult, FlowSummary
from app.anomaly_detection import DetectionResult, TrainingReference


def test_capture_window_is_learning_eligibility_not_analysis_rejection() -> None:
    short = classify_capture_window(60.0, 64.0)
    assert short.window_start == "1970-01-01T00:01:00Z"
    assert short.window_end == "1970-01-01T00:02:00Z"
    assert short.activity_span_seconds == 4.0
    assert short.reason_code == "INSUFFICIENT_EVIDENCE"

    boundary = classify_capture_window(60.0, 105.0)
    assert boundary.reason_code is None
    assert boundary.activity_span_seconds == 45.0

    crossed = classify_capture_window(60.0, 120.0)
    assert crossed.window_start is None
    assert crossed.window_end is None
    assert crossed.reason_code == "NONCOMPARABLE_WINDOW"


def test_capture_digest_distinguishes_bytes_not_extracted_features(
    tmp_path: Path,
) -> None:
    first = tmp_path / "first.pcap"
    second = tmp_path / "second.pcap"
    first.write_bytes(b"same feature representation, byte variant A")
    second.write_bytes(b"same feature representation, byte variant B")
    assert capture_digest(first) == capture_digest(first)
    assert capture_digest(first) != capture_digest(second)


@pytest.mark.parametrize(
    ("observed", "baseline", "expected"),
    [
        (5, 4, "Accept"),
        (3, 4, "Accept"),
        (7, 4, "Hold"),
        (1, 4, "Hold"),
        (8, 4, "Reject"),
        (0, 4, "Reject"),
        (0, 1, "Accept"),
        (3, 1, "Hold"),
        (4, 1, "Reject"),
    ],
)
def test_count_bands_are_symmetric_at_boundaries(
    observed: float, baseline: float, expected: str,
) -> None:
    assert classify_count(observed, baseline) == expected


def test_log_band_handles_zero_and_both_directions() -> None:
    upper = 1.5 * (64 + 64) - 64
    lower = (64 + 64) / 1.5 - 64
    assert classify_log_metric(upper, 64, 64, 1.5, 2) == "Accept"
    assert classify_log_metric(lower, 64, 64, 1.5, 2) == "Accept"
    assert classify_log_metric(0, 0, 64, 1.5, 2) == "Accept"
    assert classify_log_metric(192, 64, 64, 1.5, 2) == "Hold"
    assert classify_log_metric(300, 64, 64, 1.5, 2) == "Reject"
    assert classify_log_metric(float("nan"), 64, 64, 1.5, 2) == "Insufficient"


def test_protocol_shares_are_normalized_and_sparse_rule_is_explicit() -> None:
    assert classify_protocol_share(0.15, 0.0, current_count=1) == "Hold"
    assert classify_protocol_share(0.26, 0.0, current_count=1) == "Reject"
    assert classify_protocol_share(0.10, 0.0, current_count=2) == "Reject"
    assert classify_protocol_share(0.0, 0.15, current_count=0) == "Accept"
    assert classify_protocol_share(0.0, 0.30, current_count=0) == "Hold"


def test_training_range_guard_is_symmetric_and_zero_safe() -> None:
    assert classify_training_range(10, 10, 20, 1) == "Accept"
    assert classify_training_range(9, 10, 20, 1) == "Hold"
    assert classify_training_range(3, 10, 20, 1) == "Reject"
    assert classify_training_range(30, 10, 20, 1) == "Hold"
    assert classify_training_range(50, 10, 20, 1) == "Reject"
    assert classify_training_range(-1, 10, 20, 1) == "Insufficient"


def test_bounded_numeric_and_share_updates_obey_anchor_limit() -> None:
    assert proposed_numeric_update(100, 200, 100, 1, 0.20) == 110
    assert proposed_numeric_update(100, 0, 100, 1, 0.20) == 90
    assert proposed_numeric_update(150, 160, 100, 1, 0.20) is None
    assert proposed_share_update(
        {"TCP": 0.75, "UDP": 0.25},
        {"TCP": 0.50, "UDP": 0.50},
        {"TCP": 0.75, "UDP": 0.25},
        0.20,
    ) == pytest.approx({"TCP": 0.70, "UDP": 0.30})


def test_bidirectional_flows_count_once_for_each_distinct_endpoint() -> None:
    flows = (
        FlowSummary("TCP", "192.0.2.10", 40001, "198.51.100.20", 443, 2, 108, 1.0, 2.0, 108.0),
        FlowSummary("UDP", "198.51.100.20", 40002, "192.0.2.10", 53, 3, 126, 2.0, 1.5, 63.0),
    )
    profiles = build_adaptive_host_profiles(flows)
    assert set(profiles) == {"192.0.2.10", "198.51.100.20"}
    for profile in profiles.values():
        assert profile.observed_flow_count == 2
        assert profile.average_bytes_per_flow == 117
        assert profile.average_duration_seconds == 1.5
        assert profile.average_packets_per_second == 1.75
        assert profile.protocol_shares == pytest.approx({
            "TCP": 0.5, "UDP": 0.5, "ICMP": 0, "OTHER": 0,
        })


def test_self_flow_is_attributed_once() -> None:
    flow = FlowSummary("TCP", "192.0.2.10", 40001, "192.0.2.10", 443, 2, 108, 1.0, 2.0, 108.0)
    profiles = build_adaptive_host_profiles((flow,))
    assert profiles["192.0.2.10"].observed_flow_count == 1


def _detection(flow: FlowSummary, *, high: bool = False) -> DetectionResult:
    return DetectionResult(
        flow=flow,
        anomaly_score=0.7 if high else 0.4,
        is_statistically_unusual=high,
        risk_score=90 if high else 20,
        risk_level="High" if high else "Low",
        alert_flagged=high,
        explanations=(),
    )


def test_high_flow_vetoes_both_endpoint_baselines_without_attack_attribution() -> None:
    flow = FlowSummary("TCP", "192.0.2.10", 40001, "198.51.100.20", 443, 2, 108, 1.0, 2.0, 108.0)
    profiles = build_adaptive_host_profiles((flow,))
    reference = TrainingReference(
        numeric_ranges=((2, 4), (100, 200), (1, 3), (1, 4), (50, 200)),
        protocols=("TCP", "UDP"),
        port_presence=((1.0, 1.0),),
    )
    for host, profile in profiles.items():
        result = decide_host(host, profile, profile, (_detection(flow, high=True),), reference)
        assert result.decision == "Reject"
        assert "ML_HIGH" in result.reason_codes
        assert result.high_flow_count == 1
        assert all("attacker" not in finding["explanation"].lower() for finding in result.findings)


def test_low_flow_can_produce_separate_severe_host_finding() -> None:
    flow = FlowSummary("TCP", "192.0.2.10", 40001, "198.51.100.20", 443, 2, 108, 1.0, 2.0, 108.0)
    baseline = build_adaptive_host_profiles((flow,) * 20)["192.0.2.10"]
    current = build_adaptive_host_profiles((flow,) * 4)["192.0.2.10"]
    reference = TrainingReference(
        numeric_ranges=((2, 4), (100, 200), (1, 3), (1, 4), (50, 200)),
        protocols=("TCP", "UDP"),
        port_presence=((1.0, 1.0),),
    )
    result = decide_host("192.0.2.10", current, baseline, (_detection(flow),) * 4, reference)
    assert result.decision == "Reject"
    assert result.reason_codes == ("SEVERE_BASELINE_DEVIATION",)
    assert result.high_flow_count == 0
    assert result.findings[0]["kind"] == "BASELINE_SEVERE_DEVIATION"
    assert result.findings[0]["severity"] == "High"
    assert result.findings[0]["is_phase5c_signed_alert"] is False
    count_evidence = next(
        item for item in result.feature_deviations
        if item["feature"] == "observed_flow_count"
    )
    assert count_evidence["deviation"] == pytest.approx(0.8)
    assert count_evidence["accept_limit"] == 0.25
    assert count_evidence["hold_limit"] == 0.75


def test_many_new_protocol_flows_reject_host_admission() -> None:
    tcp = FlowSummary("TCP", "192.0.2.10", 40001, "198.51.100.20", 443, 2, 108, 1.0, 2.0, 108.0)
    udp = FlowSummary("UDP", "192.0.2.10", 40002, "198.51.100.20", 53, 2, 108, 1.0, 2.0, 108.0)
    baseline = build_adaptive_host_profiles((tcp,) * 20)["192.0.2.10"]
    current = build_adaptive_host_profiles((tcp,) * 18 + (udp, udp))["192.0.2.10"]
    reference = TrainingReference(
        numeric_ranges=((2, 4), (100, 200), (1, 3), (1, 4), (50, 200)),
        protocols=("TCP", "UDP"),
        port_presence=((1.0, 1.0),),
    )
    result = decide_host(
        "192.0.2.10", current, baseline,
        tuple(_detection(flow) for flow in (tcp,) * 18 + (udp, udp)), reference,
    )
    assert result.decision == "Reject"
    assert "NEW_PROTOCOL" in result.reason_codes


def test_low_risk_extreme_flow_rejects_admission() -> None:
    flow = FlowSummary("TCP", "192.0.2.10", 40001, "198.51.100.20", 443, 20, 1080, 1.0, 20.0, 1080.0)
    profile = build_adaptive_host_profiles((flow,))["192.0.2.10"]
    reference = TrainingReference(
        numeric_ranges=((2, 4), (100, 200), (1, 3), (1, 4), (50, 200)),
        protocols=("TCP", "UDP"),
        port_presence=((1.0, 1.0),),
    )
    result = decide_host("192.0.2.10", profile, None, (_detection(flow),), reference)
    assert result.decision == "Reject"
    assert "EXTREME_FLOW_EVIDENCE" in result.reason_codes


def test_scored_observation_registry_is_bounded_and_expires_visibly() -> None:
    now = [100.0]
    registry = ScoredObservationRegistry(
        max_items=1, ttl_seconds=900, clock=lambda: now[0],
    )
    first = ScoredObservation(
        analysis_id=uuid4(), observation_id=uuid4(), capture_digest="a" * 64,
        analysis=AnalysisResult(0, ()), detected=(), training_reference=TrainingReference((), (), ()),
        model_version="phase4-iforest-v1", model_threshold=0.636672,
    )
    second = ScoredObservation(
        analysis_id=uuid4(), observation_id=uuid4(), capture_digest="b" * 64,
        analysis=AnalysisResult(0, ()), detected=(), training_reference=TrainingReference((), (), ()),
        model_version="phase4-iforest-v1", model_threshold=0.636672,
    )
    registry.register(first)
    assert registry.get(first.analysis_id) == first
    with pytest.raises(ObservationCapacityExceeded):
        registry.register(second)
    with pytest.raises(ObservationNotFound):
        registry.get(second.analysis_id)
    now[0] = 1001.0
    with pytest.raises(ObservationExpired):
        registry.get(first.analysis_id)
    registry.register(second)
    assert registry.get(second.analysis_id) == second


def _scored_window(
    start: int, *,
    digest: str | None = None,
    byte_count: int = 108,
    high: bool = False,
) -> ScoredObservation:
    flows = tuple(
        FlowSummary(
            "TCP", "192.0.2.10", 45000 + index,
            "198.51.100.20", 443, 2, byte_count, 2.0, 1.0,
            byte_count / 2,
        )
        for index in range(4)
    )
    bounds = tuple((float(start + offset), float(start + offset + 2))
                   for offset in (0, 15, 30, 46))
    analysis = AnalysisResult(
        packet_count=8, flows=flows,
        capture_first_timestamp=float(start),
        capture_last_timestamp=float(start + 48),
        flow_time_bounds=bounds,
    )
    reference = TrainingReference(
        numeric_ranges=((2, 4), (100, 300), (1, 4), (0.5, 4), (40, 200)),
        protocols=("TCP", "UDP"), port_presence=((1.0, 1.0),),
    )
    return ScoredObservation(
        analysis_id=uuid4(), observation_id=uuid4(),
        capture_digest=digest or f"capture-{start}-{byte_count}-{uuid4()}",
        analysis=analysis,
        detected=tuple(_detection(flow, high=high) for flow in flows),
        training_reference=reference,
        model_version="phase4-iforest-v1", model_threshold=0.636672,
    )


def _host_result(response: dict[str, object]) -> dict[str, object]:
    hosts = response["hosts"]
    assert isinstance(hosts, list)
    return next(item for item in hosts if item["host_ip"] == "192.0.2.10")


def test_five_admissions_transition_from_warming_to_provisional_to_ready() -> None:
    store = AdaptiveBaselineStore()
    states = [
        _host_result(store.evaluate(_scored_window(start)))
        for start in (60, 120, 180, 240, 300)
    ]
    assert [(item["readiness_after"], item["version_after"]) for item in states] == [
        ("warming", 0), ("provisional", 1), ("provisional", 2),
        ("provisional", 3), ("ready", 4),
    ]
    assert states[1]["coverage_confidence"] == "limited"
    assert states[4]["coverage_confidence"] == "accumulated"
    assert all(item["decision"] == "Accept" for item in states)


def test_exact_five_minute_end_to_start_gap_keeps_warmup() -> None:
    store = AdaptiveBaselineStore()
    first = _host_result(store.evaluate(_scored_window(60)))
    second = _host_result(store.evaluate(_scored_window(420)))
    assert first["readiness_after"] == "warming"
    assert second["readiness_after"] == "provisional"
    assert second["version_after"] == 1


def test_greater_than_five_minute_gap_restarts_warmup_with_later_observation() -> None:
    store = AdaptiveBaselineStore()
    store.evaluate(_scored_window(60))
    restarted = _host_result(store.evaluate(_scored_window(480)))
    assert restarted["decision"] == "Accept"
    assert restarted["readiness_after"] == "warming"
    assert restarted["version_after"] == 0
    assert restarted["accepted_count_after"] == 1
    next_result = _host_result(store.evaluate(_scored_window(540)))
    assert next_result["readiness_after"] == "provisional"


def test_duplicate_overlap_and_out_of_order_never_update() -> None:
    store = AdaptiveBaselineStore()
    original = _scored_window(60, digest="same bytes")
    first_response = store.evaluate(original)
    assert store.evaluate(original) == first_response
    duplicate = _host_result(store.evaluate(_scored_window(60, digest="same bytes")))
    overlap = _host_result(store.evaluate(_scored_window(60, digest="different bytes")))
    older = _host_result(store.evaluate(_scored_window(0)))
    assert "DUPLICATE_CAPTURE" in duplicate["reason_codes"]
    assert "OVERLAPPING_WINDOW" in overlap["reason_codes"]
    assert "OUT_OF_ORDER_CAPTURE" in older["reason_codes"]
    assert all(item["version_after"] == 0 for item in (duplicate, overlap, older))


def _ready_store() -> AdaptiveBaselineStore:
    store = AdaptiveBaselineStore()
    for start in (60, 120, 180, 240, 300):
        store.evaluate(_scored_window(start))
    return store


def test_exact_five_minute_gap_admits_second_consistent_probation_candidate() -> None:
    store = _ready_store()
    first = _host_result(store.evaluate(_scored_window(360, byte_count=200)))
    second = _host_result(store.evaluate(_scored_window(720, byte_count=200)))
    assert first["decision"] == "Hold"
    assert first["probation_count"] == 1
    assert first["version_after"] == 4
    assert second["decision"] == "Accept"
    assert second["reason_codes"] == ["PROBATION_ADMITTED"]
    assert second["version_after"] == 5


def test_long_gap_restarts_probation_and_preserves_established_baseline() -> None:
    store = _ready_store()
    first = _host_result(store.evaluate(_scored_window(360, byte_count=200)))
    second = _host_result(store.evaluate(_scored_window(780, byte_count=200)))
    assert first["probation_count"] == 1
    assert second["decision"] == "Hold"
    assert second["probation_count"] == 1
    assert second["version_before"] == second["version_after"] == 4
    assert second["baseline_before"] == second["baseline_after"]
    third = _host_result(store.evaluate(_scored_window(840, byte_count=200)))
    assert third["decision"] == "Accept"
    assert third["version_after"] == 5


def test_warmup_poisoning_resets_tentative_sample() -> None:
    store = AdaptiveBaselineStore()
    store.evaluate(_scored_window(60))
    poisoned = _host_result(store.evaluate(_scored_window(120, byte_count=300)))
    assert poisoned["decision"] == "Hold"
    assert "WARMUP_INCONSISTENT" in poisoned["reason_codes"]
    assert poisoned["readiness_after"] == "absent"
    later = _host_result(store.evaluate(_scored_window(180)))
    assert later["readiness_after"] == "warming"
    assert later["version_after"] == 0


def test_severe_baseline_only_finding_does_not_update_or_become_signed_alert() -> None:
    store = _ready_store()
    result = _host_result(store.evaluate(_scored_window(360, byte_count=300)))
    assert result["decision"] == "Reject"
    assert "SEVERE_BASELINE_DEVIATION" in result["reason_codes"]
    assert result["high_flow_count"] == 0
    assert result["version_before"] == result["version_after"] == 4
    assert result["baseline_before"] == result["baseline_after"]
    assert result["findings"][0]["severity"] == "High"
    assert result["findings"][0]["is_phase5c_signed_alert"] is False


def test_cumulative_anchor_limit_eventually_holds_gradual_drift() -> None:
    store = _ready_store()
    reached = None
    for start in range(360, 1200, 60):
        result = _host_result(store.evaluate(_scored_window(start, byte_count=185)))
        if "ADAPTATION_LIMIT_REACHED" in result["reason_codes"]:
            reached = result
            break
        assert result["decision"] == "Accept"
    assert reached is not None
    assert reached["decision"] == "Hold"
    assert reached["version_before"] == reached["version_after"]
    assert reached["baseline_before"] == reached["baseline_after"]
    assert reached["findings"][0]["kind"] == "ADAPTATION_LIMIT_REACHED"
    assert "average_bytes_per_flow" in reached["findings"][0]["evidence_features"]


def test_concurrent_repeat_evaluation_is_idempotent_and_history_is_bounded() -> None:
    store = AdaptiveBaselineStore()
    observation = _scored_window(60)
    with ThreadPoolExecutor(max_workers=8) as executor:
        results = list(executor.map(store.evaluate, (observation,) * 16))
    assert all(item == results[0] for item in results)
    history = store.history("192.0.2.10")
    assert history["current_version"] == 0
    assert len(history["snapshots"]) == 1
    assert len(history["decisions"]) == 1


def test_invalid_observation_cannot_partially_change_two_hosts() -> None:
    store = _ready_store()
    before_a = store.history("192.0.2.10")
    before_b = store.history("198.51.100.20")
    valid = _scored_window(360)
    invalid = replace(valid, detected=valid.detected[:-1])
    with pytest.raises(Exception):
        store.evaluate(invalid)
    assert store.history("192.0.2.10") == before_a
    assert store.history("198.51.100.20") == before_b


def test_short_capture_is_hold_without_baseline_only_severe_finding() -> None:
    store = _ready_store()
    candidate = _scored_window(360, byte_count=300)
    short = replace(
        candidate,
        analysis=replace(
            candidate.analysis,
            capture_last_timestamp=364.0,
        ),
    )
    result = _host_result(store.evaluate(short))
    assert result["decision"] == "Hold"
    assert result["reason_codes"] == ["INSUFFICIENT_EVIDENCE"]
    assert result["findings"] == []
    assert result["version_after"] == 4


def test_digest_history_capacity_refuses_new_capture_without_partial_update() -> None:
    store = AdaptiveBaselineStore(max_digests_per_host=2)
    store.evaluate(_scored_window(60))
    store.evaluate(_scored_window(120))
    before_a = store.history("192.0.2.10")
    before_b = store.history("198.51.100.20")
    with pytest.raises(AdaptiveCapacityExceeded):
        store.evaluate(_scored_window(180))
    assert store.history("192.0.2.10") == before_a
    assert store.history("198.51.100.20") == before_b


def test_high_flow_vetoes_both_ready_hosts_without_baseline_change() -> None:
    store = _ready_store()
    before_a = store.history("192.0.2.10")["current_baseline"]
    before_b = store.history("198.51.100.20")["current_baseline"]
    response = store.evaluate(_scored_window(360, high=True))
    assert [host["decision"] for host in response["hosts"]] == ["Reject", "Reject"]
    assert all("ML_HIGH" in host["reason_codes"] for host in response["hosts"])
    assert all(host["version_before"] == host["version_after"] == 4
               for host in response["hosts"])
    assert store.history("192.0.2.10")["current_baseline"] == before_a
    assert store.history("198.51.100.20")["current_baseline"] == before_b


def test_history_keeps_eight_accepted_snapshots_and_32_decisions() -> None:
    now = [0.0]
    store = AdaptiveBaselineStore(clock=lambda: now[0])
    for index in range(40):
        store.evaluate(_scored_window(60 + index * 60))
        now[0] += 901
    history = store.history("192.0.2.10")
    assert history["current_version"] == 39
    assert history["anchor_version"] == 1
    assert len(history["snapshots"]) == 8
    assert [item["version"] for item in history["snapshots"]] == list(range(32, 40))
    assert len(history["decisions"]) == 32
    restarted = AdaptiveBaselineStore()
    assert restarted.store_epoch != store.store_epoch
    with pytest.raises(AdaptiveHostNotFound):
        restarted.history("192.0.2.10")


def test_later_ineligible_capture_after_long_gap_is_not_auto_admitted() -> None:
    store = AdaptiveBaselineStore()
    store.evaluate(_scored_window(60))
    later = _scored_window(480)
    short = replace(
        later, analysis=replace(later.analysis, capture_last_timestamp=484.0),
    )
    result = _host_result(store.evaluate(short))
    assert result["decision"] == "Hold"
    assert result["readiness_after"] == "absent"
    assert result["version_after"] is None
    next_result = _host_result(store.evaluate(_scored_window(540)))
    assert next_result["readiness_after"] == "warming"
    assert next_result["version_after"] == 0
