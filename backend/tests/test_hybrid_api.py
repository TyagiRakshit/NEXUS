from uuid import uuid4

from app.hybrid_evaluation import HybridEvaluationCoordinator
from app.adaptive_baseline import AdaptiveBaselineStore, ScoredObservation
from app.anomaly_detection import DetectionResult, TrainingReference
from app.pcap_analysis import AnalysisResult, FlowSummary


def _observation(*, high: bool = False) -> ScoredObservation:
    flows = tuple(
        FlowSummary(
            "TCP", "192.0.2.10", 40000 + i, "198.51.100.20", 100 + i,
            2, 108, 2.0, 1.0, 54.0,
        )
        for i in range(6)
    )
    analysis = AnalysisResult(
        packet_count=12, flows=flows,
        capture_first_timestamp=600.0, capture_last_timestamp=652.0,
        flow_time_bounds=tuple((600.0 + i * 10, 602.0 + i * 10) for i in range(6)),
    )
    detected = tuple(DetectionResult(
        flow=flow, anomaly_score=0.7 if high else 0.4,
        is_statistically_unusual=high, risk_score=90 if high else 20,
        risk_level="High" if high else "Low", alert_flagged=high,
        explanations=(),
    ) for flow in flows)
    return ScoredObservation(
        analysis_id=uuid4(), observation_id=uuid4(), capture_digest=uuid4().hex,
        analysis=analysis, detected=detected,
        training_reference=TrainingReference(
            numeric_ranges=((1, 10), (1, 1000), (0.1, 10), (0.1, 10), (0.1, 1000)),
            protocols=("TCP",), port_presence=((1.0, 1.0),),
        ),
        model_version="phase4-iforest-v1", model_threshold=0.636672,
    )


def test_hybrid_high_port_rule_vetoes_both_hosts_before_warmup() -> None:
    store = AdaptiveBaselineStore()
    coordinator = HybridEvaluationCoordinator(store)
    observation = _observation()
    result = coordinator.evaluate_hybrid(observation)
    assert all(host["decision"] == "Reject" for host in result["hosts"])
    assert all(host["version_after"] is None for host in result["hosts"])
    assert all("RULE_HIGH_EVIDENCE" in host["reason_codes"] for host in result["hosts"])
    assert all(host["rule_veto_effect"] == "applied" for host in result["hosts"])
    assert all(item["risk_level"] == "Low" for item in result["flow_results"])
    assert any(item["possible_category"] == "possible_port_sweep" for item in result["findings"])
    assert coordinator.evaluate_hybrid(observation) == result
    assert all(len(store.history(host["host_ip"])["decisions"]) == 1 for host in result["hosts"])

def test_legacy_first_high_rule_conflict_preserves_finalized_history() -> None:
    import pytest
    from app.hybrid_evaluation import HybridEvaluationConflict

    store = AdaptiveBaselineStore()
    coordinator = HybridEvaluationCoordinator(store)
    observation = _observation()
    legacy = coordinator.evaluate_legacy(observation)
    assert all(host["decision"] == "Accept" for host in legacy["hosts"])
    before = {
        host["host_ip"]: store.history(host["host_ip"])
        for host in legacy["hosts"]
    }
    with pytest.raises(HybridEvaluationConflict):
        coordinator.evaluate_hybrid(observation)
    assert {
        host: store.history(host) for host in before
    } == before
    assert coordinator.evaluate_legacy(observation) == legacy


def test_legacy_first_rejected_observation_can_add_read_only_rule_evidence() -> None:
    store = AdaptiveBaselineStore()
    coordinator = HybridEvaluationCoordinator(store)
    observation = _observation(high=True)
    legacy = coordinator.evaluate_legacy(observation)
    assert all(host["decision"] == "Reject" for host in legacy["hosts"])
    hybrid = coordinator.evaluate_hybrid(observation)
    assert all(host["rule_veto_effect"] == "redundant" for host in hybrid["hosts"])
    assert coordinator.evaluate_legacy(observation) == legacy
    assert all(len(store.history(host["host_ip"])["decisions"]) == 1 for host in legacy["hosts"])


def test_registration_failure_leaves_no_partial_host_admission() -> None:
    import pytest
    from app.adaptive_baseline import AdaptiveHostNotFound

    def fail_registration(_analysis_id, _findings) -> None:
        raise RuntimeError("candidate store full")

    store = AdaptiveBaselineStore()
    coordinator = HybridEvaluationCoordinator(
        store, candidate_registrar=fail_registration,
    )
    observation = _observation()
    with pytest.raises(RuntimeError, match="candidate store full"):
        coordinator.evaluate_hybrid(observation)
    for host in ("192.0.2.10", "198.51.100.20"):
        with pytest.raises(AdaptiveHostNotFound):
            store.history(host)

def test_hybrid_api_reuses_scored_upload_and_exposes_versioned_result(
    monkeypatch, tmp_path,
) -> None:
    import anyio
    import httpx
    from app import main
    from app.adaptive_baseline import ScoredObservationRegistry
    from app.secure_telemetry import SecureTelemetryStore

    observation = _observation()
    registry = ScoredObservationRegistry()
    registry.register(observation)
    baseline_store = AdaptiveBaselineStore()
    telemetry = SecureTelemetryStore(
        key_directory=tmp_path / "keys",
        evidence_directory=tmp_path / "evidence",
    )
    coordinator = HybridEvaluationCoordinator(
        baseline_store,
        candidate_registrar=telemetry.register_hybrid_candidate,
        candidate_finalizer=telemetry.finalize_hybrid_candidate,
    )
    monkeypatch.setattr(main, "scored_observation_registry", registry)
    monkeypatch.setattr(main, "adaptive_baseline_store", baseline_store)
    monkeypatch.setattr(main, "secure_telemetry_store", telemetry)
    monkeypatch.setattr(main, "hybrid_coordinator", coordinator)

    async def sequence():
        transport = httpx.ASGITransport(app=main.app)
        async with httpx.AsyncClient(
            transport=transport, base_url="http://testserver",
        ) as client:
            first = await client.post(
                "/api/v1/demo/hybrid/evaluate",
                json={"analysis_id": str(observation.analysis_id)},
            )
            second = await client.post(
                "/api/v1/demo/hybrid/evaluate",
                json={"analysis_id": str(observation.analysis_id)},
            )
            legacy = await client.post(
                "/api/v1/demo/baselines/evaluate",
                json={"analysis_id": str(observation.analysis_id)},
            )
            detail = await client.get(
                f"/api/v1/demo/hybrid/{observation.analysis_id}",
            )
            return first, second, legacy, detail

    first, second, legacy, detail = anyio.run(sequence)
    assert first.status_code == second.status_code == detail.status_code == 200
    assert first.json() == second.json() == detail.json()
    assert first.json()["schema_version"] == "phase7.hybrid.v1"
    assert first.json()["telemetry"]["eligible_count"] == 1
    assert legacy.status_code == 200
    assert legacy.json()["schema_version"] == "phase6.baseline.v1"
    assert all(host["decision"] == "Reject" for host in legacy.json()["hosts"])
    assert all(len(baseline_store.history(host["host_ip"])["decisions"]) == 1
               for host in legacy.json()["hosts"])

def test_hybrid_api_manual_v2_protection_verifies_and_rejects_tampered_copy(
    monkeypatch, tmp_path,
) -> None:
    import anyio
    import httpx
    from app import main
    from app.adaptive_baseline import ScoredObservationRegistry
    from app.secure_telemetry import SecureTelemetryStore

    observation = _observation()
    registry = ScoredObservationRegistry()
    registry.register(observation)
    baseline_store = AdaptiveBaselineStore()
    telemetry = SecureTelemetryStore(
        key_directory=tmp_path / "keys",
        evidence_directory=tmp_path / "evidence",
    )
    coordinator = HybridEvaluationCoordinator(
        baseline_store,
        candidate_registrar=telemetry.register_hybrid_candidate,
        candidate_finalizer=telemetry.finalize_hybrid_candidate,
    )
    monkeypatch.setattr(main, "scored_observation_registry", registry)
    monkeypatch.setattr(main, "adaptive_baseline_store", baseline_store)
    monkeypatch.setattr(main, "secure_telemetry_store", telemetry)
    monkeypatch.setattr(main, "hybrid_coordinator", coordinator)

    async def sequence():
        transport = httpx.ASGITransport(app=main.app)
        async with httpx.AsyncClient(
            transport=transport, base_url="http://testserver",
        ) as client:
            evaluated = await client.post(
                "/api/v1/demo/hybrid/evaluate",
                json={"analysis_id": str(observation.analysis_id)},
            )
            protect = await client.post(
                "/api/v1/demo/hybrid/telemetry/protect",
                json={"analysis_id": str(observation.analysis_id)},
            )
            verify = await client.post(
                f"/api/v1/demo/hybrid/telemetry/{observation.analysis_id}/verify",
            )
            tamper = await client.post(
                f"/api/v1/demo/hybrid/telemetry/{observation.analysis_id}/verify-tampered",
            )
            return evaluated, protect, verify, tamper

    evaluated, protect, verify, tamper = anyio.run(sequence)
    assert evaluated.status_code == 200
    assert evaluated.json()["telemetry"]["eligible_count"] == 1
    assert protect.status_code == 200
    assert protect.json()["schema_version"] == "phase7.secure-telemetry.v2"
    assert protect.json()["protected_count"] == 1
    assert verify.status_code == 200 and verify.json()["all_valid"] is True
    assert tamper.status_code == 200 and tamper.json()["tamper_rejected"] is True
    assert len(list((tmp_path / "evidence").glob("protected-telemetry-v2-*.json"))) == 1

def test_compatible_legacy_first_still_registers_v2_candidate(tmp_path) -> None:
    from app.secure_telemetry import SecureTelemetryStore

    store = AdaptiveBaselineStore()
    telemetry = SecureTelemetryStore(
        key_directory=tmp_path / "keys",
        evidence_directory=tmp_path / "evidence",
    )
    coordinator = HybridEvaluationCoordinator(
        store,
        candidate_registrar=telemetry.register_hybrid_candidate,
        candidate_finalizer=telemetry.finalize_hybrid_candidate,
    )
    observation = _observation(high=True)
    coordinator.evaluate_legacy(observation)
    hybrid = coordinator.evaluate_hybrid(observation)
    assert hybrid["telemetry"]["eligible_count"] == 7
    assert telemetry.hybrid_status(observation.analysis_id)["status"] == "not_requested"
    assert telemetry.protect_hybrid(observation.analysis_id).protected_count == 7

def test_post_commit_failure_rolls_back_all_hosts_and_v2_candidate(tmp_path) -> None:
    import pytest
    from app.adaptive_baseline import AdaptiveHostNotFound
    from app.secure_telemetry import AnalysisNotFound, SecureTelemetryStore

    class FailAfterCommit(AdaptiveBaselineStore):
        def evaluate(self, observation, *, rule_veto_hosts=frozenset()):
            super().evaluate(observation, rule_veto_hosts=rule_veto_hosts)
            raise RuntimeError("post-commit failure")

    store = FailAfterCommit()
    telemetry = SecureTelemetryStore(
        key_directory=tmp_path / "keys",
        evidence_directory=tmp_path / "evidence",
    )
    coordinator = HybridEvaluationCoordinator(
        store,
        candidate_registrar=telemetry.register_hybrid_candidate,
        candidate_unregistrar=telemetry.unregister_hybrid_candidate,
        candidate_finalizer=telemetry.finalize_hybrid_candidate,
    )
    observation = _observation()
    with pytest.raises(RuntimeError, match="post-commit failure"):
        coordinator.evaluate_hybrid(observation)
    for host in ("192.0.2.10", "198.51.100.20"):
        with pytest.raises(AdaptiveHostNotFound):
            store.history(host)
    with pytest.raises(AnalysisNotFound):
        telemetry.hybrid_status(observation.analysis_id)


def test_pending_candidate_cannot_escape_failed_multi_host_admission(tmp_path) -> None:
    from concurrent.futures import ThreadPoolExecutor
    from threading import Event
    import pytest
    from app.secure_telemetry import (
        AnalysisNotFound, HybridEvaluationPending, SecureTelemetryStore,
    )

    registered, release = Event(), Event()

    class FailAfterCommit(AdaptiveBaselineStore):
        def evaluate(self, observation, *, rule_veto_hosts=frozenset()):
            super().evaluate(observation, rule_veto_hosts=rule_veto_hosts)
            raise RuntimeError("post-commit failure")

    baseline = FailAfterCommit()
    telemetry = SecureTelemetryStore(
        key_directory=tmp_path / "keys", evidence_directory=tmp_path / "evidence",
    )
    observation = _observation()

    def register(analysis_id, findings):
        telemetry.register_hybrid_candidate(analysis_id, findings)
        registered.set()
        assert release.wait(5)

    coordinator = HybridEvaluationCoordinator(
        baseline, candidate_registrar=register,
        candidate_unregistrar=telemetry.unregister_hybrid_candidate,
        candidate_finalizer=telemetry.finalize_hybrid_candidate,
    )
    with ThreadPoolExecutor(max_workers=2) as executor:
        evaluation = executor.submit(coordinator.evaluate_hybrid, observation)
        try:
            assert registered.wait(5)
            with pytest.raises(HybridEvaluationPending):
                telemetry.protect_hybrid(observation.analysis_id)
            assert not list((tmp_path / "evidence").glob("protected-telemetry-v2-*.json"))
        finally:
            release.set()
        with pytest.raises(RuntimeError, match="post-commit failure"):
            evaluation.result(timeout=5)
    with pytest.raises(AnalysisNotFound):
        telemetry.hybrid_status(observation.analysis_id)
    assert not list((tmp_path / "evidence").glob("protected-telemetry-v2-*.json"))

def test_real_parser_upload_then_hybrid_rule_and_manual_v2_telemetry(
    monkeypatch, tmp_path,
) -> None:
    import anyio
    import httpx
    import os
    import pytest
    from pathlib import Path
    from generate_phase4_fixtures import _alternating_flow, write_pcap
    from app import main
    from app.adaptive_baseline import ScoredObservationRegistry
    from app.secure_telemetry import SecureTelemetryStore

    training_name = os.environ.get("NEXUS_TEST_PHASE4_NORMAL_PCAP_PATH")
    if training_name is None:
        pytest.skip("fixed Phase 4 training fixture is not mounted")
    monkeypatch.setenv("NEXUS_DETECTION_TRAINING_PCAP_PATH", training_name)
    records = []
    for index in range(6):
        records.extend(_alternating_flow(
            start=600 + index * 10, duration=2.0, packet_count=2,
            source="192.0.2.10", destination="198.51.100.20",
            protocol="TCP", source_port=40000 + index,
            destination_port=100 + index,
        ))
    capture = write_pcap(tmp_path / "possible-port-sweep.pcap", records)
    registry = ScoredObservationRegistry()
    baselines = AdaptiveBaselineStore()
    telemetry = SecureTelemetryStore(
        key_directory=tmp_path / "keys",
        evidence_directory=tmp_path / "evidence",
    )
    coordinator = HybridEvaluationCoordinator(
        baselines, candidate_registrar=telemetry.register_hybrid_candidate,
        candidate_unregistrar=telemetry.unregister_hybrid_candidate,
        candidate_finalizer=telemetry.finalize_hybrid_candidate,
    )
    monkeypatch.setattr(main, "scored_observation_registry", registry)
    monkeypatch.setattr(main, "adaptive_baseline_store", baselines)
    monkeypatch.setattr(main, "secure_telemetry_store", telemetry)
    monkeypatch.setattr(main, "hybrid_coordinator", coordinator)

    async def sequence():
        transport = httpx.ASGITransport(app=main.app)
        async with httpx.AsyncClient(
            transport=transport, base_url="http://testserver",
        ) as client:
            upload = await client.post(
                "/api/v1/demo/upload/analyze",
                files={"file": (
                    capture.name, capture.read_bytes(),
                    "application/vnd.tcpdump.pcap",
                )},
            )
            assert upload.status_code == 200, upload.text
            analysis_id = upload.json()["analysis_id"]
            hybrid = await client.post(
                "/api/v1/demo/hybrid/evaluate",
                json={"analysis_id": analysis_id},
            )
            legacy = await client.post(
                "/api/v1/demo/baselines/evaluate",
                json={"analysis_id": analysis_id},
            )
            protect = await client.post(
                "/api/v1/demo/hybrid/telemetry/protect",
                json={"analysis_id": analysis_id},
            )
            verify = await client.post(
                f"/api/v1/demo/hybrid/telemetry/{analysis_id}/verify",
            )
            return upload, hybrid, legacy, protect, verify

    upload, hybrid, legacy, protect, verify = anyio.run(sequence)
    assert upload.json()["flow_count"] == 6
    assert upload.json()["source"] == "REPLAYED DEMO TRAFFIC"
    assert hybrid.status_code == 200, hybrid.text
    assert any(item["rule_id"] == "R1" and item["status"] == "Match"
               for item in hybrid.json()["rule_assessments"])
    assert [item["anomaly_score"] for item in hybrid.json()["flow_results"]] == [
        item["anomaly_score"] for item in upload.json()["results"]
    ]
    assert all(host["decision"] == "Reject" for host in legacy.json()["hosts"])
    assert protect.status_code == 200 and verify.status_code == 200
    assert protect.json()["protected_count"] == hybrid.json()["telemetry"]["eligible_count"]

def test_expired_hybrid_result_cannot_re_admit_same_analysis() -> None:
    import pytest
    from app.hybrid_evaluation import HybridEvaluationNotFound

    now = [0.0]
    store = AdaptiveBaselineStore(ttl_seconds=1.0, clock=lambda: now[0])
    coordinator = HybridEvaluationCoordinator(store)
    observation = _observation()
    coordinator.evaluate_hybrid(observation)
    now[0] = 2.0
    with pytest.raises(HybridEvaluationNotFound):
        coordinator.evaluate_hybrid(observation)
    with pytest.raises(HybridEvaluationNotFound):
        coordinator.get_hybrid(str(observation.analysis_id))
    assert all(
        len(store.history(host)["decisions"]) == 1
        for host in ("192.0.2.10", "198.51.100.20")
    )

def test_recon_rule_vetoes_focal_host_without_vetoing_all_peers() -> None:
    from dataclasses import replace

    original = _observation()
    flows = tuple(FlowSummary(
        "TCP", "192.0.2.10", 40000 + i,
        f"198.51.100.{20 + i}", 443,
        2, 108, 2.0, 1.0, 54.0,
    ) for i in range(5))
    analysis = AnalysisResult(
        packet_count=10, flows=flows,
        capture_first_timestamp=600.0, capture_last_timestamp=650.0,
        flow_time_bounds=tuple((600.0 + 12 * i, 602.0 + 12 * i) for i in range(5)),
    )
    low = tuple(replace(
        original.detected[0], flow=flow,
    ) for flow in flows)
    observation = replace(original, analysis=analysis, detected=low)
    result = HybridEvaluationCoordinator(AdaptiveBaselineStore()).evaluate_hybrid(observation)
    focal = next(host for host in result["hosts"] if host["host_ip"] == "192.0.2.10")
    peers = [host for host in result["hosts"] if host["host_ip"] != "192.0.2.10"]
    assert focal["decision"] == "Reject"
    assert "RULE_HIGH_EVIDENCE" in focal["reason_codes"]
    assert len(peers) == 5
    assert all("RULE_HIGH_EVIDENCE" not in host["reason_codes"] for host in peers)
    assert any(item["rule_id"] == "R2" and item["status"] == "Match"
               for item in result["rule_assessments"])


def test_concurrent_hybrid_evaluation_admits_each_host_once() -> None:
    from concurrent.futures import ThreadPoolExecutor

    observation = _observation()
    store = AdaptiveBaselineStore()
    coordinator = HybridEvaluationCoordinator(store)
    with ThreadPoolExecutor(max_workers=8) as pool:
        results = list(pool.map(coordinator.evaluate_hybrid, [observation] * 16))
    assert all(item == results[0] for item in results)
    assert all(
        len(store.history(host)["decisions"]) == 1
        for host in ("192.0.2.10", "198.51.100.20")
    )
