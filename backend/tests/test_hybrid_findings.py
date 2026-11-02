from uuid import UUID

from app.hybrid_findings import build_findings
from app.adaptive_baseline import ScoredObservation
from app.anomaly_detection import DetectionResult, TrainingReference
from app.pcap_analysis import AnalysisResult, FlowSummary


def _observation() -> ScoredObservation:
    flow = FlowSummary(
        "TCP", "192.0.2.10", 40000, "198.51.100.20", 443,
        2, 108, 1.0, 2.0, 108.0,
    )
    detected = DetectionResult(
        flow=flow, anomaly_score=0.7, is_statistically_unusual=True,
        risk_score=90, risk_level="High", alert_flagged=True,
        explanations=("Unusual packet count.",),
    )
    return ScoredObservation(
        analysis_id=UUID("11111111-1111-1111-1111-111111111111"),
        observation_id=UUID("22222222-2222-2222-2222-222222222222"),
        capture_digest="a" * 64,
        analysis=AnalysisResult(
            packet_count=2, flows=(flow,), flow_time_bounds=((600.0, 601.0),),
        ),
        detected=(detected,),
        training_reference=TrainingReference(
            numeric_ranges=((1, 2),) * 5, protocols=("TCP",),
            port_presence=((1.0, 1.0),),
        ),
        model_version="phase4-iforest-v1", model_threshold=0.636672,
    )


def test_findings_keep_three_sources_distinct_and_stable() -> None:
    observation = _observation()
    baseline = {"hosts": [{
        "host_ip": "192.0.2.10",
        "findings": [{
            "finding_id": "33333333-3333-3333-3333-333333333333",
            "kind": "BASELINE_SEVERE_DEVIATION",
            "severity": "High",
            "evidence_features": ["observed_flow_count"],
            "explanation": "Severe host change.",
        }],
        "flow_evidence_refs": [0],
    }]}
    rules = ({
        "rule_id": "R1", "status": "Match",
        "reason_code": "POSSIBLE_PORT_SWEEP",
        "subject_host_ips": ["192.0.2.10", "198.51.100.20"],
        "affected_host_ips": ["192.0.2.10", "198.51.100.20"],
        "flow_indices": [0],
        "rule_evidence_strength": 60,
        "evidence": {"tcp_flow_count": 6},
        "explanation": "Possible port sweep; initiator unknown.",
    },)
    findings = build_findings(observation, baseline, rules)
    assert [item["detection_source"] for item in findings] == [
        "isolation_forest", "adaptive_baseline", "security_rule",
    ]
    assert len({item["finding_id"] for item in findings}) == 3
    assert all(item["telemetry_eligible"] for item in findings)
    assert findings[0]["ml_anomaly_score"] == 0.7
    assert findings[-1]["rule_evidence_strength"] == 60
    assert all(item["schema_version"] == "phase7.finding.v1" for item in findings)
    assert findings == build_findings(observation, baseline, rules)


def test_high_findings_retain_numerical_baseline_and_rule_evidence() -> None:
    observation = _observation()
    baseline = {"hosts": [{
        "host_ip": "192.0.2.10", "flow_evidence_refs": [0],
        "feature_deviations": [{
            "feature": "observed_flow_count", "observed": 8.0,
            "baseline": 4.0, "deviation": 1.0,
            "accept_limit": 0.25, "hold_limit": 0.75,
            "band": "Reject", "reason_code": "SEVERE_BASELINE_DEVIATION",
        }],
        "findings": [{
            "kind": "BASELINE_SEVERE_DEVIATION", "severity": "High",
            "evidence_features": ["observed_flow_count"],
            "explanation": "Severe host change.",
        }],
    }]}
    rules = ({
        "rule_id": "R1", "status": "Match", "subject_host_ips": [
            "192.0.2.10", "198.51.100.20",
        ], "flow_indices": [0], "rule_evidence_strength": 60,
        "evidence": {
            "tcp_flow_count": 6, "distinct_start_times": 3,
            "start_timestamp": 600.0, "end_timestamp": 601.0,
        }, "explanation": "Possible port sweep; initiator unknown.",
    },)
    findings = build_findings(observation, baseline, rules)
    baseline_evidence = findings[1]["evidence"]
    assert any(
        all(entry.get(key) == value for key, value in {
            "metric": "observed_flow_count", "observed": 8.0,
            "baseline": 4.0, "deviation": 1.0,
            "accept_limit": 0.25, "hold_limit": 0.75,
            "band": "Reject", "reason_code": "SEVERE_BASELINE_DEVIATION",
        }.items()) for entry in baseline_evidence
    )
    assert findings[1]["capture_window_start"] == "1970-01-01T00:10:00+00:00"
    rule_evidence = findings[2]["evidence"]
    assert any(item["metric"] == "tcp_flow_count" and
               item["comparator"] == ">=" and item["threshold"] == 6
               for item in rule_evidence)
    assert findings[2]["capture_window_end"] == "1970-01-01T00:10:01+00:00"
