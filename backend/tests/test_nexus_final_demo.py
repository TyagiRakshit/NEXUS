"""Final one-capture demo: real parser, isolated Hybrid admission and telemetry."""

from __future__ import annotations

import hashlib
import json
import subprocess
import sys
from pathlib import Path

from app.adaptive_baseline import build_adaptive_host_profiles, classify_capture_window
from app.anomaly_detection import detect_flows, train_detector
from app.hybrid_rules import evaluate_rules
from app.pcap_analysis import analyze_pcap

GENERATOR = Path("/app/scripts/generate_nexus_final_demo.py")
VALIDATOR = Path("/app/scripts/validate_nexus_final_demo.py")
TRAINING = Path("/app/fixtures/phase4-normal-training.pcap")
PRINCIPALS = ("192.0.2.10", "198.51.100.20", "203.0.113.30")


def _generate(directory: Path) -> dict[str, object]:
    result = subprocess.run(
        [sys.executable, str(GENERATOR), str(directory)],
        capture_output=True, text=True, check=False,
    )
    assert result.returncode == 0, result.stderr
    return json.loads((directory / "manifest.json").read_text(encoding="utf-8"))


def test_final_capture_is_deterministic_payload_free_and_rule_supported(tmp_path: Path) -> None:
    help_result = subprocess.run(
        [sys.executable, str(GENERATOR), "--help"],
        cwd=tmp_path, capture_output=True, text=True, check=False,
    )
    assert help_result.returncode == 0
    assert not (tmp_path / "--help").exists()
    first = _generate(tmp_path / "first")
    second = _generate(tmp_path / "second")
    assert first == second
    assert first["source"] == "REPLAYED DEMO TRAFFIC"
    assert first["starting_checkpoint"] == "adaptive-00..04 Hybrid, Ready v4"
    name = "nexus-final-hybrid-demo.pcap"
    left = (tmp_path / "first" / name).read_bytes()
    right = (tmp_path / "second" / name).read_bytes()
    assert left == right
    assert hashlib.sha256(left).hexdigest() == first["sha256"]
    assert len(left) <= 1_048_576
    assert first["packet_count"] <= 2_000
    parsed = analyze_pcap(tmp_path / "first" / name)
    assert parsed.packet_count == first["packet_count"]
    assert len(parsed.flows) == first["flow_count"]
    assert classify_capture_window(
        parsed.capture_first_timestamp, parsed.capture_last_timestamp
    ).reason_code is None
    assert first["capture_window_start"] == "1970-01-01T02:05:00Z"
    features = build_adaptive_host_profiles(parsed.flows)
    assert all(host in features for host in PRINCIPALS)
    assert features[PRINCIPALS[0]].observed_flow_count == 4
    assert features[PRINCIPALS[1]].observed_flow_count == 4
    assert features[PRINCIPALS[2]].observed_flow_count >= 5
    detector = train_detector(analyze_pcap(TRAINING).flows)
    detected = detect_flows(detector, parsed.flows)
    assert any(item.risk_level == "High" for item in detected)
    assert all(
        item.risk_level == "Low"
        for item in detected
        if PRINCIPALS[0] in {item.flow.source_ip, item.flow.destination_ip}
    )
    matches = [item for item in evaluate_rules(parsed) if item["status"] == "Match"]
    assert {item["rule_id"] for item in matches} >= {"R1", "R2"}
    assert all(PRINCIPALS[0] not in item["affected_host_ips"] for item in matches)
    assert all(PRINCIPALS[1] not in item["affected_host_ips"] for item in matches)
    marker = tmp_path / "occupied"
    marker.mkdir()
    (marker / "keep.txt").write_text("owner", encoding="utf-8")
    refused = subprocess.run(
        [sys.executable, str(GENERATOR), str(marker)],
        capture_output=True, text=True, check=False,
    )
    assert refused.returncode != 0
    assert (marker / "keep.txt").read_text(encoding="utf-8") == "owner"


def test_final_api_and_both_telemetry_versions_are_verified_in_isolation(tmp_path: Path) -> None:
    corpus = tmp_path / "corpus"
    _generate(corpus)
    validation = subprocess.run(
        [sys.executable, str(VALIDATOR), str(corpus), "--preparation-directory", "/app/preparation", "--write-results"],
        capture_output=True, text=True, check=False,
    )
    assert validation.returncode == 0, validation.stderr
    manifest = json.loads((corpus / "manifest.json").read_text(encoding="utf-8"))
    assert manifest["validation_status"] == "PASS"
    actual = manifest["actual"]
    assert actual["preparation"]["ready_versions"] == {
        host: 4 for host in PRINCIPALS
    }
    hosts = actual["hybrid"]["hosts"]
    a, b, c = (hosts[host] for host in PRINCIPALS)
    assert a["decision"] == "Accept" and a["version_after"] == 5
    assert a["baseline_after"]["average_duration_seconds"] > (
        a["baseline_before"]["average_duration_seconds"]
    )
    assert b["decision"] == "Accept" and b["version_after"] == 5
    assert b["baseline_after"] == b["baseline_before"]
    assert c["decision"] == "Reject" and c["version_after"] == 4
    assert "SEVERE_BASELINE_DEVIATION" in c["reason_codes"]
    assert any(item["detection_source"] == "adaptive_baseline" and item["kind"] == "BASELINE_SEVERE_DEVIATION" for item in actual["hybrid"]["high_findings"])
    assert c["baseline_after"] == c["baseline_before"]
    assert actual["hybrid"]["high_ml_flow_count"] >= 1
    assert {"R1", "R2"} <= set(actual["hybrid"]["matched_rule_ids"])
    assert all(item["decision"] == "Reject" and "RULE_HIGH_EVIDENCE" in item["reason_codes"] and item["rule_veto_effect"] == "applied" for item in actual["hybrid"]["rule_affected_hosts"].values())
    assert set(actual["hybrid"]["rule_affected_hosts"]) == {"203.0.113.40", "203.0.113.41", "203.0.113.50"}
    assert actual["telemetry"]["v1"]["protected_count"] == (
        actual["hybrid"]["high_ml_flow_count"]
    )
    assert actual["telemetry"]["v2"]["protected_count"] == (
        actual["hybrid"]["eligible_high_finding_count"]
    )
    for version in ("v1", "v2"):
        assert actual["telemetry"][version]["verified"] is True
        assert actual["telemetry"][version]["tamper_rejected"] is True
    assert len(list(corpus.glob("protected-telemetry*.json"))) == 0



