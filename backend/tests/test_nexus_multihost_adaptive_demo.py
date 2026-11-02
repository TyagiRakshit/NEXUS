"""Focused multi-host synthetic PCAP and host-specific admission contract."""

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

GENERATOR = Path("/app/scripts/generate_nexus_multihost_adaptive_demo.py")
VALIDATOR = Path("/app/scripts/validate_nexus_multihost_adaptive_demo.py")
TRAINING = Path("/app/fixtures/phase4-normal-training.pcap")
PRINCIPALS = ("192.0.2.10", "198.51.100.20", "203.0.113.30")


def _generate(directory: Path) -> dict[str, object]:
    result = subprocess.run(
        [sys.executable, str(GENERATOR), str(directory)],
        capture_output=True, text=True, check=False,
    )
    assert result.returncode == 0, result.stderr
    return json.loads((directory / "manifest.json").read_text(encoding="utf-8"))


def test_safe_help_and_deterministic_seven_capture_sequence(tmp_path: Path) -> None:
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
    assert first["principal_hosts"] == list(PRINCIPALS)
    assert len(first["captures"]) == 7
    assert [item["filename"] for item in first["captures"]] == [
        f"adaptive-{index:02d}.pcap" for index in range(7)
    ]
    assert [item["presentation_phase"] for item in first["captures"]] == (
        ["preparation"] * 5 + ["live"] * 2
    )
    for item in first["captures"]:
        left = (tmp_path / "first" / item["filename"]).read_bytes()
        right = (tmp_path / "second" / item["filename"]).read_bytes()
        assert left == right
        assert hashlib.sha256(left).hexdigest() == item["sha256"]
        assert len(left) <= 1_048_576
        assert item["packet_count"] <= 2_000
        assert item["scenario_id"].encode() not in left
        assert b"REPLAYED DEMO TRAFFIC" not in left
    marker = tmp_path / "occupied"
    marker.mkdir()
    (marker / "keep.txt").write_text("owner", encoding="utf-8")
    refused = subprocess.run(
        [sys.executable, str(GENERATOR), str(marker)],
        capture_output=True, text=True, check=False,
    )
    assert refused.returncode != 0
    assert (marker / "keep.txt").read_text(encoding="utf-8") == "owner"


def test_real_parser_has_distinct_principal_features_and_no_high_rules(
    tmp_path: Path,
) -> None:
    manifest = _generate(tmp_path / "corpus")
    detector = train_detector(analyze_pcap(TRAINING).flows)
    seen_host_vectors = []
    for index, item in enumerate(manifest["captures"]):
        parsed = analyze_pcap(tmp_path / "corpus" / item["filename"])
        assert parsed.packet_count == item["packet_count"]
        assert len(parsed.flows) == item["flow_count"]
        assert classify_capture_window(
            parsed.capture_first_timestamp, parsed.capture_last_timestamp
        ).reason_code is None
        assert int(parsed.capture_first_timestamp // 60) == 120 + index
        assert int(parsed.capture_last_timestamp // 60) == 120 + index
        features = build_adaptive_host_profiles(parsed.flows)
        assert all(host in features for host in PRINCIPALS)
        assert all(features[host].observed_flow_count >= 4 for host in PRINCIPALS)
        assert features[PRINCIPALS[0]] != features[PRINCIPALS[1]]
        assert features[PRINCIPALS[1]] != features[PRINCIPALS[2]]
        assert all(result.risk_level == "Low"
                   for result in detect_flows(detector, parsed.flows))
        assert not any(item["status"] == "Match"
                       for item in evaluate_rules(parsed))
        seen_host_vectors.append(features)
    assert seen_host_vectors[6][PRINCIPALS[2]].observed_flow_count == 8
    assert seen_host_vectors[6][PRINCIPALS[0]].observed_flow_count == 4
    assert seen_host_vectors[6][PRINCIPALS[1]].observed_flow_count == 4
    assert (seen_host_vectors[5][PRINCIPALS[0]].average_duration_seconds
            > seen_host_vectors[4][PRINCIPALS[0]].average_duration_seconds)
    assert (seen_host_vectors[6][PRINCIPALS[0]].average_duration_seconds
            > seen_host_vectors[5][PRINCIPALS[0]].average_duration_seconds)


def test_legacy_and_hybrid_isolated_api_runs_prove_host_independence(
    tmp_path: Path,
) -> None:
    import csv
    directory = tmp_path / "corpus"
    _generate(directory)
    validated = subprocess.run(
        [sys.executable, str(VALIDATOR), str(directory), "--write-results"],
        capture_output=True, text=True, check=False,
    )
    assert validated.returncode == 0, validated.stderr
    manifest = json.loads((directory / "manifest.json").read_text(encoding="utf-8"))
    assert manifest["validation_status"] == "PASS"
    captures = manifest["captures"]
    for mode in ("legacy", "hybrid"):
        results = [item[f"actual_{mode}"] for item in captures]
        a4, a5, a6 = [
            results[index]["hosts"][PRINCIPALS[0]] for index in (4, 5, 6)
        ]
        b4, b5, b6 = [
            results[index]["hosts"][PRINCIPALS[1]] for index in (4, 5, 6)
        ]
        c5, c6 = [results[index]["hosts"][PRINCIPALS[2]]
                  for index in (5, 6)]
        assert a4["readiness_after"] == "ready"
        assert all(results[index]["hosts"][host]["version_after"] == index
                   for index in range(5) for host in PRINCIPALS)
        assert a5["decision"] == a6["decision"] == "Accept"
        assert (a4["baseline_after"]["average_duration_seconds"]
                < a5["baseline_after"]["average_duration_seconds"]
                < a6["baseline_after"]["average_duration_seconds"])
        assert b4["baseline_after"] == b5["baseline_after"] == b6["baseline_after"]
        assert c6["decision"] == "Reject"
        assert "SEVERE_BASELINE_DEVIATION" in c6["reason_codes"]
        assert c6["baseline_before"] == c6["baseline_after"] == c5["baseline_after"]
        assert c6["version_after"] == c5["version_after"] == 5
        assert a6["version_after"] == b6["version_after"] == 6
        assert all(not item["high_rule_matches"] for item in results)
        histories = manifest[f"{mode}_histories"]
        assert all(histories[host]["host_ip"] == host for host in PRINCIPALS)
        assert histories[PRINCIPALS[0]]["current_baseline"] != (
            histories[PRINCIPALS[1]]["current_baseline"])
        assert histories[PRINCIPALS[2]]["current_version"] == 5
    with (directory / "expected-vs-actual.csv").open(
        newline="", encoding="utf-8"
    ) as handle:
        assert len(list(csv.DictReader(handle))) == 7
