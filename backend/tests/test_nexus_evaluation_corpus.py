"""Contract checks for the separately generated, synthetic NEXUS evaluation corpus."""

from __future__ import annotations

import hashlib
import json
import subprocess
import sys
from pathlib import Path

from app.anomaly_detection import detect_flows, train_detector
from app.hybrid_rules import evaluate_rules
from app.pcap_analysis import analyze_pcap

GENERATOR = Path("/app/scripts/generate_nexus_evaluation_corpus.py")
TRAINING = Path("/app/fixtures/phase4-normal-training.pcap")
EXPECTED_FILES = {
    "normal/normal-tcp.pcap", "normal/normal-udp.pcap",
    "normal/normal-mixed.pcap",
    "anomalies/unusual-short-flows.pcap",
    "anomalies/unusual-packet-rate.pcap",
    "anomalies/unusual-flow-volume.pcap",
    "anomalies/mixed-normal-anomalous.pcap",
    "security-rules/port-sweep-match.pcap",
    "security-rules/port-sweep-nonmatch.pcap",
    "security-rules/port-sweep-above.pcap",
    "security-rules/reconnaissance-match.pcap",
    "security-rules/reconnaissance-nonmatch.pcap",
    "security-rules/reconnaissance-above.pcap",
    "security-rules/sparse-evidence.pcap",
    "security-rules/combined-rule-evidence.pcap",
    *(f"adaptive/adaptive-{index:02d}.pcap" for index in range(14)),
}


def _generate(directory: Path) -> dict[str, object]:
    result = subprocess.run(
        [sys.executable, str(GENERATOR), str(directory)],
        capture_output=True, text=True, check=False,
    )
    assert result.returncode == 0, result.stderr
    return json.loads((directory / "manifest.json").read_text(encoding="utf-8"))


def test_help_is_safe_and_does_not_create_a_help_directory(tmp_path: Path) -> None:
    result = subprocess.run(
        [sys.executable, str(GENERATOR), "--help"],
        cwd=tmp_path, capture_output=True, text=True, check=False,
    )
    assert result.returncode == 0, result.stderr
    assert "usage:" in result.stdout.lower()
    assert not (tmp_path / "--help").exists()


def test_corpus_generation_is_deterministic_bounded_and_label_free(
    tmp_path: Path,
) -> None:
    first = _generate(tmp_path / "first")
    second = _generate(tmp_path / "second")
    assert first == second
    assert first["source"] == "REPLAYED DEMO TRAFFIC"
    entries = first["scenarios"]
    assert {entry["filename"] for entry in entries} == EXPECTED_FILES
    assert len(entries) == 29
    assert hashlib.sha256(TRAINING.read_bytes()).hexdigest() not in {
        entry["sha256"] for entry in entries
    }
    for entry in entries:
        path = tmp_path / "first" / entry["filename"]
        raw = path.read_bytes()
        assert raw == (tmp_path / "second" / entry["filename"]).read_bytes()
        assert path.stat().st_size <= 1_048_576
        assert hashlib.sha256(raw).hexdigest() == entry["sha256"]
        assert entry["independent_label"] in {
            "ordinary-intent", "unusual-intent", "rule-boundary", "adaptive-demo"
        }
        assert entry["scenario_id"].encode() not in raw
        assert b"REPLAYED DEMO TRAFFIC" not in raw
        assert entry["actual_model_outcome"] is None
        assert entry["validation_status"] == "NOT VERIFIED"
    occupied = tmp_path / "occupied"
    occupied.mkdir()
    (occupied / "keep.txt").write_text("owner", encoding="utf-8")
    refusal = subprocess.run(
        [sys.executable, str(GENERATOR), str(occupied)],
        capture_output=True, text=True, check=False,
    )
    assert refusal.returncode != 0
    assert (occupied / "keep.txt").read_text(encoding="utf-8") == "owner"


def test_real_parser_model_and_rules_on_selected_captures(tmp_path: Path) -> None:
    manifest = _generate(tmp_path / "corpus")
    by_name = {entry["scenario_id"]: entry for entry in manifest["scenarios"]}
    detector = train_detector(analyze_pcap(TRAINING).flows)
    assert detector.training_flow_count == 48
    assert detector.model_threshold == 0.636672
    for entry in manifest["scenarios"]:
        parsed = analyze_pcap(tmp_path / "corpus" / entry["filename"])
        assert parsed.packet_count == entry["packet_count"]
        assert len(parsed.flows) == entry["flow_count"]
        assert parsed.packet_count <= 2_000
        assert {flow.protocol for flow in parsed.flows} == set(
            entry["protocol_distribution"]
        )
        assert len(detect_flows(detector, parsed.flows)) == len(parsed.flows)
    mixed = analyze_pcap(
        tmp_path / "corpus" / by_name["mixed-normal-anomalous"]["filename"]
    )
    risks = {item.risk_level for item in detect_flows(detector, mixed.flows)}
    assert {"High", "Low"} <= risks
    expected_rules = {
        "port-sweep-match": ("R1", "Match", 60),
        "port-sweep-nonmatch": ("R1", "NoPatternMatchedInObservedMetadata", 0),
        "port-sweep-above": ("R1", "Match", 65),
        "reconnaissance-match": ("R2", "Match", 60),
        "reconnaissance-nonmatch": (
            "R2", "NoPatternMatchedInObservedMetadata", 0
        ),
        "reconnaissance-above": ("R2", "Match", 65),
        "sparse-evidence": ("R1", "Unknown", None),
    }
    for scenario, (rule, status, strength) in expected_rules.items():
        parsed = analyze_pcap(
            tmp_path / "corpus" / by_name[scenario]["filename"]
        )
        assessments = [
            item for item in evaluate_rules(parsed) if item["rule_id"] == rule
        ]
        assert any(
            item["status"] == status
            and item["rule_evidence_strength"] == strength
            for item in assessments
        ), (scenario, assessments)
    combined = analyze_pcap(
        tmp_path / "corpus" / by_name["combined-rule-evidence"]["filename"]
    )
    assert {item["rule_id"] for item in evaluate_rules(combined)
            if item["status"] == "Match"} == {"R1", "R2"}


def test_validator_records_actual_results_and_isolated_api_transitions(
    tmp_path: Path,
) -> None:
    import csv
    corpus = tmp_path / "corpus"
    _generate(corpus)
    result = subprocess.run(
        [sys.executable, "/app/scripts/validate_nexus_evaluation_corpus.py",
         str(corpus), "--write-results"],
        capture_output=True, text=True, check=False,
    )
    assert result.returncode == 0, result.stderr
    manifest = json.loads((corpus / "manifest.json").read_text(encoding="utf-8"))
    entries = manifest["scenarios"]
    assert len(entries) == 29
    assert all(entry["actual_model_outcome"] is not None for entry in entries)
    assert all(entry["actual_rule_outcome"] is not None for entry in entries)
    assert all(entry["validation_status"] != "NOT VERIFIED" for entry in entries)
    assert any(
        entry["actual_model_outcome"]["high_flows"] > 0
        and entry["actual_model_outcome"]["low_flows"] > 0
        for entry in entries if entry["filename"].startswith("anomalies/")
    )
    assert manifest["adaptive_duplicate_check"]["same_analysis_id_idempotent"]
    assert manifest["adaptive_duplicate_check"]["new_analysis_same_bytes_held"]
    adaptive = [entry for entry in entries
                if entry["filename"].startswith("adaptive/")]
    assert [entry["actual_baseline_transition"]["hosts"][0]["version_after"]
            for entry in adaptive] == [0, 1, 2, 3, 4, 5, 6, 7, 8, 8, 8, 9, 9, 9]
    assert adaptive[10]["actual_baseline_transition"]["hosts"][0]["decision"] == "Hold"
    assert adaptive[12]["actual_baseline_transition"]["hosts"][0]["decision"] == "Reject"
    assert adaptive[13]["actual_baseline_transition"]["hosts"][0]["decision"] == "Reject"
    with (corpus / "expected-vs-actual.csv").open(
        newline="", encoding="utf-8"
    ) as handle:
        rows = list(csv.DictReader(handle))
    assert len(rows) == 29
    assert all(row["actual_high_flows"] for row in rows)
