"""Validate a generated NEXUS corpus against the real parser, model, rules and APIs."""

from __future__ import annotations

import argparse
import csv
import hashlib
import importlib
import json
import os
import struct
import tempfile
from collections import Counter
from pathlib import Path

import anyio
import httpx

from app.adaptive_baseline import AdaptiveBaselineStore, ScoredObservationRegistry
from app.anomaly_detection import (
    FEATURE_NAMES, detect_flows, train_detector,
)
from app.hybrid_evaluation import HybridEvaluationCoordinator
from app.hybrid_rules import evaluate_rules
from app.pcap_analysis import analyze_pcap
from app.secure_telemetry import SecureTelemetryStore

TRAINING = Path("/app/fixtures/phase4-normal-training.pcap")
MAX_BYTES = 1_048_576
MAX_PACKETS = 2_000


def _header_only_lengths(path: Path) -> list[int]:
    raw = path.read_bytes()
    if len(raw) < 24 or raw[:4] != b"\xd4\xc3\xb2\xa1":
        raise ValueError(f"Not a generated little-endian PCAP: {path}")
    offset, lengths = 24, []
    while offset < len(raw):
        if offset + 16 > len(raw):
            raise ValueError(f"Truncated packet header: {path}")
        _, _, captured, original = struct.unpack_from("<IIII", raw, offset)
        offset += 16
        frame = raw[offset:offset + captured]
        offset += captured
        if captured != original or len(frame) != captured or len(frame) < 42:
            raise ValueError(f"Invalid frame: {path}")
        if frame[12:14] != b"\x08\x00" or frame[14] >> 4 != 4:
            raise ValueError(f"Unexpected link or IP version: {path}")
        ip_header_bytes = (frame[14] & 15) * 4
        ip_bytes = struct.unpack_from("!H", frame, 16)[0]
        if len(frame) != 14 + ip_bytes:
            raise ValueError(f"Unexpected trailing packet data: {path}")
        transport = 14 + ip_header_bytes
        protocol = frame[23]
        if protocol == 6:
            transport_bytes = (frame[transport + 12] >> 4) * 4
        elif protocol == 17:
            transport_bytes = struct.unpack_from("!H", frame, transport + 4)[0]
        elif protocol == 1:
            transport_bytes = 8
        else:
            raise ValueError(f"Unexpected transport protocol: {path}")
        if ip_bytes != ip_header_bytes + transport_bytes:
            raise ValueError(f"Packet contains transport payload: {path}")
        lengths.append(len(frame))
    if offset != len(raw):
        raise ValueError(f"Trailing PCAP bytes: {path}")
    return lengths


def _verify_scenario(
    directory: Path, entry: dict[str, object], detector: object,
) -> tuple[object, bool, bool | None]:
    path = directory / str(entry["filename"])
    raw = path.read_bytes()
    if len(raw) > MAX_BYTES or hashlib.sha256(raw).hexdigest() != entry["sha256"]:
        raise ValueError(f"Size/hash mismatch: {entry['filename']}")
    frame_lengths = _header_only_lengths(path)
    parsed = analyze_pcap(path)
    protocols = dict(sorted(Counter(flow.protocol for flow in parsed.flows).items()))
    counts_match = (
        parsed.packet_count == entry["packet_count"]
        and len(parsed.flows) == entry["flow_count"]
        and parsed.packet_count == len(frame_lengths)
        and parsed.packet_count <= MAX_PACKETS
        and protocols == entry["protocol_distribution"]
    )
    detected = detect_flows(detector, parsed.flows)
    actual_rules = evaluate_rules(parsed)
    expected_rules = entry["expected_rule_outcome"]
    rules_match = all(any(
        item["rule_id"] == rule
        and item["status"] == expected[0]
        and item["rule_evidence_strength"] == expected[1]
        for item in actual_rules
    ) for rule, expected in expected_rules.items())
    high = sum(item.risk_level == "High" for item in detected)
    low = sum(item.risk_level == "Low" for item in detected)
    entry["actual_model_outcome"] = {
        "threshold": detector.model_threshold,
        "high_flows": high,
        "low_flows": low,
        "medium_flows": sum(item.risk_level == "Medium" for item in detected),
        "flagged_flows": sum(item.alert_flagged for item in detected),
        "flows": [{
            "flow_index": index,
            "protocol": item.flow.protocol,
            "source_ip": item.flow.source_ip,
            "source_port": item.flow.source_port,
            "destination_ip": item.flow.destination_ip,
            "destination_port": item.flow.destination_port,
            "packet_count": item.flow.packet_count,
            "byte_count": item.flow.byte_count,
            "duration_seconds": item.flow.duration_seconds,
            "packets_per_second": item.flow.packets_per_second,
            "bytes_per_second": item.flow.bytes_per_second,
            "anomaly_score": item.anomaly_score,
            "risk_level": item.risk_level,
            "alert_flagged": item.alert_flagged,
            "explanations": list(item.explanations),
        } for index, item in enumerate(detected)],
    }
    entry["actual_rule_outcome"] = [{
        "rule_id": item["rule_id"],
        "status": item["status"],
        "severity": "High" if item["status"] == "Match" else None,
        "rule_evidence_strength": item["rule_evidence_strength"],
        "subject_host_ips": item["subject_host_ips"],
        "affected_host_ips": item["affected_host_ips"],
        "flow_indices": item["flow_indices"],
        "evidence": item["evidence"],
    } for item in actual_rules]
    entry["actual_observation"] = {
        "packet_count": parsed.packet_count,
        "flow_count": len(parsed.flows),
        "protocol_distribution": protocols,
        "capture_start": parsed.capture_first_timestamp,
        "capture_end": parsed.capture_last_timestamp,
        "host_ips": sorted({
            ip for flow in parsed.flows
            for ip in (flow.source_ip, flow.destination_ip)
        }),
        "frame_lengths": sorted(set(frame_lengths)),
    }
    if entry["scenario_id"] == "mixed-normal-anomalous":
        functional = counts_match and rules_match and high > 0 and low > 0
    else:
        functional = counts_match and rules_match
    label = entry["independent_label"]
    label_agreement = (
        high == 0 if label == "ordinary-intent" else
        high > 0 if label == "unusual-intent" else None
    )
    return parsed, functional, label_agreement


def _fresh_api_state(main: object, directory: Path) -> None:
    main.scored_observation_registry = ScoredObservationRegistry()
    main.adaptive_baseline_store = AdaptiveBaselineStore()
    main.secure_telemetry_store = SecureTelemetryStore(
        key_directory=directory / "keys",
        evidence_directory=directory / "evidence",
    )
    main.hybrid_coordinator = HybridEvaluationCoordinator(
        main.adaptive_baseline_store,
        candidate_registrar=main.secure_telemetry_store.register_hybrid_candidate,
        candidate_unregistrar=main.secure_telemetry_store.unregister_hybrid_candidate,
        candidate_finalizer=main.secure_telemetry_store.finalize_hybrid_candidate,
    )


async def _upload(client: httpx.AsyncClient, path: Path) -> dict[str, object]:
    response = await client.post(
        "/api/v1/demo/upload/analyze",
        files={"file": (path.name, path.read_bytes(), "application/vnd.tcpdump.pcap")},
    )
    if response.status_code != 200:
        raise ValueError(f"Upload failed for {path.name}: {response.status_code} {response.text}")
    return response.json()


async def _api_checks(
    directory: Path, entries: list[dict[str, object]],
) -> tuple[dict[str, bool], dict[str, object]]:
    main = importlib.import_module("app.main")
    os.environ["NEXUS_DETECTION_TRAINING_PCAP_PATH"] = str(TRAINING)
    by_name = {entry["scenario_id"]: entry for entry in entries}
    with tempfile.TemporaryDirectory(prefix="nexus-corpus-") as temporary:
        isolated = Path(temporary)
        _fresh_api_state(main, isolated)
        transport = httpx.ASGITransport(app=main.app)
        async with httpx.AsyncClient(
            transport=transport, base_url="http://isolated.invalid",
        ) as client:
            duplicate_checks = {
                "same_analysis_id_idempotent": False,
                "new_analysis_same_bytes_held": False,
            }
            for index in range(14):
                entry = by_name[f"adaptive-{index:02d}"]
                upload = await _upload(client, directory / str(entry["filename"]))
                actual_flows = entry["actual_model_outcome"]["flows"]
                if [item["anomaly_score"] for item in upload["results"]] != [
                    item["anomaly_score"] for item in actual_flows
                ]:
                    raise ValueError(f"API model scores differ from direct model: {entry['scenario_id']}")
                response = await client.post(
                    "/api/v1/demo/baselines/evaluate",
                    json={"analysis_id": upload["analysis_id"]},
                )
                if response.status_code != 200:
                    raise ValueError(f"Adaptive API failed: {response.status_code} {response.text}")
                result = response.json()
                entry["actual_baseline_transition"] = {
                    "capture_window_start": result["capture_window_start"],
                    "capture_window_end": result["capture_window_end"],
                    "capture_fingerprint_status": result["capture_fingerprint_status"],
                    "hosts": [{
                        "host_ip": host["host_ip"],
                        "decision": host["decision"],
                        "reason_codes": host["reason_codes"],
                        "readiness_after": host["readiness_after"],
                        "version_before": host["version_before"],
                        "version_after": host["version_after"],
                        "probation_count": host["probation_count"],
                        "finding_count": len(host["findings"]),
                        "baseline_before": host["baseline_before"],
                        "baseline_after": host["baseline_after"],
                    } for host in result["hosts"]],
                }
                expected = entry["expected_baseline_transition"]
                entry["functional_expectation_pass"] = (
                    entry["functional_expectation_pass"]
                    and result["capture_window_start"] == entry["capture_window_start"]
                    and result["capture_window_end"] == entry["capture_window_end"]
                    and all(
                        host["decision"] == expected["decision"]
                        and host["version_after"] == expected["version"]
                        and host["readiness_after"] == expected["readiness"]
                        and expected["reason"] in host["reason_codes"]
                        for host in result["hosts"]
                    )
                )
                if index == 1:
                    repeat = await client.post(
                        "/api/v1/demo/baselines/evaluate",
                        json={"analysis_id": upload["analysis_id"]},
                    )
                    duplicate_checks["same_analysis_id_idempotent"] = (
                        repeat.status_code == 200 and repeat.json() == result
                    )
                    duplicated = await _upload(
                        client, directory / str(entry["filename"])
                    )
                    duplicate = await client.post(
                        "/api/v1/demo/baselines/evaluate",
                        json={"analysis_id": duplicated["analysis_id"]},
                    )
                    duplicate_checks["new_analysis_same_bytes_held"] = (
                        duplicate.status_code == 200
                        and duplicate.json()["capture_fingerprint_status"] == "duplicate"
                        and all(
                            host["decision"] == "Hold"
                            and "DUPLICATE_CAPTURE" in host["reason_codes"]
                            and host["version_after"] == 1
                            for host in duplicate.json()["hosts"]
                        )
                    )
        hybrid_checks: dict[str, object] = {}
        for scenario in (
            "port-sweep-match", "reconnaissance-match",
            "combined-rule-evidence",
        ):
            _fresh_api_state(main, isolated)
            transport = httpx.ASGITransport(app=main.app)
            async with httpx.AsyncClient(
                transport=transport, base_url="http://isolated.invalid",
            ) as client:
                upload = await _upload(
                    client, directory / str(by_name[scenario]["filename"])
                )
                response = await client.post(
                    "/api/v1/demo/hybrid/evaluate",
                    json={"analysis_id": upload["analysis_id"]},
                )
                if response.status_code != 200:
                    raise ValueError(f"Hybrid API failed: {scenario} {response.status_code} {response.text}")
                result = response.json()
                matched = sorted({
                    item["rule_id"] for item in result["rule_assessments"]
                    if item["status"] == "Match"
                })
                findings = [
                    item for item in result["findings"]
                    if item["detection_source"] == "security_rule"
                ]
                hybrid_checks[scenario] = {
                    "matched_rule_ids": matched,
                    "security_rule_finding_count": len(findings),
                    "veto_host_ips": sorted({
                        host["host_ip"] for host in result["hosts"]
                        if host["rule_veto_effect"] == "applied"
                    }),
                    "high_ml_flow_count": sum(
                        item["risk_level"] == "High"
                        for item in result["flow_results"]
                    ),
                }
                if not matched or not findings:
                    raise ValueError(f"Hybrid API did not expose rule findings: {scenario}")
    return duplicate_checks, hybrid_checks


def validate(directory: Path, *, write_results: bool) -> dict[str, object]:
    manifest_path = directory / "manifest.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    if manifest["schema_version"] != "nexus.evaluation-corpus.v1":
        raise ValueError("Unexpected corpus manifest schema")
    entries = manifest["scenarios"]
    training_raw = TRAINING.read_bytes()
    training_hash = hashlib.sha256(training_raw).hexdigest()
    if training_hash in {item["sha256"] for item in entries}:
        raise ValueError("Evaluation capture equals the fixed training fixture")
    training = analyze_pcap(TRAINING)
    detector = train_detector(training.flows)
    manifest["model_reference"] = {
        "training_fixture_sha256": training_hash,
        "training_flow_count": detector.training_flow_count,
        "feature_names": list(FEATURE_NAMES),
        "model_threshold": detector.model_threshold,
        "parameters": detector.parameters,
    }
    all_frame_lengths: set[int] = set()
    for entry in entries:
        _, functional, label_agreement = _verify_scenario(
            directory, entry, detector,
        )
        entry["functional_expectation_pass"] = functional
        entry["label_prediction_agreement"] = label_agreement
        all_frame_lengths.update(entry["actual_observation"]["frame_lengths"])
    duplicate, hybrid = anyio.run(_api_checks, directory, entries)
    manifest["adaptive_duplicate_check"] = duplicate
    manifest["hybrid_api_verification"] = hybrid
    manifest["observed_frame_lengths"] = sorted(all_frame_lengths)
    for entry in entries:
        functional = entry["functional_expectation_pass"]
        label = entry["label_prediction_agreement"]
        entry["validation_status"] = (
            "FAIL" if not functional else
            "DISCREPANCY" if label is False else "PASS"
        )
    if write_results:
        manifest_path.write_text(
            json.dumps(manifest, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
        with (directory / "expected-vs-actual.csv").open(
            "w", newline="", encoding="utf-8",
        ) as handle:
            writer = csv.DictWriter(handle, fieldnames=[
                "scenario_id", "filename", "independent_label", "intended_behavior",
                "expected_rule_outcome", "expected_baseline_transition",
                "actual_high_flows", "actual_low_flows", "actual_rule_matches",
                "actual_baseline_transition", "functional_expectation_pass",
                "label_prediction_agreement", "validation_status",
            ])
            writer.writeheader()
            for entry in entries:
                model = entry["actual_model_outcome"]
                matches = [
                    item["rule_id"] for item in entry["actual_rule_outcome"]
                    if item["status"] == "Match"
                ]
                writer.writerow({
                    "scenario_id": entry["scenario_id"],
                    "filename": entry["filename"],
                    "independent_label": entry["independent_label"],
                    "intended_behavior": entry["intended_behavior"],
                    "expected_rule_outcome": json.dumps(entry["expected_rule_outcome"], sort_keys=True),
                    "expected_baseline_transition": json.dumps(entry["expected_baseline_transition"], sort_keys=True),
                    "actual_high_flows": model["high_flows"],
                    "actual_low_flows": model["low_flows"],
                    "actual_rule_matches": ",".join(sorted(set(matches))),
                    "actual_baseline_transition": json.dumps(entry["actual_baseline_transition"], sort_keys=True),
                    "functional_expectation_pass": entry["functional_expectation_pass"],
                    "label_prediction_agreement": entry["label_prediction_agreement"],
                    "validation_status": entry["validation_status"],
                })
    return manifest


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Validate generated offline NEXUS PCAPs with the real parser, fixed model, rules and fresh APIs."
    )
    parser.add_argument("corpus_directory", type=Path)
    parser.add_argument(
        "--write-results", action="store_true",
        help="Update only this generated corpus's manifest and CSV with observed results.",
    )
    args = parser.parse_args()
    result = validate(args.corpus_directory, write_results=args.write_results)
    counts = Counter(item["validation_status"] for item in result["scenarios"])
    print(json.dumps({
        "scenario_count": len(result["scenarios"]),
        "validation_status_counts": dict(sorted(counts.items())),
        "model_threshold": result["model_reference"]["model_threshold"],
        "frame_lengths": result["observed_frame_lengths"],
        "adaptive_duplicate_check": result["adaptive_duplicate_check"],
        "hybrid_api_verification": result["hybrid_api_verification"],
    }, sort_keys=True))


if __name__ == "__main__":
    main()
