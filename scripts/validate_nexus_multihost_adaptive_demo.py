"""Record real Legacy and Hybrid host-specific results for the separate PCAP demo."""

from __future__ import annotations

import argparse
import csv
import hashlib
import importlib
import json
import os
import tempfile
from collections import Counter
from datetime import UTC, datetime
from pathlib import Path

import anyio
import httpx

from app.adaptive_baseline import (
    AdaptiveBaselineStore, ScoredObservationRegistry,
    build_adaptive_host_profiles, classify_capture_window,
)
from app.anomaly_detection import detect_flows, train_detector
from app.hybrid_evaluation import HybridEvaluationCoordinator
from app.hybrid_rules import evaluate_rules
from app.pcap_analysis import analyze_pcap
from app.secure_telemetry import SecureTelemetryStore

from validate_nexus_evaluation_corpus import TRAINING, _header_only_lengths

PRINCIPALS = ("192.0.2.10", "198.51.100.20", "203.0.113.30")


def _iso(seconds: float) -> str:
    return datetime.fromtimestamp(seconds, UTC).isoformat().replace("+00:00", "Z")


def _fresh_state(main: object, temporary: Path) -> None:
    main.scored_observation_registry = ScoredObservationRegistry()
    main.adaptive_baseline_store = AdaptiveBaselineStore()
    main.secure_telemetry_store = SecureTelemetryStore(
        key_directory=temporary / "keys",
        evidence_directory=temporary / "evidence",
    )
    main.hybrid_coordinator = HybridEvaluationCoordinator(
        main.adaptive_baseline_store,
        candidate_registrar=main.secure_telemetry_store.register_hybrid_candidate,
        candidate_unregistrar=main.secure_telemetry_store.unregister_hybrid_candidate,
        candidate_finalizer=main.secure_telemetry_store.finalize_hybrid_candidate,
    )


def _host_fields(host: dict[str, object]) -> dict[str, object]:
    return {
        key: host[key] for key in (
            "host_ip", "decision", "reason_codes", "readiness_before",
            "readiness_after", "coverage_confidence", "version_before",
            "version_after", "current_features", "baseline_before",
            "baseline_after", "feature_deviations", "incident_flow_count",
            "high_flow_count", "probation_count",
        )
    } | {
        "finding_kinds": [item["kind"] for item in host["findings"]],
        "rule_veto_effect": host.get("rule_veto_effect", "none"),
    }


async def _mode_run(
    main: object, directory: Path, captures: list[dict[str, object]],
    mode: str, temporary: Path,
) -> tuple[list[dict[str, object]], dict[str, object]]:
    _fresh_state(main, temporary)
    transport = httpx.ASGITransport(app=main.app)
    results = []
    async with httpx.AsyncClient(
        transport=transport, base_url="http://isolated.invalid",
    ) as client:
        for item in captures:
            capture = directory / item["filename"]
            upload = await client.post(
                "/api/v1/demo/upload/analyze",
                files={"file": (capture.name, capture.read_bytes(),
                                "application/vnd.tcpdump.pcap")},
            )
            if upload.status_code != 200:
                raise ValueError(f"{mode} upload {capture.name}: {upload.status_code} {upload.text}")
            upload_body = upload.json()
            if upload_body["packet_count"] != item["packet_count"] or (
                upload_body["flow_count"] != item["flow_count"]
            ):
                raise ValueError(f"{mode} API parser counts differ: {capture.name}")
            if [result["anomaly_score"] for result in upload_body["results"]] != [
                result["anomaly_score"] for result in item["actual_model"]["flows"]
            ]:
                raise ValueError(f"{mode} API ML scores differ: {capture.name}")
            route = (
                "/api/v1/demo/hybrid/evaluate" if mode == "hybrid"
                else "/api/v1/demo/baselines/evaluate"
            )
            response = await client.post(
                route, json={"analysis_id": upload_body["analysis_id"]},
            )
            if response.status_code != 200:
                raise ValueError(f"{mode} evaluate {capture.name}: {response.status_code} {response.text}")
            body = response.json()
            hosts = {host["host_ip"]: _host_fields(host) for host in body["hosts"]}
            if not all(host in hosts for host in PRINCIPALS):
                raise ValueError(f"Principal host absent: {capture.name}")
            assessments = body.get("rule_assessments", [])
            matched = sorted({
                assessment["rule_id"] for assessment in assessments
                if assessment["status"] == "Match"
            })
            results.append({
                "capture_window_start": body["capture_window_start"],
                "capture_window_end": body["capture_window_end"],
                "model_threshold": body["model_threshold"],
                "high_ml_flow_count": sum(
                    result["risk_level"] == "High"
                    for result in upload_body["results"]
                ),
                "high_rule_matches": matched,
                "rule_assessments": [{
                    "rule_id": assessment["rule_id"],
                    "status": assessment["status"],
                    "rule_evidence_strength": assessment["rule_evidence_strength"],
                    "subject_host_ips": assessment["subject_host_ips"],
                    "affected_host_ips": assessment["affected_host_ips"],
                    "flow_indices": assessment["flow_indices"],
                } for assessment in assessments],
                "hosts": {host: hosts[host] for host in PRINCIPALS},
            })
        histories: dict[str, object] = {}
        for host_ip in PRINCIPALS:
            response = await client.get(
                "/api/v1/demo/baselines/history",
                params={"host_ip": host_ip},
            )
            if response.status_code != 200:
                raise ValueError(f"{mode} history {host_ip}: {response.status_code} {response.text}")
            body = response.json()
            if body["host_ip"] != host_ip:
                raise ValueError(f"{mode} history returned wrong host")
            histories[host_ip] = {
                "host_ip": body["host_ip"],
                "readiness": body["readiness"],
                "current_version": body["current_version"],
                "current_baseline": body["current_baseline"],
                "decisions": [{
                    key: decision[key] for key in (
                        "window_start", "decision", "reason_codes",
                        "version_before", "version_after",
                    )
                } for decision in body["decisions"]],
                "snapshots": [{
                    key: snapshot[key] for key in (
                        "version", "window_start", "reason_code",
                        "features_before", "features_after",
                    )
                } for snapshot in body["snapshots"]],
            }
    return results, histories


def validate(directory: Path, *, write_results: bool) -> dict[str, object]:
    manifest_path = directory / "manifest.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    if manifest["schema_version"] != "nexus.multihost-adaptive-demo.v1":
        raise ValueError("Unexpected multi-host manifest schema")
    captures = manifest["captures"]
    if len(captures) != 7 or manifest["principal_hosts"] != list(PRINCIPALS):
        raise ValueError("Unexpected principal host or capture count")
    training_hash = hashlib.sha256(TRAINING.read_bytes()).hexdigest()
    training = analyze_pcap(TRAINING)
    detector = train_detector(training.flows)
    manifest["model_reference"] = {
        "training_sha256": training_hash,
        "training_flow_count": detector.training_flow_count,
        "model_threshold": detector.model_threshold,
        "parameters": detector.parameters,
    }
    for index, item in enumerate(captures):
        path = directory / item["filename"]
        if hashlib.sha256(path.read_bytes()).hexdigest() != item["sha256"]:
            raise ValueError(f"PCAP hash mismatch: {path}")
        if item["sha256"] == training_hash or path.stat().st_size > 1_048_576:
            raise ValueError(f"Training overlap or upload size exceeded: {path}")
        lengths = _header_only_lengths(path)
        parsed = analyze_pcap(path)
        window = classify_capture_window(
            parsed.capture_first_timestamp, parsed.capture_last_timestamp,
        )
        observed_protocols = dict(sorted(
            Counter(flow.protocol for flow in parsed.flows).items()
        ))
        if (
            parsed.packet_count != item["packet_count"]
            or len(parsed.flows) != item["flow_count"]
            or parsed.packet_count > 2_000
            or parsed.packet_count != len(lengths)
            or window.reason_code is not None
            or window.window_start != item["capture_window_start"]
            or window.window_end != item["capture_window_end"]
            or _iso(parsed.capture_first_timestamp) != item["capture_start"]
            or _iso(parsed.capture_last_timestamp) != item["capture_end"]
            or observed_protocols != item["protocol_distribution"]
        ):
            raise ValueError(f"Parser/window/metadata mismatch: {path}")
        features = build_adaptive_host_profiles(parsed.flows)
        if not all(host in features and features[host].observed_flow_count >= 4
                   for host in PRINCIPALS):
            raise ValueError(f"Principal host coverage missing: {path}")
        detected = detect_flows(detector, parsed.flows)
        rules = evaluate_rules(parsed)
        item["actual_model"] = {
            "threshold": detector.model_threshold,
            "high_flow_count": sum(x.risk_level == "High" for x in detected),
            "low_flow_count": sum(x.risk_level == "Low" for x in detected),
            "flows": [{
                "flow_index": number,
                "host_ips": [result.flow.source_ip, result.flow.destination_ip],
                "protocol": result.flow.protocol,
                "anomaly_score": result.anomaly_score,
                "risk_level": result.risk_level,
                "alert_flagged": result.alert_flagged,
                "explanations": list(result.explanations),
            } for number, result in enumerate(detected)],
        }
        item["actual_rule_summary"] = [{
            "rule_id": rule["rule_id"],
            "status": rule["status"],
            "rule_evidence_strength": rule["rule_evidence_strength"],
            "affected_host_ips": rule["affected_host_ips"],
            "flow_indices": rule["flow_indices"],
        } for rule in rules]
        item["actual_principal_features"] = {
            host: {
                "observed_flow_count": features[host].observed_flow_count,
                "average_bytes_per_flow": features[host].average_bytes_per_flow,
                "average_duration_seconds": features[host].average_duration_seconds,
                "average_packets_per_second": features[host].average_packets_per_second,
                "protocol_shares": features[host].protocol_shares,
            } for host in PRINCIPALS
        }
        item["actual_parser"] = {
            "packet_count": parsed.packet_count,
            "flow_count": len(parsed.flows),
            "protocol_distribution": observed_protocols,
            "capture_start": _iso(parsed.capture_first_timestamp),
            "capture_end": _iso(parsed.capture_last_timestamp),
            "frame_lengths": sorted(set(lengths)),
            "host_ips": sorted(features),
        }
        item["direct_checks_pass"] = (
            all(result.risk_level == "Low" for result in detected)
            and not any(rule["status"] == "Match" for rule in rules)
            and features[PRINCIPALS[0]] != features[PRINCIPALS[1]]
            and features[PRINCIPALS[1]] != features[PRINCIPALS[2]]
        )
    main = importlib.import_module("app.main")
    os.environ["NEXUS_DETECTION_TRAINING_PCAP_PATH"] = str(TRAINING)
    with tempfile.TemporaryDirectory(prefix="nexus-multihost-") as temporary:
        base = Path(temporary)
        for mode in ("legacy", "hybrid"):
            results, histories = anyio.run(
                _mode_run, main, directory, captures, mode, base / mode,
            )
            for item, result in zip(captures, results, strict=True):
                item[f"actual_{mode}"] = result
            manifest[f"{mode}_histories"] = histories
    for item in captures:
        expected = item["intended_host_outcome"]
        checks = [item["direct_checks_pass"]]
        for mode in ("legacy", "hybrid"):
            actual = item[f"actual_{mode}"]
            checks.extend([
                not actual["high_rule_matches"],
                actual["high_ml_flow_count"] == 0,
                actual["capture_window_start"] == item["capture_window_start"],
                actual["capture_window_end"] == item["capture_window_end"],
            ])
            for role, host_ip in zip(("A", "B", "C"), PRINCIPALS, strict=True):
                host = actual["hosts"][host_ip]
                intended = expected[role]
                checks.append(
                    host["decision"] == intended["decision"]
                    and intended["reason"] in host["reason_codes"]
                    and host["readiness_after"] == intended["readiness"]
                    and host["version_after"] == intended["version"]
                    and host["rule_veto_effect"] == "none"
                )
        item["validation_status"] = "PASS" if all(checks) else "DISCREPANCY"
    independence = {}
    for mode in ("legacy", "hybrid"):
        a = [item[f"actual_{mode}"]["hosts"][PRINCIPALS[0]] for item in captures]
        b = [item[f"actual_{mode}"]["hosts"][PRINCIPALS[1]] for item in captures]
        c = [item[f"actual_{mode}"]["hosts"][PRINCIPALS[2]] for item in captures]
        histories = manifest[f"{mode}_histories"]
        independence[mode] = {
            "different_initial_features": a[0]["current_features"] != b[0]["current_features"],
            "a_duration_observed": [host["current_features"]["average_duration_seconds"] for host in a],
            "a_duration_baseline_after": [
                None if host["baseline_after"] is None else host["baseline_after"]["average_duration_seconds"]
                for host in a
            ],
            "b_duration_baseline_after": [
                None if host["baseline_after"] is None else host["baseline_after"]["average_duration_seconds"]
                for host in b
            ],
            "c_flow_count_observed": [host["current_features"]["observed_flow_count"] for host in c],
            "c_final_rejected_without_update": (
                c[6]["decision"] == "Reject"
                and c[6]["baseline_before"] == c[6]["baseline_after"]
                and c[6]["version_after"] == c[5]["version_after"]
            ),
            "other_principals_independent_at_final": (
                a[6]["decision"] == b[6]["decision"] == "Accept"
                and a[6]["version_after"] == b[6]["version_after"] == 6
                and b[6]["baseline_after"] == b[5]["baseline_after"]
            ),
            "host_histories_distinct": (
                histories[PRINCIPALS[0]]["current_baseline"]
                != histories[PRINCIPALS[1]]["current_baseline"]
                and histories[PRINCIPALS[2]]["current_version"] == 5
                and all(histories[host]["host_ip"] == host for host in PRINCIPALS)
            ),
        }
        if not (
            independence[mode]["different_initial_features"]
            and independence[mode]["c_final_rejected_without_update"]
            and independence[mode]["other_principals_independent_at_final"]
            and independence[mode]["host_histories_distinct"]
            and a[4]["baseline_after"]["average_duration_seconds"]
            < a[5]["baseline_after"]["average_duration_seconds"]
            < a[6]["baseline_after"]["average_duration_seconds"]
            and b[4]["baseline_after"] == b[5]["baseline_after"] == b[6]["baseline_after"]
        ):
            raise ValueError(f"Host independence not demonstrated in {mode}")
    manifest["host_independence"] = independence
    manifest["validation_status"] = (
        "PASS" if all(item["validation_status"] == "PASS" for item in captures)
        else "DISCREPANCY"
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
                "capture_order", "filename", "presentation_phase",
                "intended_scenario", "expected_hosts",
                "actual_legacy", "actual_hybrid", "validation_status",
            ])
            writer.writeheader()
            for item in captures:
                writer.writerow({
                    "capture_order": item["capture_order"],
                    "filename": item["filename"],
                    "presentation_phase": item["presentation_phase"],
                    "intended_scenario": item["intended_scenario"],
                    "expected_hosts": json.dumps(item["intended_host_outcome"], sort_keys=True),
                    "actual_legacy": json.dumps(item["actual_legacy"]["hosts"], sort_keys=True),
                    "actual_hybrid": json.dumps(item["actual_hybrid"]["hosts"], sort_keys=True),
                    "validation_status": item["validation_status"],
                })
    return manifest


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Validate separate multi-host captures through real parser, fixed model and fresh Legacy/Hybrid APIs."
    )
    parser.add_argument("corpus_directory", type=Path)
    parser.add_argument("--write-results", action="store_true")
    args = parser.parse_args()
    manifest = validate(args.corpus_directory, write_results=args.write_results)
    print(json.dumps({
        "captures": len(manifest["captures"]),
        "validation_status": manifest["validation_status"],
        "host_independence": manifest["host_independence"],
        "legacy_decisions": [
            {host: item["actual_legacy"]["hosts"][host]["decision"] for host in PRINCIPALS}
            for item in manifest["captures"]
        ],
        "hybrid_decisions": [
            {host: item["actual_hybrid"]["hosts"][host]["decision"] for host in PRINCIPALS}
            for item in manifest["captures"]
        ],
    }, sort_keys=True))


if __name__ == "__main__":
    main()
