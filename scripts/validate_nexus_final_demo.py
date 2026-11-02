"""Validate the one-PCAP demo through real upload, Hybrid admission and v1/v2 APIs."""

from __future__ import annotations

import argparse
import csv
import hashlib
import importlib
import json
import os
import tempfile
from collections import Counter
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
from validate_nexus_multihost_adaptive_demo import _host_fields

PRINCIPALS = {
    "A": "192.0.2.10",
    "B": "198.51.100.20",
    "C": "203.0.113.30",
}
ROOT = Path(__file__).resolve().parents[1]


def _summary(item: dict[str, object]) -> dict[str, object]:
    return {
        "status_code": item["status_code"],
        "schema_version": item["schema_version"],
        "protected_count": item["protected_count"],
        "verified_count": item["verified_count"],
        "verified": item["verified"],
        "tamper_rejected": item["tamper_rejected"],
        "original_reverified": item["original_reverified"],
    }


async def _api_run(
    main: object, preparation: Path, final: Path, temporary: Path,
) -> dict[str, object]:
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
    prep_rows: list[dict[str, object]] = []
    transport = httpx.ASGITransport(app=main.app)
    async with httpx.AsyncClient(
        transport=transport, base_url="http://isolated.invalid",
    ) as client:
        async def upload_and_hybrid(path: Path) -> tuple[dict[str, object], dict[str, object]]:
            upload = await client.post(
                "/api/v1/demo/upload/analyze",
                files={"file": (path.name, path.read_bytes(),
                                "application/vnd.tcpdump.pcap")},
            )
            if upload.status_code != 200:
                raise ValueError(f"upload {path.name}: {upload.status_code} {upload.text}")
            body = upload.json()
            response = await client.post(
                "/api/v1/demo/hybrid/evaluate",
                json={"analysis_id": body["analysis_id"]},
            )
            if response.status_code != 200:
                raise ValueError(f"Hybrid {path.name}: {response.status_code} {response.text}")
            return body, response.json()

        for index in range(5):
            _, hybrid = await upload_and_hybrid(preparation / f"adaptive-{index:02d}.pcap")
            hosts = {item["host_ip"]: item for item in hybrid["hosts"]}
            prep_rows.append({
                "capture": f"adaptive-{index:02d}.pcap",
                "hosts": {
                    ip: {
                        "decision": hosts[ip]["decision"],
                        "reason_codes": hosts[ip]["reason_codes"],
                        "readiness": hosts[ip]["readiness_after"],
                        "version": hosts[ip]["version_after"],
                    } for ip in PRINCIPALS.values()
                },
            })
        ready = {
            ip: prep_rows[-1]["hosts"][ip]["version"]
            for ip in PRINCIPALS.values()
            if prep_rows[-1]["hosts"][ip]["readiness"] == "ready"
        }
        upload, hybrid = await upload_and_hybrid(final)
        analysis_id = upload["analysis_id"]
        host_results = {
            item["host_ip"]: _host_fields(item)
            for item in hybrid["hosts"]
            if item["host_ip"] in PRINCIPALS.values()
        }
        histories = {}
        for ip in PRINCIPALS.values():
            response = await client.get(
                "/api/v1/demo/baselines/history", params={"host_ip": ip},
            )
            if response.status_code != 200:
                raise ValueError(f"host history {ip}: {response.status_code} {response.text}")
            body = response.json()
            histories[ip] = {
                "host_ip": body["host_ip"],
                "current_version": body["current_version"],
                "readiness": body["readiness"],
                "current_baseline": body["current_baseline"],
                "decisions": body["decisions"],
            }

        async def protect_version(
            version: str, endpoint: str, expected_count: int,
        ) -> dict[str, object]:
            protect = await client.post(endpoint, json={"analysis_id": analysis_id})
            if protect.status_code != 200:
                return {
                    "status_code": protect.status_code, "error": protect.text,
                    "protected_count": None, "verified_count": None,
                    "verified": False, "tamper_rejected": False,
                    "original_reverified": False, "schema_version": None,
                }
            protected = protect.json()
            route = (
                "/api/v1/demo/hybrid/telemetry"
                if version == "v2" else "/api/v1/demo/telemetry"
            )
            verify = await client.post(
                f"{route}/{analysis_id}/verify",
            )
            tamper = await client.post(
                f"{route}/{analysis_id}/verify-tampered",
            )
            reverify = await client.post(
                f"{route}/{analysis_id}/verify",
            )
            if not all(response.status_code == 200
                       for response in (verify, tamper, reverify)):
                raise ValueError(f"{version} verification/tamper endpoint failure")
            valid, altered, again = (
                verify.json(), tamper.json(), reverify.json()
            )
            return {
                "status_code": protect.status_code,
                "schema_version": protected["schema_version"],
                "protected_count": protected["protected_count"],
                "verified_count": valid["verified_count"],
                "verified": valid["all_valid"] and valid["verification"] == "verified"
                            and valid["aes_gcm"] == "authenticated"
                            and valid["sha256"] == "verified"
                            and valid["rsa_pss"] == "valid",
                "tamper_rejected": altered["tamper_rejected"]
                                   and altered["verification"] == "rejected",
                "original_reverified": again["all_valid"]
                                       and again["verified_count"] == expected_count,
            }

        high_ml = [item for item in upload["results"]
                   if item["risk_level"] == "High" and item["alert_flagged"]]
        high_findings = [item for item in hybrid["findings"]
                         if item["severity"] == "High" and item["telemetry_eligible"]]
        v1 = await protect_version(
            "v1", "/api/v1/demo/telemetry/protect", len(high_ml),
        )
        v2 = await protect_version(
            "v2", "/api/v1/demo/hybrid/telemetry/protect", len(high_findings),
        )
        saved = sorted(path.name for path in (temporary / "evidence").glob("*.json"))
        return {
            "preparation": {"rows": prep_rows, "ready_versions": ready},
            "upload": {
                "analysis_id": analysis_id,
                "packet_count": upload["packet_count"],
                "flow_count": upload["flow_count"],
                "model_threshold": upload["model"]["model_threshold"],
                "flagged_alert_count": upload["flagged_alert_count"],
                "protocol_distribution": dict(sorted(Counter(
                    item["protocol"] for item in upload["flows"]
                ).items())),
                "flows": [{
                    "flow_index": index,
                    "protocol": item["protocol"],
                    "source_ip": item["source_ip"],
                    "destination_ip": item["destination_ip"],
                    "anomaly_score": item["anomaly_score"],
                    "risk_level": item["risk_level"],
                    "alert_flagged": item["alert_flagged"],
                    "explanations": item["explanations"],
                } for index, item in enumerate(upload["results"])],
            },
            "hybrid": {
                "schema_version": hybrid["schema_version"],
                "hosts": host_results,
                "rule_affected_hosts": {
                    item["host_ip"]: {
                        "decision": item["decision"],
                        "reason_codes": item["reason_codes"],
                        "rule_veto_effect": item["rule_veto_effect"],
                        "version_before": item["version_before"],
                        "version_after": item["version_after"],
                    } for item in hybrid["hosts"]
                    if item["host_ip"] in {
                        "203.0.113.40", "203.0.113.41", "203.0.113.50"
                    }
                },
                "high_ml_flow_count": len(high_ml),
                "low_ml_flow_count": sum(
                    item["risk_level"] == "Low" for item in upload["results"]
                ),
                "matched_rule_ids": sorted({
                    item["rule_id"] for item in hybrid["rule_assessments"]
                    if item["status"] == "Match"
                }),
                "rule_assessments": [
                    item for item in hybrid["rule_assessments"]
                    if item["status"] == "Match"
                ],
                "eligible_high_finding_count": len(high_findings),
                "high_findings": [{
                    "finding_id": item["finding_id"],
                    "detection_source": item["detection_source"],
                    "kind": item["kind"],
                    "severity": item["severity"],
                    "subject_host_ips": item["subject_host_ips"],
                    "possible_category": item["possible_category"],
                    "flow_indices": item["flow_indices"],
                    "ml_anomaly_score": item["ml_anomaly_score"],
                    "rule_evidence_strength": item["rule_evidence_strength"],
                } for item in high_findings],
            },
            "histories": histories,
            "telemetry": {
                "v1": v1, "v2": v2,
                "artifact_filenames": saved,
            },
        }


def validate(
    directory: Path, preparation: Path, *, write_results: bool,
) -> dict[str, object]:
    manifest_path = directory / "manifest.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    if manifest["schema_version"] != "nexus.final-hybrid-demo.v1":
        raise ValueError("Unexpected final demo schema")
    capture = directory / manifest["filename"]
    raw = capture.read_bytes()
    if (hashlib.sha256(raw).hexdigest() != manifest["sha256"]
            or len(raw) > 1_048_576 or len(raw) != manifest["size_bytes"]):
        raise ValueError("Final capture hash or upload size mismatch")
    if hashlib.sha256(TRAINING.read_bytes()).hexdigest() == manifest["sha256"]:
        raise ValueError("Final and training captures overlap")
    lengths = _header_only_lengths(capture)
    parsed = analyze_pcap(capture)
    window = classify_capture_window(
        parsed.capture_first_timestamp, parsed.capture_last_timestamp,
    )
    if (
        window.reason_code is not None
        or window.window_start != manifest["capture_window_start"]
        or window.window_end != manifest["capture_window_end"]
        or parsed.packet_count != manifest["packet_count"]
        or len(parsed.flows) != manifest["flow_count"]
        or parsed.packet_count != len(lengths)
        or parsed.packet_count > 2_000
    ):
        raise ValueError("Final parser/window/packet result mismatch")
    prior = json.loads((preparation / "manifest.json").read_text(encoding="utf-8"))
    for item in prior["captures"][:5]:
        path = preparation / item["filename"]
        if hashlib.sha256(path.read_bytes()).hexdigest() != item["sha256"]:
            raise ValueError(f"Preparation hash mismatch: {path}")
    detector = train_detector(analyze_pcap(TRAINING).flows)
    direct = detect_flows(detector, parsed.flows)
    rules = evaluate_rules(parsed)
    profiles = build_adaptive_host_profiles(parsed.flows)
    direct_evidence = {
        "training_flow_count": detector.training_flow_count,
        "model_threshold": detector.model_threshold,
        "high_ml_flow_count": sum(item.risk_level == "High" for item in direct),
        "matched_rule_ids": sorted({
            item["rule_id"] for item in rules if item["status"] == "Match"
        }),
        "principal_feature_vectors": {
            ip: {
                "observed_flow_count": profiles[ip].observed_flow_count,
                "average_duration_seconds": profiles[ip].average_duration_seconds,
                "average_bytes_per_flow": profiles[ip].average_bytes_per_flow,
                "average_packets_per_second": profiles[ip].average_packets_per_second,
                "protocol_shares": profiles[ip].protocol_shares,
            } for ip in PRINCIPALS.values()
        },
        "header_lengths": sorted(set(lengths)),
    }
    os.environ["NEXUS_DETECTION_TRAINING_PCAP_PATH"] = str(TRAINING)
    main = importlib.import_module("app.main")
    with tempfile.TemporaryDirectory(prefix="nexus-final-demo-") as temporary_name:
        actual = anyio.run(
            _api_run, main, preparation, capture, Path(temporary_name),
        )
    actual["direct"] = direct_evidence
    a, b, c = (actual["hybrid"]["hosts"][ip] for ip in PRINCIPALS.values())
    v1, v2 = actual["telemetry"]["v1"], actual["telemetry"]["v2"]
    checks = {
        "ready_v4_before_final": actual["preparation"]["ready_versions"] == {
            ip: 4 for ip in PRINCIPALS.values()
        },
        "capture_counts": (
            actual["upload"]["packet_count"] == manifest["packet_count"]
            and actual["upload"]["flow_count"] == manifest["flow_count"]
        ),
        "fixed_model_consistency": (
            actual["upload"]["model_threshold"] == detector.model_threshold
            and actual["hybrid"]["high_ml_flow_count"] == direct_evidence["high_ml_flow_count"]
        ),
        "A_accepted_adapts": (
            a["decision"] == "Accept" and a["version_before"] == 4
            and a["version_after"] == 5
            and a["baseline_after"]["average_duration_seconds"]
            > a["baseline_before"]["average_duration_seconds"]
            and a["rule_veto_effect"] == "none" and a["high_flow_count"] == 0
        ),
        "B_accepted_stable": (
            b["decision"] == "Accept" and b["version_before"] == 4
            and b["version_after"] == 5
            and b["baseline_after"] == b["baseline_before"]
            and b["rule_veto_effect"] == "none" and b["high_flow_count"] == 0
        ),
        "C_rejected_no_poisoning": (
            c["decision"] == "Reject" and c["version_before"] == 4
            and c["version_after"] == 4
            and c["baseline_after"] == c["baseline_before"]
            and c["high_flow_count"] >= 1
            and "SEVERE_BASELINE_DEVIATION" in c["reason_codes"]
            and "BASELINE_SEVERE_DEVIATION" in c["finding_kinds"]
        ),
        "rule_veto_scope": (
            set(actual["hybrid"]["rule_affected_hosts"]) == {
                "203.0.113.40", "203.0.113.41", "203.0.113.50"
            } and all(
                item["decision"] == "Reject"
                and "RULE_HIGH_EVIDENCE" in item["reason_codes"]
                and item["rule_veto_effect"] == "applied"
                for item in actual["hybrid"]["rule_affected_hosts"].values()
            )
        ),
        "R1_R2_genuine": (
            {"R1", "R2"} <= set(actual["hybrid"]["matched_rule_ids"])
            and {"R1", "R2"} <= set(direct_evidence["matched_rule_ids"])
            and all(ip not in {
                host for rule in actual["hybrid"]["rule_assessments"]
                for host in rule["affected_host_ips"]
            } for ip in (PRINCIPALS["A"], PRINCIPALS["B"]))
        ),
        "v1_all_ml": (
            v1["protected_count"] == actual["hybrid"]["high_ml_flow_count"]
            and v1["verified_count"] == v1["protected_count"]
            and v1["verified"] and v1["tamper_rejected"]
            and v1["original_reverified"]
        ),
        "v2_all_high": (
            v2["protected_count"] == actual["hybrid"]["eligible_high_finding_count"]
            and v2["verified_count"] == v2["protected_count"]
            and v2["verified"] and v2["tamper_rejected"]
            and v2["original_reverified"]
        ),
        "separate_artifacts": (
            len(actual["telemetry"]["artifact_filenames"]) == 2
            and len(set(actual["telemetry"]["artifact_filenames"])) == 2
        ),
    }
    manifest["actual"] = actual
    manifest["checks"] = checks
    manifest["validation_status"] = (
        "PASS" if all(checks.values()) else "DISCREPANCY"
    )
    if write_results:
        manifest_path.write_text(
            json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8"
        )
        with (directory / "expected-vs-actual.csv").open(
            "w", newline="", encoding="utf-8"
        ) as handle:
            writer = csv.DictWriter(handle, fieldnames=[
                "source", "intended", "actual", "validation_status",
            ])
            writer.writeheader()
            for source, intended in manifest["intended_outcomes"].items():
                result = (
                    actual["hybrid"]["hosts"][PRINCIPALS[source]]
                    if source in PRINCIPALS else
                    actual["hybrid"]["rule_assessments"]
                    if source == "rules" else actual["telemetry"]
                )
                writer.writerow({
                    "source": source,
                    "intended": intended,
                    "actual": json.dumps(result, sort_keys=True),
                    "validation_status": "PASS" if checks[
                        {"A": "A_accepted_adapts", "B": "B_accepted_stable",
                         "C": "C_rejected_no_poisoning", "rules": "R1_R2_genuine",
                         "telemetry": "v2_all_high"}[source]
                    ] else "DISCREPANCY",
                })
    return manifest


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Validate one final PCAP through fresh Hybrid and manual v1/v2 APIs."
    )
    parser.add_argument("corpus_directory", type=Path)
    parser.add_argument(
        "--preparation-directory", type=Path,
        default=ROOT / "data" / "nexus-multihost-adaptive-demo",
    )
    parser.add_argument("--write-results", action="store_true")
    args = parser.parse_args()
    result = validate(
        args.corpus_directory, args.preparation_directory,
        write_results=args.write_results,
    )
    print(json.dumps({
        "validation_status": result["validation_status"],
        "checks": result["checks"],
        "high_ml_flow_count": result["actual"]["hybrid"]["high_ml_flow_count"],
        "matched_rule_ids": result["actual"]["hybrid"]["matched_rule_ids"],
        "telemetry": {
            key: _summary(result["actual"]["telemetry"][key])
            for key in ("v1", "v2")
        },
    }, sort_keys=True))


if __name__ == "__main__":
    main()


