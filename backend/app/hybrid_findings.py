"""Source-preserving, deterministic findings for the offline hybrid demonstration."""

from __future__ import annotations

import ipaddress
import json
from datetime import datetime, timezone
from uuid import NAMESPACE_URL, uuid5

from app.adaptive_baseline import ScoredObservation


SCHEMA_VERSION = "phase7.finding.v1"


def _hosts(values: list[str] | tuple[str, ...]) -> list[str]:
    return sorted(
        {str(ipaddress.ip_address(value)) for value in values},
        key=lambda value: (ipaddress.ip_address(value).version,
                           ipaddress.ip_address(value).packed),
    )


def _indices(values: list[int] | tuple[int, ...]) -> list[int]:
    return sorted(set(values))


def _identity(
    observation: ScoredObservation, source: str, kind: str,
    hosts: list[str], indices: list[int], rule_id: str | None = None,
) -> str:
    canonical = json.dumps(
        [str(observation.analysis_id), str(observation.observation_id),
         source, kind, hosts, indices, rule_id],
        ensure_ascii=True, separators=(",", ":"),
    )
    return str(uuid5(NAMESPACE_URL, "NEXUS|phase7.finding.v1|" + canonical))


def _utc(timestamp: float | None) -> str | None:
    return datetime.fromtimestamp(timestamp, timezone.utc).isoformat() if timestamp is not None else None


def _span(observation: ScoredObservation, refs: list[int]) -> tuple[str | None, str | None]:
    bounds = [observation.analysis.flow_time_bounds[index]
              for index in refs if index < len(observation.analysis.flow_time_bounds)]
    if not bounds:
        return (_utc(observation.analysis.capture_first_timestamp),
                _utc(observation.analysis.capture_last_timestamp))
    return _utc(min(start for start, _ in bounds)), _utc(max(end for _, end in bounds))


def _evidence(mapping: dict[str, object], rule_id: str | None = None) -> list[dict[str, object]]:
    thresholds = {
        "R1": {"tcp_flow_count": 6, "distinct_start_times": 3},
        "R2": {"flow_count": 5, "distinct_peer_count": 5,
               "distinct_focal_ports": 4, "distinct_start_times": 3},
    }.get(rule_id or "", {})
    entries = [
        {
            "metric": key, "observed": value,
            "comparator": ">=" if key in thresholds else None,
            "threshold": thresholds.get(key),
            "unit": "flows" if key in {"tcp_flow_count", "flow_count"} else
                    "count" if key in thresholds else None,
        }
        for key, value in sorted(mapping.items())
    ]
    if rule_id == "R1":
        for orientation in sorted(
            mapping.get("qualifying_orientations", []),
            key=lambda item: (item["focal_host_ip"], item["port_varying_host_ip"]),
        ):
            for key, threshold in (("distinct_peer_ports", 6),
                                   ("distinct_focal_ports", 4)):
                entries.append({
                    "metric": key, "observed": orientation[key],
                    "comparator": ">=", "threshold": threshold, "unit": "ports",
                    "focal_host_ip": orientation["focal_host_ip"],
                    "port_varying_host_ip": orientation["port_varying_host_ip"],
                })
    return entries


def build_findings(
    observation: ScoredObservation,
    baseline: dict[str, object],
    rules: tuple[dict[str, object], ...],
) -> list[dict[str, object]]:
    """Keep ML, baseline, and rule results independently attributable."""
    findings: list[dict[str, object]] = []
    for index, detected in enumerate(observation.detected):
        if not (detected.risk_level == "High" and detected.alert_flagged):
            continue
        hosts = _hosts([detected.flow.source_ip, detected.flow.destination_ip])
        refs = [index]
        span_start, span_end = _span(observation, refs)
        findings.append({
            "schema_version": SCHEMA_VERSION,
            "finding_id": _identity(observation, "isolation_forest", "ML_HIGH", hosts, refs),
            "analysis_id": str(observation.analysis_id),
            "observation_id": str(observation.observation_id),
            "detection_source": "isolation_forest",
            "kind": "ML_HIGH", "severity": "High",
            "subject_scope": "flow", "host_ip": None,
            "subject_host_ips": hosts, "possible_category": None,
            "flow_indices": refs,
            "capture_window_start": span_start,
            "capture_window_end": span_end,
            "evidence": _evidence({
                "anomaly_score": detected.anomaly_score,
                "model_threshold": observation.model_threshold,
            }),
            "explanation": "Flow metadata is statistically unusual under the fixed demo model.",
            "ml_anomaly_score": detected.anomaly_score,
            "rule_evidence_strength": None,
            "telemetry_eligible": True,
        })
    for host in sorted(baseline.get("hosts", []), key=lambda item: item["host_ip"]):
        host_ip = _hosts([host["host_ip"]])[0]
        refs = _indices(host.get("flow_evidence_refs", []))
        span_start, span_end = _span(observation, refs)
        for item in sorted(host.get("findings", []), key=lambda finding: finding["kind"]):
            kind = item["kind"]
            severity = item["severity"]
            findings.append({
                "schema_version": SCHEMA_VERSION,
                "finding_id": _identity(
                    observation, "adaptive_baseline", kind, [host_ip], refs,
                ),
                "analysis_id": str(observation.analysis_id),
                "observation_id": str(observation.observation_id),
                "detection_source": "adaptive_baseline",
                "kind": kind, "severity": severity,
                "subject_scope": "host", "host_ip": host_ip,
                "subject_host_ips": [host_ip], "possible_category": None,
                "flow_indices": refs,
                "capture_window_start": span_start,
                "capture_window_end": span_end,
                "evidence": [
                    {"metric": deviation["feature"], **deviation}
                    for deviation in sorted(
                        host.get("feature_deviations", []),
                        key=lambda value: value["feature"],
                    )
                    if deviation["feature"] in item.get("evidence_features", [])
                ] or _evidence({
                    "evidence_features": sorted(item.get("evidence_features", [])),
                }),
                "explanation": item["explanation"],
                "ml_anomaly_score": None,
                "rule_evidence_strength": None,
                "telemetry_eligible": severity == "High",
            })
    for rule in sorted(
        rules, key=lambda item: (
            item["rule_id"], tuple(item["subject_host_ips"]),
            tuple(item["flow_indices"]),
        ),
    ):
        if rule["status"] != "Match":
            continue
        hosts = _hosts(rule["subject_host_ips"])
        refs = _indices(rule["flow_indices"])
        span_start = _utc(rule["evidence"].get("start_timestamp"))
        span_end = _utc(rule["evidence"].get("end_timestamp"))
        category = {
            "R1": "possible_port_sweep",
            "R2": "possible_host_recon",
        }[rule["rule_id"]]
        findings.append({
            "schema_version": SCHEMA_VERSION,
            "finding_id": _identity(
                observation, "security_rule", "RULE_MATCH",
                hosts, refs, rule["rule_id"],
            ),
            "analysis_id": str(observation.analysis_id),
            "observation_id": str(observation.observation_id),
            "detection_source": "security_rule",
            "kind": "RULE_MATCH", "severity": "High",
            "subject_scope": "host_pair" if rule["rule_id"] == "R1" else "host",
            "host_ip": None if rule["rule_id"] == "R1" else hosts[0],
            "subject_host_ips": hosts, "possible_category": category,
            "flow_indices": refs,
            "capture_window_start": span_start,
            "capture_window_end": span_end,
            "evidence": _evidence(rule["evidence"], rule["rule_id"]),
            "explanation": rule["explanation"],
            "ml_anomaly_score": None,
            "rule_evidence_strength": rule["rule_evidence_strength"],
            "telemetry_eligible": True,
        })
    unique: dict[str, dict[str, object]] = {}
    for finding in findings:
        unique[finding["finding_id"]] = finding
    return list(unique.values())
