"""One authoritative in-memory admission path for optional hybrid evaluation."""

from __future__ import annotations

import copy
from collections import OrderedDict
from threading import RLock
from typing import Callable
from uuid import UUID

from app.adaptive_baseline import AdaptiveBaselineStore, ScoredObservation
from app.hybrid_findings import build_findings
from app.hybrid_rules import RULE_SET_VERSION, evaluate_rules


class HybridEvaluationConflict(Exception):
    """A finalized legacy admission cannot be changed by a later rule veto."""


class HybridEvaluationNotFound(Exception):
    """No hybrid projection was finalized for this analysis."""


class HybridEvaluationCoordinator:
    def __init__(
        self, baseline_store: AdaptiveBaselineStore, *,
        candidate_registrar: Callable[[UUID, list[dict[str, object]]], None] | None = None,
        candidate_unregistrar: Callable[[UUID], None] | None = None,
        candidate_finalizer: Callable[[UUID], None] | None = None,
    ) -> None:
        self.baseline_store = baseline_store
        self.candidate_registrar = candidate_registrar
        self.candidate_unregistrar = candidate_unregistrar
        self.candidate_finalizer = candidate_finalizer
        self._registered_in_attempt = False
        self._lock = RLock()
        self._hybrid_results: OrderedDict[str, tuple[dict[str, object], float]] = OrderedDict()
        self._expired_ids: OrderedDict[str, None] = OrderedDict()

    def _purge_hybrid(self) -> None:
        now = self.baseline_store.clock()
        for key, (_, created_at) in tuple(self._hybrid_results.items()):
            if now - created_at >= self.baseline_store.ttl_seconds:
                del self._hybrid_results[key]
                self._expired_ids[key] = None
        while len(self._expired_ids) > self.baseline_store.max_results:
            self._expired_ids.popitem(last=False)
    def evaluate_legacy(self, observation: ScoredObservation) -> dict[str, object]:
        with self._lock:
            return self.baseline_store.evaluate(observation)

    def evaluate_hybrid(self, observation: ScoredObservation) -> dict[str, object]:
        """Serialize both hosts and roll back admission if any later step fails."""
        key = str(observation.analysis_id)
        with self._lock:
            self._purge_hybrid()
            if key in self._expired_ids:
                raise HybridEvaluationNotFound
            cached = self._hybrid_results.get(key)
            if cached is not None:
                return copy.deepcopy(cached[0])
            with self.baseline_store._lock:
                hosts_before = copy.deepcopy(self.baseline_store._hosts)
                results_before = copy.deepcopy(self.baseline_store._results)
                self._registered_in_attempt = False
                try:
                    return self._evaluate_hybrid_locked(observation)
                except Exception:
                    self.baseline_store._hosts = hosts_before
                    self.baseline_store._results = results_before
                    self._hybrid_results.pop(key, None)
                    if self._registered_in_attempt and self.candidate_unregistrar is not None:
                        self.candidate_unregistrar(observation.analysis_id)
                    raise

    def _evaluate_hybrid_locked(self, observation: ScoredObservation) -> dict[str, object]:
        key = str(observation.analysis_id)
        with self._lock:
            if key in self._hybrid_results:
                return copy.deepcopy(self._hybrid_results[key][0])
            rules = evaluate_rules(observation.analysis)
            affected = {
                host for rule in rules if rule["status"] == "Match"
                for host in rule["affected_host_ips"]
            }
            with self.baseline_store._lock:
                cached = self.baseline_store._results.get(observation.analysis_id)
                if cached is not None:
                    baseline = copy.deepcopy(cached[0])
                    if any(
                        host["host_ip"] in affected and host["decision"] != "Reject"
                        for host in baseline["hosts"]
                    ):
                        raise HybridEvaluationConflict
                    veto_effect = "redundant"
                else:
                    if self.candidate_registrar is not None:
                        preview_store = AdaptiveBaselineStore(
                            max_hosts=self.baseline_store.max_hosts,
                            max_results=self.baseline_store.max_results,
                            max_digests_per_host=self.baseline_store.max_digests_per_host,
                            ttl_seconds=self.baseline_store.ttl_seconds,
                            clock=self.baseline_store.clock,
                        )
                        preview_store.store_epoch = self.baseline_store.store_epoch
                        preview_store._hosts = copy.deepcopy(self.baseline_store._hosts)
                        preview_store._results = copy.deepcopy(self.baseline_store._results)
                        preview = preview_store.evaluate(
                            observation, rule_veto_hosts=frozenset(affected),
                        )
                        prepared = build_findings(observation, preview, rules)
                        self.candidate_registrar(observation.analysis_id, prepared)
                        self._registered_in_attempt = True
                    baseline = self.baseline_store.evaluate(
                        observation, rule_veto_hosts=frozenset(affected),
                    )
                    veto_effect = "applied"
            findings = build_findings(observation, baseline, rules)
            if cached is not None and self.candidate_registrar is not None:
                self.candidate_registrar(observation.analysis_id, findings)
                self._registered_in_attempt = True
            host_results: list[dict[str, object]] = []
            for host in baseline["hosts"]:
                ip = host["host_ip"]
                incident_high = any(
                    item.risk_level == "High"
                    for item in observation.detected
                    if ip in (item.flow.source_ip, item.flow.destination_ip)
                )
                high = incident_high or ip in affected or any(
                    item["severity"] == "High" for item in host["findings"]
                )
                medium = any(
                    item["severity"] == "Medium" for item in host["findings"]
                )
                host_results.append({
                    **host,
                    "overall_severity": "High" if high else "Medium" if medium else "Low",
                    "rule_veto_effect": veto_effect if ip in affected else "none",
                    "admission": {
                        "decision": host["decision"],
                        "reason_codes": host["reason_codes"],
                        "readiness_before": host["readiness_before"],
                        "readiness_after": host["readiness_after"],
                        "version_before": host["version_before"],
                        "version_after": host["version_after"],
                        "baseline_before": host["baseline_before"],
                        "baseline_after": host["baseline_after"],
                        "feature_deviations": host["feature_deviations"],
                        "history_host_ip": ip,
                    },
                })
            result: dict[str, object] = {
                "schema_version": "phase7.hybrid.v1",
                "source": "REPLAYED DEMO TRAFFIC",
                "analysis_id": key,
                "observation_id": str(observation.observation_id),
                "capture_window_start": baseline["capture_window_start"],
                "capture_window_end": baseline["capture_window_end"],
                "model_version": observation.model_version,
                "model_threshold": observation.model_threshold,
                "rule_set_version": RULE_SET_VERSION,
                "baseline_store_epoch": baseline["baseline_store_epoch"],
                "flow_results": [
                    {
                        "flow_index": index,
                        "anomaly_score": item.anomaly_score,
                        "risk_level": item.risk_level,
                        "risk_score": item.risk_score,
                        "alert_flagged": item.alert_flagged,
                    }
                    for index, item in enumerate(observation.detected)
                ],
                "rule_assessments": list(rules),
                "hosts": host_results,
                "findings": findings,
                "telemetry": {
                    "schema_version": "phase7.secure-telemetry.v2",
                    "eligible_count": sum(
                        item["telemetry_eligible"] for item in findings
                    ),
                },
            }
            self._hybrid_results[key] = (copy.deepcopy(result), self.baseline_store.clock())
            while len(self._hybrid_results) > self.baseline_store.max_results:
                expired_key, _ = self._hybrid_results.popitem(last=False)
                self._expired_ids[expired_key] = None
            response = copy.deepcopy(result)
            if self._registered_in_attempt and self.candidate_finalizer is not None:
                self.candidate_finalizer(observation.analysis_id)
            return response

    def get_hybrid(self, analysis_id: str) -> dict[str, object]:
        with self._lock:
            self._purge_hybrid()
            result = self._hybrid_results.get(analysis_id)
            if result is None:
                raise HybridEvaluationNotFound
            return copy.deepcopy(result[0])
