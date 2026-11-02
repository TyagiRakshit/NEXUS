from __future__ import annotations

import copy
import hashlib
import ipaddress
import math
import statistics
import time
from collections import OrderedDict
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from threading import RLock
from uuid import UUID, uuid4

from app.anomaly_detection import (
    NUMERIC_FEATURE_NAMES, DetectionResult, TrainingReference,
    flow_to_raw_features,
)
from app.pcap_analysis import AnalysisResult, FlowSummary


@dataclass(frozen=True)
class CaptureWindow:
    window_start: str | None
    window_end: str | None
    activity_span_seconds: float
    reason_code: str | None


def _utc_timestamp(seconds: float) -> str:
    return datetime.fromtimestamp(seconds, UTC).isoformat().replace("+00:00", "Z")


def classify_capture_window(first: float, last: float) -> CaptureWindow:
    if not all(math.isfinite(value) and value >= 0 for value in (first, last)):
        return CaptureWindow(None, None, 0.0, "INSUFFICIENT_EVIDENCE")
    if last < first:
        return CaptureWindow(None, None, 0.0, "INSUFFICIENT_EVIDENCE")
    span = last - first
    start = math.floor(first / 60) * 60
    if math.floor(last / 60) != math.floor(first / 60):
        return CaptureWindow(None, None, span, "NONCOMPARABLE_WINDOW")
    try:
        start_utc = _utc_timestamp(start)
        end_utc = _utc_timestamp(start + 60)
    except (OverflowError, ValueError):
        return CaptureWindow(None, None, span, "INSUFFICIENT_EVIDENCE")
    return CaptureWindow(
        start_utc,
        end_utc,
        span,
        "INSUFFICIENT_EVIDENCE" if span < 45 else None,
    )


def capture_digest(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as capture:
        for chunk in iter(lambda: capture.read(65_536), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _valid_nonnegative(*values: float) -> bool:
    return all(math.isfinite(value) and value >= 0 for value in values)


def _at_most(value: float, limit: float) -> bool:
    return value <= limit or math.isclose(value, limit, rel_tol=1e-12, abs_tol=1e-12)


def classify_count(observed: float, baseline: float) -> str:
    if not _valid_nonnegative(observed, baseline):
        return "Insufficient"
    difference = abs(observed - baseline)
    if baseline < 4:
        return "Accept" if _at_most(difference, 1) else (
            "Hold" if _at_most(difference, 2) else "Reject"
        )
    ratio = difference / baseline
    return "Accept" if _at_most(ratio, 0.25) else (
        "Hold" if _at_most(ratio, 0.75) else "Reject"
    )


def classify_log_metric(
    observed: float, baseline: float, floor: float,
    accept_factor: float, hold_factor: float,
) -> str:
    if not _valid_nonnegative(observed, baseline) or floor <= 0:
        return "Insufficient"
    ratio = (observed + floor) / (baseline + floor)
    distance = max(ratio, 1 / ratio)
    return "Accept" if _at_most(distance, accept_factor) else (
        "Hold" if _at_most(distance, hold_factor) else "Reject"
    )


def classify_protocol_share(
    observed: float, baseline: float, *, current_count: int,
) -> str:
    if (not _valid_nonnegative(observed, baseline)
        or observed > 1 or baseline > 1 or current_count < 0):
        return "Insufficient"
    if baseline == 0 and current_count:
        return "Hold" if current_count == 1 and _at_most(observed, 0.25) else "Reject"
    difference = abs(observed - baseline)
    return "Accept" if _at_most(difference, 0.15) else (
        "Hold" if _at_most(difference, 0.30) else "Reject"
    )


def classify_training_range(
    observed: float, minimum: float, maximum: float, floor: float,
) -> str:
    if (not _valid_nonnegative(observed, minimum, maximum)
        or minimum > maximum or floor <= 0):
        return "Insufficient"
    if minimum <= observed <= maximum:
        return "Accept"
    ratio = (
        (minimum + floor) / (observed + floor)
        if observed < minimum else
        (observed + floor) / (maximum + floor)
    )
    return "Hold" if _at_most(ratio, 2) else "Reject"


def proposed_numeric_update(
    baseline: float, observed: float, anchor: float, floor: float, alpha: float,
) -> float | None:
    if (not _valid_nonnegative(baseline, observed, anchor)
        or floor <= 0 or not 0 < alpha <= 1):
        return None
    scale = max(anchor, floor)
    step = max(-0.10 * scale, min(0.10 * scale, alpha * (observed - baseline)))
    proposed = baseline + step
    return proposed if _at_most(abs(proposed - anchor), 0.50 * scale) else None


def proposed_share_update(
    baseline: dict[str, float],
    observed: dict[str, float],
    anchor: dict[str, float],
    alpha: float,
) -> dict[str, float] | None:
    if not 0 < alpha <= 1 or set(baseline) != set(observed) or set(baseline) != set(anchor):
        return None
    if any(
        not _valid_nonnegative(*shares.values())
        or not math.isclose(sum(shares.values()), 1, abs_tol=1e-9)
        for shares in (baseline, observed, anchor)
    ):
        return None
    proposed = {
        protocol: (1 - alpha) * share + alpha * observed[protocol]
        for protocol, share in baseline.items()
    }
    if any(
        not _at_most(abs(share - anchor[protocol]), 0.25)
        for protocol, share in proposed.items()
    ):
        return None
    return proposed


PROTOCOL_CATEGORIES = ("TCP", "UDP", "ICMP", "OTHER")


@dataclass(frozen=True)
class AdaptiveHostFeatures:
    observed_flow_count: int
    average_bytes_per_flow: float
    average_duration_seconds: float
    average_packets_per_second: float
    protocol_shares: dict[str, float]


def _protocol_category(protocol: str) -> str:
    upper = protocol.upper()
    if upper in {"ICMP", "ICMPV6"}:
        return "ICMP"
    return upper if upper in {"TCP", "UDP"} else "OTHER"


def build_adaptive_host_profiles(
    flows: tuple[FlowSummary, ...],
) -> dict[str, AdaptiveHostFeatures]:
    by_host: dict[str, list[FlowSummary]] = {}
    for flow in flows:
        endpoints = {
            str(ipaddress.ip_address(flow.source_ip)),
            str(ipaddress.ip_address(flow.destination_ip)),
        }
        for host in endpoints:
            by_host.setdefault(host, []).append(flow)
    profiles: dict[str, AdaptiveHostFeatures] = {}
    for host, incident in by_host.items():
        count = len(incident)
        shares = {
            category: sum(
                _protocol_category(flow.protocol) == category for flow in incident
            ) / count
            for category in PROTOCOL_CATEGORIES
        }
        profiles[host] = AdaptiveHostFeatures(
            observed_flow_count=count,
            average_bytes_per_flow=statistics.fmean(flow.byte_count for flow in incident),
            average_duration_seconds=statistics.fmean(
                flow.duration_seconds for flow in incident
            ),
            average_packets_per_second=statistics.fmean(
                flow.packets_per_second for flow in incident
            ),
            protocol_shares=shares,
        )
    return profiles


@dataclass(frozen=True)
class HostDecision:
    decision: str
    reason_codes: tuple[str, ...]
    high_flow_count: int
    feature_deviations: tuple[dict[str, object], ...]
    findings: tuple[dict[str, object], ...]


def decide_host(
    host_ip: str,
    current: AdaptiveHostFeatures,
    baseline: AdaptiveHostFeatures | None,
    incident: tuple[DetectionResult, ...],
    reference: TrainingReference,
) -> HostDecision:
    reasons: set[str] = set()
    deviations: list[dict[str, object]] = []
    findings: list[dict[str, object]] = []
    high_count = sum(
        item.risk_level == "High" or item.alert_flagged for item in incident
    )
    if high_count:
        reasons.add("ML_HIGH")
    for item in incident:
        if item.risk_level == "Medium":
            reasons.add("INSUFFICIENT_EVIDENCE")
        if item.flow.protocol.upper() not in reference.protocols:
            reasons.add("INSUFFICIENT_EVIDENCE")
        raw = flow_to_raw_features(item.flow)
        for name, bounds, floor in zip(
            NUMERIC_FEATURE_NAMES, reference.numeric_ranges,
            (1.0, 64.0, 1.0, 1.0, 64.0), strict=True,
        ):
            band = classify_training_range(
                getattr(raw, name), bounds[0], bounds[1], floor,
            )
            if band == "Reject":
                reasons.add("EXTREME_FLOW_EVIDENCE")
            elif band == "Hold":
                reasons.add("FLOW_OUTSIDE_TRAINING_RANGE")
            elif band == "Insufficient":
                reasons.add("INSUFFICIENT_EVIDENCE")
    if baseline is not None:
        metrics = (
            ("observed_flow_count", current.observed_flow_count,
             baseline.observed_flow_count, classify_count(
                 current.observed_flow_count, baseline.observed_flow_count,
             )),
            ("average_bytes_per_flow", current.average_bytes_per_flow,
             baseline.average_bytes_per_flow, classify_log_metric(
                 current.average_bytes_per_flow, baseline.average_bytes_per_flow,
                 64, 1.5, 2,
             )),
            ("average_duration_seconds", current.average_duration_seconds,
             baseline.average_duration_seconds, classify_log_metric(
                 current.average_duration_seconds,
                 baseline.average_duration_seconds, 1, 1.75, 3,
             )),
            ("average_packets_per_second", current.average_packets_per_second,
             baseline.average_packets_per_second, classify_log_metric(
                 current.average_packets_per_second,
                 baseline.average_packets_per_second, 1, 1.75, 3,
             )),
        )
        for name, observed, before, band in metrics:
            if name == "observed_flow_count":
                deviation = (
                    abs(observed - before) if before < 4
                    else abs(observed - before) / before
                )
                accept_limit, hold_limit = (
                    (1.0, 2.0) if before < 4 else (0.25, 0.75)
                )
            else:
                floor, accept_factor, hold_factor = (
                    (64.0, 1.5, 2.0)
                    if name == "average_bytes_per_flow"
                    else (1.0, 1.75, 3.0)
                )
                deviation = abs(math.log((observed + floor) / (before + floor)))
                accept_limit, hold_limit = (
                    math.log(accept_factor), math.log(hold_factor)
                )
            deviations.append({
                "feature": name, "observed": observed,
                "baseline": before, "deviation": deviation,
                "accept_limit": accept_limit, "hold_limit": hold_limit,
                "band": band,
                "reason_code": "SEVERE_BASELINE_DEVIATION" if band == "Reject"
                else "HOST_DEVIATION" if band == "Hold" else "WITHIN_BAND",
            })
            if band == "Reject":
                reasons.add("SEVERE_BASELINE_DEVIATION")
            elif band == "Hold":
                reasons.add("HOST_DEVIATION")
            elif band == "Insufficient":
                reasons.add("INSUFFICIENT_EVIDENCE")
        counts = {
            name: round(current.protocol_shares[name] * current.observed_flow_count)
            for name in PROTOCOL_CATEGORIES
        }
        for name in PROTOCOL_CATEGORIES:
            band = classify_protocol_share(
                current.protocol_shares[name], baseline.protocol_shares[name],
                current_count=counts[name],
            )
            reason = (
                "NEW_PROTOCOL"
                if baseline.protocol_shares[name] == 0 and counts[name] > 0
                else "SEVERE_BASELINE_DEVIATION" if band == "Reject"
                else "HOST_DEVIATION" if band == "Hold" else "WITHIN_BAND"
            )
            deviations.append({
                "feature": f"protocol_share.{name}",
                "observed": current.protocol_shares[name],
                "baseline": baseline.protocol_shares[name],
                "deviation": abs(
                    current.protocol_shares[name] - baseline.protocol_shares[name]
                ),
                "accept_limit": 0.15, "hold_limit": 0.30,
                "band": band, "reason_code": reason,
            })
            if band in {"Hold", "Reject"}:
                reasons.add(reason)
            elif band == "Insufficient":
                reasons.add("INSUFFICIENT_EVIDENCE")
        severe_features = tuple(
            item["feature"] for item in deviations if item["band"] == "Reject"
        )
        if severe_features:
            findings.append({
                "kind": "BASELINE_SEVERE_DEVIATION",
                "severity": "High",
                "evidence_features": severe_features,
                "explanation": "Host metadata differs severely from its earlier baseline.",
                "is_phase5c_signed_alert": False,
            })
    reject = {"ML_HIGH", "EXTREME_FLOW_EVIDENCE", "SEVERE_BASELINE_DEVIATION"}
    severe_new_protocol = any(
        item["band"] == "Reject" and item["reason_code"] == "NEW_PROTOCOL"
        for item in deviations
    )
    decision = (
        "Reject" if reasons & reject or severe_new_protocol
        else "Hold" if reasons else "Accept"
    )
    priority = {
        "ML_HIGH": 0, "EXTREME_FLOW_EVIDENCE": 0,
        "SEVERE_BASELINE_DEVIATION": 0,
    }
    return HostDecision(
        decision=decision,
        reason_codes=tuple(sorted(reasons, key=lambda code: (priority.get(code, 1), code))),
        high_flow_count=high_count,
        feature_deviations=tuple(deviations),
        findings=tuple(findings),
    )


@dataclass(frozen=True)
class ScoredObservation:
    analysis_id: UUID
    observation_id: UUID
    capture_digest: str
    analysis: AnalysisResult
    detected: tuple[DetectionResult, ...]
    training_reference: TrainingReference
    model_version: str
    model_threshold: float


class ObservationNotFound(Exception):
    pass


class ObservationExpired(Exception):
    pass


class ObservationCapacityExceeded(Exception):
    pass


class ScoredObservationRegistry:
    def __init__(
        self, *, max_items: int = 32, ttl_seconds: float = 900,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        self.max_items = max_items
        self.ttl_seconds = ttl_seconds
        self.clock = clock
        self._lock = RLock()
        self._items: OrderedDict[UUID, tuple[ScoredObservation, float]] = OrderedDict()
        self._expired: OrderedDict[UUID, None] = OrderedDict()

    def _purge_expired(self) -> None:
        now = self.clock()
        for analysis_id, (_, created_at) in tuple(self._items.items()):
            if now - created_at >= self.ttl_seconds:
                del self._items[analysis_id]
                self._expired[analysis_id] = None
        while len(self._expired) > self.max_items:
            self._expired.popitem(last=False)

    def register(self, observation: ScoredObservation) -> None:
        with self._lock:
            self._purge_expired()
            if observation.analysis_id in self._items:
                raise ValueError("Analysis already registered.")
            if len(self._items) >= self.max_items:
                raise ObservationCapacityExceeded
            self._items[observation.analysis_id] = (observation, self.clock())

    def unregister(self, analysis_id: UUID) -> None:
        with self._lock:
            self._items.pop(analysis_id, None)

    def get(self, analysis_id: UUID) -> ScoredObservation:
        with self._lock:
            self._purge_expired()
            item = self._items.get(analysis_id)
            if item is not None:
                return item[0]
            if analysis_id in self._expired:
                raise ObservationExpired
            raise ObservationNotFound


class AdaptiveCapacityExceeded(Exception):
    pass


class AdaptiveObservationInvalid(Exception):
    pass


class AdaptiveHostNotFound(Exception):
    pass


@dataclass
class _Probation:
    features: AdaptiveHostFeatures
    reason_codes: tuple[str, ...]
    window_end: int
    observation_id: UUID


@dataclass
class _HostState:
    readiness: str = "absent"
    accepted_count: int = 0
    version: int | None = None
    baseline: AdaptiveHostFeatures | None = None
    anchor: AdaptiveHostFeatures | None = None
    warming_features: AdaptiveHostFeatures | None = None
    warming_window_end: int | None = None
    probation: _Probation | None = None
    latest_evaluated_start: int | None = None
    last_admitted_start: int | None = None
    seen_digests: set[str] | None = None
    snapshots: list[dict[str, object]] | None = None
    decisions: list[dict[str, object]] | None = None

    def __post_init__(self) -> None:
        if self.seen_digests is None:
            self.seen_digests = set()
        if self.snapshots is None:
            self.snapshots = []
        if self.decisions is None:
            self.decisions = []


def _features_json(features: AdaptiveHostFeatures | None) -> dict[str, object] | None:
    if features is None:
        return None
    return {
        "observed_flow_count": features.observed_flow_count,
        "average_bytes_per_flow": features.average_bytes_per_flow,
        "average_duration_seconds": features.average_duration_seconds,
        "average_packets_per_second": features.average_packets_per_second,
        "protocol_shares": dict(features.protocol_shares),
    }


def _pool_warmup(
    first: AdaptiveHostFeatures, second: AdaptiveHostFeatures,
) -> AdaptiveHostFeatures:
    total = first.observed_flow_count + second.observed_flow_count
    return AdaptiveHostFeatures(
        observed_flow_count=(first.observed_flow_count + second.observed_flow_count) / 2,
        average_bytes_per_flow=(
            first.average_bytes_per_flow + second.average_bytes_per_flow
        ) / 2,
        average_duration_seconds=(
            first.average_duration_seconds + second.average_duration_seconds
        ) / 2,
        average_packets_per_second=(
            first.average_packets_per_second + second.average_packets_per_second
        ) / 2,
        protocol_shares={
            name: (
                first.protocol_shares[name] * first.observed_flow_count
                + second.protocol_shares[name] * second.observed_flow_count
            ) / total
            for name in PROTOCOL_CATEGORIES
        },
    )


def _within_accept(
    current: AdaptiveHostFeatures, previous: AdaptiveHostFeatures,
) -> bool:
    return (
        classify_count(
            current.observed_flow_count, previous.observed_flow_count,
        ) == "Accept"
        and classify_log_metric(
            current.average_bytes_per_flow, previous.average_bytes_per_flow,
            64, 1.5, 2,
        ) == "Accept"
        and classify_log_metric(
            current.average_duration_seconds, previous.average_duration_seconds,
            1, 1.75, 3,
        ) == "Accept"
        and classify_log_metric(
            current.average_packets_per_second,
            previous.average_packets_per_second, 1, 1.75, 3,
        ) == "Accept"
        and all(
            _at_most(
                abs(current.protocol_shares[name] - previous.protocol_shares[name]),
                0.15,
            )
            for name in PROTOCOL_CATEGORIES
        )
    )


def _proposed_profile(
    baseline: AdaptiveHostFeatures,
    current: AdaptiveHostFeatures,
    anchor: AdaptiveHostFeatures,
    alpha: float,
) -> AdaptiveHostFeatures | None:
    values: dict[str, float] = {}
    for name, floor in (
        ("observed_flow_count", 1.0),
        ("average_bytes_per_flow", 64.0),
        ("average_duration_seconds", 1.0),
        ("average_packets_per_second", 1.0),
    ):
        proposed = proposed_numeric_update(
            float(getattr(baseline, name)),
            float(getattr(current, name)),
            float(getattr(anchor, name)),
            floor, alpha,
        )
        if proposed is None:
            return None
        values[name] = proposed
    shares = proposed_share_update(
        baseline.protocol_shares, current.protocol_shares,
        anchor.protocol_shares, alpha,
    )
    if shares is None:
        return None
    return AdaptiveHostFeatures(
        observed_flow_count=values["observed_flow_count"],
        average_bytes_per_flow=values["average_bytes_per_flow"],
        average_duration_seconds=values["average_duration_seconds"],
        average_packets_per_second=values["average_packets_per_second"],
        protocol_shares=shares,
    )


def _cap_features(
    baseline: AdaptiveHostFeatures,
    current: AdaptiveHostFeatures,
    anchor: AdaptiveHostFeatures,
    alpha: float,
) -> list[str]:
    exceeded: list[str] = []
    for name, floor in (
        ("observed_flow_count", 1.0),
        ("average_bytes_per_flow", 64.0),
        ("average_duration_seconds", 1.0),
        ("average_packets_per_second", 1.0),
    ):
        if proposed_numeric_update(
            float(getattr(baseline, name)),
            float(getattr(current, name)),
            float(getattr(anchor, name)),
            floor, alpha,
        ) is None:
            exceeded.append(name)
    if proposed_share_update(
        baseline.protocol_shares, current.protocol_shares,
        anchor.protocol_shares, alpha,
    ) is None:
        exceeded.extend(
            f"protocol_share.{name}" for name in PROTOCOL_CATEGORIES
            if abs(
                ((1 - alpha) * baseline.protocol_shares[name]
                 + alpha * current.protocol_shares[name])
                - anchor.protocol_shares[name]
            ) > 0.25
        )
    return exceeded


def _host_coverage(
    analysis: AnalysisResult, indices: tuple[int, ...],
) -> bool:
    if len(indices) < 4 or len(analysis.flow_time_bounds) != len(analysis.flows):
        return False
    flows = [analysis.flows[index] for index in indices]
    if sum(flow.packet_count for flow in flows) < 8:
        return False
    starts = sorted({
        analysis.flow_time_bounds[index][0] for index in indices
    })
    return len(starts) >= 3 and starts[-1] - starts[0] >= 30


def _ordered_reasons(reasons: set[str]) -> list[str]:
    reject_codes = {
        "ML_HIGH", "EXTREME_FLOW_EVIDENCE", "SEVERE_BASELINE_DEVIATION",
    }
    return sorted(reasons, key=lambda value: (value not in reject_codes, value))


def _ip_order(value: str) -> tuple[int, bytes]:
    parsed = ipaddress.ip_address(value)
    return parsed.version, parsed.packed


class AdaptiveBaselineStore:
    def __init__(
        self, *, max_hosts: int = 64, max_results: int = 32,
        max_digests_per_host: int = 256,
        ttl_seconds: float = 900, clock: Callable[[], float] = time.monotonic,
    ) -> None:
        self.store_epoch = uuid4()
        self.max_hosts = max_hosts
        self.max_results = max_results
        self.max_digests_per_host = max_digests_per_host
        self.ttl_seconds = ttl_seconds
        self.clock = clock
        self._lock = RLock()
        self._hosts: dict[str, _HostState] = {}
        self._results: OrderedDict[UUID, tuple[dict[str, object], float]] = OrderedDict()

    def _purge_results(self) -> None:
        now = self.clock()
        for analysis_id, (_, created_at) in tuple(self._results.items()):
            if now - created_at >= self.ttl_seconds:
                del self._results[analysis_id]

    def evaluate(
        self, observation: ScoredObservation, *,
        rule_veto_hosts: frozenset[str] = frozenset(),
    ) -> dict[str, object]:
        with self._lock:
            self._purge_results()
            cached = self._results.get(observation.analysis_id)
            if cached is not None:
                return copy.deepcopy(cached[0])
            if len(self._results) >= self.max_results:
                raise AdaptiveCapacityExceeded
            analysis = observation.analysis
            if len(analysis.flows) != len(observation.detected):
                raise AdaptiveObservationInvalid
            profiles = build_adaptive_host_profiles(analysis.flows)
            if len(self._hosts) + sum(host not in self._hosts for host in profiles) > self.max_hosts:
                raise AdaptiveCapacityExceeded
            first = analysis.capture_first_timestamp
            last = analysis.capture_last_timestamp
            window = classify_capture_window(
                first if first is not None else float("nan"),
                last if last is not None else float("nan"),
            )
            window_start = (
                math.floor(first / 60) * 60
                if first is not None and window.window_start is not None else None
            )
            window_end = window_start + 60 if window_start is not None else None
            staged: dict[str, _HostState] = {}
            host_results: list[dict[str, object]] = []
            any_duplicate = False
            for host_ip in sorted(profiles, key=_ip_order):
                prior = self._hosts.get(host_ip, _HostState())
                state = copy.deepcopy(prior)
                profile = profiles[host_ip]
                indices = tuple(
                    index for index, flow in enumerate(analysis.flows)
                    if host_ip in {
                        str(ipaddress.ip_address(flow.source_ip)),
                        str(ipaddress.ip_address(flow.destination_ip)),
                    }
                )
                incident = tuple(observation.detected[index] for index in indices)
                coverage = window.reason_code is None and _host_coverage(analysis, indices)
                result = decide_host(
                    host_ip, profile,
                    prior.baseline
                    if coverage and prior.readiness in {"provisional", "ready"}
                    else None,
                    incident, observation.training_reference,
                )
                before = _features_json(prior.baseline)
                readiness_before = prior.readiness
                version_before = prior.version
                accepted_before = prior.accepted_count
                reasons = set(result.reason_codes)
                if host_ip in rule_veto_hosts:
                    reasons.add("RULE_HIGH_EVIDENCE")
                findings = [dict(finding, finding_id=str(uuid4())) for finding in result.findings]
                if window.reason_code:
                    reasons.add(window.reason_code)
                if window.reason_code is None and not coverage:
                    reasons.add("INSUFFICIENT_EVIDENCE")
                duplicate = observation.capture_digest in prior.seen_digests
                if duplicate:
                    reasons.add("DUPLICATE_CAPTURE")
                    any_duplicate = True
                if window_start is not None and prior.latest_evaluated_start is not None:
                    if window_start < prior.latest_evaluated_start:
                        reasons.add("OUT_OF_ORDER_CAPTURE")
                    elif window_start == prior.latest_evaluated_start and not duplicate:
                        reasons.add("OVERLAPPING_WINDOW")
                ordering_block = bool(
                    reasons & {
                        "DUPLICATE_CAPTURE", "OUT_OF_ORDER_CAPTURE",
                        "OVERLAPPING_WINDOW",
                    }
                )
                if not ordering_block and coverage and window_start is not None:
                    state.latest_evaluated_start = window_start
                if (
                    not duplicate
                    and len(state.seen_digests) >= self.max_digests_per_host
                ):
                    raise AdaptiveCapacityExceeded
                state.seen_digests.add(observation.capture_digest)
                if state.readiness == "warming" and window_start is not None:
                    gap = window_start - state.warming_window_end
                    if gap > 300 and not ordering_block:
                        state.readiness = "absent"
                        state.accepted_count = 0
                        state.version = None
                        state.warming_features = None
                        state.warming_window_end = None
                        state.baseline = None
                        state.anchor = None
                        state.snapshots = []
                if state.probation is not None and window_start is not None:
                    gap = window_start - state.probation.window_end
                    if gap > 300 and not ordering_block:
                        state.probation = None
                reject_reasons = {
                    "ML_HIGH", "EXTREME_FLOW_EVIDENCE",
                    "SEVERE_BASELINE_DEVIATION", "RULE_HIGH_EVIDENCE",
                }
                severe_new = any(
                    item["band"] == "Reject" and item["reason_code"] == "NEW_PROTOCOL"
                    for item in result.feature_deviations
                )
                decision = (
                    "Reject" if reasons & reject_reasons or severe_new
                    else "Hold" if reasons else "Accept"
                )
                if state.readiness == "warming" and decision == "Accept":
                    if not _within_accept(profile, state.warming_features):
                        decision = "Hold"
                        reasons.add("WARMUP_INCONSISTENT")
                        state.readiness = "absent"
                        state.accepted_count = 0
                        state.version = None
                        state.warming_features = None
                        state.warming_window_end = None
                        state.snapshots = []
                if state.readiness == "warming" and decision == "Reject":
                    state.readiness = "absent"
                    state.accepted_count = 0
                    state.version = None
                    state.warming_features = None
                    state.warming_window_end = None
                    state.snapshots = []
                if decision == "Accept" and state.readiness == "absent":
                    state.readiness = "warming"
                    state.accepted_count = 1
                    state.version = 0
                    state.warming_features = profile
                    state.warming_window_end = window_end
                    state.last_admitted_start = window_start
                    reasons.add("WARMING")
                elif decision == "Accept" and state.readiness == "warming":
                    initial = _pool_warmup(state.warming_features, profile)
                    state.baseline = initial
                    state.anchor = initial
                    state.readiness = "provisional"
                    state.accepted_count = 2
                    state.version = 1
                    state.warming_features = None
                    state.warming_window_end = None
                    state.last_admitted_start = window_start
                    reasons.add("PROVISIONAL_BASELINE")
                elif state.readiness in {"provisional", "ready"}:
                    probation_reasons = {
                        "FLOW_OUTSIDE_TRAINING_RANGE", "HOST_DEVIATION",
                        "NEW_PROTOCOL",
                    }
                    eligible_probation = (
                        state.readiness == "ready" and decision == "Hold"
                        and bool(reasons) and reasons <= probation_reasons
                        and coverage and not ordering_block
                    )
                    if eligible_probation:
                        prior_probation = state.probation
                        same_sequence = (
                            prior_probation is not None
                            and prior_probation.reason_codes == tuple(sorted(reasons))
                            and window_start is not None
                            and 0 <= window_start - prior_probation.window_end <= 300
                            and _within_accept(profile, prior_probation.features)
                        )
                        if same_sequence:
                            proposed = _proposed_profile(
                                state.baseline, profile, state.anchor, 0.10,
                            )
                            if proposed is None:
                                reasons.add("ADAPTATION_LIMIT_REACHED")
                                findings.append({
                                    "finding_id": str(uuid4()),
                                    "kind": "ADAPTATION_LIMIT_REACHED",
                                    "severity": "Medium",
                                    "evidence_features": _cap_features(
                                        state.baseline, profile, state.anchor, 0.10,
                                    ),
                                    "explanation": "The proposed host update would exceed its fixed anchor limit.",
                                    "is_phase5c_signed_alert": False,
                                })
                                state.probation = None
                            else:
                                decision = "Accept"
                                reasons = {"PROBATION_ADMITTED"}
                                state.baseline = proposed
                                state.accepted_count += 1
                                state.version += 1
                                state.last_admitted_start = window_start
                                state.probation = None
                        else:
                            state.probation = _Probation(
                                profile, tuple(sorted(reasons)), window_end,
                                observation.observation_id,
                            )
                    else:
                        state.probation = None
                    if decision == "Accept" and "PROBATION_ADMITTED" not in reasons:
                        proposed = _proposed_profile(
                            state.baseline, profile, state.anchor, 0.20,
                        )
                        if proposed is None:
                            decision = "Hold"
                            reasons = {"ADAPTATION_LIMIT_REACHED"}
                            findings.append({
                                "finding_id": str(uuid4()),
                                "kind": "ADAPTATION_LIMIT_REACHED",
                                "severity": "Medium",
                                "evidence_features": _cap_features(
                                    state.baseline, profile, state.anchor, 0.20,
                                ),
                                "explanation": "The proposed host update would exceed its fixed anchor limit.",
                                "is_phase5c_signed_alert": False,
                            })
                        else:
                            state.baseline = proposed
                            state.accepted_count += 1
                            state.version += 1
                            state.last_admitted_start = window_start
                            if state.readiness == "provisional" and state.accepted_count >= 5:
                                state.readiness = "ready"
                            reasons = {"WITHIN_BAND"}
                after = _features_json(state.baseline)
                if decision == "Accept":
                    state.snapshots.append({
                        "version": state.version,
                        "observation_id": str(observation.observation_id),
                        "window_start": window.window_start,
                        "reason_code": next(iter(reasons)),
                        "features_before": before,
                        "features_after": after if after is not None else _features_json(profile),
                    })
                    state.snapshots = state.snapshots[-8:]
                state.decisions.append({
                    "observation_id": str(observation.observation_id),
                    "window_start": window.window_start,
                    "decision": decision,
                    "reason_codes": _ordered_reasons(reasons),
                    "version_before": version_before,
                    "version_after": state.version,
                    "finding_ids": [finding["finding_id"] for finding in findings],
                })
                state.decisions = state.decisions[-32:]
                staged[host_ip] = state
                host_results.append({
                    "host_ip": host_ip,
                    "decision": decision,
                    "reason_codes": _ordered_reasons(reasons),
                    "readiness_before": readiness_before,
                    "readiness_after": state.readiness,
                    "coverage_confidence": (
                        "accumulated" if state.readiness == "ready"
                        else "limited" if state.readiness == "provisional"
                        else "insufficient"
                    ),
                    "accepted_count_before": accepted_before,
                    "accepted_count_after": state.accepted_count,
                    "version_before": version_before,
                    "version_after": state.version,
                    "probation_count": 1 if state.probation else 0,
                    "incident_flow_count": len(indices),
                    "high_flow_count": result.high_flow_count,
                    "flow_evidence_refs": list(indices),
                    "current_features": _features_json(profile),
                    "baseline_before": before,
                    "baseline_after": after,
                    "feature_deviations": list(result.feature_deviations),
                    "last_evaluated_window_start": (
                        _utc_timestamp(state.latest_evaluated_start)
                        if state.latest_evaluated_start is not None else None
                    ),
                    "last_admitted_window_start": (
                        _utc_timestamp(state.last_admitted_start)
                        if state.last_admitted_start is not None else None
                    ),
                    "findings": findings,
                })
            response: dict[str, object] = {
                "schema_version": "phase6.baseline.v1",
                "source": "REPLAYED DEMO TRAFFIC",
                "analysis_id": str(observation.analysis_id),
                "observation_id": str(observation.observation_id),
                "capture_window_start": window.window_start,
                "capture_window_end": window.window_end,
                "activity_span_seconds": window.activity_span_seconds,
                "capture_fingerprint_status": "duplicate" if any_duplicate else "new",
                "model_version": observation.model_version,
                "model_threshold": observation.model_threshold,
                "baseline_store_epoch": str(self.store_epoch),
                "hosts": host_results,
            }
            self._hosts.update(staged)
            self._results[observation.analysis_id] = (
                copy.deepcopy(response), self.clock(),
            )
            return copy.deepcopy(response)

    def history(self, host_ip: str) -> dict[str, object]:
        normalized = str(ipaddress.ip_address(host_ip))
        with self._lock:
            state = self._hosts.get(normalized)
            if state is None:
                raise AdaptiveHostNotFound
            return {
                "schema_version": "phase6.baseline.history.v1",
                "source": "REPLAYED DEMO TRAFFIC",
                "baseline_store_epoch": str(self.store_epoch),
                "host_ip": normalized,
                "readiness": state.readiness,
                "coverage_confidence": (
                    "accumulated" if state.readiness == "ready"
                    else "limited" if state.readiness == "provisional"
                    else "insufficient"
                ),
                "current_version": state.version,
                "anchor_version": 1 if state.anchor is not None else None,
                "current_baseline": _features_json(state.baseline),
                "snapshots": copy.deepcopy(state.snapshots),
                "decisions": copy.deepcopy(state.decisions),
            }
