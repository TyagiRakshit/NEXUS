from __future__ import annotations

import math
import statistics
from dataclasses import dataclass
from typing import Any, Literal

from sklearn.ensemble import IsolationForest

from app.pcap_analysis import FlowSummary


FEATURE_NAMES = (
    "packet_count",
    "byte_count",
    "duration_seconds",
    "packets_per_second",
    "bytes_per_second",
    "protocol_tcp",
    "protocol_udp",
    "protocol_icmp_or_icmpv6",
    "protocol_other",
    "source_port_present",
    "destination_port_present",
)

NUMERIC_FEATURE_NAMES = FEATURE_NAMES[:5]


class FeatureDataError(Exception):
    def __init__(self) -> None:
        super().__init__("Synthetic training data is insufficient.")


class ModelUnavailable(Exception):
    def __init__(self) -> None:
        super().__init__("Offline anomaly detection is unavailable.")


@dataclass(frozen=True)
class RawFeatureVector:
    packet_count: float
    byte_count: float
    duration_seconds: float
    packets_per_second: float
    bytes_per_second: float
    protocol_tcp: float
    protocol_udp: float
    protocol_icmp_or_icmpv6: float
    protocol_other: float
    source_port_present: float
    destination_port_present: float

    def as_tuple(self) -> tuple[float, ...]:
        return tuple(getattr(self, name) for name in FEATURE_NAMES)


@dataclass(frozen=True)
class TrainingReference:
    numeric_ranges: tuple[tuple[float, float], ...]
    protocols: tuple[str, ...]
    port_presence: tuple[tuple[float, float], ...]


@dataclass(frozen=True)
class FeatureNormalizer:
    means: tuple[float, ...]
    standard_deviations: tuple[float, ...]
    reference: TrainingReference

    def transform(self, flow: FlowSummary) -> tuple[float, ...]:
        raw = flow_to_raw_features(flow).as_tuple()
        numeric = tuple(
            (math.log1p(value) - mean) / deviation
            for value, mean, deviation in zip(
                raw[:5], self.means, self.standard_deviations, strict=True
            )
        )
        transformed = numeric + raw[5:]
        if not all(math.isfinite(value) for value in transformed):
            raise FeatureDataError()
        return transformed


MODEL_PARAMETERS: dict[str, object] = {
    "n_estimators": 100,
    "max_samples": 32,
    "contamination": 0.05,
    "max_features": 1.0,
    "bootstrap": False,
    "random_state": 42,
    "n_jobs": 1,
}


@dataclass(frozen=True)
class TrainedDetector:
    model: Any
    normalizer: FeatureNormalizer
    training_vectors: tuple[tuple[float, ...], ...]
    training_flow_count: int
    model_threshold: float
    parameters: dict[str, object]


@dataclass(frozen=True)
class RiskDecision:
    risk_score: int
    risk_level: Literal["Low", "Medium", "High"]
    is_statistically_unusual: bool
    alert_flagged: bool


@dataclass(frozen=True)
class DetectionResult:
    flow: FlowSummary
    anomaly_score: float
    is_statistically_unusual: bool
    risk_score: int
    risk_level: Literal["Low", "Medium", "High"]
    alert_flagged: bool
    explanations: tuple[str, ...]


def _validated_metric(value: int | float) -> float:
    converted = float(value)
    if not math.isfinite(converted) or converted < 0:
        raise FeatureDataError()
    return converted


def flow_to_raw_features(flow: FlowSummary) -> RawFeatureVector:
    protocol = flow.protocol.upper()
    return RawFeatureVector(
        packet_count=_validated_metric(flow.packet_count),
        byte_count=_validated_metric(flow.byte_count),
        duration_seconds=_validated_metric(flow.duration_seconds),
        packets_per_second=_validated_metric(flow.packets_per_second),
        bytes_per_second=_validated_metric(flow.bytes_per_second),
        protocol_tcp=float(protocol == "TCP"),
        protocol_udp=float(protocol == "UDP"),
        protocol_icmp_or_icmpv6=float(protocol in {"ICMP", "ICMPV6"}),
        protocol_other=float(protocol not in {"TCP", "UDP", "ICMP", "ICMPV6"}),
        source_port_present=float(flow.source_port is not None),
        destination_port_present=float(flow.destination_port is not None),
    )


def fit_feature_normalizer(
    training: tuple[FlowSummary, ...],
) -> FeatureNormalizer:
    if not training:
        raise FeatureDataError()

    raw_vectors = tuple(flow_to_raw_features(flow).as_tuple() for flow in training)
    numeric_columns = tuple(
        tuple(math.log1p(vector[index]) for vector in raw_vectors)
        for index in range(5)
    )
    means = tuple(statistics.fmean(column) for column in numeric_columns)
    standard_deviations = tuple(
        deviation if deviation != 0 else 1.0
        for deviation in (statistics.pstdev(column) for column in numeric_columns)
    )
    reference = TrainingReference(
        numeric_ranges=tuple(
            (
                min(vector[index] for vector in raw_vectors),
                max(vector[index] for vector in raw_vectors),
            )
            for index in range(5)
        ),
        protocols=tuple(sorted({flow.protocol.upper() for flow in training})),
        port_presence=tuple(sorted({vector[9:11] for vector in raw_vectors})),
    )
    return FeatureNormalizer(
        means=means,
        standard_deviations=standard_deviations,
        reference=reference,
    )


def _endpoint_sort_key(ip: str, port: int | None) -> tuple[int, bytes, int]:
    import ipaddress

    address = ipaddress.ip_address(ip)
    return (address.version, address.packed, -1 if port is None else port)


def _training_sort_key(flow: FlowSummary) -> tuple[object, ...]:
    raw = flow_to_raw_features(flow)
    return (
        flow.protocol.upper(),
        _endpoint_sort_key(flow.source_ip, flow.source_port),
        _endpoint_sort_key(flow.destination_ip, flow.destination_port),
        *raw.as_tuple()[:5],
    )


def train_detector(training: tuple[FlowSummary, ...]) -> TrainedDetector:
    if len(training) < 32:
        raise FeatureDataError()

    ordered = tuple(sorted(training, key=_training_sort_key))
    normalizer = fit_feature_normalizer(ordered)
    vectors = tuple(normalizer.transform(flow) for flow in ordered)
    try:
        model = IsolationForest(**MODEL_PARAMETERS)
        model.fit(vectors)
        training_scores = tuple(
            round(-float(value), 6) for value in model.score_samples(vectors)
        )
    except Exception as error:
        raise ModelUnavailable() from error
    if not training_scores or not all(math.isfinite(value) for value in training_scores):
        raise ModelUnavailable()

    return TrainedDetector(
        model=model,
        normalizer=normalizer,
        training_vectors=vectors,
        training_flow_count=len(ordered),
        model_threshold=round(-float(model.offset_), 6),
        parameters=dict(MODEL_PARAMETERS),
    )


def map_risk(anomaly_score: float, model_threshold: float) -> RiskDecision:
    margin = round(anomaly_score - model_threshold, 6)
    if margin <= 0:
        return RiskDecision(20, "Low", False, False)
    return RiskDecision(90, "High", True, True)


def _display_number(value: float) -> str:
    return str(int(value)) if value.is_integer() else f"{value:g}"


def explain_detection(
    flow: FlowSummary,
    reference: TrainingReference,
    *,
    is_unusual: bool,
) -> tuple[str, ...]:
    raw = flow_to_raw_features(flow)
    numeric = raw.as_tuple()[:5]
    labels = (
        "Packet count",
        "Byte count",
        "Duration seconds",
        "Packets per second",
        "Bytes per second",
    )
    explanations: list[str] = []
    for label, value, (minimum, maximum) in zip(
        labels, numeric, reference.numeric_ranges, strict=True
    ):
        if value < minimum:
            explanations.append(
                f"{label} {_display_number(value)} is below synthetic training range "
                f"{_display_number(minimum)} to {_display_number(maximum)}."
            )
        elif value > maximum:
            explanations.append(
                f"{label} {_display_number(value)} is above synthetic training range "
                f"{_display_number(minimum)} to {_display_number(maximum)}."
            )
        if len(explanations) == 3:
            return tuple(explanations)

    protocol = flow.protocol.upper()
    if protocol not in reference.protocols:
        explanations.append(
            f"Protocol {protocol} was not present in the synthetic training fixture."
        )
    presence = raw.as_tuple()[9:11]
    if len(explanations) < 3 and presence not in reference.port_presence:
        explanations.append(
            "Port-presence pattern was not present in the synthetic training fixture."
        )
    if not explanations and is_unusual:
        explanations.append(
            "Combined metadata pattern is unusual relative to the synthetic training fixture."
        )
    elif not explanations:
        explanations.append(
            "No metadata feature is outside the synthetic training range."
        )
    return tuple(explanations[:3])


def detect_flows(
    detector: TrainedDetector,
    flows: tuple[FlowSummary, ...],
) -> tuple[DetectionResult, ...]:
    if not flows:
        return ()
    vectors = tuple(detector.normalizer.transform(flow) for flow in flows)
    try:
        scores = tuple(
            round(-float(value), 6)
            for value in detector.model.score_samples(vectors)
        )
    except Exception as error:
        raise ModelUnavailable() from error
    if len(scores) != len(flows) or not all(math.isfinite(value) for value in scores):
        raise ModelUnavailable()

    results: list[DetectionResult] = []
    for flow, score in zip(flows, scores, strict=True):
        risk = map_risk(score, detector.model_threshold)
        results.append(
            DetectionResult(
                flow=flow,
                anomaly_score=score,
                is_statistically_unusual=risk.is_statistically_unusual,
                risk_score=risk.risk_score,
                risk_level=risk.risk_level,
                alert_flagged=risk.alert_flagged,
                explanations=explain_detection(
                    flow,
                    detector.normalizer.reference,
                    is_unusual=risk.is_statistically_unusual,
                ),
            )
        )
    return tuple(results)
