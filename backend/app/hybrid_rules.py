"""Deterministic metadata-only possible-pattern assessments for offline replay."""

from __future__ import annotations

import ipaddress
import math
from collections import defaultdict

from app.pcap_analysis import AnalysisResult, FlowSummary


RULE_SET_VERSION = "increment4-demo-rules-v1"


def _ip(value: str) -> str | None:
    try:
        return str(ipaddress.ip_address(value))
    except ValueError:
        return None


def _endpoint_port(flow: FlowSummary, host: str) -> int | None:
    if flow.source_ip == host:
        return flow.source_port
    if flow.destination_ip == host:
        return flow.destination_port
    return None


def _start(analysis: AnalysisResult, index: int) -> float | None:
    if index >= len(analysis.flow_time_bounds):
        return None
    value = analysis.flow_time_bounds[index][0]
    return value if math.isfinite(value) else None


def _complete(
    analysis: AnalysisResult, index: int, flow: FlowSummary,
) -> tuple[str, str, float] | None:
    left, right = _ip(flow.source_ip), _ip(flow.destination_ip)
    if left is None or right is None or left == right:
        return None
    if not isinstance(flow.source_port, int) or not 0 <= flow.source_port <= 65535:
        return None
    if not isinstance(flow.destination_port, int) or not 0 <= flow.destination_port <= 65535:
        return None
    start = _start(analysis, index)
    if start is None:
        return None
    return left, right, start


def _score(primary: int, minimum: int) -> int:
    return min(90, 60 + 5 * (primary - minimum))


def _r1(analysis: AnalysisResult) -> list[dict[str, object]]:
    groups: dict[tuple[str, str], list[tuple[int, FlowSummary, float]]] = defaultdict(list)
    for index, flow in enumerate(analysis.flows):
        if flow.protocol.upper() != "TCP":
            continue
        complete = _complete(analysis, index, flow)
        if complete is None:
            continue
        left, right, start = complete
        groups[tuple(sorted((left, right)))].append((index, flow, start))
    if not groups:
        return [{
            "rule_id": "R1", "status": "Unknown",
            "reason_code": "INSUFFICIENT_EVIDENCE", "subject_host_ips": [],
            "affected_host_ips": [], "flow_indices": [],
            "rule_evidence_strength": None, "evidence": {},
            "explanation": "Insufficient TCP endpoint and timing metadata to assess a possible port sweep.",
        }]
    output: list[dict[str, object]] = []
    for pair in sorted(groups):
        records = groups[pair]
        starts = {start for _, _, start in records}
        qualifying: list[dict[str, object]] = []
        counts: list[dict[str, object]] = []
        for focal, peer in (pair, pair[::-1]):
            peer_ports = {_endpoint_port(flow, peer) for _, flow, _ in records}
            focal_ports = {_endpoint_port(flow, focal) for _, flow, _ in records}
            count = {
                "focal_host_ip": focal,
                "port_varying_host_ip": peer,
                "distinct_peer_ports": len(peer_ports),
                "distinct_focal_ports": len(focal_ports),
            }
            counts.append(count)
            if len(records) >= 6 and len(starts) >= 3 and len(peer_ports) >= 6 and len(focal_ports) >= 4:
                qualifying.append(count)
        if qualifying:
            best = max(int(item["distinct_peer_ports"]) for item in qualifying)
            status, reason, strength = "Match", "POSSIBLE_PORT_SWEEP", _score(best, 6)
        elif len(records) < 6 or len(starts) < 3:
            status, reason, strength = "Unknown", "INSUFFICIENT_EVIDENCE", None
        else:
            status, reason, strength = "NoPatternMatchedInObservedMetadata", "NO_PATTERN_MATCHED", 0
        output.append({
            "rule_id": "R1", "status": status, "reason_code": reason,
            "subject_host_ips": list(pair),
            "affected_host_ips": list(pair) if status == "Match" else [],
            "flow_indices": sorted(index for index, _, _ in records),
            "rule_evidence_strength": strength,
            "evidence": {
                "tcp_flow_count": len(records),
                "distinct_start_times": len(starts),
                "orientations": counts,
                "qualifying_orientations": qualifying,
                "start_timestamp": min(starts),
                "end_timestamp": max(starts),
            },
            "explanation": (
                "Metadata shows a possible port sweep involving this host pair; "
                "the initiator and intent are unknown."
                if status == "Match" else
                "The observed TCP metadata is insufficient for this pattern."
                if status == "Unknown" else
                "No port-sweep pattern matched in the observed TCP metadata."
            ),
        })
    return output


def _r2(analysis: AnalysisResult) -> list[dict[str, object]]:
    groups: dict[tuple[str, str, int], list[tuple[int, str, int, float]]] = defaultdict(list)
    for index, flow in enumerate(analysis.flows):
        protocol = flow.protocol.upper()
        if protocol not in {"TCP", "UDP"}:
            continue
        complete = _complete(analysis, index, flow)
        if complete is None:
            continue
        left, right, start = complete
        for focal, peer in ((left, right), (right, left)):
            peer_port = _endpoint_port(flow, peer)
            focal_port = _endpoint_port(flow, focal)
            assert peer_port is not None and focal_port is not None
            groups[(focal, protocol, peer_port)].append(
                (index, peer, focal_port, start)
            )
    if not groups:
        return [{
            "rule_id": "R2", "status": "Unknown",
            "reason_code": "INSUFFICIENT_EVIDENCE", "subject_host_ips": [],
            "affected_host_ips": [], "flow_indices": [],
            "rule_evidence_strength": None, "evidence": {},
            "explanation": "Insufficient TCP or UDP endpoint and timing metadata to assess possible host reconnaissance.",
        }]
    output: list[dict[str, object]] = []
    for (focal, protocol, peer_port), records in sorted(groups.items()):
        peers = sorted({peer for _, peer, _, _ in records})
        focal_ports = {port for _, _, port, _ in records}
        starts = {start for _, _, _, start in records}
        if len(records) >= 5 and len(starts) >= 3 and len(peers) >= 5 and len(focal_ports) >= 4:
            status, reason, strength = "Match", "POSSIBLE_HOST_RECON", _score(len(peers), 5)
        elif len(records) < 5 or len(starts) < 3:
            status, reason, strength = "Unknown", "INSUFFICIENT_EVIDENCE", None
        else:
            status, reason, strength = "NoPatternMatchedInObservedMetadata", "NO_PATTERN_MATCHED", 0
        output.append({
            "rule_id": "R2", "status": status, "reason_code": reason,
            "subject_host_ips": [focal],
            "affected_host_ips": [focal] if status == "Match" else [],
            "flow_indices": sorted(index for index, _, _, _ in records),
            "rule_evidence_strength": strength,
            "evidence": {
                "protocol": protocol,
                "common_peer_port": peer_port,
                "flow_count": len(records),
                "peer_ips": peers,
                "distinct_peer_count": len(peers),
                "distinct_focal_ports": len(focal_ports),
                "distinct_start_times": len(starts),
                "start_timestamp": min(starts),
                "end_timestamp": max(starts),
            },
            "explanation": (
                "Metadata shows possible host reconnaissance involving this host; "
                "the initiator and intent are unknown."
                if status == "Match" else
                "The observed TCP or UDP metadata is insufficient for this pattern."
                if status == "Unknown" else
                "No host-reconnaissance pattern matched in the observed metadata."
            ),
        })
    return output


def evaluate_rules(analysis: AnalysisResult) -> tuple[dict[str, object], ...]:
    """Assess supported patterns without changing ML or host baseline state."""
    return tuple(_r1(analysis) + _r2(analysis))
