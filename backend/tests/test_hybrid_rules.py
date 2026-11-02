from app.hybrid_rules import evaluate_rules
from app.pcap_analysis import AnalysisResult, FlowSummary


def test_port_sweep_matches_exact_metadata_boundary_without_attributing_actor() -> None:
    flows = tuple(
        FlowSummary(
            "TCP", "192.0.2.10", 40000 + index,
            "198.51.100.20", 100 + index,
            2, 108, 1.0, 2.0, 108.0,
        )
        for index in range(6)
    )
    analysis = AnalysisResult(
        packet_count=12,
        flows=flows,
        capture_first_timestamp=600.0,
        capture_last_timestamp=631.0,
        flow_time_bounds=tuple((600.0 + 6 * i, 601.0 + 6 * i) for i in range(6)),
    )
    matches = [
        item for item in evaluate_rules(analysis)
        if item["rule_id"] == "R1" and item["status"] == "Match"
    ]
    assert len(matches) == 1
    assert matches[0]["rule_evidence_strength"] == 60
    assert matches[0]["subject_host_ips"] == ["192.0.2.10", "198.51.100.20"]
    assert matches[0]["affected_host_ips"] == ["192.0.2.10", "198.51.100.20"]
    assert matches[0]["flow_indices"] == list(range(6))
    assert "attacker" not in matches[0]["explanation"].lower()

def _traffic(
    *, count: int, protocol: str = "TCP", peer_count: int = 1,
    peer_port_base: int = 100, focal_port_count: int | None = None,
    start_count: int | None = None,
) -> AnalysisResult:
    flows = []
    bounds = []
    for index in range(count):
        peer = f"198.51.100.{20 + index % peer_count}"
        focal_port = 40000 + index % (focal_port_count or count)
        peer_port = peer_port_base + index if peer_count == 1 else peer_port_base
        flows.append(FlowSummary(
            protocol, "192.0.2.10", focal_port, peer, peer_port,
            2, 108, 1.0, 2.0, 108.0,
        ))
        start = 600.0 + 5 * (index % (start_count or count))
        bounds.append((start, start + 1))
    return AnalysisResult(
        packet_count=2 * count, flows=tuple(flows),
        capture_first_timestamp=600.0, capture_last_timestamp=630.0,
        flow_time_bounds=tuple(bounds),
    )


def _assessment(analysis: AnalysisResult, rule: str) -> dict[str, object]:
    return next(item for item in evaluate_rules(analysis) if item["rule_id"] == rule)


def test_port_sweep_boundary_distinguishes_unknown_from_adequate_nonmatch() -> None:
    assert _assessment(_traffic(count=5), "R1")["status"] == "Unknown"
    assert _assessment(_traffic(count=6, focal_port_count=3), "R1")["status"] == "NoPatternMatchedInObservedMetadata"
    assert _assessment(_traffic(count=6, start_count=2), "R1")["status"] == "Unknown"
    assert _assessment(_traffic(count=7), "R1")["rule_evidence_strength"] == 65
    assert _assessment(_traffic(count=12), "R1")["rule_evidence_strength"] == 90


def test_host_recon_matches_focal_host_only_at_exact_boundary() -> None:
    result = _assessment(_traffic(
        count=5, peer_count=5, peer_port_base=443, focal_port_count=4,
        protocol="UDP",
    ), "R2")
    assert result["status"] == "Match"
    assert result["rule_evidence_strength"] == 60
    assert result["affected_host_ips"] == ["192.0.2.10"]
    assert result["subject_host_ips"] == ["192.0.2.10"]
    assert len(result["evidence"]["peer_ips"]) == 5


def test_host_recon_rejects_sparse_and_mixed_protocol_evidence() -> None:
    assert _assessment(_traffic(count=4, peer_count=4), "R2")["status"] == "Unknown"
    assert _assessment(_traffic(count=5, peer_count=5, focal_port_count=3), "R2")["status"] == "NoPatternMatchedInObservedMetadata"
    assert _assessment(_traffic(count=5, peer_count=5, start_count=2), "R2")["status"] == "Unknown"
    mixed = _traffic(count=5, peer_count=5)
    flows = list(mixed.flows)
    flow = flows[-1]
    flows[-1] = FlowSummary(
        "UDP", flow.source_ip, flow.source_port, flow.destination_ip,
        flow.destination_port, flow.packet_count, flow.byte_count,
        flow.duration_seconds, flow.packets_per_second, flow.bytes_per_second,
    )
    mixed = AnalysisResult(
        packet_count=mixed.packet_count, flows=tuple(flows),
        flow_time_bounds=mixed.flow_time_bounds,
    )
    assert all(
        item["status"] != "Match"
        for item in evaluate_rules(mixed) if item["rule_id"] == "R2"
    )


def test_r1_port_diversity_and_input_order_boundaries() -> None:
    complete = _traffic(count=6)
    flows = list(complete.flows)
    last = flows[-1]
    flows[-1] = FlowSummary(
        last.protocol, last.source_ip, flows[-2].source_port,
        last.destination_ip, flows[-2].destination_port,
        last.packet_count, last.byte_count, last.duration_seconds,
        last.packets_per_second, last.bytes_per_second,
    )
    five_ports = AnalysisResult(
        packet_count=complete.packet_count, flows=tuple(flows),
        flow_time_bounds=complete.flow_time_bounds,
    )
    assert _assessment(five_ports, "R1")["status"] == "NoPatternMatchedInObservedMetadata"
    reversed_order = AnalysisResult(
        packet_count=complete.packet_count, flows=tuple(reversed(complete.flows)),
        flow_time_bounds=tuple(reversed(complete.flow_time_bounds)),
    )
    assert _assessment(reversed_order, "R1")["status"] == "Match"
    assert _assessment(reversed_order, "R1")["rule_evidence_strength"] == 60


def test_r2_score_growth_cap_and_icmp_unknown() -> None:
    assert _assessment(_traffic(count=6, peer_count=6), "R2")["rule_evidence_strength"] == 65
    assert _assessment(_traffic(count=11, peer_count=11), "R2")["rule_evidence_strength"] == 90
    icmp = _traffic(count=6, peer_count=6, protocol="ICMP")
    assert all(item["status"] == "Unknown" for item in evaluate_rules(icmp))


def test_packet_orientation_cannot_create_actor_claim_or_server_fan_in_match() -> None:
    original = _traffic(count=6)
    reversed_flows = tuple(FlowSummary(
        flow.protocol, flow.destination_ip, flow.destination_port,
        flow.source_ip, flow.source_port, flow.packet_count,
        flow.byte_count, flow.duration_seconds,
        flow.packets_per_second, flow.bytes_per_second,
    ) for flow in original.flows)
    reversed_capture = AnalysisResult(
        packet_count=original.packet_count, flows=reversed_flows,
        flow_time_bounds=original.flow_time_bounds,
    )
    match = _assessment(reversed_capture, "R1")
    assert match["status"] == "Match"
    assert match["subject_host_ips"] == ["192.0.2.10", "198.51.100.20"]
    assert "attacker" not in match["explanation"].lower()

    fan_in = _traffic(count=5, peer_count=5)
    fan_in_flows = tuple(FlowSummary(
        flow.protocol, flow.destination_ip, flow.source_port,
        "192.0.2.10", 443, flow.packet_count,
        flow.byte_count, flow.duration_seconds,
        flow.packets_per_second, flow.bytes_per_second,
    ) for flow in fan_in.flows)
    fan_in_capture = AnalysisResult(
        packet_count=fan_in.packet_count, flows=fan_in_flows,
        flow_time_bounds=fan_in.flow_time_bounds,
    )
    assert all(item["status"] != "Match" for item in evaluate_rules(fan_in_capture))
