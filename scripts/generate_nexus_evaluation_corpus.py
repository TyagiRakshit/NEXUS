"""Deterministic header-only synthetic PCAP corpus; never sends network traffic."""

from __future__ import annotations

import argparse
import csv
import hashlib
import ipaddress
import json
import random
import struct
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path

from generate_increment3_scenarios import EXPECTED as ADAPTIVE_EXPECTED
from generate_increment3_scenarios import _records as adaptive_records
from generate_phase4_fixtures import checksum, ipv4_packet, write_pcap

SEED = 20261102
HOST_A = "192.0.2.10"
HOST_B = "198.51.100.20"
MAX_BYTES = 1_048_576
MAX_PACKETS = 2_000
ROOT = Path(__file__).resolve().parents[1]


@dataclass(frozen=True)
class Flow:
    protocol: str
    source: str
    destination: str
    source_port: int | None
    destination_port: int | None
    start_offset: float
    duration: float = 2.0
    packets: int = 2


def _mac(ip: str) -> bytes:
    return b"\x02" + hashlib.sha256(ip.encode("ascii")).digest()[:5]


def _transport_frame(flow: Flow, packet_index: int, flow_index: int) -> bytes:
    reverse = packet_index % 2 == 1
    source, destination = (
        (flow.destination, flow.source) if reverse else
        (flow.source, flow.destination)
    )
    source_port, destination_port = (
        (flow.destination_port, flow.source_port) if reverse else
        (flow.source_port, flow.destination_port)
    )
    if flow.protocol == "TCP":
        # Header-only SYN/SYN-ACK/ACK-like exchange, not a complete session.
        options = b"\x02\x04\x05\xb4" if packet_index == 0 and flow_index % 2 == 0 else b""
        flags = 0x02 if packet_index == 0 else 0x12 if packet_index == 1 else 0x10
        first_seq, peer_seq = 1000 + flow_index * 17, 5000 + flow_index * 19
        sequence = (peer_seq if packet_index == 1 else peer_seq + 1) if reverse else (
            first_seq if packet_index == 0 else first_seq + 1
        )
        acknowledgement = 0 if packet_index == 0 else (
            first_seq + 1 if reverse else peer_seq + 1
        )
        header = struct.pack(
            "!HHIIBBHHH", int(source_port), int(destination_port),
            sequence, acknowledgement, (5 + len(options) // 4) << 4,
            flags, 8192, 0, 0,
        ) + options
        protocol = 6
    elif flow.protocol == "UDP":
        header = struct.pack(
            "!HHHH", int(source_port), int(destination_port), 8, 0
        )
        protocol = 17
    else:
        header = struct.pack(
            "!BBHHH", 0 if reverse else 8, 0, 0, flow_index + 1, packet_index + 1
        )
        header = header[:2] + struct.pack("!H", checksum(header)) + header[4:]
        protocol = 1
    if protocol in {6, 17}:
        pseudo = (
            ipaddress.IPv4Address(source).packed
            + ipaddress.IPv4Address(destination).packed
            + struct.pack("!BBH", 0, protocol, len(header))
        )
        value = checksum(pseudo + header)
        header = header[:16] + struct.pack("!H", value) + header[18:] if protocol == 6 else (
            header[:6] + struct.pack("!H", value or 0xFFFF)
        )
    ip = ipv4_packet(source, destination, protocol, header)
    return _mac(destination) + _mac(source) + struct.pack("!H", 0x0800) + ip


def _records(flows: list[Flow], window_start: int, rng: random.Random) -> list[tuple[float, bytes]]:
    records: list[tuple[float, bytes]] = []
    for flow_index, flow in enumerate(flows):
        shape = rng.choice((0.85, 1.0, 1.15))
        for packet_index in range(flow.packets):
            fraction = (packet_index / (flow.packets - 1)) ** shape
            when = window_start + flow.start_offset + flow.duration * fraction
            records.append((
                when, _transport_frame(flow, packet_index, flow_index)
            ))
    return sorted(records, key=lambda record: record[0])


def _regular(protocol: str, count: int, rng: random.Random) -> list[Flow]:
    destinations = (443, 80, 443, 8443, 443, 123)
    flows = []
    for index in range(count):
        current = protocol if protocol != "MIXED" else (
            "TCP" if index < 3 else "UDP" if index < 5 else "ICMP"
        )
        flows.append(Flow(
            current, HOST_A, HOST_B,
            None if current == "ICMP" else 40000 + index,
            None if current == "ICMP" else (
                destinations[index] if current == "TCP" else 53 if index % 2 else 123
            ),
            (0, 11, 22, 33, 46, 50)[index],
            float(rng.choice((1.5, 2.0, 3.0))),
            rng.choice((2, 3, 4)),
        ))
    return flows


def _sweep(count: int, *, below: bool = False) -> list[Flow]:
    return [
        Flow("TCP", HOST_A, HOST_B,
             42000 + index if not below or index < count - 1 else 42000,
             100 + index if not below or index < count - 1 else 101,
             (0, 8, 16, 24, 32, 40, 48)[index])
        for index in range(count)
    ]


def _recon(count: int, *, below: bool = False) -> list[Flow]:
    return [
        Flow("UDP", HOST_A,
             f"198.51.100.{20 + (index if not below or index < count - 1 else index - 1)}",
             43000 + index, 443, (0, 9, 18, 27, 36, 45)[index])
        for index in range(count)
    ]


def _specifications() -> list[tuple[str, list[Flow], str, str, dict[str, object]]]:
    rng = random.Random(SEED)
    tcp = _regular("TCP", 5, rng)
    udp = _regular("UDP", 5, rng)
    mixed = _regular("MIXED", 6, rng)
    normal = [
        ("normal/normal-tcp.pcap", tcp, "ordinary-intent", "TCP-dominant header-only exchange", {}),
        ("normal/normal-udp.pcap", udp, "ordinary-intent", "UDP-dominant header-only exchange", {}),
        ("normal/normal-mixed.pcap", mixed, "ordinary-intent", "Mixed TCP, UDP and ICMP header-only exchange", {}),
    ]
    short = [
        Flow("TCP", HOST_A, HOST_B, 44000 + i, 443, 15 * i, 0.05, 2)
        for i in range(4)
    ]
    rate = [
        Flow("TCP", HOST_A, HOST_B, 45000 + i, 443,
             (0, 15, 30, 46)[i], 0.1 if i == 0 else 2.0,
             40 if i == 0 else 3)
        for i in range(4)
    ]
    volume = [
        Flow("TCP", HOST_A, HOST_B, 46000 + i, 443,
             (0, 15, 30, 46)[i], 45.0 if i == 0 else 2.0,
             180 if i == 0 else 3)
        for i in range(4)
    ]
    mixed_anomaly = [
        Flow("TCP", HOST_A, HOST_B, 47000, 443, 0, 2, 3),
        Flow("UDP", HOST_A, HOST_B, 47001, 123, 15, 3, 2),
        Flow("TCP", HOST_A, HOST_B, 47002, 443, 30, 0.1, 40),
        Flow("ICMP", HOST_A, HOST_B, None, None, 46, 0.1, 2),
    ]
    anomalies = [
        ("anomalies/unusual-short-flows.pcap", short, "unusual-intent", "Very short flow durations", {}),
        ("anomalies/unusual-packet-rate.pcap", rate, "unusual-intent", "High packet rate in one flow", {}),
        ("anomalies/unusual-flow-volume.pcap", volume, "unusual-intent", "Unusual packet and byte count", {}),
        ("anomalies/mixed-normal-anomalous.pcap", mixed_anomaly, "unusual-intent", "Mixed ordinary and unusual metadata", {}),
    ]
    rules = [
        ("security-rules/port-sweep-match.pcap", _sweep(6), {"R1": ["Match", 60]}),
        ("security-rules/port-sweep-nonmatch.pcap", _sweep(6, below=True), {"R1": ["NoPatternMatchedInObservedMetadata", 0]}),
        ("security-rules/port-sweep-above.pcap", _sweep(7), {"R1": ["Match", 65]}),
        ("security-rules/reconnaissance-match.pcap", _recon(5), {"R2": ["Match", 60]}),
        ("security-rules/reconnaissance-nonmatch.pcap", _recon(5, below=True), {"R2": ["NoPatternMatchedInObservedMetadata", 0]}),
        ("security-rules/reconnaissance-above.pcap", _recon(6), {"R2": ["Match", 65]}),
        ("security-rules/sparse-evidence.pcap", [Flow("TCP", HOST_A, HOST_B, 48000, 443, 0), Flow("UDP", HOST_A, HOST_B, 48001, 123, 46)], {"R1": ["Unknown", None], "R2": ["Unknown", None]}),
        ("security-rules/combined-rule-evidence.pcap", _sweep(6) + _recon(5), {"R1": ["Match", 60], "R2": ["Match", 60]}),
    ]
    return normal + anomalies + [
        (path, flows, "rule-boundary", "Metadata-only rule boundary", expected)
        for path, flows, expected in rules
    ]


def _utc(seconds: float) -> str:
    return datetime.fromtimestamp(seconds, UTC).isoformat().replace("+00:00", "Z")


def generate(output_directory: Path) -> dict[str, object]:
    """Create only in an empty target; preserve any existing corpus or owner files."""
    if output_directory.exists() and any(output_directory.iterdir()):
        raise FileExistsError(f"Refusing nonempty output directory: {output_directory}")
    output_directory.mkdir(parents=True, exist_ok=True)
    entries: list[dict[str, object]] = []
    for number, (relative, flows, label, intent, expected_rules) in enumerate(_specifications()):
        start = 3600 + number * 60
        records = _records(flows, start, random.Random(SEED + number))
        path = write_pcap(output_directory / relative, records)
        raw = path.read_bytes()
        if len(raw) > MAX_BYTES or len(records) > MAX_PACKETS:
            raise ValueError(f"Generated capture exceeds upload limits: {relative}")
        distribution = {
            protocol: sum(flow.protocol == protocol for flow in flows)
            for protocol in sorted({flow.protocol for flow in flows})
        }
        entries.append({
            "scenario_id": path.stem, "filename": relative, "capture_order": number,
            "capture_start": _utc(min(when for when, _ in records)),
            "capture_end": _utc(max(when for when, _ in records)),
            "capture_window_start": _utc(start),
            "capture_window_end": _utc(start + 60),
            "packet_count": len(records), "flow_count": len(flows),
            "protocol_distribution": distribution,
            "sha256": hashlib.sha256(raw).hexdigest(),
            "intended_behavior": intent, "independent_label": label,
            "expected_rule_outcome": expected_rules,
            "expected_baseline_transition": None,
            "actual_model_outcome": None, "actual_rule_outcome": None,
            "actual_baseline_transition": None, "validation_status": "NOT VERIFIED",
            "limitations": ["Synthetic header-only packets; not a complete application session."],
        })
    for index, (behavior, decision, reason, readiness, version) in enumerate(ADAPTIVE_EXPECTED):
        relative = f"adaptive/adaptive-{index:02d}.pcap"
        records = adaptive_records(index)
        path = write_pcap(output_directory / relative, records)
        raw = path.read_bytes()
        if len(raw) > MAX_BYTES or len(records) > MAX_PACKETS:
            raise ValueError(f"Generated capture exceeds upload limits: {relative}")
        if index == 12:
            protocols = {"TCP": 8}
        elif index in {10, 11}:
            protocols = {"TCP": 3, "UDP": 1}
        elif index == 13:
            protocols = {"TCP": 3, "ICMP": 1}
        else:
            protocols = {"TCP": 4}
        entries.append({
            "scenario_id": f"adaptive-{index:02d}", "filename": relative,
            "capture_order": index,
            "capture_start": _utc(min(when for when, _ in records)),
            "capture_end": _utc(max(when for when, _ in records)),
            "capture_window_start": _utc(600 + index * 60),
            "capture_window_end": _utc(660 + index * 60),
            "packet_count": len(records),
            "flow_count": len(records) // 2,
            "protocol_distribution": protocols,
            "sha256": hashlib.sha256(raw).hexdigest(),
            "intended_behavior": behavior, "independent_label": "adaptive-demo",
            "expected_rule_outcome": {},
            "expected_baseline_transition": {
                "decision": decision, "reason": reason,
                "readiness": readiness, "version": version,
            },
            "actual_model_outcome": None, "actual_rule_outcome": None,
            "actual_baseline_transition": None, "validation_status": "NOT VERIFIED",
            "limitations": ["Reused accepted Increment 3 header-only observation; in-memory learning only."],
        })
    manifest: dict[str, object] = {
        "schema_version": "nexus.evaluation-corpus.v1",
        "source": "REPLAYED DEMO TRAFFIC",
        "seed": SEED,
        "training_fixture": "phase4-normal-training.pcap",
        "scenarios": entries,
    }
    (output_directory / "manifest.json").write_text(
        json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    with (output_directory / "expected-vs-actual.csv").open(
        "w", newline="", encoding="utf-8"
    ) as handle:
        writer = csv.DictWriter(handle, fieldnames=[
            "scenario_id", "filename", "independent_label", "intended_behavior",
            "expected_rule_outcome", "expected_baseline_transition",
            "actual_high_flows", "actual_low_flows", "actual_rule_matches",
            "actual_baseline_transition", "validation_status",
        ])
        writer.writeheader()
        for entry in entries:
            writer.writerow({
                "scenario_id": entry["scenario_id"],
                "filename": entry["filename"],
                "independent_label": entry["independent_label"],
                "intended_behavior": entry["intended_behavior"],
                "expected_rule_outcome": json.dumps(entry["expected_rule_outcome"], sort_keys=True),
                "expected_baseline_transition": json.dumps(entry["expected_baseline_transition"], sort_keys=True),
                "validation_status": "NOT VERIFIED",
            })
    return manifest


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Generate offline header-only NEXUS evaluation PCAPs in an empty directory."
    )
    parser.add_argument(
        "output_directory", nargs="?", type=Path,
        default=ROOT / "data" / "nexus-evaluation-corpus",
    )
    args = parser.parse_args()
    result = generate(args.output_directory)
    print(f"Generated {len(result['scenarios'])} synthetic PCAPs in {args.output_directory}")


if __name__ == "__main__":
    main()
