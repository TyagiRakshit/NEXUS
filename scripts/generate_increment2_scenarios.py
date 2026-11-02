"""Generate payload-free, comparable offline adaptive-baseline test captures."""

from __future__ import annotations

import json
import sys
from pathlib import Path

from generate_phase4_fixtures import HOSTS, _alternating_flow, write_pcap


def scenario_records(kind: str, minute_index: int) -> list[tuple[float, bytes]]:
    minute_start = 600 + minute_index * 60
    records: list[tuple[float, bytes]] = []
    for index, offset in enumerate((0, 15, 30, 46)):
        protocol = "ICMP" if kind == "anomalous" and index == 3 else "TCP"
        records.extend(
            _alternating_flow(
                start=minute_start + offset,
                duration=0.1 if protocol == "ICMP" else (
                    3.0 if kind == "gradual_drift" else 2.0
                ),
                packet_count=2,
                source=HOSTS[0],
                destination=HOSTS[1],
                protocol=protocol,
                source_port=None if protocol == "ICMP" else 45000 + index,
                destination_port=None if protocol == "ICMP" else 443,
            )
        )
    return records


def generate(output_directory: Path) -> dict[str, str]:
    output_directory.mkdir(parents=True, exist_ok=True)
    manifest: dict[str, str] = {}
    for minute_index, kind in enumerate(("normal", "gradual_drift", "anomalous")):
        filename = f"increment2-{minute_index}.pcap"
        write_pcap(
            output_directory / filename,
            scenario_records(kind, minute_index),
        )
        manifest[kind] = filename
    (output_directory / "manifest.json").write_text(
        json.dumps(manifest, sort_keys=True), encoding="utf-8"
    )
    return manifest


if __name__ == "__main__":
    if len(sys.argv) != 2:
        raise SystemExit("usage: generate_increment2_scenarios.py OUTPUT_DIRECTORY")
    generate(Path(sys.argv[1]))
