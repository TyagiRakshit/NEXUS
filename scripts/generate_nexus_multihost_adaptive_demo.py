"""Seven deterministic header-only captures for independent host baselines."""

from __future__ import annotations

import argparse
import csv
import hashlib
import json
import random
from collections import Counter
from datetime import UTC, datetime
from pathlib import Path

from generate_nexus_evaluation_corpus import Flow, _records
from generate_phase4_fixtures import write_pcap

ROOT = Path(__file__).resolve().parents[1]
SEED = 20261102
PRINCIPALS = {
    "A": "192.0.2.10",
    "B": "198.51.100.20",
    "C": "203.0.113.30",
}
SERVICES = {
    "A": "192.0.2.200",
    "B": "198.51.100.200",
    "C": "203.0.113.200",
}
OFFSETS = (0, 15, 30, 46)


def _utc(seconds: float) -> str:
    return datetime.fromtimestamp(seconds, UTC).isoformat().replace("+00:00", "Z")


def _flows(index: int) -> list[Flow]:
    a_duration = 2.0 if index < 5 else 2.3 if index == 5 else 2.6
    flows: list[Flow] = []
    for number, offset in enumerate(OFFSETS):
        flows.append(Flow(
            "TCP", PRINCIPALS["A"], SERVICES["A"],
            41000 + number, 443, offset, a_duration, 2,
        ))
        flows.append(Flow(
            "UDP", PRINCIPALS["B"], SERVICES["B"],
            42000 + number, 123, offset, 3.0, 3,
        ))
    c_offsets = (0, 6, 12, 18, 24, 30, 38, 46) if index == 6 else OFFSETS
    for number, offset in enumerate(c_offsets):
        flows.append(Flow(
            "TCP", PRINCIPALS["C"], SERVICES["C"],
            43000 + number, 443, offset, 2.0, 2,
        ))
    return flows


def generate(output_directory: Path) -> dict[str, object]:
    """Refuse nonempty output; do not modify other fixtures or corpora."""
    if output_directory.exists() and any(output_directory.iterdir()):
        raise FileExistsError(f"Refusing nonempty output directory: {output_directory}")
    output_directory.mkdir(parents=True, exist_ok=True)
    captures = []
    for index in range(7):
        flows = _flows(index)
        start = 7200 + 60 * index
        records = _records(flows, start, random.Random(SEED + index))
        filename = f"adaptive-{index:02d}.pcap"
        path = write_pcap(output_directory / filename, records)
        raw = path.read_bytes()
        if len(raw) > 1_048_576 or len(records) > 2_000:
            raise ValueError(f"Generated capture exceeds upload bounds: {filename}")
        expected = {
            role: {
                "decision": "Reject" if role == "C" and index == 6 else "Accept",
                "reason": (
                    "SEVERE_BASELINE_DEVIATION" if role == "C" and index == 6
                    else "WARMING" if index == 0
                    else "PROVISIONAL_BASELINE" if index == 1
                    else "WITHIN_BAND"
                ),
                "readiness": (
                    "warming" if index == 0 else "provisional" if index < 4
                    else "ready"
                ),
                "version": 5 if role == "C" and index == 6 else index,
            } for role in PRINCIPALS
        }
        captures.append({
            "scenario_id": f"adaptive-{index:02d}",
            "filename": filename,
            "presentation_phase": "preparation" if index < 5 else "live",
            "capture_order": index,
            "capture_window_start": _utc(start),
            "capture_window_end": _utc(start + 60),
            "capture_start": _utc(min(time for time, _ in records)),
            "capture_end": _utc(max(time for time, _ in records)),
            "packet_count": len(records),
            "flow_count": len(flows),
            "protocol_distribution": dict(sorted(Counter(
                flow.protocol for flow in flows
            ).items())),
            "principal_hosts": list(PRINCIPALS.values()),
            "sha256": hashlib.sha256(raw).hexdigest(),
            "intended_scenario": (
                "all hosts establish independent baselines" if index < 5
                else "A gradually adapts, B stays stable, C stays stable"
                if index == 5 else
                "A adapts again, B stays stable, C has severe host-only deviation"
            ),
            "intended_host_outcome": expected,
            "expected_high_rule_matches": [],
            "actual_legacy": None,
            "actual_hybrid": None,
            "validation_status": "NOT VERIFIED",
        })
    manifest: dict[str, object] = {
        "schema_version": "nexus.multihost-adaptive-demo.v1",
        "source": "REPLAYED DEMO TRAFFIC",
        "seed": SEED,
        "training_fixture": "phase4-normal-training.pcap",
        "principal_hosts": list(PRINCIPALS.values()),
        "service_endpoints": list(SERVICES.values()),
        "captures": captures,
    }
    (output_directory / "manifest.json").write_text(
        json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    with (output_directory / "expected-vs-actual.csv").open(
        "w", newline="", encoding="utf-8"
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
                "validation_status": "NOT VERIFIED",
            })
    return manifest


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Generate seven separate multi-host, offline, header-only PCAPs."
    )
    parser.add_argument(
        "output_directory", nargs="?", type=Path,
        default=ROOT / "data" / "nexus-multihost-adaptive-demo",
    )
    args = parser.parse_args()
    manifest = generate(args.output_directory)
    print(f"Generated {len(manifest['captures'])} captures in {args.output_directory}")


if __name__ == "__main__":
    main()

