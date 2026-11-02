"""One deterministic, header-only final Hybrid demo capture; no network I/O."""

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
from generate_nexus_multihost_adaptive_demo import PRINCIPALS, SERVICES

ROOT = Path(__file__).resolve().parents[1]
SEED = 20261103
FILENAME = "nexus-final-hybrid-demo.pcap"
WINDOW_START = 7500  # The minute immediately after adaptive-04.
OFFSETS = (0, 15, 30, 46)


def _utc(seconds: float) -> str:
    return datetime.fromtimestamp(seconds, UTC).isoformat().replace("+00:00", "Z")


def _flows() -> list[Flow]:
    flows: list[Flow] = []
    for index, offset in enumerate(OFFSETS):
        flows.append(Flow(
            "TCP", PRINCIPALS["A"], SERVICES["A"],
            41000 + index, 443, offset, 2.3, 2,
        ))
        flows.append(Flow(
            "UDP", PRINCIPALS["B"], SERVICES["B"],
            42000 + index, 123, offset, 3.0, 3,
        ))
    for index, offset in enumerate((0, 6, 12, 18, 24, 30, 38, 46)):
        flows.append(Flow(
            "TCP", PRINCIPALS["C"], SERVICES["C"],
            43000 + index, 443, offset, 2.0, 2,
        ))
    # A short ICMP flow is statistically unusual under the fixed training PCAP.
    # Its incident endpoints are C and C's service, never A or B.
    flows.append(Flow(
        "ICMP", PRINCIPALS["C"], SERVICES["C"],
        None, None, 46, 0.1, 2,
    ))
    sweep_left, sweep_right = "203.0.113.40", "203.0.113.41"
    for index, offset in enumerate((0, 8, 16, 24, 32, 46)):
        flows.append(Flow(
            "TCP", sweep_left, sweep_right,
            44000 + index, 100 + index, offset, 2.0, 2,
        ))
    recon_focal = "203.0.113.50"
    for index, offset in enumerate((0, 9, 18, 27, 46)):
        flows.append(Flow(
            "UDP", recon_focal, f"203.0.113.{60 + index}",
            45000 + index, 123, offset, 2.0, 2,
        ))
    return flows


def generate(output_directory: Path) -> dict[str, object]:
    """Create only in an empty target; never overwrite another corpus."""
    if output_directory.exists() and any(output_directory.iterdir()):
        raise FileExistsError(f"Refusing nonempty output directory: {output_directory}")
    output_directory.mkdir(parents=True, exist_ok=True)
    flows = _flows()
    records = _records(flows, WINDOW_START, random.Random(SEED))
    capture = write_pcap(output_directory / FILENAME, records)
    raw = capture.read_bytes()
    if len(raw) > 1_048_576 or len(records) > 2_000:
        raise ValueError("Final capture exceeds existing upload limits")
    manifest: dict[str, object] = {
        "schema_version": "nexus.final-hybrid-demo.v1",
        "source": "REPLAYED DEMO TRAFFIC",
        "seed": SEED,
        "filename": FILENAME,
        "starting_checkpoint": "adaptive-00..04 Hybrid, Ready v4",
        "preparation_files": [f"adaptive-{index:02d}.pcap" for index in range(5)],
        "capture_window_start": _utc(WINDOW_START),
        "capture_window_end": _utc(WINDOW_START + 60),
        "capture_start": _utc(min(time for time, _ in records)),
        "capture_end": _utc(max(time for time, _ in records)),
        "sha256": hashlib.sha256(raw).hexdigest(),
        "size_bytes": len(raw),
        "packet_count": len(records),
        "flow_count": len(flows),
        "protocol_distribution": dict(sorted(Counter(
            flow.protocol for flow in flows
        ).items())),
        "principal_hosts": PRINCIPALS,
        "traffic_groups": {
            "A_legitimate": {"hosts": [PRINCIPALS["A"], SERVICES["A"]], "flow_count": 4},
            "B_stable": {"hosts": [PRINCIPALS["B"], SERVICES["B"]], "flow_count": 4},
            "C_suspicious": {"hosts": [PRINCIPALS["C"], SERVICES["C"]], "flow_count": 9},
            "R1_possible_port_sweep": {"hosts": ["203.0.113.40", "203.0.113.41"], "flow_count": 6},
            "R2_possible_host_recon": {"focal_host": "203.0.113.50", "flow_count": 5},
        },
        "intended_outcomes": {
            "A": "Accept Ready v5 with increased mean-duration baseline",
            "B": "Accept Ready v5 with stable baseline",
            "C": "Reject Ready v4 with unchanged baseline and High ML evidence",
            "rules": ["R1 Match", "R2 Match"],
            "telemetry": "manual v1 and v2 protection/verification/tamper rejection",
        },
        "actual": None,
        "validation_status": "NOT VERIFIED",
    }
    (output_directory / "manifest.json").write_text(
        json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    with (output_directory / "expected-vs-actual.csv").open(
        "w", newline="", encoding="utf-8"
    ) as handle:
        writer = csv.DictWriter(handle, fieldnames=[
            "source", "intended", "actual", "validation_status",
        ])
        writer.writeheader()
        for source, intended in manifest["intended_outcomes"].items():
            writer.writerow({
                "source": source, "intended": intended,
                "validation_status": "NOT VERIFIED",
            })
    return manifest


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Generate one offline, payload-free NEXUS Hybrid demo PCAP."
    )
    parser.add_argument(
        "output_directory", nargs="?", type=Path,
        default=ROOT / "data" / "nexus-final-demo",
    )
    arguments = parser.parse_args()
    result = generate(arguments.output_directory)
    print(f"Generated {result['filename']} ({result['size_bytes']} bytes)")


if __name__ == "__main__":
    main()

