"""Deterministic, payload-free offline captures for the Increment 3 demonstration."""

from __future__ import annotations

import hashlib
import json
import sys
from datetime import UTC, datetime
from pathlib import Path

from generate_phase4_fixtures import HOSTS, _alternating_flow, write_pcap


OFFSETS = (0, 15, 30, 46)
EXPECTED = (
    ("normal", "Accept", "WARMING", "warming", 0),
    ("normal", "Accept", "PROVISIONAL_BASELINE", "provisional", 1),
    ("gradual_drift", "Accept", "WITHIN_BAND", "provisional", 2),
    ("normal", "Accept", "WITHIN_BAND", "provisional", 3),
    ("normal", "Accept", "WITHIN_BAND", "ready", 4),
    *((("gradual_drift", "Accept", "WITHIN_BAND", "ready", i)
       for i in range(5, 9))),
    ("anchor_limit", "Hold", "ADAPTATION_LIMIT_REACHED", "ready", 8),
    ("moderate_deviation", "Hold", "NEW_PROTOCOL", "ready", 8),
    ("moderate_deviation", "Accept", "PROBATION_ADMITTED", "ready", 9),
    ("severe_deviation", "Reject", "SEVERE_BASELINE_DEVIATION", "ready", 9),
    ("high_flow", "Reject", "ML_HIGH", "ready", 9),
)


def _utc(seconds: float) -> str:
    return datetime.fromtimestamp(seconds, UTC).isoformat().replace("+00:00", "Z")


def _records(index: int) -> list[tuple[float, bytes]]:
    starts = (0, 6, 12, 18, 24, 30, 38, 46) if index == 12 else OFFSETS
    duration = 3.0 if 2 <= index <= 4 else 3.1 if 5 <= index <= 8 else 4.0 if index == 9 else 2.0
    records: list[tuple[float, bytes]] = []
    for flow_index, offset in enumerate(starts):
        protocol = (
            "UDP" if index in {10, 11} and flow_index == 3 else
            "ICMP" if index == 13 and flow_index == 3 else "TCP"
        )
        records.extend(_alternating_flow(
            start=600 + index * 60 + offset,
            duration=0.1 if protocol == "ICMP" else duration,
            packet_count=2,
            source=HOSTS[0],
            destination=HOSTS[1],
            protocol=protocol,
            source_port=None if protocol == "ICMP" else 45000 + flow_index,
            destination_port=None if protocol == "ICMP" else (
                53 if protocol == "UDP" else 443
            ),
        ))
    return records


def generate(output_directory: Path) -> dict[str, object]:
    """Write a new corpus; reject an occupied target before creating any files."""
    if output_directory.exists() and any(output_directory.iterdir()):
        raise FileExistsError(f"Refusing nonempty output directory: {output_directory}")
    output_directory.mkdir(parents=True, exist_ok=True)
    observations: list[dict[str, object]] = []
    for index, (behavior, decision, reason, readiness, version) in enumerate(EXPECTED):
        scenario_id = f"observation-{index:02d}"
        filename = f"{scenario_id}.pcap"
        records = _records(index)
        capture = write_pcap(output_directory / filename, records)
        raw = capture.read_bytes()
        start = 600 + index * 60
        observations.append({
            "capture_order": index,
            "scenario_id": scenario_id,
            "filename": filename,
            "capture_window_start": _utc(start),
            "capture_window_end": _utc(start + 60),
            "capture_first_timestamp": _utc(min(time for time, _ in records)),
            "capture_last_timestamp": _utc(max(time for time, _ in records)),
            "intended_behavior": behavior,
            "expected_flow_risk": "High incident flow" if index == 13 else "all Low",
            "expected_baseline": {
                "decision": decision,
                "reason": reason,
                "readiness": readiness,
                "version": version,
            },
            "expected_packet_count": len(records),
            "expected_flow_count": len(records) // 2,
            "expected_protocols": (
                ["TCP", "UDP"] if index in {10, 11} else
                ["TCP", "ICMP"] if index == 13 else ["TCP"]
            ),
            "sha256": hashlib.sha256(raw).hexdigest(),
        })
    manifest: dict[str, object] = {
        "schema_version": "increment3.demo.v1",
        "source": "REPLAYED DEMO TRAFFIC",
        "hosts": [HOSTS[0], HOSTS[1]],
        "training_fixture": "phase4-normal-training.pcap",
        "observations": observations,
    }
    (output_directory / "manifest.json").write_text(
        json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    return manifest


if __name__ == "__main__":
    if len(sys.argv) != 2:
        raise SystemExit("usage: generate_increment3_scenarios.py OUTPUT_DIRECTORY")
    generate(Path(sys.argv[1]))
