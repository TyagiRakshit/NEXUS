"""Increment 3 corpus contract through the real PCAP parser."""

from __future__ import annotations

import hashlib
import json
import subprocess
import sys
from pathlib import Path
from datetime import UTC, datetime


from app.pcap_analysis import analyze_pcap
from app.anomaly_detection import flow_to_raw_features


GENERATOR = Path("/app/scripts/generate_increment3_scenarios.py")
HOSTS = {"192.0.2.10", "198.51.100.20"}


def _generate(directory: Path) -> dict[str, object]:
    result = subprocess.run(
        [sys.executable, str(GENERATOR), str(directory)],
        capture_output=True, text=True, check=False,
    )
    assert result.returncode == 0, result.stderr
    return json.loads((directory / "manifest.json").read_text(encoding="utf-8"))


def test_increment3_bytes_and_manifest_are_deterministic(tmp_path: Path) -> None:
    first = _generate(tmp_path / "first")
    second = _generate(tmp_path / "second")
    assert first == second
    assert first["schema_version"] == "increment3.demo.v1"
    assert first["source"] == "REPLAYED DEMO TRAFFIC"
    assert len(first["observations"]) == 14
    assert [item["scenario_id"] for item in first["observations"]] == [
        f"observation-{index:02d}" for index in range(14)
    ]
    for item in first["observations"]:
        filename = item["filename"]
        assert filename == f"{item['scenario_id']}.pcap"
        assert Path(filename).name == filename
        capture = (tmp_path / "first" / filename).read_bytes()
        assert capture == (tmp_path / "second" / filename).read_bytes()
        assert hashlib.sha256(capture).hexdigest() == item["sha256"]
        assert b"REPLAYED DEMO TRAFFIC" not in capture
        assert item["scenario_id"].encode() not in capture
    print("INCREMENT3_CORPUS=" + json.dumps([{
        "id": item["scenario_id"], "sha256": item["sha256"],
        "bytes": (tmp_path / "first" / item["filename"]).stat().st_size,
    } for item in first["observations"]], sort_keys=True))


def test_increment3_real_parser_windows_hosts_and_protocols(tmp_path: Path) -> None:
    manifest = _generate(tmp_path / "corpus")
    seen_protocols: set[str] = set()
    for index, item in enumerate(manifest["observations"]):
        parsed = analyze_pcap(tmp_path / "corpus" / item["filename"])
        assert parsed.packet_count == item["expected_packet_count"]
        assert len(parsed.flows) == item["expected_flow_count"]
        assert parsed.packet_count in {8, 16}
        assert 45 <= parsed.capture_last_timestamp - parsed.capture_first_timestamp < 60
        assert int(parsed.capture_first_timestamp // 60) == 10 + index
        assert int(parsed.capture_last_timestamp // 60) == 10 + index
        assert item["capture_first_timestamp"] == datetime.fromtimestamp(
            parsed.capture_first_timestamp, UTC
        ).isoformat().replace("+00:00", "Z")
        assert item["capture_last_timestamp"] == datetime.fromtimestamp(
            parsed.capture_last_timestamp, UTC
        ).isoformat().replace("+00:00", "Z")
        assert item["capture_window_start"] == f"1970-01-01T00:{10 + index:02d}:00Z"
        assert item["capture_window_end"] == f"1970-01-01T00:{11 + index:02d}:00Z"
        assert {flow.source_ip for flow in parsed.flows} | {
            flow.destination_ip for flow in parsed.flows
        } == HOSTS
        protocols = {flow.protocol for flow in parsed.flows}
        seen_protocols.update(protocols)
        assert set(item["expected_protocols"]) == protocols
        if index in {10, 11}:
            udp = [flow for flow in parsed.flows if flow.protocol == "UDP"]
            assert len(udp) == 1
            assert {udp[0].source_port, udp[0].destination_port} == {45003, 53}
        if index == 13:
            assert len([flow for flow in parsed.flows if flow.protocol == "ICMP"]) == 1
    assert seen_protocols == {"TCP", "UDP", "ICMP"}


def test_increment3_refuses_nonempty_target_and_respects_upload_limits(
    tmp_path: Path,
) -> None:
    manifest = _generate(tmp_path / "corpus")
    for item in manifest["observations"]:
        capture = tmp_path / "corpus" / item["filename"]
        assert capture.stat().st_size <= 1_048_576
        assert analyze_pcap(capture).packet_count <= 2_000
    marker = tmp_path / "occupied" / "keep.txt"
    marker.parent.mkdir()
    marker.write_text("owner content", encoding="utf-8")
    result = subprocess.run(
        [sys.executable, str(GENERATOR), str(marker.parent)],
        capture_output=True, text=True, check=False,
    )
    assert result.returncode != 0
    assert marker.read_text(encoding="utf-8") == "owner content"
    assert sorted(path.name for path in marker.parent.iterdir()) == ["keep.txt"]


def test_increment3_distinct_captures_can_share_feature_values(tmp_path: Path) -> None:
    manifest = _generate(tmp_path / "corpus")
    first = tmp_path / "corpus" / manifest["observations"][0]["filename"]
    second = tmp_path / "corpus" / manifest["observations"][1]["filename"]
    assert first.read_bytes() != second.read_bytes()
    left, right = analyze_pcap(first), analyze_pcap(second)
    assert [flow_to_raw_features(flow).as_tuple() for flow in left.flows] == [
        flow_to_raw_features(flow).as_tuple() for flow in right.flows
    ]
