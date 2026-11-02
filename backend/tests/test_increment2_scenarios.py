import json
import subprocess
import sys
from pathlib import Path

from app.pcap_analysis import analyze_pcap


def test_real_parser_scenarios_have_comparable_windows_and_external_labels(
    tmp_path: Path,
) -> None:
    script = Path("/app/scripts/generate_increment2_scenarios.py")
    result = subprocess.run(
        [sys.executable, str(script), str(tmp_path)],
        capture_output=True, text=True, check=False,
    )
    assert result.returncode == 0, result.stderr
    manifest = json.loads((tmp_path / "manifest.json").read_text())
    assert set(manifest) == {"normal", "gradual_drift", "anomalous"}
    for name, filename in manifest.items():
        path = tmp_path / filename
        parsed = analyze_pcap(path)
        assert parsed.packet_count >= 8
        assert len(parsed.flows) >= 4
        assert parsed.capture_last_timestamp - parsed.capture_first_timestamp >= 45
        assert int(parsed.capture_first_timestamp // 60) == int(
            parsed.capture_last_timestamp // 60
        )
        assert {
            flow.source_ip for flow in parsed.flows
        } | {
            flow.destination_ip for flow in parsed.flows
        } == {"192.0.2.10", "198.51.100.20"}
        assert name.encode() not in path.read_bytes()
