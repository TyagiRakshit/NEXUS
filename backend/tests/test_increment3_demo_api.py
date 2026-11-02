"""Real parser -> fixed model -> guarded baseline -> manual telemetry demo."""

from __future__ import annotations

import hashlib
import json
import os
import subprocess
import sys
from pathlib import Path

import anyio
import httpx
import pytest

from app.adaptive_baseline import AdaptiveBaselineStore, ScoredObservationRegistry
from app.main import app
from app.secure_telemetry import SecureTelemetryStore


HOSTS = ("192.0.2.10", "198.51.100.20")
EXPECTED = (
    ("Accept", 0, "warming"),
    ("Accept", 1, "provisional"),
    ("Accept", 2, "provisional"),
    ("Accept", 3, "provisional"),
    ("Accept", 4, "ready"),
    *((("Accept", version, "ready") for version in range(5, 9))),
    ("Hold", 8, "ready"),
    ("Hold", 8, "ready"),
    ("Accept", 9, "ready"),
    ("Reject", 9, "ready"),
    ("Reject", 9, "ready"),
)


@pytest.mark.skipif(
    "NEXUS_TEST_PHASE4_NORMAL_PCAP_PATH" not in os.environ,
    reason="fixed Phase 4 training PCAP is not mounted",
)
def test_increment3_real_api_sequence_and_manual_telemetry(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path,
) -> None:
    generated = subprocess.run(
        [sys.executable, "/app/scripts/generate_increment3_scenarios.py",
         str(tmp_path / "corpus")],
        capture_output=True, text=True, check=False,
    )
    assert generated.returncode == 0, generated.stderr
    manifest = json.loads((tmp_path / "corpus" / "manifest.json").read_text())
    training_path = Path(os.environ["NEXUS_TEST_PHASE4_NORMAL_PCAP_PATH"])
    assert hashlib.sha256(training_path.read_bytes()).hexdigest() not in {
        item["sha256"] for item in manifest["observations"]
    }
    monkeypatch.setenv("NEXUS_DETECTION_TRAINING_PCAP_PATH", str(training_path))
    registry = ScoredObservationRegistry()
    baselines = AdaptiveBaselineStore()
    evidence = tmp_path / "evidence"
    monkeypatch.setattr("app.main.scored_observation_registry", registry)
    monkeypatch.setattr("app.main.adaptive_baseline_store", baselines)
    monkeypatch.setattr(
        "app.main.secure_telemetry_store",
        SecureTelemetryStore(
            key_directory=tmp_path / "keys", evidence_directory=evidence,
        ),
    )

    async def run() -> None:
        transport = httpx.ASGITransport(app=app)
        async with httpx.AsyncClient(
            transport=transport, base_url="http://testserver",
        ) as client:
            ledger: list[dict[str, object]] = []
            epoch = None
            first_analysis_id = None
            for index, item in enumerate(manifest["observations"]):
                assert item["expected_baseline"] == {
                    "decision": EXPECTED[index][0],
                    "reason": item["expected_baseline"]["reason"],
                    "readiness": EXPECTED[index][2],
                    "version": EXPECTED[index][1],
                }
                capture = (tmp_path / "corpus" / item["filename"]).read_bytes()
                uploaded = await client.post(
                    "/api/v1/demo/upload/analyze",
                    files={"file": (
                        item["filename"], capture, "application/vnd.tcpdump.pcap",
                    )},
                )
                assert uploaded.status_code == 200, uploaded.text
                body = uploaded.json()
                assert body["source"] == "REPLAYED DEMO TRAFFIC"
                assert body["packet_count"] == item["expected_packet_count"]
                assert body["flow_count"] == item["expected_flow_count"]
                assert body["model"]["training_flow_count"] == 48
                assert body["model"]["feature_count"] == 11
                assert body["model"]["model_type"] == "IsolationForest"
                analysis_id = body["analysis_id"]
                evaluated = await client.post(
                    "/api/v1/demo/baselines/evaluate",
                    json={"analysis_id": analysis_id},
                )
                assert evaluated.status_code == 200, evaluated.text
                result = evaluated.json()
                if epoch is None:
                    epoch = result["baseline_store_epoch"]
                assert result["baseline_store_epoch"] == epoch
                assert result["capture_window_start"] == item["capture_window_start"]
                assert result["capture_window_end"] == item["capture_window_end"]
                assert result["capture_fingerprint_status"] == "new"
                risks = [flow["risk_level"] for flow in body["results"]]
                if index < 13:
                    assert risks == ["Low"] * len(risks), (index, risks)
                else:
                    assert "High" in risks
                    assert body["flagged_alert_count"] >= 1
                assert len(result["hosts"]) == 2
                for host in result["hosts"]:
                    assert host["host_ip"] in HOSTS
                    assert (
                        host["decision"], host["version_after"],
                        host["readiness_after"],
                    ) == EXPECTED[index], (index, host)
                    assert item["expected_baseline"]["reason"] in host["reason_codes"]
                    if host["decision"] != "Accept":
                        assert host["baseline_before"] == host["baseline_after"]
                    if index == 9:
                        assert "ADAPTATION_LIMIT_REACHED" in host["reason_codes"]
                    if index == 10:
                        assert host["probation_count"] == 1
                    if index == 11:
                        assert "PROBATION_ADMITTED" in host["reason_codes"]
                    if index == 12:
                        assert "SEVERE_BASELINE_DEVIATION" in host["reason_codes"]
                        assert host["findings"]
                    if index == 13:
                        assert "ML_HIGH" in host["reason_codes"]
                ledger.append({
                    "index": index,
                    "analysis_id": analysis_id,
                    "observation_id": result["observation_id"],
                    "window": result["capture_window_start"],
                    "risk_levels": risks,
                    "flagged_alert_count": body["flagged_alert_count"],
                    "hosts": [{
                        "host_ip": host["host_ip"],
                        "decision": host["decision"],
                        "reasons": host["reason_codes"],
                        "version_before": host["version_before"],
                        "version_after": host["version_after"],
                        "readiness": host["readiness_after"],
                        "baseline_before": host["baseline_before"],
                        "baseline_after": host["baseline_after"],
                        "findings": host["findings"],
                    } for host in result["hosts"]],
                })
                if index == 1:
                    first_analysis_id = analysis_id
                    again = await client.post(
                        "/api/v1/demo/baselines/evaluate",
                        json={"analysis_id": analysis_id},
                    )
                    assert again.status_code == 200
                    assert again.json() == result
                    replay = await client.post(
                        "/api/v1/demo/upload/analyze",
                        files={"file": (
                            item["filename"], capture,
                            "application/vnd.tcpdump.pcap",
                        )},
                    )
                    assert replay.status_code == 200, replay.text
                    duplicate = await client.post(
                        "/api/v1/demo/baselines/evaluate",
                        json={"analysis_id": replay.json()["analysis_id"]},
                    )
                    assert duplicate.status_code == 200, duplicate.text
                    assert duplicate.json()["capture_fingerprint_status"] == "duplicate"
                    assert all(
                        host["decision"] == "Hold"
                        and "DUPLICATE_CAPTURE" in host["reason_codes"]
                        and host["version_after"] == 1
                        for host in duplicate.json()["hosts"]
                    )
                for host_ip in HOSTS:
                    history = await client.get(
                        "/api/v1/demo/baselines/history",
                        params={"host_ip": host_ip},
                    )
                    assert history.status_code == 200, history.text
                    record = history.json()
                    assert record["baseline_store_epoch"] == epoch
                    assert record["current_version"] == EXPECTED[index][1]
                    assert result["observation_id"] in {entry["observation_id"] for entry in record["decisions"]}
                    assert len(record["snapshots"]) <= 8
            assert first_analysis_id is not None
            for host_ip in HOSTS:
                final_history = (await client.get(
                    "/api/v1/demo/baselines/history", params={"host_ip": host_ip},
                )).json()
                assert len(final_history["snapshots"]) == 8
                assert [entry["version"] for entry in final_history["snapshots"]] == list(range(2, 10))
            unknown = await client.post(
                "/api/v1/demo/baselines/evaluate",
                json={"analysis_id": "11111111-1111-4111-8111-111111111111"},
            )
            assert unknown.status_code == 404
            assert ledger[12]["flagged_alert_count"] == 0
            protected = await client.post(
                "/api/v1/demo/telemetry/protect",
                json={"analysis_id": ledger[13]["analysis_id"]},
            )
            assert protected.status_code == 200, protected.text
            assert protected.json()["protected_count"] == (
                ledger[13]["flagged_alert_count"]
            )
            assert len(list(evidence.glob("protected-telemetry-*.json"))) == 1
            protection_id = protected.json()["protection_id"]
            verified = await client.post(
                f"/api/v1/demo/telemetry/{protection_id}/verify",
            )
            assert verified.status_code == 200, verified.text
            assert verified.json()["all_valid"] is True
            assert verified.json()["verified_count"] == protected.json()["protected_count"]
            tampered = await client.post(
                f"/api/v1/demo/telemetry/{protection_id}/verify-tampered",
            )
            assert tampered.status_code == 200, tampered.text
            assert tampered.json()["tamper_rejected"] is True
            assert (await client.post(
                f"/api/v1/demo/telemetry/{protection_id}/verify",
            )).status_code == 200
            print("INCREMENT3_ACTUAL=" + json.dumps([{"index": entry["index"], "risks": entry["risk_levels"], "flagged": entry["flagged_alert_count"], "decision": entry["hosts"][0]["decision"], "reasons": entry["hosts"][0]["reasons"], "version_before": entry["hosts"][0]["version_before"], "version_after": entry["hosts"][0]["version_after"], "readiness": entry["hosts"][0]["readiness"], "duration_before": None if entry["hosts"][0]["baseline_before"] is None else entry["hosts"][0]["baseline_before"]["average_duration_seconds"], "duration_after": None if entry["hosts"][0]["baseline_after"] is None else entry["hosts"][0]["baseline_after"]["average_duration_seconds"], "finding_count": len(entry["hosts"][0]["findings"])} for entry in ledger], sort_keys=True))
            print("INCREMENT3_EPOCH=" + str(epoch))
    anyio.run(run)
    assert AdaptiveBaselineStore().store_epoch != baselines.store_epoch
