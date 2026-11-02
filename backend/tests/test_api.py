import hashlib
import os
import subprocess
import sys
from collections.abc import Callable
from dataclasses import replace
from datetime import datetime
from pathlib import Path
from uuid import UUID, uuid4
from types import SimpleNamespace

import anyio
import httpx
import pytest
from fastapi import FastAPI

from app.adaptive_baseline import (
    AdaptiveBaselineStore, ScoredObservation, ScoredObservationRegistry,
)
from app.pcap_analysis import (
    AnalysisResult,
    FixtureNotFound,
    FixtureUnreadable,
    FlowSummary,
    NoSupportedPackets,
    ParserUnavailable,
)
from app.host_profiles import BaselineAdmissionError, InMemoryBaselineStore
from app.anomaly_detection import (
    DetectionResult,
    FeatureDataError,
    ModelUnavailable,
    TrainingReference,
)
from app.secure_telemetry import (
    CryptographyUnavailable,
    EvidenceStorageUnavailable,
    KeyStorageUnavailable,
    SecureTelemetryStore,
)


def load_app() -> FastAPI:
    try:
        from app.main import app
    except (ImportError, ModuleNotFoundError):
        pytest.fail("FastAPI app is not implemented")
    return app


def get(app: FastAPI, path: str) -> httpx.Response:
    async def send() -> httpx.Response:
        transport = httpx.ASGITransport(app=app)
        async with httpx.AsyncClient(
            transport=transport, base_url="http://testserver"
        ) as client:
            return await client.get(path)

    return anyio.run(send)


def post(app: FastAPI, path: str) -> httpx.Response:
    async def send() -> httpx.Response:
        transport = httpx.ASGITransport(app=app)
        async with httpx.AsyncClient(
            transport=transport, base_url="http://testserver"
        ) as client:
            return await client.post(path)

    return anyio.run(send)


def post_json(app: FastAPI, path: str, body: object = None) -> httpx.Response:
    async def send() -> httpx.Response:
        transport = httpx.ASGITransport(app=app)
        async with httpx.AsyncClient(
            transport=transport, base_url="http://testserver"
        ) as client:
            return await client.post(path, json=body)

    return anyio.run(send)


def post_file(
    app: FastAPI,
    path: str,
    *,
    filename: str,
    content: bytes,
) -> httpx.Response:
    async def send() -> httpx.Response:
        transport = httpx.ASGITransport(app=app)
        async with httpx.AsyncClient(
            transport=transport, base_url="http://testserver"
        ) as client:
            return await client.post(
                path,
                files={"file": (filename, content, "application/vnd.tcpdump.pcap")},
            )

    return anyio.run(send)


def test_health_reports_backend_liveness_without_database_access(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    app = load_app()

    def unexpected_database_check(_database_url: str) -> str:
        pytest.fail("health endpoint must not check the database")

    monkeypatch.setattr("app.main.check_database", unexpected_database_check)

    response = get(app, "/api/v1/health")

    assert response.status_code == 200
    assert response.json() == {"service": "backend", "status": "healthy"}


@pytest.mark.parametrize(
    ("database_status", "expected"),
    [
        (
            "healthy",
            {
                "overall_status": "healthy",
                "services": {"backend": "healthy", "database": "healthy"},
            },
        ),
        (
            "unavailable",
            {
                "overall_status": "degraded",
                "services": {
                    "backend": "healthy",
                    "database": "unavailable",
                },
            },
        ),
    ],
)
def test_status_reports_database_state_without_leaking_details(
    monkeypatch: pytest.MonkeyPatch,
    database_status: str,
    expected: dict[str, object],
) -> None:
    app = load_app()
    monkeypatch.setenv("DATABASE_URL", "postgresql://secret-value")
    monkeypatch.setattr(
        "app.main.check_database", lambda _database_url: database_status
    )

    response = get(app, "/api/v1/status")

    assert response.status_code == 200
    assert response.json() == expected
    assert "secret-value" not in response.text


def test_application_exposes_only_approved_routes_through_increment_four() -> None:
    app = load_app()
    framework_routes = {"/openapi.json", "/docs", "/docs/oauth2-redirect", "/redoc"}

    application_routes = {
        route.path for route in app.routes if route.path not in framework_routes
    }

    assert application_routes == {
        "/api/v1/health",
        "/api/v1/status",
        "/api/v1/demo/flows/analyze",
        "/api/v1/demo/profiles/adapt",
        "/api/v1/demo/detection/analyze",
        "/api/v1/demo/upload/analyze",
        "/api/v1/demo/baselines/evaluate",
        "/api/v1/demo/baselines/history",
        "/api/v1/demo/hybrid/evaluate",
        "/api/v1/demo/hybrid/{analysis_id}",
        "/api/v1/demo/hybrid/telemetry/protect",
        "/api/v1/demo/hybrid/telemetry/{analysis_id}/status",
        "/api/v1/demo/hybrid/telemetry/{protection_id}/verify",
        "/api/v1/demo/hybrid/telemetry/{protection_id}/verify-tampered",
        "/api/v1/demo/telemetry/protect",
        "/api/v1/demo/telemetry/{protection_id}/verify",
        "/api/v1/demo/telemetry/{protection_id}/verify-tampered",
    }


def test_analyze_route_returns_labelled_metadata_only_flows(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    app = load_app()
    observed_paths: list[str] = []
    result = AnalysisResult(
        packet_count=3,
        flows=(
            FlowSummary(
                protocol="TCP",
                source_ip="192.0.2.10",
                source_port=51515,
                destination_ip="198.51.100.20",
                destination_port=443,
                packet_count=3,
                byte_count=162,
                duration_seconds=2.0,
                packets_per_second=1.5,
                bytes_per_second=81.0,
            ),
        ),
    )

    def fake_analyze(path: object) -> AnalysisResult:
        observed_paths.append(str(path))
        return result

    monkeypatch.setenv("NEXUS_DEMO_PCAP_PATH", "/fixed/phase2-demo.pcap")
    monkeypatch.setattr("app.main.analyze_pcap", fake_analyze)

    response = post(app, "/api/v1/demo/flows/analyze")

    assert response.status_code == 200
    body = response.json()
    assert body["schema_version"] == "phase2.flow.v1"
    assert body["source"] == "REPLAYED DEMO TRAFFIC"
    assert body["fixture_id"] == "phase2-synthetic-v1"
    assert UUID(body["analysis_id"]).version == 4
    assert datetime.fromisoformat(body["analyzed_at"]).utcoffset().total_seconds() == 0
    assert body["packet_count"] == 3
    assert body["flow_count"] == 1
    assert body["flows"] == [
        {
            "protocol": "TCP",
            "source_ip": "192.0.2.10",
            "source_port": 51515,
            "destination_ip": "198.51.100.20",
            "destination_port": 443,
            "packet_count": 3,
            "byte_count": 162,
            "duration_seconds": 2.0,
            "packets_per_second": 1.5,
            "bytes_per_second": 81.0,
        }
    ]
    assert observed_paths == ["/fixed/phase2-demo.pcap"]
    assert "payload" not in response.text.lower()


@pytest.mark.parametrize(
    ("error", "status_code", "code", "message"),
    [
        (
            FixtureNotFound(),
            404,
            "fixture_not_found",
            "Offline demo fixture is unavailable.",
        ),
        (
            FixtureUnreadable(),
            422,
            "fixture_unreadable",
            "Offline demo fixture cannot be analyzed.",
        ),
        (
            NoSupportedPackets(),
            422,
            "no_supported_packets",
            "Offline demo fixture contains no supported packets.",
        ),
        (
            ParserUnavailable(),
            503,
            "parser_unavailable",
            "Offline packet analysis is unavailable.",
        ),
    ],
)
def test_analyze_route_maps_sanitized_failures(
    monkeypatch: pytest.MonkeyPatch,
    error: Exception,
    status_code: int,
    code: str,
    message: str,
) -> None:
    app = load_app()

    def fail(_path: object) -> None:
        raise error

    monkeypatch.setattr("app.main.analyze_pcap", fail)

    response = post(app, "/api/v1/demo/flows/analyze")

    assert response.status_code == status_code
    assert response.json() == {"detail": {"code": code, "message": message}}
    assert "traceback" not in response.text.lower()


def test_analyze_route_declares_no_upload_or_request_body() -> None:
    app = load_app()
    operation = app.openapi()["paths"]["/api/v1/demo/flows/analyze"]["post"]

    assert "requestBody" not in operation


def normal_result() -> AnalysisResult:
    return AnalysisResult(
        packet_count=2,
        flows=(
            FlowSummary(
                protocol="TCP",
                source_ip="192.0.2.10",
                source_port=51001,
                destination_ip="198.51.100.20",
                destination_port=443,
                packet_count=2,
                byte_count=108,
                duration_seconds=1.0,
                packets_per_second=2.0,
                bytes_per_second=108.0,
            ),
        ),
    )


def test_profile_route_returns_warming_then_ready_without_database_access(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    app = load_app()
    observed_paths: list[str] = []

    def fake_analyze(path: object) -> AnalysisResult:
        observed_paths.append(str(path))
        return normal_result()

    def unexpected_database_check(_database_url: str) -> str:
        pytest.fail("profile adaptation must not access PostgreSQL")

    monkeypatch.setenv("NEXUS_NORMAL_PCAP_PATH", "/fixed/phase3-normal.pcap")
    monkeypatch.setattr("app.main.analyze_pcap", fake_analyze)
    monkeypatch.setattr("app.main.check_database", unexpected_database_check)
    monkeypatch.setattr("app.main.baseline_store", InMemoryBaselineStore())

    warming = post(app, "/api/v1/demo/profiles/adapt")
    ready = post(app, "/api/v1/demo/profiles/adapt")

    assert warming.status_code == 200
    assert ready.status_code == 200
    first = warming.json()
    second = ready.json()
    assert first["schema_version"] == "phase3.profile.v1"
    assert first["source"] == "REPLAYED DEMO TRAFFIC"
    assert first["fixture_id"] == "phase3-normal-v1"
    assert first["interpretation"] == (
        "NORMAL BASELINE ONLY - NO ANOMALY DECISION"
    )
    assert UUID(first["analysis_id"]).version == 4
    assert datetime.fromisoformat(first["analyzed_at"]).utcoffset().total_seconds() == 0
    assert first["packet_count"] == 2
    assert first["flow_count"] == 1
    assert first["baseline_state"] == "warming"
    assert first["warmup_required_batches"] == 2
    assert first["admitted_batch_count"] == 1
    assert first["window_batch_count"] == 1
    assert first["baseline_version"] == 0
    assert first["previous_baseline_version"] is None
    assert len(first["hosts"]) == 2
    assert first["hosts"][0] == {
        "host_ip": "192.0.2.10",
        "current_profile": {
            "observed_flow_count": 1,
            "protocol_mix": [{"protocol": "TCP", "flow_count": 1}],
            "average_bytes_per_flow": 108.0,
            "average_duration_seconds": 1.0,
            "average_packets_per_second": 2.0,
        },
        "baseline": None,
    }
    assert second["baseline_state"] == "ready"
    assert second["admitted_batch_count"] == 2
    assert second["window_batch_count"] == 2
    assert second["baseline_version"] == 1
    assert second["hosts"][0]["baseline"] == {
        "observed_batch_count": 2,
        "average_flow_count": 1.0,
        "protocol_mix": [{"protocol": "TCP", "average_flow_count": 1.0}],
        "average_bytes_per_flow": 108.0,
        "average_duration_seconds": 1.0,
        "average_packets_per_second": 2.0,
    }
    assert observed_paths == [
        "/fixed/phase3-normal.pcap",
        "/fixed/phase3-normal.pcap",
    ]
    for forbidden_key in ("score", "risk", "alert", "prediction", "model"):
        assert forbidden_key not in first


@pytest.mark.parametrize(
    ("error", "status_code", "code", "message"),
    [
        (FixtureNotFound(), 404, "fixture_not_found", "Offline demo fixture is unavailable."),
        (
            FixtureUnreadable(),
            422,
            "fixture_unreadable",
            "Offline demo fixture cannot be analyzed.",
        ),
        (
            NoSupportedPackets(),
            422,
            "no_supported_packets",
            "Offline demo fixture contains no supported packets.",
        ),
        (
            ParserUnavailable(),
            503,
            "parser_unavailable",
            "Offline packet analysis is unavailable.",
        ),
    ],
)
def test_profile_route_sanitizes_parser_failures_without_advancing_state(
    monkeypatch: pytest.MonkeyPatch,
    error: Exception,
    status_code: int,
    code: str,
    message: str,
) -> None:
    app = load_app()
    store = InMemoryBaselineStore()

    def fail(_path: object) -> None:
        raise error

    monkeypatch.setattr("app.main.baseline_store", store)
    monkeypatch.setattr("app.main.analyze_pcap", fail)

    failed = post(app, "/api/v1/demo/profiles/adapt")
    monkeypatch.setattr("app.main.analyze_pcap", lambda _path: normal_result())
    first_success = post(app, "/api/v1/demo/profiles/adapt")

    assert failed.status_code == status_code
    assert failed.json() == {"detail": {"code": code, "message": message}}
    assert "traceback" not in failed.text.lower()
    assert first_success.status_code == 200
    assert first_success.json()["admitted_batch_count"] == 1
    assert first_success.json()["baseline_version"] == 0


def test_profile_route_rejects_empty_profiles_without_advancing_state(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    app = load_app()
    store = InMemoryBaselineStore()
    monkeypatch.setattr("app.main.baseline_store", store)
    monkeypatch.setattr(
        "app.main.analyze_pcap",
        lambda _path: AnalysisResult(packet_count=1, flows=()),
    )

    failed = post(app, "/api/v1/demo/profiles/adapt")
    monkeypatch.setattr("app.main.analyze_pcap", lambda _path: normal_result())
    first_success = post(app, "/api/v1/demo/profiles/adapt")

    assert failed.status_code == 422
    assert failed.json() == {
        "detail": {
            "code": "empty_profile_batch",
            "message": "Normal replay produced no host profiles.",
        }
    }
    assert first_success.json()["admitted_batch_count"] == 1


def test_profile_route_maps_internal_admission_rejection(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    app = load_app()

    class RejectingStore:
        def admit_normal_batch(self, *_args: object, **_kwargs: object) -> None:
            raise BaselineAdmissionError()

    monkeypatch.setattr("app.main.baseline_store", RejectingStore())
    monkeypatch.setattr("app.main.analyze_pcap", lambda _path: normal_result())

    response = post(app, "/api/v1/demo/profiles/adapt")

    assert response.status_code == 422
    assert response.json() == {
        "detail": {
            "code": "baseline_batch_rejected",
            "message": "Baseline batch was not admitted.",
        }
    }


def test_profile_route_declares_no_upload_body_query_or_path_input() -> None:
    app = load_app()
    operation = app.openapi()["paths"]["/api/v1/demo/profiles/adapt"]["post"]

    assert "requestBody" not in operation
    assert operation.get("parameters", []) == []


def detection_flows() -> tuple[FlowSummary, ...]:
    return (
        FlowSummary(
            protocol="TCP",
            source_ip="192.0.2.10",
            source_port=56001,
            destination_ip="198.51.100.20",
            destination_port=443,
            packet_count=12,
            byte_count=648,
            duration_seconds=1.0,
            packets_per_second=12.0,
            bytes_per_second=648.0,
        ),
        FlowSummary(
            protocol="UDP",
            source_ip="198.51.100.20",
            source_port=56002,
            destination_ip="203.0.113.30",
            destination_port=123,
            packet_count=2,
            byte_count=84,
            duration_seconds=45.0,
            packets_per_second=0.044,
            bytes_per_second=1.867,
        ),
        FlowSummary(
            protocol="ICMP",
            source_ip="203.0.113.30",
            source_port=None,
            destination_ip="192.0.2.10",
            destination_port=None,
            packet_count=2,
            byte_count=84,
            duration_seconds=1.0,
            packets_per_second=2.0,
            bytes_per_second=84.0,
        ),
    )


def test_detection_route_returns_labelled_model_and_separate_risk_results(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    app = load_app()
    paths: list[str] = []
    fit_count = 0
    replay_flows = detection_flows()

    def fake_analyze(path: object) -> AnalysisResult:
        paths.append(str(path))
        if "training" in str(path):
            return AnalysisResult(packet_count=144, flows=normal_result().flows * 48)
        return AnalysisResult(packet_count=16, flows=replay_flows)

    def fake_train(flows: tuple[FlowSummary, ...]) -> object:
        nonlocal fit_count
        fit_count += 1
        assert len(flows) == 48
        return SimpleNamespace(
            model_threshold=0.5,
            training_flow_count=48,
            parameters={"n_estimators": 100, "max_samples": 32},
        )

    def fake_detect(_detector: object, flows: tuple[FlowSummary, ...]):
        assert flows == replay_flows
        return tuple(
            DetectionResult(
                flow=flow,
                anomaly_score=score,
                is_statistically_unusual=True,
                risk_score=90,
                risk_level="High",
                alert_flagged=True,
                explanations=explanations,
            )
            for flow, score, explanations in zip(
                flows,
                (0.600084, 0.620599, 0.61167),
                (
                    ("Packet count is above the synthetic training range.",),
                    ("Duration is above the synthetic training range.",),
                    ("Protocol was not present in the synthetic training fixture.",),
                ),
                strict=True,
            )
        )

    monkeypatch.setenv(
        "NEXUS_DETECTION_TRAINING_PCAP_PATH", "/fixed/phase4-normal-training.pcap"
    )
    monkeypatch.setenv(
        "NEXUS_DETECTION_UNUSUAL_PCAP_PATH", "/fixed/phase4-unusual.pcap"
    )
    monkeypatch.setattr("app.main.analyze_pcap", fake_analyze)
    monkeypatch.setattr("app.main.train_detector", fake_train)
    monkeypatch.setattr("app.main.detect_flows", fake_detect)

    response = post(app, "/api/v1/demo/detection/analyze")

    assert response.status_code == 200
    body = response.json()
    assert body["schema_version"] == "phase4.detection.v1"
    assert body["source"] == "REPLAYED DEMO TRAFFIC"
    assert body["interpretation"] == (
        "SYNTHETIC ANOMALY DEMO - STATISTICAL UNUSUALNESS, NOT MALICIOUS PROOF"
    )
    assert body["training_fixture_id"] == "phase4-normal-train-v1"
    assert body["replay_fixture_id"] == "phase4-unusual-v1"
    assert UUID(body["analysis_id"]).version == 4
    assert datetime.fromisoformat(body["analyzed_at"]).utcoffset().total_seconds() == 0
    assert body["model"] == {
        "model_type": "IsolationForest",
        "model_version": "phase4-iforest-v1",
        "random_seed": 42,
        "training_flow_count": 48,
        "feature_count": 11,
        "n_estimators": 100,
        "max_samples": 32,
        "model_threshold": 0.5,
    }
    assert body["replay_packet_count"] == 16
    assert body["replay_flow_count"] == 3
    assert body["flagged_alert_count"] == 3
    assert [item["anomaly_score"] for item in body["results"]] == [
        0.600084,
        0.620599,
        0.61167,
    ]
    assert all(item["risk_score"] == 90 for item in body["results"])
    assert all(item["risk_level"] == "High" for item in body["results"])
    assert all(item["alert_flagged"] is True for item in body["results"])
    assert paths == [
        "/fixed/phase4-normal-training.pcap",
        "/fixed/phase4-unusual.pcap",
    ]
    assert fit_count == 1
    for forbidden in ("probability", "critical", "malicious proof"):
        assert forbidden not in response.text.lower().replace("not malicious proof", "")


@pytest.mark.parametrize(
    ("error", "status_code", "code", "message"),
    [
        (
            FixtureNotFound(),
            404,
            "detection_fixture_not_found",
            "Offline detection fixture is unavailable.",
        ),
        (
            FixtureUnreadable(),
            422,
            "detection_fixture_unreadable",
            "Offline detection fixture cannot be analyzed.",
        ),
        (
            NoSupportedPackets(),
            422,
            "detection_no_supported_flows",
            "Offline detection fixture contains no supported flows.",
        ),
        (
            ParserUnavailable(),
            503,
            "detection_parser_unavailable",
            "Offline detection parsing is unavailable.",
        ),
    ],
)
def test_detection_route_maps_both_fixture_failures_without_partial_results(
    monkeypatch: pytest.MonkeyPatch,
    error: Exception,
    status_code: int,
    code: str,
    message: str,
) -> None:
    app = load_app()

    def fail(_path: object) -> None:
        raise error

    monkeypatch.setattr("app.main.analyze_pcap", fail)
    response = post(app, "/api/v1/demo/detection/analyze")

    assert response.status_code == status_code
    assert response.json() == {"detail": {"code": code, "message": message}}
    for forbidden in ("path", "score", "risk", "alert", "traceback"):
        assert forbidden not in response.text.lower()


@pytest.mark.parametrize(
    ("error", "status_code", "code", "message"),
    [
        (
            FeatureDataError(),
            422,
            "insufficient_training_data",
            "Synthetic training data is insufficient.",
        ),
        (
            ModelUnavailable(),
            503,
            "model_unavailable",
            "Offline anomaly detection is unavailable.",
        ),
    ],
)
def test_detection_route_maps_sanitized_training_and_model_failures(
    monkeypatch: pytest.MonkeyPatch,
    error: Exception,
    status_code: int,
    code: str,
    message: str,
) -> None:
    app = load_app()
    monkeypatch.setattr("app.main.analyze_pcap", lambda _path: normal_result())

    def fail(_flows: object) -> None:
        raise error

    monkeypatch.setattr("app.main.train_detector", fail)
    response = post(app, "/api/v1/demo/detection/analyze")

    assert response.status_code == status_code
    assert response.json() == {"detail": {"code": code, "message": message}}
    assert "traceback" not in response.text.lower()


def test_detection_route_declares_no_body_query_or_path_input() -> None:
    app = load_app()
    operation = app.openapi()["paths"]["/api/v1/demo/detection/analyze"]["post"]

    assert "requestBody" not in operation
    assert operation.get("parameters", []) == []


def upload_analysis_result() -> AnalysisResult:
    return AnalysisResult(packet_count=3, flows=(detection_flows()[0],))


def test_upload_route_returns_metadata_profiles_and_fixed_model_results(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: object,
) -> None:
    app = load_app()
    upload_directory = tmp_path
    observed: list[tuple[str, int]] = []
    fit_inputs: list[tuple[FlowSummary, ...]] = []
    retained: list[object] = []
    uploaded = upload_analysis_result()
    training = AnalysisResult(packet_count=144, flows=normal_result().flows * 48)

    def fake_analyze(path: object, *, max_packets: int = 2_000) -> AnalysisResult:
        observed.append((str(path), max_packets))
        if str(path) == "/fixed/phase4-normal-training.pcap":
            return training
        assert str(path).startswith(str(upload_directory))
        assert Path(str(path)).is_file()
        return uploaded

    def fake_train(flows: tuple[FlowSummary, ...]) -> object:
        fit_inputs.append(flows)
        return SimpleNamespace(
            model_threshold=0.636672,
            training_flow_count=48,
            parameters={"n_estimators": 100, "max_samples": 32},
            normalizer=SimpleNamespace(reference=TrainingReference(
                numeric_ranges=((2, 4), (100, 200), (1, 3), (1, 4), (50, 200)),
                protocols=("TCP", "UDP"), port_presence=((1.0, 1.0),),
            )),
        )

    def fake_detect(_detector: object, flows: tuple[FlowSummary, ...]):
        assert flows == uploaded.flows
        return (
            DetectionResult(
                flow=flows[0],
                anomaly_score=0.700001,
                is_statistically_unusual=True,
                risk_score=90,
                risk_level="High",
                alert_flagged=True,
                explanations=(
                    "Packet count 12 is above synthetic training range 2 to 4.",
                ),
            ),
        )

    class BaselineMustNotBeUsed:
        def admit_normal_batch(self, *_args: object, **_kwargs: object) -> None:
            pytest.fail("upload analysis must not mutate the Phase 3 baseline")

    monkeypatch.setenv(
        "NEXUS_DETECTION_TRAINING_PCAP_PATH", "/fixed/phase4-normal-training.pcap"
    )
    monkeypatch.setattr("app.main.UPLOAD_TEMP_DIRECTORY", upload_directory)
    monkeypatch.setattr("app.main.analyze_pcap", fake_analyze)
    monkeypatch.setattr("app.main.train_detector", fake_train)
    monkeypatch.setattr("app.main.detect_flows", fake_detect)
    monkeypatch.setattr("app.main.baseline_store", BaselineMustNotBeUsed())
    monkeypatch.setattr(
        "app.main.scored_observation_registry",
        SimpleNamespace(register=lambda observation: retained.append(observation)),
        raising=False,
    )

    response = post_file(
        app,
        "/api/v1/demo/upload/analyze",
        filename="local-synthetic.pcap",
        content=b"safe synthetic pcap bytes",
    )

    assert response.status_code == 200
    body = response.json()
    assert body["schema_version"] == "demo.upload-analysis.v1"
    assert body["source"] == "REPLAYED DEMO TRAFFIC"
    assert body["interpretation"] == (
        "STATISTICAL UNUSUALNESS RELATIVE TO SYNTHETIC TRAINING, "
        "NOT MALICIOUS PROOF"
    )
    assert body["packet_count"] == 3
    assert body["flow_count"] == 1
    assert body["flows"][0]["protocol"] == "TCP"
    assert [item["host_ip"] for item in body["host_profiles"]] == [
        "192.0.2.10",
        "198.51.100.20",
    ]
    assert body["model"]["training_flow_count"] == 48
    assert body["results"][0]["anomaly_score"] == 0.700001
    assert body["results"][0]["risk_level"] == "High"
    assert body["results"][0]["alert_flagged"] is True
    assert body["flagged_alert_count"] == 1
    assert len(retained) == 1
    assert retained[0].analysis_id == UUID(body["analysis_id"])
    assert retained[0].capture_digest == hashlib.sha256(b"safe synthetic pcap bytes").hexdigest()
    assert retained[0].analysis is uploaded
    assert retained[0].detected[0].alert_flagged is True
    assert fit_inputs == [training.flows]
    assert observed[0][1] == 2_000
    assert observed[1] == ("/fixed/phase4-normal-training.pcap", 2_000)
    assert list(upload_directory.iterdir()) == []
    for forbidden in ("payload", "temporary", "vector", "secret"):
        assert forbidden not in response.text.lower()


def test_upload_digest_failure_is_visible_without_retained_observation(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path,
) -> None:
    app = load_app()
    uploaded = upload_analysis_result()
    reference = TrainingReference(
        numeric_ranges=((2, 4), (100, 200), (1, 3), (1, 4), (50, 200)),
        protocols=("TCP", "UDP"), port_presence=((1.0, 1.0),),
    )
    retained: list[object] = []
    telemetry_calls: list[object] = []
    monkeypatch.setattr("app.main.UPLOAD_TEMP_DIRECTORY", tmp_path)
    monkeypatch.setattr(
        "app.main.analyze_pcap",
        lambda _path, **_kwargs: uploaded,
    )
    monkeypatch.setattr(
        "app.main.train_detector",
        lambda _flows: SimpleNamespace(
            model_threshold=0.636672,
            training_flow_count=48,
            normalizer=SimpleNamespace(reference=reference),
        ),
    )
    monkeypatch.setattr("app.main.detect_flows", lambda _model, _flows: ())
    monkeypatch.setattr(
        "app.main.scored_observation_registry",
        SimpleNamespace(register=lambda item: retained.append(item)),
    )
    monkeypatch.setattr(
        "app.main.secure_telemetry_store",
        SimpleNamespace(register_upload=lambda *_args: telemetry_calls.append(True)),
    )
    monkeypatch.setattr(
        "app.main.capture_digest",
        lambda _path: (_ for _ in ()).throw(OSError("private temporary path")),
    )
    response = post_file(
        app, "/api/v1/demo/upload/analyze",
        filename="safe.pcap", content=b"synthetic bytes",
    )
    assert response.status_code == 503
    assert response.json()["detail"]["code"] == "upload_storage_unavailable"
    assert "private temporary path" not in response.text
    assert retained == []
    assert telemetry_calls == []
    assert list(tmp_path.iterdir()) == []


def test_upload_route_rejects_invalid_extension_without_creating_temp_file(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: object,
) -> None:
    app = load_app()
    monkeypatch.setattr("app.main.UPLOAD_TEMP_DIRECTORY", tmp_path)

    response = post_file(
        app,
        "/api/v1/demo/upload/analyze",
        filename="not-a-capture.txt",
        content=b"not a pcap",
    )

    assert response.status_code == 422
    assert response.json() == {
        "detail": {
            "code": "upload_invalid_extension",
            "message": "Choose a .pcap file.",
        }
    }
    assert list(tmp_path.iterdir()) == []


def test_upload_route_rejects_more_than_one_mib_and_cleans_temp_file(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: object,
) -> None:
    app = load_app()
    monkeypatch.setattr("app.main.UPLOAD_TEMP_DIRECTORY", tmp_path)

    response = post_file(
        app,
        "/api/v1/demo/upload/analyze",
        filename="too-large.pcap",
        content=b"x" * (1_048_576 + 1),
    )

    assert response.status_code == 413
    assert response.json() == {
        "detail": {
            "code": "upload_too_large",
            "message": "Uploaded PCAP must be 1 MiB or smaller.",
        }
    }
    assert list(tmp_path.iterdir()) == []


@pytest.mark.parametrize(
    ("error", "status_code", "code", "message"),
    [
        (
            FixtureUnreadable(),
            422,
            "upload_unreadable",
            "Uploaded PCAP cannot be analyzed.",
        ),
        (
            NoSupportedPackets(),
            422,
            "upload_no_supported_flows",
            "Uploaded PCAP contains no supported flows.",
        ),
        (
            ParserUnavailable(),
            503,
            "upload_parser_unavailable",
            "Uploaded PCAP parsing is unavailable.",
        ),
    ],
)
def test_upload_route_sanitizes_parser_failures_and_cleans_temp_file(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: object,
    error: Exception,
    status_code: int,
    code: str,
    message: str,
) -> None:
    app = load_app()

    def fail(_path: object, *, max_packets: int = 2_000) -> None:
        assert max_packets == 2_000
        raise error

    monkeypatch.setattr("app.main.UPLOAD_TEMP_DIRECTORY", tmp_path)
    monkeypatch.setattr("app.main.analyze_pcap", fail)

    response = post_file(
        app,
        "/api/v1/demo/upload/analyze",
        filename="broken.pcap",
        content=b"malformed local capture",
    )

    assert response.status_code == status_code
    assert response.json() == {"detail": {"code": code, "message": message}}
    assert list(tmp_path.iterdir()) == []
    for forbidden in ("path", "traceback", "parser internals", "partial"):
        assert forbidden not in response.text.lower()


def test_upload_route_accepts_only_one_multipart_file_and_no_arbitrary_inputs() -> None:
    app = load_app()
    operation = app.openapi()["paths"]["/api/v1/demo/upload/analyze"]["post"]

    assert operation.get("parameters", []) == []
    request_body = operation["requestBody"]
    assert set(request_body["content"]) == {"multipart/form-data"}
    schema_reference = request_body["content"]["multipart/form-data"]["schema"]["$ref"]
    schema_name = schema_reference.rsplit("/", 1)[-1]
    schema = app.openapi()["components"]["schemas"][schema_name]
    assert schema["required"] == ["file"]
    assert set(schema["properties"]) == {"file"}


def api_flagged_result() -> SimpleNamespace:
    return SimpleNamespace(
        protocol="ICMP",
        source_ip="192.0.2.10",
        source_port=None,
        destination_ip="198.51.100.20",
        destination_port=None,
        packet_count=2,
        byte_count=84,
        duration_seconds=0.1,
        packets_per_second=20.0,
        bytes_per_second=840.0,
        anomaly_score=0.641502,
        is_statistically_unusual=True,
        risk_score=90,
        risk_level="High",
        alert_flagged=True,
        explanations=("Packet rate is above the synthetic normal range.",),
    )


def assert_safe_telemetry_response(response: httpx.Response) -> None:
    forbidden_keys = {
        "key",
        "private_key",
        "plaintext",
        "ciphertext",
        "nonce",
        "digest",
        "signature",
        "envelope",
        "path",
    }

    def visit(value: object) -> None:
        if isinstance(value, dict):
            assert forbidden_keys.isdisjoint(value)
            for nested in value.values():
                visit(nested)
        elif isinstance(value, list):
            for nested in value:
                visit(nested)

    visit(response.json())
    for secret_marker in (
        "BEGIN PRIVATE KEY",
        "/app/demo-keys",
        "/app/demo-evidence",
    ):
        assert secret_marker not in response.text


def test_telemetry_routes_protect_verify_reject_tamper_and_keep_valid_record(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    app = load_app()
    store = SecureTelemetryStore(
        key_directory=tmp_path / "keys",
        evidence_directory=tmp_path / "evidence",
    )
    monkeypatch.setattr("app.main.secure_telemetry_store", store)
    analysis_id = UUID("11111111-1111-4111-8111-111111111111")
    store.register_upload(analysis_id, [api_flagged_result(), api_flagged_result()])

    protected = post_json(
        app,
        "/api/v1/demo/telemetry/protect",
        {"analysis_id": str(analysis_id)},
    )
    assert protected.status_code == 200
    assert protected.json() == {
        "schema_version": "phase5.secure-telemetry.v1",
        "protection_id": str(analysis_id),
        "analysis_id": str(analysis_id),
        "status": "protected",
        "aes_gcm": "protected",
        "protected_count": 2,
    }
    protection_id = protected.json()["protection_id"]

    verified = post_json(
        app,
        f"/api/v1/demo/telemetry/{protection_id}/verify",
    )
    assert verified.status_code == 200
    assert verified.json() == {
        "schema_version": "phase5.secure-telemetry.v1",
        "protection_id": protection_id,
        "analysis_id": str(analysis_id),
        "verification": "verified",
        "aes_gcm": "authenticated",
        "sha256": "verified",
        "rsa_pss": "valid",
        "protected_count": 2,
        "verified_count": 2,
        "all_valid": True,
    }

    tampered = post_json(
        app,
        f"/api/v1/demo/telemetry/{protection_id}/verify-tampered",
    )
    assert tampered.status_code == 200
    assert tampered.json() == {
        "schema_version": "phase5.secure-telemetry.v1",
        "protection_id": protection_id,
        "analysis_id": str(analysis_id),
        "verification": "rejected",
        "reason": "tamper_detected",
        "protected_count": 2,
        "tamper_rejected": True,
    }
    assert post_json(
        app,
        f"/api/v1/demo/telemetry/{protection_id}/verify",
    ).status_code == 200
    for response in (protected, verified, tampered):
        assert_safe_telemetry_response(response)


def test_telemetry_protect_reports_no_flagged_alert_and_unknown_analysis(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    app = load_app()
    store = SecureTelemetryStore(
        key_directory=tmp_path / "keys",
        evidence_directory=tmp_path / "evidence",
    )
    monkeypatch.setattr("app.main.secure_telemetry_store", store)
    analysis_id = uuid4()
    store.register_upload(analysis_id, [])

    no_flag = post_json(
        app,
        "/api/v1/demo/telemetry/protect",
        {"analysis_id": str(analysis_id)},
    )
    assert no_flag.status_code == 409
    assert no_flag.json()["detail"]["code"] == "no_flagged_alert"

    unknown = post_json(
        app,
        "/api/v1/demo/telemetry/protect",
        {"analysis_id": str(uuid4())},
    )
    assert unknown.status_code == 404
    assert unknown.json()["detail"]["code"] == "analysis_not_found_or_expired"
    assert_safe_telemetry_response(no_flag)
    assert_safe_telemetry_response(unknown)


@pytest.mark.parametrize("body", [None, {}, {"analysis_id": "not-a-uuid"}])
def test_telemetry_protect_rejects_malformed_request(body: object) -> None:
    response = post_json(load_app(), "/api/v1/demo/telemetry/protect", body)
    assert response.status_code == 422


def test_telemetry_protect_forbids_extra_input() -> None:
    response = post_json(
        load_app(),
        "/api/v1/demo/telemetry/protect",
        {"analysis_id": str(uuid4()), "plaintext": "forbidden"},
    )
    assert response.status_code == 422


@pytest.mark.parametrize(
    ("error", "code"),
    [
        (KeyStorageUnavailable(), "key_storage_unavailable"),
        (EvidenceStorageUnavailable(), "evidence_storage_unavailable"),
    ],
)
def test_telemetry_protect_sanitizes_storage_failures(
    monkeypatch: pytest.MonkeyPatch,
    error: Exception,
    code: str,
) -> None:
    app = load_app()

    class FailingStore:
        def protect_all_flagged(self, _analysis_id: UUID) -> None:
            raise error

    monkeypatch.setattr("app.main.secure_telemetry_store", FailingStore())
    response = post_json(
        app,
        "/api/v1/demo/telemetry/protect",
        {"analysis_id": str(uuid4())},
    )
    assert response.status_code == 503
    assert response.json()["detail"]["code"] == code
    assert_safe_telemetry_response(response)


def test_telemetry_unknown_protection_and_stored_tamper_are_sanitized(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    app = load_app()
    store = SecureTelemetryStore(
        key_directory=tmp_path / "keys",
        evidence_directory=tmp_path / "evidence",
    )
    monkeypatch.setattr("app.main.secure_telemetry_store", store)

    unknown = post_json(
        app,
        f"/api/v1/demo/telemetry/{uuid4()}/verify",
    )
    assert unknown.status_code == 404
    assert unknown.json()["detail"]["code"] == "protection_not_found_or_expired"

    analysis_id = uuid4()
    store.register_upload(analysis_id, [api_flagged_result()])
    store.protect_all_flagged(analysis_id)
    batch = store._batches[analysis_id]
    record = batch.records[0]
    altered = dict(record.envelope)
    altered["ciphertext"] = "changed"
    store._batches[analysis_id] = replace(
        batch,
        records=(replace(record, envelope=altered), *batch.records[1:]),
    )
    failed = post_json(
        app,
        f"/api/v1/demo/telemetry/{analysis_id}/verify",
    )
    assert failed.status_code == 409
    assert failed.json()["detail"]["code"] == "verification_failed"
    assert_safe_telemetry_response(unknown)
    assert_safe_telemetry_response(failed)


def test_telemetry_verify_sanitizes_cryptography_failure(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    app = load_app()

    class FailingStore:
        def verify_all(self, _analysis_id: UUID) -> None:
            raise CryptographyUnavailable()

    monkeypatch.setattr("app.main.secure_telemetry_store", FailingStore())
    response = post_json(
        app,
        f"/api/v1/demo/telemetry/{uuid4()}/verify",
    )

    assert response.status_code == 503
    assert response.json()["detail"]["code"] == "cryptography_unavailable"
    assert_safe_telemetry_response(response)


def test_telemetry_openapi_accepts_only_approved_inputs() -> None:
    schema = load_app().openapi()
    protect = schema["paths"]["/api/v1/demo/telemetry/protect"]["post"]
    body_ref = protect["requestBody"]["content"]["application/json"]["schema"]["$ref"]
    body_schema = schema["components"]["schemas"][body_ref.rsplit("/", 1)[-1]]
    assert body_schema["required"] == ["analysis_id"]
    assert set(body_schema["properties"]) == {"analysis_id"}
    assert body_schema["additionalProperties"] is False

    for route in (
        "/api/v1/demo/telemetry/{protection_id}/verify",
        "/api/v1/demo/telemetry/{protection_id}/verify-tampered",
    ):
        operation = schema["paths"][route]["post"]
        assert "requestBody" not in operation
        assert [item["name"] for item in operation["parameters"]] == [
            "protection_id"
        ]


def _scored_api_observation() -> ScoredObservation:
    flows = tuple(
        FlowSummary(
            "TCP", "192.0.2.10", 45000 + index,
            "198.51.100.20", 443, 2, 108, 2.0, 1.0, 54.0,
        )
        for index in range(4)
    )
    analysis = AnalysisResult(
        packet_count=8, flows=flows,
        capture_first_timestamp=60.0,
        capture_last_timestamp=108.0,
        flow_time_bounds=tuple(
            (float(60 + offset), float(62 + offset))
            for offset in (0, 15, 30, 46)
        ),
    )
    detected = tuple(
        DetectionResult(
            flow=flow, anomaly_score=0.4,
            is_statistically_unusual=False,
            risk_score=20, risk_level="Low",
            alert_flagged=False, explanations=(),
        )
        for flow in flows
    )
    return ScoredObservation(
        analysis_id=uuid4(), observation_id=uuid4(),
        capture_digest="c" * 64,
        analysis=analysis, detected=detected,
        training_reference=TrainingReference(
            numeric_ranges=((2, 4), (100, 300), (1, 4), (0.5, 4), (40, 200)),
            protocols=("TCP", "UDP"), port_presence=((1.0, 1.0),),
        ),
        model_version="phase4-iforest-v1",
        model_threshold=0.636672,
    )


def test_baseline_evaluate_and_history_api_are_versioned_and_idempotent(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    app = load_app()
    observation = _scored_api_observation()
    registry = ScoredObservationRegistry()
    registry.register(observation)
    monkeypatch.setattr("app.main.scored_observation_registry", registry)
    monkeypatch.setattr(
        "app.main.adaptive_baseline_store", AdaptiveBaselineStore(),
        raising=False,
    )
    monkeypatch.setattr(
        "app.main.analyze_pcap",
        lambda *_args, **_kwargs: pytest.fail("evaluate must not reparse PCAP"),
    )
    path = "/api/v1/demo/baselines/evaluate"
    first = post_json(app, path, {"analysis_id": str(observation.analysis_id)})
    assert first.status_code == 200
    body = first.json()
    assert set(body) == {
        "schema_version", "source", "analysis_id", "observation_id",
        "capture_window_start", "capture_window_end", "activity_span_seconds",
        "capture_fingerprint_status", "model_version", "model_threshold",
        "baseline_store_epoch", "hosts",
    }
    assert body["schema_version"] == "phase6.baseline.v1"
    assert body["source"] == "REPLAYED DEMO TRAFFIC"
    assert body["hosts"][0]["decision"] == "Accept"
    assert body["hosts"][0]["version_after"] == 0
    assert body["hosts"][0]["coverage_confidence"] == "insufficient"
    assert post_json(app, path, {"analysis_id": str(observation.analysis_id)}).json() == body
    history = get(
        app, "/api/v1/demo/baselines/history?host_ip=192.0.2.10",
    )
    assert history.status_code == 200
    assert history.json()["schema_version"] == "phase6.baseline.history.v1"
    assert history.json()["current_version"] == 0
    assert len(history.json()["decisions"]) == 1


def test_baseline_api_rejects_unknown_expired_and_invalid_ids(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    app = load_app()
    now = [0.0]
    registry = ScoredObservationRegistry(clock=lambda: now[0])
    observation = _scored_api_observation()
    registry.register(observation)
    monkeypatch.setattr("app.main.scored_observation_registry", registry)
    monkeypatch.setattr(
        "app.main.adaptive_baseline_store", AdaptiveBaselineStore(),
        raising=False,
    )
    path = "/api/v1/demo/baselines/evaluate"
    assert post_json(app, path, {"analysis_id": str(uuid4())}).status_code == 404
    assert post_json(app, path, {"analysis_id": "not-a-uuid"}).status_code == 422
    now[0] = 901.0
    expired = post_json(app, path, {"analysis_id": str(observation.analysis_id)})
    assert expired.status_code == 404
    assert expired.json()["detail"]["code"] == "ANALYSIS_EXPIRED"
    assert get(
        app, "/api/v1/demo/baselines/history?host_ip=not-an-ip",
    ).status_code == 422
    assert get(
        app, "/api/v1/demo/baselines/history?host_ip=203.0.113.99",
    ).status_code == 404


@pytest.mark.skipif(
    "NEXUS_TEST_PHASE4_NORMAL_PCAP_PATH" not in os.environ,
    reason="real fixed training fixture is not mounted",
)
def test_real_parser_upload_to_guarded_evaluation_uses_scored_analysis(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path,
) -> None:
    app = load_app()
    generator = Path("/app/scripts/generate_increment2_scenarios.py")
    generated = subprocess.run(
        [sys.executable, str(generator), str(tmp_path)],
        capture_output=True, text=True, check=False,
    )
    assert generated.returncode == 0, generated.stderr
    monkeypatch.setenv(
        "NEXUS_DETECTION_TRAINING_PCAP_PATH",
        os.environ["NEXUS_TEST_PHASE4_NORMAL_PCAP_PATH"],
    )
    monkeypatch.setattr(
        "app.main.scored_observation_registry", ScoredObservationRegistry(),
    )
    monkeypatch.setattr(
        "app.main.adaptive_baseline_store", AdaptiveBaselineStore(),
    )
    upload = post_file(
        app, "/api/v1/demo/upload/analyze",
        filename="normal.pcap",
        content=(tmp_path / "increment2-0.pcap").read_bytes(),
    )
    assert upload.status_code == 200, upload.text
    assert upload.json()["packet_count"] == 8
    assert upload.json()["flow_count"] == 4
    analysis_id = upload.json()["analysis_id"]
    with monkeypatch.context() as no_reparse:
        no_reparse.setattr(
            "app.main.analyze_pcap",
            lambda *_args, **_kwargs: pytest.fail("evaluate reparsed a PCAP"),
        )
        evaluated = post_json(
            app, "/api/v1/demo/baselines/evaluate",
            {"analysis_id": analysis_id},
        )
    assert evaluated.status_code == 200, evaluated.text
    assert evaluated.json()["analysis_id"] == analysis_id
    assert evaluated.json()["hosts"][0]["decision"] == "Accept"
    assert evaluated.json()["hosts"][0]["readiness_after"] == "warming"
    assert evaluated.json()["hosts"][0]["version_after"] == 0
    assert evaluated.json()["hosts"][0]["incident_flow_count"] == 4

    drift_upload = post_file(
        app, "/api/v1/demo/upload/analyze",
        filename="drift.pcap",
        content=(tmp_path / "increment2-1.pcap").read_bytes(),
    )
    assert drift_upload.status_code == 200, drift_upload.text
    drift = post_json(
        app, "/api/v1/demo/baselines/evaluate",
        {"analysis_id": drift_upload.json()["analysis_id"]},
    )
    assert drift.status_code == 200, drift.text
    assert all(host["readiness_after"] == "provisional" for host in drift.json()["hosts"])
    assert all(host["version_after"] == 1 for host in drift.json()["hosts"])

    anomaly_upload = post_file(
        app, "/api/v1/demo/upload/analyze",
        filename="anomalous.pcap",
        content=(tmp_path / "increment2-2.pcap").read_bytes(),
    )
    assert anomaly_upload.status_code == 200, anomaly_upload.text
    assert anomaly_upload.json()["flagged_alert_count"] >= 1
    anomaly = post_json(
        app, "/api/v1/demo/baselines/evaluate",
        {"analysis_id": anomaly_upload.json()["analysis_id"]},
    )
    assert anomaly.status_code == 200, anomaly.text
    assert [host["decision"] for host in anomaly.json()["hosts"]] == [
        "Reject", "Reject",
    ]
    assert all("ML_HIGH" in host["reason_codes"] for host in anomaly.json()["hosts"])
    assert all(host["version_after"] == 1 for host in anomaly.json()["hosts"])
