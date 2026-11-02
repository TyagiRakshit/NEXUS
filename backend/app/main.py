import ipaddress
import os
from datetime import UTC, datetime
from pathlib import Path
from tempfile import NamedTemporaryFile
from typing import Literal
from uuid import UUID, uuid4

from fastapi import FastAPI, File, HTTPException, UploadFile
from pydantic import BaseModel, ConfigDict

from app.adaptive_baseline import (
    AdaptiveBaselineStore,
    AdaptiveCapacityExceeded,
    AdaptiveHostNotFound,
    AdaptiveObservationInvalid,
    ObservationExpired,
    ObservationNotFound,
    ObservationCapacityExceeded,
    ScoredObservation,
    ScoredObservationRegistry,
    capture_digest,
)
from app.anomaly_detection import (
    FeatureDataError,
    ModelUnavailable,
    detect_flows,
    train_detector,
)
from app.hybrid_evaluation import (
    HybridEvaluationConflict,
    HybridEvaluationCoordinator,
    HybridEvaluationNotFound,
)
from app.database import check_database
from app.host_profiles import (
    BaselineAdmissionError,
    InMemoryBaselineStore,
    build_host_profiles,
)
from app.pcap_analysis import (
    FixtureNotFound,
    FixtureUnreadable,
    NoSupportedPackets,
    ParserUnavailable,
    analyze_pcap,
)
from app.secure_telemetry import (
    AnalysisNotFound,
    CryptographyUnavailable,
    EvidenceStorageUnavailable,
    KeyStorageUnavailable,
    NoFlaggedAlert,
    ProtectionNotFound,
    SecureTelemetryStore,
    VerificationFailed,
    HybridArtifactExists,
    HybridCandidateCapacity,
    HybridEvaluationPending,
)


class HealthResponse(BaseModel):
    service: Literal["backend"]
    status: Literal["healthy"]


class ServiceStatuses(BaseModel):
    backend: Literal["healthy"]
    database: Literal["healthy", "unavailable"]


class StatusResponse(BaseModel):
    overall_status: Literal["healthy", "degraded"]
    services: ServiceStatuses


class FlowResponse(BaseModel):
    protocol: str
    source_ip: str
    source_port: int | None
    destination_ip: str
    destination_port: int | None
    packet_count: int
    byte_count: int
    duration_seconds: float
    packets_per_second: float
    bytes_per_second: float


class AnalysisResponse(BaseModel):
    schema_version: Literal["phase2.flow.v1"]
    source: Literal["REPLAYED DEMO TRAFFIC"]
    fixture_id: Literal["phase2-synthetic-v1"]
    analysis_id: UUID
    analyzed_at: datetime
    packet_count: int
    flow_count: int
    flows: list[FlowResponse]


class ProtocolCountResponse(BaseModel):
    protocol: str
    flow_count: int


class CurrentProfileResponse(BaseModel):
    observed_flow_count: int
    protocol_mix: list[ProtocolCountResponse]
    average_bytes_per_flow: float
    average_duration_seconds: float
    average_packets_per_second: float


class ProtocolAverageResponse(BaseModel):
    protocol: str
    average_flow_count: float


class BaselineProfileResponse(BaseModel):
    observed_batch_count: int
    average_flow_count: float
    protocol_mix: list[ProtocolAverageResponse]
    average_bytes_per_flow: float
    average_duration_seconds: float
    average_packets_per_second: float


class HostProfileResponse(BaseModel):
    host_ip: str
    current_profile: CurrentProfileResponse
    baseline: BaselineProfileResponse | None


class ProfileAdaptResponse(BaseModel):
    schema_version: Literal["phase3.profile.v1"]
    source: Literal["REPLAYED DEMO TRAFFIC"]
    fixture_id: Literal["phase3-normal-v1"]
    interpretation: Literal["NORMAL BASELINE ONLY - NO ANOMALY DECISION"]
    analysis_id: UUID
    analyzed_at: datetime
    packet_count: int
    flow_count: int
    baseline_state: Literal["warming", "ready"]
    warmup_required_batches: int
    admitted_batch_count: int
    window_batch_count: int
    baseline_version: int
    previous_baseline_version: int | None
    hosts: list[HostProfileResponse]


class DetectionModelResponse(BaseModel):
    model_type: Literal["IsolationForest"]
    model_version: Literal["phase4-iforest-v1"]
    random_seed: Literal[42]
    training_flow_count: int
    feature_count: Literal[11]
    n_estimators: Literal[100]
    max_samples: Literal[32]
    model_threshold: float


class DetectionResultResponse(FlowResponse):
    anomaly_score: float
    is_statistically_unusual: bool
    risk_score: Literal[20, 60, 90]
    risk_level: Literal["Low", "Medium", "High"]
    alert_flagged: bool
    explanations: list[str]


class DetectionResponse(BaseModel):
    schema_version: Literal["phase4.detection.v1"]
    source: Literal["REPLAYED DEMO TRAFFIC"]
    interpretation: Literal[
        "SYNTHETIC ANOMALY DEMO - STATISTICAL UNUSUALNESS, NOT MALICIOUS PROOF"
    ]
    training_fixture_id: Literal["phase4-normal-train-v1"]
    replay_fixture_id: Literal["phase4-unusual-v1"]
    analysis_id: UUID
    analyzed_at: datetime
    model: DetectionModelResponse
    replay_packet_count: int
    replay_flow_count: int
    flagged_alert_count: int
    results: list[DetectionResultResponse]


class UploadHostProfileResponse(BaseModel):
    host_ip: str
    observed_flow_count: int
    protocol_mix: list[ProtocolCountResponse]
    average_bytes_per_flow: float
    average_duration_seconds: float
    average_packets_per_second: float


class UploadAnalysisResponse(BaseModel):
    schema_version: Literal["demo.upload-analysis.v1"]
    source: Literal["REPLAYED DEMO TRAFFIC"]
    interpretation: Literal[
        "STATISTICAL UNUSUALNESS RELATIVE TO SYNTHETIC TRAINING, NOT MALICIOUS PROOF"
    ]
    analysis_id: UUID
    analyzed_at: datetime
    packet_count: int
    flow_count: int
    flows: list[FlowResponse]
    host_profiles: list[UploadHostProfileResponse]
    model: DetectionModelResponse
    flagged_alert_count: int
    results: list[DetectionResultResponse]


class BaselineFeatureResponse(BaseModel):
    observed_flow_count: float
    average_bytes_per_flow: float
    average_duration_seconds: float
    average_packets_per_second: float
    protocol_shares: dict[str, float]


class BaselineDeviationResponse(BaseModel):
    feature: str
    observed: float
    baseline: float
    deviation: float
    accept_limit: float
    hold_limit: float
    band: Literal["Accept", "Hold", "Reject"]
    reason_code: str


class BaselineFindingResponse(BaseModel):
    finding_id: UUID
    kind: Literal["BASELINE_SEVERE_DEVIATION", "ADAPTATION_LIMIT_REACHED"]
    severity: Literal["High", "Medium"]
    evidence_features: list[str]
    explanation: str
    is_phase5c_signed_alert: Literal[False]


class BaselineHostResponse(BaseModel):
    host_ip: str
    decision: Literal["Accept", "Hold", "Reject"]
    reason_codes: list[str]
    readiness_before: Literal["absent", "warming", "provisional", "ready"]
    readiness_after: Literal["absent", "warming", "provisional", "ready"]
    coverage_confidence: Literal["insufficient", "limited", "accumulated"]
    accepted_count_before: int
    accepted_count_after: int
    version_before: int | None
    version_after: int | None
    probation_count: int
    incident_flow_count: int
    high_flow_count: int
    flow_evidence_refs: list[int]
    current_features: BaselineFeatureResponse
    baseline_before: BaselineFeatureResponse | None
    baseline_after: BaselineFeatureResponse | None
    feature_deviations: list[BaselineDeviationResponse]
    last_evaluated_window_start: datetime | None
    last_admitted_window_start: datetime | None
    findings: list[BaselineFindingResponse]


class BaselineEvaluateRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    analysis_id: UUID


class BaselineEvaluateResponse(BaseModel):
    schema_version: Literal["phase6.baseline.v1"]
    source: Literal["REPLAYED DEMO TRAFFIC"]
    analysis_id: UUID
    observation_id: UUID
    capture_window_start: datetime | None
    capture_window_end: datetime | None
    activity_span_seconds: float
    capture_fingerprint_status: Literal["new", "duplicate"]
    model_version: str
    model_threshold: float
    baseline_store_epoch: UUID
    hosts: list[BaselineHostResponse]


class BaselineHistorySnapshotResponse(BaseModel):
    version: int
    observation_id: UUID
    window_start: datetime | None
    reason_code: str
    features_before: BaselineFeatureResponse | None
    features_after: BaselineFeatureResponse


class BaselineHistoryDecisionResponse(BaseModel):
    observation_id: UUID
    window_start: datetime | None
    decision: Literal["Accept", "Hold", "Reject"]
    reason_codes: list[str]
    version_before: int | None
    version_after: int | None
    finding_ids: list[UUID]


class BaselineHistoryResponse(BaseModel):
    schema_version: Literal["phase6.baseline.history.v1"]
    source: Literal["REPLAYED DEMO TRAFFIC"]
    baseline_store_epoch: UUID
    host_ip: str
    readiness: Literal["absent", "warming", "provisional", "ready"]
    coverage_confidence: Literal["insufficient", "limited", "accumulated"]
    current_version: int | None
    anchor_version: int | None
    current_baseline: BaselineFeatureResponse | None
    snapshots: list[BaselineHistorySnapshotResponse]
    decisions: list[BaselineHistoryDecisionResponse]


class HybridEvaluateRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    analysis_id: UUID


class HybridEvaluateResponse(BaseModel):
    schema_version: Literal["phase7.hybrid.v1"]
    source: Literal["REPLAYED DEMO TRAFFIC"]
    analysis_id: UUID
    observation_id: UUID
    capture_window_start: datetime | None
    capture_window_end: datetime | None
    model_version: str
    model_threshold: float
    rule_set_version: Literal["increment4-demo-rules-v1"]
    baseline_store_epoch: UUID
    flow_results: list[dict[str, object]]
    rule_assessments: list[dict[str, object]]
    hosts: list[dict[str, object]]
    findings: list[dict[str, object]]
    telemetry: dict[str, object]

class HybridProtectResponse(BaseModel):
    schema_version: Literal["phase7.secure-telemetry.v2"]
    protection_id: UUID
    analysis_id: UUID
    status: Literal["protected"]
    protected_count: int


class HybridVerifyResponse(BaseModel):
    schema_version: Literal["phase7.secure-telemetry.v2"]
    protection_id: UUID
    analysis_id: UUID
    verification: Literal["verified"]
    aes_gcm: Literal["authenticated"]
    sha256: Literal["verified"]
    rsa_pss: Literal["valid"]
    protected_count: int
    verified_count: int
    all_valid: Literal[True]


class HybridTamperResponse(BaseModel):
    schema_version: Literal["phase7.secure-telemetry.v2"]
    protection_id: UUID
    analysis_id: UUID
    verification: Literal["rejected"]
    reason: Literal["tamper_detected"]
    protected_count: int
    tamper_rejected: Literal[True]


class HybridTelemetryStatusResponse(BaseModel):
    schema_version: Literal["phase7.secure-telemetry.v2"]
    analysis_id: UUID
    status: Literal["preparing", "not_requested", "protected"]
    protected_count: int

class ProtectAlertRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    analysis_id: UUID


class ProtectAlertResponse(BaseModel):
    schema_version: Literal["phase5.secure-telemetry.v1"]
    protection_id: UUID
    analysis_id: UUID
    status: Literal["protected"]
    aes_gcm: Literal["protected"]
    protected_count: int


class VerifyAlertResponse(BaseModel):
    schema_version: Literal["phase5.secure-telemetry.v1"]
    protection_id: UUID
    analysis_id: UUID
    verification: Literal["verified"]
    aes_gcm: Literal["authenticated"]
    sha256: Literal["verified"]
    rsa_pss: Literal["valid"]
    protected_count: int
    verified_count: int
    all_valid: Literal[True]


class TamperAlertResponse(BaseModel):
    schema_version: Literal["phase5.secure-telemetry.v1"]
    protection_id: UUID
    analysis_id: UUID
    verification: Literal["rejected"]
    reason: Literal["tamper_detected"]
    protected_count: int
    tamper_rejected: Literal[True]


app = FastAPI(title="NEXUS")
baseline_store = InMemoryBaselineStore()
secure_telemetry_store = SecureTelemetryStore()
scored_observation_registry = ScoredObservationRegistry()
adaptive_baseline_store = AdaptiveBaselineStore()
hybrid_coordinator = HybridEvaluationCoordinator(
    adaptive_baseline_store,
    candidate_registrar=secure_telemetry_store.register_hybrid_candidate,
    candidate_unregistrar=secure_telemetry_store.unregister_hybrid_candidate,
    candidate_finalizer=secure_telemetry_store.finalize_hybrid_candidate,
)
UPLOAD_MAX_BYTES = 1_048_576
UPLOAD_MAX_PACKETS = 2_000
UPLOAD_TEMP_DIRECTORY: Path | None = None
UPLOAD_CHUNK_BYTES = 65_536


@app.get("/api/v1/health", response_model=HealthResponse)
def health() -> HealthResponse:
    return HealthResponse(service="backend", status="healthy")


@app.get("/api/v1/status", response_model=StatusResponse)
def status() -> StatusResponse:
    database_status = check_database(os.getenv("DATABASE_URL", ""))
    overall_status = "healthy" if database_status == "healthy" else "degraded"
    return StatusResponse(
        overall_status=overall_status,
        services=ServiceStatuses(
            backend="healthy",
            database=database_status,
        ),
    )


@app.post("/api/v1/demo/flows/analyze", response_model=AnalysisResponse)
def analyze_demo_fixture() -> AnalysisResponse:
    fixture_path = Path(
        os.getenv("NEXUS_DEMO_PCAP_PATH", "/app/fixtures/phase2-demo.pcap")
    )
    try:
        result = analyze_pcap(fixture_path)
    except FixtureNotFound as error:
        raise HTTPException(
            status_code=404,
            detail={"code": "fixture_not_found", "message": str(error)},
        ) from error
    except FixtureUnreadable as error:
        raise HTTPException(
            status_code=422,
            detail={"code": "fixture_unreadable", "message": str(error)},
        ) from error
    except NoSupportedPackets as error:
        raise HTTPException(
            status_code=422,
            detail={"code": "no_supported_packets", "message": str(error)},
        ) from error
    except ParserUnavailable as error:
        raise HTTPException(
            status_code=503,
            detail={"code": "parser_unavailable", "message": str(error)},
        ) from error

    flows = [
        FlowResponse(
            protocol=flow.protocol,
            source_ip=flow.source_ip,
            source_port=flow.source_port,
            destination_ip=flow.destination_ip,
            destination_port=flow.destination_port,
            packet_count=flow.packet_count,
            byte_count=flow.byte_count,
            duration_seconds=flow.duration_seconds,
            packets_per_second=flow.packets_per_second,
            bytes_per_second=flow.bytes_per_second,
        )
        for flow in result.flows
    ]
    return AnalysisResponse(
        schema_version="phase2.flow.v1",
        source="REPLAYED DEMO TRAFFIC",
        fixture_id="phase2-synthetic-v1",
        analysis_id=uuid4(),
        analyzed_at=datetime.now(UTC),
        packet_count=result.packet_count,
        flow_count=len(flows),
        flows=flows,
    )


@app.post("/api/v1/demo/profiles/adapt", response_model=ProfileAdaptResponse)
def adapt_normal_profiles() -> ProfileAdaptResponse:
    fixture_path = Path(
        os.getenv("NEXUS_NORMAL_PCAP_PATH", "/app/fixtures/phase3-normal.pcap")
    )
    try:
        analysis = analyze_pcap(fixture_path)
    except FixtureNotFound as error:
        raise HTTPException(
            status_code=404,
            detail={"code": "fixture_not_found", "message": str(error)},
        ) from error
    except FixtureUnreadable as error:
        raise HTTPException(
            status_code=422,
            detail={"code": "fixture_unreadable", "message": str(error)},
        ) from error
    except NoSupportedPackets as error:
        raise HTTPException(
            status_code=422,
            detail={"code": "no_supported_packets", "message": str(error)},
        ) from error
    except ParserUnavailable as error:
        raise HTTPException(
            status_code=503,
            detail={"code": "parser_unavailable", "message": str(error)},
        ) from error

    profiles = build_host_profiles(analysis.flows)
    if not profiles:
        raise HTTPException(
            status_code=422,
            detail={
                "code": "empty_profile_batch",
                "message": "Normal replay produced no host profiles.",
            },
        )
    try:
        baseline = baseline_store.admit_normal_batch(
            profiles,
            fixture_id="phase3-normal-v1",
        )
    except BaselineAdmissionError as error:
        raise HTTPException(
            status_code=422,
            detail={"code": "baseline_batch_rejected", "message": str(error)},
        ) from error

    baselines_by_host = {
        item.host_ip: item for item in baseline.baseline_profiles
    }
    hosts: list[HostProfileResponse] = []
    for profile in baseline.current_profiles:
        baseline_profile = baselines_by_host.get(profile.host_ip)
        hosts.append(
            HostProfileResponse(
                host_ip=profile.host_ip,
                current_profile=CurrentProfileResponse(
                    observed_flow_count=profile.observed_flow_count,
                    protocol_mix=[
                        ProtocolCountResponse(
                            protocol=item.protocol,
                            flow_count=item.flow_count,
                        )
                        for item in profile.protocol_mix
                    ],
                    average_bytes_per_flow=profile.average_bytes_per_flow,
                    average_duration_seconds=profile.average_duration_seconds,
                    average_packets_per_second=profile.average_packets_per_second,
                ),
                baseline=(
                    None
                    if baseline_profile is None
                    else BaselineProfileResponse(
                        observed_batch_count=baseline_profile.observed_batch_count,
                        average_flow_count=baseline_profile.average_flow_count,
                        protocol_mix=[
                            ProtocolAverageResponse(
                                protocol=item.protocol,
                                average_flow_count=item.average_flow_count,
                            )
                            for item in baseline_profile.protocol_mix
                        ],
                        average_bytes_per_flow=(
                            baseline_profile.average_bytes_per_flow
                        ),
                        average_duration_seconds=(
                            baseline_profile.average_duration_seconds
                        ),
                        average_packets_per_second=(
                            baseline_profile.average_packets_per_second
                        ),
                    )
                ),
            )
        )

    return ProfileAdaptResponse(
        schema_version="phase3.profile.v1",
        source="REPLAYED DEMO TRAFFIC",
        fixture_id="phase3-normal-v1",
        interpretation="NORMAL BASELINE ONLY - NO ANOMALY DECISION",
        analysis_id=uuid4(),
        analyzed_at=datetime.now(UTC),
        packet_count=analysis.packet_count,
        flow_count=len(analysis.flows),
        baseline_state=baseline.baseline_state,
        warmup_required_batches=baseline.warmup_required_batches,
        admitted_batch_count=baseline.admitted_batch_count,
        window_batch_count=baseline.window_batch_count,
        baseline_version=baseline.baseline_version,
        previous_baseline_version=baseline.previous_baseline_version,
        hosts=hosts,
    )


@app.post("/api/v1/demo/detection/analyze", response_model=DetectionResponse)
def analyze_detection_fixture() -> DetectionResponse:
    training_path = Path(
        os.getenv(
            "NEXUS_DETECTION_TRAINING_PCAP_PATH",
            "/app/fixtures/phase4-normal-training.pcap",
        )
    )
    unusual_path = Path(
        os.getenv(
            "NEXUS_DETECTION_UNUSUAL_PCAP_PATH",
            "/app/fixtures/phase4-unusual.pcap",
        )
    )
    try:
        training = analyze_pcap(training_path)
        replay = analyze_pcap(unusual_path)
    except FixtureNotFound as error:
        raise HTTPException(
            status_code=404,
            detail={
                "code": "detection_fixture_not_found",
                "message": "Offline detection fixture is unavailable.",
            },
        ) from error
    except FixtureUnreadable as error:
        raise HTTPException(
            status_code=422,
            detail={
                "code": "detection_fixture_unreadable",
                "message": "Offline detection fixture cannot be analyzed.",
            },
        ) from error
    except NoSupportedPackets as error:
        raise HTTPException(
            status_code=422,
            detail={
                "code": "detection_no_supported_flows",
                "message": "Offline detection fixture contains no supported flows.",
            },
        ) from error
    except ParserUnavailable as error:
        raise HTTPException(
            status_code=503,
            detail={
                "code": "detection_parser_unavailable",
                "message": "Offline detection parsing is unavailable.",
            },
        ) from error

    try:
        detector = train_detector(training.flows)
        detected = detect_flows(detector, replay.flows)
    except FeatureDataError as error:
        raise HTTPException(
            status_code=422,
            detail={
                "code": "insufficient_training_data",
                "message": "Synthetic training data is insufficient.",
            },
        ) from error
    except ModelUnavailable as error:
        raise HTTPException(
            status_code=503,
            detail={
                "code": "model_unavailable",
                "message": "Offline anomaly detection is unavailable.",
            },
        ) from error

    results = [
        DetectionResultResponse(
            protocol=item.flow.protocol,
            source_ip=item.flow.source_ip,
            source_port=item.flow.source_port,
            destination_ip=item.flow.destination_ip,
            destination_port=item.flow.destination_port,
            packet_count=item.flow.packet_count,
            byte_count=item.flow.byte_count,
            duration_seconds=item.flow.duration_seconds,
            packets_per_second=item.flow.packets_per_second,
            bytes_per_second=item.flow.bytes_per_second,
            anomaly_score=item.anomaly_score,
            is_statistically_unusual=item.is_statistically_unusual,
            risk_score=item.risk_score,
            risk_level=item.risk_level,
            alert_flagged=item.alert_flagged,
            explanations=list(item.explanations),
        )
        for item in detected
    ]
    return DetectionResponse(
        schema_version="phase4.detection.v1",
        source="REPLAYED DEMO TRAFFIC",
        interpretation=(
            "SYNTHETIC ANOMALY DEMO - STATISTICAL UNUSUALNESS, "
            "NOT MALICIOUS PROOF"
        ),
        training_fixture_id="phase4-normal-train-v1",
        replay_fixture_id="phase4-unusual-v1",
        analysis_id=uuid4(),
        analyzed_at=datetime.now(UTC),
        model=DetectionModelResponse(
            model_type="IsolationForest",
            model_version="phase4-iforest-v1",
            random_seed=42,
            training_flow_count=detector.training_flow_count,
            feature_count=11,
            n_estimators=100,
            max_samples=32,
            model_threshold=detector.model_threshold,
        ),
        replay_packet_count=replay.packet_count,
        replay_flow_count=len(replay.flows),
        flagged_alert_count=sum(item.alert_flagged for item in detected),
        results=results,
    )


async def _write_uploaded_pcap(file: UploadFile) -> Path:
    temporary_path: Path | None = None
    try:
        with NamedTemporaryFile(
            mode="wb",
            prefix="nexus-upload-",
            suffix=".pcap",
            dir=UPLOAD_TEMP_DIRECTORY,
            delete=False,
        ) as temporary:
            temporary_path = Path(temporary.name)
            total_bytes = 0
            while chunk := await file.read(UPLOAD_CHUNK_BYTES):
                total_bytes += len(chunk)
                if total_bytes > UPLOAD_MAX_BYTES:
                    raise HTTPException(
                        status_code=413,
                        detail={
                            "code": "upload_too_large",
                            "message": "Uploaded PCAP must be 1 MiB or smaller.",
                        },
                    )
                temporary.write(chunk)
        return temporary_path
    except HTTPException:
        if temporary_path is not None:
            temporary_path.unlink(missing_ok=True)
        raise
    except OSError as error:
        if temporary_path is not None:
            temporary_path.unlink(missing_ok=True)
        raise HTTPException(
            status_code=503,
            detail={
                "code": "upload_storage_unavailable",
                "message": "Uploaded PCAP cannot be stored for analysis.",
            },
        ) from error


@app.post("/api/v1/demo/upload/analyze", response_model=UploadAnalysisResponse)
async def analyze_uploaded_pcap(file: UploadFile = File(...)) -> UploadAnalysisResponse:
    if not file.filename or Path(file.filename).suffix.lower() != ".pcap":
        await file.close()
        raise HTTPException(
            status_code=422,
            detail={
                "code": "upload_invalid_extension",
                "message": "Choose a .pcap file.",
            },
        )

    temporary_path: Path | None = None
    try:
        temporary_path = await _write_uploaded_pcap(file)
        try:
            uploaded = analyze_pcap(
                temporary_path,
                max_packets=UPLOAD_MAX_PACKETS,
            )
        except FixtureUnreadable as error:
            raise HTTPException(
                status_code=422,
                detail={
                    "code": "upload_unreadable",
                    "message": "Uploaded PCAP cannot be analyzed.",
                },
            ) from error
        except NoSupportedPackets as error:
            raise HTTPException(
                status_code=422,
                detail={
                    "code": "upload_no_supported_flows",
                    "message": "Uploaded PCAP contains no supported flows.",
                },
            ) from error
        except (FixtureNotFound, ParserUnavailable) as error:
            raise HTTPException(
                status_code=503,
                detail={
                    "code": "upload_parser_unavailable",
                    "message": "Uploaded PCAP parsing is unavailable.",
                },
            ) from error

        training_path = Path(
            os.getenv(
                "NEXUS_DETECTION_TRAINING_PCAP_PATH",
                "/app/fixtures/phase4-normal-training.pcap",
            )
        )
        try:
            training = analyze_pcap(training_path, max_packets=UPLOAD_MAX_PACKETS)
            detector = train_detector(training.flows)
            detected = detect_flows(detector, uploaded.flows)
        except (FixtureNotFound, FixtureUnreadable, NoSupportedPackets) as error:
            raise HTTPException(
                status_code=503,
                detail={
                    "code": "upload_training_unavailable",
                    "message": "Synthetic training data is unavailable.",
                },
            ) from error
        except ParserUnavailable as error:
            raise HTTPException(
                status_code=503,
                detail={
                    "code": "upload_parser_unavailable",
                    "message": "Uploaded PCAP parsing is unavailable.",
                },
            ) from error
        except FeatureDataError as error:
            raise HTTPException(
                status_code=422,
                detail={
                    "code": "insufficient_training_data",
                    "message": "Synthetic training data is insufficient.",
                },
            ) from error
        except ModelUnavailable as error:
            raise HTTPException(
                status_code=503,
                detail={
                    "code": "model_unavailable",
                    "message": "Offline anomaly detection is unavailable.",
                },
            ) from error

        flows = [
            FlowResponse(
                protocol=flow.protocol,
                source_ip=flow.source_ip,
                source_port=flow.source_port,
                destination_ip=flow.destination_ip,
                destination_port=flow.destination_port,
                packet_count=flow.packet_count,
                byte_count=flow.byte_count,
                duration_seconds=flow.duration_seconds,
                packets_per_second=flow.packets_per_second,
                bytes_per_second=flow.bytes_per_second,
            )
            for flow in uploaded.flows
        ]
        host_profiles = [
            UploadHostProfileResponse(
                host_ip=profile.host_ip,
                observed_flow_count=profile.observed_flow_count,
                protocol_mix=[
                    ProtocolCountResponse(
                        protocol=item.protocol,
                        flow_count=item.flow_count,
                    )
                    for item in profile.protocol_mix
                ],
                average_bytes_per_flow=profile.average_bytes_per_flow,
                average_duration_seconds=profile.average_duration_seconds,
                average_packets_per_second=profile.average_packets_per_second,
            )
            for profile in build_host_profiles(uploaded.flows)
        ]
        results = [
            DetectionResultResponse(
                protocol=item.flow.protocol,
                source_ip=item.flow.source_ip,
                source_port=item.flow.source_port,
                destination_ip=item.flow.destination_ip,
                destination_port=item.flow.destination_port,
                packet_count=item.flow.packet_count,
                byte_count=item.flow.byte_count,
                duration_seconds=item.flow.duration_seconds,
                packets_per_second=item.flow.packets_per_second,
                bytes_per_second=item.flow.bytes_per_second,
                anomaly_score=item.anomaly_score,
                is_statistically_unusual=item.is_statistically_unusual,
                risk_score=item.risk_score,
                risk_level=item.risk_level,
                alert_flagged=item.alert_flagged,
                explanations=list(item.explanations),
            )
            for item in detected
        ]
        analysis_id = uuid4()
        response = UploadAnalysisResponse(
            schema_version="demo.upload-analysis.v1",
            source="REPLAYED DEMO TRAFFIC",
            interpretation=(
                "STATISTICAL UNUSUALNESS RELATIVE TO SYNTHETIC TRAINING, "
                "NOT MALICIOUS PROOF"
            ),
            analysis_id=analysis_id,
            analyzed_at=datetime.now(UTC),
            packet_count=uploaded.packet_count,
            flow_count=len(flows),
            flows=flows,
            host_profiles=host_profiles,
            model=DetectionModelResponse(
                model_type="IsolationForest",
                model_version="phase4-iforest-v1",
                random_seed=42,
                training_flow_count=detector.training_flow_count,
                feature_count=11,
                n_estimators=100,
                max_samples=32,
                model_threshold=detector.model_threshold,
            ),
            flagged_alert_count=sum(item.alert_flagged for item in detected),
            results=results,
        )
        try:
            fingerprint = capture_digest(temporary_path)
        except OSError as error:
            raise HTTPException(
                status_code=503,
                detail={
                    "code": "upload_storage_unavailable",
                    "message": "Uploaded PCAP cannot be stored for analysis.",
                },
            ) from error
        observation = ScoredObservation(
            analysis_id=analysis_id,
            observation_id=uuid4(),
            capture_digest=fingerprint,
            analysis=uploaded,
            detected=detected,
            training_reference=detector.normalizer.reference,
            model_version=response.model.model_version,
            model_threshold=detector.model_threshold,
        )
        try:
            scored_observation_registry.register(observation)
        except ObservationCapacityExceeded as error:
            raise HTTPException(
                status_code=503,
                detail={
                    "code": "upload_capacity_limit",
                    "message": "Offline analysis capacity is temporarily full.",
                },
            ) from error
        try:
            secure_telemetry_store.register_upload(analysis_id, results)
        except Exception as error:
            scored_observation_registry.unregister(analysis_id)
            raise HTTPException(
                status_code=503,
                detail={
                    "code": "upload_registration_unavailable",
                    "message": "Offline analysis could not be retained.",
                },
            ) from error
        return response
    finally:
        await file.close()
        if temporary_path is not None:
            temporary_path.unlink(missing_ok=True)


@app.post(
    "/api/v1/demo/baselines/evaluate",
    response_model=BaselineEvaluateResponse,
)
def evaluate_adaptive_baseline(
    request: BaselineEvaluateRequest,
) -> BaselineEvaluateResponse:
    try:
        observation = scored_observation_registry.get(request.analysis_id)
    except ObservationExpired as error:
        raise HTTPException(
            status_code=404,
            detail={
                "code": "ANALYSIS_EXPIRED",
                "message": "Offline analysis is no longer available.",
            },
        ) from error
    except ObservationNotFound as error:
        raise HTTPException(
            status_code=404,
            detail={
                "code": "ANALYSIS_NOT_FOUND",
                "message": "Offline analysis was not found.",
            },
        ) from error
    try:
        result = adaptive_baseline_store.evaluate(observation)
    except AdaptiveCapacityExceeded as error:
        raise HTTPException(
            status_code=503,
            detail={
                "code": "CAPACITY_LIMIT",
                "message": "Adaptive baseline capacity is temporarily full.",
            },
        ) from error
    except AdaptiveObservationInvalid as error:
        raise HTTPException(
            status_code=422,
            detail={
                "code": "ANALYSIS_INVALID",
                "message": "Offline analysis has incompatible scored evidence.",
            },
        ) from error
    return BaselineEvaluateResponse.model_validate(result)


@app.get(
    "/api/v1/demo/baselines/history",
    response_model=BaselineHistoryResponse,
)
def adaptive_baseline_history(host_ip: str) -> BaselineHistoryResponse:
    try:
        normalized = str(ipaddress.ip_address(host_ip))
    except ValueError as error:
        raise HTTPException(
            status_code=422,
            detail={"code": "INVALID_HOST_IP", "message": "Choose a valid host IP."},
        ) from error
    try:
        result = adaptive_baseline_store.history(normalized)
    except AdaptiveHostNotFound as error:
        raise HTTPException(
            status_code=404,
            detail={"code": "HOST_NOT_FOUND", "message": "Host history was not found."},
        ) from error
    return BaselineHistoryResponse.model_validate(result)


@app.post(
    "/api/v1/demo/hybrid/evaluate",
    response_model=HybridEvaluateResponse,
)
def evaluate_hybrid(request: HybridEvaluateRequest) -> HybridEvaluateResponse:
    try:
        observation = scored_observation_registry.get(request.analysis_id)
    except ObservationExpired as error:
        raise HTTPException(
            status_code=404,
            detail={"code": "ANALYSIS_EXPIRED", "message": "Offline analysis is no longer available."},
        ) from error
    except ObservationNotFound as error:
        raise HTTPException(
            status_code=404,
            detail={"code": "ANALYSIS_NOT_FOUND", "message": "Offline analysis was not found."},
        ) from error
    try:
        result = hybrid_coordinator.evaluate_hybrid(observation)
    except HybridEvaluationConflict as error:
        raise HTTPException(
            status_code=409,
            detail={"code": "HYBRID_EVALUATION_CONFLICT", "message": "A finalized host admission cannot be changed by later rule evidence."},
        ) from error
    except (AdaptiveCapacityExceeded, HybridCandidateCapacity) as error:
        raise HTTPException(
            status_code=503,
            detail={"code": "CAPACITY_LIMIT", "message": "Offline evaluation capacity is temporarily full."},
        ) from error
    except AdaptiveObservationInvalid as error:
        raise HTTPException(
            status_code=422,
            detail={"code": "ANALYSIS_INVALID", "message": "Offline analysis has incompatible scored evidence."},
        ) from error
    return HybridEvaluateResponse.model_validate(result)


@app.get(
    "/api/v1/demo/hybrid/{analysis_id}",
    response_model=HybridEvaluateResponse,
)
def get_hybrid(analysis_id: UUID) -> HybridEvaluateResponse:
    try:
        scored_observation_registry.get(analysis_id)
        result = hybrid_coordinator.get_hybrid(str(analysis_id))
    except (ObservationExpired, ObservationNotFound, HybridEvaluationNotFound) as error:
        raise HTTPException(
            status_code=404,
            detail={"code": "HYBRID_ANALYSIS_NOT_FOUND", "message": "Hybrid analysis is unavailable or expired."},
        ) from error
    return HybridEvaluateResponse.model_validate(result)

@app.post(
    "/api/v1/demo/hybrid/telemetry/protect",
    response_model=HybridProtectResponse,
)
def protect_hybrid_findings(request: ProtectAlertRequest) -> HybridProtectResponse:
    try:
        result = secure_telemetry_store.protect_hybrid(request.analysis_id)
    except HybridEvaluationPending as error:
        raise HTTPException(
            status_code=409,
            detail={"code": "HYBRID_EVALUATION_PENDING", "message": "Hybrid evaluation has not finalized."},
        ) from error
    except AnalysisNotFound as error:
        raise HTTPException(
            status_code=404,
            detail={"code": "HYBRID_ANALYSIS_NOT_FOUND", "message": "Hybrid analysis is unavailable or expired."},
        ) from error
    except NoFlaggedAlert as error:
        raise HTTPException(
            status_code=409,
            detail={"code": "NO_ELIGIBLE_FINDING", "message": "Hybrid analysis has no eligible High finding."},
        ) from error
    except HybridArtifactExists as error:
        raise HTTPException(
            status_code=409,
            detail={"code": "ARTIFACT_ALREADY_EXISTS", "message": "A protected v2 artifact already exists."},
        ) from error
    except (KeyStorageUnavailable, EvidenceStorageUnavailable, CryptographyUnavailable) as error:
        raise HTTPException(
            status_code=503,
            detail={"code": "HYBRID_PROTECTION_UNAVAILABLE", "message": "Local demo protection is unavailable."},
        ) from error
    return HybridProtectResponse(
        schema_version="phase7.secure-telemetry.v2",
        protection_id=result.analysis_id,
        analysis_id=result.analysis_id,
        status="protected",
        protected_count=result.protected_count,
    )


@app.get(
    "/api/v1/demo/hybrid/telemetry/{analysis_id}/status",
    response_model=HybridTelemetryStatusResponse,
)
def hybrid_telemetry_status(analysis_id: UUID) -> HybridTelemetryStatusResponse:
    try:
        result = secure_telemetry_store.hybrid_status(analysis_id)
    except AnalysisNotFound as error:
        raise HTTPException(
            status_code=404,
            detail={"code": "HYBRID_ANALYSIS_NOT_FOUND", "message": "Hybrid analysis is unavailable or expired."},
        ) from error
    return HybridTelemetryStatusResponse(
        schema_version="phase7.secure-telemetry.v2",
        analysis_id=analysis_id,
        **result,
    )


@app.post(
    "/api/v1/demo/hybrid/telemetry/{protection_id}/verify",
    response_model=HybridVerifyResponse,
)
def verify_hybrid_findings(protection_id: UUID) -> HybridVerifyResponse:
    try:
        result = secure_telemetry_store.verify_hybrid(protection_id)
    except ProtectionNotFound as error:
        raise HTTPException(
            status_code=404,
            detail={"code": "HYBRID_PROTECTION_NOT_FOUND", "message": "Protected hybrid batch is unavailable or expired."},
        ) from error
    except VerificationFailed as error:
        raise HTTPException(
            status_code=409,
            detail={"code": "VERIFICATION_FAILED", "message": "Protected hybrid batch verification failed."},
        ) from error
    return HybridVerifyResponse(
        schema_version="phase7.secure-telemetry.v2",
        protection_id=result.analysis_id,
        analysis_id=result.analysis_id,
        verification="verified",
        aes_gcm="authenticated",
        sha256="verified",
        rsa_pss="valid",
        protected_count=result.protected_count,
        verified_count=result.verified_count,
        all_valid=True,
    )


@app.post(
    "/api/v1/demo/hybrid/telemetry/{protection_id}/verify-tampered",
    response_model=HybridTamperResponse,
)
def verify_hybrid_tampered_copy(protection_id: UUID) -> HybridTamperResponse:
    try:
        result = secure_telemetry_store.verify_hybrid_tampered_copy(protection_id)
    except ProtectionNotFound as error:
        raise HTTPException(
            status_code=404,
            detail={"code": "HYBRID_PROTECTION_NOT_FOUND", "message": "Protected hybrid batch is unavailable or expired."},
        ) from error
    return HybridTamperResponse(
        schema_version="phase7.secure-telemetry.v2",
        protection_id=result.analysis_id,
        analysis_id=result.analysis_id,
        verification="rejected",
        reason="tamper_detected",
        protected_count=result.protected_count,
        tamper_rejected=True,
    )

@app.post(
    "/api/v1/demo/telemetry/protect",
    response_model=ProtectAlertResponse,
)
def protect_flagged_alert(request: ProtectAlertRequest) -> ProtectAlertResponse:
    try:
        status = secure_telemetry_store.protect_all_flagged(request.analysis_id)
    except AnalysisNotFound as error:
        raise HTTPException(
            status_code=404,
            detail={
                "code": "analysis_not_found_or_expired",
                "message": "Upload analysis is unavailable or expired.",
            },
        ) from error
    except NoFlaggedAlert as error:
        raise HTTPException(
            status_code=409,
            detail={
                "code": "no_flagged_alert",
                "message": "Upload analysis has no flagged alert to protect.",
            },
        ) from error
    except KeyStorageUnavailable as error:
        raise HTTPException(
            status_code=503,
            detail={
                "code": "key_storage_unavailable",
                "message": "Local demo key storage is unavailable.",
            },
        ) from error
    except EvidenceStorageUnavailable as error:
        raise HTTPException(
            status_code=503,
            detail={
                "code": "evidence_storage_unavailable",
                "message": "Local demo evidence storage is unavailable.",
            },
        ) from error
    except CryptographyUnavailable as error:
        raise HTTPException(
            status_code=503,
            detail={
                "code": "cryptography_unavailable",
                "message": "Secure telemetry protection is unavailable.",
            },
        ) from error
    return ProtectAlertResponse(
        schema_version="phase5.secure-telemetry.v1",
        protection_id=status.analysis_id,
        analysis_id=status.analysis_id,
        status="protected",
        aes_gcm="protected",
        protected_count=status.protected_count,
    )


@app.post(
    "/api/v1/demo/telemetry/{protection_id}/verify",
    response_model=VerifyAlertResponse,
)
def verify_protected_alert(protection_id: UUID) -> VerifyAlertResponse:
    try:
        status = secure_telemetry_store.verify_all(protection_id)
    except ProtectionNotFound as error:
        raise HTTPException(
            status_code=404,
            detail={
                "code": "protection_not_found_or_expired",
                "message": "Protected alert is unavailable or expired.",
            },
        ) from error
    except VerificationFailed as error:
        raise HTTPException(
            status_code=409,
            detail={
                "code": "verification_failed",
                "message": "Protected alert verification failed.",
            },
        ) from error
    except EvidenceStorageUnavailable as error:
        raise HTTPException(
            status_code=503,
            detail={
                "code": "evidence_storage_unavailable",
                "message": "Local demo evidence storage is unavailable.",
            },
        ) from error
    except CryptographyUnavailable as error:
        raise HTTPException(
            status_code=503,
            detail={
                "code": "cryptography_unavailable",
                "message": "Secure telemetry verification is unavailable.",
            },
        ) from error
    return VerifyAlertResponse(
        schema_version="phase5.secure-telemetry.v1",
        protection_id=status.analysis_id,
        analysis_id=status.analysis_id,
        verification="verified",
        aes_gcm="authenticated",
        sha256="verified",
        rsa_pss="valid",
        protected_count=status.protected_count,
        verified_count=status.verified_count,
        all_valid=status.all_valid,
    )


@app.post(
    "/api/v1/demo/telemetry/{protection_id}/verify-tampered",
    response_model=TamperAlertResponse,
)
def verify_tampered_alert_copy(protection_id: UUID) -> TamperAlertResponse:
    try:
        status = secure_telemetry_store.verify_tampered_batch_copy(protection_id)
    except ProtectionNotFound as error:
        raise HTTPException(
            status_code=404,
            detail={
                "code": "protection_not_found_or_expired",
                "message": "Protected alert is unavailable or expired.",
            },
        ) from error
    except EvidenceStorageUnavailable as error:
        raise HTTPException(
            status_code=503,
            detail={
                "code": "evidence_storage_unavailable",
                "message": "Local demo evidence storage is unavailable.",
            },
        ) from error
    except CryptographyUnavailable as error:
        raise HTTPException(
            status_code=503,
            detail={
                "code": "cryptography_unavailable",
                "message": "Secure telemetry verification is unavailable.",
            },
        ) from error
    return TamperAlertResponse(
        schema_version="phase5.secure-telemetry.v1",
        protection_id=status.analysis_id,
        analysis_id=status.analysis_id,
        verification="rejected",
        reason="tamper_detected",
        protected_count=status.protected_count,
        tamper_rejected=status.tamper_rejected,
    )
