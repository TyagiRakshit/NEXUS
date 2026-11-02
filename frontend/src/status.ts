export type StatusResponse = {
  overall_status: "healthy" | "degraded";
  services: {
    backend: "healthy";
    database: "healthy" | "unavailable";
  };
};

export type FlowSummary = {
  protocol: string;
  source_ip: string;
  source_port: number | null;
  destination_ip: string;
  destination_port: number | null;
  packet_count: number;
  byte_count: number;
  duration_seconds: number;
  packets_per_second: number;
  bytes_per_second: number;
};

export type AnalysisResponse = {
  schema_version: "phase2.flow.v1";
  source: "REPLAYED DEMO TRAFFIC";
  fixture_id: "phase2-synthetic-v1";
  analysis_id: string;
  analyzed_at: string;
  packet_count: number;
  flow_count: number;
  flows: FlowSummary[];
};

export type ProtocolCount = {
  protocol: string;
  flow_count: number;
};

export type CurrentHostProfile = {
  observed_flow_count: number;
  protocol_mix: ProtocolCount[];
  average_bytes_per_flow: number;
  average_duration_seconds: number;
  average_packets_per_second: number;
};

export type ProtocolAverage = {
  protocol: string;
  average_flow_count: number;
};

export type HostBaseline = {
  observed_batch_count: number;
  average_flow_count: number;
  protocol_mix: ProtocolAverage[];
  average_bytes_per_flow: number;
  average_duration_seconds: number;
  average_packets_per_second: number;
};

export type HostProfile = {
  host_ip: string;
  current_profile: CurrentHostProfile;
  baseline: HostBaseline | null;
};

export type ProfileAdaptResponse = {
  schema_version: "phase3.profile.v1";
  source: "REPLAYED DEMO TRAFFIC";
  fixture_id: "phase3-normal-v1";
  interpretation: "NORMAL BASELINE ONLY - NO ANOMALY DECISION";
  analysis_id: string;
  analyzed_at: string;
  packet_count: number;
  flow_count: number;
  baseline_state: "warming" | "ready";
  warmup_required_batches: number;
  admitted_batch_count: number;
  window_batch_count: number;
  baseline_version: number;
  previous_baseline_version: number | null;
  hosts: HostProfile[];
};

export type DetectionResult = FlowSummary & {
  anomaly_score: number;
  is_statistically_unusual: boolean;
  risk_score: 20 | 60 | 90;
  risk_level: "Low" | "Medium" | "High";
  alert_flagged: boolean;
  explanations: string[];
};

export type DetectionResponse = {
  schema_version: "phase4.detection.v1";
  source: "REPLAYED DEMO TRAFFIC";
  interpretation: "SYNTHETIC ANOMALY DEMO - STATISTICAL UNUSUALNESS, NOT MALICIOUS PROOF";
  training_fixture_id: "phase4-normal-train-v1";
  replay_fixture_id: "phase4-unusual-v1";
  analysis_id: string;
  analyzed_at: string;
  model: {
    model_type: "IsolationForest";
    model_version: "phase4-iforest-v1";
    random_seed: 42;
    training_flow_count: number;
    feature_count: 11;
    n_estimators: 100;
    max_samples: 32;
    model_threshold: number;
  };
  replay_packet_count: number;
  replay_flow_count: number;
  flagged_alert_count: number;
  results: DetectionResult[];
};

export type UploadHostProfile = {
  host_ip: string;
  observed_flow_count: number;
  protocol_mix: ProtocolCount[];
  average_bytes_per_flow: number;
  average_duration_seconds: number;
  average_packets_per_second: number;
};

export type UploadAnalysisResponse = {
  schema_version: "demo.upload-analysis.v1";
  source: "REPLAYED DEMO TRAFFIC";
  interpretation: "STATISTICAL UNUSUALNESS RELATIVE TO SYNTHETIC TRAINING, NOT MALICIOUS PROOF";
  analysis_id: string;
  analyzed_at: string;
  packet_count: number;
  flow_count: number;
  flows: FlowSummary[];
  host_profiles: UploadHostProfile[];
  model: DetectionResponse["model"];
  flagged_alert_count: number;
  results: DetectionResult[];
};

export type ProtectAlertResponse = {
  schema_version: "phase5.secure-telemetry.v1";
  protection_id: string;
  analysis_id: string;
  status: "protected";
  aes_gcm: "protected";
  protected_count: number;
};

export type VerifyAlertResponse = {
  schema_version: "phase5.secure-telemetry.v1";
  protection_id: string;
  analysis_id: string;
  verification: "verified";
  aes_gcm: "authenticated";
  sha256: "verified";
  rsa_pss: "valid";
  protected_count: number;
  verified_count: number;
  all_valid: true;
};

export type TamperAlertResponse = {
  schema_version: "phase5.secure-telemetry.v1";
  protection_id: string;
  analysis_id: string;
  verification: "rejected";
  reason: "tamper_detected";
  protected_count: number;
  tamper_rejected: true;
};

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null;
}

function hasExactKeys(value: Record<string, unknown>, expected: string[]): boolean {
  const actual = Object.keys(value).sort();
  return (
    actual.length === expected.length &&
    actual.every((key, index) => key === [...expected].sort()[index])
  );
}

function isStatusResponse(value: unknown): value is StatusResponse {
  if (!isRecord(value) || !isRecord(value.services)) {
    return false;
  }

  const database = value.services.database;
  const expectedOverall = database === "healthy" ? "healthy" : "degraded";

  return (
    value.services.backend === "healthy" &&
    (database === "healthy" || database === "unavailable") &&
    value.overall_status === expectedOverall
  );
}

function isNonNegativeNumber(value: unknown): value is number {
  return typeof value === "number" && Number.isFinite(value) && value >= 0;
}

function isPort(value: unknown): value is number | null {
  return (
    value === null ||
    (Number.isInteger(value) && typeof value === "number" && value >= 0 && value <= 65535)
  );
}

function isFlowSummary(value: unknown): value is FlowSummary {
  return (
    isRecord(value) &&
    typeof value.protocol === "string" &&
    typeof value.source_ip === "string" &&
    isPort(value.source_port) &&
    typeof value.destination_ip === "string" &&
    isPort(value.destination_port) &&
    Number.isInteger(value.packet_count) &&
    isNonNegativeNumber(value.packet_count) &&
    Number.isInteger(value.byte_count) &&
    isNonNegativeNumber(value.byte_count) &&
    isNonNegativeNumber(value.duration_seconds) &&
    isNonNegativeNumber(value.packets_per_second) &&
    isNonNegativeNumber(value.bytes_per_second)
  );
}

function isAnalysisResponse(value: unknown): value is AnalysisResponse {
  if (!isRecord(value) || !Array.isArray(value.flows)) {
    return false;
  }

  return (
    value.schema_version === "phase2.flow.v1" &&
    value.source === "REPLAYED DEMO TRAFFIC" &&
    value.fixture_id === "phase2-synthetic-v1" &&
    typeof value.analysis_id === "string" &&
    typeof value.analyzed_at === "string" &&
    Number.isInteger(value.packet_count) &&
    isNonNegativeNumber(value.packet_count) &&
    Number.isInteger(value.flow_count) &&
    value.flow_count === value.flows.length &&
    value.flows.every(isFlowSummary)
  );
}

function isProtocolCount(value: unknown): value is ProtocolCount {
  return (
    isRecord(value) &&
    typeof value.protocol === "string" &&
    Number.isInteger(value.flow_count) &&
    isNonNegativeNumber(value.flow_count)
  );
}

function isCurrentHostProfile(value: unknown): value is CurrentHostProfile {
  return (
    isRecord(value) &&
    Number.isInteger(value.observed_flow_count) &&
    isNonNegativeNumber(value.observed_flow_count) &&
    Array.isArray(value.protocol_mix) &&
    value.protocol_mix.every(isProtocolCount) &&
    isNonNegativeNumber(value.average_bytes_per_flow) &&
    isNonNegativeNumber(value.average_duration_seconds) &&
    isNonNegativeNumber(value.average_packets_per_second)
  );
}

function isProtocolAverage(value: unknown): value is ProtocolAverage {
  return (
    isRecord(value) &&
    typeof value.protocol === "string" &&
    isNonNegativeNumber(value.average_flow_count)
  );
}

function isHostBaseline(value: unknown): value is HostBaseline {
  return (
    isRecord(value) &&
    Number.isInteger(value.observed_batch_count) &&
    isNonNegativeNumber(value.observed_batch_count) &&
    isNonNegativeNumber(value.average_flow_count) &&
    Array.isArray(value.protocol_mix) &&
    value.protocol_mix.every(isProtocolAverage) &&
    isNonNegativeNumber(value.average_bytes_per_flow) &&
    isNonNegativeNumber(value.average_duration_seconds) &&
    isNonNegativeNumber(value.average_packets_per_second)
  );
}

function isHostProfile(value: unknown): value is HostProfile {
  return (
    isRecord(value) &&
    typeof value.host_ip === "string" &&
    isCurrentHostProfile(value.current_profile) &&
    (value.baseline === null || isHostBaseline(value.baseline))
  );
}

function isProfileAdaptResponse(value: unknown): value is ProfileAdaptResponse {
  if (!isRecord(value) || !Array.isArray(value.hosts)) {
    return false;
  }

  const countsAreIntegers = [
    value.packet_count,
    value.flow_count,
    value.warmup_required_batches,
    value.admitted_batch_count,
    value.window_batch_count,
    value.baseline_version,
  ].every((count) => Number.isInteger(count) && isNonNegativeNumber(count));
  const previousVersionIsValid =
    value.previous_baseline_version === null ||
    (Number.isInteger(value.previous_baseline_version) &&
      isNonNegativeNumber(value.previous_baseline_version));
  const stateIsConsistent =
    (value.baseline_state === "warming" &&
      value.baseline_version === 0 &&
      value.hosts.every(
        (host) => isHostProfile(host) && host.baseline === null,
      )) ||
    (value.baseline_state === "ready" &&
      typeof value.baseline_version === "number" &&
      value.baseline_version >= 1 &&
      value.hosts.every(
        (host) => isHostProfile(host) && host.baseline !== null,
      ));

  return (
    value.schema_version === "phase3.profile.v1" &&
    value.source === "REPLAYED DEMO TRAFFIC" &&
    value.fixture_id === "phase3-normal-v1" &&
    value.interpretation === "NORMAL BASELINE ONLY - NO ANOMALY DECISION" &&
    typeof value.analysis_id === "string" &&
    typeof value.analyzed_at === "string" &&
    countsAreIntegers &&
    previousVersionIsValid &&
    stateIsConsistent
  );
}

function isDetectionResult(value: unknown): value is DetectionResult {
  if (!isRecord(value) || !isFlowSummary(value)) {
    return false;
  }
  const detection = value as Record<string, unknown>;
  return (
    typeof detection.anomaly_score === "number" &&
    Number.isFinite(detection.anomaly_score) &&
    typeof detection.is_statistically_unusual === "boolean" &&
    (detection.risk_score === 20 ||
      detection.risk_score === 60 ||
      detection.risk_score === 90) &&
    (detection.risk_level === "Low" ||
      detection.risk_level === "Medium" ||
      detection.risk_level === "High") &&
    typeof detection.alert_flagged === "boolean" &&
    Array.isArray(detection.explanations) &&
    detection.explanations.length <= 3 &&
    detection.explanations.every((item) => typeof item === "string")
  );
}

function isDetectionResponse(value: unknown): value is DetectionResponse {
  if (!isRecord(value) || !isRecord(value.model) || !Array.isArray(value.results)) {
    return false;
  }

  return (
    value.schema_version === "phase4.detection.v1" &&
    value.source === "REPLAYED DEMO TRAFFIC" &&
    value.interpretation ===
      "SYNTHETIC ANOMALY DEMO - STATISTICAL UNUSUALNESS, NOT MALICIOUS PROOF" &&
    value.training_fixture_id === "phase4-normal-train-v1" &&
    value.replay_fixture_id === "phase4-unusual-v1" &&
    typeof value.analysis_id === "string" &&
    typeof value.analyzed_at === "string" &&
    value.model.model_type === "IsolationForest" &&
    value.model.model_version === "phase4-iforest-v1" &&
    value.model.random_seed === 42 &&
    Number.isInteger(value.model.training_flow_count) &&
    isNonNegativeNumber(value.model.training_flow_count) &&
    value.model.feature_count === 11 &&
    value.model.n_estimators === 100 &&
    value.model.max_samples === 32 &&
    isNonNegativeNumber(value.model.model_threshold) &&
    Number.isInteger(value.replay_packet_count) &&
    isNonNegativeNumber(value.replay_packet_count) &&
    Number.isInteger(value.replay_flow_count) &&
    value.replay_flow_count === value.results.length &&
    Number.isInteger(value.flagged_alert_count) &&
    value.flagged_alert_count ===
      value.results.filter(
        (item) => isDetectionResult(item) && item.alert_flagged,
      ).length &&
    value.results.every(isDetectionResult)
  );
}

function isUploadHostProfile(value: unknown): value is UploadHostProfile {
  return (
    isRecord(value) &&
    typeof value.host_ip === "string" &&
    Number.isInteger(value.observed_flow_count) &&
    isNonNegativeNumber(value.observed_flow_count) &&
    Array.isArray(value.protocol_mix) &&
    value.protocol_mix.every(isProtocolCount) &&
    isNonNegativeNumber(value.average_bytes_per_flow) &&
    isNonNegativeNumber(value.average_duration_seconds) &&
    isNonNegativeNumber(value.average_packets_per_second)
  );
}

function isUploadAnalysisResponse(value: unknown): value is UploadAnalysisResponse {
  if (
    !isRecord(value) ||
    !Array.isArray(value.flows) ||
    !Array.isArray(value.host_profiles) ||
    !isRecord(value.model) ||
    !Array.isArray(value.results)
  ) {
    return false;
  }

  return (
    value.schema_version === "demo.upload-analysis.v1" &&
    value.source === "REPLAYED DEMO TRAFFIC" &&
    value.interpretation ===
      "STATISTICAL UNUSUALNESS RELATIVE TO SYNTHETIC TRAINING, NOT MALICIOUS PROOF" &&
    typeof value.analysis_id === "string" &&
    typeof value.analyzed_at === "string" &&
    Number.isInteger(value.packet_count) &&
    isNonNegativeNumber(value.packet_count) &&
    Number.isInteger(value.flow_count) &&
    value.flow_count === value.flows.length &&
    value.flows.every(isFlowSummary) &&
    value.host_profiles.every(isUploadHostProfile) &&
    value.model.model_type === "IsolationForest" &&
    value.model.model_version === "phase4-iforest-v1" &&
    value.model.random_seed === 42 &&
    Number.isInteger(value.model.training_flow_count) &&
    isNonNegativeNumber(value.model.training_flow_count) &&
    value.model.feature_count === 11 &&
    value.model.n_estimators === 100 &&
    value.model.max_samples === 32 &&
    isNonNegativeNumber(value.model.model_threshold) &&
    value.results.length === value.flow_count &&
    value.results.every(isDetectionResult) &&
    Number.isInteger(value.flagged_alert_count) &&
    value.flagged_alert_count ===
      value.results.filter(
        (item) => isDetectionResult(item) && item.alert_flagged,
      ).length
  );
}

export async function fetchStatus(): Promise<StatusResponse> {
  const response = await fetch("/api/v1/status");
  if (!response.ok) {
    throw new Error("Status request failed");
  }

  const body: unknown = await response.json();
  if (!isStatusResponse(body)) {
    throw new Error("Status response was invalid");
  }

  return body;
}

export async function analyzeFixture(): Promise<AnalysisResponse> {
  const response = await fetch("/api/v1/demo/flows/analyze", { method: "POST" });
  if (!response.ok) {
    throw new Error("Analysis request failed");
  }

  const body: unknown = await response.json();
  if (!isAnalysisResponse(body)) {
    throw new Error("Analysis response was invalid");
  }

  return body;
}

export async function adaptNormalProfiles(): Promise<ProfileAdaptResponse> {
  const response = await fetch("/api/v1/demo/profiles/adapt", { method: "POST" });
  if (!response.ok) {
    throw new Error("Profile request failed");
  }

  const body: unknown = await response.json();
  if (!isProfileAdaptResponse(body)) {
    throw new Error("Profile response was invalid");
  }

  return body;
}


export async function analyzeDetection(): Promise<DetectionResponse> {
  const response = await fetch("/api/v1/demo/detection/analyze", {
    method: "POST",
  });
  if (!response.ok) {
    throw new Error("Detection request failed");
  }

  const body: unknown = await response.json();
  if (!isDetectionResponse(body)) {
    throw new Error("Detection response was invalid");
  }

  return body;
}

export async function analyzeUploadedPcap(
  file: File,
): Promise<UploadAnalysisResponse> {
  const form = new FormData();
  form.append("file", file);
  const response = await fetch("/api/v1/demo/upload/analyze", {
    method: "POST",
    body: form,
  });
  if (!response.ok) {
    throw new Error("Upload analysis request failed");
  }

  const body: unknown = await response.json();
  if (!isUploadAnalysisResponse(body)) {
    throw new Error("Upload analysis response was invalid");
  }

  return body;
}

export async function protectFlaggedAlert(
  analysisId: string,
): Promise<ProtectAlertResponse> {
  const response = await fetch("/api/v1/demo/telemetry/protect", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ analysis_id: analysisId }),
  });
  if (!response.ok) {
    throw new Error("Protection request failed");
  }
  const body: unknown = await response.json();
  if (
    !isRecord(body) ||
    !hasExactKeys(body, [
      "schema_version",
      "protection_id",
      "analysis_id",
      "status",
      "aes_gcm",
      "protected_count",
    ]) ||
    body.schema_version !== "phase5.secure-telemetry.v1" ||
    typeof body.protection_id !== "string" ||
    typeof body.analysis_id !== "string" ||
    body.status !== "protected" ||
    body.aes_gcm !== "protected" ||
    !Number.isInteger(body.protected_count) ||
    !isNonNegativeNumber(body.protected_count)
  ) {
    throw new Error("Protection response was invalid");
  }
  return {
    schema_version: body.schema_version,
    protection_id: body.protection_id,
    analysis_id: body.analysis_id,
    status: body.status,
    aes_gcm: body.aes_gcm,
    protected_count: body.protected_count,
  };
}

export async function verifyProtectedAlert(
  protectionId: string,
): Promise<VerifyAlertResponse> {
  const response = await fetch(
    `/api/v1/demo/telemetry/${protectionId}/verify`,
    { method: "POST" },
  );
  if (!response.ok) {
    throw new Error("Verification request failed");
  }
  const body: unknown = await response.json();
  if (
    !isRecord(body) ||
    !hasExactKeys(body, [
      "schema_version",
      "protection_id",
      "analysis_id",
      "verification",
      "aes_gcm",
      "sha256",
      "rsa_pss",
      "protected_count",
      "verified_count",
      "all_valid",
    ]) ||
    body.schema_version !== "phase5.secure-telemetry.v1" ||
    body.protection_id !== protectionId ||
    body.analysis_id !== protectionId ||
    body.verification !== "verified" ||
    body.aes_gcm !== "authenticated" ||
    body.sha256 !== "verified" ||
    body.rsa_pss !== "valid" ||
    !Number.isInteger(body.protected_count) ||
    !isNonNegativeNumber(body.protected_count) ||
    !Number.isInteger(body.verified_count) ||
    body.verified_count !== body.protected_count ||
    body.all_valid !== true
  ) {
    throw new Error("Verification response was invalid");
  }
  return {
    schema_version: body.schema_version,
    protection_id: body.protection_id,
    analysis_id: body.analysis_id,
    verification: body.verification,
    aes_gcm: body.aes_gcm,
    sha256: body.sha256,
    rsa_pss: body.rsa_pss,
    protected_count: body.protected_count,
    verified_count: body.verified_count,
    all_valid: body.all_valid,
  };
}

export async function verifyTamperedCopy(
  protectionId: string,
): Promise<TamperAlertResponse> {
  const response = await fetch(
    `/api/v1/demo/telemetry/${protectionId}/verify-tampered`,
    { method: "POST" },
  );
  if (!response.ok) {
    throw new Error("Tamper verification request failed");
  }
  const body: unknown = await response.json();
  if (
    !isRecord(body) ||
    !hasExactKeys(body, [
      "schema_version",
      "protection_id",
      "analysis_id",
      "verification",
      "reason",
      "protected_count",
      "tamper_rejected",
    ]) ||
    body.schema_version !== "phase5.secure-telemetry.v1" ||
    body.protection_id !== protectionId ||
    body.analysis_id !== protectionId ||
    body.verification !== "rejected" ||
    body.reason !== "tamper_detected" ||
    !Number.isInteger(body.protected_count) ||
    !isNonNegativeNumber(body.protected_count) ||
    body.tamper_rejected !== true
  ) {
    throw new Error("Tamper verification response was invalid");
  }
  return {
    schema_version: body.schema_version,
    protection_id: body.protection_id,
    analysis_id: body.analysis_id,
    verification: body.verification,
    reason: body.reason,
    protected_count: body.protected_count,
    tamper_rejected: body.tamper_rejected,
  };
}
