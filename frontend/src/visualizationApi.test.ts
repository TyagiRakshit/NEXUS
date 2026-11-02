import { afterEach, expect, test, vi } from "vitest";

import {
  VisualizationApiError,
  evaluateBaseline,
  evaluateHybrid,
  getBaselineHistory,
  getHybridTelemetryStatus,
  protectHybrid,
  verifyHybrid,
} from "./visualizationApi";

const analysisId = "11111111-1111-1111-1111-111111111111";
const observationId = "22222222-2222-2222-2222-222222222222";
const epoch = "33333333-3333-3333-3333-333333333333";
const features = {
  observed_flow_count: 4,
  average_bytes_per_flow: 108,
  average_duration_seconds: 2,
  average_packets_per_second: 1,
  protocol_shares: { TCP: 1, UDP: 0, ICMP: 0, OTHER: 0 },
};
const host = {
  host_ip: "192.0.2.10",
  decision: "Accept",
  reason_codes: ["WARMUP_STARTED"],
  readiness_before: "absent",
  readiness_after: "warming",
  coverage_confidence: "insufficient",
  accepted_count_before: 0,
  accepted_count_after: 1,
  version_before: null,
  version_after: 0,
  probation_count: 0,
  incident_flow_count: 4,
  high_flow_count: 0,
  flow_evidence_refs: [0],
  current_features: features,
  baseline_before: null,
  baseline_after: null,
  feature_deviations: [],
  last_evaluated_window_start: "2026-11-01T10:00:00Z",
  last_admitted_window_start: "2026-11-01T10:00:00Z",
  findings: [],
};

function reply(body: unknown, status = 200): Promise<Response> {
  return Promise.resolve({
    ok: status >= 200 && status < 300,
    status,
    json: async () => body,
  } as Response);
}

afterEach(() => vi.unstubAllGlobals());

test("baseline evaluate validates version, host features and observation identity", async () => {
  const fetchMock = vi.fn(() => reply({
    schema_version: "phase6.baseline.v1",
    source: "REPLAYED DEMO TRAFFIC",
    analysis_id: analysisId,
    observation_id: observationId,
    capture_window_start: "2026-11-01T10:00:00Z",
    capture_window_end: "2026-11-01T10:01:00Z",
    activity_span_seconds: 50,
    capture_fingerprint_status: "new",
    model_version: "phase4-iforest-v1",
    model_threshold: 0.636672,
    baseline_store_epoch: epoch,
    hosts: [host],
  }));
  vi.stubGlobal("fetch", fetchMock);
  const result = await evaluateBaseline(analysisId);
  expect(result.hosts[0].current_features.protocol_shares.TCP).toBe(1);
  expect(result.hosts[0].version_after).toBe(0);
  expect(fetchMock).toHaveBeenCalledWith("/api/v1/demo/baselines/evaluate", expect.objectContaining({method: "POST"}));
});

test("evaluation rejects a valid-shaped response for a different analysis", async () => {
  vi.stubGlobal("fetch", vi.fn(() => reply({
    schema_version: "phase6.baseline.v1", source: "REPLAYED DEMO TRAFFIC", analysis_id: "99999999-9999-9999-9999-999999999999", observation_id: observationId,
    capture_window_start: "2026-11-01T10:00:00Z", capture_window_end: "2026-11-01T10:01:00Z", activity_span_seconds: 50,
    capture_fingerprint_status: "new", model_version: "phase4-iforest-v1", model_threshold: .6, baseline_store_epoch: epoch, hosts: [host],
  })));
  await expect(evaluateBaseline(analysisId)).rejects.toMatchObject({code: "ANALYSIS_MISMATCH"});
});

test("history keeps decisions and accepted snapshots separate", async () => {
  vi.stubGlobal("fetch", vi.fn(() => reply({
    schema_version: "phase6.baseline.history.v1",
    source: "REPLAYED DEMO TRAFFIC",
    baseline_store_epoch: epoch,
    host_ip: "192.0.2.10",
    readiness: "warming",
    coverage_confidence: "insufficient",
    current_version: 0,
    anchor_version: null,
    current_baseline: null,
    snapshots: [],
    decisions: [{
      observation_id: observationId,
      window_start: "2026-11-01T10:00:00Z",
      decision: "Accept",
      reason_codes: ["WARMUP_STARTED"],
      version_before: null,
      version_after: 0,
      finding_ids: [],
    }],
  })));
  const result = await getBaselineHistory("192.0.2.10");
  expect(result.decisions).toHaveLength(1);
  expect(result.snapshots).toHaveLength(0);
});

test("hybrid rejects duplicate or out-of-range flow indices", async () => {
  const body = {
    schema_version: "phase7.hybrid.v1",
    source: "REPLAYED DEMO TRAFFIC",
    analysis_id: analysisId,
    observation_id: observationId,
    capture_window_start: "2026-11-01T10:00:00Z",
    capture_window_end: "2026-11-01T10:01:00Z",
    model_version: "phase4-iforest-v1",
    model_threshold: 0.636672,
    rule_set_version: "increment4-demo-rules-v1",
    baseline_store_epoch: epoch,
    flow_results: [{ flow_index: 2, anomaly_score: 0.5, risk_level: "Low", risk_score: 20, alert_flagged: false }],
    rule_assessments: [],
    hosts: [host],
    findings: [],
    telemetry: { schema_version: "phase7.secure-telemetry.v2", eligible_count: 0 },
  };
  vi.stubGlobal("fetch", vi.fn(() => reply(body)));
  await expect(evaluateHybrid(analysisId)).rejects.toThrow(/invalid/i);
});

test("hybrid accepts separate ML, rule and finding evidence from the backend schema", async () => {
  const body = {
    schema_version: "phase7.hybrid.v1", source: "REPLAYED DEMO TRAFFIC", analysis_id: analysisId, observation_id: observationId,
    capture_window_start: "2026-11-01T10:00:00Z", capture_window_end: "2026-11-01T10:01:00Z", model_version: "phase4-iforest-v1", model_threshold: .636672, rule_set_version: "increment4-demo-rules-v1", baseline_store_epoch: epoch,
    flow_results: [{flow_index: 0, anomaly_score: .81, risk_level: "High", risk_score: 90, alert_flagged: true}],
    rule_assessments: [{rule_id: "R1", status: "Match", reason_code: "POSSIBLE_PORT_SWEEP", subject_host_ips: ["192.0.2.10", "192.0.2.20"], affected_host_ips: ["192.0.2.10", "192.0.2.20"], flow_indices: [0], rule_evidence_strength: 60, evidence: {tcp_flow_count: 6}, explanation: "Possible pattern"}],
    hosts: [host], findings: [{schema_version: "phase7.finding.v1", finding_id: "44444444-4444-4444-4444-444444444444", analysis_id: analysisId, observation_id: observationId, detection_source: "security_rule", kind: "RULE_MATCH", severity: "High", subject_scope: "host_pair", host_ip: null, subject_host_ips: ["192.0.2.10", "192.0.2.20"], possible_category: "possible_port_sweep", flow_indices: [0], capture_window_start: "2026-11-01T10:00:00Z", capture_window_end: "2026-11-01T10:01:00Z", evidence: [{metric: "tcp_flow_count", observed: 6, comparator: ">=", threshold: 6, unit: "flows"}], explanation: "Possible pattern", ml_anomaly_score: null, rule_evidence_strength: 60, telemetry_eligible: true}],
    telemetry: {schema_version: "phase7.secure-telemetry.v2", eligible_count: 1},
  };
  vi.stubGlobal("fetch", vi.fn(() => reply(body)));
  const result = await evaluateHybrid(analysisId);
  expect(result.findings[0].detection_source).toBe("security_rule");
  expect(result.findings[0].rule_evidence_strength).toBe(60);
  expect(result.flow_results[0].anomaly_score).toBe(.81);
});

test("v2 status, Protect and Verify remain distinct responses", async () => {
  vi.stubGlobal("fetch", vi.fn()
    .mockImplementationOnce(() => reply({schema_version: "phase7.secure-telemetry.v2", analysis_id: analysisId, status: "not_requested", protected_count: 0}))
    .mockImplementationOnce(() => reply({schema_version: "phase7.secure-telemetry.v2", analysis_id: analysisId, protection_id: analysisId, status: "protected", protected_count: 2}))
    .mockImplementationOnce(() => reply({schema_version: "phase7.secure-telemetry.v2", analysis_id: analysisId, protection_id: analysisId, verification: "verified", aes_gcm: "authenticated", sha256: "verified", rsa_pss: "valid", protected_count: 2, verified_count: 2, all_valid: true})));
  expect((await getHybridTelemetryStatus(analysisId)).status).toBe("not_requested");
  expect((await protectHybrid(analysisId)).status).toBe("protected");
  expect((await verifyHybrid(analysisId)).verification).toBe("verified");
});

test("409 conflict preserves its safe backend code without retrying", async () => {
  const fetchMock = vi.fn(() => reply({detail: {code: "HYBRID_EVALUATION_CONFLICT", message: "A finalized host admission cannot be changed."}}, 409));
  vi.stubGlobal("fetch", fetchMock);
  await expect(evaluateHybrid(analysisId)).rejects.toMatchObject({
    status: 409, code: "HYBRID_EVALUATION_CONFLICT",
  } satisfies Partial<VisualizationApiError>);
  expect(fetchMock).toHaveBeenCalledTimes(1);
});

test.each([
  [404, "ANALYSIS_EXPIRED"],
  [503, "HYBRID_PROTECTION_UNAVAILABLE"],
])("HTTP %i exposes only the safe error code", async (httpStatus, code) => {
  vi.stubGlobal("fetch", vi.fn(() => reply({detail: {code, message: "internal filesystem path must stay hidden"}}, httpStatus)));
  await expect(evaluateHybrid(analysisId)).rejects.toMatchObject({status: httpStatus, code});
});
