export type Features = {
  observed_flow_count: number;
  average_bytes_per_flow: number;
  average_duration_seconds: number;
  average_packets_per_second: number;
  protocol_shares: Record<"TCP" | "UDP" | "ICMP" | "OTHER", number>;
};
export type Decision = "Accept" | "Hold" | "Reject";
export type Readiness = "absent" | "warming" | "provisional" | "ready";
export type HostAdmission = {
  host_ip: string; decision: Decision; reason_codes: string[];
  readiness_before: Readiness; readiness_after: Readiness;
  coverage_confidence: "insufficient" | "limited" | "accumulated";
  accepted_count_before: number; accepted_count_after: number;
  version_before: number | null; version_after: number | null;
  probation_count: number; incident_flow_count: number; high_flow_count: number;
  flow_evidence_refs: number[]; current_features: Features;
  baseline_before: Features | null; baseline_after: Features | null;
  feature_deviations: {feature: string; observed: number; baseline: number; deviation: number; accept_limit: number; hold_limit: number; band: Decision; reason_code: string}[];
  findings: {finding_id: string; kind: string; severity: string; evidence_features: string[]; explanation: string}[];
  last_evaluated_window_start: string | null; last_admitted_window_start: string | null;
  overall_severity?: string; rule_veto_effect?: string;
};
export type BaselineEvaluateResponse = {
  schema_version: "phase6.baseline.v1"; source: "REPLAYED DEMO TRAFFIC";
  analysis_id: string; observation_id: string; capture_window_start: string | null; capture_window_end: string | null;
  activity_span_seconds: number; capture_fingerprint_status: "new" | "duplicate";
  model_version: string; model_threshold: number; baseline_store_epoch: string;
  hosts: HostAdmission[];
};
export type BaselineHistoryResponse = {
  schema_version: "phase6.baseline.history.v1"; source: "REPLAYED DEMO TRAFFIC";
  baseline_store_epoch: string; host_ip: string; readiness: Readiness;
  coverage_confidence: "insufficient" | "limited" | "accumulated";
  current_version: number | null; anchor_version: number | null;
  current_baseline: Features | null;
  snapshots: {version: number; observation_id: string; window_start: string | null; reason_code: string; features_before: Features | null; features_after: Features}[];
  decisions: {observation_id: string; window_start: string | null; decision: Decision; reason_codes: string[]; version_before: number | null; version_after: number | null; finding_ids: string[]}[];
};
export type HybridFinding = {
  schema_version: "phase7.finding.v1"; finding_id: string; detection_source: "isolation_forest" | "adaptive_baseline" | "security_rule"; kind: string; severity: string; host_ip: string | null;
  subject_host_ips: string[]; possible_category: string | null; flow_indices: number[]; telemetry_eligible: boolean;
  evidence: Record<string, unknown>[]; explanation: string; ml_anomaly_score: number | null; rule_evidence_strength: number | null;
};
export type HybridEvaluateResponse = Omit<BaselineEvaluateResponse, "schema_version" | "activity_span_seconds" | "capture_fingerprint_status"> & {
  schema_version: "phase7.hybrid.v1"; rule_set_version: string;
  flow_results: {flow_index: number; anomaly_score: number; risk_level: "Low" | "Medium" | "High"; risk_score: number; alert_flagged: boolean}[];
  rule_assessments: Record<string, unknown>[]; findings: HybridFinding[];
  telemetry: {schema_version: "phase7.secure-telemetry.v2"; eligible_count: number};
};
export type HybridTelemetryStatus = {schema_version: "phase7.secure-telemetry.v2"; analysis_id: string; status: "preparing" | "not_requested" | "protected"; protected_count: number};
export type HybridProtect = {schema_version: "phase7.secure-telemetry.v2"; analysis_id: string; protection_id: string; status: "protected"; protected_count: number};
export type HybridVerify = {schema_version: "phase7.secure-telemetry.v2"; analysis_id: string; protection_id: string; verification: "verified"; aes_gcm: "authenticated"; sha256: "verified"; rsa_pss: "valid"; protected_count: number; verified_count: number; all_valid: true};
export type HybridTamper = {schema_version: "phase7.secure-telemetry.v2"; analysis_id: string; protection_id: string; verification: "rejected"; reason: "tamper_detected"; protected_count: number; tamper_rejected: true};

export class VisualizationApiError extends Error {
  constructor(public readonly status: number, public readonly code: string) {
    super(status === 404 ? "Analysis expired or unavailable" : status === 409 ? "Evaluation conflict" : status === 503 ? "Backend unavailable" : "API response invalid or unavailable");
    this.name = "VisualizationApiError";
  }
}
const rec = (x: unknown): x is Record<string, unknown> => typeof x === "object" && x !== null && !Array.isArray(x);
const num = (x: unknown): x is number => typeof x === "number" && Number.isFinite(x);
const nat = (x: unknown): x is number => num(x) && Number.isInteger(x) && x >= 0;
const str = (x: unknown): x is string => typeof x === "string" && x.length > 0;
const uuid = (x: unknown): x is string => str(x) && /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(x);
const time = (x: unknown) => x === null || (str(x) && !Number.isNaN(Date.parse(x)) && /(?:Z|[+-]\d\d:\d\d)$/.test(x));
const strings = (x: unknown) => Array.isArray(x) && x.every(str);
const version = (x: unknown) => x === null || nat(x);
const decision = (x: unknown) => x === "Accept" || x === "Hold" || x === "Reject";
const readiness = (x: unknown) => x === "absent" || x === "warming" || x === "provisional" || x === "ready";
const confidence = (x: unknown) => x === "insufficient" || x === "limited" || x === "accumulated";
function features(x: unknown): x is Features {
  if (!rec(x) || !rec(x.protocol_shares) || !nat(x.observed_flow_count) || !num(x.average_bytes_per_flow) || !num(x.average_duration_seconds) || !num(x.average_packets_per_second)) return false;
  const shares = x.protocol_shares;
  return (["TCP", "UDP", "ICMP", "OTHER"] as const).every(k => num(shares[k]) && shares[k] >= 0 && shares[k] <= 1);
}
function host(x: unknown): x is HostAdmission {
  return rec(x) && str(x.host_ip) && decision(x.decision) && strings(x.reason_codes) && readiness(x.readiness_before) && readiness(x.readiness_after) && confidence(x.coverage_confidence) && nat(x.accepted_count_before) && nat(x.accepted_count_after) && version(x.version_before) && version(x.version_after) && nat(x.probation_count) && nat(x.incident_flow_count) && nat(x.high_flow_count) && Array.isArray(x.flow_evidence_refs) && x.flow_evidence_refs.every(nat) && features(x.current_features) && (x.baseline_before === null || features(x.baseline_before)) && (x.baseline_after === null || features(x.baseline_after)) && Array.isArray(x.feature_deviations) && x.feature_deviations.every(d => rec(d) && str(d.feature) && num(d.observed) && num(d.baseline) && num(d.deviation) && num(d.accept_limit) && num(d.hold_limit) && decision(d.band) && str(d.reason_code)) && Array.isArray(x.findings) && x.findings.every(f => rec(f) && uuid(f.finding_id) && str(f.kind) && str(f.severity) && strings(f.evidence_features) && str(f.explanation)) && time(x.last_evaluated_window_start) && time(x.last_admitted_window_start);
}
function common(x: unknown): x is Record<string, unknown> {
  return rec(x) && x.source === "REPLAYED DEMO TRAFFIC" && uuid(x.analysis_id) && uuid(x.observation_id) && uuid(x.baseline_store_epoch) && time(x.capture_window_start) && time(x.capture_window_end) && str(x.model_version) && num(x.model_threshold) && Array.isArray(x.hosts) && x.hosts.every(host);
}
const baseline = (x: unknown): x is BaselineEvaluateResponse => common(x) && x.schema_version === "phase6.baseline.v1" && num(x.activity_span_seconds) && (x.capture_fingerprint_status === "new" || x.capture_fingerprint_status === "duplicate");
function history(x: unknown): x is BaselineHistoryResponse {
  return rec(x) && x.schema_version === "phase6.baseline.history.v1" && x.source === "REPLAYED DEMO TRAFFIC" && uuid(x.baseline_store_epoch) && str(x.host_ip) && readiness(x.readiness) && confidence(x.coverage_confidence) && version(x.current_version) && version(x.anchor_version) && (x.current_baseline === null || features(x.current_baseline)) && Array.isArray(x.snapshots) && x.snapshots.every(s => rec(s) && nat(s.version) && uuid(s.observation_id) && time(s.window_start) && str(s.reason_code) && (s.features_before === null || features(s.features_before)) && features(s.features_after)) && Array.isArray(x.decisions) && x.decisions.every(d => rec(d) && uuid(d.observation_id) && time(d.window_start) && decision(d.decision) && strings(d.reason_codes) && version(d.version_before) && version(d.version_after) && Array.isArray(d.finding_ids) && d.finding_ids.every(uuid));
}
function hybrid(x: unknown): x is HybridEvaluateResponse {
  if (!common(x) || x.schema_version !== "phase7.hybrid.v1" || x.rule_set_version !== "increment4-demo-rules-v1" || !Array.isArray(x.flow_results) || !Array.isArray(x.rule_assessments) || !Array.isArray(x.findings) || !rec(x.telemetry) || x.telemetry.schema_version !== "phase7.secure-telemetry.v2" || !nat(x.telemetry.eligible_count)) return false;
  const seen = new Set<number>();
  const flows = x.flow_results;
  if (!flows.every(f => {if (!rec(f) || !nat(f.flow_index)) return false; const index = f.flow_index; if (index >= flows.length || seen.has(index) || !num(f.anomaly_score) || !["Low", "Medium", "High"].includes(String(f.risk_level)) || !nat(f.risk_score) || typeof f.alert_flagged !== "boolean") return false; seen.add(index); return true;})) return false;
  if (!x.rule_assessments.every(r => rec(r) && (r.rule_id === "R1" || r.rule_id === "R2") && ["Match", "Unknown", "NoPatternMatchedInObservedMetadata"].includes(String(r.status)) && strings(r.subject_host_ips) && Array.isArray(r.flow_indices) && r.flow_indices.every(i => nat(i) && i < flows.length) && (r.rule_evidence_strength === null || num(r.rule_evidence_strength)) && rec(r.evidence) && str(r.explanation))) return false;
  const ids = new Set<string>();
  if (!x.findings.every(f => {if (!rec(f) || f.schema_version !== "phase7.finding.v1" || !uuid(f.finding_id) || ids.has(f.finding_id) || !["isolation_forest", "adaptive_baseline", "security_rule"].includes(String(f.detection_source)) || !str(f.kind) || !str(f.severity) || !(f.host_ip === null || str(f.host_ip)) || !strings(f.subject_host_ips) || !(f.possible_category === null || str(f.possible_category)) || !Array.isArray(f.flow_indices) || !f.flow_indices.every(i => nat(i) && i < flows.length) || typeof f.telemetry_eligible !== "boolean" || !Array.isArray(f.evidence) || !f.evidence.every(rec) || !str(f.explanation) || !(f.ml_anomaly_score === null || num(f.ml_anomaly_score)) || !(f.rule_evidence_strength === null || num(f.rule_evidence_strength))) return false; ids.add(f.finding_id); return true;})) return false;
  return x.telemetry.eligible_count === x.findings.filter(f => rec(f) && f.telemetry_eligible === true).length;
}
async function request<T>(path: string, method: "GET" | "POST", valid: (x: unknown) => x is T, body?: unknown, signal?: AbortSignal): Promise<T> {
  let response: Response;
  try { response = await fetch(path, {method, ...(body === undefined ? {} : {headers: {"Content-Type": "application/json"}, body: JSON.stringify(body)}), signal}); }
  catch (error) { if (signal?.aborted) throw error; throw new VisualizationApiError(0, "NETWORK_UNAVAILABLE"); }
  let data: unknown;
  try {data = await response.json();} catch {throw new VisualizationApiError(response.status, "INVALID_RESPONSE");}
  if (!response.ok) {
    const detail = rec(data) ? data.detail : null;
    const code = rec(detail) && str(detail.code) && /^[A-Z_]+$/.test(detail.code) ? detail.code : "REQUEST_FAILED";
    throw new VisualizationApiError(response.status, code);
  }
  if (!valid(data)) throw new VisualizationApiError(response.status, "INVALID_RESPONSE");
  return data;
}
const payload = (analysis_id: string) => ({analysis_id});
async function matchingAnalysis<T extends {analysis_id: string}>(id: string, result: Promise<T>): Promise<T> {
  const value = await result;
  if (value.analysis_id !== id) throw new VisualizationApiError(200, "ANALYSIS_MISMATCH");
  return value;
}
export const evaluateBaseline = (id: string, signal?: AbortSignal) => matchingAnalysis(id, request("/api/v1/demo/baselines/evaluate", "POST", baseline, payload(id), signal));
export const evaluateHybrid = (id: string, signal?: AbortSignal) => matchingAnalysis(id, request("/api/v1/demo/hybrid/evaluate", "POST", hybrid, payload(id), signal));
export async function getBaselineHistory(ip: string, signal?: AbortSignal) {
  const result = await request(`/api/v1/demo/baselines/history?host_ip=${encodeURIComponent(ip)}`, "GET", history, undefined, signal);
  if (result.host_ip !== ip) throw new VisualizationApiError(200, "HOST_MISMATCH");
  return result;
}
const v2 = (x: unknown): x is Record<string, unknown> => rec(x) && x.schema_version === "phase7.secure-telemetry.v2" && uuid(x.analysis_id);
const status = (x: unknown): x is HybridTelemetryStatus => v2(x) && ["preparing", "not_requested", "protected"].includes(String(x.status)) && nat(x.protected_count);
const protectedV2 = (x: unknown): x is HybridProtect => v2(x) && uuid(x.protection_id) && x.protection_id === x.analysis_id && x.status === "protected" && nat(x.protected_count);
const verifiedV2 = (x: unknown): x is HybridVerify => v2(x) && uuid(x.protection_id) && x.protection_id === x.analysis_id && x.verification === "verified" && x.aes_gcm === "authenticated" && x.sha256 === "verified" && x.rsa_pss === "valid" && nat(x.protected_count) && x.verified_count === x.protected_count && x.all_valid === true;
const tamperedV2 = (x: unknown): x is HybridTamper => v2(x) && uuid(x.protection_id) && x.protection_id === x.analysis_id && x.verification === "rejected" && x.reason === "tamper_detected" && nat(x.protected_count) && x.tamper_rejected === true;
export const getHybridTelemetryStatus = (id: string, signal?: AbortSignal) => matchingAnalysis(id, request(`/api/v1/demo/hybrid/telemetry/${encodeURIComponent(id)}/status`, "GET", status, undefined, signal));
export const protectHybrid = (id: string, signal?: AbortSignal) => matchingAnalysis(id, request("/api/v1/demo/hybrid/telemetry/protect", "POST", protectedV2, payload(id), signal));
export const verifyHybrid = (id: string, signal?: AbortSignal) => matchingAnalysis(id, request(`/api/v1/demo/hybrid/telemetry/${encodeURIComponent(id)}/verify`, "POST", verifiedV2, undefined, signal));
export const verifyHybridTamperedCopy = (id: string, signal?: AbortSignal) => matchingAnalysis(id, request(`/api/v1/demo/hybrid/telemetry/${encodeURIComponent(id)}/verify-tampered`, "POST", tamperedV2, undefined, signal));
