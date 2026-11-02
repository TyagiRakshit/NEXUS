import {act} from "react";
import {createRoot} from "react-dom/client";
import {afterEach, beforeEach, expect, test, vi} from "vitest";
import AnalysisWorkspace from "./AnalysisWorkspace";
import type {UploadAnalysisResponse} from "./status";
import {VisualizationApiError} from "./visualizationApi";
import type {BaselineEvaluateResponse, BaselineHistoryResponse} from "./visualizationApi";
Object.assign(globalThis, {IS_REACT_ACT_ENVIRONMENT: true});

const {evaluateBaseline, evaluateHybrid, getBaselineHistory, getHybridTelemetryStatus, protectHybrid, verifyHybrid, verifyHybridTamperedCopy} = vi.hoisted(() => ({evaluateBaseline: vi.fn(), evaluateHybrid: vi.fn(), getBaselineHistory: vi.fn(), getHybridTelemetryStatus: vi.fn(), protectHybrid: vi.fn(), verifyHybrid: vi.fn(), verifyHybridTamperedCopy: vi.fn()}));
vi.mock("./visualizationApi", async importOriginal => ({...(await importOriginal<typeof import("./visualizationApi")>()), evaluateBaseline, evaluateHybrid, getBaselineHistory, getHybridTelemetryStatus, protectHybrid, verifyHybrid, verifyHybridTamperedCopy}));
const features = {observed_flow_count: 4, average_bytes_per_flow: 100, average_duration_seconds: 2, average_packets_per_second: 3, protocol_shares: {TCP: 1, UDP: 0, ICMP: 0, OTHER: 0}};
const host = {host_ip: "192.0.2.10", decision: "Accept", reason_codes: ["WARMUP_STARTED"], readiness_before: "absent", readiness_after: "warming", coverage_confidence: "insufficient", accepted_count_before: 0, accepted_count_after: 1, version_before: null, version_after: 0, probation_count: 0, incident_flow_count: 4, high_flow_count: 0, flow_evidence_refs: [0], current_features: features, baseline_before: null, baseline_after: null, feature_deviations: [], findings: [], last_evaluated_window_start: "2026-11-01T10:00:00Z", last_admitted_window_start: "2026-11-01T10:00:00Z"};
const result = {schema_version: "phase6.baseline.v1", source: "REPLAYED DEMO TRAFFIC", analysis_id: "a", observation_id: "o", capture_window_start: "2026-11-01T10:00:00Z", capture_window_end: "2026-11-01T10:01:00Z", activity_span_seconds: 50, capture_fingerprint_status: "new", model_version: "phase4-iforest-v1", model_threshold: .6, baseline_store_epoch: "e", hosts: [host]} as BaselineEvaluateResponse;
const history = {schema_version: "phase6.baseline.history.v1", source: "REPLAYED DEMO TRAFFIC", baseline_store_epoch: "e", host_ip: "192.0.2.10", readiness: "warming", coverage_confidence: "insufficient", current_version: 0, anchor_version: null, current_baseline: null, snapshots: [], decisions: [{observation_id: "o", window_start: "2026-11-01T10:00:00Z", decision: "Accept", reason_codes: ["WARMUP_STARTED"], version_before: null, version_after: 0, finding_ids: []}]} as BaselineHistoryResponse;
const upload = {analysis_id: "a", source: "REPLAYED DEMO TRAFFIC", flows: [], results: [], host_profiles: [{host_ip: "192.0.2.10"}], model: {model_threshold: .6}, flagged_alert_count: 0} as unknown as UploadAnalysisResponse;
let container: HTMLDivElement; let root: ReturnType<typeof createRoot>;
beforeEach(() => {container = document.createElement("div"); document.body.append(container); root = createRoot(container); evaluateBaseline.mockReset().mockResolvedValue(result); evaluateHybrid.mockReset(); getBaselineHistory.mockReset().mockResolvedValue(history); getHybridTelemetryStatus.mockReset(); protectHybrid.mockReset(); verifyHybrid.mockReset(); verifyHybridTamperedCopy.mockReset();});
afterEach(async () => {await act(async () => root.unmount()); container.remove();});

test("upload does not admit until explicit mode and one Evaluate click; graph uses actual response", async () => {
  await act(async () => root.render(<AnalysisWorkspace upload={upload} />));
  expect(evaluateBaseline).not.toHaveBeenCalled();
  const button = [...container.querySelectorAll("button")].find(b => b.textContent === "Evaluate selected analysis")!;
  await act(async () => {button.click(); await Promise.resolve();});
  expect(evaluateBaseline).toHaveBeenCalledTimes(1);
  expect(evaluateHybrid).not.toHaveBeenCalled();
  expect(container.textContent).toContain("Evaluation requested: Legacy");
  expect(container.textContent).not.toContain("Offline PCAP analysis only");
  expect(container.textContent).not.toContain("REPLAYED DEMO TRAFFIC");
  expect(container.textContent).toContain("Adaptive baseline evolution");
  expect(container.textContent).toContain("WARMUP_STARTED");
  expect(container.textContent).toContain("4.000");
});

test("a hybrid 409 stays on the selected route and never retries legacy admission", async () => {
  evaluateHybrid.mockRejectedValue(new VisualizationApiError(409, "HYBRID_EVALUATION_CONFLICT"));
  await act(async () => root.render(<AnalysisWorkspace upload={upload} />));
  const hybridRadio = container.querySelectorAll<HTMLInputElement>('input[type="radio"]')[1];
  await act(async () => {hybridRadio.click();});
  const button = [...container.querySelectorAll("button")].find(b => b.textContent === "Evaluate selected analysis")!;
  await act(async () => {button.click(); await Promise.resolve();});
  expect(evaluateHybrid).toHaveBeenCalledTimes(1);
  expect(evaluateBaseline).not.toHaveBeenCalled();
  expect(container.textContent).toContain("Evaluation requested: Hybrid");
  expect(container.textContent).toContain("HYBRID_EVALUATION_CONFLICT");
  expect(button.disabled).toBe(true);
});

test("opt-in v2 Protect and Verify have independent states and one request each", async () => {
  evaluateHybrid.mockResolvedValue({...result, schema_version: "phase7.hybrid.v1", rule_set_version: "increment4-demo-rules-v1", flow_results: [], rule_assessments: [], findings: [], telemetry: {schema_version: "phase7.secure-telemetry.v2", eligible_count: 1}});
  getHybridTelemetryStatus.mockResolvedValue({schema_version: "phase7.secure-telemetry.v2", analysis_id: "a", status: "not_requested", protected_count: 0});
  protectHybrid.mockResolvedValue({schema_version: "phase7.secure-telemetry.v2", analysis_id: "a", protection_id: "a", status: "protected", protected_count: 1});
  verifyHybrid.mockResolvedValue({schema_version: "phase7.secure-telemetry.v2", analysis_id: "a", protection_id: "a", verification: "verified", protected_count: 1, verified_count: 1, all_valid: true});
  await act(async () => root.render(<AnalysisWorkspace upload={upload} />));
  await act(async () => {container.querySelectorAll<HTMLInputElement>('input[type="radio"]')[1].click();});
  await act(async () => {[...container.querySelectorAll("button")].find(b => b.textContent === "Evaluate selected analysis")!.click(); await Promise.resolve();});
  expect(container.textContent).toContain("Evaluation requested: Hybrid");
  expect(container.textContent).not.toContain("High findings Verified");
  await act(async () => {[...container.querySelectorAll("button")].find(b => b.textContent === "Protect unified findings (v2)")!.click(); await Promise.resolve();});
  expect(protectHybrid).toHaveBeenCalledTimes(1);
  expect(container.textContent).toContain("High findings Protected");
  expect(container.textContent).not.toContain("High findings Verified");
  await act(async () => {[...container.querySelectorAll("button")].find(b => b.textContent === "Verify unified findings (v2)")!.click(); await Promise.resolve();});
  expect(verifyHybrid).toHaveBeenCalledTimes(1);
  expect(container.textContent).toContain("High findings Verified");
});

test("switching hosts never renders the previous host history as the new host", async () => {
  evaluateBaseline.mockResolvedValue({...result, hosts: [host, {...host, host_ip: "198.51.100.20"}]});
  getBaselineHistory.mockImplementation((ip: string) => Promise.resolve({...history, host_ip: ip}));
  await act(async () => root.render(<AnalysisWorkspace upload={upload} />));
  await act(async () => {[...container.querySelectorAll("button")].find(b => b.textContent === "Evaluate selected analysis")!.click(); await Promise.resolve();});
  await act(async () => root.render(<AnalysisWorkspace upload={upload} view="baseline" tab="evolution" />));
  const select = container.querySelector<HTMLSelectElement>('.dashboard-selectors select')!;
  await act(async () => {select.value = "198.51.100.20"; select.dispatchEvent(new Event("change", {bubbles: true})); await Promise.resolve();});
  expect(getBaselineHistory).toHaveBeenCalledWith("198.51.100.20", expect.anything());
  expect(container.textContent).toContain("Host 198.51.100.20");
});

test("epoch change shows restart discontinuity and never plots the old ledger", async () => {
  const oldRecord = {analysisId: "old", observationId: "old", epoch: "older-epoch", hostIp: "192.0.2.10", mode: "legacy" as const, current: features, before: null, after: null, readiness: "warming" as const, versionBefore: null, versionAfter: 0};
  const update = vi.fn();
  await act(async () => root.render(<AnalysisWorkspace upload={upload} ledger={[oldRecord]} onLedger={update} />));
  await act(async () => {[...container.querySelectorAll("button")].find(b => b.textContent === "Evaluate selected analysis")!.click(); await Promise.resolve();});
  expect(container.textContent).toContain("Backend restart or baseline epoch change detected");
  expect(container.textContent).not.toContain("older-epoch");
});

test("backend unavailable is explicit and never reports an admission", async () => {
  evaluateBaseline.mockRejectedValue(new VisualizationApiError(503, "BASELINE_UNAVAILABLE"));
  await act(async () => root.render(<AnalysisWorkspace upload={upload} />));
  await act(async () => {[...container.querySelectorAll("button")].find(b => b.textContent === "Evaluate selected analysis")!.click(); await Promise.resolve();});
  expect(container.textContent).toContain("Backend unavailable");
  expect(container.textContent).toContain("No baseline admission requested yet");
  expect(container.textContent).not.toContain("Host 192.0.2.10 · Accept");
});

test("hybrid flow-count mismatch reports invalid response without blanking the dashboard", async () => {
  evaluateHybrid.mockResolvedValue({...result, schema_version: "phase7.hybrid.v1", rule_set_version: "increment4-demo-rules-v1", flow_results: [{flow_index: 0, anomaly_score: .7, risk_level: "High", risk_score: 90, alert_flagged: true}], rule_assessments: [], findings: [], telemetry: {schema_version: "phase7.secure-telemetry.v2", eligible_count: 0}});
  await act(async () => root.render(<AnalysisWorkspace upload={upload} />));
  await act(async () => {container.querySelectorAll<HTMLInputElement>('input[type="radio"]')[1].click();});
  await act(async () => {[...container.querySelectorAll("button")].find(b => b.textContent === "Evaluate selected analysis")!.click(); await Promise.resolve();});
  expect(container.textContent).toContain("invalid or unavailable");
  expect(container.textContent).toContain("Adaptive analysis dashboard");
});
test("navigation hides panels without resetting admission or history", async () => {
  await act(async () => root.render(<AnalysisWorkspace upload={upload} view="overview" tab="summary" />));
  await act(async () => {[...container.querySelectorAll("button")].find(b => b.textContent === "Evaluate selected analysis")!.click(); await Promise.resolve();});
  await act(async () => root.render(<AnalysisWorkspace upload={upload} view="baseline" tab="evolution" />));
  expect(evaluateBaseline).toHaveBeenCalledTimes(1);
  expect(getBaselineHistory).toHaveBeenCalledTimes(1);
  expect(container.querySelector(".baseline-evolution")?.closest("[hidden]")).toBeNull();
  await act(async () => root.render(<AnalysisWorkspace upload={upload} view="traffic" tab="protocols" />));
  expect(container.querySelector(".baseline-evolution")?.closest("[hidden]")).not.toBeNull();
  await act(async () => root.render(<AnalysisWorkspace upload={upload} view="baseline" tab="evolution" />));
  expect(container.textContent).toContain("Evaluation requested: Legacy");
  expect(evaluateBaseline).toHaveBeenCalledTimes(1);
});
test("v2 Protected and Verified state survives sidebar and tab changes without a second admission", async () => {
  evaluateHybrid.mockResolvedValue({...result, schema_version: "phase7.hybrid.v1", rule_set_version: "increment4-demo-rules-v1", flow_results: [], rule_assessments: [], findings: [], telemetry: {schema_version: "phase7.secure-telemetry.v2", eligible_count: 1}});
  getHybridTelemetryStatus.mockResolvedValue({schema_version: "phase7.secure-telemetry.v2", analysis_id: "a", status: "not_requested", protected_count: 0});
  protectHybrid.mockResolvedValue({schema_version: "phase7.secure-telemetry.v2", analysis_id: "a", protection_id: "a", status: "protected", protected_count: 1});
  verifyHybrid.mockResolvedValue({schema_version: "phase7.secure-telemetry.v2", analysis_id: "a", protection_id: "a", verification: "verified", protected_count: 1, verified_count: 1, all_valid: true});
  await act(async () => root.render(<AnalysisWorkspace upload={upload} view="overview" tab="summary" />));
  await act(async () => container.querySelectorAll<HTMLInputElement>('input[type="radio"]')[1].click());
  await act(async () => {[...container.querySelectorAll("button")].find(b => b.textContent === "Evaluate selected analysis")!.click(); await Promise.resolve();});
  await act(async () => root.render(<AnalysisWorkspace upload={upload} view="telemetry" tab="unified-findings-v2" />));
  await act(async () => {[...container.querySelectorAll("button")].find(b => b.textContent === "Protect unified findings (v2)")!.click(); await Promise.resolve();});
  await act(async () => {[...container.querySelectorAll("button")].find(b => b.textContent === "Verify unified findings (v2)")!.click(); await Promise.resolve();});
  await act(async () => root.render(<AnalysisWorkspace upload={upload} view="baseline" tab="evolution" />));
  await act(async () => root.render(<AnalysisWorkspace upload={upload} view="telemetry" tab="unified-findings-v2" />));
  expect(container.textContent).toContain("High findings Verified");
  expect(evaluateHybrid).toHaveBeenCalledTimes(1);
  expect(protectHybrid).toHaveBeenCalledTimes(1);
  expect(verifyHybrid).toHaveBeenCalledTimes(1);
});
