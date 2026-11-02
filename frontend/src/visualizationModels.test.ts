import {expect, test} from "vitest";
import {addEvaluationRecords, buildEvolutionRows, buildFlowScoreRows, buildProtocolRows} from "./visualizationModels";
import type {BaselineHistoryResponse, Features} from "./visualizationApi";
import type {UploadAnalysisResponse} from "./status";

const features: Features = {observed_flow_count: 4, average_bytes_per_flow: 100, average_duration_seconds: 2, average_packets_per_second: 3, protocol_shares: {TCP: .5, UDP: .25, ICMP: .25, OTHER: 0}};
const history: BaselineHistoryResponse = {schema_version: "phase6.baseline.history.v1", source: "REPLAYED DEMO TRAFFIC", baseline_store_epoch: "epoch-1", host_ip: "192.0.2.10", readiness: "ready", coverage_confidence: "accumulated", current_version: 1, anchor_version: 0, current_baseline: features, snapshots: [], decisions: [
  {observation_id: "old", window_start: "2026-11-01T10:00:00Z", decision: "Accept", reason_codes: ["WARMUP_STARTED"], version_before: null, version_after: 0, finding_ids: []},
  {observation_id: "new", window_start: "2026-11-01T10:01:00Z", decision: "Hold", reason_codes: ["PROBATION_STARTED"], version_before: 1, version_after: 1, finding_ids: []},
]};

test("evolution uses only same-epoch observed values and leaves missing points explicit", () => {
  const rows = buildEvolutionRows(history, [{analysisId: "a", observationId: "new", epoch: "epoch-1", hostIp: "192.0.2.10", mode: "hybrid", current: features, before: features, after: features, readiness: "ready", versionBefore: 1, versionAfter: 1}, {analysisId: "b", observationId: "old", epoch: "old-epoch", hostIp: "192.0.2.10", mode: "legacy", current: features, before: null, after: null, readiness: "warming", versionBefore: null, versionAfter: 0}], "192.0.2.10", "observed_flow_count");
  expect(rows.map(r => r.observed)).toEqual([null, 4]);
  expect(rows[0].availability).toBe("unavailable");
  expect(rows[1].decision).toBe("Hold");
  expect(rows[1].after).toBe(4);
});

test("retained accepted snapshots supply baseline lines but never invent observed values", () => {
  const withSnapshot = {...history, snapshots: [{version: 0, observation_id: "old", window_start: "2026-11-01T10:00:00Z", reason_code: "WARMUP_STARTED", features_before: null, features_after: features}]};
  const rows = buildEvolutionRows(withSnapshot, [], "192.0.2.10", "protocol_shares.TCP");
  expect(rows[0]).toMatchObject({observed: null, before: null, after: .5, availability: "retained-snapshot"});
  expect(rows[1]).toMatchObject({observed: null, before: null, after: null, availability: "unavailable"});
});

test("same-session ledger retains distinct uploads, deduplicates evaluation and resets on epoch change", () => {
  const admission = {host_ip: "192.0.2.10", current_features: features, baseline_before: features, baseline_after: features, readiness_after: "ready", version_before: 1, version_after: 2};
  const first = {analysis_id: "a1", observation_id: "o1", baseline_store_epoch: "epoch-1", hosts: [admission]};
  const second = {analysis_id: "a2", observation_id: "o2", baseline_store_epoch: "epoch-1", hosts: [admission]};
  const one = addEvaluationRecords([], first as never, "legacy");
  const two = addEvaluationRecords(one, second as never, "hybrid");
  expect(two.map(r => r.observationId)).toEqual(["o1", "o2"]);
  expect(addEvaluationRecords(two, second as never, "hybrid")).toHaveLength(2);
  expect(addEvaluationRecords(two, {...second, baseline_store_epoch: "epoch-2"} as never, "hybrid")).toHaveLength(1);
});

test("protocol counts and scores come from uploaded flow results once", () => {
  const flow = {protocol: "TCP", source_ip: "192.0.2.10", source_port: 1234, destination_ip: "192.0.2.20", destination_port: 80, packet_count: 2, byte_count: 100, duration_seconds: 1, packets_per_second: 2, bytes_per_second: 100};
  const upload = {analysis_id: "a", flows: [flow, {...flow, protocol: "UDP"}], results: [{...flow, anomaly_score: -0.2, risk_level: "Low", risk_score: 20, alert_flagged: false, is_statistically_unusual: false, explanations: []}, {...flow, protocol: "UDP", anomaly_score: 0.8, risk_level: "High", risk_score: 90, alert_flagged: true, is_statistically_unusual: true, explanations: []}], model: {model_threshold: 0.6}} as unknown as UploadAnalysisResponse;
  expect(buildProtocolRows(upload)).toEqual([{protocol: "TCP", count: 1}, {protocol: "UDP", count: 1}]);
  const scores = buildFlowScoreRows(upload);
  expect(scores.map(s => s.score)).toEqual([-0.2, 0.8]);
  expect(scores.every(s => s.threshold === 0.6)).toBe(true);
});
