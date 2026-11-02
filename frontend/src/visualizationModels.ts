import type {BaselineHistoryResponse, Features, HostAdmission, HybridEvaluateResponse, Readiness} from "./visualizationApi";
import type {UploadAnalysisResponse} from "./status";

export type HostMetric = "observed_flow_count" | "average_bytes_per_flow" | "average_duration_seconds" | "average_packets_per_second" | "protocol_shares.TCP" | "protocol_shares.UDP" | "protocol_shares.ICMP" | "protocol_shares.OTHER";
export const metricLabels: Record<HostMetric, string> = {
  observed_flow_count: "Observed flow count", average_bytes_per_flow: "Average bytes per flow", average_duration_seconds: "Average duration (seconds)", average_packets_per_second: "Average packets per second", "protocol_shares.TCP": "TCP share", "protocol_shares.UDP": "UDP share", "protocol_shares.ICMP": "ICMP share", "protocol_shares.OTHER": "Other protocol share",
};
export type EvaluationRecord = {analysisId: string; observationId: string; epoch: string; hostIp: string; mode: "legacy" | "hybrid"; current: Features; before: Features | null; after: Features | null; readiness: Readiness; versionBefore: number | null; versionAfter: number | null};
export type EvolutionRow = {observationId: string; windowStart: string | null; decision: "Accept" | "Hold" | "Reject"; reasons: string[]; versionBefore: number | null; versionAfter: number | null; observed: number | null; before: number | null; after: number | null; readiness: Readiness | null; availability: "observed" | "retained-snapshot" | "unavailable"; findingIds: string[]};
export function metricValue(features: Features | null, metric: HostMetric): number | null {
  if (features === null) return null;
  if (metric.startsWith("protocol_shares.")) return features.protocol_shares[metric.slice(16) as keyof Features["protocol_shares"]];
  return features[metric as Exclude<HostMetric, `protocol_shares.${string}`>];
}
export function buildEvolutionRows(history: BaselineHistoryResponse, ledger: EvaluationRecord[], hostIp: string, metric: HostMetric): EvolutionRow[] {
  if (history.host_ip !== hostIp) throw new Error("History host mismatch");
  return history.decisions.map(d => {
    const record = ledger.find(r => r.epoch === history.baseline_store_epoch && r.hostIp === hostIp && r.observationId === d.observation_id);
    const snapshot = history.snapshots.find(s => s.observation_id === d.observation_id);
    return {observationId: d.observation_id, windowStart: d.window_start, decision: d.decision, reasons: d.reason_codes, versionBefore: d.version_before, versionAfter: d.version_after, observed: record ? metricValue(record.current, metric) : null, before: record ? metricValue(record.before, metric) : snapshot ? metricValue(snapshot.features_before, metric) : null, after: record ? metricValue(record.after, metric) : snapshot ? metricValue(snapshot.features_after, metric) : null, readiness: record?.readiness ?? null, availability: record ? "observed" : snapshot ? "retained-snapshot" : "unavailable", findingIds: d.finding_ids};
  });
}
export function addEvaluationRecords(ledger: EvaluationRecord[], evaluation: {analysis_id: string; observation_id: string; baseline_store_epoch: string; hosts: HostAdmission[]}, mode: "legacy" | "hybrid"): EvaluationRecord[] {
  const currentEpoch = evaluation.baseline_store_epoch;
  const sameEpoch = ledger.filter(r => r.epoch === currentEpoch);
  for (const h of evaluation.hosts) {
    const key = `${currentEpoch}|${h.host_ip}|${evaluation.observation_id}`;
    if (sameEpoch.some(r => `${r.epoch}|${r.hostIp}|${r.observationId}` === key)) continue;
    sameEpoch.push({analysisId: evaluation.analysis_id, observationId: evaluation.observation_id, epoch: currentEpoch, hostIp: h.host_ip, mode, current: h.current_features, before: h.baseline_before, after: h.baseline_after, readiness: h.readiness_after, versionBefore: h.version_before, versionAfter: h.version_after});
  }
  const perHost = new Map<string, EvaluationRecord[]>();
  for (const r of sameEpoch) perHost.set(r.hostIp, [...(perHost.get(r.hostIp) ?? []), r].slice(-32));
  return [...perHost.values()].flat();
}
export function buildProtocolRows(upload: UploadAnalysisResponse): {protocol: string; count: number}[] {
  const counts = new Map<string, number>();
  for (const flow of upload.flows) counts.set(flow.protocol, (counts.get(flow.protocol) ?? 0) + 1);
  return [...counts].map(([protocol, count]) => ({protocol, count}));
}
export function buildFlowScoreRows(upload: UploadAnalysisResponse, hybrid?: HybridEvaluateResponse): {index: number; score: number; threshold: number; risk: string; flagged: boolean}[] {
  if (hybrid && (hybrid.analysis_id !== upload.analysis_id || hybrid.flow_results.length !== upload.results.length)) throw new Error("Analysis result mismatch");
  return upload.results.map((item, index) => ({index, score: item.anomaly_score, threshold: upload.model.model_threshold, risk: item.risk_level, flagged: item.alert_flagged}));
}
export function buildHostComparison(host: HostAdmission): {metric: HostMetric; observed: number; before: number | null; after: number | null}[] {
  return (Object.keys(metricLabels) as HostMetric[]).map(metric => ({metric, observed: metricValue(host.current_features, metric)!, before: metricValue(host.baseline_before, metric), after: metricValue(host.baseline_after, metric)}));
}
