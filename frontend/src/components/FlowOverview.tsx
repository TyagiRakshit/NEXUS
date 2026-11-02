import type {UploadAnalysisResponse} from "../status";
import type {HybridEvaluateResponse} from "../visualizationApi";
import {buildFlowScoreRows, buildProtocolRows} from "../visualizationModels";
import {FlowScoreChart} from "./FlowScoreChart";

export function FlowOverview({upload, hybrid, section = "all"}: {upload: UploadAnalysisResponse; hybrid: HybridEvaluateResponse | null; section?: "all" | "protocols" | "scores"}) {
  const protocols = buildProtocolRows(upload), scores = buildFlowScoreRows(upload, hybrid ?? undefined);
  const maxCount = Math.max(1, ...protocols.map(p => p.count));
  return <section className="dashboard-panel" aria-labelledby="flow-overview-heading">
    <div className="panel-heading"><div><p className="eyebrow">FLOW ANALYSIS</p><h3 id="flow-overview-heading">{section === "protocols" ? "Protocol distribution" : section === "scores" ? "Isolation Forest scores" : "Protocol distribution and Isolation Forest scores"}</h3></div></div>
    <p>Flow counts and original anomaly scores come from this uploaded PCAP. The score measures statistical unusualness, not attack probability.</p>
    {(section === "all" || section === "protocols") && <>
      <div className="chart-scroll"><svg viewBox={`0 0 620 ${Math.max(100, protocols.length * 36 + 30)}`} role="img" aria-label="Protocol distribution; exact counts in the following table"><title>Uploaded flow count by protocol</title>{protocols.map((p, i) => <g key={p.protocol}><text x="5" y={33+i*36} fontSize="14" fill="#e8f4f5">{p.protocol}</text><rect x="80" y={18+i*36} height="20" width={490*p.count/maxCount} fill="#42d5c5" /><text x={85+490*p.count/maxCount} y={33+i*36} fontSize="14" fill="#e8f4f5">{p.count}</text></g>)}</svg></div>
      <div className="table-scroll"><table><caption>Uploaded flow count by protocol</caption><thead><tr><th scope="col">Protocol</th><th scope="col">Flows</th></tr></thead><tbody>{protocols.map(p => <tr key={p.protocol}><td>{p.protocol}</td><td>{p.count}</td></tr>)}</tbody></table></div>
    </>}
    {(section === "all" || section === "scores") && <>
      <FlowScoreChart key={upload.analysis_id} upload={upload} scores={scores} />
      <details className="evidence-details"><summary>Inspect all flow scores and explanations ({scores.length})</summary><div className="table-scroll"><table><caption>Original Isolation Forest results; score is not a probability</caption><thead><tr><th scope="col">Flow</th><th scope="col">Anomaly score</th><th scope="col">Threshold</th><th scope="col">Risk</th><th scope="col">Flagged</th><th scope="col">Explanation</th></tr></thead><tbody>{upload.results.map((r,i) => <tr key={i}><td>{i+1}: {r.protocol} {r.source_ip} → {r.destination_ip}</td><td>{r.anomaly_score.toFixed(6)}</td><td>{upload.model.model_threshold.toFixed(6)}</td><td>{r.risk_level}</td><td>{r.alert_flagged ? "Yes" : "No"}</td><td>{r.explanations.join(" ")}</td></tr>)}</tbody></table></div></details>
    </>}
  </section>;
}
