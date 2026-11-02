import type {UploadAnalysisResponse} from "../status";
import type {EvaluationRecord} from "../visualizationModels";
import {buildProtocolRows} from "../visualizationModels";

export function DashboardSummary({upload, ledger, tab}: {upload: UploadAnalysisResponse | null; ledger: EvaluationRecord[]; tab: string}) {
  if (tab === "recent-analysis") {
    const recent = [...new Map(ledger.map(row => [row.analysisId, row])).values()].reverse();
    return <section className="dashboard-panel" aria-label="Recent Analysis">
      <h2>Recent Analysis</h2><p>Current browser session only. Earlier PCAP uploads cannot be reopened here; reload clears this list.</p>
      {upload && <p>Selected analysis: <code>{upload.analysis_id}</code></p>}
      {recent.length === 0 ? <p>No evaluated analyses in this browser session.</p> :
        <ol className="recent-list">{recent.map(row => <li key={row.analysisId}><code>{row.analysisId}</code> · Evaluation requested: {row.mode === "legacy" ? "Legacy" : "Hybrid"} · host {row.hostIp}. Summary only; upload details unavailable.</li>)}</ol>}
    </section>;
  }
  if (!upload) return null;
  const protocols = buildProtocolRows(upload);
  return <section className="summary-dashboard" aria-label="Analysis summary">
    <div className="kpi-grid">
      <div className="kpi-card"><span>Packets</span><strong>{upload.packet_count.toLocaleString()}</strong></div>
      <div className="kpi-card"><span>Flows</span><strong>{upload.flow_count.toLocaleString()}</strong></div>
      <div className="kpi-card"><span>Hosts</span><strong>{upload.host_profiles.length.toLocaleString()}</strong></div>
      <div className="kpi-card"><span>Flagged flow alerts</span><strong>{upload.flagged_alert_count.toLocaleString()}</strong></div>
    </div>
    <div className="dashboard-panel"><h2>Protocol distribution</h2><p>Flow counts from the selected uploaded PCAP.</p>
      {protocols.length === 0 ? <p>No flows were extracted.</p> : <ul className="protocol-summary">{protocols.map(row => <li key={row.protocol}><span>{row.protocol}</span><span className="protocol-track" role="img" aria-label={`${row.protocol}: ${row.count} of ${upload.flow_count} flows`}><span style={{width: `${(row.count / (upload.flow_count || 1)) * 100}%`}} /></span><strong>{row.count}</strong></li>)}</ul>}
    </div>
  </section>;
}
