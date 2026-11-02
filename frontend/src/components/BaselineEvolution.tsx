import type {EvolutionRow, HostMetric} from "../visualizationModels";
import {metricLabels} from "../visualizationModels";
import {describeAdmissionReason} from "../admissionCopy";

function format(value: number | null, metric: HostMetric): string {
  return value === null ? "Unavailable" : metric.startsWith("protocol_shares.") ? `${(value * 100).toFixed(1)}%` : value.toFixed(3);
}

export function BaselineEvolution({rows, metric, display = "evolution"}: {rows: EvolutionRow[]; metric: HostMetric; display?: "evolution" | "history"}) {
  const values = rows.flatMap(r => [r.observed, r.before, r.after]).filter((v): v is number => v !== null);
  const min = Math.min(...values, 0), max = Math.max(...values, 1);
  const y = (v: number) => 218 - (v - min) / (max - min || 1) * 172;
  const x = (index: number) => rows.length < 2 ? 390 : 68 + index * (660 / (rows.length - 1));
  const series = [{key: "observed" as const, color: "#42d5c5", label: "Observed"}, {key: "before" as const, color: "#f6b65f", label: "Baseline before"}, {key: "after" as const, color: "#a99bff", label: "Baseline after"}];
  return <section className="dashboard-panel baseline-evolution" aria-labelledby="evolution-heading">
    <div className="panel-heading"><div><p className="eyebrow">HOST BEHAVIOUR</p><h3 id="evolution-heading">{display === "history" ? "Decision history" : "Adaptive baseline evolution"}</h3></div><p>{metricLabels[metric]}</p></div>
    <p>Actual {metricLabels[metric]} by capture order. Missing observations remain gaps; no values are interpolated.</p>
    {rows.length === 0 ? <p>No baseline decisions yet. Upload a PCAP and choose Evaluate.</p> : <>
      {display === "evolution" && <>
        <div className="chart-scroll"><svg viewBox="0 0 760 280" role="img" aria-label={`${metricLabels[metric]} evolution graph; exact values in the following table`}>
          <title>{`${metricLabels[metric]} across baseline decisions`}</title>
          <desc>Observed behavior, baseline before and after. Each capture has its backend decision. Missing values have no marks or connecting lines.</desc>
          {[0,1,2,3,4].map(step => {const value = min+(max-min)*step/4; const pos=y(value); return <g key={step}><line x1="68" x2="730" y1={pos} y2={pos} stroke="#29434b" /><text x="4" y={pos+5} fontSize="12" fill="#a9c0c5">{format(value, metric)}</text></g>;})}
          {series.map(s => <g key={s.key}>{rows.map((r, i) => {
            const value = r[s.key]; if (value === null) return null;
            const previous = i > 0 ? rows[i-1][s.key] : null;
            return <g key={`${s.key}-${r.observationId}`}>
              {previous !== null && <line x1={x(i-1)} y1={y(previous)} x2={x(i)} y2={y(value)} stroke={s.color} strokeWidth="2" />}
              <circle cx={x(i)} cy={y(value)} r={r.decision === "Reject" ? 7 : 5} fill={s.color} stroke="#08151b" strokeWidth="2"><title>{`${s.label}: ${format(value, metric)}; ${r.decision}; ${r.observationId}`}</title></circle>
            </g>;
          })}</g>)}
          {rows.map((r,i) => <g key={r.observationId}><line x1={x(i)} x2={x(i)} y1="218" y2="224" stroke="#a9c0c5" /><text x={x(i)} y="245" textAnchor="middle" fontSize="12" fill="#e8f4f5">{r.decision === "Accept" ? "A" : r.decision === "Hold" ? "H" : "R"}</text><title>{`${r.decision}; ${r.windowStart ?? "time unavailable"}`}</title></g>)}
          <text x="390" y="270" textAnchor="middle" fontSize="12" fill="#a9c0c5">Capture order (A Accept, H Hold, R Reject)</text>
        </svg></div>
        <p className="chart-legend"><span className="legend-observed">Observed</span><span className="legend-before">Baseline before</span><span className="legend-after">Baseline after</span></p>
      </>}
      {rows.some(r => r.availability !== "observed") && <p className="history-gap">Observed values unavailable for earlier decisions. Available baseline snapshots are labelled; missing points remain gaps.</p>}
      <details className="evidence-details" open={display === "history"}><summary>Exact values and decisions ({rows.length} observations)</summary>
      <div className="table-scroll"><table><caption>Adaptive baseline decisions and plotted values</caption><thead><tr><th scope="col">Capture start (UTC)</th><th scope="col">Observation</th><th scope="col">Decision</th><th scope="col">Reasons and meaning</th><th scope="col">Observed</th><th scope="col">Before</th><th scope="col">After</th><th scope="col">Version before → after</th><th scope="col">Readiness</th><th scope="col">Data source</th></tr></thead><tbody>
        {rows.map(r => <tr key={r.observationId}><td>{r.windowStart ?? "Unavailable"}</td><td title={r.observationId}>{r.observationId.slice(0, 8)}…<span className="sr-only">{r.observationId}</span></td><td><strong className={`decision-pill decision-${r.decision.toLowerCase()}`}>{r.decision}</strong></td><td>{r.reasons.map(code => <p key={code} className="reason-text"><code>{code}</code>: {describeAdmissionReason(code)}</p>)}</td><td>{format(r.observed, metric)}</td><td>{format(r.before, metric)}</td><td>{format(r.after, metric)}</td><td>{r.versionBefore ?? "—"} → {r.versionAfter ?? "—"}</td><td>{r.readiness ?? "Unavailable"}</td><td>{r.availability === "observed" ? "Current session" : r.availability === "retained-snapshot" ? "Retained accepted snapshot" : "History marker only"}</td></tr>)}
      </tbody></table></div></details>
    </>}
  </section>;
}
