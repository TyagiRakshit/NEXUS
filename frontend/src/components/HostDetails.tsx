import type {HostAdmission, BaselineHistoryResponse} from "../visualizationApi";
import {buildHostComparison, metricLabels} from "../visualizationModels";

export function HostDetails({host, history}: {host: HostAdmission | null; history: BaselineHistoryResponse | null}) {
  return <section className="dashboard-panel" aria-labelledby="host-details-heading"><h3 id="host-details-heading">Current host versus baseline</h3>
    {host === null ? <p>Evaluate this analysis to see host admission and feature comparisons.</p> : <>
      <p>Host {host.host_ip} · {host.decision} · {host.reason_codes.join(", ")}</p>
      <p>Readiness {host.readiness_before} → {host.readiness_after} · confidence {host.coverage_confidence} · probation {host.probation_count} · version {host.version_before ?? "—"} → {host.version_after ?? "—"}</p>
      <div className="table-scroll"><table><caption>Actual observed and stored host feature values</caption><thead><tr><th scope="col">Feature</th><th scope="col">Observed</th><th scope="col">Baseline before</th><th scope="col">Baseline after</th></tr></thead><tbody>{buildHostComparison(host).map(row => <tr key={row.metric}><th scope="row">{metricLabels[row.metric]}</th><td>{row.observed.toFixed(3)}</td><td>{row.before === null ? "Not established" : row.before.toFixed(3)}</td><td>{row.after === null ? "Not established" : row.after.toFixed(3)}</td></tr>)}</tbody></table></div>
      {host.feature_deviations.length > 0 && <div className="table-scroll"><table><caption>Backend feature-deviation evidence</caption><thead><tr><th scope="col">Feature</th><th scope="col">Band</th><th scope="col">Deviation</th><th scope="col">Accept limit</th><th scope="col">Hold limit</th><th scope="col">Reason</th></tr></thead><tbody>{host.feature_deviations.map(d => <tr key={d.feature}><td>{d.feature}</td><td>{d.band}</td><td>{d.deviation}</td><td>{d.accept_limit}</td><td>{d.hold_limit}</td><td>{d.reason_code}</td></tr>)}</tbody></table></div>}
      {host.findings.map(f => <p key={f.finding_id}>{f.severity} host finding: {f.kind}. {f.explanation}</p>)}
    </>}
    {history && <p>History: {history.decisions.length} retained decisions, {history.snapshots.length} accepted snapshots; current version {history.current_version ?? "—"}, anchor {history.anchor_version ?? "—"}.</p>}
  </section>;
}
