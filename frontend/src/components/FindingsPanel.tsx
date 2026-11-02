import type {UploadAnalysisResponse} from "../status";
import type {BaselineEvaluateResponse, HybridEvaluateResponse} from "../visualizationApi";

function evidenceValue(value: unknown): string {
  if (value === null || value === undefined) return "—";
  if (typeof value === "string" || typeof value === "number" || typeof value === "boolean") return String(value);
  return JSON.stringify(value);
}
export function FindingsPanel({hybrid, source = "all", upload, baseline}: {hybrid: HybridEvaluateResponse | null; source?: string; upload?: UploadAnalysisResponse; baseline?: BaselineEvaluateResponse | null}) {
  const sourceKey = {ml:"isolation_forest", baseline:"adaptive_baseline", rules:"security_rule"}[source];
  const findings = hybrid?.findings.filter(f => !sourceKey || f.detection_source === sourceKey) ?? [];
  const showRules = source === "all" || source === "rules";
  const showMl = source === "all" || source === "ml";
  const showBaseline = source === "all" || source === "baseline";
  const legacyAlerts = hybrid === null && showMl ? upload?.results.filter(r => r.alert_flagged) ?? [] : [];
  const legacyHostFindings = hybrid === null && showBaseline ? baseline?.hosts.flatMap(h => h.findings.map(f => ({host:h.host_ip, finding:f}))) ?? [] : [];
  return <section className="dashboard-panel" aria-labelledby="findings-heading"><div className="panel-heading"><div><p className="eyebrow">SECURITY EVIDENCE</p><h3 id="findings-heading">Possible attack-pattern evidence and findings</h3></div><span>{hybrid ? "Hybrid evaluation" : baseline ? "Legacy evaluation" : "Not evaluated"}</span></div>
    <p>Rules use metadata only. A match is a possible pattern, not a confirmed attack, initiator or compromise. Rule evidence strength is not a calibrated probability. Isolation Forest scores are separate.</p>
    {hybrid === null ? <>
      <p>Unified findings require Hybrid evaluation. This view shows available original ML flow alerts and separate host baseline findings.</p>
      {legacyAlerts.map((r,i) => <article className="finding-card" key={i}><h4>ML flow alert · {r.risk_level}</h4><p>{r.protocol} {r.source_ip} → {r.destination_ip}</p><p>Original Isolation Forest score: {r.anomaly_score.toFixed(6)} · Risk severity: {r.risk_level}</p><p>{r.explanations.join(" ")}</p></article>)}
      {legacyHostFindings.map(({host,finding}) => <article className="finding-card" key={finding.finding_id}><h4>Baseline host finding · {finding.severity}</h4><p>Host {host} · {finding.kind}</p><p>{finding.explanation}</p></article>)}
      {legacyAlerts.length === 0 && legacyHostFindings.length === 0 && <p>No findings in this source for this evaluation.</p>}
    </> : <>
      {showRules && hybrid.rule_assessments.map((rule, i) => <article key={i} className="finding-card"><h4>{String(rule.rule_id)}: {rule.status === "Unknown" ? "Unknown / Insufficient Evidence" : String(rule.status)}</h4><p>{String(rule.explanation)}</p><p>Rule evidence strength: {rule.rule_evidence_strength === null ? "Unavailable" : String(rule.rule_evidence_strength)} · hosts: {Array.isArray(rule.subject_host_ips) ? rule.subject_host_ips.join(", ") : "Unavailable"}</p></article>)}
      {findings.length === 0 && !showRules ? <p>No unified findings from this source for this evaluation.</p> : findings.map(f => <article className="finding-card" key={f.finding_id}><h4>{f.severity}: {f.possible_category ? f.possible_category.replaceAll("_", " ") : f.kind}</h4><p>Source: {f.detection_source} · subject hosts: {f.subject_host_ips.join(", ")} · flow references: {f.flow_indices.join(", ") || "None"}</p><p>{f.explanation}</p><p>ML anomaly score: {f.ml_anomaly_score ?? "Not applicable"} · rule evidence strength: {f.rule_evidence_strength ?? "Not applicable"}</p><details className="evidence-details"><summary>Supporting evidence for finding {f.finding_id}</summary><div className="table-scroll"><table><caption>Evidence for finding {f.finding_id}</caption><thead><tr><th scope="col">Metric</th><th scope="col">Observed</th><th scope="col">Comparator</th><th scope="col">Threshold</th><th scope="col">Unit</th></tr></thead><tbody>{f.evidence.map((e,i) => <tr key={i}><td>{evidenceValue(e.metric)}</td><td>{evidenceValue(e.observed)}</td><td>{evidenceValue(e.comparator)}</td><td>{evidenceValue(e.threshold)}</td><td>{evidenceValue(e.unit)}</td></tr>)}</tbody></table></div></details></article>)}
      {findings.length === 0 && showRules && hybrid.rule_assessments.length === 0 && <p>No rule assessments or unified findings in this source.</p>}
    </>}
  </section>;
}
