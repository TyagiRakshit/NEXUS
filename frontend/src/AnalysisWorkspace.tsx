import {useEffect, useRef, useState} from "react";
import type {Dispatch, SetStateAction} from "react";
import type {UploadAnalysisResponse} from "./status";
import {evaluateBaseline, evaluateHybrid, getBaselineHistory, VisualizationApiError} from "./visualizationApi";
import type {BaselineEvaluateResponse, BaselineHistoryResponse, HybridEvaluateResponse} from "./visualizationApi";
import {addEvaluationRecords, buildEvolutionRows, metricLabels} from "./visualizationModels";
import type {EvaluationRecord, HostMetric} from "./visualizationModels";
import {BaselineEvolution} from "./components/BaselineEvolution";
import {HostDetails} from "./components/HostDetails";
import {FlowOverview} from "./components/FlowOverview";
import {FindingsPanel} from "./components/FindingsPanel";
import {TelemetryPanel} from "./components/TelemetryPanel";
import type {DashboardView} from "./components/DashboardShell";

type Props = {upload: UploadAnalysisResponse; ledger?: EvaluationRecord[]; onLedger?: Dispatch<SetStateAction<EvaluationRecord[]>>; view?: DashboardView; tab?: string};
type Result = BaselineEvaluateResponse | HybridEvaluateResponse;
function describe(error: unknown): string {
  if (!(error instanceof VisualizationApiError)) return "The API response was invalid or unavailable.";
  if (error.status === 404) return "This analysis or history expired or is unavailable. Upload the PCAP again.";
  if (error.status === 409) return `Conflict (${error.code}). No alternate evaluation route was attempted.`;
  if (error.status === 503 || error.status === 0) return "Backend unavailable. In-memory baseline state may have restarted; recheck history after reconnecting.";
  return `API request failed (${error.code}).`;
}
export default function AnalysisWorkspace({upload, ledger: parentLedger, onLedger, view = "overview", tab = "summary"}: Props) {
  const [localLedger, setLocalLedger] = useState<EvaluationRecord[]>([]);
  const ledger = parentLedger ?? localLedger;
  const updateLedger = onLedger ?? setLocalLedger;
  const [mode, setMode] = useState<"legacy" | "hybrid">("legacy");
  const [requestedMode, setRequestedMode] = useState<"legacy" | "hybrid" | null>(null);
  const [evaluation, setEvaluation] = useState<Result | null>(null);
  const [history, setHistory] = useState<BaselineHistoryResponse | null>(null);
  const [selectedHost, setSelectedHost] = useState(upload.host_profiles[0]?.host_ip ?? "");
  const [metric, setMetric] = useState<HostMetric>("observed_flow_count");
  const [pending, setPending] = useState(false);
  const [historyPending, setHistoryPending] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [historyError, setHistoryError] = useState<string | null>(null);
  const [restartNotice, setRestartNotice] = useState(false);
  const [expired, setExpired] = useState(false);
  const inFlight = useRef(false);
  const alive = useRef(true);
  useEffect(() => {alive.current = true; return () => {alive.current = false;};}, []);

  async function evaluate() {
    if (inFlight.current || requestedMode !== null || expired) return;
    inFlight.current = true;
    setPending(true); setError(null); setRequestedMode(mode);
    try {
      const result = mode === "hybrid" ? await evaluateHybrid(upload.analysis_id) : await evaluateBaseline(upload.analysis_id);
      if (!alive.current) return;
      if (result.analysis_id !== upload.analysis_id) throw new Error("Analysis identity mismatch");
      if (result.schema_version === "phase7.hybrid.v1" && result.flow_results.length !== upload.results.length) throw new Error("Hybrid flow count mismatch");
      setRestartNotice(ledger.length > 0 && ledger.some(r => r.epoch !== result.baseline_store_epoch));
      updateLedger(current => addEvaluationRecords(current, result, mode));
      setEvaluation(result);
      setSelectedHost(current => result.hosts.some(h => h.host_ip === current) ? current : result.hosts[0]?.host_ip ?? "");
    } catch (e) {
      if (!alive.current) return;
      setError(describe(e));
      if (e instanceof VisualizationApiError && e.status === 404) setExpired(true);
    } finally {if (alive.current) setPending(false); inFlight.current = false;}
  }

  useEffect(() => {
    if (!selectedHost || !evaluation) return;
    const controller = new AbortController();
    setHistoryPending(true); setHistoryError(null); setHistory(null);
    void getBaselineHistory(selectedHost, controller.signal).then(result => {
      if (controller.signal.aborted) return;
      if (result.host_ip !== selectedHost) throw new Error("Host mismatch");
      if (result.baseline_store_epoch !== evaluation.baseline_store_epoch) {
        setRestartNotice(true); updateLedger([]); setHistoryError("Backend baseline epoch changed; old observed history was cleared. Re-upload to evaluate in the new state."); return;
      }
      setHistory(result);
    }).catch(e => {if (!controller.signal.aborted) setHistoryError(describe(e));}).finally(() => {if (!controller.signal.aborted) setHistoryPending(false);});
    return () => controller.abort();
  }, [selectedHost, evaluation, updateLedger]);

  const selected = evaluation?.hosts.find(h => h.host_ip === selectedHost) ?? null;
  const selectedHistory = history?.host_ip === selectedHost && history.baseline_store_epoch === evaluation?.baseline_store_epoch ? history : null;
  const rows = selectedHistory ? buildEvolutionRows(selectedHistory, ledger, selectedHost, metric) : [];
  const hybrid = evaluation?.schema_version === "phase7.hybrid.v1" ? evaluation : null;
  return <section className="dashboard-workspace" aria-label="Analysis dashboard">
    <div hidden={view !== "overview" || tab !== "summary"}>
    <h3>Adaptive analysis dashboard</h3>
    <p>Analysis ID: <code>{upload.analysis_id}</code></p>
    <fieldset disabled={requestedMode !== null || pending}><legend>Choose one admission route for this analysis</legend>
      <label><input type="radio" name={`admission-${upload.analysis_id}`} checked={mode === "legacy"} onChange={() => setMode("legacy")} /> Legacy baseline</label>
      <label><input type="radio" name={`admission-${upload.analysis_id}`} checked={mode === "hybrid"} onChange={() => setMode("hybrid")} /> Hybrid rules + baseline</label>
    </fieldset>
    <button type="button" disabled={requestedMode !== null || pending || expired} onClick={() => void evaluate()}>{pending ? "Evaluating..." : "Evaluate selected analysis"}</button>
    {requestedMode && <p>Evaluation requested: {requestedMode === "legacy" ? "Legacy" : "Hybrid"}. This describes the route selected in this browser session.</p>}
    {evaluation && <p>Observation {evaluation.observation_id} · capture {evaluation.capture_window_start ?? "Unavailable"} → {evaluation.capture_window_end ?? "Unavailable"} UTC · baseline epoch {evaluation.baseline_store_epoch}</p>}
    {restartNotice && <p role="alert" className="status-error">Backend restart or baseline epoch change detected. Earlier observed points were cleared.</p>}
    {error && <p role="alert" className="status-error">{error}</p>}
    {historyError && <p role="alert" className="status-error">{historyError}</p>}
    <p role="status" aria-live="polite">{pending ? "Evaluating analysis..." : historyPending ? "Loading host history..." : evaluation ? "Evaluation and host history available where returned." : "No baseline admission requested yet."}</p>
    </div>
    {evaluation && view === "baseline" && <div className="dashboard-selectors"><label>Host <select value={selectedHost} onChange={e => setSelectedHost(e.target.value)}>{evaluation.hosts.map(h => <option key={h.host_ip} value={h.host_ip}>{h.host_ip}</option>)}</select></label><label>Feature <select value={metric} onChange={e => setMetric(e.target.value as HostMetric)}>{(Object.keys(metricLabels) as HostMetric[]).map(m => <option key={m} value={m}>{metricLabels[m]}</option>)}</select></label></div>}
    <div hidden={view !== "baseline" || (tab !== "evolution" && tab !== "decision-history")}><BaselineEvolution rows={rows} metric={metric} display={tab === "decision-history" ? "history" : "evolution"} /></div>
    <div hidden={view !== "baseline" || tab !== "feature-comparison"}><HostDetails host={selected} history={selectedHistory} /></div>
    <div hidden={view !== "traffic" || (tab !== "protocols" && tab !== "flow-explorer")}><FlowOverview upload={upload} hybrid={hybrid} section={tab === "flow-explorer" ? "scores" : "protocols"} /></div>
    <div hidden={view !== "findings"}><FindingsPanel hybrid={hybrid} source={tab} upload={upload} baseline={evaluation?.schema_version === "phase6.baseline.v1" ? evaluation : null} /></div>
    <div hidden={view !== "telemetry" || tab !== "unified-findings-v2"}><TelemetryPanel upload={upload} hybrid={hybrid} /></div>
  </section>;
}
