import { type ChangeEvent, useCallback, useEffect, useRef, useState } from "react";
import AnalysisWorkspace from "./AnalysisWorkspace";
import {DashboardShell, type DashboardView} from "./components/DashboardShell";
import {DashboardSummary} from "./components/DashboardSummary";
import {SecurityRuleCatalogue} from "./components/SecurityRuleCatalogue";
import type {EvaluationRecord} from "./visualizationModels";

import {
  adaptNormalProfiles,
  analyzeDetection,
  analyzeFixture,
  analyzeUploadedPcap,
  fetchStatus,
  protectFlaggedAlert,
  verifyProtectedAlert,
  verifyTamperedCopy,
  type AnalysisResponse,
  type DetectionResponse,
  type ProfileAdaptResponse,
  type ProtectAlertResponse,
  type TamperAlertResponse,
  type UploadAnalysisResponse,
  type VerifyAlertResponse,
} from "./status";

type VisibleStatus = "Healthy" | "Checking" | "Unavailable" | "Unknown";

const MAX_PCAP_BYTES = 1024 * 1024;

type CardProps = {
  name: "Frontend" | "Backend" | "Database";
  status: VisibleStatus;
};

function ServiceCard({ name, status }: CardProps) {
  return (
    <article className="service-card">
      <h2>{name}</h2>
      <p>{status}</p>
    </article>
  );
}

function endpoint(ip: string, port: number | null): string {
  return `${ip}:${port === null ? "-" : port}`;
}

function protocolCounts(
  values: Array<{ protocol: string; flow_count: number }>,
): string {
  return values.map((item) => `${item.protocol} ${item.flow_count}`).join(", ");
}

function protocolAverages(
  values: Array<{ protocol: string; average_flow_count: number }>,
): string {
  return values
    .map((item) => `${item.protocol} ${item.average_flow_count.toFixed(3)}`)
    .join(", ");
}

export default function App() {
  const [backend, setBackend] = useState<VisibleStatus>("Checking");
  const [database, setDatabase] = useState<VisibleStatus>("Checking");
  const [error, setError] = useState<string | null>(null);
  const [isChecking, setIsChecking] = useState(true);
  const [lastChecked, setLastChecked] = useState<string | null>(null);
  const [analysis, setAnalysis] = useState<AnalysisResponse | null>(null);
  const [analysisError, setAnalysisError] = useState<string | null>(null);
  const [isAnalyzing, setIsAnalyzing] = useState(false);
  const [profiles, setProfiles] = useState<ProfileAdaptResponse | null>(null);
  const [profileError, setProfileError] = useState<string | null>(null);
  const [isBuildingBaseline, setIsBuildingBaseline] = useState(false);
  const [detection, setDetection] = useState<DetectionResponse | null>(null);
  const [detectionError, setDetectionError] = useState<string | null>(null);
  const [isDetecting, setIsDetecting] = useState(false);
  const [networkFile, setNetworkFile] = useState<File | null>(null);
  const [networkFileError, setNetworkFileError] = useState<string | null>(null);
  const [uploadAnalysis, setUploadAnalysis] =
    useState<UploadAnalysisResponse | null>(null);
  const [uploadedFilename, setUploadedFilename] = useState<string | null>(null);
  const [networkUploadError, setNetworkUploadError] = useState<string | null>(null);
  const [isUploading, setIsUploading] = useState(false);
  const [protection, setProtection] = useState<ProtectAlertResponse | null>(null);
  const [verification, setVerification] = useState<VerifyAlertResponse | null>(null);
  const [tamperVerification, setTamperVerification] =
    useState<TamperAlertResponse | null>(null);
  const [cryptoError, setCryptoError] = useState<string | null>(null);
  const [isProtecting, setIsProtecting] = useState(false);
  const [isVerifying, setIsVerifying] = useState(false);
  const [isCheckingTamper, setIsCheckingTamper] = useState(false);
  const [evaluationLedger, setEvaluationLedger] = useState<EvaluationRecord[]>([]);
  const uploadGeneration = useRef(0);
  const [view, setView] = useState<DashboardView>("overview");
  const [tab, setTab] = useState("summary");
  const [flowFilter, setFlowFilter] = useState("");
  const navigate = (nextView: DashboardView, nextTab: string) => {setView(nextView); setTab(nextTab);};

  const selectNetworkFile = (event: ChangeEvent<HTMLInputElement>) => {
    ++uploadGeneration.current;
    setUploadAnalysis(null);
    setUploadedFilename(null);
    setProtection(null);
    setVerification(null);
    setTamperVerification(null);
    setCryptoError(null);
    setIsUploading(false);
    const file = event.currentTarget.files?.[0] ?? null;
    setNetworkFile(file);
    setNetworkUploadError(null);

    if (file === null) {
      setNetworkFileError(null);
    } else if (!file.name.toLowerCase().endsWith(".pcap")) {
      setNetworkFileError("Choose a .pcap file.");
    } else if (file.size > MAX_PCAP_BYTES) {
      setNetworkFileError("PCAP files must be 1 MiB or smaller.");
    } else {
      setNetworkFileError(null);
    }
  };

  const refresh = useCallback(async () => {
    setError(null);
    setIsChecking(true);
    try {
      const status = await fetchStatus();
      setBackend("Healthy");
      setDatabase(
        status.services.database === "healthy" ? "Healthy" : "Unavailable",
      );
      setLastChecked(new Date().toLocaleTimeString());
    } catch {
      setBackend("Unavailable");
      setDatabase("Unknown");
      setError("Unable to load service status.");
    } finally {
      setIsChecking(false);
    }
  }, []);

  useEffect(() => {
    void refresh();
  }, [refresh]);

  const analyze = useCallback(async () => {
    setAnalysisError(null);
    setIsAnalyzing(true);
    try {
      setAnalysis(await analyzeFixture());
    } catch {
      setAnalysis(null);
      setAnalysisError("Unable to analyze offline fixture.");
    } finally {
      setIsAnalyzing(false);
    }
  }, []);

  const adaptProfiles = useCallback(async () => {
    setProfileError(null);
    setIsBuildingBaseline(true);
    try {
      setProfiles(await adaptNormalProfiles());
    } catch {
      setProfiles(null);
      setProfileError("Unable to update normal baseline.");
    } finally {
      setIsBuildingBaseline(false);
    }
  }, []);

  const detect = useCallback(async () => {
    setDetectionError(null);
    setIsDetecting(true);
    try {
      setDetection(await analyzeDetection());
    } catch {
      setDetection(null);
      setDetectionError("Unable to run synthetic anomaly replay.");
    } finally {
      setIsDetecting(false);
    }
  }, []);

  const analyzeNetworkFile = useCallback(async () => {
    if (networkFile === null || networkFileError !== null) {
      return;
    }

    const generation = ++uploadGeneration.current;
    setUploadAnalysis(null);
    setUploadedFilename(null);
    setProtection(null);
    setVerification(null);
    setTamperVerification(null);
    setCryptoError(null);
    setNetworkUploadError(null);
    setIsUploading(true);
    try {
      const result = await analyzeUploadedPcap(networkFile);
      if (generation !== uploadGeneration.current) return;
      setUploadAnalysis(result);
      setUploadedFilename(networkFile.name);
    } catch {
      if (generation === uploadGeneration.current) setNetworkUploadError("Unable to analyze selected PCAP.");
    } finally {
      if (generation === uploadGeneration.current) setIsUploading(false);
    }
  }, [networkFile, networkFileError]);

  const protectAlert = useCallback(async () => {
    if (uploadAnalysis === null) {
      return;
    }
    setCryptoError(null);
    setIsProtecting(true);
    const generation = uploadGeneration.current;
    try {
      const result = await protectFlaggedAlert(uploadAnalysis.analysis_id);
      if (generation !== uploadGeneration.current) return;
      setProtection(result);
      setVerification(null);
      setTamperVerification(null);
    } catch {
      if (generation === uploadGeneration.current) setCryptoError("Unable to protect flagged alerts.");
    } finally {
      if (generation === uploadGeneration.current) setIsProtecting(false);
    }
  }, [uploadAnalysis]);

  const verifyAlert = useCallback(async () => {
    if (protection === null) {
      return;
    }
    setCryptoError(null);
    setIsVerifying(true);
    const generation = uploadGeneration.current;
    try {
      const result = await verifyProtectedAlert(protection.analysis_id);
      if (generation === uploadGeneration.current) setVerification(result);
    } catch {
      if (generation === uploadGeneration.current) setCryptoError("Unable to verify protected alert.");
    } finally {
      if (generation === uploadGeneration.current) setIsVerifying(false);
    }
  }, [protection]);

  const verifyTamper = useCallback(async () => {
    if (protection === null) {
      return;
    }
    setCryptoError(null);
    setIsCheckingTamper(true);
    const generation = uploadGeneration.current;
    try {
      const result = await verifyTamperedCopy(protection.analysis_id);
      if (generation === uploadGeneration.current) setTamperVerification(result);
    } catch {
      if (generation === uploadGeneration.current) setCryptoError("Unable to verify tampered copy.");
    } finally {
      if (generation === uploadGeneration.current) setIsCheckingTamper(false);
    }
  }, [protection]);

  return (
    <DashboardShell view={view} tab={tab} onNavigate={navigate} selectedAnalysis={uploadedFilename}>
      <div className="service-area" hidden={!(view === "overview" && tab === "summary") && !(view === "system" && tab === "services")}>
      <header>
        <div>
          <p className="eyebrow">NEXUS</p>
          <h2>Service status</h2>
        </div>
        <button type="button" onClick={() => void refresh()}>
          Refresh
        </button>
      </header>
      <p className="status-feedback" role="status" aria-live="polite">
        {isChecking
          ? "Checking..."
          : lastChecked === null
            ? ""
            : `Last checked: ${lastChecked}`}
      </p>
      {error === null ? null : (
        <p className="status-error" role="alert">
          {error}
        </p>
      )}
      <section className="service-grid" aria-label="Service status">
        <ServiceCard name="Frontend" status="Healthy" />
        <ServiceCard name="Backend" status={backend} />
        <ServiceCard name="Database" status={database} />
      </section>
      </div>
      {(uploadAnalysis !== null || tab === "recent-analysis") && <div hidden={view !== "overview"}><DashboardSummary upload={uploadAnalysis} ledger={evaluationLedger} tab={tab} /></div>}
      {view === "findings" && tab === "rules" && <SecurityRuleCatalogue />}
      <section className={view === "overview" ? "network-data-picker" : "network-data-picker analysis-only"} aria-labelledby="network-data-heading" hidden={(view !== "overview" && uploadAnalysis === null) || (view === "overview" && tab === "recent-analysis")}>
        <div hidden={view !== "overview" || tab !== "summary"}>
        <h2 id="network-data-heading">Analyze network data</h2>
        <div className="network-data-controls">
          <input
            type="file"
            accept=".pcap"
            aria-label="Choose PCAP file"
            onChange={selectNetworkFile}
          />
          <button
            type="button"
            disabled={
              networkFile === null || networkFileError !== null || isUploading
            }
            onClick={() => void analyzeNetworkFile()}
          >
            {isUploading ? "Analyzing network data..." : "Analyze network data"}
          </button>
        </div>
        {networkFile === null ? null : (
          <p className="network-file-details">
            Selected: {networkFile.name} | {networkFile.size} bytes
          </p>
        )}
        {networkFileError === null ? null : (
          <p className="status-error network-file-error" role="alert">
            {networkFileError}
          </p>
        )}
        {networkUploadError === null ? null : (
          <p className="status-error network-file-error" role="alert">
            {networkUploadError}
          </p>
        )}
        </div>
        {uploadAnalysis === null || uploadedFilename === null ? null : (
          <section
            className="uploaded-network-analysis"
            aria-labelledby="uploaded-network-analysis-heading"
          >
            <div hidden={view !== "overview" || tab !== "summary"}>
            <h3 id="uploaded-network-analysis-heading">
              Uploaded network analysis
            </h3>
            <p className="analysis-summary">{uploadedFilename}</p>
            <p className="analysis-summary">
              {uploadAnalysis.packet_count} packets | {uploadAnalysis.flow_count} flows
            </p>
            </div>
            <AnalysisWorkspace key={uploadAnalysis.analysis_id} upload={uploadAnalysis} ledger={evaluationLedger} onLedger={setEvaluationLedger} view={view} tab={tab} />
            <div hidden={view !== "traffic" || tab !== "flow-explorer"}>
            <label className="filter-control">Filter uploaded flows
              <input aria-label="Filter uploaded flows" type="search" value={flowFilter} onChange={event => setFlowFilter(event.target.value)} placeholder="Protocol, address or port" />
            </label>
            <details className="evidence-details"><summary>Flow metadata ({uploadAnalysis.flows.length} flows)</summary>
            <div className="table-scroll">
              <table id="uploaded-flow-table">
                <thead>
                  <tr>
                    <th scope="col">Protocol</th>
                    <th scope="col">Source</th>
                    <th scope="col">Destination</th>
                    <th scope="col">Packets</th>
                    <th scope="col">Bytes</th>
                    <th scope="col">Duration (s)</th>
                    <th scope="col">Packets/s</th>
                    <th scope="col">Bytes/s</th>
                  </tr>
                </thead>
                <tbody>
                  {uploadAnalysis.flows.filter(flow => [flow.protocol, flow.source_ip, flow.destination_ip, flow.source_port ?? "", flow.destination_port ?? ""].some(value => String(value).toLowerCase().includes(flowFilter.toLowerCase()))).map((flow, index) => (
                    <tr
                      key={`${flow.protocol}-${flow.source_ip}-${flow.destination_ip}-${index}`}
                    >
                      <td>{flow.protocol}</td>
                      <td>{endpoint(flow.source_ip, flow.source_port)}</td>
                      <td>{endpoint(flow.destination_ip, flow.destination_port)}</td>
                      <td>{flow.packet_count}</td>
                      <td>{flow.byte_count}</td>
                      <td>{flow.duration_seconds.toFixed(3)}</td>
                      <td>{flow.packets_per_second.toFixed(3)}</td>
                      <td>{flow.bytes_per_second.toFixed(3)}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
            </details>
            </div>
            <div hidden={view !== "traffic" || tab !== "hosts"}>
            <h4>Host profiles</h4>
            <details className="evidence-details"><summary>Inspect host profile metadata ({uploadAnalysis.host_profiles.length} hosts)</summary>
            <div className="table-scroll">
              <table>
                <thead>
                  <tr>
                    <th scope="col">Host</th>
                    <th scope="col">Flows</th>
                    <th scope="col">Protocols</th>
                    <th scope="col">Avg bytes</th>
                    <th scope="col">Avg duration (s)</th>
                    <th scope="col">Avg packets/s</th>
                  </tr>
                </thead>
                <tbody>
                  {uploadAnalysis.host_profiles.map((profile) => (
                    <tr key={profile.host_ip}>
                      <td>{profile.host_ip}</td>
                      <td>{profile.observed_flow_count}</td>
                      <td>{protocolCounts(profile.protocol_mix)}</td>
                      <td>{profile.average_bytes_per_flow.toFixed(3)}</td>
                      <td>{profile.average_duration_seconds.toFixed(3)}</td>
                      <td>{profile.average_packets_per_second.toFixed(3)}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
            </details>
            </div>
            <div hidden={view !== "traffic" || tab !== "flow-explorer"}>
            <p className="analysis-summary">
              {uploadAnalysis.flagged_alert_count} flagged{" "}
              {uploadAnalysis.flagged_alert_count === 1 ? "alert" : "alerts"}
            </p>
            <div className="table-scroll">
              <table>
                <thead>
                  <tr>
                    <th scope="col">Flow</th>
                    <th scope="col">Anomaly score</th>
                    <th scope="col">Risk level</th>
                    <th scope="col">Explanation</th>
                    <th scope="col">Alert</th>
                  </tr>
                </thead>
                <tbody>
                  {uploadAnalysis.results.map((result, index) => (
                    <tr
                      key={`${result.protocol}-${result.source_ip}-${result.destination_ip}-${index}`}
                      className={result.alert_flagged ? "alert-row" : undefined}
                    >
                      <td>
                        {result.protocol} {endpoint(result.source_ip, result.source_port)} to{" "}
                        {endpoint(result.destination_ip, result.destination_port)}
                      </td>
                      <td>{result.anomaly_score.toFixed(6)}</td>
                      <td>{result.risk_level}</td>
                      <td>{result.explanations.join(" ")}</td>
                      <td className={result.alert_flagged ? "alert-flagged" : undefined}>
                        {result.alert_flagged ? "ALERT FLAGGED" : "Not flagged"}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
            </div>
            {uploadAnalysis.flagged_alert_count < 1 && view === "telemetry" && tab === "flow-alerts-v1" && <p>No flagged flow alerts from this analysis are eligible for v1 protection.</p>}
            {uploadAnalysis.flagged_alert_count < 1 ? null : (
              <section className="secure-telemetry" aria-label="Flow alerts (v1) secure telemetry" hidden={view !== "telemetry" || tab !== "flow-alerts-v1"}>
                <h4>Flow alerts (v1)</h4>
                <p>{protection === null ? "Status unavailable until protected in this browser session." : "Protected in this browser session."} Verification is separate.</p>
                {protection === null ? (
                  <button
                    type="button"
                    disabled={isProtecting}
                    onClick={() => void protectAlert()}
                  >
                    {isProtecting ? "Protecting..." : "Protect all flagged alerts"}
                  </button>
                ) : (
                  <>
                    <p>AES-GCM protected</p>
                    <p>{protection.protected_count} flagged alerts protected</p>
                    <div className="network-data-controls">
                      <button
                        type="button"
                        disabled={isVerifying}
                        onClick={() => void verifyAlert()}
                      >
                        {isVerifying
                          ? "Verifying protected alert..."
                          : "Verify protected alerts"}
                      </button>
                      <button
                        type="button"
                        disabled={isCheckingTamper}
                        onClick={() => void verifyTamper()}
                      >
                        {isCheckingTamper
                          ? "Verifying tampered copy..."
                          : "Verify tampered copy"}
                      </button>
                    </div>
                  </>
                )}
                {verification === null ? null : (
                  <div aria-label="Protected alert verification">
                    <p>
                      {verification.verified_count}/{verification.protected_count} alerts
                      verified
                    </p>
                    <p>All SHA-256 digests verified</p>
                    <p>All RSA signatures valid</p>
                  </div>
                )}
                {tamperVerification === null ? null : (
                  <p>Tampered copy rejected</p>
                )}
                {cryptoError === null ? null : (
                  <p className="status-error" role="alert">
                    {cryptoError}
                  </p>
                )}
              </section>
            )}
          </section>
        )}
      </section>
      {uploadAnalysis === null && view !== "overview" && view !== "system" && <section className="dashboard-panel empty-state"><h2>No analysis selected</h2><p>Open Overview to upload a local PCAP. Analysis and evaluation are offline and manual.</p></section>}
      {view === "system" && tab === "demo-information" && <section className="dashboard-panel" aria-label="Demo information"><h2>Offline demo information</h2><p>REPLAYED DEMO TRAFFIC. Uploaded PCAPs are analyzed locally; this dashboard does not capture or transmit network traffic.</p><p>Baseline and hybrid state are in memory and can be lost on backend restart. Observed graph history and v1 telemetry status are browser-session only.</p><p>Windows host-key isolation: OPEN / NOT VERIFIED. The demo does not establish exclusive host access to keys.</p></section>}
      <details className="advanced-replay-controls" hidden={view !== "system" || tab !== "demo-information"}>
        <summary>Advanced replay controls (optional)</summary>
        <section className="replay-analysis" aria-labelledby="replay-heading">
        <p className="replay-label">REPLAYED DEMO TRAFFIC</p>
        <div className="replay-heading-row">
          <div>
            <h2 id="replay-heading">Offline flow analysis</h2>
            <p>Metadata-only summary from the fixed synthetic fixture.</p>
          </div>
          <button type="button" disabled={isAnalyzing} onClick={() => void analyze()}>
            {isAnalyzing ? "Analyzing..." : "Analyze offline fixture"}
          </button>
        </div>
        {analysisError === null ? null : (
          <p className="status-error" role="alert">
            {analysisError}
          </p>
        )}
        {analysis === null ? null : (
          <>
            <p className="analysis-summary">
              {analysis.packet_count} packets | {analysis.flow_count} flows
            </p>
            <div className="table-scroll">
              <table>
                <thead>
                  <tr>
                    <th scope="col">Protocol</th>
                    <th scope="col">Source</th>
                    <th scope="col">Destination</th>
                    <th scope="col">Packets</th>
                    <th scope="col">Bytes</th>
                    <th scope="col">Duration (s)</th>
                    <th scope="col">Packets/s</th>
                    <th scope="col">Bytes/s</th>
                  </tr>
                </thead>
                <tbody>
                  {analysis.flows.map((flow, index) => (
                    <tr key={`${flow.protocol}-${flow.source_ip}-${flow.destination_ip}-${index}`}>
                      <td>{flow.protocol}</td>
                      <td>{endpoint(flow.source_ip, flow.source_port)}</td>
                      <td>{endpoint(flow.destination_ip, flow.destination_port)}</td>
                      <td>{flow.packet_count}</td>
                      <td>{flow.byte_count}</td>
                      <td>{flow.duration_seconds.toFixed(3)}</td>
                      <td>{flow.packets_per_second.toFixed(3)}</td>
                      <td>{flow.bytes_per_second.toFixed(3)}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </>
        )}
        </section>
        <section className="profile-baseline" aria-labelledby="profile-heading">
        <p className="replay-label">REPLAYED DEMO TRAFFIC</p>
        <p className="baseline-label">NORMAL BASELINE ONLY - NO ANOMALY DECISION</p>
        <div className="replay-heading-row">
          <div>
            <h2 id="profile-heading">Normal host profiles</h2>
            <p>Host-specific summaries from the fixed synthetic normal fixture.</p>
          </div>
          <button
            type="button"
            disabled={isBuildingBaseline}
            onClick={() => void adaptProfiles()}
          >
            {isBuildingBaseline
              ? "Building baseline..."
              : "Build/update normal baseline"}
          </button>
        </div>
        {profileError === null ? null : (
          <p className="status-error" role="alert">
            {profileError}
          </p>
        )}
        {profiles === null ? null : (
          <>
            <p className="analysis-summary">
              {profiles.baseline_state === "warming"
                ? `Warm-up: ${profiles.admitted_batch_count} of ${profiles.warmup_required_batches} batches`
                : `Baseline v${profiles.baseline_version} | ${profiles.admitted_batch_count} admitted batches | ${profiles.window_batch_count} in window`}
            </p>
            <div className="table-scroll">
              <table>
                <thead>
                  <tr>
                    <th scope="col">Host</th>
                    <th scope="col">Current flows</th>
                    <th scope="col">Current protocols</th>
                    <th scope="col">Current avg bytes</th>
                    <th scope="col">Current avg duration (s)</th>
                    <th scope="col">Current avg packets/s</th>
                    <th scope="col">Baseline flows</th>
                    <th scope="col">Baseline protocols</th>
                    <th scope="col">Baseline avg bytes</th>
                    <th scope="col">Baseline avg duration (s)</th>
                    <th scope="col">Baseline avg packets/s</th>
                  </tr>
                </thead>
                <tbody>
                  {profiles.hosts.map((host) => (
                    <tr key={host.host_ip}>
                      <td>{host.host_ip}</td>
                      <td>{host.current_profile.observed_flow_count}</td>
                      <td>{protocolCounts(host.current_profile.protocol_mix)}</td>
                      <td>{host.current_profile.average_bytes_per_flow.toFixed(3)}</td>
                      <td>{host.current_profile.average_duration_seconds.toFixed(3)}</td>
                      <td>{host.current_profile.average_packets_per_second.toFixed(3)}</td>
                      {host.baseline === null ? (
                        <td colSpan={5}>Not ready</td>
                      ) : (
                        <>
                          <td>{host.baseline.average_flow_count.toFixed(3)}</td>
                          <td>{protocolAverages(host.baseline.protocol_mix)}</td>
                          <td>{host.baseline.average_bytes_per_flow.toFixed(3)}</td>
                          <td>{host.baseline.average_duration_seconds.toFixed(3)}</td>
                          <td>{host.baseline.average_packets_per_second.toFixed(3)}</td>
                        </>
                      )}
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
            <p className="baseline-limitation">
              Repeated requests replay identical normal data, so unchanged values are not
              evidence of real-world adaptive learning.
            </p>
          </>
        )}
        </section>
        <section className="anomaly-detection" aria-labelledby="detection-heading">
        <p className="replay-label">REPLAYED DEMO TRAFFIC</p>
        <p className="detection-label">
          SYNTHETIC ANOMALY DEMO - STATISTICAL UNUSUALNESS, NOT MALICIOUS PROOF
        </p>
        <div className="replay-heading-row">
          <div>
            <h2 id="detection-heading">Synthetic anomaly replay</h2>
            <p>Deterministic metadata-only scoring of the fixed unusual fixture.</p>
          </div>
          <button type="button" disabled={isDetecting} onClick={() => void detect()}>
            {isDetecting ? "Detecting..." : "Run anomaly replay"}
          </button>
        </div>
        {detectionError === null ? null : (
          <p className="status-error" role="alert">
            {detectionError}
          </p>
        )}
        {detection === null ? null : (
          <>
            <p className="analysis-summary">
              IsolationForest | model {detection.model.model_version} | seed{" "}
              {detection.model.random_seed} | {detection.model.training_flow_count}{" "}
              training flows
            </p>
            <p className="analysis-summary">
              {detection.replay_flow_count} scored flows |{" "}
              {detection.flagged_alert_count} flagged{" "}
              {detection.flagged_alert_count === 1 ? "alert" : "alerts"}
            </p>
            <div className="table-scroll">
              <table>
                <thead>
                  <tr>
                    <th scope="col">Flow</th>
                    <th scope="col">Score</th>
                    <th scope="col">Threshold</th>
                    <th scope="col">Unusual</th>
                    <th scope="col">Risk score</th>
                    <th scope="col">Risk level</th>
                    <th scope="col">Explanation</th>
                    <th scope="col">Alert</th>
                  </tr>
                </thead>
                <tbody>
                  {detection.results.map((result, index) => (
                    <tr
                      key={`${result.protocol}-${result.source_ip}-${result.destination_ip}-${index}`}
                      className={result.alert_flagged ? "alert-row" : undefined}
                    >
                      <td>
                        {result.protocol} {endpoint(result.source_ip, result.source_port)} to{" "}
                        {endpoint(result.destination_ip, result.destination_port)}
                      </td>
                      <td>{result.anomaly_score.toFixed(6)}</td>
                      <td>{detection.model.model_threshold.toFixed(6)}</td>
                      <td>{result.is_statistically_unusual ? "Yes" : "No"}</td>
                      <td>{result.risk_score}</td>
                      <td>{result.risk_level}</td>
                      <td>{result.explanations.join(" ")}</td>
                      <td className={result.alert_flagged ? "alert-flagged" : undefined}>
                        {result.alert_flagged ? "ALERT FLAGGED" : "Not flagged"}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
            <p className="detection-limitation">
              Statistical unusualness in synthetic replay data is not proof of malicious
              activity.
            </p>
          </>
        )}
        </section>
      </details>
    </DashboardShell>
  );
}
