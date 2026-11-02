import {useEffect, useRef, useState} from "react";
import type {UploadAnalysisResponse} from "../status";
import {getHybridTelemetryStatus, protectHybrid, verifyHybrid, verifyHybridTamperedCopy, VisualizationApiError} from "../visualizationApi";
import type {HybridEvaluateResponse, HybridProtect, HybridTelemetryStatus, HybridVerify, HybridTamper} from "../visualizationApi";

export function TelemetryPanel({upload, hybrid}: {upload: UploadAnalysisResponse; hybrid: HybridEvaluateResponse | null}) {
  const [status, setStatus] = useState<HybridTelemetryStatus | null>(null);
  const [protection, setProtection] = useState<HybridProtect | null>(null);
  const [verification, setVerification] = useState<HybridVerify | null>(null);
  const [tamper, setTamper] = useState<HybridTamper | null>(null);
  const [pending, setPending] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const busy = useRef(false);
  useEffect(() => {
    if (!hybrid) return;
    const controller = new AbortController();
    void getHybridTelemetryStatus(upload.analysis_id, controller.signal).then(value => {if (!controller.signal.aborted) setStatus(value);}).catch(e => {if (!controller.signal.aborted) setError(e instanceof VisualizationApiError ? `V2 status unavailable (${e.code}).` : "V2 status unavailable.");});
    return () => controller.abort();
  }, [hybrid, upload.analysis_id]);
  async function run(action: "protect" | "verify" | "tamper") {
    if (busy.current || !hybrid || hybrid.telemetry.eligible_count < 1) return;
    busy.current = true; setPending(true); setError(null);
    try {
      if (action === "protect") {const value = await protectHybrid(upload.analysis_id); setProtection(value); setStatus({schema_version: "phase7.secure-telemetry.v2", analysis_id: upload.analysis_id, status: "protected", protected_count: value.protected_count}); setVerification(null); setTamper(null);}
      if (action === "verify") setVerification(await verifyHybrid(upload.analysis_id));
      if (action === "tamper") setTamper(await verifyHybridTamperedCopy(upload.analysis_id));
    } catch (e) {setError(e instanceof VisualizationApiError ? `V2 ${action} failed (${e.code}).` : `V2 ${action} failed.`);}
    finally {busy.current = false; setPending(false);}
  }
  const protectedNow = protection !== null || status?.status === "protected";
  return <section className="dashboard-panel" aria-labelledby="telemetry-v2-heading"><h3 id="telemetry-v2-heading">Unified High findings (v2)</h3>
    <p>Manual protection of distinct eligible High findings. Protected and Verified are separate states. Flow alerts (v1) use their own tab.</p>
    {hybrid === null ? <p>Hybrid evaluation required before v2 protection.</p> : <>
      <p>{hybrid.telemetry.eligible_count} eligible High findings · status {status?.status ?? "Status unavailable"}</p>
      {hybrid.telemetry.eligible_count === 0 ? <p>No eligible v2 finding.</p> : <div className="network-data-controls">
        {!protectedNow && <button type="button" disabled={pending || status?.status === "preparing"} onClick={() => void run("protect")}>Protect unified findings (v2)</button>}
        {protectedNow && <><p>{status?.protected_count ?? protection?.protected_count} High findings Protected</p><button type="button" disabled={pending} onClick={() => void run("verify")}>Verify unified findings (v2)</button><button type="button" disabled={pending} onClick={() => void run("tamper")}>Verify tampered v2 copy</button></>}
      </div>}
      {verification && <p>{verification.verified_count}/{verification.protected_count} High findings Verified · AES-GCM authenticated · SHA-256 verified · RSA-PSS valid</p>}
      {tamper && <p>Tampered v2 copy rejected</p>}
      {error && <p className="status-error" role="alert">{error}</p>}
      <p role="status" aria-live="polite">{pending ? "V2 telemetry request in progress..." : ""}</p>
    </>}
  </section>;
}
