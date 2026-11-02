import {useState} from "react";
import type {UploadAnalysisResponse} from "../status";
import type {buildFlowScoreRows} from "../visualizationModels";

type ScoreRow = ReturnType<typeof buildFlowScoreRows>[number];
type ProtocolFilter = "All" | "TCP" | "UDP" | "ICMP" | "Other";
type RiskFilter = "All" | "High" | "Low" | "Medium";
const plotTop = 30;
const plotBottom = 220;
const plotLeft = 105;
const plotRight = 32;
const plotHeight = plotBottom - plotTop;
const chartHeight = 280;

function protocolGroup(protocol: string): ProtocolFilter {
  const upper = protocol.toUpperCase();
  return upper === "TCP" || upper === "UDP" || upper === "ICMP" ? upper : "Other";
}

function endpoint(ip: string, port: number | null): string {
  return port === null ? ip : `${ip}:${port}`;
}

export function FlowScoreChart({upload, scores}: {upload: UploadAnalysisResponse; scores: ScoreRow[]}) {
  const [protocol, setProtocol] = useState<ProtocolFilter>("All");
  const [risk, setRisk] = useState<RiskFilter>("All");
  const [selectedIndex, setSelectedIndex] = useState<number | null>(null);
  const threshold = upload.model.model_threshold;
  const visible = scores.filter(row => {
    const flow = upload.results[row.index];
    return (protocol === "All" || protocolGroup(flow.protocol) === protocol)
      && (risk === "All" || row.risk === risk);
  });
  const selected = visible.find(row => row.index === selectedIndex) ?? null;
  const flagged = scores.filter(row => row.flagged).length;
  const highest = scores.length ? Math.max(...scores.map(row => row.score)) : null;
  const availableProtocols = (["TCP", "UDP", "ICMP", "Other"] as const)
    .filter(value => upload.results.some(flow => protocolGroup(flow.protocol) === value));
  const availableRisks = (["High", "Low", "Medium"] as const)
    .filter(value => scores.some(row => row.risk === value));

  // Keep the full original index domain while filtering, so a point never changes identity.
  const plotWidth = Math.max(840, plotLeft + plotRight + Math.max(1, scores.length - 1) * 18);
  const innerWidth = plotWidth - plotLeft - plotRight;
  const x = (index: number) => plotLeft + (scores.length < 2 ? innerWidth / 2 : index / (scores.length - 1) * innerWidth);
  const values = [threshold, ...visible.map(row => row.score)];
  const low = Math.min(...values), high = Math.max(...values);
  const padding = Math.max((high - low) * 0.12, 0.01);
  const yMin = low - padding, yMax = high + padding;
  const y = (score: number) => plotBottom - (score - yMin) / (yMax - yMin) * plotHeight;
  const ticks = Array.from({length: 5}, (_, index) => yMin + index * (yMax - yMin) / 4);
  const precision = (yMax - yMin) / 4 < 0.001 ? 6 : 3;
  const xTickCount = Math.min(6, scores.length);
  const xTicks = [...new Set(Array.from({length: xTickCount}, (_, index) =>
    Math.round(index * (scores.length - 1) / Math.max(1, xTickCount - 1))
  ))];

  return <>
    <div className="kpi-grid score-kpi-grid" aria-label="Flow anomaly summary">
      <div className="kpi-card"><span>Total flows</span><strong>{scores.length}</strong></div>
      <div className="kpi-card"><span>Flagged flows</span><strong>{flagged}</strong></div>
      <div className="kpi-card"><span>Non-flagged flows</span><strong>{scores.length - flagged}</strong></div>
      <div className="kpi-card"><span>Highest anomaly score</span><strong>{highest === null ? "Unavailable" : highest.toFixed(6)}</strong></div>
      <div className="kpi-card"><span>Model threshold</span><strong>{threshold.toFixed(6)}</strong></div>
    </div>
    <p className="score-count">{flagged} of {scores.length} flows flagged. A low or unflagged score does not establish that traffic is safe.</p>
    <div className="score-controls">
      <label>Protocol <select aria-label="Protocol filter" value={protocol} onChange={event => setProtocol(event.target.value as ProtocolFilter)}>
        <option value="All">All</option>
        {availableProtocols.map(value => <option key={value} value={value}>{value}</option>)}
      </select></label>
      <label>Risk <select aria-label="Risk filter" value={risk} onChange={event => setRisk(event.target.value as RiskFilter)}>
        <option value="All">All</option>
        {availableRisks.map(value => <option key={value} value={value}>{value}</option>)}
      </select></label>
      <label>Inspect flow <select aria-label="Inspect flow" value={selected?.index ?? ""} onChange={event => setSelectedIndex(event.target.value === "" ? null : Number(event.target.value))}>
        <option value="">Select a visible flow</option>
        {visible.map(row => <option key={row.index} value={row.index}>Flow {row.index + 1}</option>)}
      </select></label>
    </div>
    {scores.length === 0 ? <p role="status">No flows available in this analysis.</p> : <>
      {visible.length === 0 && <p role="status">No flows match the selected filters.</p>}
      <div className="chart-scroll score-chart-scroll" role="group" aria-label="Isolation Forest score chart; scroll horizontally for more flows">
        <svg viewBox={`0 0 ${plotWidth} ${chartHeight}`} style={{minWidth: plotWidth}} role="group" aria-label="Original flow anomaly scores with numerical axes and backend anomaly threshold">
          <title>Isolation Forest anomaly scores</title>
          {ticks.map((tick, index) => <g key={index}>
            <line x1={plotLeft} x2={plotWidth - plotRight} y1={y(tick)} y2={y(tick)} stroke="#29434b" strokeWidth="1" />
            <text x={plotLeft - 10} y={y(tick) + 4} textAnchor="end" fontSize="11" fill="#a9c0c5">{tick.toFixed(precision)}</text>
          </g>)}
          <line x1={plotLeft} x2={plotLeft} y1={plotTop} y2={plotBottom} stroke="#a9c0c5" />
          <line x1={plotLeft} x2={plotWidth - plotRight} y1={plotBottom} y2={plotBottom} stroke="#a9c0c5" />
          {xTicks.map(index => <g key={index}>
            <line x1={x(index)} x2={x(index)} y1={plotBottom} y2={plotBottom + 5} stroke="#a9c0c5" />
            <text x={x(index)} y={plotBottom + 19} textAnchor="middle" fontSize="11" fill="#a9c0c5">{index + 1}</text>
          </g>)}
          <line x1={plotLeft} x2={plotWidth - plotRight} y1={y(threshold)} y2={y(threshold)} stroke="#f6b65f" strokeWidth="2" strokeDasharray="6 5" data-testid="anomaly-threshold" />
          <text x={plotWidth - plotRight - 4} y={Math.max(plotTop + 13, y(threshold) - 7)} textAnchor="end" fontSize="11" fill="#f9d7a3">Anomaly threshold {threshold.toFixed(6)}</text>
          {visible.map(row => <circle key={row.index} data-flow-index={row.index + 1} data-flagged={row.flagged} role="button" tabIndex={0}
            aria-label={`Select flow ${row.index + 1}, ${row.flagged ? "flagged" : "not flagged"}, anomaly score ${row.score.toFixed(6)}, risk ${row.risk}`}
            cx={x(row.index)} cy={y(row.score)} r={row.flagged ? 6 : 4}
            fill={row.flagged ? "#ff8f83" : "#42d5c5"} stroke={row.flagged ? "#fff0e6" : "#0b2028"} strokeWidth={row.flagged ? 2 : 1}
            onClick={() => setSelectedIndex(row.index)}
            onKeyDown={event => {if (event.key === "Enter" || event.key === " ") {event.preventDefault(); setSelectedIndex(row.index);}}}>
            <title>{`Flow ${row.index + 1}: score ${row.score.toFixed(6)}, threshold ${threshold.toFixed(6)}, risk ${row.risk}`}</title>
          </circle>)}
          <text x={plotLeft + innerWidth / 2} y={chartHeight - 9} textAnchor="middle" fontSize="12" fill="#e8f4f5">Flow index</text>
          <text transform={`translate(18 ${plotTop + plotHeight / 2}) rotate(-90)`} textAnchor="middle" fontSize="12" fill="#e8f4f5">Isolation Forest anomaly score</text>
        </svg>
      </div>
    </>}
    <div className="chart-legend score-legend" aria-label="Score chart legend">
      <span className="score-legend-normal">Non-flagged · smaller teal point</span>
      <span className="score-legend-flagged">Flagged · larger outlined coral point</span>
      <span className="score-legend-threshold">Dashed line · Anomaly threshold</span>
    </div>
    {selected && <div className="score-detail" role="region" aria-label={`Flow ${selected.index + 1} details`}>
      <h4>Flow {selected.index + 1} details</h4>
      <dl>
        <div><dt>Flow index</dt><dd>{selected.index + 1}</dd></div>
        <div><dt>Source</dt><dd>{endpoint(upload.results[selected.index].source_ip, upload.results[selected.index].source_port)}</dd></div>
        <div><dt>Destination</dt><dd>{endpoint(upload.results[selected.index].destination_ip, upload.results[selected.index].destination_port)}</dd></div>
        <div><dt>Protocol</dt><dd>{upload.results[selected.index].protocol}</dd></div>
        <div><dt>Anomaly score</dt><dd>{selected.score.toFixed(6)}</dd></div>
        <div><dt>Threshold</dt><dd>{threshold.toFixed(6)}</dd></div>
        <div><dt>Risk level</dt><dd>{selected.risk}</dd></div>
        <div><dt>Flagged</dt><dd>{selected.flagged ? "Yes" : "No"}</dd></div>
      </dl>
      <p><strong>Backend explanation:</strong> {upload.results[selected.index].explanations.length ? upload.results[selected.index].explanations.join(" ") : "Unavailable from backend."}</p>
    </div>}
  </>;
}
