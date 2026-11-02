import {renderToStaticMarkup} from "react-dom/server";
import {expect, test} from "vitest";
import {FlowOverview} from "./FlowOverview";
import type {UploadAnalysisResponse} from "../status";
const upload = {analysis_id:"a",flows:[{protocol:"TCP"}],results:[{protocol:"TCP",source_ip:"192.0.2.10",destination_ip:"198.51.100.20",anomaly_score:0.7,risk_level:"High",alert_flagged:true,explanations:["Unusual flow"]}],model:{model_threshold:0.6}} as UploadAnalysisResponse;
test("protocol and score tabs retain original values but show focused charts", () => {
  const protocol = renderToStaticMarkup(<FlowOverview upload={upload} hybrid={null} section="protocols" />);
  expect(protocol).toContain("TCP");
  expect(protocol).not.toContain("Original anomaly scores");
  const scores = renderToStaticMarkup(<FlowOverview upload={upload} hybrid={null} section="scores" />);
  expect(scores).toContain("0.700000");
  expect(scores).toContain("0.600000");
  expect(scores).not.toContain("Uploaded flow count by protocol");
});
import {act} from "react";
import {createRoot} from "react-dom/client";

function sample(scores: Array<{score: number; protocol: string; risk: "Low" | "Medium" | "High"; flagged: boolean}>): UploadAnalysisResponse {
  const results = scores.map((entry, index) => ({
    protocol: entry.protocol, source_ip: "192.0.2.10", source_port: index + 1000,
    destination_ip: "198.51.100.20", destination_port: null,
    packet_count: 2, byte_count: 128, duration_seconds: 1,
    packets_per_second: 2, bytes_per_second: 128,
    anomaly_score: entry.score, is_statistically_unusual: entry.flagged,
    risk_score: entry.risk === "High" ? 90 as const : entry.risk === "Medium" ? 60 as const : 20 as const,
    risk_level: entry.risk, alert_flagged: entry.flagged,
    explanations: [`Backend explanation ${index + 1}`],
  }));
  return {
    schema_version: "demo.upload-analysis.v1",
    source: "REPLAYED DEMO TRAFFIC",
    interpretation: "STATISTICAL UNUSUALNESS RELATIVE TO SYNTHETIC TRAINING, NOT MALICIOUS PROOF",
    analysis_id: "a", analyzed_at: "2026-11-02T00:00:00Z",
    packet_count: results.length * 2, flow_count: results.length,
    flows: results, host_profiles: [],
    model: {model_type: "IsolationForest", model_version: "phase4-iforest-v1", random_seed: 42, training_flow_count: 48, feature_count: 11, n_estimators: 100, max_samples: 32, model_threshold: 0.63},
    flagged_alert_count: results.filter(r => r.alert_flagged).length,
    results,
  };
}

test("score chart shows numerical axes, backend threshold, and actual summary counts", () => {
  const html = renderToStaticMarkup(<FlowOverview upload={sample([
    {score: 0.5, protocol: "TCP", risk: "Low", flagged: false},
    {score: 0.7, protocol: "UDP", risk: "High", flagged: true},
  ])} hybrid={null} section="scores" />);
  expect(html).toContain("Flow index");
  expect(html).toContain("Isolation Forest anomaly score");
  expect(html).toContain("Anomaly threshold");
  expect(html).toContain("0.630000");
  expect(html).toContain("Total flows");
  expect(html).toContain("Flagged flows");
  expect(html).toContain("Non-flagged flows");
  expect(html).toContain("Highest anomaly score");
  expect(html).toContain("1 of 2 flows flagged");
  expect(html).toContain('data-flow-index="1"');
  expect(html).toContain('data-flow-index="2"');
  expect(html).toContain('stroke-dasharray=');
});

test("empty and zero-alert datasets do not fabricate chart points or safety claims", () => {
  const empty = renderToStaticMarkup(<FlowOverview upload={sample([])} hybrid={null} section="scores" />);
  expect(empty).toContain("No flows available");
  expect(empty).not.toContain('data-flow-index=');
  expect(empty).toContain("Unavailable");
  const noAlerts = renderToStaticMarkup(<FlowOverview upload={sample([
    {score: 0.5, protocol: "TCP", risk: "Low", flagged: false},
  ])} hybrid={null} section="scores" />);
  expect(noAlerts).toContain("0 of 1 flows flagged");
  expect(noAlerts).not.toContain("safe traffic");
});

test("identical scores remain separate points and large flow sets retain original indices", () => {
  const rows = Array.from({length: 120}, (_, index) => ({score: 0.5, protocol: index % 2 ? "UDP" : "TCP", risk: "Low" as const, flagged: false}));
  const html = renderToStaticMarkup(<FlowOverview upload={sample(rows)} hybrid={null} section="scores" />);
  expect(html).toContain('data-flow-index="1"');
  expect(html).toContain('data-flow-index="120"');
  expect((html.match(/data-flow-index=/g) ?? []).length).toBe(120);
  expect(html).toContain("min-width");
});

test("protocol and risk filters preserve flow identity; point and selector expose backend details", async () => {
  Object.assign(globalThis, {IS_REACT_ACT_ENVIRONMENT: true});
  const container = document.createElement("div"); document.body.append(container);
  const root = createRoot(container);
  const upload = sample([
    {score: 0.5, protocol: "TCP", risk: "Low", flagged: false},
    {score: 0.71, protocol: "UDP", risk: "High", flagged: true},
    {score: 0.71, protocol: "ICMP", risk: "High", flagged: true},
  ]);
  try {
    await act(async () => root.render(<FlowOverview upload={upload} hybrid={null} section="scores" />));
    const protocol = container.querySelector<HTMLSelectElement>('select[aria-label="Protocol filter"]')!;
    const risk = container.querySelector<HTMLSelectElement>('select[aria-label="Risk filter"]')!;
    expect(protocol).not.toBeNull();
    expect(risk).not.toBeNull();
    await act(async () => {protocol.value = "UDP"; protocol.dispatchEvent(new Event("change", {bubbles: true}));});
    expect([...container.querySelectorAll("[data-flow-index]")].map(p => p.getAttribute("data-flow-index"))).toEqual(["2"]);
    await act(async () => {risk.value = "Low"; risk.dispatchEvent(new Event("change", {bubbles: true}));});
    expect(container.querySelectorAll("[data-flow-index]")).toHaveLength(0);
    await act(async () => {risk.value = "All"; risk.dispatchEvent(new Event("change", {bubbles: true}));});
    const point = container.querySelector<SVGCircleElement>('[data-flow-index="2"]')!;
    point.focus();
    await act(async () => point.dispatchEvent(new KeyboardEvent("keydown", {key: "Enter", bubbles: true})));
    expect(container.textContent).toContain("Backend explanation 2");
    expect(container.textContent).toContain("192.0.2.10:1001");
    expect(container.textContent).toContain("198.51.100.20");
    expect(container.textContent).toContain("0.710000");
    const selector = container.querySelector<HTMLSelectElement>('select[aria-label="Inspect flow"]')!;
    expect(selector.value).toBe("1");
    expect(upload.results[1].anomaly_score).toBe(0.71);
  } finally {
    await act(async () => root.unmount()); container.remove();
  }
});

test("equal scores remain distinct, and threshold-boundary flags follow backend results", () => {
  const boundary = sample([
    {score: 0.63, protocol: "TCP", risk: "Low", flagged: false},
    {score: 0.63, protocol: "UDP", risk: "High", flagged: true},
  ]);
  const node = document.createElement("div");
  node.innerHTML = renderToStaticMarkup(<FlowOverview upload={boundary} hybrid={null} section="scores" />);
  const points = [...node.querySelectorAll<SVGCircleElement>("[data-flow-index]")];
  expect(points).toHaveLength(2);
  expect(points[0].getAttribute("cy")).toBe(points[1].getAttribute("cy"));
  expect(points[0].getAttribute("cx")).not.toBe(points[1].getAttribute("cx"));
  expect(points.map(point => point.getAttribute("data-flagged"))).toEqual(["false", "true"]);
  expect(node.querySelector("[data-testid=anomaly-threshold]")?.getAttribute("y1")).toBe(points[0].getAttribute("cy"));
});

test("all-flagged and missing-port flows retain backend values in the detail panel", async () => {
  Object.assign(globalThis, {IS_REACT_ACT_ENVIRONMENT: true});
  const container = document.createElement("div"); document.body.append(container);
  const root = createRoot(container);
  const upload = sample([{score: 0.8, protocol: "OTHER", risk: "High", flagged: true}]);
  upload.results[0].source_port = null;
  upload.results[0].destination_port = null;
  upload.results[0].explanations = [];
  try {
    await act(async () => root.render(<FlowOverview upload={upload} hybrid={null} section="scores" />));
    expect(container.textContent).toContain("1 of 1 flows flagged");
    const point = container.querySelector<SVGCircleElement>("[data-flow-index='1']")!;
    await act(async () => point.dispatchEvent(new MouseEvent("click", {bubbles: true})));
    const detail = container.querySelector('[aria-label="Flow 1 details"]')!;
    expect(detail.textContent).toContain("192.0.2.10");
    expect(detail.textContent).toContain("198.51.100.20");
    expect(detail.textContent).toContain("Unavailable from backend.");
    expect(detail.textContent).not.toContain(":0");
    expect([...container.querySelectorAll<HTMLSelectElement>('select[aria-label="Protocol filter"] option')].map(option => option.value)).toContain("Other");
  } finally {
    await act(async () => root.unmount()); container.remove();
  }
});
