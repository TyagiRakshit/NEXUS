import {act} from "react";
import {createRoot} from "react-dom/client";
import {afterEach, expect, test} from "vitest";
import {DashboardSummary} from "./components/DashboardSummary";
import type {UploadAnalysisResponse} from "./status";
Object.assign(globalThis, {IS_REACT_ACT_ENVIRONMENT: true});
let root: ReturnType<typeof createRoot>;
let container: HTMLDivElement;
afterEach(async () => {if (root) await act(async () => root.unmount()); container?.remove();});
const upload = {analysis_id:"abc", packet_count:16, flow_count:3, flagged_alert_count:1, host_profiles:[{host_ip:"192.0.2.10"}], flows:[{protocol:"TCP"},{protocol:"UDP"},{protocol:"ICMP"}]} as UploadAnalysisResponse;
test("summary uses actual upload counts and recent analysis is session-only", async () => {
  container=document.createElement("div"); document.body.append(container); root=createRoot(container);
  await act(async () => root.render(<DashboardSummary upload={upload} ledger={[]} tab="summary" />));
  expect(container.textContent).toContain("16");
  expect(container.textContent).toContain("3");
  expect(container.textContent).toContain("1");
  expect(container.querySelectorAll(".protocol-track")).toHaveLength(3);
  await act(async () => root.render(<DashboardSummary upload={upload} ledger={[]} tab="recent-analysis" />));
  expect(container.textContent).toContain("Current browser session");
  expect(container.textContent).toContain("abc");
  expect(container.querySelector("button")).toBeNull();
});

test("empty Overview summary renders no card or placeholder", async () => {
  container=document.createElement("div"); document.body.append(container); root=createRoot(container);
  await act(async () => root.render(<DashboardSummary upload={null} ledger={[]} tab="summary" />));
  expect(container.querySelector(".dashboard-panel")).toBeNull();
  expect(container.textContent).not.toContain("Analysis summary");
});
