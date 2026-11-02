import {act} from "react";
import {createRoot} from "react-dom/client";
import {afterEach, expect, test, vi} from "vitest";
import {DashboardShell} from "./components/DashboardShell";
Object.assign(globalThis, {IS_REACT_ACT_ENVIRONMENT: true});
let root: ReturnType<typeof createRoot>;
let container: HTMLDivElement;
afterEach(async () => {if (root) await act(async () => root.unmount()); container?.remove();});
test("sidebar and tabs navigate while preserving mounted main content", async () => {
  container = document.createElement("div"); document.body.append(container); root = createRoot(container);
  const navigate = vi.fn();
  await act(async () => root.render(<DashboardShell view="overview" tab="summary" onNavigate={navigate} selectedAnalysis="demo.pcap"><span id="persistent">Persistent analysis</span></DashboardShell>));
  expect(container.querySelectorAll("main")).toHaveLength(1);
  expect(container.querySelector('[aria-current="page"]')?.textContent).toContain("Overview");
  expect(container.querySelector('[role="tab"][aria-selected="true"]')?.textContent).toContain("Summary");
  expect(container.querySelector(".page-heading")?.textContent).toBe("Overview");
  expect(container.querySelector(".sidebar-footnote")).toBeNull();
  expect(container.querySelector(".offline-badge")).toBeNull();
  await act(async () => container.querySelector<HTMLButtonElement>('[aria-label="Adaptive Baseline"]')!.click());
  expect(navigate).toHaveBeenCalledWith("baseline", "evolution");
  expect(container.querySelector("#persistent")).not.toBeNull();
});
test("mobile menu closes after navigation", async () => {
  container = document.createElement("div"); document.body.append(container); root = createRoot(container);
  const navigate = vi.fn();
  await act(async () => root.render(<DashboardShell view="overview" tab="summary" onNavigate={navigate} selectedAnalysis={null}><p>Content</p></DashboardShell>));
  const menu = container.querySelector<HTMLButtonElement>('button[aria-controls="dashboard-sidebar"]')!;
  expect(menu.getAttribute("aria-expanded")).toBe("false");
  await act(async () => menu.click());
  expect(menu.getAttribute("aria-expanded")).toBe("true");
  await act(async () => container.querySelector<HTMLButtonElement>('[aria-label="Traffic Analysis"]')!.click());
  expect(menu.getAttribute("aria-expanded")).toBe("false");
  expect(navigate).toHaveBeenCalledWith("traffic", "protocols");
});
test("tabs support arrow-key navigation and link to one active tab panel", async () => {
  container=document.createElement("div"); document.body.append(container); root=createRoot(container);
  const navigate=vi.fn();
  await act(async () => root.render(<DashboardShell view="overview" tab="summary" onNavigate={navigate} selectedAnalysis={null}><p>Summary content</p></DashboardShell>));
  const selected=container.querySelector<HTMLButtonElement>('[role="tab"][aria-selected="true"]')!;
  expect(selected.getAttribute("aria-controls")).toBe("dashboard-tabpanel");
  expect(container.querySelector('[role="tabpanel"]')?.getAttribute("aria-labelledby")).toBe(selected.id);
  await act(async () => selected.dispatchEvent(new KeyboardEvent("keydown",{key:"ArrowRight",bubbles:true})));
  expect(navigate).toHaveBeenCalledWith("overview","recent-analysis");
});

test("non-Overview views retain replay and offline context", async () => {
  container=document.createElement("div"); document.body.append(container); root=createRoot(container);
  await act(async () => root.render(<DashboardShell view="traffic" tab="protocols" onNavigate={vi.fn()} selectedAnalysis={null}><p>Content</p></DashboardShell>));
  expect(container.querySelector(".page-heading")?.textContent).toContain("REPLAYED DEMO TRAFFIC");
  expect(container.querySelector(".sidebar-footnote")?.textContent).toContain("Offline PCAP analysis");
});
