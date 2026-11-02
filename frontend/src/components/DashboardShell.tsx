import {useRef, useState, type ReactNode} from "react";

export type DashboardView = "overview" | "traffic" | "baseline" | "findings" | "telemetry" | "system";
export const dashboardTabs: Record<DashboardView, readonly [string, string] | readonly [string, string, string] | readonly [string, string, string, string]> = {
  overview: ["Summary", "Recent Analysis"],
  traffic: ["Protocols", "Flow Explorer", "Hosts"],
  baseline: ["Evolution", "Decision History", "Feature Comparison"],
  findings: ["All", "ML", "Baseline", "Rules"],
  telemetry: ["Flow Alerts v1", "Unified Findings v2"],
  system: ["Services", "Demo Information"],
};
export const dashboardLabels: Record<DashboardView, string> = {
  overview: "Overview", traffic: "Traffic Analysis", baseline: "Adaptive Baseline",
  findings: "Security Findings", telemetry: "Secure Telemetry", system: "System Status",
};
export const defaultTab = (view: DashboardView) => dashboardTabs[view][0].toLowerCase().replaceAll(" ", "-");

export function DashboardShell({view, tab, onNavigate, selectedAnalysis, children}: {
  view: DashboardView; tab: string; onNavigate: (view: DashboardView, tab: string) => void;
  selectedAnalysis: string | null; children: ReactNode;
}) {
  const [menuOpen, setMenuOpen] = useState(false);
  const menuToggle = useRef<HTMLButtonElement>(null);
  const go = (next: DashboardView, nextTab: string) => {onNavigate(next, nextTab); if (menuOpen) queueMicrotask(() => menuToggle.current?.focus()); setMenuOpen(false);};
  const onTabKey = (event: React.KeyboardEvent<HTMLButtonElement>, index: number) => {
    const labels = dashboardTabs[view];
    const nextIndex = event.key === "ArrowRight" ? (index + 1) % labels.length : event.key === "ArrowLeft" ? (index + labels.length - 1) % labels.length : event.key === "Home" ? 0 : event.key === "End" ? labels.length - 1 : -1;
    if (nextIndex < 0) return;
    event.preventDefault();
    const nextKey = labels[nextIndex].toLowerCase().replaceAll(" ", "-");
    go(view, nextKey);
    const buttons = event.currentTarget.parentElement?.querySelectorAll<HTMLButtonElement>('[role="tab"]');
    buttons?.[nextIndex]?.focus();
  };
  return <div className="dashboard-shell">
    <a className="skip-link" href="#dashboard-main">Skip to main content</a>
    <aside id="dashboard-sidebar" className={menuOpen ? "dashboard-sidebar is-open" : "dashboard-sidebar"} aria-label="Primary navigation">
      <div className="sidebar-brand"><span className="brand-mark" aria-hidden="true">◆</span><span>NEXUS</span></div>
      <nav aria-label="Dashboard views">{(Object.keys(dashboardLabels) as DashboardView[]).map(next =>
        <button type="button" key={next} aria-label={dashboardLabels[next]} aria-current={view === next ? "page" : undefined}
          onClick={() => go(next, defaultTab(next))}>{dashboardLabels[next]}</button>)}</nav>
      {view !== "overview" && <p className="sidebar-footnote">REPLAYED DEMO TRAFFIC<br />Offline PCAP analysis</p>}
    </aside>
    <div className="dashboard-frame">
      <div className="dashboard-topbar">
        <button ref={menuToggle} className="mobile-menu-toggle" type="button" aria-controls="dashboard-sidebar" aria-expanded={menuOpen} onClick={() => setMenuOpen(open => !open)}>{menuOpen ? "Close menu" : "Menu"}</button>
        <div><strong>{dashboardLabels[view]}</strong><span className="topbar-context">{selectedAnalysis ? `Selected analysis: ${selectedAnalysis}` : "No analysis selected"}</span></div>
        {view !== "overview" && <span className="offline-badge">Offline PCAP demo</span>}
      </div>
      <main id="dashboard-main" className="dashboard-main">
        <div className="page-heading"><div>{view !== "overview" && <p className="eyebrow">REPLAYED DEMO TRAFFIC</p>}<h1>{dashboardLabels[view]}</h1></div>{view !== "overview" && <p>Offline PCAP analysis only. No live capture or packet transmission.</p>}</div>
        <div className="dashboard-tabs" role="tablist" aria-label={`${dashboardLabels[view]} sections`}>
          {dashboardTabs[view].map((label,index) => {const key = label.toLowerCase().replaceAll(" ", "-"); return <button type="button" role="tab" key={key} id={`dashboard-tab-${view}-${key}`} aria-controls="dashboard-tabpanel" aria-selected={tab === key} tabIndex={tab === key ? 0 : -1} onKeyDown={event => onTabKey(event,index)} onClick={() => go(view, key)}>{label}</button>;})}
        </div>
        <div id="dashboard-tabpanel" role="tabpanel" aria-labelledby={`dashboard-tab-${view}-${tab}`} tabIndex={0}>{children}</div>
      </main>
    </div>
  </div>;
}
