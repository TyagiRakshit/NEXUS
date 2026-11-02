import {renderToStaticMarkup} from "react-dom/server";
import {expect, test} from "vitest";
import {BaselineEvolution} from "./BaselineEvolution";
import type {EvolutionRow} from "../visualizationModels";
const rows: EvolutionRow[] = [{observationId:"obs-1",windowStart:"2026-11-01T00:00:00Z",decision:"Hold",reasons:["ADAPTATION_LIMIT_REACHED"],versionBefore:4,versionAfter:4,observed:12,before:10,after:10,readiness:"ready",availability:"observed",findingIds:[]}];
test("evolution explains backend decision and displays all exact values and version", () => {
  const html=renderToStaticMarkup(<BaselineEvolution rows={rows} metric="observed_flow_count" />);
  expect(html).toContain("anchor limit");
  expect(html).toContain("12.000");
  expect(html).toContain("10.000");
  expect(html).toContain("4 → 4");
  expect(html).toContain("ready");
  expect(html).toContain("ADAPTATION_LIMIT_REACHED");
  expect(html).toContain('<details class="evidence-details">');
});
test("history view retains exact table without the graph", () => {
  const html=renderToStaticMarkup(<BaselineEvolution rows={rows} metric="observed_flow_count" display="history" />);
  expect(html).toContain("Adaptive baseline decisions and plotted values");
  expect(html).not.toContain("<svg");
});
