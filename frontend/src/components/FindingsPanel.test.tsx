import {renderToStaticMarkup} from "react-dom/server";
import {expect, test} from "vitest";
import {FindingsPanel} from "./FindingsPanel";
import type {HybridEvaluateResponse} from "../visualizationApi";

test("possible rule match and Unknown evidence keep rule strength distinct from ML score", () => {
  const hybrid = {
    rule_assessments: [
      {rule_id: "R1", status: "Match", subject_host_ips: ["192.0.2.10", "198.51.100.20"], rule_evidence_strength: 60, explanation: "Possible port sweep in metadata"},
      {rule_id: "R2", status: "Unknown", subject_host_ips: [], rule_evidence_strength: null, explanation: "Insufficient evidence"},
    ],
    findings: [{finding_id: "id", severity: "High", possible_category: "possible_port_sweep", kind: "RULE_MATCH", detection_source: "security_rule", subject_host_ips: ["192.0.2.10", "198.51.100.20"], flow_indices: [0,1], explanation: "Possible pattern", ml_anomaly_score: null, rule_evidence_strength: 60, evidence: [{metric: "tcp_flow_count", observed: 6, comparator: ">=", threshold: 6, unit: "flows"}]}],
  } as unknown as HybridEvaluateResponse;
  const html = renderToStaticMarkup(<FindingsPanel hybrid={hybrid} />);
  expect(html).toContain("possible port sweep");
  expect(html).toContain("Unknown / Insufficient Evidence");
  expect(html).toContain("Rule evidence strength: 60");
  expect(html).toContain("ML anomaly score: Not applicable");
  expect(html).toContain("tcp_flow_count");
  expect(html).toContain("not a confirmed attack");
});
test("source tabs filter existing unified findings without changing their evidence", () => {
  const common = {severity:"High", possible_category:null, kind:"finding", subject_host_ips:["192.0.2.10"], flow_indices:[0], explanation:"Evidence", ml_anomaly_score:null, rule_evidence_strength:null, evidence:[]};
  const hybrid = {rule_assessments:[], findings:[
    {...common, finding_id:"ml-1", detection_source:"isolation_forest", explanation:"ML source", ml_anomaly_score:0.72},
    {...common, finding_id:"rule-1", detection_source:"security_rule", explanation:"Rule source", rule_evidence_strength:85}
  ]} as unknown as HybridEvaluateResponse;
  const ml = renderToStaticMarkup(<FindingsPanel hybrid={hybrid} source="ml" />);
  expect(ml).toContain("ML source");
  expect(ml).not.toContain("Rule source");
  const rules = renderToStaticMarkup(<FindingsPanel hybrid={hybrid} source="rules" />);
  expect(rules).toContain("Rule source");
  expect(rules).not.toContain("ML source");
});
