import {useState} from "react";

export function SecurityRuleCatalogue() {
  const [open, setOpen] = useState(false);
  return <section className="rule-catalogue-toggle" aria-label="Security rule reference">
    <button type="button" aria-expanded={open} aria-controls="security-rule-catalogue" onClick={() => setOpen(value => !value)}>
      {open ? "Hide Security Rules" : "View Security Rules"}
    </button>
    <div id="security-rule-catalogue" role="region" aria-labelledby="security-rule-catalogue-heading" hidden={!open} className="rule-catalogue">
      <div className="dashboard-panel">
        <p className="eyebrow">IMPLEMENTED METADATA RULES</p>
        <h3 id="security-rule-catalogue-heading">Security Rule Catalogue</h3>
        <p>These deterministic rules flag possible patterns in offline flow metadata. A match is not proof of an attack, its initiator, or malicious intent. Existing findings and rule assessments appear separately below.</p>
      </div>
      <div className="rule-catalogue-grid">
        <article className="rule-catalogue-card">
          <div className="rule-catalogue-heading"><h4>R1 — Possible Port Sweep</h4><span className="rule-severity">High when matched</span></div>
          <p>Detects communication between two hosts involving an unusual variety of endpoint ports.</p>
          <details className="evidence-details"><summary>Detection conditions</summary>
            <ul>
              <li>At least 6 TCP flows involving the same host pair.</li>
              <li>At least 6 distinct ports at one endpoint and at least 4 at the other.</li>
              <li>At least 3 distinct flow start times.</li>
            </ul>
            <p>Flows must have usable host addresses, endpoint ports and start timestamps. Either endpoint orientation may satisfy the port counts.</p>
          </details>
          <p><strong>Learning effect:</strong> Veto baseline learning for both hosts in the supporting pair.</p>
          <p>A match does not identify which host initiated traffic or prove an attack.</p>
        </article>
        <article className="rule-catalogue-card">
          <div className="rule-catalogue-heading"><h4>R2 — Possible Host Reconnaissance</h4><span className="rule-severity">High when matched</span></div>
          <p>Detects a pattern where one host communicates with multiple peers using diverse ports.</p>
          <details className="evidence-details"><summary>Detection conditions</summary>
            <ul>
              <li>At least 5 TCP flows or at least 5 UDP flows for one focal host and one shared peer-side port.</li>
              <li>At least 5 distinct peers sharing that peer-side port.</li>
              <li>At least 4 distinct focal-side ports.</li>
              <li>At least 3 distinct flow start times.</li>
              <li>TCP and UDP evidence are evaluated separately; their counts are never combined.</li>
            </ul>
            <p>Flows must have usable host addresses, endpoint ports and start timestamps.</p>
          </details>
          <p><strong>Learning effect:</strong> Veto baseline learning for the focal host only.</p>
          <p>A match does not prove malicious intent or identify an attacker.</p>
        </article>
      </div>
      <div className="dashboard-panel rule-strength">
        <h4>Rule Evidence Strength</h4>
        <p><code>min(90, 60 + 5 × (primary count − minimum count))</code></p>
        <p>R1 uses the larger qualifying endpoint's distinct-port count, with minimum 6. R2 uses distinct peers, with minimum 5.</p>
        <ul>
          <li>60 at the matching boundary.</li>
          <li>65 when the primary count exceeds its minimum by one.</li>
          <li>Maximum 90.</li>
          <li>Nonmatches with adequate evidence: 0.</li>
          <li>Insufficient evidence: Unknown, with no numerical score.</li>
        </ul>
        <p>This is deterministic rule evidence strength, not attack probability or ML confidence.</p>
      </div>
    </div>
  </section>;
}
