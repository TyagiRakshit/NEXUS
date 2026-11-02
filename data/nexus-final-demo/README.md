# NEXUS final one-upload Hybrid demonstration

**REPLAYED DEMO TRAFFIC.** One deterministic, payload-free, header-only synthetic PCAP for offline local analysis. No packet transmission or real-world accuracy claim. Rule matches are possible metadata patterns; scores are not attack probabilities.

## Before the presentation

Start from a fresh backend baseline store. Check `GET /api/v1/demo/baselines/history?host_ip=<IP>` for A `192.0.2.10`, B `198.51.100.20`, and C `203.0.113.30`; each should return 404 before preparation. If not, stop rather than claiming this run is fresh. Do not restart the owner's backend without approval.

Upload `adaptive-00.pcap` through `adaptive-04.pcap` in order from `data/nexus-multihost-adaptive-demo/`. For **each** file, choose **Hybrid rules + baseline** and **Evaluate selected analysis** exactly once. The API calls are `POST /api/v1/demo/upload/analyze` (multipart `file`) then `POST /api/v1/demo/hybrid/evaluate` with `{"analysis_id":"<returned UUID>"}`. All three principal hosts must reach **Ready v4** after 04. Do not use Legacy on the same analysis. The final capture occupies the immediately next UTC minute, 1970-01-01T02:05:00Z–02:06:00Z.

## During the presentation: one upload

Upload `nexus-final-hybrid-demo.pcap` from this folder. Choose **Hybrid rules + baseline** and evaluate once.

| Page | Select | Verified result |
| --- | --- | --- |
| Overview → Summary | Current analysis | **60 packets, 28 flows, 14 hosts, 1 flagged alert**; 18 TCP, 9 UDP, 1 ICMP flows |
| Traffic Analysis → Flow Explorer | Risk High, flow 23 | ICMP `203.0.113.30` ↔ `203.0.113.200`, score **0.641502**, fixed threshold **0.636672**. The other 27 flows are Low. |
| Adaptive Baseline → Evolution | A, Average duration (seconds) | Observed **2.3 s**, baseline **2.0 → 2.06 s**, Accept/WITHIN_BAND, Ready v4 → v5 |
| Adaptive Baseline → Evolution | B, Average duration (seconds) | Observed **3.0 s**, baseline **3.0 → 3.0 s**, Accept/WITHIN_BAND, Ready v4 → v5 |
| Adaptive Baseline → Evolution | C, Observed flow count | Observed **9**, baseline **4 → 4**, Reject with ML_HIGH and SEVERE_BASELINE_DEVIATION, Ready v4 → v4 |
| Adaptive Baseline → Feature Comparison | A, B, C | Observed, before and after features show A's update, B's stability and C's denied update |
| Security Findings → ML | High | One source-labelled ML_HIGH ICMP finding. Bidirectional attribution does not identify an attacker. |
| Security Findings → Baseline | High | Two severe host findings: C and its service endpoint. Both saw the incident flows; neither learned them. |
| Security Findings → Rules | R1 and R2 Match | R1: six TCP flows between `203.0.113.40`/`.41`, six distinct ports on each, six starts, strength **60**, pair veto. R2: five UDP flows from focal `203.0.113.50` to five peers sharing port 123, five focal ports and starts, strength **60**, focal veto. A/B unaffected. |
| Secure Telemetry → Flow Alerts v1 | Protect, Verify, tampered copy | **1/1** flagged alert protected and verified; tampered copy rejected |
| Secure Telemetry → Unified Findings v2 | Protect, Verify, tampered copy | **5/5** distinct High findings protected and verified: one ML, two baseline, two rule; tampered copy rejected |

The dashboard keeps observed chart values only in the current browser session; after reload, unavailable points remain gaps. Switching pages does not require another admission request. On a 404, 409 or epoch change, stop and inspect the visible failure.

## Reproduction

Generator: `python scripts/generate_nexus_final_demo.py <empty-output-directory>`. It uses fixed seed `20261103`, refuses nonempty output, and never changes the earlier corpus. Validator: `scripts/validate_nexus_final_demo.py <final-directory> --preparation-directory <multi-host-directory> --write-results` in the existing backend image with source, training PCAP and preparation corpus mounted read-only. It uses two disposable container-local key/evidence directories; no developer key or protected JSON is accessed or copied here. Omit `--write-results` for a read-only rerun.

The PCAP is **3,980 bytes** (SHA-256 `32f915d08cfd080391e42a986d10b7d928a2240caad4496a51f448700cc722ce`), within the 1,048,576-byte/2,000-packet upload limits. `manifest.json` separates intended and actual per-flow, rule, host, history and telemetry outcomes; `expected-vs-actual.csv` gives the compact comparison. These generated artifacts remain ignored and unstaged. This fixture does not validate real-world detection, attacker attribution, durable state, offline v2 verification after restart, or production Windows key isolation. **Windows host-key isolation remains OPEN / NOT VERIFIED.**
