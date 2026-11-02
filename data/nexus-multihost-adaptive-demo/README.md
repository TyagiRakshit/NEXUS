# Independent host adaptive demo

**REPLAYED DEMO TRAFFIC.** These are deterministic, payload-free, header-only synthetic PCAPs for offline local analysis. They are not captured traffic, attack labels, or evidence of real-world detection accuracy.

## What this sequence shows

NEXUS attributes a bidirectional flow to both endpoint hosts. The earlier adaptive fixtures paired the same two endpoints for every flow, so both hosts acquired the same incident-flow features. This sequence gives each principal host a separate simulated service endpoint, making its incident flows and baseline history independent.

| Role | Principal host | Service endpoint | Normal behavior |
| --- | --- | --- | --- |
| A | `192.0.2.10` | `192.0.2.200` | Four 2-packet TCP flows; mean duration starts at 2.0 s |
| B | `198.51.100.20` | `198.51.100.200` | Four 3-packet UDP flows; mean duration stays at 3.0 s |
| C | `203.0.113.30` | `203.0.113.200` | Four 2-packet TCP flows; final observation has eight |

Each capture uses a distinct, chronological UTC-aligned 60-second window beginning at 1970-01-01T02:00:00Z. There are at least four flows, eight packets, three starts spread over 30 seconds, and sufficient activity at each principal. The fixed training PCAP and model threshold are unchanged. The synthetic TCP/UDP packets carry no payload. ICMP is covered by the separate accepted Increment 3 parser fixtures; adding it here would risk an unrelated High ML veto under the fixed training distribution.

## Reproduction and verification

Run the generator only with an **empty** target directory; it refuses nonempty targets and does not touch the previous corpus:

```powershell
python scripts/generate_nexus_multihost_adaptive_demo.py data/nexus-multihost-adaptive-demo
```

The fixed seed is 20261102. `manifest.json` records capture hashes, UTC windows, intended outcomes and actual results; `expected-vs-actual.csv` is a compact machine-readable comparison. PCAPs, manifest and CSV are local generated evidence and must remain unstaged. To revalidate, use `scripts/validate_nexus_multihost_adaptive_demo.py` in an isolated environment with PyShark/TShark and the declared backend dependencies, mounting only the new corpus as writable and the backend, scripts and fixed training PCAP as read-only. The validator uses the real parser, fixed model and two independent in-memory API stores. It never needs key or telemetry mounts. The documented focused integration test performs this validation in a disposable container.

## Presentation runbook

**Before the presentation**

1. Confirm the backend is the current build and its baseline state is fresh. Request `GET /api/v1/demo/baselines/history?host_ip=192.0.2.10`, then repeat for `198.51.100.20` and `203.0.113.30`. A fresh store returns no history (404) for these hosts. If any history exists, do not claim a fresh run; use a separately approved fresh backend session. Do not restart the owner's running backend solely for this sequence.
2. Choose **one** evaluation mode for the entire run: Legacy baseline or Hybrid rules + baseline. Do not evaluate a single analysis through both routes. The manifest contains results from separate fresh stores for comparison.
3. Upload `adaptive-00.pcap` through `adaptive-04.pcap` in order. For each file, use **Analyze network data**, choose the mode, then **Evaluate selected analysis**. The corresponding API calls are `POST /api/v1/demo/upload/analyze` with multipart field `file`, followed by `POST /api/v1/demo/baselines/evaluate` (Legacy) or `POST /api/v1/demo/hybrid/evaluate` (Hybrid) with `{"analysis_id":"<returned UUID>"}`.
4. Check all three hosts: 00 is Accept/WARMING/v0, 01 is Accept/PROVISIONAL_BASELINE/v1, 02–03 remain provisional, and 04 is Accept/Ready/v4. Select each host in **Adaptive Baseline**. A and C initially show 2.0 s mean duration; B shows 3.0 s and UDP traffic. Host C has different mean bytes from A.

**During the presentation: two uploads**

5. Upload/evaluate `adaptive-05.pcap`. Select A and **Average duration (seconds)**. Its observed value is 2.3 s, its baseline moves from 2.0 to 2.06 s, and it becomes Ready/v5. Select B: observed and baseline duration remain 3.0 s, Ready/v5. C remains at four flows, Ready/v5.
6. Upload/evaluate `adaptive-06.pcap`. A's observed duration is 2.6 s and its baseline moves 2.06 → 2.168 s, Ready/v6. B remains at 3.0 s, Ready/v6. Select C and **Observed flow count**: observed count jumps 4 → 8, decision Reject with `SEVERE_BASELINE_DEVIATION`, baseline count stays 4, and version stays v5. This is a suspicious host-level deviation, not proof of an attacker.
7. Query `GET /api/v1/demo/baselines/history?host_ip=<selected host>` for A, B and C. Compare the host-specific histories and the graph's exact-value table. Keep the same browser session: the dashboard retains observed values only within that session; after reload, unavailable observations appear as explicit gaps.

The final capture contains no High ML flow and no High R1/R2 rule match in either isolated run. Thus C's rejection is a baseline-only finding and does not veto A or B. Uploading the same bytes again, changing capture order, or switching admission routes for one analysis can change the result; stop and inspect the visible error rather than presenting the manifest as a fresh run. Restarting the backend loses in-memory analyses and baseline history; a complete new run starts again with 00 in a fresh store. Do not delete files or reset Docker volumes to recover.

## Verified local result

Seven files, 28 packets/12 flows each for 00–05, and 36 packets/16 flows for 06. The first six files are 1,864 bytes each; the final file is 2,432 bytes. All seven pass the existing upload limits. Real PyShark/TShark parsing, fixed Isolation Forest scoring, rule evaluation, Legacy upload/evaluate/history and Hybrid upload/evaluate/history passed in disposable isolated tests. Both modes returned the same principal-host decisions and versions. See the ignored manifest for every observation's score, rule assessment, reason, baseline before/after and history result; see the verification report under `docs/phase-reports/` for the command evidence.

Windows host-key isolation remains **OPEN / NOT VERIFIED**. This corpus does not access keys or protected telemetry.
