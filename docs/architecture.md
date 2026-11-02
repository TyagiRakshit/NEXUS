# NEXUS Architecture

## Status and ownership

- Status: Approved conceptual architecture; Phase 4, Phase 5C, and Increments 2–4 are owner-accepted and committed. Increment 5 frontend visualization is implemented for owner review, unaccepted and uncommitted; see the dated addenda below.
- Owner: Lead engineer and human owner
- Update trigger: Any accepted change to module boundaries, data lifecycle, deployment, trust boundaries, or failure behavior
- Governing decisions: [`docs/decisions/`](decisions/README.md)

## Architectural goals

NEXUS must make the academic security pipeline visible and understandable while remaining small enough to build, test, and demonstrate reliably. It uses a modular monolith so modules have clear responsibilities without the operational complexity of distributed services.

## Deployment view

```text
Authorized local host
  Wireshark/TShark/PyShark capture process (outside Docker)
                |
                | versioned normalized observations
                v
Docker Compose network
  FastAPI modular monolith <----> PostgreSQL
             ^
             |
       React/TypeScript
       polls every 5 seconds
```

Docker Compose is limited to PostgreSQL, backend, and frontend. Capture runs on the authorized local host because interface access and capture permissions are host concerns. No cloud deployment is in prototype scope.

## Module view

| Module | Purpose | Explicit exclusions |
|---|---|---|
| `contracts` | Versioned immutable shapes for observations, flows, profiles, scores, alerts, and telemetry envelopes | Business rules, framework models, database calls |
| `capture` | Authorized local live-capture and temporary PCAP replay adapters; emit normalized metadata | Payload inspection/storage, flow aggregation, scoring |
| `flows` | Build bidirectional flows, apply the 60-second idle timeout, and derive required features | Profiles, ML, risk policy |
| `profiles` | Maintain host-specific statistical profiles, learning state, snapshots, deviations, and candidate updates | ML retraining, alert severity |
| `detection` | Load/train/version one shared seeded Isolation Forest and produce anomaly scores | Probability claims, explanations, baseline updates |
| `risk` | Map anomaly and deviation evidence into configured Low/Medium/High risk and readable alerts | Model training, cryptography |
| `secure_telemetry` | Canonicalize, AES-GCM protect, SHA-256 digest, and RSA-PSS sign/verify critical records | Secret storage in source, browser, or normal records |
| `persistence` | PostgreSQL migrations, transactions, retention, and repositories for derived data | Packet payloads, raw PCAP retention, scoring rules |
| `api` | Versioned FastAPI validation and HTTP transport | Domain policy, capture parsing |
| `application` | Orchestrate the one-way use cases, correlation IDs, failure propagation, and baseline-admission decision | UI logic, hidden cross-module calls |
| `observability` | Honest health/readiness, versions, and structured operational logs without sensitive data | Security-event storage, payload logging |
| Frontend | Analyst overview, hosts, alerts, and verification views using typed API data | Secret material, backend policy duplication |

## Dependency and processing direction

```text
capture
  -> flows
  -> profiles (compare with current statistical baseline)
  -> detection (shared seeded Isolation Forest)
  -> risk (configured band plus readable feature deviations)
  -> application (baseline candidate admission/rejection)
  -> secure_telemetry
  -> persistence
  -> API
  -> frontend
```

The application layer owns the sequence. Modules exchange versioned contracts and never call backward through the pipeline. High-risk observations cannot automatically update a baseline. Statistical adaptation does not retrain the Isolation Forest.

## Core data contracts

Exact fields and types will be specified before Phase 1 implementation. Every future contract must include:

- schema version;
- UTC event and processing timestamps where relevant;
- correlation ID connecting capture, flow, profile, alert, and telemetry records;
- source classification such as `LIVE` or `REPLAYED_DEMO_TRAFFIC`;
- model/profile versions where a decision depends on them;
- explicit verification and persistence states rather than inferred success.

Flow identity uses the approved bidirectional five-tuple: source IP, source port, destination IP, destination port, and protocol. Endpoint canonicalization must make both directions resolve to one identity. IP address is the initial host identity, with DHCP/NAT/privacy limitations documented in the UI and glossary.

## Required flow features

The first prototype derives only approved metadata features needed for the synopsis:

- packet and byte counts;
- flow duration and connection frequency;
- protocol distribution;
- destination diversity;
- destination-port diversity;
- DNS activity;
- other fields only after traceability and human approval.

Packet payloads are neither inspected nor stored.

## Adaptive learning and detection

- Statistical profiles are host-specific.
- Only low-risk observations may become baseline-update candidates.
- High-risk observations are never admitted automatically.
- Baseline updates must be bounded, attributable, and recoverable from a prior snapshot.
- The first prototype has one shared Isolation Forest with a fixed seed and deterministic fixtures.
- ML retraining is explicit and versioned; continuous retraining is out of scope.
- Anomaly score and human-facing risk score are separate. Neither is automatically a probability.
- A critical alert requires both a High-risk result and a separate explicit rule.

## Trust boundaries and protected data

1. **Capture boundary:** authorized host metadata enters NEXUS; raw PCAP exists temporarily and is deleted according to the approved cleanup rule.
2. **Application boundary:** derived observations and flow/profile evidence are processed. Payloads and secrets are prohibited.
3. **Telemetry boundary:** approved records are canonically serialized and protected with AES-GCM before persistence where required.
4. **Verification boundary:** SHA-256 demonstrates digest comparison; RSA-PSS/SHA-256 authenticates critical-event content. Failed verification is stored/displayed as unverified or tampered.
5. **Browser boundary:** the UI receives display-safe data only and never receives private or symmetric keys.

Development keys are generated locally and excluded from Git. Exact key size, storage path, provider interface, and lifecycle remain open decisions.

## Data lifecycle

```text
authorized live traffic or safe PCAP
  -> temporary packet source
  -> metadata-only observation
  -> derived flow summary
  -> profile/detection/risk decision
  -> protected telemetry and alert
  -> retained derived records
  -> temporary raw source deleted
```

The prototype retains derived flow summaries and alerts only. The exact retention duration and deletion schedule remain unresolved. Demo resets must name their target and must not delete unrelated data.

## Failure behavior

- Capture failure: show a capture error; allow a clearly labeled replay path.
- Database failure: show persistence failure; do not claim telemetry or alerts were saved.
- Cryptographic failure: mark the record unverified/tampered; never present it as valid.
- Model unavailable or incompatible: show detection unavailable; do not synthesize a normal result.
- Partial backend failure: health/readiness and UI state must expose the affected capability.

## Prohibited dependencies and designs

The prototype excludes microservices, Kafka, Redis, Kubernetes, cloud deployment, authentication/OAuth, plugin frameworks, continuous ML retraining, WebSockets without later evidence, and capture from inside Docker.

## Planned repository structure

```text
backend/src/nexus/{application,contracts,capture,flows,profiles,detection,risk,secure_telemetry,persistence,api,observability}/
backend/tests/{unit,integration,fixtures}/
frontend/src/{api,components,features,routes}/
frontend/tests/
infra/docker/
scripts/
```

These paths are planned and do not yet exist.

## Implemented boundary at Increment 1 (2026-10-31 UTC)

The current original `main` worktree implements metadata-only offline PCAP upload, flow/profile extraction, per-request training from a separate fixed normal PCAP, Isolation Forest scoring, a separate Low/High risk mapping, and manual full-batch secure telemetry protection. The Phase 3 in-memory baseline remains a separate normal-fixture demonstration and is not updated by uploads. The backend-only protected JSON is local evaluator evidence, not PostgreSQL persistence or restart recovery. `docs/phase-reports/increment-1-stabilization.md` records fresh checks and current blockers. The planned module paths above are conceptual; the implemented backend currently lives under `backend/app/`.

A future guarded baseline must consume completed risk decisions before admitting observations. A future security-rule engine must not infer confirmed scans, DNS queries, or outbound transfers from unavailable metadata. The final offline-only demo direction requires owner reconciliation with the historical live-capture plan and ADR-0002; this document does not change that accepted ADR.

## Phase 4 commit and Phase 5C staging boundary (2026-11-01 UTC)

Phase 4 was committed as bef833ac73e9d68ff7baa384c991d2c16c8a5a89 after an independent staged-tree build and tests. The owner authorized a separate Phase 5C staged snapshot for review, not a commit. Windows host-key isolation remains OPEN / NOT VERIFIED; container 0600 modes and crypto checks do not establish exclusive Windows host access.

## Increment 2 planning boundary (2026-11-01 UTC)

The proposed [guarded adaptive baseline contract](plans/increment-02-guarded-adaptive-baseline-contract.md) places a separate, in-memory host admission step after fixed-model flow risk. It proposes capture-time ordering, two-endpoint evidence attribution, and versioned host history without changing the accepted Phase 3 route or Phase 5C manual telemetry path. This is a design proposal, not an accepted architecture change. Windows host-key isolation remains OPEN / NOT VERIFIED.

## Increment 2 implementation boundary (2026-11-01 UTC)

An upload still parses metadata, builds Phase 3-compatible host profiles, fits the fixed Phase 4 Isolation Forest from its separate training PCAP, scores risk, and retains an immutable scored observation by analysis ID. Explicit `POST /api/v1/demo/baselines/evaluate` reads that observation without reparsing or retraining. The new in-memory store snapshots both endpoint hosts, applies the High-flow veto and feature-aware admission, then atomically records bounded host decisions, accepted versions, and separate host-only findings. `GET /api/v1/demo/baselines/history` exposes backend-supplied evolution for a future graph. Phase 3's fixed-normal route and Phase 5C's manual signed-alert batch remain independent. Host findings are not added to Phase 5C telemetry in Increment 2.

Capture timestamps, not upload time, set the aligned 60-second learning window and five-minute warm-up/probation gap. Short captures remain valid analysis but Hold for adaptive learning. Exact duplicate bytes, overlap, and out-of-order windows cannot update a host. The state, digest memory, cache, and histories disappear on backend restart; `baseline_store_epoch` exposes that discontinuity. There is no database or multi-process coordination. Windows host-key isolation remains OPEN / NOT VERIFIED.

## Increment 2 owner acceptance boundary (2026-11-01 UTC)

The owner accepted the separate guarded adaptive store and versioned APIs only for the offline, in-memory local academic demonstration. This does not make baseline-only host findings Phase 5C signed alerts, retrain the fixed Isolation Forest, persist baseline state, or establish production Windows host-key isolation. The Increment 2 implementation remains uncommitted pending a separately approved commit; proposed ADR-0011/0012 remain proposed. The Windows host-key isolation gate is OPEN / NOT VERIFIED.

## Increment 4 implementation addendum (2026-11-01 UTC)

The owner subsequently approved the exact Increment 4 rule and telemetry policy for implementation. In the opt-in hybrid path, the existing scored upload is read by analysis ID; pure R1/R2 metadata rules run before the one shared host-baseline admission; the response retains original Isolation Forest, baseline and rule evidence separately. High R1 evidence vetoes learning for both incident hosts, and High R2 evidence vetoes only its focal host. Neither identifies an attacker. Legacy evaluate/history and Phase 5C v1 routes remain supported. Compatible finalized legacy evaluations are projected without another admission; incompatible legacy-first High rule evidence returns 409 without state change.

Hybrid candidate findings are reserved as pending before admission and become protectable only after the coordinated admission result is finalized. Failed evaluations roll back both host state and the pending candidate. A separate explicit manual v2 action protects all distinct eligible High unified findings using the existing AES-GCM, SHA-256 and RSA-PSS primitives, separate artifact identity, and no silent overwrite. This adds opt-in cryptographic coverage for baseline-only High findings without changing the v1 signed-alert schema. Findings include canonical UUIDv5 identities, numerical baseline/rule evidence and supporting UTC spans. The implementation evidence and limitations are in the [Increment 4 report](phase-reports/increment-4-hybrid-detection.md). In-memory restart limits and **CRYP-05 Windows host-key isolation OPEN / NOT VERIFIED** remain.

## Increment 4 scoped acceptance boundary (2026-11-02 IST)

The human owner accepted this opt-in hybrid path for a controlled offline academic demonstration, including its separate v1/v2 telemetry behavior. The acceptance does not establish real-world detection accuracy, attacker identity, restart persistence, saved-v2-file verification after restart, an independent clean build of this exact tree, or production-grade Windows host-key isolation. Increment 4 has no accepted commit; staging alone is authorized for owner review. **CRYP-05 remains OPEN / NOT VERIFIED.**

## Increment 5 frontend implementation addendum (2026-11-02 IST)

The owner-approved, uncommitted Increment 5 UI is a read-only presentation and manual-action layer over the existing upload, baseline/hybrid, history and telemetry APIs. `frontend/src/visualizationApi.ts` validates versioned responses and safe error codes; `visualizationModels.ts` maps actual flow and host values to charts without calculating risk or rule verdicts. Upload alone does not admit a baseline. The user selects exactly one Legacy or Hybrid evaluate route per analysis; the UI disables another attempt and does not silently switch routes on 409. Backend admission remains authoritative.

The SVG evolution graph and semantic table use the backend's decision order and a bounded browser-memory ledger of observed values keyed by epoch, host and observation ID. The ledger survives successive uploads within one page session only. After reload, decision markers and at most eight accepted snapshots remain available from the in-memory history API, but earlier observed values are labelled unavailable and no lines bridge missing points. A changed backend epoch clears old plotted values. Separate protocol and Isolation Forest views use uploaded flow results; unified findings retain ML, baseline and rule sources, with rule strength explicitly described as evidence rather than probability. V1 manual flow-alert controls retain Phase 5C behavior; opt-in v2 controls protect and verify only eligible High unified findings, with separate Protected and Verified states. The browser receives no keys or protected JSON.

The old 2026-11-02 Increment 4 acceptance paragraph above records its historical pre-commit state. Increment 4 was subsequently committed at `97b32502e98f869dab519ae6fc1c01fd81ffd9bc`; Increment 5 remains pending owner review. All adaptive/hybrid state is in memory, and **CRYP-05 Windows host-key isolation remains OPEN / NOT VERIFIED**.
