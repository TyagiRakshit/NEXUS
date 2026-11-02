# NEXUS

**NEXUS** is an academic cybersecurity prototype for analyzing offline network packet captures, detecting unusual traffic, comparing behaviour against adaptive host baselines, identifying possible network reconnaissance patterns, and cryptographically protecting security findings.

It is built for **controlled offline demonstrations** rather than live network monitoring or production intrusion detection.

## Features

| Feature | Description |
| --- | --- |
| Offline PCAP analysis | Parses packet metadata and constructs bidirectional flows and host profiles. |
| ML anomaly detection | Uses a seeded Isolation Forest to score flow-level anomalies. |
| Guarded adaptive baseline | Learns eligible host-specific behaviour; supports warm-up, provisional/ready states, Accept/Hold/Reject decisions, and bounded updates. |
| Hybrid security findings | Combines distinct ML, baseline, and deterministic rule evidence. Rules identify **possible** port sweeps and host reconnaissance, not confirmed attacks. |
| Visual dashboard | Displays protocol distribution, flow anomaly scores, adaptive evolution, host comparisons, decision history, and security findings. |
| Secure telemetry | Manually protects eligible High findings using AES-256-GCM, SHA-256 and RSA-PSS/SHA-256, with verification and tamper detection. |

## Technology stack

| Layer | Technologies |
| --- | --- |
| Frontend | React, TypeScript, Vite |
| Backend | Python, FastAPI |
| Packet decoding | PyShark, TShark |
| Machine learning | scikit-learn, Isolation Forest |
| Adaptive and rule engines | Custom Python logic |
| Cryptography | AES-256-GCM, SHA-256, RSA-PSS/SHA-256 |
| Services | Docker Compose, PostgreSQL 17 |
| Tests | pytest, Vitest, React Testing Library |

PostgreSQL runs as a service; **adaptive history and telemetry lookup state are currently process-local, not stored in PostgreSQL**. Protected telemetry JSON artifacts are stored locally.

## Requirements

- Docker Desktop / Docker Engine with Docker Compose
- Python for generating the approved synthetic demonstration fixtures
- A local `.env` file based on the repository's `.env.example` (do not commit `.env`)

## Run locally

From the repository root, create a local `.env` using `.env.example`, then generate the required synthetic fixtures and start the services:

```powershell
python scripts/generate_phase2_fixture.py
python scripts/generate_phase3_normal_fixture.py
python scripts/generate_phase4_fixtures.py
docker compose --env-file .env up -d --build
docker compose --env-file .env ps
```

Open the dashboard at **http://127.0.0.1:5173/**.

To stop the services:

```powershell
docker compose --env-file .env stop
```

> Restarting the backend clears in-memory analysis and adaptive-baseline state. Do not restart it between baseline preparation and a live demonstration.

## Demonstration workflow

The project includes deterministic generators and validators for synthetic evaluation scenarios. Generated PCAPs and result manifests are intentionally excluded from version control.

1. Generate the multi-host adaptive corpus using `scripts/generate_nexus_multihost_adaptive_demo.py` and follow its [runbook](data/nexus-multihost-adaptive-demo/README.md).
2. Using a fresh backend state, upload and evaluate adaptive captures `00` through `04` in chronological order to establish the three principal host baselines.
3. Generate the combined scenario using `scripts/generate_nexus_final_demo.py` and follow its [runbook](data/nexus-final-demo/README.md).
4. Upload the final combined PCAP in **Hybrid rules + baseline** mode. Inspect flow scores, per-host adaptation, rule findings, and the manual telemetry v1/v2 Protect/Verify controls.

The reported controlled demonstration includes independent host adaptation, a rejected severe host deviation, a High ML flow, and possible port-sweep/reconnaissance findings. These are **synthetic validation outcomes**, not measurements of real-world attack-detection accuracy.

See the [offline demonstration guide](docs/demo-scenario.md) and [API documentation](docs/api/) for further details.

## Tests

For backend tests using the test-only read-only fixture mounts:

```powershell
docker compose --env-file .env -f compose.yaml -f compose.test.yaml run --rm --no-deps backend pytest -q
```

The frontend includes Vitest tests, a TypeScript typecheck, and a Vite production build. See `frontend/package.json` for the exact commands.

## Architecture and limitations

NEXUS separates packet parsing, flow feature extraction, fixed Isolation Forest scoring, host-specific guarded admission, security rules, and telemetry protection. The frontend presents backend results but does not determine risk or mutate baselines itself.

Current limits:

- Offline, authorized synthetic `.pcap` files only; no live capture or traffic transmission.
- Upload limit: 1 MiB and up to 2,000 supported packets per analysis.
- The fixed Isolation Forest was evaluated with limited synthetic training coverage; its flags do not prove malicious intent or provide calibrated attack probabilities.
- Adaptive history is held in memory and is lost when the backend process restarts.
- Telemetry is protected manually; local evidence files do not provide production-grade audit storage.
- Exclusive Windows host access to demo keys/evidence has **not been verified**.

For more detail, see [architecture](docs/architecture.md) and the [phase reports](docs/phase-reports/README.md).

## Security and responsible use

Use only PCAPs you own or are authorized to analyze. Do not commit `.env`, cryptographic keys, protected JSON, private data, or generated captures. Rule findings represent **possible network activity patterns**, not attribution or proof of compromise.
