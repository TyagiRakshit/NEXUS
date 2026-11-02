# Increment 2 guarded baseline API

Status: owner-accepted for offline, in-memory local academic demonstration and committed at `98b7db5707076fc7ba78bf4b12399fdca983a7ea`. Schema source: [approved contract](../plans/increment-02-guarded-adaptive-baseline-contract.md). All data is offline `REPLAYED DEMO TRAFFIC` metadata.

## Sequence

1. `POST /api/v1/demo/upload/analyze` with a `.pcap` file. Keep its returned `analysis_id`. Upload parses and scores once with the separate fixed Phase 4 training PCAP; it does not update the adaptive baseline.
2. `POST /api/v1/demo/baselines/evaluate` with `{"analysis_id":"UUID"}`. The server looks up the immutable scored observation, decides both endpoint hosts against their prior versions, then records the result atomically. Repeating the same analysis ID returns the identical recorded body without a second update.
3. `GET /api/v1/demo/baselines/history?host_ip=192.0.2.10` to read that host's bounded evolution.

The full typed JSON shapes, reason-code enum, feature formulas and precedence are in the approved contract. Evaluate returns `phase6.baseline.v1`, `observation_id`, aligned UTC capture bounds or null, activity span, digest status (`new`/`duplicate`), fixed model version/threshold, `baseline_store_epoch`, and IP-sorted `hosts`. Each host includes Accept/Hold/Reject, ordered reason codes, readiness and confidence before/after, accepted count and version before/after, probation count, incident/high flow counts, flow ordinals, current and baseline features, per-feature deviations, last evaluated/admitted capture window, and separate findings. History returns `phase6.baseline.history.v1`, current baseline/version and anchor version, up to eight accepted snapshots and 32 decisions. A finding has severity and feature evidence; it is not a Phase 5C signed alert and makes no attacker attribution.

Unknown analysis: 404 `ANALYSIS_NOT_FOUND`; known expired analysis: 404 `ANALYSIS_EXPIRED`; invalid UUID: 422; incompatible scored evidence: 422 `ANALYSIS_INVALID`; bounded capacity exceeded: 503 `CAPACITY_LIMIT`. Unknown host: 404 `HOST_NOT_FOUND`; invalid IP: 422 `INVALID_HOST_IP`. Errors are sanitized and tested failure paths do not partially update host state. No capture digest, packet payload, raw PCAP, key or protected telemetry envelope is returned.

The 60-second aligned UTC window, at least 45 seconds activity and host sample coverage govern learning only. Short captures still analyze. Gap reset uses capture time: exactly 300 seconds preserves the tentative sequence; over 300 seconds discards it and evaluates the later observation normally as a possible first new sample. Overlap and out-of-order windows never learn.

State is local to one backend process. Restart changes `baseline_store_epoch` and loses scored observations, duplicate memory, baselines, and history. There is no persistence or multi-process consistency. The existing Phase 3 profile route and Phase 5C manual alert protection remain separate.
