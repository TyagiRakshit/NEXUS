# NEXUS offline evaluation corpus

**REPLAYED DEMO TRAFFIC.** These are synthetic, header-only PCAPs for controlled local testing. Generation does not open a network interface or transmit packets. Scenario labels and intended outcomes live only in the manifest/CSV, never in packet bytes.

## Contents and results

| Group | Captures | Packets | Flows | Observed result |
| --- | ---: | ---: | ---: | --- |
| `normal/` | 3 | 48 | 16 | All 16 flows Low under this fixed model |
| `anomalies/` | 4 | 293 | 16 | The mixed capture has 1 High and 3 Low; three TCP-only unusual-intent cases were all Low |
| `security-rules/` | 8 | 96 | 48 | R1 and R2 exact/above gates matched; just-below cases did not; sparse evidence was Unknown |
| `adaptive/` | 14 | 120 | 60 | Fresh API state reproduced warm-up through High-flow rejection |
| **Total** | **29** | **557** | **140** | **26 PASS, 3 DISCREPANCY** against declared expectations |

The maximum capture is 13,262 bytes and 189 supported packets, below the upload ceilings of 1,048,576 bytes and 2,000 packets. Captures use documentation-reserved hosts and peers; the adaptive sequence retains the accepted Increment 3 host identities and non-overlapping 60-second UTC windows. Observed frame lengths are 42, 54 and 58 bytes. TCP options account for some length variation. TCP/UDP/ICMP packets have no application payload. TCP records are partial header exchanges, not complete application sessions or realistic byte-transfer sessions.

The fixed training PCAP is separate: 48 flows, SHA-256 `4d3bfd3f1d47e0a626211e68226df03f7f4d1f61d2de2d7b71bdb2d38cf8116c`. The current model threshold is `0.636672`. The eleven exact feature names, model parameters, each PCAP SHA-256, capture timestamps, protocol counts, per-flow scores/risks/explanations, rule assessments and adaptive API results are in `manifest.json`. `expected-vs-actual.csv` gives one row per capture. These generated evidence files and all PCAPs are ignored by Git.

## Diagnostic interpretation

- `anomalies/mixed-normal-anomalous.pcap`: **verified ML demonstration** with 1 High and 3 Low flows. This is a synthetic pattern relative to the fixed training capture, not measured real-world recall.
- `security-rules/port-sweep-match.pcap`: **verified rule demonstration**; R1 matched at strength 60, the isolated Hybrid API exposed one High security-rule finding and vetoed both hosts. All six ML flow risks were Low. The rule does not identify an initiator.
- `security-rules/reconnaissance-match.pcap`: R2 matched at strength 60; the isolated Hybrid API exposed one High finding and vetoed the focal host only. All five ML flow risks were Low.
- `security-rules/combined-rule-evidence.pcap`: R1 and R2 matched together; the isolated Hybrid API exposed two distinct High rule findings.
- `anomalies/unusual-short-flows.pcap`, `unusual-packet-rate.pcap` and `unusual-flow-volume.pcap` are independently labelled unusual-intent, but **all their flows scored Low**. Their highest scores were `0.610943`, `0.600084` and `0.593200`, below `0.636672`. These are recorded as discrepancies; the model, threshold, training fixture and labels were not changed.

The corpus checks parser/model/rule function and controlled demonstration behaviour. It does not establish real-world accuracy, calibrated probabilities, confirmed attacks, attacker attribution or outbound exfiltration. R1/R2 are metadata-only possible-pattern rules. Windows host-key isolation remains **OPEN / NOT VERIFIED**; this validation did not mount or read the host key/evidence directories.

## Reproduce in an empty directory

From the original repository root in PowerShell, with the existing backend Docker image and the fixed training PCAP already present:

```powershell
$nexusRoot = (Get-Location).Path
$nexusCorpus = Join-Path $nexusRoot 'data/nexus-evaluation-corpus-regenerated'
python scripts/generate_nexus_evaluation_corpus.py $nexusCorpus
$nexusMounts = @(
  '--network', 'none',
  '-e', 'PYTHONPATH=/app:/app/scripts',
  '--mount', "type=bind,source=$nexusRoot\backend\app,target=/app/app,readonly",
  '--mount', "type=bind,source=$nexusRoot\scripts,target=/app/scripts,readonly",
  '--mount', "type=bind,source=$nexusRoot\data\pcap\phase4-normal-training.pcap,target=/app/fixtures/phase4-normal-training.pcap,readonly",
  '--mount', "type=bind,source=$nexusCorpus,target=/app/corpus"
)
docker run --rm @nexusMounts isprojectnexus-backend python /app/scripts/validate_nexus_evaluation_corpus.py /app/corpus --write-results
```

The generator **refuses a nonempty target**, so choose a new empty path for each regeneration. `python scripts/generate_nexus_evaluation_corpus.py --help` prints usage and creates no directory. The validator checks every file's hash, bounds and header-only structure before writing observed results; it uses fresh in-process API stores inside the disposable, network-isolated container. It does not use the running NEXUS baseline state, start a Compose service, or mount host private keys. For a read-only validation pass, omit `--write-results`.

Focused test command, using the same mount pattern plus a read-only test mount:

```powershell
docker run --rm @nexusMounts --mount "type=bind,source=$nexusRoot\backend\tests,target=/app/tests,readonly" isprojectnexus-backend pytest -q tests/test_nexus_evaluation_corpus.py
```

The focused test generates two fresh temporary corpora and compares every PCAP byte and SHA-256. It also exercises the real PyShark/TShark parser, fixed Isolation Forest, rule boundaries, isolated upload → baseline-evaluate APIs, duplicate protection and Hybrid rule findings. Do not use this synthetic corpus as a real-world detection benchmark.
