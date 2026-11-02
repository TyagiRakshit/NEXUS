# NEXUS Glossary

## Status and ownership

- Owner: Teacher/documentation lead
- Update trigger: A new technical term is introduced or a learner misunderstands an existing definition

- **Packet:** A small unit of network data. NEXUS uses approved header metadata, not packet payload contents.
- **Packet payload:** The content carried inside a packet. NEXUS is prohibited from inspecting or storing it.
- **Five-tuple:** Source IP, source port, destination IP, destination port, and protocol. Together they identify a connection direction.
- **Bidirectional flow:** Both directions of the same conversation grouped into one record by canonicalizing the five-tuple endpoints.
- **Idle timeout:** How long a flow may receive no new packets before it is considered finished. The prototype uses 60 seconds.
- **Feature window:** The time span or grouping over which behavioral measurements are calculated. Its exact prototype value is not yet approved.
- **Feature:** A numeric or categorical measurement derived from allowed metadata, such as byte count or destination-port diversity.
- **Host identity:** The value used to group behavior for a device. The first prototype uses IP address, which has DHCP, NAT, and privacy limitations.
- **Host profile:** A host-specific statistical summary of previously accepted behavior.
- **Baseline:** The current expected behavior against which new observations are compared.
- **Adaptive baseline:** A baseline that changes carefully when approved low-risk observations show legitimate drift.
- **Drift:** A gradual legitimate change in normal behavior over time.
- **Baseline poisoning:** Corruption caused by allowing malicious or abnormal observations to redefine what the system considers normal.
- **Anomaly score:** The Isolation Forest output used to estimate how unusual a feature vector is. It is not automatically a probability or explanation.
- **Risk score/band:** A separate human-facing assessment derived from anomaly and contextual evidence. NEXUS configures Low, Medium, and High bands.
- **Critical alert:** A signed event that requires both a High-risk condition and a separate explicit critical rule.
- **Isolation Forest:** A machine-learning algorithm that isolates unusual observations using randomly constructed trees.
- **Model:** A stored mathematical pattern learned from training data and configuration, used to produce a result for new data. A model's output is evidence to interpret, not automatic truth.
- **Seed:** A fixed value controlling model randomness so the same data and configuration can produce repeatable results.
- **Model retraining:** Building a new model version from training data. It is separate from statistical baseline adaptation and is not continuous in the first prototype.
- **Telemetry:** Security and operational records passed through NEXUS, such as derived flows, scores, alerts, and verification status.
- **Encryption:** Reversible protection that keeps data unreadable without the correct key.
- **AES-GCM:** An authenticated-encryption mode that provides confidentiality and detects unauthorized ciphertext changes when used correctly.
- **Nonce:** A value that must be unique for each encryption under the same AES-GCM key; it is not itself secret.
- **Authentication tag:** AES-GCM output used to detect altered ciphertext or associated data.
- **Hash/digest:** A fixed-size value derived from data. NEXUS uses SHA-256 for an explicit tamper demonstration against a trusted digest.
- **SHA-256:** A cryptographic hash function. A plain SHA-256 digest alone does not prove who created a record.
- **Digital signature:** A private-key operation that lets a public key verify origin and integrity of the signed content.
- **RSA-PSS:** The approved RSA signature padding scheme; NEXUS combines it with SHA-256 for critical events.
- **Canonical serialization:** One precisely defined byte representation of a record so hashing and signing are repeatable.
- **Schema version:** A label identifying the exact structure and meaning of a contract or telemetry record.
- **Correlation ID:** A non-secret identifier linking related capture, flow, profile, alert, telemetry, API, and UI evidence.
- **Fixture:** Controlled test/demo input with known provenance and expected output.
- **Replay:** Processing a saved safe fixture rather than observing live traffic. NEXUS labels it `REPLAYED DEMO TRAFFIC`.
- **Modular monolith:** One backend deployment whose internal modules have strict responsibilities and interfaces.
- **ADR:** Architecture Decision Record: a durable document stating a decision, context, consequences, owner, date, and status.
- **Verified fact:** A claim supported by fresh command output from the current repository state.
