from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import time
from collections import OrderedDict
from dataclasses import dataclass, replace
from pathlib import Path
from tempfile import NamedTemporaryFile
from threading import RLock
from typing import Any, Callable, Literal, Sequence
from uuid import UUID, uuid4

from cryptography.exceptions import InvalidSignature, InvalidTag
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


SCHEMA_VERSION = "phase5.secure-telemetry.v1"
HYBRID_SCHEMA_VERSION = "phase7.secure-telemetry.v2"
ALGORITHM = "AES-256-GCM+SHA-256+RSA-PSS-SHA-256"
FLOW_FIELDS = (
    "protocol",
    "source_ip",
    "source_port",
    "destination_ip",
    "destination_port",
    "packet_count",
    "byte_count",
    "duration_seconds",
    "packets_per_second",
    "bytes_per_second",
)


class SecureTelemetryError(Exception):
    pass


class AnalysisNotFound(SecureTelemetryError):
    pass


class NoFlaggedAlert(SecureTelemetryError):
    pass


class ProtectionNotFound(SecureTelemetryError):
    pass


class KeyStorageUnavailable(SecureTelemetryError):
    pass


class EvidenceStorageUnavailable(SecureTelemetryError):
    pass


class CryptographyUnavailable(SecureTelemetryError):
    pass


class VerificationFailed(SecureTelemetryError):
    pass


class HybridArtifactExists(SecureTelemetryError):
    pass


class HybridCandidateCapacity(SecureTelemetryError):
    pass


class HybridEvaluationPending(SecureTelemetryError):
    pass


@dataclass(frozen=True)
class ProtectionStatus:
    protection_id: UUID
    status: Literal["protected"] = "protected"
    aes_gcm: Literal["protected"] = "protected"


@dataclass(frozen=True)
class VerificationStatus:
    protection_id: UUID
    verification: Literal["verified"] = "verified"
    aes_gcm: Literal["authenticated"] = "authenticated"
    sha256: Literal["verified"] = "verified"
    rsa_pss: Literal["valid"] = "valid"


@dataclass(frozen=True)
class TamperStatus:
    protection_id: UUID
    verification: Literal["rejected"] = "rejected"
    reason: Literal["tamper_detected"] = "tamper_detected"


@dataclass(frozen=True)
class BatchProtectionStatus:
    analysis_id: UUID
    protected_count: int


@dataclass(frozen=True)
class BatchVerificationStatus:
    analysis_id: UUID
    protected_count: int
    verified_count: int
    all_valid: Literal[True] = True


@dataclass(frozen=True)
class BatchTamperStatus:
    analysis_id: UUID
    protected_count: int
    tamper_rejected: Literal[True] = True


@dataclass(frozen=True)
class _Candidate:
    alerts: tuple[bytes, ...]
    created_at: float

    @property
    def alert(self) -> bytes | None:
        return self.alerts[0] if self.alerts else None


@dataclass(frozen=True)
class _HybridCandidate:
    alerts: tuple[bytes, ...]
    created_at: float
    ready: bool = False

@dataclass(frozen=True)
class _ProtectedRecord:
    envelope: dict[str, str]
    created_at: float


@dataclass(frozen=True)
class _BatchRecord:
    record_id: UUID
    envelope: dict[str, str]


@dataclass(frozen=True)
class _ProtectedBatch:
    records: tuple[_BatchRecord, ...]
    created_at: float
    verified_count: int = 0
    all_valid: bool = False
    tamper_rejected: bool = False


def _value(item: Any, field: str) -> Any:
    if isinstance(item, dict):
        return item[field]
    return getattr(item, field)


def canonical_alert_bytes(analysis_id: UUID, alert_index: int, result: Any) -> bytes:
    alert = {
        "schema_version": SCHEMA_VERSION,
        "analysis_id": str(analysis_id),
        "alert_index": alert_index,
        "flow": {field: _value(result, field) for field in FLOW_FIELDS},
        "anomaly_score": _value(result, "anomaly_score"),
        "risk_score": _value(result, "risk_score"),
        "risk_level": _value(result, "risk_level"),
        "alert_flagged": _value(result, "alert_flagged"),
        "explanations": list(_value(result, "explanations")),
    }
    return _canonical_json(alert)


def _canonical_json(value: object) -> bytes:
    return json.dumps(
        value,
        sort_keys=True,
        ensure_ascii=True,
        separators=(",", ":"),
    ).encode("utf-8")


class SecureTelemetryStore:
    def __init__(
        self,
        *,
        max_candidates: int = 32,
        max_records: int = 32,
        ttl_seconds: float = 900,
        key_directory: Path = Path("/app/demo-keys"),
        evidence_directory: Path = Path("/app/demo-evidence"),
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        self._max_candidates = max_candidates
        self._max_records = max_records
        self._ttl_seconds = ttl_seconds
        self._key_directory = Path(key_directory)
        self._evidence_directory = Path(evidence_directory)
        self._clock = clock
        self._lock = RLock()
        self._candidates: OrderedDict[UUID, _Candidate] = OrderedDict()
        self._records: OrderedDict[UUID, _ProtectedRecord] = OrderedDict()
        self._batches: OrderedDict[UUID, _ProtectedBatch] = OrderedDict()
        self._hybrid_candidates: OrderedDict[UUID, _HybridCandidate] = OrderedDict()
        self._hybrid_batches: OrderedDict[UUID, _ProtectedBatch] = OrderedDict()
        self._aes_key: bytes | None = None
        self._private_key: rsa.RSAPrivateKey | None = None
        self._public_key: rsa.RSAPublicKey | None = None
        self._positive_verified = False
        self._tampered_rejected = False

    def register_upload(self, analysis_id: UUID, results: Sequence[Any]) -> None:
        alerts: list[bytes] = []
        for index, result in enumerate(results):
            if (
                _value(result, "risk_level") == "High"
                and _value(result, "risk_score") == 90
                and _value(result, "alert_flagged") is True
            ):
                alerts.append(canonical_alert_bytes(analysis_id, index, result))
        with self._lock:
            self._purge_expired()
            self._candidates[analysis_id] = _Candidate(tuple(alerts), self._clock())
            self._candidates.move_to_end(analysis_id)
            self._trim(self._candidates, self._max_candidates)

    def protect_all_flagged(self, analysis_id: UUID) -> BatchProtectionStatus:
        with self._lock:
            self._purge_expired()
            candidate = self._candidates.get(analysis_id)
            if candidate is None:
                raise AnalysisNotFound
            if not candidate.alerts:
                raise NoFlaggedAlert
            existing = self._batches.get(analysis_id)
            if existing is not None:
                return BatchProtectionStatus(analysis_id, len(existing.records))

            self._ensure_keys()
            try:
                records = tuple(
                    self._protect_alert(alert)
                    for alert in candidate.alerts
                )
            except Exception as error:
                raise CryptographyUnavailable from error

            batch = _ProtectedBatch(records=records, created_at=self._clock())
            self._write_batch_document(analysis_id, batch)
            self._batches[analysis_id] = batch
            self._batches.move_to_end(analysis_id)
            self._trim(self._batches, self._max_records)
            return BatchProtectionStatus(analysis_id, len(records))

    def verify_all(self, analysis_id: UUID) -> BatchVerificationStatus:
        with self._lock:
            batch = self._get_batch(analysis_id)
            for record in batch.records:
                self._verify_envelope(record.envelope)
            verified = replace(
                batch,
                verified_count=len(batch.records),
                all_valid=True,
            )
            self._write_batch_document(analysis_id, verified)
            self._batches[analysis_id] = verified
            return BatchVerificationStatus(
                analysis_id,
                protected_count=len(verified.records),
                verified_count=verified.verified_count,
            )

    def verify_tampered_batch_copy(self, analysis_id: UUID) -> BatchTamperStatus:
        with self._lock:
            batch = self._get_batch(analysis_id)
            first = batch.records[0]
            altered = dict(first.envelope)
            ciphertext = bytearray(self._decode(altered["ciphertext"]))
            ciphertext[0] ^= 1
            altered["ciphertext"] = self._encode(bytes(ciphertext))
            try:
                self._verify_envelope(altered)
            except VerificationFailed:
                rejected = replace(batch, tamper_rejected=True)
                self._write_batch_document(analysis_id, rejected)
                self._batches[analysis_id] = rejected
                return BatchTamperStatus(analysis_id, len(rejected.records))
            raise CryptographyUnavailable

    def protect_first_flagged(self, analysis_id: UUID) -> ProtectionStatus:
        with self._lock:
            self._purge_expired()
            candidate = self._candidates.get(analysis_id)
            if candidate is None:
                raise AnalysisNotFound
            if candidate.alert is None:
                raise NoFlaggedAlert

            self._ensure_keys()
            protection_id = uuid4()
            nonce = os.urandom(12)
            associated_data = self._associated_data(protection_id)
            try:
                ciphertext = AESGCM(self._aes_key).encrypt(
                    nonce,
                    candidate.alert,
                    associated_data,
                )
                unsigned_envelope = {
                    "schema_version": SCHEMA_VERSION,
                    "algorithm": ALGORITHM,
                    "protection_id": str(protection_id),
                    "nonce": self._encode(nonce),
                    "ciphertext": self._encode(ciphertext),
                    "plaintext_digest": self._encode(
                        hashlib.sha256(candidate.alert).digest()
                    ),
                }
                envelope = dict(unsigned_envelope)
                envelope["signature"] = self._sign_envelope(unsigned_envelope)
            except Exception as error:
                raise CryptographyUnavailable from error

            self._positive_verified = False
            self._tampered_rejected = False
            self._write_evidence(candidate.alert, envelope)
            self._records[protection_id] = _ProtectedRecord(
                envelope=envelope,
                created_at=self._clock(),
            )
            self._records.move_to_end(protection_id)
            self._trim(self._records, self._max_records)
            return ProtectionStatus(protection_id=protection_id)

    def register_hybrid_candidate(
        self, analysis_id: UUID, findings: Sequence[dict[str, object]],
    ) -> None:
        """Reserve a separate v2 High-only batch without touching v1."""
        unique: dict[str, bytes] = {}
        for finding in findings:
            if finding.get("severity") != "High" or finding.get("telemetry_eligible") is not True:
                continue
            if finding.get("schema_version") != "phase7.finding.v1":
                raise ValueError("Incompatible finding schema.")
            if finding.get("analysis_id") != str(analysis_id):
                raise ValueError("Finding belongs to another analysis.")
            finding_id = str(UUID(str(finding["finding_id"])))
            plaintext = _canonical_json({
                "schema_version": HYBRID_SCHEMA_VERSION,
                "analysis_id": str(analysis_id),
                "finding": finding,
            })
            if finding_id in unique and unique[finding_id] != plaintext:
                raise ValueError("Conflicting duplicate finding identity.")
            unique[finding_id] = plaintext
        alerts = tuple(unique[key] for key in sorted(unique))
        with self._lock:
            self._purge_expired()
            existing = self._hybrid_candidates.get(analysis_id)
            if existing is not None:
                if existing.alerts != alerts:
                    raise ValueError("Hybrid candidate already registered differently.")
                return
            if len(self._hybrid_candidates) >= self._max_candidates:
                raise HybridCandidateCapacity
            self._hybrid_candidates[analysis_id] = _HybridCandidate(alerts, self._clock())

    def finalize_hybrid_candidate(self, analysis_id: UUID) -> None:
        """Publish the candidate only after the admission result is committed."""
        with self._lock:
            self._purge_expired()
            candidate = self._hybrid_candidates.get(analysis_id)
            if candidate is None:
                raise AnalysisNotFound
            self._hybrid_candidates[analysis_id] = replace(candidate, ready=True)
    def unregister_hybrid_candidate(self, analysis_id: UUID) -> None:
        with self._lock:
            if analysis_id not in self._hybrid_batches:
                self._hybrid_candidates.pop(analysis_id, None)

    def _hybrid_path(self, analysis_id: UUID) -> Path:
        return self._evidence_directory / f"protected-telemetry-v2-{analysis_id}.json"

    def _hybrid_aad(
        self, analysis_id: UUID, finding_id: UUID, record_id: UUID,
    ) -> bytes:
        return (
            f"NEXUS|{HYBRID_SCHEMA_VERSION}|{analysis_id}|{finding_id}|{record_id}"
        ).encode("ascii")

    def _protect_hybrid_finding(
        self, analysis_id: UUID, plaintext: bytes,
    ) -> _BatchRecord:
        finding_id = UUID(json.loads(plaintext)["finding"]["finding_id"])
        record_id = uuid4()
        nonce = os.urandom(12)
        ciphertext = AESGCM(self._aes_key).encrypt(
            nonce, plaintext, self._hybrid_aad(analysis_id, finding_id, record_id),
        )
        unsigned = {
            "schema_version": HYBRID_SCHEMA_VERSION,
            "algorithm": ALGORITHM,
            "analysis_id": str(analysis_id),
            "finding_id": str(finding_id),
            "record_id": str(record_id),
            "nonce": self._encode(nonce),
            "ciphertext": self._encode(ciphertext),
            "plaintext_digest": self._encode(hashlib.sha256(plaintext).digest()),
        }
        envelope = dict(unsigned)
        envelope["signature"] = self._sign_envelope(unsigned)
        return _BatchRecord(record_id, envelope)

    def _hybrid_document(
        self, analysis_id: UUID, batch: _ProtectedBatch,
    ) -> bytes:
        return _canonical_json({
            "schema_version": HYBRID_SCHEMA_VERSION,
            "analysis_id": str(analysis_id),
            "algorithm": ALGORITHM,
            "protected_count": len(batch.records),
            "records": [
                {"record_id": str(record.record_id), "envelope": record.envelope}
                for record in batch.records
            ],
        })

    def _atomic_create_hybrid(self, destination: Path, content: bytes) -> None:
        temporary_path: Path | None = None
        try:
            destination.parent.mkdir(parents=True, exist_ok=True)
            with NamedTemporaryFile(
                mode="wb", prefix=f".{destination.name}.", suffix=".tmp",
                dir=destination.parent, delete=False,
            ) as temporary:
                temporary_path = Path(temporary.name)
                temporary.write(content)
                temporary.flush()
                os.fsync(temporary.fileno())
            os.chmod(temporary_path, 0o600)
            os.link(temporary_path, destination)
        except FileExistsError as error:
            raise HybridArtifactExists from error
        except OSError as error:
            raise EvidenceStorageUnavailable from error
        finally:
            if temporary_path is not None:
                temporary_path.unlink(missing_ok=True)

    def protect_hybrid(self, analysis_id: UUID) -> BatchProtectionStatus:
        with self._lock:
            self._purge_expired()
            existing = self._hybrid_batches.get(analysis_id)
            if existing is not None:
                return BatchProtectionStatus(analysis_id, len(existing.records))
            candidate = self._hybrid_candidates.get(analysis_id)
            if candidate is None:
                raise AnalysisNotFound
            if not candidate.ready:
                raise HybridEvaluationPending
            if not candidate.alerts:
                raise NoFlaggedAlert
            if self._hybrid_path(analysis_id).exists():
                raise HybridArtifactExists
            self._ensure_keys()
            try:
                records = tuple(
                    self._protect_hybrid_finding(analysis_id, alert)
                    for alert in candidate.alerts
                )
            except Exception as error:
                raise CryptographyUnavailable from error
            batch = _ProtectedBatch(records, self._clock())
            self._atomic_create_hybrid(
                self._hybrid_path(analysis_id),
                self._hybrid_document(analysis_id, batch),
            )
            self._hybrid_batches[analysis_id] = batch
            return BatchProtectionStatus(analysis_id, len(records))

    def _get_hybrid_batch(self, analysis_id: UUID) -> _ProtectedBatch:
        self._purge_expired()
        batch = self._hybrid_batches.get(analysis_id)
        if batch is None:
            raise ProtectionNotFound
        return batch

    def _verify_hybrid_envelope(
        self, envelope: dict[str, str], analysis_id: UUID,
    ) -> None:
        if self._public_key is None or self._aes_key is None:
            raise VerificationFailed
        try:
            if envelope["schema_version"] != HYBRID_SCHEMA_VERSION:
                raise VerificationFailed
            if envelope["algorithm"] != ALGORITHM:
                raise VerificationFailed
            if UUID(envelope["analysis_id"]) != analysis_id:
                raise VerificationFailed
            unsigned = {
                key: value for key, value in envelope.items() if key != "signature"
            }
            self._public_key.verify(
                self._decode(envelope["signature"]),
                _canonical_json(unsigned),
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH,
                ),
                hashes.SHA256(),
            )
            finding_id = UUID(envelope["finding_id"])
            record_id = UUID(envelope["record_id"])
            plaintext = AESGCM(self._aes_key).decrypt(
                self._decode(envelope["nonce"]),
                self._decode(envelope["ciphertext"]),
                self._hybrid_aad(analysis_id, finding_id, record_id),
            )
            if not hmac.compare_digest(
                hashlib.sha256(plaintext).digest(),
                self._decode(envelope["plaintext_digest"]),
            ):
                raise VerificationFailed
            body = json.loads(plaintext)
            if (
                body["schema_version"] != HYBRID_SCHEMA_VERSION
                or body["analysis_id"] != str(analysis_id)
                or body["finding"]["finding_id"] != str(finding_id)
                or body["finding"]["schema_version"] != "phase7.finding.v1"
                or body["finding"]["severity"] != "High"
            ):
                raise VerificationFailed
        except VerificationFailed:
            raise
        except Exception as error:
            raise VerificationFailed from error

    def verify_hybrid(self, analysis_id: UUID) -> BatchVerificationStatus:
        with self._lock:
            batch = self._get_hybrid_batch(analysis_id)
            for record in batch.records:
                self._verify_hybrid_envelope(record.envelope, analysis_id)
            return BatchVerificationStatus(
                analysis_id, len(batch.records), len(batch.records),
            )

    def verify_hybrid_tampered_copy(self, analysis_id: UUID) -> BatchTamperStatus:
        with self._lock:
            batch = self._get_hybrid_batch(analysis_id)
            altered = dict(batch.records[0].envelope)
            ciphertext = bytearray(self._decode(altered["ciphertext"]))
            ciphertext[0] ^= 1
            altered["ciphertext"] = self._encode(bytes(ciphertext))
            try:
                self._verify_hybrid_envelope(altered, analysis_id)
            except VerificationFailed:
                return BatchTamperStatus(analysis_id, len(batch.records))
            raise CryptographyUnavailable

    def hybrid_status(self, analysis_id: UUID) -> dict[str, object]:
        with self._lock:
            self._purge_expired()
            if analysis_id in self._hybrid_batches:
                return {
                    "status": "protected",
                    "protected_count": len(self._hybrid_batches[analysis_id].records),
                }
            if analysis_id in self._hybrid_candidates:
                return {
                    "status": (
                        "not_requested" if self._hybrid_candidates[analysis_id].ready
                        else "preparing"
                    ),
                    "protected_count": 0,
                }
            raise AnalysisNotFound
    def _protect_alert(self, plaintext: bytes) -> _BatchRecord:
        record_id = uuid4()
        nonce = os.urandom(12)
        ciphertext = AESGCM(self._aes_key).encrypt(
            nonce,
            plaintext,
            self._associated_data(record_id),
        )
        unsigned_envelope = {
            "schema_version": SCHEMA_VERSION,
            "algorithm": ALGORITHM,
            "record_id": str(record_id),
            "nonce": self._encode(nonce),
            "ciphertext": self._encode(ciphertext),
            "plaintext_digest": self._encode(hashlib.sha256(plaintext).digest()),
        }
        envelope = dict(unsigned_envelope)
        envelope["signature"] = self._sign_envelope(unsigned_envelope)
        return _BatchRecord(record_id=record_id, envelope=envelope)

    def verify(self, protection_id: UUID) -> VerificationStatus:
        with self._lock:
            record = self._get_record(protection_id)
            self._verify_envelope(record.envelope)
            self._positive_verified = True
            self._write_verification_evidence()
            return VerificationStatus(protection_id=protection_id)

    def verify_tampered_copy(self, protection_id: UUID) -> TamperStatus:
        with self._lock:
            record = self._get_record(protection_id)
            altered = dict(record.envelope)
            ciphertext = bytearray(self._decode(altered["ciphertext"]))
            ciphertext[0] ^= 1
            altered["ciphertext"] = self._encode(bytes(ciphertext))
            try:
                self._verify_envelope(altered)
            except VerificationFailed:
                self._tampered_rejected = True
                self._write_verification_evidence()
                return TamperStatus(protection_id=protection_id)
            raise CryptographyUnavailable

    @staticmethod
    def _encode(value: bytes) -> str:
        return base64.b64encode(value).decode("ascii")

    @staticmethod
    def _decode(value: str) -> bytes:
        return base64.b64decode(value, validate=True)

    def _associated_data(self, protection_id: UUID) -> bytes:
        return f"NEXUS|{SCHEMA_VERSION}|{protection_id}".encode("ascii")

    def _sign_envelope(self, envelope: dict[str, str]) -> str:
        if self._private_key is None:
            raise CryptographyUnavailable
        unsigned = {key: value for key, value in envelope.items() if key != "signature"}
        signature = self._private_key.sign(
            _canonical_json(unsigned),
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH,
            ),
            hashes.SHA256(),
        )
        return self._encode(signature)

    def _verify_envelope(self, envelope: dict[str, str]) -> None:
        if self._public_key is None or self._aes_key is None:
            raise VerificationFailed
        try:
            signature = self._decode(envelope["signature"])
            unsigned = {
                key: value for key, value in envelope.items() if key != "signature"
            }
            self._public_key.verify(
                signature,
                _canonical_json(unsigned),
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH,
                ),
                hashes.SHA256(),
            )
            record_identifier = envelope.get("record_id")
            if record_identifier is None:
                record_identifier = envelope["protection_id"]
            record_id = UUID(record_identifier)
            plaintext = AESGCM(self._aes_key).decrypt(
                self._decode(envelope["nonce"]),
                self._decode(envelope["ciphertext"]),
                self._associated_data(record_id),
            )
            actual_digest = hashlib.sha256(plaintext).digest()
            expected_digest = self._decode(envelope["plaintext_digest"])
            if not hmac.compare_digest(actual_digest, expected_digest):
                raise VerificationFailed
        except VerificationFailed:
            raise
        except (InvalidSignature, InvalidTag, KeyError, TypeError, ValueError) as error:
            raise VerificationFailed from error

    def _ensure_keys(self) -> None:
        if (
            self._aes_key is not None
            and self._private_key is not None
            and self._public_key is not None
        ):
            return
        try:
            self._key_directory.mkdir(parents=True, exist_ok=True)
            aes_path = self._key_directory / "aes-demo.key"
            private_path = self._key_directory / "rsa-demo-private.pem"
            public_path = self._key_directory / "rsa-demo-public.pem"

            if aes_path.exists():
                aes_key = aes_path.read_bytes()
                if len(aes_key) != 32:
                    raise ValueError("invalid AES key")
            else:
                aes_key = AESGCM.generate_key(bit_length=256)
                self._atomic_write(aes_path, aes_key, 0o600, KeyStorageUnavailable)

            if private_path.exists():
                loaded = serialization.load_pem_private_key(
                    private_path.read_bytes(),
                    password=None,
                )
                if not isinstance(loaded, rsa.RSAPrivateKey) or loaded.key_size != 2048:
                    raise ValueError("invalid RSA private key")
                private_key = loaded
            else:
                if public_path.exists():
                    raise ValueError("orphan RSA public key")
                private_key = rsa.generate_private_key(
                    public_exponent=65537,
                    key_size=2048,
                )
                private_bytes = private_key.private_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PrivateFormat.PKCS8,
                    encryption_algorithm=serialization.NoEncryption(),
                )
                self._atomic_write(
                    private_path,
                    private_bytes,
                    0o600,
                    KeyStorageUnavailable,
                )

            public_key = private_key.public_key()
            expected_public = public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo,
            )
            if public_path.exists():
                loaded_public = serialization.load_pem_public_key(public_path.read_bytes())
                if not isinstance(loaded_public, rsa.RSAPublicKey):
                    raise ValueError("invalid RSA public key")
                actual_public = loaded_public.public_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PublicFormat.SubjectPublicKeyInfo,
                )
                if actual_public != expected_public:
                    raise ValueError("RSA key mismatch")
            else:
                self._atomic_write(
                    public_path,
                    expected_public,
                    0o644,
                    KeyStorageUnavailable,
                )

            self._aes_key = aes_key
            self._private_key = private_key
            self._public_key = public_key
        except KeyStorageUnavailable:
            raise
        except (OSError, TypeError, ValueError) as error:
            raise KeyStorageUnavailable from error

    def _write_evidence(self, plaintext: bytes, envelope: dict[str, str]) -> None:
        source_path = self._evidence_directory / "source-alert.json"
        protected_path = self._evidence_directory / "protected-alert.json"
        verification_path = self._evidence_directory / "verification-result.json"
        preexisting = {
            source_path: source_path.exists(),
            protected_path: protected_path.exists(),
            verification_path: verification_path.exists(),
        }
        published: list[Path] = []
        try:
            self._evidence_directory.mkdir(parents=True, exist_ok=True)
            self._atomic_write(
                source_path,
                plaintext,
                0o600,
                EvidenceStorageUnavailable,
            )
            published.append(source_path)
            self._atomic_write(
                protected_path,
                _canonical_json(envelope),
                0o600,
                EvidenceStorageUnavailable,
            )
            published.append(protected_path)
            self._atomic_write(
                verification_path,
                self._verification_evidence_bytes(),
                0o600,
                EvidenceStorageUnavailable,
            )
            published.append(verification_path)
        except EvidenceStorageUnavailable:
            self._remove_new_evidence(published, preexisting)
            raise
        except OSError as error:
            self._remove_new_evidence(published, preexisting)
            raise EvidenceStorageUnavailable from error

    def _write_verification_evidence(self) -> None:
        self._atomic_write(
            self._evidence_directory / "verification-result.json",
            self._verification_evidence_bytes(),
            0o600,
            EvidenceStorageUnavailable,
        )

    def _write_batch_document(
        self,
        analysis_id: UUID,
        batch: _ProtectedBatch,
    ) -> None:
        document = {
            "schema_version": SCHEMA_VERSION,
            "analysis_id": str(analysis_id),
            "algorithm": ALGORITHM,
            "protected_count": len(batch.records),
            "records": [
                {"record_id": str(record.record_id), "envelope": record.envelope}
                for record in batch.records
            ],
            "verification": {
                "verified_count": batch.verified_count,
                "all_valid": batch.all_valid,
                "tamper_rejected": batch.tamper_rejected,
            },
        }
        self._atomic_write(
            self._evidence_directory / f"protected-telemetry-{analysis_id}.json",
            _canonical_json(document),
            0o600,
            EvidenceStorageUnavailable,
        )

    def _verification_evidence_bytes(self) -> bytes:
        result = {
            "positive_verification": (
                "verified" if self._positive_verified else "not_run"
            ),
            "tampered_copy": (
                "rejected" if self._tampered_rejected else "not_run"
            ),
        }
        return _canonical_json(result)

    @staticmethod
    def _remove_new_evidence(
        published: Sequence[Path],
        preexisting: dict[Path, bool],
    ) -> None:
        for path in published:
            if not preexisting[path]:
                path.unlink(missing_ok=True)

    @staticmethod
    def _atomic_write(
        destination: Path,
        content: bytes,
        mode: int,
        error_type: type[SecureTelemetryError],
    ) -> None:
        temporary_path: Path | None = None
        try:
            destination.parent.mkdir(parents=True, exist_ok=True)
            with NamedTemporaryFile(
                mode="wb",
                prefix=f".{destination.name}.",
                suffix=".tmp",
                dir=destination.parent,
                delete=False,
            ) as temporary:
                temporary_path = Path(temporary.name)
                temporary.write(content)
                temporary.flush()
                os.fsync(temporary.fileno())
            os.chmod(temporary_path, mode)
            os.replace(temporary_path, destination)
            os.chmod(destination, mode)
        except OSError as error:
            if temporary_path is not None:
                temporary_path.unlink(missing_ok=True)
            raise error_type from error

    def _get_record(self, protection_id: UUID) -> _ProtectedRecord:
        self._purge_expired()
        record = self._records.get(protection_id)
        if record is None:
            raise ProtectionNotFound
        return record

    def _get_batch(self, analysis_id: UUID) -> _ProtectedBatch:
        self._purge_expired()
        batch = self._batches.get(analysis_id)
        if batch is None:
            raise ProtectionNotFound
        return batch

    def _purge_expired(self) -> None:
        cutoff = self._clock() - self._ttl_seconds
        for mapping in (self._candidates, self._records, self._batches, self._hybrid_candidates, self._hybrid_batches):
            expired = [key for key, item in mapping.items() if item.created_at <= cutoff]
            for key in expired:
                del mapping[key]

    @staticmethod
    def _trim(mapping: OrderedDict[UUID, Any], limit: int) -> None:
        while len(mapping) > limit:
            mapping.popitem(last=False)
