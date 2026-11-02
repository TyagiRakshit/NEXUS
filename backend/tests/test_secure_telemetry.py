import hashlib
import json
import os
import stat
from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
from pathlib import Path
from types import SimpleNamespace
from uuid import UUID, uuid4

import pytest
from cryptography.hazmat.primitives.asymmetric import rsa

from app.secure_telemetry import (
    AnalysisNotFound,
    EvidenceStorageUnavailable,
    KeyStorageUnavailable,
    NoFlaggedAlert,
    ProtectionNotFound,
    SecureTelemetryStore,
    VerificationFailed,
    canonical_alert_bytes,
)


def flagged_result(*, score: float = 0.641502) -> SimpleNamespace:
    return SimpleNamespace(
        protocol="ICMP",
        source_ip="192.0.2.10",
        source_port=None,
        destination_ip="198.51.100.20",
        destination_port=None,
        packet_count=2,
        byte_count=84,
        duration_seconds=0.1,
        packets_per_second=20.0,
        bytes_per_second=840.0,
        anomaly_score=score,
        is_statistically_unusual=True,
        risk_score=90,
        risk_level="High",
        alert_flagged=True,
        explanations=("Packet rate is above the synthetic normal range.",),
    )


def low_result() -> SimpleNamespace:
    result = flagged_result(score=0.5)
    result.risk_score = 20
    result.risk_level = "Low"
    result.alert_flagged = False
    result.is_statistically_unusual = False
    return result


def make_store(tmp_path: Path, **kwargs: object) -> SecureTelemetryStore:
    return SecureTelemetryStore(
        key_directory=tmp_path / "keys",
        evidence_directory=tmp_path / "evidence",
        **kwargs,
    )


def test_canonical_alert_bytes_are_stable_and_exact(tmp_path: Path) -> None:
    analysis_id = UUID("11111111-1111-4111-8111-111111111111")

    first = canonical_alert_bytes(analysis_id, 2, flagged_result())
    second = canonical_alert_bytes(analysis_id, 2, flagged_result())
    body = json.loads(first)

    assert first == second
    assert first == json.dumps(
        body,
        sort_keys=True,
        ensure_ascii=True,
        separators=(",", ":"),
    ).encode("utf-8")
    assert set(body) == {
        "schema_version",
        "analysis_id",
        "alert_index",
        "flow",
        "anomaly_score",
        "risk_score",
        "risk_level",
        "alert_flagged",
        "explanations",
    }
    assert set(body["flow"]) == {
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
    }


def test_protection_uses_fresh_12_byte_nonce_and_verifies(tmp_path: Path) -> None:
    store = make_store(tmp_path)
    analysis_id = uuid4()
    store.register_upload(analysis_id, [flagged_result()])

    first = store.protect_first_flagged(analysis_id)
    first_nonce = store._records[first.protection_id].envelope["nonce"]
    second = store.protect_first_flagged(analysis_id)
    second_nonce = store._records[second.protection_id].envelope["nonce"]

    assert first_nonce != second_nonce
    assert len(store._decode(first_nonce)) == 12
    assert store.verify(first.protection_id).verification == "verified"
    assert store.verify_tampered_copy(first.protection_id).verification == "rejected"
    assert store.verify(first.protection_id).verification == "verified"


@pytest.mark.parametrize("field", ["ciphertext", "plaintext_digest", "algorithm"])
def test_altered_signed_envelope_fields_fail_verification(
    tmp_path: Path,
    field: str,
) -> None:
    store = make_store(tmp_path)
    analysis_id = uuid4()
    store.register_upload(analysis_id, [flagged_result()])
    status = store.protect_first_flagged(analysis_id)
    record = store._records[status.protection_id]
    altered = dict(record.envelope)
    altered[field] = "changed"
    store._records[status.protection_id] = replace(record, envelope=altered)

    with pytest.raises(VerificationFailed):
        store.verify(status.protection_id)


def test_wrong_public_key_and_digest_mismatch_fail(tmp_path: Path) -> None:
    store = make_store(tmp_path)
    analysis_id = uuid4()
    store.register_upload(analysis_id, [flagged_result()])
    status = store.protect_first_flagged(analysis_id)

    store._public_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    ).public_key()
    with pytest.raises(VerificationFailed):
        store.verify(status.protection_id)

    store = make_store(tmp_path / "second")
    store.register_upload(analysis_id, [flagged_result()])
    status = store.protect_first_flagged(analysis_id)
    record = store._records[status.protection_id]
    altered = dict(record.envelope)
    altered["plaintext_digest"] = store._encode(hashlib.sha256(b"other").digest())
    altered["signature"] = store._sign_envelope(altered)
    store._records[status.protection_id] = replace(record, envelope=altered)
    with pytest.raises(VerificationFailed):
        store.verify(status.protection_id)


def test_signature_failure_stops_before_decryption(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    store = make_store(tmp_path)
    analysis_id = uuid4()
    store.register_upload(analysis_id, [flagged_result()])
    status = store.protect_first_flagged(analysis_id)
    record = store._records[status.protection_id]
    altered = dict(record.envelope)
    altered["signature"] = store._encode(b"invalid")
    store._records[status.protection_id] = replace(record, envelope=altered)

    def must_not_decrypt(*args: object, **kwargs: object) -> bytes:
        raise AssertionError("AES-GCM decrypt ran before signature verification")

    monkeypatch.setattr("app.secure_telemetry.AESGCM.decrypt", must_not_decrypt)
    with pytest.raises(VerificationFailed):
        store.verify(status.protection_id)


def test_no_flagged_result_is_registered_without_creating_artifacts(
    tmp_path: Path,
) -> None:
    store = make_store(tmp_path)
    analysis_id = uuid4()
    store.register_upload(analysis_id, [low_result()])

    with pytest.raises(NoFlaggedAlert):
        store.protect_first_flagged(analysis_id)
    assert not (tmp_path / "keys").exists()
    assert not (tmp_path / "evidence").exists()


def test_store_bounds_expiry_and_restart_loss(tmp_path: Path) -> None:
    now = [100.0]
    store = make_store(
        tmp_path,
        max_candidates=2,
        max_records=2,
        ttl_seconds=10,
        clock=lambda: now[0],
    )
    analysis_ids = [uuid4(), uuid4(), uuid4()]
    for analysis_id in analysis_ids:
        store.register_upload(analysis_id, [flagged_result()])
    with pytest.raises(AnalysisNotFound):
        store.protect_first_flagged(analysis_ids[0])

    statuses = [store.protect_first_flagged(item) for item in analysis_ids[1:]]
    store.protect_first_flagged(analysis_ids[1])
    with pytest.raises(ProtectionNotFound):
        store.verify(statuses[0].protection_id)

    now[0] = 111.0
    with pytest.raises(AnalysisNotFound):
        store.protect_first_flagged(analysis_ids[2])
    with pytest.raises(ProtectionNotFound):
        store.verify(statuses[1].protection_id)

    restarted = make_store(tmp_path)
    with pytest.raises(ProtectionNotFound):
        restarted.verify(statuses[1].protection_id)


def test_artifacts_have_expected_names_modes_and_safe_verification_evidence(
    tmp_path: Path,
) -> None:
    store = make_store(tmp_path)
    analysis_id = uuid4()
    store.register_upload(analysis_id, [flagged_result()])
    status = store.protect_first_flagged(analysis_id)
    store.verify(status.protection_id)
    store.verify_tampered_copy(status.protection_id)

    expected = {
        tmp_path / "keys" / "aes-demo.key": 0o600,
        tmp_path / "keys" / "rsa-demo-private.pem": 0o600,
        tmp_path / "keys" / "rsa-demo-public.pem": 0o644,
        tmp_path / "evidence" / "source-alert.json": 0o600,
        tmp_path / "evidence" / "protected-alert.json": 0o600,
        tmp_path / "evidence" / "verification-result.json": 0o600,
    }
    assert set(expected) == set((tmp_path / "keys").iterdir()) | set(
        (tmp_path / "evidence").iterdir()
    )
    for path, mode in expected.items():
        assert stat.S_IMODE(path.stat().st_mode) == mode
    result = json.loads(
        (tmp_path / "evidence" / "verification-result.json").read_text()
    )
    assert result == {
        "positive_verification": "verified",
        "tampered_copy": "rejected",
    }


def test_atomic_evidence_failure_cleans_temporary_files_and_publishes_nothing(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    store = make_store(tmp_path)
    analysis_id = uuid4()
    store.register_upload(analysis_id, [flagged_result()])
    real_replace = os.replace

    def fail_evidence_replace(source: Path, destination: Path) -> None:
        if Path(destination).name == "protected-alert.json":
            raise OSError("injected write failure")
        real_replace(source, destination)

    monkeypatch.setattr("app.secure_telemetry.os.replace", fail_evidence_replace)
    with pytest.raises(EvidenceStorageUnavailable):
        store.protect_first_flagged(analysis_id)
    assert store._records == {}
    assert list((tmp_path / "evidence").iterdir()) == []


def test_malformed_existing_key_fails_closed(tmp_path: Path) -> None:
    key_directory = tmp_path / "keys"
    key_directory.mkdir()
    (key_directory / "aes-demo.key").write_bytes(b"not-32-bytes")
    store = make_store(tmp_path)
    analysis_id = uuid4()
    store.register_upload(analysis_id, [flagged_result()])

    with pytest.raises(KeyStorageUnavailable):
        store.protect_first_flagged(analysis_id)
    assert (key_directory / "aes-demo.key").read_bytes() == b"not-32-bytes"


def test_batch_protection_keeps_each_flagged_alert_independent_and_verifiable(
    tmp_path: Path,
) -> None:
    store = make_store(tmp_path)
    analysis_id = uuid4()
    store.register_upload(
        analysis_id,
        [low_result(), flagged_result(), flagged_result(score=0.65)],
    )

    protected = store.protect_all_flagged(analysis_id)

    assert protected.analysis_id == analysis_id
    assert protected.protected_count == 2
    batch = store._batches[analysis_id]
    assert len(batch.records) == 2
    assert len({record.record_id for record in batch.records}) == 2
    assert len(
        {store._decode(record.envelope["nonce"]) for record in batch.records}
    ) == 2
    assert all(
        len(store._decode(record.envelope["nonce"])) == 12
        for record in batch.records
    )

    document_path = tmp_path / "evidence" / f"protected-telemetry-{analysis_id}.json"
    document = json.loads(document_path.read_text())
    assert set(document) == {
        "schema_version",
        "analysis_id",
        "algorithm",
        "protected_count",
        "records",
        "verification",
    }
    assert document["analysis_id"] == str(analysis_id)
    assert document["protected_count"] == 2
    assert len(document["records"]) == 2
    assert set(document["verification"]) == {
        "verified_count",
        "all_valid",
        "tamper_rejected",
    }
    assert stat.S_IMODE(document_path.stat().st_mode) == 0o600
    assert "plaintext" not in document
    assert "aes_key" not in document
    assert "private_key" not in document

    verified = store.verify_all(analysis_id)
    assert verified.verified_count == 2
    assert verified.all_valid is True
    assert store.verify_tampered_batch_copy(analysis_id).tamper_rejected is True
    assert store.verify_all(analysis_id).all_valid is True


def test_batch_protection_of_one_flagged_alert_returns_one_safe_record(
    tmp_path: Path,
) -> None:
    store = make_store(tmp_path)
    analysis_id = uuid4()
    store.register_upload(analysis_id, [flagged_result()])

    protected = store.protect_all_flagged(analysis_id)
    verified = store.verify_all(analysis_id)

    assert protected.protected_count == 1
    assert verified.protected_count == 1
    assert verified.verified_count == 1
    assert verified.all_valid is True


def test_batch_protection_rejects_empty_expired_and_unknown_analyses_without_file(
    tmp_path: Path,
) -> None:
    now = [100.0]
    store = make_store(tmp_path, ttl_seconds=10, clock=lambda: now[0])
    empty_id = uuid4()
    store.register_upload(empty_id, [low_result()])

    with pytest.raises(NoFlaggedAlert):
        store.protect_all_flagged(empty_id)
    assert list((tmp_path / "evidence").glob("protected-telemetry-*.json")) == []

    expired_id = uuid4()
    store.register_upload(expired_id, [flagged_result()])
    now[0] = 111.0
    with pytest.raises(AnalysisNotFound):
        store.protect_all_flagged(expired_id)
    with pytest.raises(ProtectionNotFound):
        store.verify_all(uuid4())


def test_batch_protection_write_failure_cleans_temporary_file_and_publishes_nothing(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    store = make_store(tmp_path)
    analysis_id = uuid4()
    store.register_upload(analysis_id, [flagged_result(), flagged_result(score=0.65)])
    real_replace = os.replace

    def fail_batch_replace(source: Path, destination: Path) -> None:
        if Path(destination).name.startswith("protected-telemetry-"):
            raise OSError("injected batch write failure")
        real_replace(source, destination)

    monkeypatch.setattr("app.secure_telemetry.os.replace", fail_batch_replace)
    with pytest.raises(EvidenceStorageUnavailable):
        store.protect_all_flagged(analysis_id)
    assert analysis_id not in store._batches
    assert list((tmp_path / "evidence").glob("protected-telemetry-*.json")) == []
    assert list((tmp_path / "evidence").glob("*.tmp")) == []


def test_concurrent_batch_protection_publishes_one_consistent_analysis_document(
    tmp_path: Path,
) -> None:
    store = make_store(tmp_path)
    analysis_id = uuid4()
    store.register_upload(analysis_id, [flagged_result(), flagged_result(score=0.65)])

    with ThreadPoolExecutor(max_workers=4) as executor:
        statuses = list(
            executor.map(lambda _: store.protect_all_flagged(analysis_id), range(4))
        )

    assert {status.protected_count for status in statuses} == {2}
    assert len(store._batches) == 1
    assert len(list((tmp_path / "evidence").glob("protected-telemetry-*.json"))) == 1

def test_v2_high_findings_coexist_with_exact_v1_batch_and_reject_tamper(
    tmp_path: Path,
) -> None:
    store = make_store(tmp_path)
    analysis_id = uuid4()
    finding_id = uuid4()
    store.register_upload(analysis_id, [flagged_result()])
    v1 = store.protect_all_flagged(analysis_id)
    v1_path = tmp_path / "evidence" / f"protected-telemetry-{analysis_id}.json"
    v1_bytes = v1_path.read_bytes()

    high = {
        "schema_version": "phase7.finding.v1",
        "analysis_id": str(analysis_id),
        "finding_id": str(finding_id),
        "severity": "High",
        "telemetry_eligible": True,
        "detection_source": "security_rule",
        "kind": "RULE_MATCH",
        "subject_host_ips": ["192.0.2.10"],
        "flow_indices": [0],
        "possible_category": "possible_host_recon",
        "evidence": [{"metric": "peer_count", "observed": 5}],
    }
    medium = {
        **high, "finding_id": str(uuid4()), "severity": "Medium",
        "telemetry_eligible": False,
    }
    store.register_hybrid_candidate(analysis_id, [high, high, medium])
    store.finalize_hybrid_candidate(analysis_id)
    v2 = store.protect_hybrid(analysis_id)
    v2_path = tmp_path / "evidence" / f"protected-telemetry-v2-{analysis_id}.json"
    original_v2 = v2_path.read_bytes()
    assert v1.protected_count == 1
    assert v2.protected_count == 1
    assert json.loads(original_v2)["schema_version"] == "phase7.secure-telemetry.v2"
    assert v1_path.read_bytes() == v1_bytes
    assert store.protect_hybrid(analysis_id) == v2
    assert v2_path.read_bytes() == original_v2
    assert store.verify_hybrid(analysis_id).verified_count == 1
    assert store.verify_hybrid_tampered_copy(analysis_id).tamper_rejected is True
    assert store.verify_hybrid(analysis_id).verified_count == 1
    assert v2_path.read_bytes() == original_v2

def _v2_finding(analysis_id: UUID, finding_id: UUID) -> dict[str, object]:
    return {
        "schema_version": "phase7.finding.v1",
        "analysis_id": str(analysis_id),
        "finding_id": str(finding_id),
        "severity": "High",
        "telemetry_eligible": True,
        "detection_source": "security_rule",
        "kind": "RULE_MATCH",
        "subject_host_ips": ["192.0.2.10"],
        "flow_indices": [0],
        "possible_category": "possible_host_recon",
        "evidence": [{"metric": "peer_count", "observed": 5}],
    }


def test_v2_signed_metadata_digest_ciphertext_and_version_tamper_reject(
    tmp_path: Path,
) -> None:
    store = make_store(tmp_path)
    analysis_id = uuid4()
    store.register_hybrid_candidate(
        analysis_id, [_v2_finding(analysis_id, uuid4())],
    )
    store.finalize_hybrid_candidate(analysis_id)
    store.protect_hybrid(analysis_id)
    envelope = store._hybrid_batches[analysis_id].records[0].envelope
    for field, replacement in (
        ("finding_id", str(uuid4())),
        ("schema_version", "phase7.secure-telemetry.v3"),
        ("plaintext_digest", "AAAA"),
        ("ciphertext", "AAAA"),
        ("signature", "AAAA"),
    ):
        altered = dict(envelope)
        altered[field] = replacement
        with pytest.raises(VerificationFailed):
            store._verify_hybrid_envelope(altered, analysis_id)
    assert store.verify_hybrid(analysis_id).all_valid is True


def test_v2_never_overwrites_existing_artifact_after_memory_expiry(
    tmp_path: Path,
) -> None:
    from app.secure_telemetry import HybridArtifactExists

    now = [0.0]
    store = make_store(tmp_path, clock=lambda: now[0], ttl_seconds=1.0)
    analysis_id = uuid4()
    finding = _v2_finding(analysis_id, uuid4())
    store.register_hybrid_candidate(analysis_id, [finding])
    store.finalize_hybrid_candidate(analysis_id)
    store.protect_hybrid(analysis_id)
    path = tmp_path / "evidence" / f"protected-telemetry-v2-{analysis_id}.json"
    before = path.read_bytes()
    now[0] = 2.0
    store.register_hybrid_candidate(analysis_id, [finding])
    store.finalize_hybrid_candidate(analysis_id)
    with pytest.raises(HybridArtifactExists):
        store.protect_hybrid(analysis_id)
    assert path.read_bytes() == before

def test_v2_candidate_cannot_be_protected_before_admission_finalizes(
    tmp_path: Path,
) -> None:
    store = make_store(tmp_path)
    analysis_id = uuid4()
    store.register_hybrid_candidate(
        analysis_id, [_v2_finding(analysis_id, uuid4())],
    )
    with pytest.raises(Exception):
        store.protect_hybrid(analysis_id)
    assert not (tmp_path / "evidence" /
                f"protected-telemetry-v2-{analysis_id}.json").exists()
    store.finalize_hybrid_candidate(analysis_id)
    assert store.protect_hybrid(analysis_id).protected_count == 1
