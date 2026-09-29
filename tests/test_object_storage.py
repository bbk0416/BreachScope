from __future__ import annotations

import asyncio
import base64
import hashlib
import io
import json
import shutil
import tempfile
from contextlib import contextmanager
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

import api.routers.cases as cases_router_module
from api.main import app
from api.security import SESSION_COOKIE_NAME, create_session_token
from api.services.artifact_encryption import encrypt_tree, read_artifact_bytes
from api.services.case_history import CaseHistoryService
from api.services.object_storage import (
    LEGACY_OBJECT_STORAGE_SCHEMA,
    OBJECT_STORAGE_NAMESPACE_VERSION,
    OBJECT_STORAGE_SCHEMA,
    ObjectStorageConfig,
    ObjectStorageError,
    ObjectStorageService,
)


class FakeS3:
    def __init__(self, fail_upload_number: int | None = None):
        self.objects: dict[tuple[str, str], bytes] = {}
        self.calls: list[tuple[str, str]] = []
        self.fail_upload_number = fail_upload_number
        self.upload_count = 0

    def upload_fileobj(self, handle, bucket: str, key: str) -> None:
        self.upload_count += 1
        if self.fail_upload_number == self.upload_count:
            raise RuntimeError("simulated upload failure")
        self.objects[(bucket, key)] = handle.read()
        self.calls.append(("upload", key))

    def put_object(self, *, Bucket: str, Key: str, Body, **kwargs):
        data = Body.read() if hasattr(Body, "read") else Body
        self.objects[(Bucket, Key)] = bytes(data)
        self.calls.append(("put", Key))
        return {"ETag": "fake"}

    def get_object(self, *, Bucket: str, Key: str):
        try:
            data = self.objects[(Bucket, Key)]
        except KeyError as exc:
            raise RuntimeError(f"missing object: {Key}") from exc
        return {"Body": io.BytesIO(data)}

    def download_fileobj(self, bucket: str, key: str, handle) -> None:
        try:
            data = self.objects[(bucket, key)]
        except KeyError as exc:
            raise RuntimeError(f"missing object: {key}") from exc
        handle.write(data)
        self.calls.append(("download", key))

    def delete_object(self, *, Bucket: str, Key: str):
        self.objects.pop((Bucket, Key), None)
        self.calls.append(("delete", Key))
        return {}


def _key(seed: int = 0) -> str:
    raw = bytes(((i + seed) % 256) for i in range(32))
    return base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")


def _config() -> ObjectStorageConfig:
    return ObjectStorageConfig(
        provider="s3",
        bucket="breachscope-test",
        prefix="breachscope/cases",
        region=None,
        endpoint_url=None,
    )


def _sample_report() -> dict:
    return {
        "summary": {
            "total_findings": 1,
            "risk": {"score": 55, "level": "medium"},
            "host_risk_summary": [
                {
                    "host": "WS-OBJ",
                    "score": 55,
                    "level": "medium",
                    "findings": 1,
                }
            ],
            "mitre_counts": {"T1059.001": 1},
        }
    }


def _encrypted_case(
    tmp_path: Path,
    monkeypatch,
    name: str = "object-case",
) -> tuple[Path, bytes]:
    cases_root = tmp_path / "cases"
    work = cases_root / name
    (work / "out").mkdir(parents=True)
    (work / "input").mkdir(parents=True)
    report_bytes = (
        json.dumps(_sample_report(), ensure_ascii=False).encode("utf-8") + b"\n"
    )
    (work / "out" / "report.json").write_bytes(report_bytes)
    (work / "out" / "report.html").write_text(
        "<html>remote</html>",
        encoding="utf-8",
    )
    (work / "input" / "events.jsonl").write_text(
        '{"event":"test"}\n',
        encoding="utf-8",
    )
    monkeypatch.setenv("BS_CASES_ROOT", str(cases_root))
    monkeypatch.setenv("BS_ARTIFACT_ENCRYPTION_KEY", _key())
    encrypt_tree(work)
    assert all(
        path.name.endswith(".enc")
        for path in work.rglob("*")
        if path.is_file()
    )
    return work, report_bytes


def test_object_storage_round_trip_restore_and_delete(
    tmp_path: Path,
    monkeypatch,
) -> None:
    work, report_bytes = _encrypted_case(tmp_path, monkeypatch)
    fake = FakeS3()
    service = ObjectStorageService(_config(), client=fake)

    remote = service.replicate_case("case-object-1", work)

    assert remote["file_count"] == 3
    assert remote["client_side_encryption"] == "AES-256-GCM"
    assert remote["manifest_key"].endswith("/case_manifest.json")
    assert fake.calls[-1] == ("put", remote["manifest_key"])

    shutil.rmtree(work)
    assert not work.exists()

    restored = service.restore_case(
        "case-object-1",
        work,
        remote,
    )
    assert restored["verified"] is True
    assert restored["file_count"] == 3
    assert restored["manifest_sha256"] == remote["manifest_sha256"]
    assert read_artifact_bytes(
        work / "out" / "report.json",
        work,
    ) == report_bytes

    deleted = service.delete_replica("case-object-1", remote)
    assert deleted["deleted_object_count"] == 4
    assert fake.objects == {}


def test_object_storage_verify_replica_full_restore_keeps_local_case(
    tmp_path: Path,
    monkeypatch,
) -> None:
    work, report_bytes = _encrypted_case(
        tmp_path,
        monkeypatch,
        "verify-case",
    )
    fake = FakeS3()
    service = ObjectStorageService(_config(), client=fake)
    remote = service.replicate_case("case-verify", work)

    result = service.verify_replica(
        "case-verify",
        remote,
    )

    assert result["verified"] is True
    assert result["file_count"] == 3
    assert result["manifest_sha256"] == remote["manifest_sha256"]
    assert work.exists()
    assert read_artifact_bytes(
        work / "out" / "report.json",
        work,
    ) == report_bytes


def test_object_storage_verify_replica_tamper_keeps_local_case(
    tmp_path: Path,
    monkeypatch,
) -> None:
    work, _ = _encrypted_case(
        tmp_path,
        monkeypatch,
        "verify-tamper-case",
    )
    fake = FakeS3()
    service = ObjectStorageService(_config(), client=fake)
    remote = service.replicate_case(
        "case-verify-tamper",
        work,
    )
    manifest = json.loads(
        fake.objects[(_config().bucket, remote["manifest_key"])].decode(
            "utf-8"
        )
    )
    first_key = manifest["files"][0]["object_key"]
    fake.objects[(_config().bucket, first_key)] += b"tamper"

    with pytest.raises(
        ObjectStorageError,
        match="size mismatch|SHA-256 mismatch",
    ):
        service.verify_replica(
            "case-verify-tamper",
            remote,
        )

    assert work.exists()


def test_object_storage_rejects_plaintext_case(
    tmp_path: Path,
    monkeypatch,
) -> None:
    cases_root = tmp_path / "cases"
    work = cases_root / "plain-case"
    work.mkdir(parents=True)
    (work / "report.json").write_text("{}\n", encoding="utf-8")
    monkeypatch.setenv("BS_CASES_ROOT", str(cases_root))
    monkeypatch.setenv("BS_ARTIFACT_ENCRYPTION_KEY", _key())

    service = ObjectStorageService(_config(), client=FakeS3())
    with pytest.raises(ObjectStorageError, match="Plaintext"):
        service.replicate_case("case-plain", work)


def test_object_storage_upload_failure_cleans_partial_objects(
    tmp_path: Path,
    monkeypatch,
) -> None:
    work, _ = _encrypted_case(tmp_path, monkeypatch, "failure-case")
    fake = FakeS3(fail_upload_number=2)
    service = ObjectStorageService(_config(), client=fake)

    with pytest.raises(ObjectStorageError, match="replication failed"):
        service.replicate_case("case-failure", work)

    assert fake.objects == {}
    assert work.exists()
    assert all(
        path.name.endswith(".enc")
        for path in work.rglob("*")
        if path.is_file()
    )


def test_object_storage_restore_rejects_tampered_object(
    tmp_path: Path,
    monkeypatch,
) -> None:
    work, _ = _encrypted_case(tmp_path, monkeypatch, "tamper-case")
    fake = FakeS3()
    service = ObjectStorageService(_config(), client=fake)
    remote = service.replicate_case("case-tamper", work)

    manifest = json.loads(
        fake.objects[(_config().bucket, remote["manifest_key"])].decode("utf-8")
    )
    first_key = manifest["files"][0]["object_key"]
    fake.objects[(_config().bucket, first_key)] += b"tamper"

    shutil.rmtree(work)
    with pytest.raises(
        ObjectStorageError,
        match="size mismatch|SHA-256 mismatch",
    ):
        service.restore_case("case-tamper", work, remote)

    assert not work.exists()


def test_object_storage_restore_requires_explicit_overwrite(
    tmp_path: Path,
    monkeypatch,
) -> None:
    work, _ = _encrypted_case(tmp_path, monkeypatch, "existing-case")
    service = ObjectStorageService(_config(), client=FakeS3())
    remote = service.replicate_case("case-existing", work)

    with pytest.raises(ObjectStorageError, match="overwrite=true"):
        service.restore_case(
            "case-existing",
            work,
            remote,
            overwrite=False,
        )


def test_case_history_tracks_object_storage_state(
    tmp_path: Path,
    monkeypatch,
) -> None:
    work, _ = _encrypted_case(tmp_path, monkeypatch, "history-case")
    monkeypatch.setenv(
        "BS_CASE_HISTORY_PATH",
        str(tmp_path / "case_history.json"),
    )
    history = CaseHistoryService()
    record = history.register_case(work, _sample_report())
    remote = {
        "provider": "s3",
        "bucket": "breachscope-test",
        "manifest_key": "breachscope/cases/case/manifest.json",
        "manifest_sha256": "a" * 64,
        "replicated_at": "2026-09-27T00:00:00Z",
    }

    updated = history.set_object_storage_state(
        record.case_id,
        remote,
        updated_by="operator",
    )
    assert updated["object_storage"]["bucket"] == "breachscope-test"
    assert updated["object_storage"]["updated_by"] == "operator"

    restored = history.mark_object_storage_restored(
        record.case_id,
        restored_at="2026-09-27T01:00:00Z",
        restored_by="operator",
    )
    assert restored["object_storage"]["restore_count"] == 1
    assert restored["object_storage"]["last_restored_by"] == "operator"

    cleared = history.clear_object_storage_state(record.case_id)
    assert cleared["object_storage"] is None


def _archived_remote_case(
    tmp_path: Path,
    monkeypatch,
    name: str,
):
    work, report_bytes = _encrypted_case(
        tmp_path,
        monkeypatch,
        name,
    )
    monkeypatch.setenv(
        "BS_CASE_HISTORY_PATH",
        str(tmp_path / f"{name}-history.json"),
    )
    monkeypatch.setenv(
        "BS_AUDIT_LOG_PATH",
        str(tmp_path / f"{name}-audit.jsonl"),
    )
    history = CaseHistoryService()
    record = history.register_case(work, _sample_report())
    fake = FakeS3()
    service = ObjectStorageService(_config(), client=fake)
    remote = service.replicate_case(
        record.case_id,
        work,
        organization_id="default",
    )
    history.set_object_storage_state(
        record.case_id,
        remote,
        updated_by="operator",
    )
    archived = history.archive_local_case(
        record.case_id,
        expected_manifest_sha256=remote["manifest_sha256"],
    )
    assert archived["archived"] is True
    assert not work.exists()
    monkeypatch.setattr(
        cases_router_module,
        "_object_storage_service",
        lambda: service,
    )
    return record, work, report_bytes, fake, service, history


def test_object_storage_temporary_case_cleans_verified_workspace(
    tmp_path: Path,
    monkeypatch,
) -> None:
    work, report_bytes = _encrypted_case(
        tmp_path,
        monkeypatch,
        "temporary-read-case",
    )
    fake = FakeS3()
    service = ObjectStorageService(_config(), client=fake)
    remote = service.replicate_case(
        "case-temporary-read",
        work,
        organization_id="default",
    )

    with service.temporary_case(
        "case-temporary-read",
        remote,
        organization_id="default",
    ) as (temporary, restored):
        assert temporary.exists()
        assert restored["verified"] is True
        assert read_artifact_bytes(
            temporary / "out" / "report.json",
            temporary,
        ) == report_bytes

    assert not temporary.exists()
    assert work.exists()


def test_archived_case_remote_preview_and_report_without_persistent_restore(
    tmp_path: Path,
    monkeypatch,
) -> None:
    (
        record,
        work,
        report_bytes,
        _fake,
        service,
        history,
    ) = _archived_remote_case(
        tmp_path,
        monkeypatch,
        "remote-primary-case",
    )

    created_temporary: list[Path] = []
    verified_manifest_sha256: list[str] = []
    original_materialize = service.materialize_temporary_case

    def capture_materialize(*args, **kwargs):
        target, result = original_materialize(*args, **kwargs)
        created_temporary.append(target)
        verified_manifest_sha256.append(
            str(result.get("manifest_sha256") or "")
        )
        return target, result

    monkeypatch.setattr(
        service,
        "materialize_temporary_case",
        capture_materialize,
    )
    reviewer = _rbac_client(tmp_path, monkeypatch, "reviewer")

    detail = reviewer.get(f"/api/cases/{record.case_id}")
    assert detail.status_code == 200, detail.text
    payload = detail.json()
    assert payload["case"]["exists"] is False
    assert payload["preview_source"] == "object_storage"
    assert payload["preview"]["total_findings"] == 1
    assert not work.exists()
    assert created_temporary
    assert all(not path.exists() for path in created_temporary)

    report = reviewer.get(
        f"/api/cases/{record.case_id}/report",
        params={"file_type": "json"},
    )
    assert report.status_code == 200, report.text
    assert report.content == report_bytes
    assert report.headers["x-breachscope-artifact-source"] == (
        "object_storage"
    )
    assert not work.exists()
    assert all(not path.exists() for path in created_temporary)

    missing_report = reviewer.get(
        f"/api/cases/{record.case_id}/report",
        params={"file_type": "pdf"},
    )
    assert missing_report.status_code == 404
    assert not work.exists()
    assert all(not path.exists() for path in created_temporary)

    current = history.get_case(record.case_id)
    assert current["exists"] is False
    assert int(
        (current.get("object_storage") or {}).get("restore_count") or 0
    ) == 0

    audit_rows = [
        json.loads(line)
        for line in (
            tmp_path / "remote-primary-case-audit.jsonl"
        ).read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]
    remote_reads = [
        row
        for row in audit_rows
        if row.get("action") == "case.object_storage.read"
    ]
    assert [
        (row.get("details") or {}).get("mode")
        for row in remote_reads
    ] == ["preview", "report"]


def test_archived_case_remote_preview_tamper_fails_closed_and_keeps_archived(
    tmp_path: Path,
    monkeypatch,
) -> None:
    (
        record,
        work,
        _report_bytes,
        fake,
        service,
        history,
    ) = _archived_remote_case(
        tmp_path,
        monkeypatch,
        "remote-primary-tamper-case",
    )
    remote = history.get_case(record.case_id)["object_storage"]
    manifest = json.loads(
        fake.objects[(_config().bucket, remote["manifest_key"])].decode(
            "utf-8"
        )
    )
    first_key = manifest["files"][0]["object_key"]
    fake.objects[(_config().bucket, first_key)] += b"tamper"

    before = {
        path
        for path in Path(tempfile.gettempdir()).glob("bs_web_remote_*")
        if path.is_dir()
    }
    reviewer = _rbac_client(tmp_path, monkeypatch, "reviewer")
    detail = reviewer.get(f"/api/cases/{record.case_id}")

    assert detail.status_code == 503
    assert "원격 보관 케이스" in detail.json()["detail"]
    assert not work.exists()
    assert history.get_case(record.case_id)["exists"] is False
    after = {
        path
        for path in Path(tempfile.gettempdir()).glob("bs_web_remote_*")
        if path.is_dir()
    }
    assert after == before

def test_archived_case_remote_report_missing_encryption_key_fails_closed(
    tmp_path: Path,
    monkeypatch,
) -> None:
    (
        record,
        work,
        _report_bytes,
        _fake,
        _service,
        history,
    ) = _archived_remote_case(
        tmp_path,
        monkeypatch,
        "remote-missing-key-case",
    )
    monkeypatch.delenv("BS_ARTIFACT_ENCRYPTION_KEY", raising=False)

    before = {
        path
        for path in Path(tempfile.gettempdir()).glob("bs_web_remote_*")
        if path.is_dir()
    }
    reviewer = _rbac_client(tmp_path, monkeypatch, "reviewer")
    response = reviewer.get(
        f"/api/cases/{record.case_id}/report",
        params={"file_type": "json"},
    )

    assert response.status_code == 503
    assert "원격 보관 케이스" in response.json()["detail"]
    assert not work.exists()
    assert history.get_case(record.case_id)["exists"] is False
    after = {
        path
        for path in Path(tempfile.gettempdir()).glob("bs_web_remote_*")
        if path.is_dir()
    }
    assert after == before


class StubObjectStorageService:
    def __init__(self):
        self.replicated: list[str] = []
        self.verified: list[str] = []
        self.restored: list[str] = []
        self.deleted: list[str] = []
        self.replicated_organizations: list[str] = []
        self.verified_organizations: list[str] = []
        self.restored_organizations: list[str] = []
        self.deleted_organizations: list[str] = []
        self.remote_reads: list[str] = []
        self.cleaned_temporary_paths: list[Path] = []
        self.fail_verify = False

    def replicate_case(
        self,
        case_id: str,
        work_dir: str,
        *,
        organization_id: str | None = None,
    ):
        self.replicated.append(case_id)
        organization = organization_id or "default"
        self.replicated_organizations.append(organization)
        case_prefix = f"breachscope/cases/orgs/{organization}/{case_id}"
        return {
            "provider": "s3",
            "bucket": "breachscope-test",
            "namespace_version": 2,
            "organization_id": organization,
            "case_prefix": case_prefix,
            "manifest_key": f"{case_prefix}/case_manifest.json",
            "manifest_sha256": "b" * 64,
            "replicated_at": "2026-09-27T02:00:00Z",
            "file_count": 3,
            "total_bytes": 100,
            "client_side_encryption": "AES-256-GCM",
        }

    def materialize_temporary_case(
        self,
        case_id: str,
        remote: dict,
        *,
        organization_id: str | None = None,
    ):
        self.remote_reads.append(case_id)
        target = Path(tempfile.mkdtemp(prefix="bs_web_remote_"))
        (target / "out").mkdir(parents=True, exist_ok=True)
        (target / "out" / "report.json").write_text(
            json.dumps(_sample_report(), ensure_ascii=False) + "\n",
            encoding="utf-8",
        )
        return target, {
            "provider": "s3",
            "bucket": "breachscope-test",
            "case_prefix": remote["case_prefix"],
            "restored_at": "2026-09-29T05:30:00Z",
            "file_count": 3,
            "target_dir": str(target),
            "verified": True,
        }

    def cleanup_temporary_case(self, target_dir: str | Path) -> None:
        target = Path(target_dir)
        self.cleaned_temporary_paths.append(target)
        shutil.rmtree(target, ignore_errors=True)

    @contextmanager
    def temporary_case(
        self,
        case_id: str,
        remote: dict,
        *,
        organization_id: str | None = None,
    ):
        target, result = self.materialize_temporary_case(
            case_id,
            remote,
            organization_id=organization_id,
        )
        try:
            yield target, result
        finally:
            self.cleanup_temporary_case(target)

    def verify_replica(
        self,
        case_id: str,
        remote: dict,
        *,
        organization_id: str | None = None,
    ):
        self.verified.append(case_id)
        self.verified_organizations.append(organization_id or "default")
        if self.fail_verify:
            raise ObjectStorageError("simulated verification failure")
        return {
            "provider": "s3",
            "bucket": "breachscope-test",
            "case_prefix": remote["case_prefix"],
            "manifest_sha256": remote["manifest_sha256"],
            "verified_at": "2026-09-29T05:00:00Z",
            "file_count": 3,
            "verified": True,
        }

    def restore_case(
        self,
        case_id: str,
        target_dir: str,
        remote: dict,
        *,
        overwrite: bool = False,
        organization_id: str | None = None,
    ):
        self.restored.append(case_id)
        self.restored_organizations.append(organization_id or "default")
        target = Path(target_dir)
        target.mkdir(parents=True, exist_ok=True)
        return {
            "provider": "s3",
            "bucket": "breachscope-test",
            "case_prefix": remote["case_prefix"],
            "restored_at": "2026-09-27T03:00:00Z",
            "file_count": 3,
            "target_dir": target_dir,
            "verified": True,
        }

    def delete_replica(
        self,
        case_id: str,
        remote: dict,
        *,
        organization_id: str | None = None,
    ):
        self.deleted.append(case_id)
        self.deleted_organizations.append(organization_id or "default")
        return {
            "provider": "s3",
            "bucket": "breachscope-test",
            "case_prefix": remote["case_prefix"],
            "deleted_at": "2026-09-27T04:00:00Z",
            "deleted_object_count": 4,
        }


def _rbac_client(
    tmp_path: Path,
    monkeypatch,
    role: str,
) -> TestClient:
    monkeypatch.delenv("BS_API_KEY", raising=False)
    monkeypatch.setenv("BS_ADMIN_PASSWORD", "admin-password")
    monkeypatch.setenv("BS_AUTHOR_PASSWORD", "author-password")
    monkeypatch.setenv("BS_REVIEWER_PASSWORD", "reviewer-password")
    monkeypatch.setenv("BS_OPERATOR_PASSWORD", "operator-password")
    monkeypatch.setenv("BS_SESSION_SECRET", "object-storage-session-secret")
    monkeypatch.setenv(
        "BS_AUTH_RATE_LIMIT_PATH",
        str(tmp_path / "auth_rate_limit.json"),
    )
    client = TestClient(app)
    token = create_session_token(subject=role, role=role)
    client.cookies.set(SESSION_COOKIE_NAME, token)
    return client


def test_object_storage_api_requires_operator_and_tracks_replica(
    tmp_path: Path,
    monkeypatch,
) -> None:
    work, _ = _encrypted_case(tmp_path, monkeypatch, "api-object-case")
    monkeypatch.setenv(
        "BS_CASE_HISTORY_PATH",
        str(tmp_path / "case_history.json"),
    )
    monkeypatch.setenv(
        "BS_AUDIT_LOG_PATH",
        str(tmp_path / "audit.jsonl"),
    )
    record = CaseHistoryService().register_case(work, _sample_report())
    stub = StubObjectStorageService()
    monkeypatch.setattr(
        cases_router_module,
        "_object_storage_service",
        lambda: stub,
    )

    reviewer = _rbac_client(tmp_path, monkeypatch, "reviewer")
    forbidden = reviewer.post(
        f"/api/cases/{record.case_id}/object-storage/replicate"
    )
    assert forbidden.status_code == 403

    operator = _rbac_client(tmp_path, monkeypatch, "operator")
    replicated = operator.post(
        f"/api/cases/{record.case_id}/object-storage/replicate"
    )
    assert replicated.status_code == 200, replicated.text
    remote = replicated.json()["object_storage"]
    assert remote["bucket"] == "breachscope-test"
    assert remote["updated_by"] == "operator"

    duplicate = operator.post(
        f"/api/cases/{record.case_id}/object-storage/replicate"
    )
    assert duplicate.status_code == 409

    archive_forbidden = reviewer.post(
        f"/api/cases/{record.case_id}/object-storage/archive"
    )
    assert archive_forbidden.status_code == 403

    archived = operator.post(
        f"/api/cases/{record.case_id}/object-storage/archive"
    )
    assert archived.status_code == 200, archived.text
    assert archived.json()["archive"]["verification"]["verified"] is True
    assert stub.verified == [record.case_id]
    assert not work.exists()

    archived_detail = operator.get(f"/api/cases/{record.case_id}")
    assert archived_detail.status_code == 200
    assert archived_detail.json()["case"]["exists"] is False
    assert archived_detail.json()["case"]["object_storage"] is not None

    restored = operator.post(
        f"/api/cases/{record.case_id}/object-storage/restore"
    )
    assert restored.status_code == 200, restored.text
    assert work.exists()

    detail = operator.get(f"/api/cases/{record.case_id}")
    assert detail.status_code == 200
    assert detail.json()["case"]["object_storage"]["restore_count"] == 1

    deleted = operator.delete(
        f"/api/cases/{record.case_id}/object-storage"
    )
    assert deleted.status_code == 200
    detail = operator.get(f"/api/cases/{record.case_id}")
    assert detail.json()["case"]["object_storage"] is None


def test_remote_replica_blocks_case_delete_and_prune(
    tmp_path: Path,
    monkeypatch,
) -> None:
    work, _ = _encrypted_case(tmp_path, monkeypatch, "retention-case")
    monkeypatch.setenv(
        "BS_CASE_HISTORY_PATH",
        str(tmp_path / "case_history.json"),
    )
    history = CaseHistoryService()
    record = history.register_case(work, _sample_report())
    history.set_object_storage_state(
        record.case_id,
        {
            "provider": "s3",
            "bucket": "breachscope-test",
            "case_prefix": f"breachscope/cases/{record.case_id}",
            "manifest_key": (
                f"breachscope/cases/{record.case_id}/case_manifest.json"
            ),
            "manifest_sha256": "c" * 64,
        },
        updated_by="operator",
    )

    deleted = history.delete_case(record.case_id)
    assert deleted["deleted"] is False
    assert deleted["reason"] == "remote_replica_exists"
    assert work.exists()

    pruned = history.prune_cases(
        keep_last=0,
        dry_run=False,
        remove_files=True,
    )
    assert pruned["removed_case_records"] == 0
    assert pruned["blocked_remote_replicas"] == 1
    assert history.get_case(record.case_id)["case_id"] == record.case_id
    assert work.exists()


def test_case_history_archive_requires_matching_verified_manifest(
    tmp_path: Path,
    monkeypatch,
) -> None:
    work, _ = _encrypted_case(
        tmp_path,
        monkeypatch,
        "archive-history-case",
    )
    monkeypatch.setenv(
        "BS_CASE_HISTORY_PATH",
        str(tmp_path / "case_history.json"),
    )
    history = CaseHistoryService()
    record = history.register_case(work, _sample_report())
    remote = {
        "provider": "s3",
        "bucket": "breachscope-test",
        "case_prefix": f"breachscope/cases/{record.case_id}",
        "manifest_key": (
            f"breachscope/cases/{record.case_id}/case_manifest.json"
        ),
        "manifest_sha256": "d" * 64,
    }
    history.set_object_storage_state(
        record.case_id,
        remote,
        updated_by="operator",
    )

    stale = history.archive_local_case(
        record.case_id,
        expected_manifest_sha256="e" * 64,
    )
    assert stale["archived"] is False
    assert stale["reason"] == "remote_replica_changed"
    assert work.exists()

    archived = history.archive_local_case(
        record.case_id,
        expected_manifest_sha256="d" * 64,
    )
    assert archived["archived"] is True
    assert archived["removed_files"] is True
    assert not work.exists()

    detail = history.get_case(record.case_id)
    assert detail["exists"] is False
    assert detail["object_storage"]["manifest_sha256"] == "d" * 64

    blocked_delete = history.delete_case(record.case_id)
    assert blocked_delete["deleted"] is False
    assert blocked_delete["reason"] == "remote_replica_exists"

    pruned = history.prune_cases(
        keep_last=0,
        dry_run=False,
        remove_files=True,
    )
    assert pruned["removed_case_records"] == 0
    assert pruned["blocked_remote_replicas"] == 1


def test_object_storage_archive_verification_failure_keeps_local_case(
    tmp_path: Path,
    monkeypatch,
) -> None:
    work, _ = _encrypted_case(
        tmp_path,
        monkeypatch,
        "archive-verify-fail-case",
    )
    monkeypatch.setenv(
        "BS_CASE_HISTORY_PATH",
        str(tmp_path / "case_history.json"),
    )
    monkeypatch.setenv(
        "BS_AUDIT_LOG_PATH",
        str(tmp_path / "audit.jsonl"),
    )
    record = CaseHistoryService().register_case(work, _sample_report())
    stub = StubObjectStorageService()
    monkeypatch.setattr(
        cases_router_module,
        "_object_storage_service",
        lambda: stub,
    )
    operator = _rbac_client(tmp_path, monkeypatch, "operator")

    replicated = operator.post(
        f"/api/cases/{record.case_id}/object-storage/replicate"
    )
    assert replicated.status_code == 200

    stub.fail_verify = True
    archived = operator.post(
        f"/api/cases/{record.case_id}/object-storage/archive"
    )

    assert archived.status_code == 503
    assert "verification failure" in archived.json()["detail"]
    assert work.exists()
    detail = operator.get(f"/api/cases/{record.case_id}")
    assert detail.json()["case"]["object_storage"] is not None


def test_object_storage_api_forget_clears_metadata_without_remote_delete(
    tmp_path: Path,
    monkeypatch,
) -> None:
    work, _ = _encrypted_case(tmp_path, monkeypatch, "forget-case")
    monkeypatch.setenv(
        "BS_CASE_HISTORY_PATH",
        str(tmp_path / "case_history.json"),
    )
    monkeypatch.setenv(
        "BS_AUDIT_LOG_PATH",
        str(tmp_path / "audit.jsonl"),
    )
    record = CaseHistoryService().register_case(work, _sample_report())
    stub = StubObjectStorageService()
    monkeypatch.setattr(
        cases_router_module,
        "_object_storage_service",
        lambda: stub,
    )
    operator = _rbac_client(tmp_path, monkeypatch, "operator")

    replicated = operator.post(
        f"/api/cases/{record.case_id}/object-storage/replicate"
    )
    assert replicated.status_code == 200

    blocked_delete = operator.delete(f"/api/cases/{record.case_id}")
    assert blocked_delete.status_code == 409
    assert "원격 replica" in blocked_delete.json()["detail"]

    forgotten = operator.delete(
        f"/api/cases/{record.case_id}/object-storage",
        params={"forget": "true"},
    )
    assert forgotten.status_code == 200
    assert forgotten.json()["delete"]["forgotten"] is True
    assert stub.deleted == []

    detail = operator.get(f"/api/cases/{record.case_id}")
    assert detail.status_code == 200
    assert detail.json()["case"]["object_storage"] is None

    deleted = operator.delete(f"/api/cases/{record.case_id}")
    assert deleted.status_code == 200


def test_archived_remote_case_reanalysis_streams_input_without_restore(
    tmp_path: Path,
    monkeypatch,
) -> None:
    (
        record,
        work,
        _report_bytes,
        _fake,
        service,
        history,
    ) = _archived_remote_case(
        tmp_path,
        monkeypatch,
        "remote-reanalysis-case",
    )

    created_temporary: list[Path] = []
    verified_manifest_sha256: list[str] = []
    original_materialize = service.materialize_temporary_case

    def capture_materialize(*args, **kwargs):
        target, result = original_materialize(*args, **kwargs)
        created_temporary.append(target)
        verified_manifest_sha256.append(
            str(result.get("manifest_sha256") or "")
        )
        return target, result

    monkeypatch.setattr(
        service,
        "materialize_temporary_case",
        capture_materialize,
    )

    class StubAnalysisService:
        def __init__(self):
            self.kwargs = None
            self.payloads: dict[str, bytes] = {}
            self.new_case_id: str | None = None

        async def analyze(self, **kwargs):
            self.kwargs = kwargs
            for source in kwargs["files"]:
                chunks: list[bytes] = []
                while True:
                    chunk = source.read(3)
                    if not chunk:
                        break
                    chunks.append(chunk)
                self.payloads[source.filename] = b"".join(chunks)

            new_work = tmp_path / "cases" / "remote-reanalysis-result"
            (new_work / "out").mkdir(parents=True, exist_ok=True)
            (new_work / "out" / "report.json").write_text(
                json.dumps(_sample_report(), ensure_ascii=False) + "\n",
                encoding="utf-8",
            )
            record = history.register_case(
                new_work,
                _sample_report(),
            )
            self.new_case_id = record.case_id
            return {
                "success": True,
                "case_id": record.case_id,
                "case": record.__dict__,
                "count": 2,
                "risk_score": 20,
                "risk_level": "low",
                "preview": {},
                "work_dir": str(new_work),
            }

    analysis = StubAnalysisService()
    monkeypatch.setattr(
        cases_router_module,
        "_analysis_service",
        analysis,
    )

    reviewer = _rbac_client(tmp_path, monkeypatch, "reviewer")
    forbidden = reviewer.post(
        f"/api/cases/{record.case_id}/object-storage/reanalyze"
    )
    assert forbidden.status_code == 403

    operator = _rbac_client(tmp_path, monkeypatch, "operator")
    response = operator.post(
        f"/api/cases/{record.case_id}/object-storage/reanalyze",
        json={
            "min_severity": "low",
            "mitre_include": "T1059.001",
            "use_custom_rules": True,
            "redact": False,
            "render_pdf": True,
        },
    )

    assert response.status_code == 200, response.text
    payload = response.json()
    assert payload["source_case_id"] == record.case_id
    assert payload["source"] == "object_storage"
    assert analysis.new_case_id
    assert payload["analysis"]["case_id"] == analysis.new_case_id
    lineage = payload["analysis"]["case"]["analysis_lineage"]
    assert lineage["source_case_id"] == record.case_id
    assert lineage["source"] == "object_storage"
    assert lineage["reanalyzed_by"] == "operator"
    source_manifest_sha256 = str(
        (history.get_case(record.case_id).get("object_storage") or {}).get(
            "manifest_sha256"
        )
        or ""
    )
    assert len(source_manifest_sha256) == 64
    assert verified_manifest_sha256 == [source_manifest_sha256]
    assert lineage["source_manifest_sha256"] == verified_manifest_sha256[0]
    assert set(analysis.payloads) == {"events.jsonl"}
    assert analysis.payloads["events.jsonl"].replace(
        b"\r\n",
        b"\n",
    ) == b'{"event":"test"}\n'
    assert analysis.kwargs is not None
    assert analysis.kwargs["use_repo_rules"] is True
    assert analysis.kwargs["min_severity"] == "low"
    assert analysis.kwargs["mitre_include"] == "T1059.001"
    assert analysis.kwargs["use_custom_rules"] is True
    assert analysis.kwargs["redact"] is False
    assert analysis.kwargs["render_pdf"] is True
    assert analysis.kwargs["do_evtx"] is False
    assert analysis.kwargs["organization_id"] == "default"
    assert analysis.kwargs["force_retain"] is True
    assert analysis.kwargs["require_case_record"] is True

    assert not work.exists()
    current = history.get_case(record.case_id)
    assert current["exists"] is False
    assert int(
        (current.get("object_storage") or {}).get("restore_count") or 0
    ) == 0
    assert created_temporary
    assert all(not item.exists() for item in created_temporary)

    audit_rows = [
        json.loads(line)
        for line in (
            tmp_path / "remote-reanalysis-case-audit.jsonl"
        ).read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]
    rows = [
        row
        for row in audit_rows
        if row.get("action") == "case.object_storage.reanalyze"
    ]
    assert len(rows) == 1
    assert rows[0]["status"] == "success"
    details = rows[0].get("details") or {}
    assert details.get("new_case_id") == analysis.new_case_id
    assert details.get("source_manifest_sha256") == source_manifest_sha256


def test_remote_reanalysis_custom_rules_requires_analysis_permission(
    tmp_path: Path,
    monkeypatch,
) -> None:
    (
        record,
        _work,
        _report_bytes,
        _fake,
        service,
        _history,
    ) = _archived_remote_case(
        tmp_path,
        monkeypatch,
        "remote-reanalysis-rbac",
    )

    called = False
    original_materialize = service.materialize_temporary_case

    def capture_materialize(*args, **kwargs):
        nonlocal called
        called = True
        return original_materialize(*args, **kwargs)

    monkeypatch.setattr(
        service,
        "materialize_temporary_case",
        capture_materialize,
    )
    monkeypatch.setenv(
        "BS_ORGANIZATION_RBAC_POLICIES",
        json.dumps(
            {
                "default": {
                    "operator": ["case.object_storage"],
                }
            }
        ),
    )

    operator = _rbac_client(tmp_path, monkeypatch, "operator")
    response = operator.post(
        f"/api/cases/{record.case_id}/object-storage/reanalyze",
        json={"use_custom_rules": True},
    )

    assert response.status_code == 403
    assert "analysis.custom_rules" in response.json()["detail"]
    assert called is False


def test_archived_remote_case_reanalysis_requires_retained_input(
    tmp_path: Path,
    monkeypatch,
) -> None:
    work, _ = _encrypted_case(
        tmp_path,
        monkeypatch,
        "remote-reanalysis-no-input",
    )
    (work / "input" / "events.jsonl.enc").unlink()
    monkeypatch.setenv(
        "BS_CASE_HISTORY_PATH",
        str(tmp_path / "remote-reanalysis-no-input-history.json"),
    )
    monkeypatch.setenv(
        "BS_AUDIT_LOG_PATH",
        str(tmp_path / "remote-reanalysis-no-input-audit.jsonl"),
    )
    history = CaseHistoryService()
    record = history.register_case(work, _sample_report())
    fake = FakeS3()
    service = ObjectStorageService(_config(), client=fake)
    remote = service.replicate_case(
        record.case_id,
        work,
        organization_id="default",
    )
    history.set_object_storage_state(
        record.case_id,
        remote,
        updated_by="operator",
    )
    archived = history.archive_local_case(
        record.case_id,
        expected_manifest_sha256=remote["manifest_sha256"],
    )
    assert archived["archived"] is True
    monkeypatch.setattr(
        cases_router_module,
        "_object_storage_service",
        lambda: service,
    )

    operator = _rbac_client(tmp_path, monkeypatch, "operator")
    response = operator.post(
        f"/api/cases/{record.case_id}/object-storage/reanalyze"
    )

    assert response.status_code == 409
    assert "원본 input" in response.json()["detail"]
    assert history.get_case(record.case_id)["exists"] is False


def test_archived_remote_case_reanalysis_tamper_fails_closed(
    tmp_path: Path,
    monkeypatch,
) -> None:
    (
        record,
        work,
        _report_bytes,
        fake,
        _service,
        history,
    ) = _archived_remote_case(
        tmp_path,
        monkeypatch,
        "remote-reanalysis-tamper",
    )
    remote = history.get_case(record.case_id)["object_storage"]
    manifest = json.loads(
        fake.objects[(_config().bucket, remote["manifest_key"])].decode(
            "utf-8"
        )
    )
    input_row = next(
        row
        for row in manifest["files"]
        if str(row.get("path") or "").startswith("input/")
    )
    key = input_row["object_key"]
    fake.objects[(_config().bucket, key)] += b"tamper"

    operator = _rbac_client(tmp_path, monkeypatch, "operator")
    response = operator.post(
        f"/api/cases/{record.case_id}/object-storage/reanalyze"
    )

    assert response.status_code == 503
    assert "재분석" in response.json()["detail"]
    assert not work.exists()
    current = history.get_case(record.case_id)
    assert current["exists"] is False
    assert int(
        (current.get("object_storage") or {}).get("restore_count") or 0
    ) == 0


def test_async_object_storage_case_lock_waits_without_blocking_event_loop() -> None:
    case_id = "async-object-storage-lock-case"
    lock = cases_router_module._object_storage_lock(case_id)

    @cases_router_module._object_storage_operation_locked
    async def operation(case_id: str):
        await asyncio.sleep(0)
        return case_id

    async def scenario() -> str:
        lock.acquire()
        try:
            task = asyncio.create_task(operation(case_id))
            await asyncio.sleep(0.05)
            assert not task.done()
        finally:
            lock.release()
        return await asyncio.wait_for(task, timeout=1.0)

    assert asyncio.run(scenario()) == case_id


def test_web_ui_exposes_operator_only_object_storage_controls() -> None:
    source = Path("templates/web_index.html").read_text(encoding="utf-8")
    runtime = Path(
        "breachscope/runtime_data/templates/web_index.html"
    ).read_text(encoding="utf-8")
    assert source == runtime
    assert "data-object-storage-action" in source
    assert "원격 복제" in source
    assert "원격 복원" in source
    assert "원격 재분석" in source
    assert "원격 전용" in source
    assert "로컬 비우기" in source
    assert "원격 삭제" in source
    assert "/object-storage/replicate" in source
    assert "/object-storage/archive" in source
    assert "/object-storage/restore" in source
    assert "/object-storage/reanalyze" in source
    assert "reanalyzed:" in source
    assert "roleAllows('operator')" in source


def test_api_replication_rolls_back_remote_when_case_index_persist_fails(
    tmp_path: Path,
    monkeypatch,
) -> None:
    work, _ = _encrypted_case(tmp_path, monkeypatch, "persist-fail-case")
    stub_storage = StubObjectStorageService()

    class FailingHistory:
        def get_case(self, case_id: str):
            return {
                "case_id": case_id,
                "exists": True,
                "work_dir": str(work),
                "object_storage": None,
            }

        def set_object_storage_state(self, *args, **kwargs):
            raise OSError("simulated case index write failure")

    monkeypatch.setattr(
        cases_router_module,
        "_object_storage_service",
        lambda: stub_storage,
    )
    monkeypatch.setattr(
        cases_router_module,
        "_service",
        lambda request: FailingHistory(),
    )
    operator = _rbac_client(tmp_path, monkeypatch, "operator")

    response = operator.post(
        "/api/cases/case-persist-fail/object-storage/replicate"
    )

    assert response.status_code == 500
    assert "되돌렸습니다" in response.json()["detail"]
    assert stub_storage.replicated == ["case-persist-fail"]
    assert stub_storage.deleted == ["case-persist-fail"]


def _legacy_replica(
    service: ObjectStorageService,
    fake: FakeS3,
    case_id: str,
    work: Path,
) -> dict:
    """Convert one freshly uploaded default-org v2 replica into a legacy v1 layout."""
    remote = service.replicate_case(
        case_id,
        work,
        organization_id="default",
    )
    manifest_bytes = fake.objects[(_config().bucket, remote["manifest_key"])]
    manifest = json.loads(manifest_bytes.decode("utf-8"))
    legacy_prefix = f"breachscope/cases/{case_id}"

    legacy_files = []
    for row in manifest["files"]:
        old_key = row["object_key"]
        rel = row["path"]
        new_key = f"{legacy_prefix}/files/{rel}"
        fake.objects[(_config().bucket, new_key)] = fake.objects[
            (_config().bucket, old_key)
        ]
        legacy_row = dict(row)
        legacy_row["object_key"] = new_key
        legacy_files.append(legacy_row)

    legacy_manifest = dict(manifest)
    legacy_manifest["schema"] = LEGACY_OBJECT_STORAGE_SCHEMA
    legacy_manifest.pop("namespace_version", None)
    legacy_manifest.pop("organization_id", None)
    legacy_manifest["case_prefix"] = legacy_prefix
    legacy_manifest["files"] = legacy_files
    legacy_manifest_bytes = (
        json.dumps(
            legacy_manifest,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
        + b"\n"
    )
    legacy_manifest_key = f"{legacy_prefix}/case_manifest.json"
    fake.objects[(_config().bucket, legacy_manifest_key)] = legacy_manifest_bytes

    for key in list(fake.objects):
        bucket, object_key = key
        if bucket == _config().bucket and object_key.startswith(
            remote["case_prefix"] + "/"
        ):
            del fake.objects[key]

    return {
        "provider": "s3",
        "bucket": _config().bucket,
        "case_prefix": legacy_prefix,
        "manifest_key": legacy_manifest_key,
        "manifest_sha256": hashlib.sha256(legacy_manifest_bytes).hexdigest(),
        "replicated_at": remote["replicated_at"],
        "file_count": remote["file_count"],
        "total_bytes": remote["total_bytes"],
        "client_side_encryption": "AES-256-GCM",
    }


def test_object_storage_namespace_separates_same_case_id_between_organizations(
    tmp_path: Path,
    monkeypatch,
) -> None:
    work, _ = _encrypted_case(tmp_path, monkeypatch, "org-namespace-case")
    fake = FakeS3()
    service = ObjectStorageService(_config(), client=fake)

    remote_a = service.replicate_case(
        "case-shared",
        work,
        organization_id="org-a",
    )
    remote_b = service.replicate_case(
        "case-shared",
        work,
        organization_id="org-b",
    )

    assert remote_a["namespace_version"] == OBJECT_STORAGE_NAMESPACE_VERSION
    assert remote_a["organization_id"] == "org-a"
    assert remote_b["organization_id"] == "org-b"
    assert remote_a["case_prefix"] == "breachscope/cases/orgs/org-a/case-shared"
    assert remote_b["case_prefix"] == "breachscope/cases/orgs/org-b/case-shared"
    assert remote_a["manifest_key"] != remote_b["manifest_key"]

    manifest_a = json.loads(
        fake.objects[(_config().bucket, remote_a["manifest_key"])].decode("utf-8")
    )
    manifest_b = json.loads(
        fake.objects[(_config().bucket, remote_b["manifest_key"])].decode("utf-8")
    )
    assert manifest_a["schema"] == OBJECT_STORAGE_SCHEMA
    assert manifest_a["organization_id"] == "org-a"
    assert manifest_b["organization_id"] == "org-b"
    assert {
        row["object_key"] for row in manifest_a["files"]
    }.isdisjoint({
        row["object_key"] for row in manifest_b["files"]
    })


def test_object_storage_rejects_cross_organization_restore_and_delete(
    tmp_path: Path,
    monkeypatch,
) -> None:
    work, _ = _encrypted_case(tmp_path, monkeypatch, "cross-org-case")
    fake = FakeS3()
    service = ObjectStorageService(_config(), client=fake)
    remote = service.replicate_case(
        "case-cross-org",
        work,
        organization_id="org-a",
    )

    target = tmp_path / "cases" / "cross-org-restore"
    with pytest.raises(ObjectStorageError, match="organization mismatch"):
        service.restore_case(
            "case-cross-org",
            target,
            remote,
            organization_id="org-b",
        )

    before = dict(fake.objects)
    with pytest.raises(ObjectStorageError, match="organization mismatch"):
        service.delete_replica(
            "case-cross-org",
            remote,
            organization_id="org-b",
        )
    assert fake.objects == before


def test_legacy_object_storage_replica_is_default_organization_only(
    tmp_path: Path,
    monkeypatch,
) -> None:
    work, report_bytes = _encrypted_case(tmp_path, monkeypatch, "legacy-case")
    fake = FakeS3()
    service = ObjectStorageService(_config(), client=fake)
    remote = _legacy_replica(
        service,
        fake,
        "case-legacy",
        work,
    )

    with pytest.raises(ObjectStorageError, match="default organization"):
        service.restore_case(
            "case-legacy",
            tmp_path / "cases" / "legacy-denied",
            remote,
            organization_id="org-a",
        )
    with pytest.raises(ObjectStorageError, match="default organization"):
        service.delete_replica(
            "case-legacy",
            remote,
            organization_id="org-a",
        )

    shutil.rmtree(work)
    restored = service.restore_case(
        "case-legacy",
        work,
        remote,
        organization_id="default",
    )
    assert restored["case_prefix"] == "breachscope/cases/case-legacy"
    assert read_artifact_bytes(
        work / "out" / "report.json",
        work,
    ) == report_bytes

    deleted = service.delete_replica(
        "case-legacy",
        remote,
        organization_id="default",
    )
    assert deleted["deleted_object_count"] == 4
    assert fake.objects == {}


def test_object_storage_rejects_invalid_recorded_organization(
    tmp_path: Path,
    monkeypatch,
) -> None:
    work, _ = _encrypted_case(tmp_path, monkeypatch, "invalid-org-case")
    fake = FakeS3()
    service = ObjectStorageService(_config(), client=fake)
    remote = service.replicate_case(
        "case-invalid-org",
        work,
        organization_id="org-a",
    )
    tampered = dict(remote)
    tampered["organization_id"] = "../org-a"

    with pytest.raises(ObjectStorageError, match="Invalid organization_id"):
        service.delete_replica(
            "case-invalid-org",
            tampered,
            organization_id="org-a",
        )


def test_object_storage_api_passes_api_key_organization_to_remote_namespace(
    tmp_path: Path,
    monkeypatch,
) -> None:
    work, _ = _encrypted_case(tmp_path, monkeypatch, "api-org-namespace")
    monkeypatch.setenv(
        "BS_CASE_HISTORY_PATH",
        str(tmp_path / "case_history.json"),
    )
    monkeypatch.setenv(
        "BS_AUDIT_LOG_PATH",
        str(tmp_path / "audit.jsonl"),
    )
    monkeypatch.setenv("BS_API_KEY", "object-org-api-key")
    for name in (
        "BS_ADMIN_PASSWORD",
        "BS_AUTHOR_PASSWORD",
        "BS_REVIEWER_PASSWORD",
        "BS_OPERATOR_PASSWORD",
    ):
        monkeypatch.delenv(name, raising=False)

    history = CaseHistoryService(organization_id="org-blue")
    record = history.register_case(work, _sample_report())
    stub = StubObjectStorageService()
    monkeypatch.setattr(
        cases_router_module,
        "_object_storage_service",
        lambda: stub,
    )

    client = TestClient(app)
    headers = {
        "x-api-key": "object-org-api-key",
        "x-breachscope-organization": "org-blue",
    }
    replicated = client.post(
        f"/api/cases/{record.case_id}/object-storage/replicate",
        headers=headers,
    )
    assert replicated.status_code == 200, replicated.text
    remote = replicated.json()["object_storage"]
    assert remote["organization_id"] == "org-blue"
    assert f"/orgs/org-blue/{record.case_id}" in remote["case_prefix"]
    assert stub.replicated_organizations == ["org-blue"]

    archived = client.post(
        f"/api/cases/{record.case_id}/object-storage/archive",
        headers=headers,
    )
    assert archived.status_code == 200, archived.text
    assert stub.verified_organizations == ["org-blue"]
    assert not work.exists()

    restored = client.post(
        f"/api/cases/{record.case_id}/object-storage/restore",
        headers=headers,
    )
    assert restored.status_code == 200, restored.text
    assert stub.restored_organizations == ["org-blue"]

    deleted = client.delete(
        f"/api/cases/{record.case_id}/object-storage",
        headers=headers,
    )
    assert deleted.status_code == 200, deleted.text
    assert stub.deleted_organizations == ["org-blue"]
