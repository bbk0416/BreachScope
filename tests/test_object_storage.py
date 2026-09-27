from __future__ import annotations

import base64
import io
import json
import shutil
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

import api.routers.cases as cases_router_module
from api.main import app
from api.security import SESSION_COOKIE_NAME, create_session_token
from api.services.artifact_encryption import encrypt_tree, read_artifact_bytes
from api.services.case_history import CaseHistoryService
from api.services.object_storage import (
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
    assert read_artifact_bytes(
        work / "out" / "report.json",
        work,
    ) == report_bytes

    deleted = service.delete_replica("case-object-1", remote)
    assert deleted["deleted_object_count"] == 4
    assert fake.objects == {}


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


class StubObjectStorageService:
    def __init__(self):
        self.replicated: list[str] = []
        self.restored: list[str] = []
        self.deleted: list[str] = []

    def replicate_case(self, case_id: str, work_dir: str):
        self.replicated.append(case_id)
        return {
            "provider": "s3",
            "bucket": "breachscope-test",
            "case_prefix": f"breachscope/cases/{case_id}",
            "manifest_key": (
                f"breachscope/cases/{case_id}/case_manifest.json"
            ),
            "manifest_sha256": "b" * 64,
            "replicated_at": "2026-09-27T02:00:00Z",
            "file_count": 3,
            "total_bytes": 100,
            "client_side_encryption": "AES-256-GCM",
        }

    def restore_case(
        self,
        case_id: str,
        target_dir: str,
        remote: dict,
        *,
        overwrite: bool = False,
    ):
        self.restored.append(case_id)
        return {
            "provider": "s3",
            "bucket": "breachscope-test",
            "case_prefix": remote["case_prefix"],
            "restored_at": "2026-09-27T03:00:00Z",
            "file_count": 3,
            "target_dir": target_dir,
            "verified": True,
        }

    def delete_replica(self, case_id: str, remote: dict):
        self.deleted.append(case_id)
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

    shutil.rmtree(work)
    restored = operator.post(
        f"/api/cases/{record.case_id}/object-storage/restore"
    )
    assert restored.status_code == 200, restored.text

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


def test_web_ui_exposes_operator_only_object_storage_controls() -> None:
    source = Path("templates/web_index.html").read_text(encoding="utf-8")
    runtime = Path(
        "breachscope/runtime_data/templates/web_index.html"
    ).read_text(encoding="utf-8")
    assert source == runtime
    assert "data-object-storage-action" in source
    assert "원격 복제" in source
    assert "원격 복원" in source
    assert "원격 삭제" in source
    assert "/object-storage/replicate" in source
    assert "/object-storage/restore" in source
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
