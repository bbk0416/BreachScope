from __future__ import annotations

import asyncio
import base64
import json
import zipfile
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from api.main import app
from api.services.backup_service import BackupService
from api.services.artifact_encryption import (
    ArtifactEncryptionError,
    decrypt_bytes,
    encrypt_file,
    encrypt_tree,
    read_artifact_bytes,
)


client = TestClient(app)


def _key(seed: int = 0) -> str:
    raw = bytes(((i + seed) % 256) for i in range(32))
    return base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")


def _disable_auth(monkeypatch) -> None:
    for name in (
        "BS_API_KEY",
        "BS_ADMIN_PASSWORD",
        "BS_AUTHOR_PASSWORD",
        "BS_REVIEWER_PASSWORD",
        "BS_OPERATOR_PASSWORD",
    ):
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setenv("BS_DEPLOYMENT_MODE", "local")


def test_artifact_encryption_round_trip_and_path_binding(
    tmp_path: Path,
    monkeypatch,
) -> None:
    monkeypatch.setenv("BS_ARTIFACT_ENCRYPTION_KEY", _key())
    root = tmp_path / "case"
    root.mkdir()
    original = root / "evidence.json"
    payload = b'{"secret":"evidence"}\n'
    original.write_bytes(payload)

    encrypted = encrypt_file(original, root)
    assert not original.exists()
    assert encrypted.name == "evidence.json.enc"
    assert encrypted.read_bytes() != payload
    assert decrypt_bytes(encrypted, root) == payload
    assert read_artifact_bytes(original, root) == payload

    swapped = root / "renamed.json.enc"
    encrypted.rename(swapped)
    with pytest.raises(ArtifactEncryptionError, match="authentication/decryption"):
        read_artifact_bytes(root / "renamed.json", root)




def test_artifact_encryption_multichunk_and_truncation_fail_closed(
    tmp_path: Path,
    monkeypatch,
) -> None:
    monkeypatch.setenv("BS_ARTIFACT_ENCRYPTION_KEY", _key(3))
    root = tmp_path / "large-case"
    root.mkdir()
    original = root / "large.bin"
    payload = (
        bytes(range(256)) * 9000
    )  # 2.3 MiB+, forces multiple authenticated chunks.
    original.write_bytes(payload)

    encrypted = encrypt_file(original, root)
    assert read_artifact_bytes(original, root) == payload

    blob = encrypted.read_bytes()
    encrypted.write_bytes(blob[:-1])
    with pytest.raises(ArtifactEncryptionError):
        read_artifact_bytes(original, root)




def test_encrypt_tree_rolls_back_when_encryption_fails(
    tmp_path: Path,
    monkeypatch,
) -> None:
    import api.services.artifact_encryption as module

    monkeypatch.setenv("BS_ARTIFACT_ENCRYPTION_KEY", _key(5))
    root = tmp_path / "tree-fail"
    root.mkdir()
    first = root / "a.txt"
    second = root / "b.txt"
    first.write_text("alpha", encoding="utf-8")
    second.write_text("beta", encoding="utf-8")

    original_encrypt = module.encrypt_file
    calls = 0

    def fail_second(*args, **kwargs):
        nonlocal calls
        calls += 1
        if calls == 2:
            raise ArtifactEncryptionError("forced encryption failure")
        return original_encrypt(*args, **kwargs)

    monkeypatch.setattr(module, "encrypt_file", fail_second)

    with pytest.raises(ArtifactEncryptionError, match="forced"):
        encrypt_tree(root)

    assert first.read_text(encoding="utf-8") == "alpha"
    assert second.read_text(encoding="utf-8") == "beta"
    assert list(root.rglob("*.enc")) == []


def test_encrypt_tree_rolls_back_when_plaintext_commit_fails(
    tmp_path: Path,
    monkeypatch,
) -> None:
    monkeypatch.setenv("BS_ARTIFACT_ENCRYPTION_KEY", _key(6))
    root = tmp_path / "commit-fail"
    root.mkdir()
    first = root / "a.txt"
    second = root / "b.txt"
    first.write_text("alpha", encoding="utf-8")
    second.write_text("beta", encoding="utf-8")

    original_unlink = Path.unlink
    failed = False

    def fail_second_source(path: Path, *args, **kwargs):
        nonlocal failed
        if path.resolve() == second.resolve() and not failed:
            failed = True
            raise PermissionError("forced unlink failure")
        return original_unlink(path, *args, **kwargs)

    monkeypatch.setattr(Path, "unlink", fail_second_source)

    with pytest.raises(
        ArtifactEncryptionError,
        match="plaintext state was restored",
    ):
        encrypt_tree(root)

    assert first.read_text(encoding="utf-8") == "alpha"
    assert second.read_text(encoding="utf-8") == "beta"
    assert list(root.rglob("*.enc")) == []




def test_artifact_encryption_key_rejects_non_base64_characters(
    monkeypatch,
) -> None:
    from api.services.artifact_encryption import (
        validate_artifact_encryption_key,
    )

    monkeypatch.setenv(
        "BS_ARTIFACT_ENCRYPTION_KEY",
        _key() + "!",
    )
    with pytest.raises(
        ArtifactEncryptionError,
        match="URL-safe base64",
    ):
        validate_artifact_encryption_key()


def test_artifact_encryption_wrong_key_fails_closed(
    tmp_path: Path,
    monkeypatch,
) -> None:
    root = tmp_path / "case"
    root.mkdir()
    original = root / "report.csv"
    original.write_text("a,b\n1,2\n", encoding="utf-8")

    monkeypatch.setenv("BS_ARTIFACT_ENCRYPTION_KEY", _key(0))
    encrypt_file(original, root)

    monkeypatch.setenv("BS_ARTIFACT_ENCRYPTION_KEY", _key(7))
    with pytest.raises(ArtifactEncryptionError, match="authentication/decryption"):
        read_artifact_bytes(original, root)


def test_analyze_encrypts_retained_case_and_downloads_transparently(
    tmp_path: Path,
    monkeypatch,
) -> None:
    _disable_auth(monkeypatch)
    cases_root = tmp_path / "cases"
    cases_root.mkdir()
    monkeypatch.setenv("BS_CASES_ROOT", str(cases_root))
    monkeypatch.setenv(
        "BS_CASE_HISTORY_PATH", str(tmp_path / "case_history.json")
    )
    monkeypatch.setenv("BS_ARTIFACT_ENCRYPTION_KEY", _key())

    event = {
        "timestamp": "2026-09-27T00:00:00Z",
        "host": "WS-ENC",
        "source": "ProcessCreate",
        "event_id": "4688",
        "user": "CORP\\analyst",
        "command_line": "whoami",
    }
    sample = tmp_path / "events.jsonl"
    sample.write_text(json.dumps(event) + "\n", encoding="utf-8")
    work = cases_root / "encrypted-case"

    with sample.open("rb") as handle:
        response = client.post(
            "/api/analyze",
            files=[
                (
                    "files",
                    ("events.jsonl", handle, "application/octet-stream"),
                )
            ],
            data={
                "use_repo_rules": "true",
                "min_severity": "low",
                "redact": "true",
                "work_dir": str(work),
            },
        )

    assert response.status_code == 200, response.text
    body = response.json()
    assert body["case_id"]
    assert body["artifact_encryption"]["enabled"] is True
    assert body["artifact_encryption"]["algorithm"] == "AES-256-GCM"
    assert body["artifact_encryption"]["plaintext_retained"] is False
    assert body["artifact_encryption"]["encrypted_file_count"] > 1
    assert body["json_path"].endswith(".json.enc")
    assert body["html_path"].endswith(".html.enc")

    stored_files = [p for p in work.rglob("*") if p.is_file()]
    assert stored_files
    assert all(p.name.endswith(".enc") for p in stored_files)
    assert not (work / "events.jsonl").exists()
    assert (work / "events.jsonl.enc").exists()
    assert not (work / "out" / "report.json").exists()
    assert (work / "out" / "report.json.enc").exists()

    case_response = client.get(f"/api/cases/{body['case_id']}")
    assert case_response.status_code == 200
    case_body = case_response.json()
    assert case_body["preview"] is not None
    assert case_body["case"]["artifacts"]["json"] is True
    assert case_body["case"]["artifacts"]["zip"] is True

    download = client.get(
        f"/api/cases/{body['case_id']}/report",
        params={"file_type": "json"},
    )
    assert download.status_code == 200
    assert download.headers["content-type"].startswith("application/json")
    assert 'filename="report.json"' in download.headers["content-disposition"]
    decoded = download.json()
    assert "summary" in decoded

    legacy_preview = client.get(
        f"/api/report-preview/{work.as_posix()}"
    )
    assert legacy_preview.status_code == 200
    assert "risk" in legacy_preview.json()

    legacy_download = client.get(
        f"/api/report/{work.as_posix()}",
        params={"file_type": "json"},
    )
    assert legacy_download.status_code == 200
    assert legacy_download.json()["summary"]

    monkeypatch.setenv("BS_ARTIFACT_ENCRYPTION_KEY", _key(11))

    denied_preview = client.get(f"/api/cases/{body['case_id']}")
    assert denied_preview.status_code == 503
    assert "복호화할 수 없습니다" in denied_preview.json()["detail"]

    denied_download = client.get(
        f"/api/cases/{body['case_id']}/report",
        params={"file_type": "json"},
    )
    assert denied_download.status_code == 503
    assert "복호화할 수 없습니다" in denied_download.json()["detail"]

    legacy_denied_preview = client.get(
        f"/api/report-preview/{work.as_posix()}"
    )
    assert legacy_denied_preview.status_code == 503

    legacy_denied_download = client.get(
        f"/api/report/{work.as_posix()}",
        params={"file_type": "json"},
    )
    assert legacy_denied_download.status_code == 503



def test_retained_work_is_encrypted_even_if_report_json_is_unreadable(
    tmp_path: Path,
    monkeypatch,
) -> None:
    import api.services.analysis_service as analysis_module
    from api.services.analysis_service import AnalysisService

    _disable_auth(monkeypatch)
    cases_root = tmp_path / "cases"
    work = cases_root / "broken-report"
    work.mkdir(parents=True)
    monkeypatch.setenv("BS_CASES_ROOT", str(cases_root))
    monkeypatch.setenv("BS_ARTIFACT_ENCRYPTION_KEY", _key(13))

    class BrokenJsonPipeline:
        def __init__(self, **kwargs):
            pass

        def run(self, *, input_dir, out_prefix, **kwargs):
            out_prefix.parent.mkdir(parents=True, exist_ok=True)
            html = out_prefix.with_suffix(".html")
            html.write_text("<html>ok</html>", encoding="utf-8")
            out_prefix.with_suffix(".json").write_text(
                "{not-json",
                encoding="utf-8",
            )
            return html, 0

    monkeypatch.setattr(analysis_module, "Pipeline", BrokenJsonPipeline)

    service = AnalysisService()
    monkeypatch.setattr(
        service.workdir_service,
        "create_work_directory",
        lambda work_dir=None: work,
    )

    result = asyncio.run(
        service.analyze(
            files=[],
            use_repo_rules=True,
            min_severity="low",
            mitre_include="",
            mitre_exclude="",
            host_include="",
            redact=True,
            render_pdf=False,
            do_evtx=False,
            collect_evtx=False,
            collect_logs="",
            collect_hours=None,
            work_dir=str(work),
        )
    )

    assert result["success"] is True
    assert result["case_id"] is None
    assert result["artifact_encryption"]["enabled"] is True
    files = [path for path in work.rglob("*") if path.is_file()]
    assert files
    assert all(path.name.endswith(".enc") for path in files)
    assert not (work / "out" / "report.html").exists()
    assert not (work / "out" / "report.json").exists()
    assert (work / "out" / "report.html.enc").exists()
    assert (work / "out" / "report.json.enc").exists()

def test_invalid_encryption_key_makes_readiness_fail(
    tmp_path: Path,
    monkeypatch,
) -> None:
    _disable_auth(monkeypatch)
    monkeypatch.setenv("BS_CASES_ROOT", str(tmp_path / "cases"))
    monkeypatch.setenv(
        "BS_CASE_HISTORY_PATH", str(tmp_path / "case_history.json")
    )
    monkeypatch.setenv("BS_AUDIT_LOG_PATH", str(tmp_path / "audit.jsonl"))
    monkeypatch.setenv("BS_BACKUP_ROOT", str(tmp_path / "backups"))
    monkeypatch.setenv("BS_ARTIFACT_ENCRYPTION_KEY", "not-a-32-byte-key")

    response = client.get("/api/health/ready")
    assert response.status_code == 503
    body = response.json()
    checks = {row["name"]: row for row in body["checks"]}
    assert checks["artifact_encryption"]["status"] == "fail"


def test_backup_preserves_encrypted_case_ciphertext_without_key(
    tmp_path: Path,
    monkeypatch,
) -> None:
    monkeypatch.setenv("BS_ARTIFACT_ENCRYPTION_KEY", _key(9))
    cases_root = tmp_path / "cases"
    case_dir = cases_root / "case-1"
    case_dir.mkdir(parents=True)
    report = case_dir / "report.json"
    secret_payload = b'{"sensitive":"plaintext-marker-741852"}\n'
    report.write_bytes(secret_payload)
    encrypted = encrypt_file(report, case_dir)

    history = tmp_path / "case_history.json"
    history.write_text('{"cases": []}\n', encoding="utf-8")
    backup_root = tmp_path / "backups"

    monkeypatch.setenv("BS_CASES_ROOT", str(cases_root))
    monkeypatch.setenv("BS_CASE_HISTORY_PATH", str(history))
    monkeypatch.setenv("BS_BACKUP_ROOT", str(backup_root))
    monkeypatch.setenv("BS_AUDIT_LOG_PATH", str(tmp_path / "audit.jsonl"))
    monkeypatch.setenv(
        "BS_RULE_TUNING_PATH", str(tmp_path / "rule_tuning.json")
    )
    monkeypatch.setenv(
        "BS_RULE_AUTHORING_ROOT", str(tmp_path / "rule_authoring")
    )
    monkeypatch.setenv(
        "BS_RULE_ACTIVATION_PATH", str(tmp_path / "activation.json")
    )

    result = BackupService(backup_root=backup_root).create_backup(
        include_cases=True,
        include_audit=False,
        label="encrypted-case",
    )
    zip_path = backup_root / result["filename"]

    with zipfile.ZipFile(zip_path, "r") as zf:
        names = set(zf.namelist())
        enc_name = "cases/case-1/report.json.enc"
        assert enc_name in names
        assert "cases/case-1/report.json" not in names
        stored = zf.read(enc_name)
        manifest = json.loads(
            zf.read("backup_manifest.json").decode("utf-8")
        )

    assert stored == encrypted.read_bytes()
    assert secret_payload not in stored
    manifest_text = json.dumps(manifest, ensure_ascii=False)
    assert "BS_ARTIFACT_ENCRYPTION_KEY" not in manifest_text
    assert _key(9) not in manifest_text


def test_analyze_invalid_encryption_key_returns_503_and_cleans_upload(
    tmp_path: Path,
    monkeypatch,
) -> None:
    _disable_auth(monkeypatch)
    cases_root = tmp_path / "cases"
    cases_root.mkdir()
    monkeypatch.setenv("BS_CASES_ROOT", str(cases_root))
    monkeypatch.setenv(
        "BS_CASE_HISTORY_PATH", str(tmp_path / "case_history.json")
    )
    monkeypatch.setenv(
        "BS_ARTIFACT_ENCRYPTION_KEY",
        "not-valid-base64!",
    )

    event = {
        "timestamp": "2026-09-27T00:00:00Z",
        "host": "WS-BADKEY",
        "source": "ProcessCreate",
        "event_id": "4688",
        "user": "CORP\\\\analyst",
        "command_line": "whoami",
    }
    sample = tmp_path / "bad-key-events.jsonl"
    sample.write_text(json.dumps(event) + "\\n", encoding="utf-8")
    work = cases_root / "bad-key-case"

    with sample.open("rb") as handle:
        response = client.post(
            "/api/analyze",
            files=[
                (
                    "files",
                    ("events.jsonl", handle, "application/octet-stream"),
                )
            ],
            data={
                "use_repo_rules": "true",
                "min_severity": "low",
                "redact": "true",
                "work_dir": str(work),
            },
        )

    assert response.status_code == 503
    assert "암호화" in response.json()["detail"]
    assert not (work / "events.jsonl").exists()
    assert not (work / "events.jsonl.enc").exists()
