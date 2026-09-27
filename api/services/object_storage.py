"""S3-compatible replication/restore for encrypted retained cases."""
from __future__ import annotations

import hashlib
import json
import os
import re
import shutil
import tempfile
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path, PurePosixPath
from typing import Any

import boto3

from api.services.artifact_encryption import (
    artifact_encryption_enabled,
    plaintext_path,
    validate_artifact_encryption_key,
    verify_artifact,
)
from api.services.path_boundary import validate_managed_work_dir


OBJECT_STORAGE_PROVIDER_ENV = "BS_OBJECT_STORAGE_PROVIDER"
OBJECT_STORAGE_BUCKET_ENV = "BS_OBJECT_STORAGE_BUCKET"
OBJECT_STORAGE_PREFIX_ENV = "BS_OBJECT_STORAGE_PREFIX"
OBJECT_STORAGE_REGION_ENV = "BS_OBJECT_STORAGE_REGION"
OBJECT_STORAGE_ENDPOINT_ENV = "BS_OBJECT_STORAGE_ENDPOINT_URL"

OBJECT_STORAGE_SCHEMA = "breachscope.case-object-storage.v1"
DEFAULT_PROVIDER = "s3"
DEFAULT_PREFIX = "breachscope/cases"
_CASE_ID_RE = re.compile(r"^[A-Za-z0-9._-]{1,160}$")


class ObjectStorageError(RuntimeError):
    pass


@dataclass(frozen=True)
class ObjectStorageConfig:
    provider: str
    bucket: str
    prefix: str
    region: str | None
    endpoint_url: str | None

    @classmethod
    def from_env(cls) -> "ObjectStorageConfig":
        provider = os.getenv(OBJECT_STORAGE_PROVIDER_ENV, "").strip().lower()
        bucket = os.getenv(OBJECT_STORAGE_BUCKET_ENV, "").strip()
        prefix = _normalize_prefix(
            os.getenv(OBJECT_STORAGE_PREFIX_ENV, DEFAULT_PREFIX)
        )
        region = os.getenv(OBJECT_STORAGE_REGION_ENV, "").strip() or None
        endpoint = os.getenv(OBJECT_STORAGE_ENDPOINT_ENV, "").strip() or None
        if not provider and not bucket:
            raise ObjectStorageError("Object storage is not configured.")
        provider = provider or DEFAULT_PROVIDER
        if provider != DEFAULT_PROVIDER:
            raise ObjectStorageError(
                f"Unsupported object storage provider: {provider}"
            )
        if not bucket:
            raise ObjectStorageError(
                f"{OBJECT_STORAGE_BUCKET_ENV} is required when object storage is enabled."
            )
        return cls(
            provider=provider,
            bucket=bucket,
            prefix=prefix,
            region=region,
            endpoint_url=endpoint,
        )


def _now_iso() -> str:
    return (
        datetime.now(timezone.utc)
        .replace(microsecond=0)
        .isoformat()
        .replace("+00:00", "Z")
    )


def _normalize_prefix(value: str) -> str:
    text = str(value or "").strip().replace("\\", "/").strip("/")
    parts = [part for part in text.split("/") if part]
    if any(part in {".", ".."} for part in parts):
        raise ObjectStorageError("Object storage prefix contains unsafe path segments.")
    return "/".join(parts) or DEFAULT_PREFIX


def object_storage_configured() -> bool:
    return bool(
        os.getenv(OBJECT_STORAGE_PROVIDER_ENV, "").strip()
        or os.getenv(OBJECT_STORAGE_BUCKET_ENV, "").strip()
        or os.getenv(OBJECT_STORAGE_REGION_ENV, "").strip()
        or os.getenv(OBJECT_STORAGE_ENDPOINT_ENV, "").strip()
    )


def validate_object_storage_configuration() -> ObjectStorageConfig | None:
    if not object_storage_configured():
        return None
    config = ObjectStorageConfig.from_env()
    if not artifact_encryption_enabled():
        raise ObjectStorageError(
            "Remote case replication requires BS_ARTIFACT_ENCRYPTION_KEY."
        )
    validate_artifact_encryption_key()
    return config


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _safe_case_id(case_id: str) -> str:
    value = str(case_id or "").strip()
    if not _CASE_ID_RE.fullmatch(value):
        raise ObjectStorageError("Invalid case_id for object storage.")
    return value


def _safe_relative_path(value: str) -> PurePosixPath:
    rel = PurePosixPath(str(value or ""))
    if rel.is_absolute() or not rel.parts:
        raise ObjectStorageError("Invalid object-storage relative path.")
    if any(part in {"", ".", ".."} for part in rel.parts):
        raise ObjectStorageError("Unsafe object-storage relative path.")
    return rel


def _case_prefix(config: ObjectStorageConfig, case_id: str) -> str:
    return f"{config.prefix}/{_safe_case_id(case_id)}"


def _client(config: ObjectStorageConfig):
    kwargs: dict[str, Any] = {}
    if config.region:
        kwargs["region_name"] = config.region
    if config.endpoint_url:
        kwargs["endpoint_url"] = config.endpoint_url
    return boto3.client("s3", **kwargs)


def _body_bytes(body: Any) -> bytes:
    if hasattr(body, "read"):
        data = body.read()
    else:
        data = body
    if not isinstance(data, (bytes, bytearray)):
        raise ObjectStorageError("Object storage returned a non-bytes body.")
    return bytes(data)


class ObjectStorageService:
    def __init__(
        self,
        config: ObjectStorageConfig | None = None,
        *,
        client: Any | None = None,
    ):
        self.config = config or ObjectStorageConfig.from_env()
        self.client = client or _client(self.config)

    def _encrypted_files(self, work_dir: Path) -> list[Path]:
        if not artifact_encryption_enabled():
            raise ObjectStorageError(
                "Remote case replication requires BS_ARTIFACT_ENCRYPTION_KEY."
            )
        validate_artifact_encryption_key()
        files: list[Path] = []
        for path in sorted(work_dir.rglob("*")):
            if path.is_symlink():
                raise ObjectStorageError(
                    f"Symlinked case artifact is not allowed: {path}"
                )
            if not path.is_file():
                continue
            if not path.name.endswith(".enc"):
                raise ObjectStorageError(
                    f"Plaintext retained case artifact blocks replication: {path.name}"
                )
            files.append(path)
        if not files:
            raise ObjectStorageError("No encrypted case artifacts were found.")
        return files

    def replicate_case(self, case_id: str, work_dir: str | Path) -> dict[str, Any]:
        case_id = _safe_case_id(case_id)
        root = validate_managed_work_dir(
            work_dir,
            allow_temp=True,
            must_exist=True,
        )
        files = self._encrypted_files(root)
        case_prefix = _case_prefix(self.config, case_id)

        manifest_files: list[dict[str, Any]] = []
        uploaded_keys: list[str] = []
        try:
            for path in files:
                rel = path.relative_to(root).as_posix()
                _safe_relative_path(rel)
                key = f"{case_prefix}/files/{rel}"
                size = path.stat().st_size
                sha256 = _sha256_file(path)
                with path.open("rb") as handle:
                    self.client.upload_fileobj(
                        handle,
                        self.config.bucket,
                        key,
                    )
                uploaded_keys.append(key)
                manifest_files.append(
                    {
                        "path": rel,
                        "object_key": key,
                        "size_bytes": size,
                        "sha256": sha256,
                    }
                )

            replicated_at = _now_iso()
            manifest = {
                "schema": OBJECT_STORAGE_SCHEMA,
                "case_id": case_id,
                "provider": self.config.provider,
                "bucket": self.config.bucket,
                "case_prefix": case_prefix,
                "replicated_at": replicated_at,
                "client_side_encryption": "AES-256-GCM",
                "work_dir_name": root.name,
                "files": manifest_files,
            }
            manifest_bytes = (
                json.dumps(
                    manifest,
                    ensure_ascii=False,
                    sort_keys=True,
                    separators=(",", ":"),
                ).encode("utf-8")
                + b"\n"
            )
            manifest_key = f"{case_prefix}/case_manifest.json"
            self.client.put_object(
                Bucket=self.config.bucket,
                Key=manifest_key,
                Body=manifest_bytes,
                ContentType="application/json",
            )
            uploaded_keys.append(manifest_key)
        except Exception as exc:
            for key in reversed(uploaded_keys):
                try:
                    self.client.delete_object(
                        Bucket=self.config.bucket,
                        Key=key,
                    )
                except Exception:
                    pass
            if isinstance(exc, ObjectStorageError):
                raise
            raise ObjectStorageError(
                f"Object storage replication failed: {exc}"
            ) from exc

        total_bytes = sum(int(row["size_bytes"]) for row in manifest_files)
        return {
            "provider": self.config.provider,
            "bucket": self.config.bucket,
            "case_prefix": case_prefix,
            "manifest_key": manifest_key,
            "manifest_sha256": _sha256_bytes(manifest_bytes),
            "replicated_at": replicated_at,
            "file_count": len(manifest_files),
            "total_bytes": total_bytes,
            "client_side_encryption": "AES-256-GCM",
        }

    def _load_manifest(
        self,
        case_id: str,
        remote: dict[str, Any],
    ) -> tuple[dict[str, Any], bytes]:
        case_id = _safe_case_id(case_id)
        if str(remote.get("provider") or "") != self.config.provider:
            raise ObjectStorageError("Recorded object-storage provider mismatch.")
        if str(remote.get("bucket") or "") != self.config.bucket:
            raise ObjectStorageError("Recorded object-storage bucket mismatch.")

        manifest_key = str(remote.get("manifest_key") or "").strip()
        expected_prefix = _case_prefix(self.config, case_id)
        if manifest_key != f"{expected_prefix}/case_manifest.json":
            raise ObjectStorageError("Recorded object-storage manifest key is invalid.")

        try:
            response = self.client.get_object(
                Bucket=self.config.bucket,
                Key=manifest_key,
            )
            manifest_bytes = _body_bytes(response.get("Body"))
        except Exception as exc:
            raise ObjectStorageError(
                f"Unable to read remote case manifest: {exc}"
            ) from exc

        expected_sha = str(remote.get("manifest_sha256") or "")
        actual_sha = _sha256_bytes(manifest_bytes)
        if not expected_sha or actual_sha != expected_sha:
            raise ObjectStorageError("Remote case manifest SHA-256 mismatch.")

        try:
            manifest = json.loads(manifest_bytes.decode("utf-8"))
        except Exception as exc:
            raise ObjectStorageError("Remote case manifest JSON is invalid.") from exc
        if not isinstance(manifest, dict):
            raise ObjectStorageError("Remote case manifest must be an object.")
        if manifest.get("schema") != OBJECT_STORAGE_SCHEMA:
            raise ObjectStorageError("Unsupported remote case manifest schema.")
        if manifest.get("case_id") != case_id:
            raise ObjectStorageError("Remote case manifest case_id mismatch.")
        if manifest.get("bucket") != self.config.bucket:
            raise ObjectStorageError("Remote case manifest bucket mismatch.")
        if manifest.get("case_prefix") != expected_prefix:
            raise ObjectStorageError("Remote case manifest prefix mismatch.")
        if manifest.get("client_side_encryption") != "AES-256-GCM":
            raise ObjectStorageError("Remote case is not client-side encrypted.")
        return manifest, manifest_bytes

    def delete_replica(
        self,
        case_id: str,
        remote: dict[str, Any],
    ) -> dict[str, Any]:
        manifest, _ = self._load_manifest(case_id, remote)
        rows = manifest.get("files")
        if not isinstance(rows, list):
            raise ObjectStorageError(
                "Remote case manifest files are invalid."
            )
        keys: list[str] = []
        for row in rows:
            if not isinstance(row, dict):
                raise ObjectStorageError(
                    "Remote case manifest contains an invalid file row."
                )
            rel = _safe_relative_path(str(row.get("path") or ""))
            expected_key = (
                f"{_case_prefix(self.config, case_id)}/files/{rel.as_posix()}"
            )
            if row.get("object_key") != expected_key:
                raise ObjectStorageError(
                    "Remote case manifest object key mismatch."
                )
            keys.append(expected_key)
        keys.append(str(remote.get("manifest_key") or ""))

        deleted = 0
        try:
            for key in keys:
                self.client.delete_object(
                    Bucket=self.config.bucket,
                    Key=key,
                )
                deleted += 1
        except Exception as exc:
            raise ObjectStorageError(
                f"Remote replica deletion failed after {deleted} object(s): {exc}"
            ) from exc

        return {
            "provider": self.config.provider,
            "bucket": self.config.bucket,
            "case_prefix": _case_prefix(self.config, case_id),
            "deleted_at": _now_iso(),
            "deleted_object_count": deleted,
        }

    def restore_case(
        self,
        case_id: str,
        target_dir: str | Path,
        remote: dict[str, Any],
        *,
        overwrite: bool = False,
    ) -> dict[str, Any]:
        if not artifact_encryption_enabled():
            raise ObjectStorageError(
                "Remote case restore requires BS_ARTIFACT_ENCRYPTION_KEY."
            )
        validate_artifact_encryption_key()

        case_id = _safe_case_id(case_id)
        target = validate_managed_work_dir(
            target_dir,
            allow_temp=True,
            must_exist=False,
        )
        if target.exists() and any(target.iterdir()) and not overwrite:
            raise ObjectStorageError(
                "Restore target already contains files; set overwrite=true explicitly."
            )

        manifest, _ = self._load_manifest(case_id, remote)
        rows = manifest.get("files")
        if not isinstance(rows, list) or not rows:
            raise ObjectStorageError("Remote case manifest contains no files.")

        parent = target.parent
        parent.mkdir(parents=True, exist_ok=True)
        temp_root = Path(
            tempfile.mkdtemp(
                prefix=f".{target.name}.restore-",
                dir=str(parent),
            )
        )
        backup_dir: Path | None = None
        restored_files: list[Path] = []
        try:
            for row in rows:
                if not isinstance(row, dict):
                    raise ObjectStorageError(
                        "Remote case manifest contains an invalid file row."
                    )
                rel = _safe_relative_path(str(row.get("path") or ""))
                if not rel.name.endswith(".enc"):
                    raise ObjectStorageError(
                        "Remote case manifest contains a plaintext artifact."
                    )
                expected_key = (
                    f"{_case_prefix(self.config, case_id)}/files/{rel.as_posix()}"
                )
                if row.get("object_key") != expected_key:
                    raise ObjectStorageError(
                        "Remote case manifest object key mismatch."
                    )
                destination = temp_root.joinpath(*rel.parts)
                destination.parent.mkdir(parents=True, exist_ok=True)
                try:
                    with destination.open("wb") as handle:
                        self.client.download_fileobj(
                            self.config.bucket,
                            expected_key,
                            handle,
                        )
                except Exception as exc:
                    raise ObjectStorageError(
                        f"Remote case object download failed: {rel.as_posix()}"
                    ) from exc
                expected_size = int(row.get("size_bytes") or -1)
                expected_sha = str(row.get("sha256") or "")
                if destination.stat().st_size != expected_size:
                    raise ObjectStorageError(
                        f"Restored object size mismatch: {rel.as_posix()}"
                    )
                if _sha256_file(destination) != expected_sha:
                    raise ObjectStorageError(
                        f"Restored object SHA-256 mismatch: {rel.as_posix()}"
                    )
                restored_files.append(destination)

            for encrypted in restored_files:
                logical = plaintext_path(encrypted)
                verify_artifact(logical, temp_root)

            if target.exists():
                if any(target.iterdir()):
                    backup_dir = target.with_name(
                        target.name + ".restore-backup"
                    )
                    if backup_dir.exists():
                        raise ObjectStorageError(
                            "Restore backup path already exists."
                        )
                    target.replace(backup_dir)
                else:
                    target.rmdir()

            temp_root.replace(target)
            if backup_dir is not None and backup_dir.exists():
                shutil.rmtree(backup_dir)
        except Exception:
            if temp_root.exists():
                shutil.rmtree(temp_root, ignore_errors=True)
            if backup_dir is not None and backup_dir.exists() and not target.exists():
                backup_dir.replace(target)
            raise

        return {
            "provider": self.config.provider,
            "bucket": self.config.bucket,
            "case_prefix": _case_prefix(self.config, case_id),
            "restored_at": _now_iso(),
            "file_count": len(restored_files),
            "target_dir": str(target),
            "verified": True,
        }


__all__ = [
    "OBJECT_STORAGE_SCHEMA",
    "ObjectStorageConfig",
    "ObjectStorageError",
    "ObjectStorageService",
    "object_storage_configured",
    "validate_object_storage_configuration",
]
