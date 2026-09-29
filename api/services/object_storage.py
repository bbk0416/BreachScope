"""S3-compatible replication/restore for encrypted retained cases."""
from __future__ import annotations

import hashlib
import json
import os
import re
import shutil
import tempfile
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path, PurePosixPath
from typing import Any, Iterator

import boto3

from api.services.artifact_encryption import (
    artifact_encryption_enabled,
    plaintext_path,
    validate_artifact_encryption_key,
    verify_artifact,
)
from api.services.organization_scope import (
    configured_default_organization,
    normalize_organization_id,
)
from api.services.path_boundary import validate_managed_work_dir


OBJECT_STORAGE_PROVIDER_ENV = "BS_OBJECT_STORAGE_PROVIDER"
OBJECT_STORAGE_BUCKET_ENV = "BS_OBJECT_STORAGE_BUCKET"
OBJECT_STORAGE_PREFIX_ENV = "BS_OBJECT_STORAGE_PREFIX"
OBJECT_STORAGE_REGION_ENV = "BS_OBJECT_STORAGE_REGION"
OBJECT_STORAGE_ENDPOINT_ENV = "BS_OBJECT_STORAGE_ENDPOINT_URL"

LEGACY_OBJECT_STORAGE_SCHEMA = "breachscope.case-object-storage.v1"
OBJECT_STORAGE_SCHEMA = "breachscope.case-object-storage.v2"
OBJECT_STORAGE_NAMESPACE_VERSION = 2
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


def _safe_organization_id(
    value: object | None,
    *,
    default: str | None,
) -> str:
    try:
        return normalize_organization_id(value, default=default)
    except ValueError as exc:
        raise ObjectStorageError(
            "Invalid organization_id for object storage."
        ) from exc


def _safe_relative_path(value: str) -> PurePosixPath:
    rel = PurePosixPath(str(value or ""))
    if rel.is_absolute() or not rel.parts:
        raise ObjectStorageError("Invalid object-storage relative path.")
    if any(part in {"", ".", ".."} for part in rel.parts):
        raise ObjectStorageError("Unsafe object-storage relative path.")
    return rel


def _legacy_case_prefix(config: ObjectStorageConfig, case_id: str) -> str:
    return f"{config.prefix}/{_safe_case_id(case_id)}"


def _case_prefix(
    config: ObjectStorageConfig,
    case_id: str,
    organization_id: str,
) -> str:
    organization = _safe_organization_id(
        organization_id,
        default=None,
    )
    return f"{config.prefix}/orgs/{organization}/{_safe_case_id(case_id)}"


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

    def replicate_case(
        self,
        case_id: str,
        work_dir: str | Path,
        *,
        organization_id: str | None = None,
    ) -> dict[str, Any]:
        case_id = _safe_case_id(case_id)
        organization = _safe_organization_id(
            organization_id,
            default=configured_default_organization(),
        )
        root = validate_managed_work_dir(
            work_dir,
            allow_temp=True,
            must_exist=True,
        )
        files = self._encrypted_files(root)
        case_prefix = _case_prefix(
            self.config,
            case_id,
            organization,
        )

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
                "namespace_version": OBJECT_STORAGE_NAMESPACE_VERSION,
                "organization_id": organization,
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
            "namespace_version": OBJECT_STORAGE_NAMESPACE_VERSION,
            "organization_id": organization,
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
        *,
        organization_id: str | None = None,
    ) -> tuple[dict[str, Any], bytes, str]:
        case_id = _safe_case_id(case_id)
        requested_organization = _safe_organization_id(
            organization_id,
            default=configured_default_organization(),
        )
        if str(remote.get("provider") or "") != self.config.provider:
            raise ObjectStorageError("Recorded object-storage provider mismatch.")
        if str(remote.get("bucket") or "") != self.config.bucket:
            raise ObjectStorageError("Recorded object-storage bucket mismatch.")

        recorded_organization_raw = remote.get("organization_id")
        if recorded_organization_raw is None:
            if requested_organization != configured_default_organization():
                raise ObjectStorageError(
                    "Legacy remote replica belongs to the default organization."
                )
            expected_prefix = _legacy_case_prefix(self.config, case_id)
            expected_schema = LEGACY_OBJECT_STORAGE_SCHEMA
            namespace = "legacy-default"
        else:
            recorded_organization = _safe_organization_id(
                recorded_organization_raw,
                default=None,
            )
            if recorded_organization != requested_organization:
                raise ObjectStorageError(
                    "Recorded object-storage organization mismatch."
                )
            expected_prefix = _case_prefix(
                self.config,
                case_id,
                recorded_organization,
            )
            expected_schema = OBJECT_STORAGE_SCHEMA
            namespace = "organization"

        recorded_prefix = str(remote.get("case_prefix") or "").strip()
        if recorded_prefix and recorded_prefix != expected_prefix:
            raise ObjectStorageError("Recorded object-storage case prefix is invalid.")

        manifest_key = str(remote.get("manifest_key") or "").strip()
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
        if manifest.get("schema") != expected_schema:
            raise ObjectStorageError("Unsupported remote case manifest schema.")
        if manifest.get("case_id") != case_id:
            raise ObjectStorageError("Remote case manifest case_id mismatch.")
        if manifest.get("bucket") != self.config.bucket:
            raise ObjectStorageError("Remote case manifest bucket mismatch.")
        if manifest.get("case_prefix") != expected_prefix:
            raise ObjectStorageError("Remote case manifest prefix mismatch.")
        if namespace == "organization":
            if manifest.get("namespace_version") != OBJECT_STORAGE_NAMESPACE_VERSION:
                raise ObjectStorageError(
                    "Remote case manifest namespace version mismatch."
                )
            if manifest.get("organization_id") != requested_organization:
                raise ObjectStorageError(
                    "Remote case manifest organization mismatch."
                )
        if manifest.get("client_side_encryption") != "AES-256-GCM":
            raise ObjectStorageError("Remote case is not client-side encrypted.")
        return manifest, manifest_bytes, expected_prefix

    def materialize_temporary_case(
        self,
        case_id: str,
        remote: dict[str, Any],
        *,
        organization_id: str | None = None,
    ) -> tuple[Path, dict[str, Any]]:
        """Fully verify a remote replica into a managed temporary directory."""
        target = Path(
            tempfile.mkdtemp(prefix="bs_web_remote_")
        )
        try:
            result = self.restore_case(
                case_id,
                target,
                remote,
                overwrite=False,
                organization_id=organization_id,
            )
        except Exception:
            if target.exists():
                shutil.rmtree(target, ignore_errors=True)
            raise
        return target, result

    @staticmethod
    def cleanup_temporary_case(target_dir: str | Path) -> None:
        """Remove only a BreachScope-owned direct temp restore directory."""
        target = Path(target_dir)
        if not target.exists():
            return
        try:
            resolved = validate_managed_work_dir(
                target,
                allow_temp=True,
                must_exist=True,
            )
        except (ValueError, FileNotFoundError, OSError):
            return
        if not resolved.name.startswith("bs_web_remote_"):
            return
        shutil.rmtree(resolved, ignore_errors=True)

    @contextmanager
    def temporary_case(
        self,
        case_id: str,
        remote: dict[str, Any],
        *,
        organization_id: str | None = None,
    ) -> Iterator[tuple[Path, dict[str, Any]]]:
        """Yield a verified temporary remote case and always clean it up."""
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
        remote: dict[str, Any],
        *,
        organization_id: str | None = None,
    ) -> dict[str, Any]:
        """Prove the remote replica can be fully restored and authenticated."""
        probe = Path(tempfile.mkdtemp(prefix="bs_web_"))
        try:
            restored = self.restore_case(
                case_id,
                probe,
                remote,
                overwrite=False,
                organization_id=organization_id,
            )
        finally:
            if probe.exists():
                shutil.rmtree(probe, ignore_errors=True)

        return {
            "provider": self.config.provider,
            "bucket": self.config.bucket,
            "case_prefix": str(remote.get("case_prefix") or ""),
            "manifest_sha256": str(
                restored.get("manifest_sha256") or ""
            ),
            "verified_at": _now_iso(),
            "file_count": int(restored.get("file_count") or 0),
            "verified": bool(restored.get("verified")),
        }

    def delete_replica(
        self,
        case_id: str,
        remote: dict[str, Any],
        *,
        organization_id: str | None = None,
    ) -> dict[str, Any]:
        manifest, _, expected_prefix = self._load_manifest(
            case_id,
            remote,
            organization_id=organization_id,
        )
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
            expected_key = f"{expected_prefix}/files/{rel.as_posix()}"
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
            "case_prefix": expected_prefix,
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
        organization_id: str | None = None,
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

        manifest, manifest_bytes, expected_prefix = self._load_manifest(
            case_id,
            remote,
            organization_id=organization_id,
        )
        verified_manifest_sha256 = _sha256_bytes(manifest_bytes)
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
                expected_key = f"{expected_prefix}/files/{rel.as_posix()}"
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
            "case_prefix": expected_prefix,
            "manifest_sha256": verified_manifest_sha256,
            "restored_at": _now_iso(),
            "file_count": len(restored_files),
            "target_dir": str(target),
            "verified": True,
        }


__all__ = [
    "LEGACY_OBJECT_STORAGE_SCHEMA",
    "OBJECT_STORAGE_SCHEMA",
    "OBJECT_STORAGE_NAMESPACE_VERSION",
    "ObjectStorageConfig",
    "ObjectStorageError",
    "ObjectStorageService",
    "object_storage_configured",
    "validate_object_storage_configuration",
]
