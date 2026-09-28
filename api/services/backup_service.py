"""Case/audit backup utilities for small BreachScope deployments."""
from __future__ import annotations

import hashlib
import json
import os
import tempfile
import zipfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from api.services.audit_log import AuditLogService, audit_log_path
from api.services.case_history import CaseHistoryService
from api.services.organization_scope import (
    configured_default_organization,
    normalize_organization_id,
    organization_scoped_file_path,
    organization_scoped_root,
)
from api.services.rule_activation import RuleActivationService
from api.services.rule_authoring import RuleAuthoringService
from api.services.rule_tuning import RuleTuningProfileService


BACKUP_ROOT_ENV = "BS_BACKUP_ROOT"


def _now_iso() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def _sha256(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as fp:
        for chunk in iter(lambda: fp.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def _sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _safe_backup_id(value: str) -> str:
    allowed = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_"
    return "".join(ch for ch in value if ch in allowed)


class BackupService:
    """Create/list/download self-contained ZIP backups.

    Backups include only the active organization's case metadata/artifacts,
    audit events, and custom-rule lifecycle stores. The default organization keeps
    the legacy backup root; non-default organizations use separate subdirectories.
    Deployment-wide recovery should still use external volume snapshots.
    """

    def __init__(
        self,
        backup_root: Path | None = None,
        organization_id: str | None = None,
    ):
        self.base_backup_root = (
            backup_root or self.default_root()
        ).expanduser().resolve()
        self.organization_id = normalize_organization_id(
            organization_id,
            default=configured_default_organization(),
        )
        self.backup_root = organization_scoped_root(
            self.base_backup_root,
            self.organization_id,
        )
        self.backup_root.mkdir(parents=True, exist_ok=True)

    @staticmethod
    def default_root() -> Path:
        raw = os.getenv(BACKUP_ROOT_ENV, "").strip()
        if raw:
            return Path(raw).expanduser().resolve()
        return (Path.home() / ".breachscope" / "backups").resolve()

    def create_backup(self, *, include_cases: bool = True, include_audit: bool = True, label: str | None = None) -> dict[str, Any]:
        created_at = _now_iso()
        suffix = hashlib.sha256(f"{created_at}|{label or ''}".encode("utf-8")).hexdigest()[:8]
        backup_id = f"backup-{created_at.replace('-', '').replace(':', '').replace('Z', '').replace('T', '-')}-{suffix}"
        backup_id = _safe_backup_id(backup_id)
        zip_path = self.backup_root / f"{backup_id}.zip"
        sidecar = self.backup_root / f"{backup_id}.manifest.json"
        history_service = CaseHistoryService(
            organization_id=self.organization_id
        )
        history_path = history_service.index_path
        history_snapshot = (
            history_service.scoped_index_snapshot()
            if history_path.exists()
            else {"cases": []}
        )
        cases_root = CaseHistoryService.default_root()
        audit_path = audit_log_path()

        tuning_base = RuleTuningProfileService.default_path().expanduser().resolve()
        rule_tuning_path = organization_scoped_file_path(
            tuning_base,
            self.organization_id,
            namespace="rule_tuning",
        )
        authoring_base = RuleAuthoringService.default_root().expanduser().resolve()
        rule_authoring_root = organization_scoped_root(
            authoring_base,
            self.organization_id,
        )
        activation_base = RuleActivationService.default_path().expanduser().resolve()
        rule_activation_path = organization_scoped_file_path(
            activation_base,
            self.organization_id,
            namespace="rule_activation",
        )

        manifest: dict[str, Any] = {
            "backup_id": backup_id,
            "created_at": created_at,
            "label": label or "BreachScope backup",
            "organization_id": self.organization_id,
            "scope": "organization",
            "include_cases": include_cases,
            "include_audit": include_audit,
            "sources": {
                "case_history_path": str(history_path),
                "cases_root": str(cases_root),
                "audit_log_path": str(audit_path),
                "rule_tuning_path": str(rule_tuning_path),
                "rule_authoring_root": str(rule_authoring_root),
                "rule_activation_path": str(rule_activation_path),
            },
            "files": [],
        }

        fd, tmp_name = tempfile.mkstemp(prefix="breachscope_backup_", suffix=".zip", dir=str(self.backup_root))
        os.close(fd)
        tmp_path = Path(tmp_name)
        try:
            with zipfile.ZipFile(
                tmp_path,
                "w",
                compression=zipfile.ZIP_DEFLATED,
            ) as zf:
                if history_path.exists():
                    history_bytes = (
                        json.dumps(
                            history_snapshot,
                            ensure_ascii=False,
                            indent=2,
                        ).encode("utf-8")
                        + b"\n"
                    )
                    self._add_bytes(
                        zf,
                        history_bytes,
                        Path("case_history.json"),
                        manifest,
                    )

                if include_audit and audit_path.exists():
                    audit_service = AuditLogService(path=audit_path)
                    events = audit_service.read_all_events(
                        organization_id=self.organization_id,
                    )
                    self._add_bytes(
                        zf,
                        audit_service.export_jsonl(events).encode("utf-8"),
                        Path("audit.jsonl"),
                        manifest,
                    )

                if include_cases and cases_root.exists():
                    added: set[str] = set()
                    for row in history_snapshot.get("cases") or []:
                        work_dir = Path(
                            str(row.get("work_dir") or "")
                        ).expanduser()
                        try:
                            work_dir = work_dir.resolve()
                            work_dir.relative_to(cases_root)
                        except (OSError, ValueError):
                            continue
                        if not work_dir.exists():
                            continue
                        for path in sorted(work_dir.rglob("*")):
                            if path.is_symlink() or not path.is_file():
                                continue
                            try:
                                resolved = path.resolve()
                                resolved.relative_to(work_dir)
                                rel = resolved.relative_to(cases_root)
                            except (OSError, ValueError):
                                continue
                            arcname = (Path("cases") / rel).as_posix()
                            if arcname in added:
                                continue
                            added.add(arcname)
                            self._add_file(
                                zf,
                                resolved,
                                Path(arcname),
                                manifest,
                            )

                if rule_tuning_path.exists():
                    self._add_file(
                        zf,
                        rule_tuning_path,
                        Path("rule_tuning_profiles.json"),
                        manifest,
                    )

                if rule_authoring_root.exists():
                    for path in sorted(rule_authoring_root.rglob("*")):
                        if path.is_symlink() or not path.is_file():
                            continue
                        try:
                            resolved = path.resolve()
                            resolved.relative_to(rule_authoring_root)
                            rel = resolved.relative_to(rule_authoring_root)
                        except (OSError, ValueError):
                            continue
                        if (
                            self.organization_id
                            == configured_default_organization()
                            and rel.parts
                            and rel.parts[0] == "organizations"
                        ):
                            continue
                        self._add_file(
                            zf,
                            resolved,
                            Path("rule_authoring") / rel,
                            manifest,
                        )

                if rule_activation_path.exists():
                    self._add_file(
                        zf,
                        rule_activation_path,
                        Path("rule_activation.json"),
                        manifest,
                    )

                zf.writestr(
                    "backup_manifest.json",
                    json.dumps(
                        manifest,
                        ensure_ascii=False,
                        indent=2,
                    )
                    + "\n",
                )
            tmp_path.replace(zip_path)
        finally:
            if tmp_path.exists():
                try:
                    tmp_path.unlink()
                except OSError:
                    pass

        manifest["archive"] = {
            "filename": zip_path.name,
            "size_bytes": zip_path.stat().st_size,
            "sha256": _sha256(zip_path),
        }
        sidecar.write_text(json.dumps(manifest, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
        return self._metadata(zip_path, manifest=manifest)

    @staticmethod
    def _add_file(zf: zipfile.ZipFile, source: Path, arcname: Path, manifest: dict[str, Any]) -> None:
        zf.write(source, arcname.as_posix())
        manifest["files"].append({
            "path": arcname.as_posix(),
            "size_bytes": source.stat().st_size,
            "sha256": _sha256(source),
        })

    @staticmethod
    def _add_bytes(
        zf: zipfile.ZipFile,
        data: bytes,
        arcname: Path,
        manifest: dict[str, Any],
    ) -> None:
        zf.writestr(arcname.as_posix(), data)
        manifest["files"].append(
            {
                "path": arcname.as_posix(),
                "size_bytes": len(data),
                "sha256": _sha256_bytes(data),
            }
        )

    def list_backups(self, limit: int = 50) -> list[dict[str, Any]]:
        zips = sorted(self.backup_root.glob("backup-*.zip"), key=lambda p: p.stat().st_mtime, reverse=True)
        return [self._metadata(path) for path in zips[: max(0, limit)]]

    def get_backup_path(self, backup_id: str) -> Path:
        safe = _safe_backup_id(backup_id)
        if safe != backup_id or not safe:
            raise KeyError(backup_id)
        path = (self.backup_root / f"{safe}.zip").resolve()
        try:
            path.relative_to(self.backup_root.resolve())
        except ValueError:
            raise KeyError(backup_id)
        if not path.exists():
            raise KeyError(backup_id)
        return path

    def integrity(self, backup_id: str) -> dict[str, Any]:
        path = self.get_backup_path(backup_id)
        return {
            "backup_id": backup_id,
            "organization_id": self.organization_id,
            "exists": True,
            "size_bytes": path.stat().st_size,
            "sha256": _sha256(path),
            "filename": path.name,
        }

    def delete_backup(self, backup_id: str) -> dict[str, Any]:
        path = self.get_backup_path(backup_id)
        sidecar = path.with_suffix(".manifest.json")
        path.unlink()
        if sidecar.exists():
            sidecar.unlink()
        return {
            "backup_id": backup_id,
            "organization_id": self.organization_id,
            "deleted": True,
        }

    def _metadata(self, path: Path, manifest: dict[str, Any] | None = None) -> dict[str, Any]:
        backup_id = path.stem
        sidecar = path.with_suffix(".manifest.json")
        if manifest is None and sidecar.exists():
            try:
                manifest = json.loads(sidecar.read_text(encoding="utf-8"))
            except json.JSONDecodeError:
                manifest = None
        return {
            "backup_id": backup_id,
            "organization_id": (
                (manifest or {}).get("organization_id")
                or self.organization_id
            ),
            "filename": path.name,
            "created_at": (manifest or {}).get("created_at"),
            "label": (manifest or {}).get("label"),
            "size_bytes": path.stat().st_size,
            "sha256": _sha256(path),
            "file_count": len((manifest or {}).get("files") or []),
        }
