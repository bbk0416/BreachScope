"""Versioned activation manifest for published custom rules."""
from __future__ import annotations

import hashlib
import json
import os
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from breachscope.rules import RuleLoadError, load_rules
from breachscope.schemas import Rule

from .rule_authoring import RuleAuthoringService
from .rule_tuning_concurrency import rule_tuning_lock


ACTIVATION_PATH_ENV = "BS_RULE_ACTIVATION_PATH"
ACTIVATION_SCHEMA = "breachscope.rule_activation.v1"
MAX_HISTORY = 100


class RuleActivationError(ValueError):
    pass


class RuleActivationVersionConflict(RuleActivationError):
    pass


class RuleActivationService:
    def __init__(
        self,
        path: Path | None = None,
        authoring_root: Path | None = None,
    ):
        self.path = (path or self.default_path()).expanduser().resolve()
        self.authoring = RuleAuthoringService(root=authoring_root)
        self.path.parent.mkdir(parents=True, exist_ok=True)

    @staticmethod
    def default_path() -> Path:
        raw = os.getenv(ACTIVATION_PATH_ENV)
        if raw:
            return Path(raw)
        return Path.home() / ".breachscope" / "rule_activation.json"

    @staticmethod
    def _now() -> str:
        return (
            datetime.now(timezone.utc)
            .replace(microsecond=0)
            .isoformat()
            .replace("+00:00", "Z")
        )

    @staticmethod
    def _base_document() -> dict[str, Any]:
        return {
            "schema": ACTIVATION_SCHEMA,
            "version": 0,
            "updated_at": None,
            "updated_by": None,
            "active": [],
            "history": [
                {
                    "version": 0,
                    "updated_at": None,
                    "updated_by": None,
                    "reason": "initial",
                    "active": [],
                }
            ],
        }

    def _read(self) -> dict[str, Any]:
        if not self.path.exists():
            return self._base_document()
        try:
            data = json.loads(self.path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            raise RuleActivationError(
                f"룰 activation manifest를 읽을 수 없습니다: {self.path}"
            ) from exc
        if not isinstance(data, dict) or data.get("schema") != ACTIVATION_SCHEMA:
            raise RuleActivationError("지원하지 않는 룰 activation manifest 형식입니다.")
        if not isinstance(data.get("active"), list) or not isinstance(
            data.get("history"), list
        ):
            raise RuleActivationError("룰 activation manifest가 손상되었습니다.")
        return data

    def _write(self, data: dict[str, Any]) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        fd, tmp_name = tempfile.mkstemp(
            prefix="rule_activation_", suffix=".json", dir=str(self.path.parent)
        )
        tmp = Path(tmp_name)
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as handle:
                json.dump(data, handle, ensure_ascii=False, indent=2)
                handle.write("\n")
            tmp.replace(self.path)
        finally:
            if tmp.exists():
                try:
                    tmp.unlink()
                except OSError:
                    pass

    @staticmethod
    def _assert_version(data: dict[str, Any], expected_version: int) -> None:
        current = int(data.get("version") or 0)
        if current != int(expected_version):
            raise RuleActivationVersionConflict(
                f"activation manifest 버전이 변경되었습니다: "
                f"expected={expected_version}, current={current}"
            )

    def _publication(self, draft_id: str, published_version: int) -> dict[str, Any]:
        try:
            draft = self.authoring.get_draft(draft_id)
        except KeyError as exc:
            raise RuleActivationError("publish된 custom rule draft를 찾을 수 없습니다.") from exc

        for item in draft.get("publications") or []:
            if int(item.get("version") or 0) == int(published_version):
                publication = dict(item)
                publication["draft_id"] = draft_id
                return publication
        raise RuleActivationError(
            f"publish artifact를 찾을 수 없습니다: {draft_id} v{published_version}"
        )

    def _verify_publication(self, publication: dict[str, Any]) -> tuple[Path, Rule]:
        relative = str(publication.get("relative_path") or "")
        if not relative:
            raise RuleActivationError("publish artifact 경로가 비어 있습니다.")
        root = self.authoring.root.resolve()
        path = (root / relative).resolve()
        try:
            path.relative_to(root)
        except ValueError as exc:
            raise RuleActivationError("publish artifact 경로가 authoring root 밖입니다.") from exc
        if not path.is_file():
            raise RuleActivationError(f"publish artifact가 없습니다: {relative}")

        payload = path.read_bytes()
        actual_sha = hashlib.sha256(payload).hexdigest()
        expected_sha = str(publication.get("sha256") or "")
        if not expected_sha or actual_sha != expected_sha:
            raise RuleActivationError(
                f"publish artifact SHA-256 불일치: {relative}"
            )

        with tempfile.TemporaryDirectory(
            prefix="rule_activation_validate_",
            dir=str(self.path.parent),
        ) as tmp_dir:
            temp_rule = Path(tmp_dir) / "candidate.yml"
            temp_rule.write_bytes(payload)
            try:
                loaded = load_rules(temp_rule.parent)
            except RuleLoadError as exc:
                raise RuleActivationError(
                    f"active custom rule runtime validation failed: {relative}"
                ) from exc
        if len(loaded) != 1:
            raise RuleActivationError(
                f"publish artifact는 정확히 1개 룰이어야 합니다: {relative}"
            )
        rule = loaded[0]
        if rule.id != publication.get("rule_id"):
            raise RuleActivationError(
                f"publish metadata와 artifact rule ID가 다릅니다: {relative}"
            )
        return path, rule

    @staticmethod
    def _entry(publication: dict[str, Any]) -> dict[str, Any]:
        return {
            "draft_id": publication["draft_id"],
            "published_version": int(publication["version"]),
            "rule_id": str(publication["rule_id"]),
            "relative_path": str(publication["relative_path"]),
            "sha256": str(publication["sha256"]),
        }

    def _commit_state(
        self,
        data: dict[str, Any],
        *,
        active: list[dict[str, Any]],
        actor: str,
        reason: str,
    ) -> dict[str, Any]:
        version = int(data.get("version") or 0) + 1
        now = self._now()
        snapshot = {
            "version": version,
            "updated_at": now,
            "updated_by": str(actor or "system")[:120],
            "reason": reason[:500],
            "active": [dict(item) for item in active],
        }
        history = list(data.get("history") or [])
        history.append(snapshot)
        history = history[-MAX_HISTORY:]
        updated = {
            "schema": ACTIVATION_SCHEMA,
            "version": version,
            "updated_at": now,
            "updated_by": snapshot["updated_by"],
            "active": [dict(item) for item in active],
            "history": history,
        }
        self._write(updated)
        return updated

    def get_state(self) -> dict[str, Any]:
        with rule_tuning_lock(self.path):
            return self._read()

    def activate(
        self,
        *,
        draft_id: str,
        published_version: int,
        expected_version: int,
        actor: str = "system",
    ) -> dict[str, Any]:
        publication = self._publication(draft_id, published_version)
        self._verify_publication(publication)
        entry = self._entry(publication)

        with rule_tuning_lock(self.path):
            data = self._read()
            self._assert_version(data, expected_version)
            active = [
                item
                for item in data.get("active") or []
                if item.get("draft_id") != draft_id
                and str(item.get("rule_id") or "").casefold()
                != entry["rule_id"].casefold()
            ]
            active.append(entry)
            active = sorted(active, key=lambda item: str(item["rule_id"]).casefold())
            return self._commit_state(
                data,
                active=active,
                actor=actor,
                reason=f"activate {entry['rule_id']} from {draft_id} v{published_version}",
            )

    def deactivate(
        self,
        *,
        draft_id: str,
        expected_version: int,
        actor: str = "system",
    ) -> dict[str, Any]:
        with rule_tuning_lock(self.path):
            data = self._read()
            self._assert_version(data, expected_version)
            active = [
                item for item in data.get("active") or []
                if item.get("draft_id") != draft_id
            ]
            if len(active) == len(data.get("active") or []):
                raise RuleActivationError("해당 draft는 현재 활성화되어 있지 않습니다.")
            return self._commit_state(
                data,
                active=active,
                actor=actor,
                reason=f"deactivate {draft_id}",
            )

    def rollback(
        self,
        *,
        target_version: int,
        expected_version: int,
        actor: str = "system",
    ) -> dict[str, Any]:
        with rule_tuning_lock(self.path):
            data = self._read()
            self._assert_version(data, expected_version)
            target = next(
                (
                    item
                    for item in data.get("history") or []
                    if int(item.get("version", -1)) == int(target_version)
                ),
                None,
            )
            if target is None:
                raise RuleActivationError(
                    f"rollback 대상 activation version이 없습니다: {target_version}"
                )
            active = [dict(item) for item in target.get("active") or []]
            for item in active:
                publication = self._publication(
                    str(item["draft_id"]),
                    int(item["published_version"]),
                )
                self._verify_publication(publication)
                if self._entry(publication) != item:
                    raise RuleActivationError(
                        "rollback 대상 publication metadata가 현재 저장소와 일치하지 않습니다."
                    )
            return self._commit_state(
                data,
                active=active,
                actor=actor,
                reason=f"rollback to activation version {target_version}",
            )

    def load_active_rules(self) -> tuple[list[Rule], list[dict[str, Any]]]:
        with rule_tuning_lock(self.path):
            data = self._read()
            rules: list[Rule] = []
            provenance: list[dict[str, Any]] = []
            seen: set[str] = set()
            for item in data.get("active") or []:
                publication = self._publication(
                    str(item["draft_id"]),
                    int(item["published_version"]),
                )
                if self._entry(publication) != item:
                    raise RuleActivationError(
                        "activation manifest와 publication metadata가 일치하지 않습니다."
                    )
                _, rule = self._verify_publication(publication)
                key = rule.id.casefold()
                if key in seen:
                    raise RuleActivationError(
                        f"active custom rule ID가 중복됩니다: {rule.id}"
                    )
                seen.add(key)
                rules.append(rule)
                provenance.append(
                    {
                        "rule_id": rule.id,
                        "draft_id": item["draft_id"],
                        "published_version": item["published_version"],
                        "sha256": item["sha256"],
                        "relative_path": item["relative_path"],
                    }
                )
            return rules, provenance
