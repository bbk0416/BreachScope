"""Versioned custom-rule authoring workflow.

Published custom rules are intentionally stored outside the canonical rules/ tree and
are not loaded by the detector unless a future explicit activation path is added.
"""
from __future__ import annotations

import hashlib
import json
import os
import re
import tempfile
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import yaml

from breachscope.rules import RuleLoadError, load_rules
from breachscope.runtime_paths import default_rules_dir

from .rule_tuning_concurrency import rule_tuning_lock


AUTHORING_ROOT_ENV = "BS_RULE_AUTHORING_ROOT"
STORE_SCHEMA = "breachscope.rule_authoring.v1"
MAX_REVISIONS = 100
_RULE_ID_RE = re.compile(r"^[A-Za-z0-9._:-]{1,120}$")
_ATTACK_RE = re.compile(r"^T\d{4}(?:\.\d{3})?$", re.IGNORECASE)


class RuleAuthoringError(ValueError):
    pass


class RuleAuthoringVersionConflict(RuleAuthoringError):
    pass


class RuleAuthoringStateError(RuleAuthoringError):
    pass


class RuleAuthoringService:
    def __init__(self, root: Path | None = None, canonical_rules_dir: Path | None = None):
        self.root = (root or self.default_root()).expanduser().resolve()
        self.index_path = self.root / "drafts.json"
        self.published_root = self.root / "published"
        self.canonical_rules_dir = (
            canonical_rules_dir or default_rules_dir()
        ).expanduser().resolve()
        self.root.mkdir(parents=True, exist_ok=True)

    @staticmethod
    def default_root() -> Path:
        raw = os.getenv(AUTHORING_ROOT_ENV)
        if raw:
            return Path(raw)
        return Path.home() / ".breachscope" / "rule_authoring"

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
        return {"schema": STORE_SCHEMA, "drafts": []}

    def _read(self) -> dict[str, Any]:
        if not self.index_path.exists():
            return self._base_document()
        try:
            data = json.loads(self.index_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            raise RuleAuthoringError(
                f"룰 작성 저장소를 읽을 수 없습니다: {self.index_path}"
            ) from exc
        if not isinstance(data, dict) or data.get("schema") != STORE_SCHEMA:
            raise RuleAuthoringError("지원하지 않는 룰 작성 저장 형식입니다.")
        if not isinstance(data.get("drafts"), list):
            raise RuleAuthoringError("룰 작성 저장소가 손상되었습니다.")
        return data

    def _write(self, data: dict[str, Any]) -> None:
        self.root.mkdir(parents=True, exist_ok=True)
        fd, tmp_name = tempfile.mkstemp(
            prefix="rule_authoring_", suffix=".json", dir=str(self.root)
        )
        tmp = Path(tmp_name)
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as handle:
                json.dump(data, handle, ensure_ascii=False, indent=2)
                handle.write("\n")
            tmp.replace(self.index_path)
        finally:
            if tmp.exists():
                try:
                    tmp.unlink()
                except OSError:
                    pass

    @staticmethod
    def _normalize_text(value: Any, *, field: str, limit: int, required: bool = False) -> str:
        text = str(value or "").strip()
        if required and not text:
            raise RuleAuthoringError(f"{field}은(는) 비워둘 수 없습니다.")
        if len(text) > limit:
            raise RuleAuthoringError(f"{field}은(는) {limit}자를 초과할 수 없습니다.")
        return text

    @classmethod
    def _normalize_rule(cls, payload: dict[str, Any]) -> dict[str, Any]:
        if not isinstance(payload, dict):
            raise RuleAuthoringError("rule은 객체여야 합니다.")
        rule_id = cls._normalize_text(payload.get("id"), field="rule.id", limit=120, required=True)
        if not _RULE_ID_RE.fullmatch(rule_id):
            raise RuleAuthoringError(
                "rule.id는 영문/숫자와 . _ : - 만 사용할 수 있습니다."
            )
        name = cls._normalize_text(payload.get("name"), field="rule.name", limit=200, required=True)
        description = cls._normalize_text(
            payload.get("description"), field="rule.description", limit=2000
        )
        field_name = cls._normalize_text(
            payload.get("field") or "command_line",
            field="rule.field",
            limit=120,
            required=True,
        )
        pattern = str(payload.get("pattern") if "pattern" in payload else "")
        if not pattern:
            raise RuleAuthoringError("rule.pattern은 비워둘 수 없습니다.")
        if len(pattern) > 8000:
            raise RuleAuthoringError("rule.pattern은 8000자를 초과할 수 없습니다.")

        severity = str(payload.get("severity") or "medium").strip().lower()
        if severity not in {"low", "medium", "high", "critical"}:
            raise RuleAuthoringError("rule.severity는 low/medium/high/critical 중 하나여야 합니다.")

        operator = str(payload.get("operator") or "regex").strip().lower()
        if operator not in {"regex", "contains", "startswith", "endswith", "equals"}:
            raise RuleAuthoringError(
                "rule.operator는 regex/contains/startswith/endswith/equals 중 하나여야 합니다."
            )

        technique = cls._normalize_text(
            payload.get("mitre_technique"),
            field="rule.mitre_technique",
            limit=20,
        )
        if technique and not _ATTACK_RE.fullmatch(technique):
            raise RuleAuthoringError("rule.mitre_technique 형식이 올바르지 않습니다.")

        fields_val = payload.get("fields")
        fields: list[str] | None = None
        if fields_val not in (None, ""):
            raw_fields = fields_val.split(",") if isinstance(fields_val, str) else list(fields_val)
            fields = []
            for value in raw_fields:
                item = cls._normalize_text(value, field="rule.fields", limit=120)
                if item and item not in fields:
                    fields.append(item)
            if not fields:
                fields = None

        all_of_val = payload.get("all_of")
        all_of: list[dict[str, str]] | None = None
        if all_of_val not in (None, ""):
            if not isinstance(all_of_val, list) or not all_of_val:
                raise RuleAuthoringError("rule.all_of는 비어 있지 않은 배열이어야 합니다.")
            all_of = []
            for index, condition in enumerate(all_of_val, start=1):
                if not isinstance(condition, dict):
                    raise RuleAuthoringError(f"rule.all_of[{index}]는 객체여야 합니다.")
                c_field = cls._normalize_text(
                    condition.get("field"),
                    field=f"rule.all_of[{index}].field",
                    limit=120,
                    required=True,
                )
                c_pattern = str(
                    condition.get("pattern") if "pattern" in condition else ""
                )
                if not c_pattern:
                    raise RuleAuthoringError(
                        f"rule.all_of[{index}].pattern은 비워둘 수 없습니다."
                    )
                c_operator = str(condition.get("operator") or "equals").strip().lower()
                if c_operator not in {
                    "regex",
                    "contains",
                    "startswith",
                    "endswith",
                    "equals",
                }:
                    raise RuleAuthoringError(
                        f"rule.all_of[{index}].operator가 지원되지 않습니다."
                    )
                all_of.append(
                    {
                        "field": c_field,
                        "operator": c_operator,
                        "pattern": c_pattern,
                    }
                )

        rule: dict[str, Any] = {
            "id": rule_id,
            "name": name,
            "description": description,
            "field": field_name,
            "pattern": pattern,
            "severity": severity,
            "operator": operator,
        }
        if technique:
            rule["mitre_technique"] = technique.upper()
        if fields:
            rule["fields"] = fields
        if all_of:
            rule["all_of"] = all_of
        return rule

    def _canonical_rule_ids(self) -> set[str]:
        return {rule.id.casefold() for rule in load_rules(self.canonical_rules_dir)}

    @staticmethod
    def _publication_owners(data: dict[str, Any]) -> dict[str, str]:
        owners: dict[str, str] = {}
        for draft in data.get("drafts") or []:
            draft_id = str(draft.get("draft_id") or "")
            for publication in draft.get("publications") or []:
                rule_id = str(publication.get("rule_id") or "").casefold()
                if rule_id:
                    owners[rule_id] = draft_id
        return owners

    def _runtime_validate(self, rule: dict[str, Any]) -> dict[str, Any]:
        if rule["id"].casefold() in self._canonical_rule_ids():
            raise RuleAuthoringError(
                f"canonical rule ID와 충돌합니다: {rule['id']}"
            )

        self.root.mkdir(parents=True, exist_ok=True)
        with tempfile.TemporaryDirectory(prefix="rule_validate_", dir=str(self.root)) as tmp_dir:
            path = Path(tmp_dir) / "candidate.yml"
            path.write_text(
                yaml.safe_dump(rule, sort_keys=False, allow_unicode=True),
                encoding="utf-8",
            )
            try:
                loaded = load_rules(path.parent)
            except RuleLoadError as exc:
                raise RuleAuthoringError(f"runtime rule validation failed: {exc}") from exc
        if len(loaded) != 1 or loaded[0].id != rule["id"]:
            raise RuleAuthoringError("runtime loader가 후보 룰을 정확히 1개로 재현하지 못했습니다.")
        return {
            "loaded_rule_id": loaded[0].id,
            "severity": loaded[0].severity,
            "mitre_technique": str(loaded[0].mitre_technique or ""),
        }

    @staticmethod
    def _public(draft: dict[str, Any], *, include_revisions: bool = False) -> dict[str, Any]:
        result = {k: v for k, v in draft.items() if k != "revisions"}
        revisions = list(draft.get("revisions") or [])
        result["revision_count"] = len(revisions)
        if include_revisions:
            result["revisions"] = revisions
        return result

    @staticmethod
    def _find(data: dict[str, Any], draft_id: str) -> tuple[int, dict[str, Any]]:
        for index, draft in enumerate(data.get("drafts") or []):
            if draft.get("draft_id") == draft_id:
                return index, draft
        raise KeyError(draft_id)

    @staticmethod
    def _assert_version(draft: dict[str, Any], expected_version: int) -> None:
        current = int(draft.get("version") or 0)
        if current != int(expected_version):
            raise RuleAuthoringVersionConflict(
                f"draft 버전이 변경되었습니다: expected={expected_version}, current={current}"
            )

    def list_drafts(self) -> list[dict[str, Any]]:
        with rule_tuning_lock(self.index_path):
            rows = self._read().get("drafts") or []
            rows = sorted(
                rows,
                key=lambda row: str(row.get("updated_at") or row.get("created_at") or ""),
                reverse=True,
            )
            return [self._public(row) for row in rows]

    def get_draft(self, draft_id: str) -> dict[str, Any]:
        with rule_tuning_lock(self.index_path):
            _, draft = self._find(self._read(), draft_id)
            return self._public(draft, include_revisions=True)

    def create_draft(self, *, rule: dict[str, Any], updated_by: str = "system") -> dict[str, Any]:
        normalized = self._normalize_rule(rule)
        with rule_tuning_lock(self.index_path):
            data = self._read()
            now = self._now()
            actor = str(updated_by or "system")[:120]
            draft_id = f"rad-{uuid.uuid4().hex[:12]}"
            revision = {
                "version": 1,
                "updated_at": now,
                "updated_by": actor,
                "rule": normalized,
            }
            draft = {
                "draft_id": draft_id,
                "version": 1,
                "status": "draft",
                "created_at": now,
                "updated_at": now,
                "updated_by": actor,
                "rule": normalized,
                "validation": None,
                "approval": None,
                "publications": [],
                "revisions": [revision],
            }
            data["drafts"].append(draft)
            self._write(data)
            return self._public(draft, include_revisions=True)

    def update_draft(
        self,
        draft_id: str,
        *,
        expected_version: int,
        rule: dict[str, Any],
        updated_by: str = "system",
    ) -> dict[str, Any]:
        normalized = self._normalize_rule(rule)
        with rule_tuning_lock(self.index_path):
            data = self._read()
            index, draft = self._find(data, draft_id)
            self._assert_version(draft, expected_version)
            version = int(draft["version"]) + 1
            now = self._now()
            actor = str(updated_by or "system")[:120]
            revisions = list(draft.get("revisions") or [])
            revisions.append(
                {
                    "version": version,
                    "updated_at": now,
                    "updated_by": actor,
                    "rule": normalized,
                }
            )
            revisions = revisions[-MAX_REVISIONS:]
            updated = {
                **draft,
                "version": version,
                "status": "draft",
                "updated_at": now,
                "updated_by": actor,
                "rule": normalized,
                "validation": None,
                "approval": None,
                "revisions": revisions,
            }
            data["drafts"][index] = updated
            self._write(data)
            return self._public(updated, include_revisions=True)

    def validate_draft(self, draft_id: str, *, expected_version: int) -> dict[str, Any]:
        with rule_tuning_lock(self.index_path):
            data = self._read()
            index, draft = self._find(data, draft_id)
            self._assert_version(draft, expected_version)
            runtime = self._runtime_validate(draft["rule"])
            now = self._now()
            validation = {
                "status": "pass",
                "version": int(draft["version"]),
                "validated_at": now,
                "runtime": runtime,
                "canonical_rulepack_modified": False,
            }
            updated = {
                **draft,
                "status": "validated",
                "updated_at": now,
                "validation": validation,
                "approval": None,
            }
            data["drafts"][index] = updated
            self._write(data)
            return self._public(updated, include_revisions=True)

    def approve_draft(
        self,
        draft_id: str,
        *,
        expected_version: int,
        review_note: str,
        approved_by: str,
    ) -> dict[str, Any]:
        note = self._normalize_text(
            review_note, field="review_note", limit=2000, required=True
        )
        with rule_tuning_lock(self.index_path):
            data = self._read()
            index, draft = self._find(data, draft_id)
            self._assert_version(draft, expected_version)
            validation = draft.get("validation") or {}
            if (
                draft.get("status") != "validated"
                or validation.get("status") != "pass"
                or int(validation.get("version") or 0) != int(draft["version"])
            ):
                raise RuleAuthoringStateError(
                    "현재 버전에 대한 validation PASS 후에만 승인할 수 있습니다."
                )
            now = self._now()
            approval = {
                "status": "approved",
                "version": int(draft["version"]),
                "approved_at": now,
                "approved_by": str(approved_by or "system")[:120],
                "review_note": note,
            }
            updated = {
                **draft,
                "status": "approved",
                "updated_at": now,
                "approval": approval,
            }
            data["drafts"][index] = updated
            self._write(data)
            return self._public(updated, include_revisions=True)

    def publish_draft(
        self,
        draft_id: str,
        *,
        expected_version: int,
        published_by: str,
    ) -> dict[str, Any]:
        with rule_tuning_lock(self.index_path):
            data = self._read()
            index, draft = self._find(data, draft_id)
            self._assert_version(draft, expected_version)
            approval = draft.get("approval") or {}
            if (
                draft.get("status") != "approved"
                or approval.get("status") != "approved"
                or int(approval.get("version") or 0) != int(draft["version"])
            ):
                raise RuleAuthoringStateError(
                    "현재 버전이 승인된 상태에서만 publish할 수 있습니다."
                )

            rule_id = str(draft["rule"]["id"])
            owner = self._publication_owners(data).get(rule_id.casefold())
            if owner and owner != draft_id:
                raise RuleAuthoringError(
                    f"이미 다른 custom draft가 publish한 rule ID입니다: {rule_id}"
                )
            if rule_id.casefold() in self._canonical_rule_ids():
                raise RuleAuthoringError(
                    f"canonical rule ID와 충돌합니다: {rule_id}"
                )

            version = int(draft["version"])
            pub_dir = self.published_root / draft_id
            pub_dir.mkdir(parents=True, exist_ok=True)
            path = pub_dir / f"v{version}.yml"
            payload = yaml.safe_dump(
                draft["rule"], sort_keys=False, allow_unicode=True
            ).encode("utf-8")
            sha256 = hashlib.sha256(payload).hexdigest()

            if path.exists():
                existing = path.read_bytes()
                if existing != payload:
                    raise RuleAuthoringError(
                        "동일 버전 publish artifact가 다른 bytes로 이미 존재합니다."
                    )
            else:
                fd, tmp_name = tempfile.mkstemp(
                    prefix=f"v{version}_", suffix=".yml", dir=str(pub_dir)
                )
                tmp = Path(tmp_name)
                try:
                    with os.fdopen(fd, "wb") as handle:
                        handle.write(payload)
                    tmp.replace(path)
                finally:
                    if tmp.exists():
                        try:
                            tmp.unlink()
                        except OSError:
                            pass

            now = self._now()
            publications = list(draft.get("publications") or [])
            if not any(
                int(item.get("version") or 0) == version for item in publications
            ):
                publications.append(
                    {
                        "version": version,
                        "rule_id": rule_id,
                        "published_at": now,
                        "published_by": str(published_by or "system")[:120],
                        "relative_path": str(path.relative_to(self.root)).replace("\\", "/"),
                        "sha256": sha256,
                        "activated_in_detector": False,
                    }
                )
            updated = {
                **draft,
                "status": "published",
                "updated_at": now,
                "publications": publications,
            }
            data["drafts"][index] = updated
            self._write(data)
            return self._public(updated, include_revisions=True)
