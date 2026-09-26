"""Persistent, versioned per-analysis rule-tuning profiles."""
from __future__ import annotations

import json
import os
import tempfile
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from breachscope.rules import load_rules
from breachscope.runtime_paths import default_rules_dir

from .rule_tuning_concurrency import rule_tuning_lock


PROFILE_PATH_ENV = "BS_RULE_TUNING_PATH"
PROFILE_SCHEMA = "breachscope.rule_tuning_profiles.v1"
MAX_PROFILE_RULES = 200
MAX_REVISIONS = 100


class RuleTuningProfileError(ValueError):
    """Invalid or unavailable rule-tuning profile state."""


class RuleTuningVersionConflict(RuleTuningProfileError):
    """Optimistic-concurrency version mismatch."""


class RuleTuningProfileService:
    def __init__(self, path: Path | None = None, rules_dir: Path | None = None):
        self.path = (path or self.default_path()).expanduser().resolve()
        self.rules_dir = (rules_dir or default_rules_dir()).expanduser().resolve()
        self.path.parent.mkdir(parents=True, exist_ok=True)

    @staticmethod
    def default_path() -> Path:
        raw = os.getenv(PROFILE_PATH_ENV)
        if raw:
            return Path(raw)
        return Path.home() / ".breachscope" / "rule_tuning_profiles.json"

    @staticmethod
    def _now() -> str:
        return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")

    @staticmethod
    def _base_document() -> dict[str, Any]:
        return {"schema": PROFILE_SCHEMA, "profiles": []}

    def _read(self) -> dict[str, Any]:
        if not self.path.exists():
            return self._base_document()
        try:
            data = json.loads(self.path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            raise RuleTuningProfileError(
                f"룰 튜닝 프로필 저장소를 읽을 수 없습니다: {self.path}"
            ) from exc
        if not isinstance(data, dict) or data.get("schema") != PROFILE_SCHEMA:
            raise RuleTuningProfileError("지원하지 않는 룰 튜닝 프로필 저장 형식입니다.")
        profiles = data.get("profiles")
        if not isinstance(profiles, list):
            raise RuleTuningProfileError("룰 튜닝 프로필 저장소가 손상되었습니다.")
        return data

    def _write(self, data: dict[str, Any]) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        fd, tmp_name = tempfile.mkstemp(
            prefix="rule_tuning_profiles_", suffix=".json", dir=str(self.path.parent)
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

    def _rule_lookup(self) -> dict[str, str]:
        rules = load_rules(self.rules_dir)
        return {rule.id.casefold(): rule.id for rule in rules}

    def _normalize_rule_ids(self, values: Any, lookup: dict[str, str]) -> list[str]:
        if values in (None, ""):
            return []
        raw = values.split(",") if isinstance(values, str) else list(values)
        result: list[str] = []
        seen: set[str] = set()
        unknown: list[str] = []
        for value in raw:
            text = str(value or "").strip()
            if not text:
                continue
            key = text.casefold()
            canonical = lookup.get(key)
            if canonical is None:
                unknown.append(text)
                continue
            if key not in seen:
                result.append(canonical)
                seen.add(key)
            if len(result) > MAX_PROFILE_RULES:
                raise RuleTuningProfileError(
                    f"룰 목록은 최대 {MAX_PROFILE_RULES}개까지 저장할 수 있습니다."
                )
        if unknown:
            raise RuleTuningProfileError(
                "존재하지 않는 룰 ID가 있습니다: " + ", ".join(sorted(set(unknown)))
            )
        return result

    @staticmethod
    def _normalize_name(value: Any) -> str:
        name = str(value or "").strip()
        if not name:
            raise RuleTuningProfileError("프로필 이름은 비워둘 수 없습니다.")
        if len(name) > 120:
            raise RuleTuningProfileError("프로필 이름은 120자를 초과할 수 없습니다.")
        return name

    @staticmethod
    def _normalize_description(value: Any) -> str:
        text = str(value or "").strip()
        if len(text) > 1000:
            raise RuleTuningProfileError("프로필 설명은 1000자를 초과할 수 없습니다.")
        return text

    def _normalized_payload(
        self,
        *,
        name: Any,
        description: Any,
        rule_include: Any,
        rule_exclude: Any,
    ) -> dict[str, Any]:
        lookup = self._rule_lookup()
        include = self._normalize_rule_ids(rule_include, lookup)
        exclude = self._normalize_rule_ids(rule_exclude, lookup)
        overlap = sorted(set(include).intersection(exclude))
        if overlap:
            raise RuleTuningProfileError(
                "같은 룰을 포함과 제외에 동시에 지정할 수 없습니다: " + ", ".join(overlap)
            )
        return {
            "name": self._normalize_name(name),
            "description": self._normalize_description(description),
            "rule_include": include,
            "rule_exclude": exclude,
        }

    @staticmethod
    def _public(profile: dict[str, Any], *, include_revisions: bool = False) -> dict[str, Any]:
        result = {k: v for k, v in profile.items() if k != "revisions"}
        revisions = profile.get("revisions") or []
        result["revision_count"] = len(revisions)
        if include_revisions:
            result["revisions"] = list(revisions)
        return result

    def list_profiles(self) -> list[dict[str, Any]]:
        with rule_tuning_lock(self.path):
            rows = self._read().get("profiles") or []
            rows = sorted(rows, key=lambda row: (str(row.get("name") or "").casefold(), str(row.get("profile_id") or "")))
            return [self._public(row) for row in rows]

    def get_profile(self, profile_id: str) -> dict[str, Any]:
        with rule_tuning_lock(self.path):
            for row in self._read().get("profiles") or []:
                if row.get("profile_id") == profile_id:
                    return self._public(row, include_revisions=True)
        raise KeyError(profile_id)

    def create_profile(
        self,
        *,
        name: Any,
        description: Any = "",
        rule_include: Any = None,
        rule_exclude: Any = None,
        updated_by: str = "system",
    ) -> dict[str, Any]:
        normalized = self._normalized_payload(
            name=name,
            description=description,
            rule_include=rule_include,
            rule_exclude=rule_exclude,
        )
        with rule_tuning_lock(self.path):
            data = self._read()
            now = self._now()
            profile_id = f"rtp-{uuid.uuid4().hex[:12]}"
            revision = {
                "version": 1,
                "updated_at": now,
                "updated_by": str(updated_by or "system")[:120],
                **normalized,
            }
            profile = {
                "profile_id": profile_id,
                "version": 1,
                "created_at": now,
                "updated_at": now,
                "updated_by": revision["updated_by"],
                **normalized,
                "revisions": [revision],
            }
            data["profiles"].append(profile)
            self._write(data)
            return self._public(profile, include_revisions=True)

    def update_profile(
        self,
        profile_id: str,
        *,
        expected_version: int,
        name: Any,
        description: Any = "",
        rule_include: Any = None,
        rule_exclude: Any = None,
        updated_by: str = "system",
    ) -> dict[str, Any]:
        normalized = self._normalized_payload(
            name=name,
            description=description,
            rule_include=rule_include,
            rule_exclude=rule_exclude,
        )
        with rule_tuning_lock(self.path):
            data = self._read()
            for index, row in enumerate(data.get("profiles") or []):
                if row.get("profile_id") != profile_id:
                    continue
                current_version = int(row.get("version") or 0)
                if current_version != int(expected_version):
                    raise RuleTuningVersionConflict(
                        f"프로필 버전이 변경되었습니다: expected={expected_version}, current={current_version}"
                    )
                now = self._now()
                version = current_version + 1
                actor = str(updated_by or "system")[:120]
                revision = {
                    "version": version,
                    "updated_at": now,
                    "updated_by": actor,
                    **normalized,
                }
                revisions = list(row.get("revisions") or [])
                revisions.append(revision)
                revisions = revisions[-MAX_REVISIONS:]
                updated = {
                    **row,
                    **normalized,
                    "version": version,
                    "updated_at": now,
                    "updated_by": actor,
                    "revisions": revisions,
                }
                data["profiles"][index] = updated
                self._write(data)
                return self._public(updated, include_revisions=True)
        raise KeyError(profile_id)

    def delete_profile(self, profile_id: str, *, expected_version: int) -> dict[str, Any]:
        with rule_tuning_lock(self.path):
            data = self._read()
            rows = data.get("profiles") or []
            for index, row in enumerate(rows):
                if row.get("profile_id") != profile_id:
                    continue
                current_version = int(row.get("version") or 0)
                if current_version != int(expected_version):
                    raise RuleTuningVersionConflict(
                        f"프로필 버전이 변경되었습니다: expected={expected_version}, current={current_version}"
                    )
                removed = rows.pop(index)
                data["profiles"] = rows
                self._write(data)
                return self._public(removed, include_revisions=True)
        raise KeyError(profile_id)
