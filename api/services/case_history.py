"""분석 케이스 이력 관리 서비스.

웹 콘솔에서 여러 분석 결과를 다시 열어볼 수 있도록 가벼운 JSON 인덱스를 유지합니다.
기본 위치는 ~/.breachscope/case_history.json 이며, 테스트/배포 환경에서는
BS_CASE_HISTORY_PATH 환경 변수로 변경할 수 있습니다.
"""
from __future__ import annotations

import hashlib
import json
import os
import shutil
import tempfile
from dataclasses import dataclass, asdict, field
from datetime import datetime, timezone, timedelta
from pathlib import Path
from typing import Any, Dict, List, Optional


CASE_INDEX_ENV = "BS_CASE_HISTORY_PATH"
CASE_ROOT_ENV = "BS_CASES_ROOT"


@dataclass
class CaseRecord:
    case_id: str
    created_at: str
    updated_at: str
    work_dir: str
    status: str
    finding_count: int
    risk_score: int
    risk_level: str
    hosts: List[str]
    techniques: List[str]
    artifacts: Dict[str, bool]
    title: str = "BreachScope Analysis"
    workflow_status: str = "new"
    assignee: str = ""
    tags: List[str] = field(default_factory=list)
    notes: str = ""
    severity_override: str = ""
    closure_summary: str = ""
    updated_by: str = "system"


class CaseHistoryService:
    """JSON 기반 케이스 인덱스 관리."""

    def __init__(self, index_path: Optional[Path] = None):
        self.index_path = index_path or self.default_index_path()
        self.index_path.parent.mkdir(parents=True, exist_ok=True)

    @staticmethod
    def default_root() -> Path:
        raw = os.getenv(CASE_ROOT_ENV)
        if raw:
            return Path(raw).expanduser().resolve()
        return (Path.home() / ".breachscope" / "cases").resolve()

    @classmethod
    def default_index_path(cls) -> Path:
        raw = os.getenv(CASE_INDEX_ENV)
        if raw:
            return Path(raw).expanduser().resolve()
        return (Path.home() / ".breachscope" / "case_history.json").resolve()

    @staticmethod
    def _now() -> str:
        return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")

    @staticmethod
    def _make_case_id(work_dir: Path, created_at: str) -> str:
        stamp = created_at.replace("-", "").replace(":", "").replace("Z", "").replace("T", "-")
        digest = hashlib.sha256(f"{work_dir}|{created_at}".encode("utf-8")).hexdigest()[:8]
        return f"case-{stamp}-{digest}"

    def _read_index(self) -> Dict[str, Any]:
        if not self.index_path.exists():
            return {"version": 1, "cases": []}
        try:
            data = json.loads(self.index_path.read_text(encoding="utf-8"))
        except json.JSONDecodeError:
            # 깨진 인덱스는 보존하고 새 인덱스를 시작합니다.
            broken = self.index_path.with_suffix(self.index_path.suffix + ".broken")
            try:
                self.index_path.replace(broken)
            except OSError:
                pass
            return {"version": 1, "cases": []}
        if not isinstance(data, dict):
            return {"version": 1, "cases": []}
        data.setdefault("version", 1)
        data.setdefault("cases", [])
        return data

    def _write_index(self, data: Dict[str, Any]) -> None:
        self.index_path.parent.mkdir(parents=True, exist_ok=True)
        fd, tmp_name = tempfile.mkstemp(prefix="case_history_", suffix=".json", dir=str(self.index_path.parent))
        tmp_path = Path(tmp_name)
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as f:
                json.dump(data, f, ensure_ascii=False, indent=2)
                f.write("\n")
            tmp_path.replace(self.index_path)
        finally:
            if tmp_path.exists():
                try:
                    tmp_path.unlink()
                except OSError:
                    pass

    @staticmethod
    def _artifact_flags(work_dir: Path) -> Dict[str, bool]:
        prefix = work_dir / "out" / "report"
        return {
            "html": prefix.with_suffix(".html").exists(),
            "json": prefix.with_suffix(".json").exists(),
            "csv": prefix.with_suffix(".csv").exists(),
            "iocs": prefix.with_suffix(".iocs.csv").exists(),
            "rules": prefix.with_suffix(".rules.csv").exists(),
            "manifest": prefix.with_suffix(".manifest.json").exists(),
            "zip": prefix.with_suffix(".zip").exists(),
            "pdf": prefix.with_suffix(".pdf").exists(),
        }

    @staticmethod
    def _hosts_from_summary(summary: Dict[str, Any]) -> List[str]:
        host_rows = summary.get("host_risk_summary") or []
        hosts = []
        for row in host_rows:
            if isinstance(row, dict) and row.get("host"):
                hosts.append(str(row["host"]))
        if hosts:
            return sorted(set(hosts))
        host_counts = summary.get("host_counts") or {}
        if isinstance(host_counts, dict):
            return sorted(str(k) for k in host_counts.keys())
        return []

    @staticmethod
    def _techniques_from_summary(summary: Dict[str, Any]) -> List[str]:
        mitre_counts = summary.get("mitre_counts") or {}
        if isinstance(mitre_counts, dict):
            return sorted(str(k) for k in mitre_counts.keys())
        techniques = set()
        for row in summary.get("attack_coverage") or []:
            if isinstance(row, dict):
                techniques.update(str(t) for t in row.get("techniques") or [])
        return sorted(techniques)

    def register_case(self, work_dir: Path, report_data: Dict[str, Any]) -> CaseRecord:
        summary = report_data.get("summary") or {}
        risk = summary.get("risk") or {}
        created_at = self._now()
        work_dir = work_dir.resolve()
        record = CaseRecord(
            case_id=self._make_case_id(work_dir, created_at),
            created_at=created_at,
            updated_at=created_at,
            work_dir=str(work_dir),
            status="completed",
            finding_count=int(summary.get("total_findings") or 0),
            risk_score=int(risk.get("score") or 0),
            risk_level=str(risk.get("level") or "none"),
            hosts=self._hosts_from_summary(summary),
            techniques=self._techniques_from_summary(summary),
            artifacts=self._artifact_flags(work_dir),
            title=self._build_title(summary),
            workflow_status="new",
            assignee="",
            tags=[],
            notes="",
            severity_override="",
            closure_summary="",
            updated_by="system",
        )
        data = self._read_index()
        cases = [row for row in data.get("cases", []) if row.get("case_id") != record.case_id]
        cases.append(asdict(record))
        data["cases"] = sorted(cases, key=lambda row: row.get("updated_at") or row.get("created_at") or "", reverse=True)
        self._write_index(data)
        return record

    @staticmethod
    def _build_title(summary: Dict[str, Any]) -> str:
        risk = summary.get("risk") or {}
        hosts = CaseHistoryService._hosts_from_summary(summary)
        level = str(risk.get("level") or "none")
        count = int(summary.get("total_findings") or 0)
        host_label = hosts[0] if len(hosts) == 1 else f"{len(hosts)} hosts"
        if not hosts:
            host_label = "no host"
        return f"{level.upper()} · {count} findings · {host_label}"

    def list_cases(self, limit: int = 50) -> List[Dict[str, Any]]:
        data = self._read_index()
        rows = data.get("cases") or []
        rows = sorted(rows, key=lambda row: row.get("updated_at") or row.get("created_at") or "", reverse=True)
        enriched = []
        for row in rows[: max(0, limit)]:
            item = self._with_workflow_defaults(row)
            work_dir = Path(str(item.get("work_dir") or ""))
            item["exists"] = work_dir.exists()
            item["artifacts"] = self._artifact_flags(work_dir) if work_dir.exists() else item.get("artifacts", {})
            enriched.append(item)
        return enriched

    def get_case(self, case_id: str) -> Dict[str, Any]:
        for row in self._read_index().get("cases") or []:
            if row.get("case_id") == case_id:
                item = self._with_workflow_defaults(row)
                work_dir = Path(str(item.get("work_dir") or ""))
                item["exists"] = work_dir.exists()
                item["artifacts"] = self._artifact_flags(work_dir) if work_dir.exists() else item.get("artifacts", {})
                return item
        raise KeyError(case_id)


    @staticmethod
    def _normalize_workflow_status(value: str | None) -> str:
        allowed = {"new", "triage", "investigating", "contained", "resolved", "false_positive"}
        text = str(value or "new").strip().lower().replace(" ", "_").replace("-", "_")
        if text in {"open", "todo"}:
            text = "new"
        if text in {"in_review", "review", "analysis"}:
            text = "triage"
        if text in {"closed", "done", "complete", "completed"}:
            text = "resolved"
        if text not in allowed:
            raise ValueError(f"지원하지 않는 워크플로 상태입니다: {value}")
        return text

    @staticmethod
    def _normalize_severity_override(value: str | None) -> str:
        text = str(value or "").strip().lower()
        allowed = {"", "none", "low", "medium", "high", "critical"}
        if text not in allowed:
            raise ValueError(f"지원하지 않는 심각도 override입니다: {value}")
        return "" if text == "none" else text

    @staticmethod
    def _normalize_tags(value: Any) -> list[str]:
        if value is None:
            return []
        if isinstance(value, str):
            raw_items = value.split(",")
        elif isinstance(value, (list, tuple, set)):
            raw_items = list(value)
        else:
            raw_items = [value]
        tags: list[str] = []
        seen: set[str] = set()
        for item in raw_items:
            tag = str(item or "").strip().lower().replace(" ", "-")
            tag = "".join(ch for ch in tag if ch.isalnum() or ch in {"-", "_", ".", ":"})[:40]
            if tag and tag not in seen:
                tags.append(tag)
                seen.add(tag)
            if len(tags) >= 20:
                break
        return tags

    @staticmethod
    def _truncate_text(value: Any, limit: int = 4000) -> str:
        text = str(value or "").strip()
        if len(text) > limit:
            return text[: limit - 1] + "…"
        return text

    def _with_workflow_defaults(self, row: Dict[str, Any]) -> Dict[str, Any]:
        item = dict(row)
        item.setdefault("workflow_status", "new")
        item.setdefault("assignee", "")
        item["tags"] = self._normalize_tags(item.get("tags"))
        item.setdefault("notes", "")
        item.setdefault("severity_override", "")
        item.setdefault("closure_summary", "")
        item.setdefault("updated_by", "system")
        return item

    def update_case_workflow(
        self,
        case_id: str,
        *,
        workflow_status: str | None = None,
        assignee: str | None = None,
        tags: Any = None,
        notes: str | None = None,
        severity_override: str | None = None,
        closure_summary: str | None = None,
        title: str | None = None,
        updated_by: str = "system",
    ) -> Dict[str, Any]:
        """Update analyst-owned workflow fields for a case record.

        Analysis evidence fields such as finding counts, risk score, work_dir and
        artifacts are intentionally not mutable through this method. This keeps
        triage notes separate from generated evidence.
        """
        data = self._read_index()
        cases = data.get("cases") or []
        found = False
        updated: Dict[str, Any] | None = None
        for i, row in enumerate(cases):
            if row.get("case_id") != case_id:
                continue
            item = self._with_workflow_defaults(row)
            if workflow_status is not None:
                item["workflow_status"] = self._normalize_workflow_status(workflow_status)
            if assignee is not None:
                item["assignee"] = self._truncate_text(assignee, 120)
            if tags is not None:
                item["tags"] = self._normalize_tags(tags)
            if notes is not None:
                item["notes"] = self._truncate_text(notes, 8000)
            if severity_override is not None:
                item["severity_override"] = self._normalize_severity_override(severity_override)
            if closure_summary is not None:
                item["closure_summary"] = self._truncate_text(closure_summary, 4000)
            if title is not None:
                item["title"] = self._truncate_text(title, 180) or item.get("title") or "BreachScope Analysis"
            item["updated_by"] = self._truncate_text(updated_by, 120) or "system"
            item["updated_at"] = self._now()
            cases[i] = item
            updated = item
            found = True
            break
        if not found or updated is None:
            raise KeyError(case_id)
        data["cases"] = sorted(cases, key=lambda row: row.get("updated_at") or row.get("created_at") or "", reverse=True)
        self._write_index(data)
        return updated

    def workflow_summary(self) -> Dict[str, Any]:
        """Return a compact board-style summary for the case queue."""
        rows = [self._with_workflow_defaults(row) for row in self._read_index().get("cases") or []]
        by_status: Dict[str, int] = {}
        by_assignee: Dict[str, int] = {}
        by_severity: Dict[str, int] = {}
        for row in rows:
            status = row.get("workflow_status") or "new"
            by_status[status] = by_status.get(status, 0) + 1
            assignee = row.get("assignee") or "unassigned"
            by_assignee[assignee] = by_assignee.get(assignee, 0) + 1
            severity = row.get("severity_override") or row.get("risk_level") or "none"
            by_severity[severity] = by_severity.get(severity, 0) + 1
        return {
            "total": len(rows),
            "by_status": dict(sorted(by_status.items())),
            "by_assignee": dict(sorted(by_assignee.items())),
            "by_severity": dict(sorted(by_severity.items())),
        }

    def delete_case(self, case_id: str, remove_files: bool = True) -> Dict[str, Any]:
        data = self._read_index()
        cases = data.get("cases") or []
        target = None
        kept = []
        for row in cases:
            if row.get("case_id") == case_id:
                target = row
            else:
                kept.append(row)
        if target is None:
            raise KeyError(case_id)
        data["cases"] = kept
        self._write_index(data)

        removed_files = False
        if remove_files:
            work_dir = Path(str(target.get("work_dir") or ""))
            if self._is_safe_to_remove(work_dir):
                shutil.rmtree(work_dir, ignore_errors=True)
                removed_files = True
        return {"case_id": case_id, "deleted": True, "removed_files": removed_files}


    @staticmethod
    def _parse_time(value: str | None) -> datetime | None:
        if not value:
            return None
        text = str(value).strip()
        try:
            if text.endswith("Z"):
                text = text[:-1] + "+00:00"
            return datetime.fromisoformat(text)
        except ValueError:
            return None

    def prune_cases(
        self,
        *,
        keep_last: int = 50,
        older_than_days: int | None = None,
        dry_run: bool = True,
        remove_files: bool = True,
    ) -> Dict[str, Any]:
        """Prune old case records and optionally remove safe case directories.

        The newest ``keep_last`` cases are always retained. When
        ``older_than_days`` is supplied, only records older than that cutoff are
        candidates. With ``dry_run=True`` the service returns candidates without
        modifying files or the index.
        """
        keep_last = max(0, int(keep_last or 0))
        data = self._read_index()
        rows = sorted(data.get("cases") or [], key=lambda row: row.get("updated_at") or row.get("created_at") or "", reverse=True)
        cutoff = None
        if older_than_days is not None:
            cutoff = datetime.now(timezone.utc) - timedelta(days=max(0, int(older_than_days)))

        candidates: list[Dict[str, Any]] = []
        kept: list[Dict[str, Any]] = []
        removed_files = 0
        for index, row in enumerate(rows):
            must_keep = index < keep_last
            timestamp = self._parse_time(row.get("updated_at") or row.get("created_at"))
            old_enough = True if cutoff is None else bool(timestamp and timestamp < cutoff)
            if must_keep or not old_enough:
                kept.append(row)
                continue
            item = {
                "case_id": row.get("case_id"),
                "created_at": row.get("created_at"),
                "updated_at": row.get("updated_at"),
                "work_dir": row.get("work_dir"),
                "risk_level": row.get("risk_level"),
                "finding_count": row.get("finding_count"),
            }
            candidates.append(item)
            if not dry_run and remove_files:
                work_dir = Path(str(row.get("work_dir") or ""))
                if self._is_safe_to_remove(work_dir):
                    shutil.rmtree(work_dir, ignore_errors=True)
                    removed_files += 1

        if not dry_run:
            data["cases"] = kept
            self._write_index(data)

        return {
            "dry_run": bool(dry_run),
            "keep_last": keep_last,
            "older_than_days": older_than_days,
            "candidate_count": len(candidates),
            "removed_case_records": 0 if dry_run else len(candidates),
            "removed_files": 0 if dry_run else removed_files,
            "candidates": candidates,
        }

    @classmethod
    def _is_safe_to_remove(cls, path: Path) -> bool:
        try:
            resolved = path.resolve()
        except OSError:
            return False
        if not resolved.exists() or not resolved.is_dir():
            return False
        root = cls.default_root()
        if resolved.name.startswith("bs_web_"):
            return True
        try:
            resolved.relative_to(root)
            return True
        except ValueError:
            return False
