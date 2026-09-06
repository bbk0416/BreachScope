"""Append-only audit trail for the BreachScope web console."""
from __future__ import annotations

import csv
import hashlib
import hmac
import io
import json
import os
import threading
import uuid
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable

try:  # FastAPI is available in the web app, but keep the service importable in CLI tests.
    from fastapi import Request
except Exception:  # pragma: no cover - defensive fallback for unusual import contexts
    Request = Any  # type: ignore

from api.security import (
    SESSION_COOKIE_NAME,
    auth_is_enabled,
    client_ip_from_request,
    configured_api_key,
    request_is_authenticated,
    verify_session_token,
)

_LOCK = threading.Lock()
SENSITIVE_KEYS = {"password", "api_key", "token", "authorization", "cookie", "secret", "session"}
DEFAULT_AUDIT_LIMIT = 100
MAX_AUDIT_LIMIT = 1000


def _now_iso() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def _env_path(name: str, default: str) -> Path:
    return Path(os.getenv(name, default)).expanduser()


def audit_log_path() -> Path:
    """Return the configured audit JSONL path."""
    return _env_path("BS_AUDIT_LOG_PATH", "~/.breachscope/audit.jsonl")


def audit_is_enabled() -> bool:
    raw = os.getenv("BS_AUDIT_ENABLED", "1").strip().lower()
    return raw not in {"0", "false", "no", "off"}


def _truncate(value: str, limit: int = 500) -> str:
    if len(value) <= limit:
        return value
    return value[: limit - 1] + "…"


def _sanitize(value: Any, key: str | None = None) -> Any:
    """Remove secrets and keep audit entries compact."""
    if key and any(marker in key.lower() for marker in SENSITIVE_KEYS):
        return "<redacted>"
    if isinstance(value, dict):
        return {str(k): _sanitize(v, str(k)) for k, v in value.items()}
    if isinstance(value, (list, tuple, set)):
        return [_sanitize(v) for v in list(value)[:50]]
    if isinstance(value, Path):
        return str(value)
    if isinstance(value, str):
        return _truncate(value)
    if isinstance(value, (int, float, bool)) or value is None:
        return value
    return _truncate(str(value))


def _hash_principal(value: str) -> str:
    if not value:
        return ""
    return hashlib.sha256(value.encode("utf-8")).hexdigest()[:12]


@dataclass
class AuditActor:
    subject: str
    method: str


def actor_from_request(request: Request | None) -> AuditActor:
    """Resolve a safe actor label from an API key, session cookie, or local demo mode."""
    if request is None:
        return AuditActor(subject="system", method="system")

    authenticated, method = request_is_authenticated(request)
    if method == "session":
        payload = verify_session_token(request.cookies.get(SESSION_COOKIE_NAME)) or {}
        return AuditActor(subject=str(payload.get("sub") or "admin"), method="session")

    if method == "api_key" and authenticated:
        supplied = request.headers.get("x-api-key", "").strip()
        if not supplied:
            auth = request.headers.get("authorization", "").strip()
            if auth.lower().startswith("bearer "):
                supplied = auth[7:].strip()
        if not supplied:
            supplied = ""
        return AuditActor(subject=f"api_key:{_hash_principal(supplied or configured_api_key())}", method="api_key")

    if not auth_is_enabled():
        return AuditActor(subject="local-demo", method="none")
    return AuditActor(subject="unauthenticated", method="none")


def _client_ip(request: Request | None) -> str | None:
    if request is None:
        return None
    return client_ip_from_request(request)


def _request_meta(request: Request | None) -> dict[str, Any]:
    if request is None:
        return {}
    return {
        "ip": _client_ip(request),
        "user_agent": _truncate(request.headers.get("user-agent", ""), 180),
        "method": request.method,
        "path": request.url.path,
    }


class AuditLogService:
    """Small append-only JSONL audit log.

    The service deliberately avoids a database so the project remains easy to run
    locally and in Docker. Each record is one JSON object per line.
    """

    def __init__(self, path: Path | None = None):
        self.path = path or audit_log_path()

    def record(
        self,
        action: str,
        *,
        request: Request | None = None,
        status: str = "success",
        actor: str | None = None,
        auth_method: str | None = None,
        case_id: str | None = None,
        target: str | None = None,
        details: dict[str, Any] | None = None,
    ) -> dict[str, Any] | None:
        if not audit_is_enabled():
            return None

        resolved = actor_from_request(request)
        entry = {
            "event_id": f"audit-{uuid.uuid4().hex[:12]}",
            "timestamp": _now_iso(),
            "action": str(action),
            "status": str(status),
            "actor": actor or resolved.subject,
            "auth_method": auth_method or resolved.method,
            "case_id": case_id,
            "target": target,
            "request": _request_meta(request),
            "details": _sanitize(details or {}),
        }
        self.path.parent.mkdir(parents=True, exist_ok=True)
        line = json.dumps(entry, ensure_ascii=False, separators=(",", ":"))
        with _LOCK:
            with self.path.open("a", encoding="utf-8") as fp:
                fp.write(line + "\n")
        return entry

    def read_events(
        self,
        *,
        limit: int = DEFAULT_AUDIT_LIMIT,
        action: str | None = None,
        status: str | None = None,
        case_id: str | None = None,
    ) -> list[dict[str, Any]]:
        limit = max(1, min(MAX_AUDIT_LIMIT, int(limit or DEFAULT_AUDIT_LIMIT)))
        if not self.path.exists():
            return []
        rows: list[dict[str, Any]] = []
        # Files are expected to be small for this project. Reverse after reading to
        # return newest first while preserving append-only simplicity.
        for line in reversed(self.path.read_text(encoding="utf-8").splitlines()):
            if not line.strip():
                continue
            try:
                row = json.loads(line)
            except json.JSONDecodeError:
                continue
            if action and row.get("action") != action:
                continue
            if status and row.get("status") != status:
                continue
            if case_id and row.get("case_id") != case_id:
                continue
            rows.append(row)
            if len(rows) >= limit:
                break
        return rows

    def export_jsonl(self, events: Iterable[dict[str, Any]] | None = None) -> str:
        rows = list(events) if events is not None else self.read_events(limit=MAX_AUDIT_LIMIT)
        return "\n".join(json.dumps(row, ensure_ascii=False) for row in rows) + ("\n" if rows else "")

    def export_csv(self, events: Iterable[dict[str, Any]] | None = None) -> str:
        rows = list(events) if events is not None else self.read_events(limit=MAX_AUDIT_LIMIT)
        output = io.StringIO()
        fieldnames = [
            "timestamp",
            "event_id",
            "action",
            "status",
            "actor",
            "auth_method",
            "case_id",
            "target",
            "ip",
            "method",
            "path",
            "details",
        ]
        writer = csv.DictWriter(output, fieldnames=fieldnames)
        writer.writeheader()
        for row in rows:
            req = row.get("request") or {}
            writer.writerow(
                {
                    "timestamp": row.get("timestamp"),
                    "event_id": row.get("event_id"),
                    "action": row.get("action"),
                    "status": row.get("status"),
                    "actor": row.get("actor"),
                    "auth_method": row.get("auth_method"),
                    "case_id": row.get("case_id"),
                    "target": row.get("target"),
                    "ip": req.get("ip"),
                    "method": req.get("method"),
                    "path": req.get("path"),
                    "details": json.dumps(row.get("details") or {}, ensure_ascii=False),
                }
            )
        return output.getvalue()

    def verify_chain(self, *, secret: str | None = None) -> dict[str, Any]:
        """Return a simple tamper-evidence digest over the current JSONL file.

        This is not a substitute for WORM storage, but it gives operators a stable
        digest to archive with incident deliverables.
        """
        if not self.path.exists():
            return {"exists": False, "events": 0, "sha256": None, "hmac_sha256": None}
        data = self.path.read_bytes()
        digest = hashlib.sha256(data).hexdigest()
        key = secret or os.getenv("BS_AUDIT_CHAIN_SECRET", "").strip()
        mac = hmac.new(key.encode("utf-8"), data, hashlib.sha256).hexdigest() if key else None
        count = sum(1 for line in data.splitlines() if line.strip())
        return {"exists": True, "events": count, "sha256": digest, "hmac_sha256": mac, "path": str(self.path)}
