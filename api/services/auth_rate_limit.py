"""Small persistent login failure limiter for the browser admin login."""
from __future__ import annotations

import json
import os
import tempfile
import threading
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any

_LOCK = threading.Lock()


def _env_int(name: str, default: int, minimum: int = 0) -> int:
    raw = os.getenv(name, "").strip()
    if not raw:
        return default
    try:
        return max(minimum, int(raw))
    except ValueError:
        return default


def rate_limit_path() -> Path:
    raw = os.getenv("BS_AUTH_RATE_LIMIT_PATH", "").strip()
    if raw:
        return Path(raw).expanduser().resolve()
    return (Path.home() / ".breachscope" / "auth_rate_limit.json").resolve()


def max_failures() -> int:
    return _env_int("BS_AUTH_MAX_FAILURES", 5, minimum=1)


def lockout_seconds() -> int:
    return _env_int("BS_AUTH_LOCKOUT_SECONDS", 300, minimum=1)


@dataclass
class LockoutStatus:
    allowed: bool
    key: str
    failures: int = 0
    locked_until: int | None = None
    retry_after_seconds: int = 0

    def as_dict(self) -> dict[str, Any]:
        return {
            "allowed": self.allowed,
            "key": self.key,
            "failures": self.failures,
            "locked_until": self.locked_until,
            "retry_after_seconds": self.retry_after_seconds,
        }


class AuthRateLimiter:
    """JSON-backed login throttling.

    The limiter is intentionally simple and local-file based so Docker and local
    deployments can get brute-force protection without a database or Redis.
    """

    def __init__(self, path: Path | None = None, now: int | None = None):
        self.path = path or rate_limit_path()
        self._now = now

    def now(self) -> int:
        return int(self._now if self._now is not None else time.time())

    @staticmethod
    def make_key(ip: str | None, username: str | None = "admin") -> str:
        ip_part = (ip or "unknown").strip() or "unknown"
        user_part = (username or "admin").strip().lower() or "admin"
        return f"{ip_part}|{user_part}"

    def status(self, key: str) -> LockoutStatus:
        data = self._read()
        item = data.get("subjects", {}).get(key) or {}
        failures = int(item.get("failures") or 0)
        locked_until = item.get("locked_until")
        now = self.now()
        if locked_until and int(locked_until) > now:
            return LockoutStatus(
                allowed=False,
                key=key,
                failures=failures,
                locked_until=int(locked_until),
                retry_after_seconds=max(1, int(locked_until) - now),
            )
        if locked_until and int(locked_until) <= now:
            # Expired lockout: keep a clean slate so the next login attempt is fair.
            self.clear(key)
            return LockoutStatus(allowed=True, key=key, failures=0)
        return LockoutStatus(allowed=True, key=key, failures=failures)

    def record_failure(self, key: str) -> LockoutStatus:
        with _LOCK:
            data = self._read()
            subjects = data.setdefault("subjects", {})
            item = subjects.setdefault(key, {})
            now = self.now()
            failures = int(item.get("failures") or 0) + 1
            item["failures"] = failures
            item["last_failure_at"] = now
            item.setdefault("first_failure_at", now)
            if failures >= max_failures():
                item["locked_until"] = now + lockout_seconds()
            self._write(data)
        return self.status(key)

    def clear(self, key: str) -> None:
        with _LOCK:
            data = self._read()
            subjects = data.setdefault("subjects", {})
            if key in subjects:
                subjects.pop(key, None)
                self._write(data)

    def _read(self) -> dict[str, Any]:
        if not self.path.exists():
            return {"version": 1, "subjects": {}}
        try:
            data = json.loads(self.path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            return {"version": 1, "subjects": {}}
        if not isinstance(data, dict):
            return {"version": 1, "subjects": {}}
        data.setdefault("version", 1)
        data.setdefault("subjects", {})
        return data

    def _write(self, data: dict[str, Any]) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        fd, tmp = tempfile.mkstemp(prefix="auth_rate_limit_", suffix=".json", dir=str(self.path.parent))
        tmp_path = Path(tmp)
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as fp:
                json.dump(data, fp, ensure_ascii=False, indent=2)
                fp.write("\n")
            tmp_path.replace(self.path)
        finally:
            if tmp_path.exists():
                try:
                    tmp_path.unlink()
                except OSError:
                    pass
