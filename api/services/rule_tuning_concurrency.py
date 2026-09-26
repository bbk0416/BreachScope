"""Cross-process lock for rule-tuning profile mutations."""
from __future__ import annotations

from contextlib import contextmanager
import os
from pathlib import Path
import threading
from typing import Iterator


_PROCESS_LOCKS_GUARD = threading.Lock()
_PROCESS_LOCKS: dict[str, threading.RLock] = {}


class RuleTuningLockError(RuntimeError):
    """Raised when a rule-tuning profile lock cannot be acquired safely."""


def _process_lock_for(path: Path) -> threading.RLock:
    key = str(path.expanduser().resolve(strict=False))
    with _PROCESS_LOCKS_GUARD:
        lock = _PROCESS_LOCKS.get(key)
        if lock is None:
            lock = threading.RLock()
            _PROCESS_LOCKS[key] = lock
        return lock


@contextmanager
def rule_tuning_lock(path: Path) -> Iterator[None]:
    path = Path(path).expanduser().resolve(strict=False)
    lock_path = path.with_name(path.name + ".lock")
    lock_path.parent.mkdir(parents=True, exist_ok=True)
    process_lock = _process_lock_for(path)
    with process_lock:
        try:
            with lock_path.open("a+b") as handle:
                if os.name == "nt":
                    import msvcrt

                    handle.seek(0, os.SEEK_END)
                    if handle.tell() == 0:
                        handle.write(b"\0")
                        handle.flush()
                    handle.seek(0)
                    try:
                        msvcrt.locking(handle.fileno(), msvcrt.LK_LOCK, 1)
                    except OSError as exc:
                        raise RuleTuningLockError(
                            f"rule-tuning lock acquisition failed: {lock_path}"
                        ) from exc
                    try:
                        yield
                    finally:
                        handle.seek(0)
                        try:
                            msvcrt.locking(handle.fileno(), msvcrt.LK_UNLCK, 1)
                        except OSError as exc:
                            raise RuleTuningLockError(
                                f"rule-tuning lock release failed: {lock_path}"
                            ) from exc
                else:
                    import fcntl

                    try:
                        fcntl.flock(handle.fileno(), fcntl.LOCK_EX)
                    except OSError as exc:
                        raise RuleTuningLockError(
                            f"rule-tuning lock acquisition failed: {lock_path}"
                        ) from exc
                    try:
                        yield
                    finally:
                        try:
                            fcntl.flock(handle.fileno(), fcntl.LOCK_UN)
                        except OSError as exc:
                            raise RuleTuningLockError(
                                f"rule-tuning lock release failed: {lock_path}"
                            ) from exc
        except RuleTuningLockError:
            raise
        except OSError as exc:
            raise RuleTuningLockError(
                f"rule-tuning lock file is unavailable: {lock_path}"
            ) from exc
