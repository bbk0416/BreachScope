"""Serialize case-history read/modify/write mutations across threads and processes."""
from __future__ import annotations

from contextlib import contextmanager
import os
from pathlib import Path
import threading
from typing import Iterator

from .case_history import CaseHistoryService


_PROCESS_LOCKS_GUARD = threading.Lock()
_PROCESS_LOCKS: dict[str, threading.RLock] = {}


class CaseHistoryLockError(RuntimeError):
    """Raised when the case-history mutation lock cannot be acquired safely."""


def _process_lock_for(index_path: Path) -> threading.RLock:
    key = str(index_path.expanduser().resolve(strict=False))
    with _PROCESS_LOCKS_GUARD:
        lock = _PROCESS_LOCKS.get(key)
        if lock is None:
            lock = threading.RLock()
            _PROCESS_LOCKS[key] = lock
        return lock


@contextmanager
def _platform_file_lock(lock_path: Path) -> Iterator[None]:
    lock_path.parent.mkdir(parents=True, exist_ok=True)
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
                    raise CaseHistoryLockError(
                        f"case-history lock acquisition failed: {lock_path}"
                    ) from exc
                try:
                    yield
                finally:
                    handle.seek(0)
                    try:
                        msvcrt.locking(handle.fileno(), msvcrt.LK_UNLCK, 1)
                    except OSError as exc:
                        raise CaseHistoryLockError(
                            f"case-history lock release failed: {lock_path}"
                        ) from exc
            else:
                import fcntl

                try:
                    fcntl.flock(handle.fileno(), fcntl.LOCK_EX)
                except OSError as exc:
                    raise CaseHistoryLockError(
                        f"case-history lock acquisition failed: {lock_path}"
                    ) from exc
                try:
                    yield
                finally:
                    try:
                        fcntl.flock(handle.fileno(), fcntl.LOCK_UN)
                    except OSError as exc:
                        raise CaseHistoryLockError(
                            f"case-history lock release failed: {lock_path}"
                        ) from exc
    except CaseHistoryLockError:
        raise
    except OSError as exc:
        raise CaseHistoryLockError(
            f"case-history lock file is unavailable: {lock_path}"
        ) from exc


@contextmanager
def case_history_mutation_lock(index_path: Path) -> Iterator[None]:
    index_path = Path(index_path).expanduser().resolve(strict=False)
    lock_path = index_path.with_name(index_path.name + ".lock")
    process_lock = _process_lock_for(index_path)
    with process_lock:
        with _platform_file_lock(lock_path):
            yield


def _install_mutation_lock() -> None:
    for method_name in (
        "register_case",
        "update_case_workflow",
        "delete_case",
        "prune_cases",
    ):
        current = getattr(CaseHistoryService, method_name)
        if getattr(current, "_bs_p208l_locked", False):
            continue

        def locked(self, *args, _current=current, **kwargs):
            with case_history_mutation_lock(self.index_path):
                return _current(self, *args, **kwargs)

        locked.__name__ = getattr(current, "__name__", method_name)
        locked.__doc__ = getattr(current, "__doc__", None)
        locked._bs_p208l_locked = True  # type: ignore[attr-defined]
        locked._bs_p208l_original = current  # type: ignore[attr-defined]
        setattr(CaseHistoryService, method_name, locked)


_install_mutation_lock()

# BREACHSCOPE_P2_08L_CASE_HISTORY_MUTATION_LOCK_V1
