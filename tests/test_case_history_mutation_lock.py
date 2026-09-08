from __future__ import annotations

import json
from pathlib import Path
import threading
import time

import pytest

from api.services.case_history import CaseHistoryService
from api.services import case_history_concurrency, case_history_integrity


def _report_data(findings: int = 1) -> dict:
    return {
        "summary": {
            "total_findings": findings,
            "risk": {"score": findings, "level": "low"},
            "host_counts": {},
            "mitre_counts": {},
        }
    }


def _work_dir(root: Path, name: str) -> Path:
    path = root / name
    path.mkdir(parents=True, exist_ok=True)
    return path


def test_case_history_operations_that_can_quarantine_are_locked() -> None:
    for name in (
        "register_case",
        "update_case_workflow",
        "delete_case",
        "prune_cases",
        "list_cases",
        "get_case",
        "workflow_summary",
    ):
        method = getattr(CaseHistoryService, name)
        assert getattr(method, "_bs_p208l_locked", False) is True
        assert getattr(method, "_bs_p208l_original", None) is not None


def test_second_mutation_cannot_read_stale_index_while_first_is_writing(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    root = tmp_path / "cases"
    root.mkdir()
    monkeypatch.setenv("BS_CASES_ROOT", str(root))
    index_path = tmp_path / "case_history.json"
    first_service = CaseHistoryService(index_path=index_path)
    second_service = CaseHistoryService(index_path=index_path)

    original_read = CaseHistoryService._read_index
    original_write = CaseHistoryService._write_index
    read_calls = 0
    read_calls_guard = threading.Lock()
    first_write_entered = threading.Event()
    release_first_write = threading.Event()
    first_write_only = True

    def read_spy(self):
        nonlocal read_calls
        with read_calls_guard:
            read_calls += 1
        return original_read(self)

    def write_spy(self, data):
        nonlocal first_write_only
        if first_write_only:
            first_write_only = False
            first_write_entered.set()
            assert release_first_write.wait(timeout=5)
        return original_write(self, data)

    monkeypatch.setattr(CaseHistoryService, "_read_index", read_spy)
    monkeypatch.setattr(CaseHistoryService, "_write_index", write_spy)

    errors: list[BaseException] = []

    def register(service: CaseHistoryService, work_dir: Path, findings: int) -> None:
        try:
            service.register_case(work_dir, _report_data(findings))
        except BaseException as exc:  # pragma: no cover - asserted below
            errors.append(exc)

    first = threading.Thread(
        target=register,
        args=(first_service, _work_dir(root, "first"), 1),
        daemon=True,
    )
    second = threading.Thread(
        target=register,
        args=(second_service, _work_dir(root, "second"), 2),
        daemon=True,
    )

    first.start()
    assert first_write_entered.wait(timeout=5)
    second.start()
    time.sleep(0.15)

    with read_calls_guard:
        assert read_calls == 1

    release_first_write.set()
    first.join(timeout=5)
    second.join(timeout=5)
    assert not first.is_alive()
    assert not second.is_alive()
    assert errors == []

    rows = CaseHistoryService(index_path=index_path).list_cases(limit=10)
    assert len(rows) == 2
    assert {Path(row["work_dir"]).name for row in rows} == {"first", "second"}


def test_concurrent_registers_keep_all_records(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    root = tmp_path / "cases"
    root.mkdir()
    monkeypatch.setenv("BS_CASES_ROOT", str(root))
    index_path = tmp_path / "case_history.json"
    count = 12
    barrier = threading.Barrier(count)
    errors: list[BaseException] = []

    def worker(index: int) -> None:
        try:
            service = CaseHistoryService(index_path=index_path)
            work_dir = _work_dir(root, f"case-{index}")
            barrier.wait(timeout=5)
            service.register_case(work_dir, _report_data(index + 1))
        except BaseException as exc:  # pragma: no cover - asserted below
            errors.append(exc)

    threads = [threading.Thread(target=worker, args=(i,), daemon=True) for i in range(count)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(timeout=10)

    assert all(not thread.is_alive() for thread in threads)
    assert errors == []
    rows = CaseHistoryService(index_path=index_path).list_cases(limit=50)
    assert len(rows) == count
    assert len({row["case_id"] for row in rows}) == count


def test_concurrent_corrupt_reads_serialize_quarantine(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    index_path = tmp_path / "case_history.json"
    index_path.write_text("{broken", encoding="utf-8")
    first_service = CaseHistoryService(index_path=index_path)
    second_service = CaseHistoryService(index_path=index_path)

    original_quarantine = case_history_integrity._quarantine_corrupt_index
    first_quarantine_entered = threading.Event()
    release_first_quarantine = threading.Event()
    quarantine_calls = 0
    quarantine_calls_guard = threading.Lock()

    def quarantine_spy(path: Path) -> Path:
        nonlocal quarantine_calls
        with quarantine_calls_guard:
            quarantine_calls += 1
            call_number = quarantine_calls
        if call_number == 1:
            first_quarantine_entered.set()
            assert release_first_quarantine.wait(timeout=5)
        return original_quarantine(path)

    monkeypatch.setattr(case_history_integrity, "_quarantine_corrupt_index", quarantine_spy)

    results: list[list[dict]] = []
    errors: list[BaseException] = []

    def read(service: CaseHistoryService) -> None:
        try:
            results.append(service.list_cases(limit=10))
        except BaseException as exc:  # pragma: no cover - asserted below
            errors.append(exc)

    first = threading.Thread(target=read, args=(first_service,), daemon=True)
    second = threading.Thread(target=read, args=(second_service,), daemon=True)

    first.start()
    assert first_quarantine_entered.wait(timeout=5)
    second.start()
    time.sleep(0.15)

    with quarantine_calls_guard:
        assert quarantine_calls == 1

    release_first_quarantine.set()
    first.join(timeout=5)
    second.join(timeout=5)
    assert not first.is_alive()
    assert not second.is_alive()
    assert errors == []
    assert results == [[], []]

    broken_files = list(tmp_path.glob("case_history.json.broken*"))
    assert len(broken_files) == 1
    assert broken_files[0].read_text(encoding="utf-8") == "{broken"
    assert not index_path.exists()


def test_lock_file_failure_aborts_without_modifying_index(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    root = tmp_path / "cases"
    root.mkdir()
    monkeypatch.setenv("BS_CASES_ROOT", str(root))
    index_path = tmp_path / "case_history.json"
    original = {"version": 1, "cases": []}
    index_path.write_text(json.dumps(original), encoding="utf-8")
    before = index_path.read_bytes()

    def fail_lock(_path):
        raise case_history_concurrency.CaseHistoryLockError("simulated lock failure")

    monkeypatch.setattr(case_history_concurrency, "_platform_file_lock", fail_lock)

    service = CaseHistoryService(index_path=index_path)
    with pytest.raises(case_history_concurrency.CaseHistoryLockError):
        service.register_case(_work_dir(root, "blocked"), _report_data())

    assert index_path.read_bytes() == before
    assert json.loads(index_path.read_text(encoding="utf-8")) == original
