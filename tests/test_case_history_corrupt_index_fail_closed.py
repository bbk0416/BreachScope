import json
from pathlib import Path

import pytest

from api.services.case_history import CaseHistoryService
from api.services.case_history_integrity import CaseHistoryIndexCorruptionError
import api.services.case_history_integrity as integrity_module


def _service(index_path: Path) -> CaseHistoryService:
    return CaseHistoryService(index_path=index_path)


def test_corrupt_json_is_quarantined_before_starting_empty_index(tmp_path):
    index = tmp_path / "case_history.json"
    corrupt = '{"version": 1, "cases": ['
    index.write_text(corrupt, encoding="utf-8")

    service = _service(index)

    assert service.list_cases() == []
    assert not index.exists()
    broken = tmp_path / "case_history.json.broken"
    assert broken.read_text(encoding="utf-8") == corrupt


def test_existing_broken_backup_is_not_overwritten(tmp_path):
    index = tmp_path / "case_history.json"
    index.write_text("{bad-current", encoding="utf-8")
    first_broken = tmp_path / "case_history.json.broken"
    first_broken.write_text("older-corrupt-index", encoding="utf-8")

    service = _service(index)

    assert service.list_cases() == []
    assert first_broken.read_text(encoding="utf-8") == "older-corrupt-index"
    assert (tmp_path / "case_history.json.broken.2").read_text(encoding="utf-8") == "{bad-current"


def test_invalid_cases_shape_is_quarantined_instead_of_silently_replaced(tmp_path):
    index = tmp_path / "case_history.json"
    malformed = {"version": 1, "cases": {"case-1": {"work_dir": "x"}}}
    raw = json.dumps(malformed)
    index.write_text(raw, encoding="utf-8")

    service = _service(index)

    assert service.list_cases() == []
    assert not index.exists()
    assert (tmp_path / "case_history.json.broken").read_text(encoding="utf-8") == raw


def test_non_mapping_case_rows_are_quarantined(tmp_path):
    index = tmp_path / "case_history.json"
    raw = json.dumps({"version": 1, "cases": ["not-a-case-record"]})
    index.write_text(raw, encoding="utf-8")

    service = _service(index)

    assert service.list_cases() == []
    assert (tmp_path / "case_history.json.broken").read_text(encoding="utf-8") == raw


def test_quarantine_failure_fails_closed_and_preserves_corrupt_bytes(tmp_path, monkeypatch):
    index = tmp_path / "case_history.json"
    corrupt = b'{"cases": [broken'
    index.write_bytes(corrupt)
    real_replace = Path.replace

    def deny_quarantine(self, target):
        if self == index:
            raise PermissionError("simulated quarantine denial")
        return real_replace(self, target)

    monkeypatch.setattr(Path, "replace", deny_quarantine)
    service = _service(index)

    with pytest.raises(CaseHistoryIndexCorruptionError):
        service.list_cases()

    assert index.read_bytes() == corrupt
    assert not (tmp_path / "case_history.json.broken").exists()


def test_register_case_cannot_overwrite_corrupt_index_when_quarantine_fails(
    tmp_path, monkeypatch
):
    cases_root = tmp_path / "cases"
    work = cases_root / "bs_case_test"
    work.mkdir(parents=True)
    index = tmp_path / "case_history.json"
    corrupt = b"not-json-at-all"
    index.write_bytes(corrupt)
    monkeypatch.setenv("BS_CASES_ROOT", str(cases_root))

    real_replace = Path.replace

    def deny_quarantine(self, target):
        if self == index:
            raise PermissionError("simulated quarantine denial")
        return real_replace(self, target)

    monkeypatch.setattr(Path, "replace", deny_quarantine)
    service = _service(index)

    with pytest.raises(CaseHistoryIndexCorruptionError):
        service.register_case(work, {"summary": {}})

    assert index.read_bytes() == corrupt
    assert not (tmp_path / "case_history.json.broken").exists()


def test_valid_index_shape_is_unchanged(tmp_path):
    index = tmp_path / "case_history.json"
    data = {"version": 1, "cases": []}
    index.write_text(json.dumps(data), encoding="utf-8")

    service = _service(index)

    assert service.list_cases() == []
    assert json.loads(index.read_text(encoding="utf-8")) == data


def test_p2_08k_marker_present():
    source = Path(integrity_module.__file__).read_text(encoding="utf-8")
    assert "BREACHSCOPE_P2_08K_CORRUPT_CASE_INDEX_FAIL_CLOSED_V1" in source
