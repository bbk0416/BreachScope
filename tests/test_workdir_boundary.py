from __future__ import annotations

import json
import tempfile
from pathlib import Path

import pytest

from api.services.case_history import CaseHistoryService
from api.services.path_boundary import (
    WorkDirBoundaryError,
    is_safe_managed_delete,
    validate_managed_work_dir,
)
from api.services.report_preview import load_preview
from api.services.workdir_service import WorkDirectoryService


def _report():
    return {
        "summary": {
            "total_findings": 0,
            "risk": {"score": 0, "level": "none"},
        },
        "findings": [],
        "events": [],
    }


def test_relative_custom_workdir_resolves_below_cases_root(tmp_path, monkeypatch):
    root = tmp_path / "cases"
    monkeypatch.setenv("BS_CASES_ROOT", str(root))
    result = WorkDirectoryService().create_work_directory("analyst/case-a")
    assert result.resolve() == (root / "analyst" / "case-a").resolve()
    assert result.is_dir()


def test_absolute_custom_workdir_inside_cases_root_is_allowed(tmp_path, monkeypatch):
    root = tmp_path / "cases"
    monkeypatch.setenv("BS_CASES_ROOT", str(root))
    requested = root / "case-b"
    result = WorkDirectoryService().create_work_directory(str(requested))
    assert result.resolve() == requested.resolve()


def test_custom_absolute_path_outside_cases_root_is_rejected(tmp_path, monkeypatch):
    root = tmp_path / "cases"
    outside = tmp_path / "outside"
    monkeypatch.setenv("BS_CASES_ROOT", str(root))
    with pytest.raises(WorkDirBoundaryError):
        WorkDirectoryService().create_work_directory(str(outside))
    assert not outside.exists()


def test_relative_parent_traversal_is_rejected(tmp_path, monkeypatch):
    root = tmp_path / "cases"
    monkeypatch.setenv("BS_CASES_ROOT", str(root))
    with pytest.raises(WorkDirBoundaryError):
        WorkDirectoryService().create_work_directory("../escape")
    assert not (tmp_path / "escape").exists()


def test_cases_root_itself_is_not_a_valid_workdir(tmp_path, monkeypatch):
    root = tmp_path / "cases"
    root.mkdir()
    monkeypatch.setenv("BS_CASES_ROOT", str(root))
    with pytest.raises(WorkDirBoundaryError):
        validate_managed_work_dir(root)
    assert not is_safe_managed_delete(root)


def test_case_registration_rejects_external_workdir(tmp_path, monkeypatch):
    root = tmp_path / "cases"
    outside = tmp_path / "external-case"
    (outside / "out").mkdir(parents=True)
    monkeypatch.setenv("BS_CASES_ROOT", str(root))
    monkeypatch.setenv("BS_CASE_HISTORY_PATH", str(tmp_path / "history.json"))
    with pytest.raises(WorkDirBoundaryError):
        CaseHistoryService().register_case(outside, _report())


def test_report_preview_rejects_external_directory_even_with_valid_report(tmp_path, monkeypatch):
    root = tmp_path / "cases"
    outside = tmp_path / "external-preview"
    (outside / "out").mkdir(parents=True)
    (outside / "out" / "report.json").write_text(
        json.dumps(_report()), encoding="utf-8"
    )
    monkeypatch.setenv("BS_CASES_ROOT", str(root))
    with pytest.raises(FileNotFoundError):
        load_preview(outside)


def test_safe_delete_accepts_case_child_but_not_root(tmp_path, monkeypatch):
    root = tmp_path / "cases"
    child = root / "case-delete"
    child.mkdir(parents=True)
    monkeypatch.setenv("BS_CASES_ROOT", str(root))
    assert is_safe_managed_delete(child)
    assert not is_safe_managed_delete(root)
    assert CaseHistoryService._is_safe_to_remove(child)
    assert not CaseHistoryService._is_safe_to_remove(root)


def test_nested_temp_bs_web_name_is_not_a_delete_bypass(tmp_path, monkeypatch):
    root = tmp_path / "cases"
    attacker = tmp_path / "bs_web_attacker"
    attacker.mkdir()
    monkeypatch.setenv("BS_CASES_ROOT", str(root))
    assert not is_safe_managed_delete(attacker)
    assert not CaseHistoryService._is_safe_to_remove(attacker)


def test_real_system_temp_bs_web_direct_child_remains_compatible(tmp_path, monkeypatch):
    root = tmp_path / "cases"
    monkeypatch.setenv("BS_CASES_ROOT", str(root))
    with tempfile.TemporaryDirectory(prefix="bs_web_") as td:
        path = Path(td)
        assert path.parent.resolve() == Path(tempfile.gettempdir()).resolve()
        assert validate_managed_work_dir(
            path, allow_temp=True, must_exist=True
        ) == path.resolve()
        assert is_safe_managed_delete(path)


def test_case_history_delete_cannot_remove_cases_root(tmp_path, monkeypatch):
    root = tmp_path / "cases"
    root.mkdir()
    monkeypatch.setenv("BS_CASES_ROOT", str(root))
    monkeypatch.setenv("BS_CASE_HISTORY_PATH", str(tmp_path / "history.json"))
    assert CaseHistoryService._is_safe_to_remove(root) is False
    assert root.exists()


def test_p0_11_markers_present():
    import api.services.workdir_service as workdir_module
    import api.services.case_history as history_module

    workdir_source = open(workdir_module.__file__, "r", encoding="utf-8").read()
    history_source = open(history_module.__file__, "r", encoding="utf-8").read()
    assert "BREACHSCOPE_P0_11_WORKDIR_BOUNDARY_V1" in workdir_source
    assert "BREACHSCOPE_P0_11_DELETE_BOUNDARY_V1" in history_source
