from __future__ import annotations

import asyncio
import json
from types import SimpleNamespace

import api.services.analysis_service as analysis_module
from api.services.analysis_service import AnalysisService


class SuccessfulPipeline:
    def __init__(self, **kwargs):
        pass

    def run(self, *, input_dir, out_prefix, **kwargs):
        out_prefix.parent.mkdir(parents=True, exist_ok=True)
        html_path = out_prefix.with_suffix(".html")
        html_path.write_text("<html>ok</html>", encoding="utf-8")
        report_data = {
            "summary": {
                "total_findings": 0,
                "risk": {"score": 0, "level": "none"},
                "executive_summary": [],
            }
        }
        out_prefix.with_suffix(".json").write_text(
            json.dumps(report_data),
            encoding="utf-8",
        )
        return html_path, 0


def _run(service: AnalysisService, *, work_dir=None):
    return asyncio.run(
        service.analyze(
            files=[],
            use_repo_rules=True,
            min_severity="low",
            mitre_include="",
            mitre_exclude="",
            host_include="",
            redact=True,
            render_pdf=False,
            do_evtx=False,
            collect_evtx=False,
            collect_logs="",
            collect_hours=None,
            work_dir=work_dir,
        )
    )


def _install_success_fakes(monkeypatch, history_calls):
    monkeypatch.setattr(analysis_module, "Pipeline", SuccessfulPipeline)
    monkeypatch.setattr(analysis_module, "build_preview", lambda report: {})

    class FakeHistory:
        def register_case(self, work, report_data):
            history_calls.append(work)
            return SimpleNamespace(case_id="case-test")

    monkeypatch.setattr(analysis_module, "CaseHistoryService", FakeHistory)


def test_cleanup_flag_removes_successful_auto_managed_case_and_skips_history(
    tmp_path,
    monkeypatch,
):
    cases_root = tmp_path / "cases"
    work = cases_root / "bs_case_success"
    work.mkdir(parents=True)
    history_calls = []

    monkeypatch.setenv("BS_CASES_ROOT", str(cases_root))
    monkeypatch.setenv("BS_WEB_CLEANUP_AFTER_ANALYSIS", "1")
    _install_success_fakes(monkeypatch, history_calls)

    service = AnalysisService()
    monkeypatch.setattr(
        service.workdir_service,
        "create_work_directory",
        lambda work_dir=None: work,
    )

    result = _run(service)

    assert result["success"] is True
    assert result["case_id"] is None
    assert history_calls == []
    assert not work.exists()


def test_cleanup_flag_preserves_explicit_workdir_and_registers_case(
    tmp_path,
    monkeypatch,
):
    cases_root = tmp_path / "cases"
    work = cases_root / "explicit_case"
    work.mkdir(parents=True)
    existing = work / "existing.evtx"
    existing.write_bytes(b"pre-existing evidence")
    history_calls = []

    monkeypatch.setenv("BS_CASES_ROOT", str(cases_root))
    monkeypatch.setenv("BS_WEB_CLEANUP_AFTER_ANALYSIS", "1")
    _install_success_fakes(monkeypatch, history_calls)

    service = AnalysisService()
    monkeypatch.setattr(
        service.workdir_service,
        "create_work_directory",
        lambda work_dir=None: work,
    )

    result = _run(service, work_dir=str(work))

    assert result["success"] is True
    assert result["case_id"] == "case-test"
    assert history_calls == [work]
    assert work.exists()
    assert existing.read_bytes() == b"pre-existing evidence"
    assert (work / "out" / "report.html").exists()


def test_cleanup_flag_off_preserves_successful_auto_case_and_history(
    tmp_path,
    monkeypatch,
):
    cases_root = tmp_path / "cases"
    work = cases_root / "bs_case_success"
    work.mkdir(parents=True)
    history_calls = []

    monkeypatch.setenv("BS_CASES_ROOT", str(cases_root))
    monkeypatch.setenv("BS_WEB_CLEANUP_AFTER_ANALYSIS", "0")
    _install_success_fakes(monkeypatch, history_calls)

    service = AnalysisService()
    monkeypatch.setattr(
        service.workdir_service,
        "create_work_directory",
        lambda work_dir=None: work,
    )

    result = _run(service)

    assert result["success"] is True
    assert result["case_id"] == "case-test"
    assert history_calls == [work]
    assert work.exists()
    assert (work / "out" / "report.json").exists()


def test_p2_08g_marker_present():
    source = open(analysis_module.__file__, "r", encoding="utf-8").read()
    assert "BREACHSCOPE_P2_08G_SUCCESS_CLEANUP_POLICY_V1" in source
