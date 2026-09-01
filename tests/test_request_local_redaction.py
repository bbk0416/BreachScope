from __future__ import annotations

import os
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

from breachscope.pipeline import Pipeline
from breachscope.reporting import render_html
from breachscope.schemas import Event, Finding, Report


SENSITIVE_CMD = "powershell.exe -encodedcommand AAAABBBBCCCCDDDD"


def _report() -> Report:
    event = Event(
        timestamp="2026-09-01T00:00:00Z",
        host="WIN-A",
        source="windows.security",
        event_id="4688",
        level="high",
        user="CORP\\alice",
        command_line=SENSITIVE_CMD,
        raw={},
    )
    finding = Finding(
        rule_id="rule-redact",
        rule_name="Encoded PowerShell",
        severity="high",
        mitre_technique="T1059.001",
        event=event,
        matched_value=SENSITIVE_CMD,
        matched_context=SENSITIVE_CMD,
    )
    return Report(
        summary={"total_findings": 1},
        findings=[finding],
        events=[event],
        chains=[],
        scenarios=[],
    )


def test_render_html_explicit_true_overrides_global_false(tmp_path, monkeypatch):
    monkeypatch.setenv("BS_REDACT", "0")
    path = tmp_path / "redacted.html"

    render_html(_report(), path, redact=True)

    html = path.read_text(encoding="utf-8")
    assert SENSITIVE_CMD not in html
    assert "REDACTED" in html


def test_render_html_explicit_false_overrides_global_true(tmp_path, monkeypatch):
    monkeypatch.setenv("BS_REDACT", "1")
    path = tmp_path / "clear.html"

    render_html(_report(), path, redact=False)

    html = path.read_text(encoding="utf-8")
    assert SENSITIVE_CMD in html


def test_render_html_default_keeps_legacy_env_fallback(tmp_path, monkeypatch):
    monkeypatch.setenv("BS_REDACT", "1")
    path = tmp_path / "legacy.html"

    render_html(_report(), path)

    html = path.read_text(encoding="utf-8")
    assert SENSITIVE_CMD not in html


def test_parallel_explicit_redaction_is_request_isolated(tmp_path, monkeypatch):
    # Keep one fixed process-global value that intentionally disagrees with
    # half the jobs. Each output must follow its explicit request value only.
    monkeypatch.setenv("BS_REDACT", "1")

    def worker(index: int, redact: bool) -> tuple[bool, str]:
        path = tmp_path / f"parallel-{index}.html"
        render_html(_report(), path, redact=redact)
        return redact, path.read_text(encoding="utf-8")

    jobs = [(i, i % 2 == 0) for i in range(24)]
    with ThreadPoolExecutor(max_workers=8) as pool:
        results = list(pool.map(lambda args: worker(*args), jobs))

    for redact, html in results:
        if redact:
            assert SENSITIVE_CMD not in html
            assert "REDACTED" in html
        else:
            assert SENSITIVE_CMD in html


def test_pipeline_instances_hold_independent_redaction_state(tmp_path):
    p_true = Pipeline(rules_dir=tmp_path, redact=True)
    p_false = Pipeline(rules_dir=tmp_path, redact=False)
    p_legacy = Pipeline(rules_dir=tmp_path)

    assert p_true.redact is True
    assert p_false.redact is False
    assert p_legacy.redact is None


def test_api_analysis_service_no_longer_mutates_bs_redact():
    import api.services.analysis_service as analysis_service

    source = Path(analysis_service.__file__).read_text(encoding="utf-8")
    assert 'os.environ["BS_REDACT"]' not in source
    assert "redact=redact" in source


def test_pipeline_passes_explicit_redaction_to_html_json_csv():
    import breachscope.pipeline as pipeline

    source = Path(pipeline.__file__).read_text(encoding="utf-8")
    assert "BREACHSCOPE_P1_02_REQUEST_LOCAL_REDACTION_V1" in source
    assert "render_html(self.report, out_html, redact=redact)" in source
    assert "export_json_func(self.report, out_json, redact=redact)" in source
    assert "export_csv_func(self.report, out_csv, redact=redact)" in source
