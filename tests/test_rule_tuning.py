from __future__ import annotations

import json
from pathlib import Path

from fastapi.testclient import TestClient

from api.main import app
from breachscope.pipeline import Pipeline
from breachscope.schemas import Rule


client = TestClient(app)


def _rules() -> list[Rule]:
    return [
        Rule(
            id="R-ONE",
            name="One",
            description="one",
            field="command_line",
            pattern="one",
            severity="medium",
            mitre_technique="T1059.003",
        ),
        Rule(
            id="R-TWO",
            name="Two",
            description="two",
            field="command_line",
            pattern="two",
            severity="high",
            mitre_technique="T1047",
        ),
    ]


def test_pipeline_rule_include_and_exclude_are_case_insensitive(monkeypatch, tmp_path: Path) -> None:
    monkeypatch.setattr("breachscope.pipeline.load_rules", lambda _: _rules())

    pipeline = Pipeline(
        rules_dir=tmp_path,
        rule_include=["r-one", "R-TWO"],
        rule_exclude=["r-two"],
    )

    assert [rule.id for rule in pipeline.load_rules()] == ["R-ONE"]


def test_pipeline_unknown_include_fails_closed_to_zero_active_rules(monkeypatch, tmp_path: Path) -> None:
    monkeypatch.setattr("breachscope.pipeline.load_rules", lambda _: _rules())

    pipeline = Pipeline(rules_dir=tmp_path, rule_include=["R-NOT-FOUND"])

    assert pipeline.load_rules() == []


def test_api_rule_include_limits_active_rulepack_and_records_filter(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setenv("BS_CASES_ROOT", str(tmp_path))
    event = {
        "timestamp": "2026-01-01T00:00:00Z",
        "host": "WS-01",
        "source": "ProcessCreate",
        "event_id": "4688",
        "user": "CORP\\alice",
        "command_line": "powershell.exe -encodedcommand AAAABBBBCCCCDDDD",
    }
    sample = tmp_path / "events.jsonl"
    sample.write_text(json.dumps(event) + "\n", encoding="utf-8")

    with sample.open("rb") as handle:
        response = client.post(
            "/api/analyze",
            files=[("files", ("events.jsonl", handle, "application/octet-stream"))],
            data={
                "use_repo_rules": "true",
                "min_severity": "low",
                "rule_include": "R-ENC",
                "redact": "true",
                "work_dir": str(tmp_path / "work"),
            },
        )

    assert response.status_code == 200
    payload = response.json()
    assert payload["count"] == 1
    assert payload["preview"]["rule_pack"]["total_rules"] == 1

    report = json.loads(Path(payload["json_path"]).read_text(encoding="utf-8"))
    filters = report["summary"]["filters"]
    assert filters["rule_include"] == ["R-ENC"]
    assert filters["rule_exclude"] == []


def test_api_rule_exclude_removes_matching_rules(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setenv("BS_CASES_ROOT", str(tmp_path))
    event = {
        "timestamp": "2026-01-01T00:00:00Z",
        "host": "WS-01",
        "source": "ProcessCreate",
        "event_id": "4688",
        "user": "CORP\\alice",
        "command_line": "powershell.exe -encodedcommand AAAABBBBCCCCDDDD",
    }
    sample = tmp_path / "exclude-events.jsonl"
    sample.write_text(json.dumps(event) + "\n", encoding="utf-8")

    with sample.open("rb") as handle:
        response = client.post(
            "/api/analyze",
            files=[("files", ("events.jsonl", handle, "application/octet-stream"))],
            data={
                "use_repo_rules": "true",
                "min_severity": "low",
                "rule_exclude": "R-ENC,2d4d3f79-4af2-4bc6-9fe8-6e2317be5511",
                "redact": "true",
                "work_dir": str(tmp_path / "exclude-work"),
            },
        )

    assert response.status_code == 200
    payload = response.json()
    assert payload["count"] == 0
    assert payload["preview"]["rule_pack"]["total_rules"] == 71

    report = json.loads(Path(payload["json_path"]).read_text(encoding="utf-8"))
    assert report["summary"]["filters"]["rule_exclude"] == [
        "R-ENC",
        "2d4d3f79-4af2-4bc6-9fe8-6e2317be5511",
    ]


def test_web_ui_exposes_rule_catalog_and_per_analysis_controls() -> None:
    response = client.get("/")

    assert response.status_code == 200
    assert 'id="ruleInclude"' in response.text
    assert 'id="ruleExclude"' in response.text
    assert 'id="ruleSearch"' in response.text
    assert 'id="loadRulesBtn"' in response.text
    assert "이번 분석에만 적용됩니다" in response.text
    assert "fd.append('rule_include'" in response.text
    assert "fd.append('rule_exclude'" in response.text
