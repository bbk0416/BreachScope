from pathlib import Path

from breachscope.collector import load_jsonl_events
from breachscope.demo_scenarios import (
    SCENARIOS,
    list_demo_scenarios,
    summarize_sample_context,
    write_demo_scenario,
)
from breachscope.rules import load_rules
from breachscope.analyzer import apply_rules
from breachscope.pipeline import run_pipeline


def test_demo_scenarios_catalog_has_ten_entries():
    rows = list_demo_scenarios()

    assert len(rows) >= 10
    assert {row["id"] for row in rows} >= {
        "powershell_downloader",
        "ransomware_preparation",
        "cloud_exfiltration_staging",
    }
    assert all(row["events"] > 0 for row in rows)


def test_every_demo_scenario_produces_findings(tmp_path: Path):
    rules = load_rules(Path("rules"))

    for scenario in SCENARIOS:
        scenario_dir = tmp_path / scenario.scenario_id
        write_demo_scenario(scenario.scenario_id, scenario_dir)
        events = list(load_jsonl_events(scenario_dir))
        findings = list(apply_rules(events, rules))
        matched_techniques = {finding.mitre_technique for finding in findings}

        assert events, scenario.scenario_id
        assert findings, scenario.scenario_id
        assert matched_techniques.intersection(set(scenario.expected_techniques)), scenario.scenario_id


def test_demo_scenario_summary_context(tmp_path: Path):
    scenario_dir = tmp_path / "sample"
    write_demo_scenario("persistence_mechanisms", scenario_dir)
    events = list(load_jsonl_events(scenario_dir))
    findings = list(apply_rules(events, load_rules(Path("rules"))))

    summary = summarize_sample_context(events, findings)

    assert len(summary) == 1
    assert summary[0]["id"] == "persistence_mechanisms"
    assert summary[0]["events"] == len(events)
    assert summary[0]["findings"] >= 3
    assert "T1547.001" in summary[0]["matched_techniques"]


def test_pipeline_all_demo_scenarios_exports_sample_summary(tmp_path: Path):
    input_dir = tmp_path / "scenarios"
    write_demo_scenario("all", input_dir)
    out_prefix = tmp_path / "out" / "report"

    html_path, count = run_pipeline(
        input_dir=input_dir,
        rules_dir=Path("rules"),
        out_prefix=out_prefix,
        export_json_flag=True,
        export_csv_flag=True,
    )

    assert html_path.exists()
    assert count >= 25
    assert out_prefix.with_suffix(".json").exists()
    assert out_prefix.with_suffix(".iocs.csv").exists()
    assert out_prefix.with_suffix(".zip").exists()
    json_text = out_prefix.with_suffix(".json").read_text(encoding="utf-8")
    assert "sample_scenarios" in json_text
    assert "ransomware_preparation" in json_text
