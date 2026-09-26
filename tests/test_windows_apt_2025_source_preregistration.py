from pathlib import Path

import yaml


ROOT = Path(__file__).resolve().parents[1]
CONTRACT = ROOT / "external_baseline" / "windows_apt_2025_source_preregistration.yaml"


def _contract() -> dict:
    return yaml.safe_load(CONTRACT.read_text(encoding="utf-8"))


def test_windows_apt_source_preregistration_freezes_current_detector_and_v3_source():
    data = _contract()

    assert data["schema"] == "breachscope.windows_apt_2025_source_preregistration.v1"
    assert data["analysis_id"] == "windows-apt-2025-v3-fresh-source-revalidation-v1"
    assert data["status"] == "PREREGISTERED_PRE_RAW_ACCESS"

    detector = data["current_detector"]
    assert detector["repo_commit"] == "277e1c7cd8460e9db4f83f49e02bf4e03d7cf310"
    assert detector["rules_tree_sha256"] == "61132f090861e56f3257c4da808fbe1f6839841a3be07367d352c66f3ac9ce88"
    assert detector["rule_count"] == 73

    source = data["source"]
    assert source["dataset_id"] == "b8fmtzvpy8"
    assert source["selected_version"] == 3
    assert source["doi"] == "10.17632/b8fmtzvpy8.3"
    assert source["raw_package_downloaded_before_preregistration"] is False
    assert source["raw_log_rows_inspected_before_preregistration"] is False
    assert source["previously_detector_evaluated_by_breachscope"] is False


def test_windows_apt_phase1_forbids_semantic_row_inspection():
    data = _contract()
    phase = data["phase_1_after_merge"]

    assert "inspect only CSV header rows and encoding/dialect" in phase["allowed_operations"]
    assert "count physical data rows without parsing semantic field values" in phase["allowed_operations"]
    assert "inspect or print any log data row values" in phase["prohibited_operations"]
    assert "run BreachScope rules against any Windows-APT row" in phase["prohibited_operations"]
    assert "modify detector rules based on package contents" in phase["prohibited_operations"]


def test_windows_apt_phase2_requires_explicit_label_provenance_and_fail_closed():
    data = _contract()
    phase = data["phase_2_gate_before_semantic_rows"]

    assert any(
        "explicit upstream-provided class field" in item
        for item in phase["requirements"]
    )
    assert any(
        "ATT&CK/Wazuh technique tags must not be used" in item
        for item in phase["requirements"]
    )
    assert any(
        "do not infer benign/malicious from MITRE tags or detector behavior" in item
        for item in phase["fail_closed"]
    )


def test_windows_apt_selection_excludes_combined_duplicate_and_is_not_posthoc():
    data = _contract()
    selection = data["planned_selection"]

    assert selection["event_rows"] == "all 16 per-period log CSVs"
    assert any("combined/consolidated" in item for item in selection["excluded_event_rows"])
    assert "scenario_manifest.csv" in selection["excluded_event_rows"]
    assert "validation_summary.csv" in selection["excluded_event_rows"]
    assert selection["no_posthoc_subsetting"] is True


def test_windows_apt_metrics_do_not_claim_recall_or_fpr():
    data = _contract()

    assert data["planned_metrics"]["attack"]["prohibited_name"] == "recall"
    assert (
        data["planned_metrics"]["benign"]["prohibited_name"]
        == "confirmed_false_positive_rate"
    )

    claims = data["claim_boundaries"]
    assert claims["upstream_wazuh_mitre_mapping_is_independent_oracle"] is False
    assert claims["confirmed_false_positive_rate"] == "NOT_CLAIMED"
    assert claims["event_level_recall"] == "NOT_CLAIMED"
    assert claims["production_accuracy"] == "NOT_CLAIMED"
    assert claims["production_recall"] == "NOT_CLAIMED"
    assert claims["production_false_positive_rate"] == "NOT_CLAIMED"
