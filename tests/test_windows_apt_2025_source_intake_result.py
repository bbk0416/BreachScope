from __future__ import annotations

import hashlib
import json
from pathlib import Path

import yaml


ROOT = Path(__file__).resolve().parents[1]
PREREG = ROOT / "external_baseline" / "windows_apt_2025_source_preregistration.yaml"
SUMMARY = ROOT / "external_baseline" / "windows_apt_2025_source_intake_summary.yaml"
RESULT = (
    ROOT
    / "external_baseline"
    / "results"
    / "windows_apt_2025_v3_source_intake"
    / "result.json"
)
RUNNER = ROOT / "scripts" / "windows_apt_2025_source_intake.py"


EXPECTED_EVENT_FILES = [
    "01-03-December.csv",
    "03-04-December.csv",
    "04-07-December.csv",
    "07-10-December.csv",
    "1-11-November.csv",
    "10-December-P1.csv",
    "10-December-P2.csv",
    "11-12-December.csv",
    "11-16-November.csv",
    "12-13-December.csv",
    "13-14-December.csv",
    "14-17-December.csv",
    "22-December.csv",
    "23-30-November.csv",
    "28-October-01-November.csv",
    "30-November.csv",
]


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _summary() -> dict:
    return yaml.safe_load(SUMMARY.read_text(encoding="utf-8"))


def _result() -> dict:
    return json.loads(RESULT.read_text(encoding="utf-8"))


def test_windows_apt_source_intake_artifacts_are_byte_exact() -> None:
    assert RESULT.stat().st_size == 319_994
    assert _sha256(RESULT) == (
        "9bd597ba47a83aae67b45a7f620c6289bb6f96b0463bd517cc5ff295efacb713"
    )
    assert _sha256(RUNNER) == (
        "c0ed39f4843ebd53cc71ecd11c433466e910e34ea7f2755ee40102b65fe6a0cf"
    )

    summary = _summary()
    assert summary["raw_metadata_result"]["size_bytes"] == RESULT.stat().st_size
    assert summary["raw_metadata_result"]["sha256"] == _sha256(RESULT)
    assert summary["intake_runner"]["sha256"] == _sha256(RUNNER)


def test_windows_apt_source_intake_preserves_preregistered_detector_and_source() -> None:
    prereg = yaml.safe_load(PREREG.read_text(encoding="utf-8"))
    summary = _summary()
    result = _result()

    assert summary["analysis_id"] == "windows-apt-2025-v3-source-intake-v1"
    assert summary["status"] == "COMPLETED_FAIL_CLOSED_LABEL_PROVENANCE"
    assert summary["preregistration"]["merge_commit"] == (
        "5fcc48dfbab2138cfe02c4fe64184d37e65abe3a"
    )
    assert summary["preregistration"]["detector_repo_commit"] == (
        prereg["current_detector"]["repo_commit"]
    )
    assert summary["preregistration"]["rules_tree_sha256"] == (
        prereg["current_detector"]["rules_tree_sha256"]
    )
    assert summary["preregistration"]["rule_count"] == 73

    assert result["schema"] == "breachscope.windows_apt_2025_source_intake.v1"
    assert result["analysis_id"] == "windows-apt-2025-v3-source-intake-v1"
    assert result["status"] == "COMPLETED_METADATA_ONLY"
    assert result["source"]["dataset_id"] == "b8fmtzvpy8"
    assert result["source"]["version"] == 3
    assert result["source"]["archive_size_bytes"] == 54_966_714
    assert result["source"]["archive_sha256"] == (
        "0dfd0270ea41788fb5e9d24045f4314fe2682cc327d9d6da537b2d908d29c5c5"
    )


def test_windows_apt_source_intake_integrity_and_selection_are_exact() -> None:
    summary = _summary()
    result = _result()

    assert result["package"]["member_count"] == 23
    assert len(result["csv_files"]) == 19
    assert result["integrity"]["checksum_entry_count"] == 19
    assert result["integrity"]["csv_checksum_match_count"] == 19
    assert result["integrity"]["csv_checksum_total"] == 19
    assert result["integrity"]["all_csv_checksums_match"] is True

    selection = result["selection"]
    assert selection["selected_event_file_count"] == 16
    assert selection["selected_event_files"] == EXPECTED_EVENT_FILES
    assert selection["excluded_duplicate_event_file"] == "combined.csv"
    assert selection["excluded_supplementary_csvs"] == [
        "scenario_manifest.csv",
        "validation_summary.csv",
    ]
    assert selection["posthoc_subsetting_allowed"] is False

    assert summary["selection"]["selected_event_files"] == EXPECTED_EVENT_FILES
    assert summary["selection"]["no_posthoc_subsetting"] is True


def test_windows_apt_source_intake_is_metadata_only_and_does_not_claim_ground_truth() -> None:
    summary = _summary()
    result = _result()

    protocol = result["protocol"]
    assert protocol["semantic_data_rows_decoded_or_printed"] is False
    assert protocol["semantic_data_rows_parsed_as_csv_records"] is False
    assert protocol["detector_rules_executed_against_source"] is False

    label_probe = result["label_provenance_probe"]
    assert label_probe["candidate_count"] == 0
    assert label_probe["explicit_source_intent_header_candidates"] == {}
    assert label_probe["attack_mitre_fields_are_not_source_intent_labels"] is True
    assert label_probe["semantic_rows_inspected_to_find_labels"] is False

    label_summary = summary["label_provenance"]
    assert label_summary["explicit_source_intent_header_candidate_count"] == 0
    assert label_summary["attack_or_general_partition_identified_without_semantic_rows"] is False
    assert label_summary["ATTACK_or_Wazuh_mitre_mapping_as_independent_oracle"] is False
    assert label_summary["result"] == "NOT_IDENTIFIED_FAIL_CLOSED"


def test_windows_apt_source_intake_fail_closed_blocks_phase2_and_performance_claims() -> None:
    summary = _summary()
    decision = summary["decision"]

    assert decision["phase_1_source_identity"] == "PASS"
    assert decision["phase_1_package_layout"] == "PASS"
    assert decision["phase_1_integrity"] == "PASS"
    assert decision["phase_1_deterministic_selection"] == "PASS"
    assert decision["phase_1_label_provenance"] == "FAIL_CLOSED"
    assert decision["phase_2_semantic_row_access_authorized"] is False
    assert decision["phase_2_adapter_execution_authorized"] is False
    assert decision["detector_execution_against_windows_apt_authorized"] is False

    claims = summary["claim_boundary"]
    assert claims["fresh_attack_revalidation"] == "NOT_RUN"
    assert claims["fresh_benign_revalidation"] == "NOT_RUN"
    assert claims["event_level_attack_ground_truth"] == "NOT_ESTABLISHED"
    assert claims["event_level_benign_ground_truth"] == "NOT_ESTABLISHED"
    assert claims["event_level_recall"] == "NOT_CLAIMED"
    assert claims["confirmed_false_positive_rate"] == "NOT_CLAIMED"
    assert claims["production_accuracy"] == "NOT_CLAIMED"
    assert claims["production_recall"] == "NOT_CLAIMED"
    assert claims["production_false_positive_rate"] == "NOT_CLAIMED"