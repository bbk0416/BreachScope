from __future__ import annotations

import hashlib
import json
from pathlib import Path

import yaml


ROOT = Path(__file__).resolve().parents[1]
RESULT_DIR = ROOT / "external_baseline" / "results" / "p2_22_c1c7316"
ASSESSMENT = RESULT_DIR / "assessment.yaml"
DOWNLOAD = RESULT_DIR / "download-verification.json"
INVENTORY = RESULT_DIR / "phase_b_allowed_inventory.json"


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _load() -> dict:
    return yaml.safe_load(ASSESSMENT.read_text(encoding="utf-8"))


def test_p2_22_aborts_when_source_label_mapping_is_not_reproducible() -> None:
    row = _load()
    assert row["status"] == "ABORT_UNSUPPORTED"
    assert row["abort_reason"]["code"] == "SOURCE_LABEL_MAPPING_NOT_REPRODUCIBLE"
    assert row["execution"]["detector_run"] is False
    assert row["execution"]["breachscope_output_inspected"] is False
    assert row["execution"]["scoring_contract_created"] is False
    assert row["execution"]["false_positive_measurement_performed"] is False

def test_p2_22_bound_bytes_and_phase_b_inventory_are_exact() -> None:
    row = _load()
    assert row["verified_bytes"]["archive"]["identity_match"] is True
    assert row["verified_bytes"]["label_table"]["identity_match"] is True
    assert row["phase_b_inventory"]["csv_rows"] == 71017
    assert row["phase_b_inventory"]["csv_label_values"] == {"0": 53802, "1": 17215}
    assert row["phase_b_inventory"]["csv_has_explicit_evtx_source_path_column"] is False
    assert row["phase_b_inventory"]["csv_has_explicit_evtx_file_id_column"] is False
    assert row["phase_b_inventory"]["zip_files"] == [
        "NLME-0.evtx",
        "NLME-1.evtx",
        "NLME-2.evtx",
    ]

    download = json.loads(DOWNLOAD.read_text(encoding="utf-8"))
    assert all(item["size_match"] for item in download["files"])
    assert all(item["git_blob_match"] for item in download["files"])
    assert row["artifacts"]["download_verification"]["sha256"] == _sha256(DOWNLOAD)
    assert row["artifacts"]["phase_b_allowed_inventory"]["sha256"] == _sha256(INVENTORY)


def test_p2_22_records_phase_b_overinspection_and_retires_source() -> None:
    row = _load()
    deviation = row["phase_b_protocol_deviation"]
    assert deviation["occurred"] is True
    assert deviation["raw_evtx_contents_parsed"] is False
    assert deviation["breachscope_detector_run"] is False
    assert deviation["breachscope_output_inspected"] is False
    assert deviation["product_or_rules_tuned_from_source"] is False
    assert "retired" in deviation["consequence"].lower()

def test_p2_22_makes_no_fpr_or_production_claim() -> None:
    row = _load()
    boundary = row["claim_boundary"]
    assert boundary["fresh_benign_evaluation"] == "ABORT_UNSUPPORTED"
    assert boundary["benign_false_positive_rate"] == "NOT_MEASURED"
    assert boundary["production_false_positive_rate"] == "NOT_CLAIMED"
    assert boundary["production_accuracy"] == "NOT_CLAIMED"
    assert boundary["production_quality"] == "NOT_CLAIMED"

    inventory = json.loads(INVENTORY.read_text(encoding="utf-8"))
    assert set(inventory) == {
        "row_count",
        "columns",
        "label_values",
        "zip_file_count",
        "zip_names",
        "zip_extensions",
    }
    assert "first_rows_selected_fields" not in inventory
    assert "candidate_unique_values" not in inventory


def test_current_evidence_index_records_p2_22_abort_without_fpr() -> None:
    current = yaml.safe_load(
        (ROOT / "external_baseline" / "current_detection_evidence.yaml").read_text(encoding="utf-8")
    )
    rows = {row["evidence_id"]: row for row in current["benign_operational_evidence"]}
    p22 = rows["p2-22-cerberus-trace-abort-unsupported"]

    assert p22["class"] == "pre_detection_benign_source_assessment"
    assert p22["status"] == "ABORT_UNSUPPORTED"
    assert p22["benign_false_positive_rate"] == "NOT_MEASURED"
    assert p22["detector_run"] is False
    assert p22["reason"] == "SOURCE_LABEL_MAPPING_NOT_REPRODUCIBLE"
