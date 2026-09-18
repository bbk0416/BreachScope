from __future__ import annotations

import hashlib
import json
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[1]
RESULT_DIR = ROOT / "external_baseline" / "results" / "p2_22b_ce5da6c"
ASSESSMENT = RESULT_DIR / "assessment.yaml"
DOWNLOAD = RESULT_DIR / "download-verification.json"
INVENTORY = RESULT_DIR / "phase_b_allowed_inventory.json"

def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()

def _load() -> dict:
    return yaml.safe_load(ASSESSMENT.read_text(encoding="utf-8"))

def test_p2_22b_aborts_without_raw_normal_evtx() -> None:
    row = _load()
    assert row["status"] == "ABORT_UNSUPPORTED"
    assert row["abort_reason"]["code"] == "NO_RAW_NORMAL_EVTX_IN_BOUND_1_75M_VERSION"
    assert row["phase_b_inventory"]["nested_raw_evtx_member_count"] == 0
    assert row["phase_b_inventory"]["normal_named_member_extension"] == ".csv"
    assert row["phase_b_inventory"]["unique_source_supported_raw_normal_evtx_available"] is False

def test_p2_22b_bound_archive_identity_and_inventory_are_exact() -> None:
    row = _load()
    download = json.loads(DOWNLOAD.read_text(encoding="utf-8"))
    inventory = json.loads(INVENTORY.read_text(encoding="utf-8"))
    archive = download["archive"]
    assert archive["size_match"] is True
    assert archive["sha256_match"] is True
    assert archive["actual_size_bytes"] == 394944383
    assert archive["actual_sha256"] == "e9f16bcd50b2cae782ceeb2d998697098df3349c8ed3e56c983dc6b096240afe"
    nested = inventory["nested_1_75m_archive"]
    assert nested["file_count"] == 6
    assert nested["extensions"] == {".csv": 6, ".evtx": 0}
    assert nested["raw_evtx_member_count"] == 0
    assert nested["normal_named_member_count"] == 1
    assert row["artifacts"]["download_verification"]["sha256"] == _sha256(DOWNLOAD)
    assert row["artifacts"]["phase_b_allowed_inventory"]["sha256"] == _sha256(INVENTORY)

def test_p2_22b_does_not_run_detector_or_measure_fpr() -> None:
    row = _load()
    execution = row["execution"]
    assert execution["selected_telemetry_extracted"] is False
    assert execution["csv_contents_inspected"] is False
    assert execution["evtx_contents_parsed"] is False
    assert execution["detector_run"] is False
    assert execution["breachscope_output_inspected"] is False
    assert execution["scoring_contract_created"] is False
    assert execution["false_positive_measurement_performed"] is False
    boundary = row["claim_boundary"]
    assert boundary["fresh_benign_evaluation"] == "ABORT_UNSUPPORTED"
    assert boundary["benign_false_positive_rate"] == "NOT_MEASURED"
    assert boundary["production_false_positive_rate"] == "NOT_CLAIMED"

def test_p2_22b_records_phase_b_metadata_overinspection() -> None:
    deviation = _load()["phase_b_protocol_deviation"]
    assert deviation["occurred"] is True
    assert deviation["file_contents_inspected"] is False
    assert deviation["csv_contents_inspected"] is False
    assert deviation["evtx_contents_parsed"] is False
    assert deviation["detector_run"] is False
    assert "crc" in deviation["description"].lower()
    assert "packed-size" in deviation["description"].lower()

def test_current_evidence_index_records_p2_22b_abort_without_fpr() -> None:
    current = yaml.safe_load(
        (ROOT / "external_baseline" / "current_detection_evidence.yaml").read_text(encoding="utf-8")
    )
    rows = {row["evidence_id"]: row for row in current["benign_operational_evidence"]}
    p22b = rows["p2-22b-lmd2023-abort-unsupported"]
    assert p22b["class"] == "pre_detection_benign_source_assessment"
    assert p22b["status"] == "ABORT_UNSUPPORTED"
    assert p22b["benign_false_positive_rate"] == "NOT_MEASURED"
    assert p22b["detector_run"] is False
    assert p22b["reason"] == "NO_RAW_NORMAL_EVTX_IN_BOUND_1_75M_VERSION"
