import hashlib
from pathlib import Path

import yaml


ROOT = Path(__file__).resolve().parents[1]
CONTRACT = ROOT / "external_baseline" / "brawl_documented_schema_adapter_contract.yaml"


def test_brawl_adapter_contract_freezes_pre_raw_source_and_adapter():
    contract = yaml.safe_load(CONTRACT.read_text(encoding="utf-8"))

    assert contract["schema"] == "breachscope.brawl_documented_schema_adapter_contract.v1"
    assert contract["status"] == "PRE_RAW_INSPECTION_FROZEN"

    source = contract["source"]
    assert source["repository"] == "mitre/brawl-public-game-001"
    assert source["commit"] == "7ec51fac8fc05ea01da210f604b821ef52818173"
    assert source["archive_path"] == "brawl-public-game-001.zip"
    assert source["archive_git_blob_sha1"] == "257a4ed9dcba427f75cc11da286f44004ed6c7c0"
    assert source["archive_size_bytes"] == 4967769
    assert source["raw_archive_downloaded_before_contract"] is False
    assert source["raw_archive_contents_inspected_before_contract"] is False

    adapter = contract["adapter"]
    adapter_path = ROOT / adapter["path"]
    actual = hashlib.sha256(adapter_path.read_bytes()).hexdigest()
    assert actual == adapter["sha256"]
    assert adapter["raw_data_used_for_implementation"] is False
    assert adapter["automatic_general_jsonl_interpretation"] is False
    documented = contract["upstream_documented_schema"]
    assert documented["sysmon_primary_timestamp"] == "data_model.fields.utc_time"
    assert documented["sysmon_timestamp_fallback"] == "@timestamp"


def test_brawl_adapter_contract_does_not_relax_claim_boundaries():
    contract = yaml.safe_load(CONTRACT.read_text(encoding="utf-8"))
    text = "\n".join(contract["claim_boundaries"])

    assert "not an evaluation result" in text
    assert "not a complete malicious/benign event label set" in text
    assert "production benign-FPR corpus" in text
    assert "no production accuracy, recall, precision, or false-positive rate" in text

    gates = contract["pre_raw_inspection_gate"]
    assert any("scoring preregistration" in item for item in gates)
    assert any("only after" in item and "raw BRAWL archive" in item for item in gates)