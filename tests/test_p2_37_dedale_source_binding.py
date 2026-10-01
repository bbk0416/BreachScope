from __future__ import annotations

from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[1]
BINDING = ROOT / "external_baseline" / "p2_37_dedale_source_binding.yaml"


def _load() -> dict:
    return yaml.safe_load(BINDING.read_text(encoding="utf-8"))


def test_p2_37_binds_exact_provider_bytes_before_window_inspection() -> None:
    row = _load()
    assert row["status"] == "EXACT_SOURCE_BYTES_BOUND_WINDOW_NOT_INSPECTED"
    source = row["source_bytes"]

    winlogbeat = source["winlogbeat"]
    assert winlogbeat["size_bytes"] == 27123250952
    assert winlogbeat["provider_md5"] == "7af54ba2977f7535d4c07beb6b1ec657"
    assert winlogbeat["verified_local_md5"] == winlogbeat["provider_md5"]
    assert winlogbeat["provider_md5_match"] is True
    assert winlogbeat["sha256"] == (
        "d65572bdf8fa2f19e8fbb0ee925f646649cff53bf5e8f9948578602082fac206"
    )
    assert winlogbeat["full_download_complete"] is True

    labels = source["labels"]
    assert labels["size_bytes"] == 2669407
    assert labels["provider_md5"] == "455d0a7042531eff74285006f97822e4"
    assert labels["verified_local_md5"] == labels["provider_md5"]
    assert labels["provider_md5_match"] is True
    assert labels["sha256"] == (
        "729ac223a89c70f771861920b6b9ee3ab1bb5569e12ec54c04f380aadf574dc7"
    )


def test_p2_37_rejects_the_preallocated_incomplete_download() -> None:
    integrity = _load()["download_integrity"]
    assert integrity["prior_incomplete_winlogbeat_bytes_rejected"] is True
    assert integrity["rejected_md5"] == "c9f0cee9d8e80bec3c0a0ee2b38ff8a4"
    assert integrity["rejected_sha256"] == (
        "37d81fab9a586249abd24b206b8dfd91924dfbd7fd7926e4fec906fea5bc3ac7"
    )
    assert integrity["rejected_zip_open"] == "BAD_ZIP_FILE"
    assert integrity["rejected_bytes_used_for_p2_37"] is False
    assert integrity["fresh_range_download_chunks"] == 203
    assert integrity["fresh_range_download_complete"] is True


def test_p2_37_next_gate_is_label_blind_window_inspection() -> None:
    row = _load()
    repo = row["repository"]
    assert repo["adapter_git_blob_sha1"] == (
        "31bf09ada2f5f511f0eea8ff492732178d848233"
    )
    assert repo["detector_code_changed_for_p2_37"] is False
    assert repo["rule_tree_changed_for_p2_37"] is False

    gate = row["next_gate"]
    assert gate == {
        "command": "inspect-window",
        "labels_may_be_read": False,
        "detector_may_run": False,
        "require_exactly_28_consecutive_utc_dates": True,
        "expected_test_window_start": "2025-01-06T00:00:00+00:00",
        "expected_test_window_end_exclusive": "2025-01-20T00:00:00+00:00",
        "abort_on_window_mismatch": True,
    }

    assert row["execution_state"] == {
        "exact_source_bytes_bound": True,
        "window_inspected": False,
        "normalized_corpus_created": False,
        "event_index_created": False,
        "labels_read_for_scoring": False,
        "label_file_created": False,
        "execution_contract_merged": False,
        "detector_run": False,
        "result_observed": False,
    }


def test_p2_37_source_binding_preserves_production_nonclaims() -> None:
    claim = _load()["claim_boundary"]
    assert claim["evaluation_class"] == "external_baseline"
    assert claim["production_accuracy"] == "NOT_CLAIMED"
    assert claim["production_precision"] == "NOT_CLAIMED"
    assert claim["production_recall"] == "NOT_CLAIMED"
    assert claim["production_false_positive_rate"] == "NOT_CLAIMED"
