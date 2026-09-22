from __future__ import annotations

import inspect
from pathlib import Path

import yaml
from Evtx import Nodes as evtx_nodes


ROOT = Path(__file__).resolve().parents[1]
RECORD = ROOT / "performance" / "p2_32_evtx_value_node_profile_diagnosis.yaml"


def _load() -> dict:
    return yaml.safe_load(RECORD.read_text(encoding="utf-8"))


def test_p2_32_closes_as_diagnosis_without_product_change() -> None:
    row = _load()
    assert row["status"] == "CLOSE_POSTHOC_CANDIDATE_IDENTIFIED"
    decision = row["decision"]
    assert decision["product_code_change"] is False
    assert decision["monkey_patch_python_evtx_in_product"] == "NO"
    assert decision["dependency_fork_or_vendor_change"] == "NO"
    assert decision["candidate_for_preregistered_benchmark"] == "YES"
    assert decision["p2_30b_result_modified"] is False
    assert decision["p2_31_result_modified"] is False


def test_p2_32_candidate_targets_current_dependency_gap() -> None:
    children_source = inspect.getsource(evtx_nodes.ValueNode.children)
    assert "@memoize" not in children_source
    assert "get_variant_value" in children_source


def test_p2_32_profile_records_duplicate_decode_reduction() -> None:
    profile = _load()["development_profile"]
    stock = profile["stock_cprofile"]
    candidate = profile["memoized_value_node_cprofile"]
    assert stock["xml_digest_sha256"] == candidate["xml_digest_sha256"]
    assert candidate["value_node_children_calls"] < stock["value_node_children_calls"]
    assert candidate["get_variant_value_calls"] < stock["get_variant_value_calls"]
    assert profile["formal_benchmark"] is False
    assert profile["use_for_speedup_claim"] is False


def test_p2_32_spot_check_preserves_canonical_xml_digest() -> None:
    row = _load()
    expected = "892861e093f0ee24b48132eae32d897a6cb84b3e2cc338ce3c9a0013baa58c58"
    assert row["development_profile"]["stock_cprofile"]["xml_digest_sha256"] == expected
    assert row["development_5000_record_spot_check"]["xml_digest_sha256"] == expected
    assert row["claim_boundary"]["candidate_general_speedup"] == "NOT_ESTABLISHED"
    assert row["claim_boundary"]["statistical_benchmark"] is False


def test_p2_32_product_still_uses_stock_record_xml() -> None:
    source = (ROOT / "breachscope" / "ingest.py").read_text(encoding="utf-8")
    assert "_extract_from_xml(record.xml())" in source
    package_init = (ROOT / "breachscope" / "__init__.py").read_text(encoding="utf-8")
    assert "ValueNode.children" not in package_init
