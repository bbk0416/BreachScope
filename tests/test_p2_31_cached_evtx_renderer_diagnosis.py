from __future__ import annotations

import inspect
from pathlib import Path

import yaml
from Evtx import Nodes as evtx_nodes


ROOT = Path(__file__).resolve().parents[1]
RECORD = ROOT / "performance" / "p2_31_cached_evtx_renderer_diagnosis.yaml"


def _load() -> dict:
    return yaml.safe_load(RECORD.read_text(encoding="utf-8"))


def test_p2_31_closes_without_product_change() -> None:
    row = _load()
    assert row["status"] == "CLOSE_POSTHOC_NO_CHANGE"
    decision = row["decision"]
    assert decision["merge_cached_renderer"] == "NO"
    assert decision["product_code_change"] is False
    assert decision["preserve_current_ingest_call"] == "_extract_from_xml(record.xml())"
    assert decision["p2_30b_result_modified"] is False
    assert decision["rerun_p2_30b"] is False
    assert decision["general_speedup_claim"] == "NOT_CLAIMED"


def test_p2_31_current_product_still_uses_stock_record_xml() -> None:
    source = (ROOT / "breachscope" / "ingest.py").read_text(encoding="utf-8")
    assert "_extract_from_xml(record.xml())" in source
    assert "render_record_xml" not in source
    assert not (ROOT / "breachscope" / "evtx_renderer.py").exists()


def test_p2_31_dependency_is_locked_to_python_evtx_0_8_1() -> None:
    for name in (
        "requirements-lock-py310.txt",
        "requirements-lock-py311.txt",
        "requirements-lock-py312.txt",
    ):
        text = (ROOT / name).read_text(encoding="utf-8")
        assert "python-evtx==0.8.1" in text


def test_p2_31_target_methods_are_already_memoized() -> None:
    tag_source = inspect.getsource(evtx_nodes.OpenStartElementNode.tag_name)
    children_source = inspect.getsource(evtx_nodes.OpenStartElementNode.children)
    assert "@memoize" in tag_source
    assert "@memoize" in children_source


def test_p2_31_development_probe_is_exact_and_non_formal() -> None:
    probe = _load()["development_probe"]
    assert probe["records"] == 5000
    assert probe["mismatches"] == 0
    assert probe["stock_xml_digest_sha256"] == (
        "892861e093f0ee24b48132eae32d897a6cb84b3e2cc338ce3c9a0013baa58c58"
    )
    assert probe["cached_xml_digest_sha256"] == probe["stock_xml_digest_sha256"]
    assert probe["stock_seconds"] == 64.83765399851836
    assert probe["cached_seconds"] == 64.62745509820525
    assert probe["stock_over_cached_ratio"] == 1.0032524706410566
    assert probe["cached_change_percent"] == -0.32419263707153867
    assert probe["formal_benchmark"] is False
    assert probe["use_for_speedup_claim"] is False


def test_p2_31_does_not_turn_probe_into_performance_claim() -> None:
    claim = _load()["claim_boundary"]
    assert claim["cached_renderer_speedup"] == "NOT_ESTABLISHED"
    assert claim["candidate_semantic_equivalence"] == (
        "OBSERVED_ON_PINNED_5000_RECORD_DEVELOPMENT_PROBE"
    )
    assert claim["production_capacity"] == "NOT_CLAIMED"
    assert claim["statistical_benchmark"] is False
    assert claim["detection_accuracy"] == "NOT_EVALUATED"
    assert claim["benign_fpr"] == "NOT_EVALUATED"
