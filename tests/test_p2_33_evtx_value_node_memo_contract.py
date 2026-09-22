from __future__ import annotations

import hashlib
import inspect
from pathlib import Path

import yaml
from Evtx import Nodes as evtx_nodes


ROOT = Path(__file__).resolve().parents[1]
CONTRACT = ROOT / "performance" / "p2_33_evtx_value_node_memo_contract.yaml"
RUNNER = ROOT / "scripts" / "p2_33_evtx_value_node_memo_benchmark.py"
P2_32 = ROOT / "performance" / "p2_32_evtx_value_node_profile_diagnosis.yaml"


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _load() -> dict:
    return yaml.safe_load(CONTRACT.read_text(encoding="utf-8"))


def test_p2_33_is_preregistered_before_canonical_execution() -> None:
    row = _load()
    assert row["benchmark_id"] == "p2-33-windows-evtx-value-node-memo-v1"
    assert row["status"] == "PREREGISTERED_BEFORE_CANONICAL_EXECUTION"
    assert row["predecessor"]["phase"] == "P2-32"
    assert row["predecessor"]["status"] == "CLOSE_POSTHOC_CANDIDATE_IDENTIFIED"
    assert row["predecessor"]["predecessor_result_modified"] is False


def test_p2_33_runner_hash_is_frozen() -> None:
    row = _load()
    assert row["runner"]["sha256"] == _sha256(RUNNER)
    assert row["runner"]["sha256"] == (
        "14c9be2f0163c8b0fb1d5250622c4c06982cf87ca43cbef164e7bc96dc26d1fd"
    )
    assert row["runner"]["lock_file"] == "P2_33_ONE_PASS.lock"


def test_p2_33_dependency_identity_and_gap_are_frozen() -> None:
    row = _load()
    dep = row["dependency"]
    assert dep["package"] == "python-evtx"
    assert dep["version"] == "0.8.1"
    assert dep["nodes_py_sha256"] == (
        "a1b8ce8de6219ff54af9e65a0aacf70f5167567c6036225f355cfc2063cbcaeb"
    )
    assert dep["value_node_children_source_sha256"] == (
        "7dd92b06690a1ec1a16658551ba54a65a15496c21c047eb5646e460c84e50533"
    )
    source = inspect.getsource(evtx_nodes.ValueNode.children)
    assert "@memoize" not in source
    assert "get_variant_value" in source
    assert dep["candidate"]["product_monkey_patch"] is False


def test_p2_33_measurement_order_and_accounting_are_fixed() -> None:
    row = _load()
    measurement = row["measurement"]
    assert measurement["record_limit"] == 5000
    assert measurement["repetitions_per_variant"] == 5
    assert measurement["variant_order"] == [
        ["stock", "candidate"],
        ["candidate", "stock"],
        ["stock", "candidate"],
        ["candidate", "stock"],
        ["stock", "candidate"],
    ]
    assert measurement["fresh_child_process_each_variant_run"] is True
    assert measurement["require_identical_xml_digest_across_all_runs"] is True
    assert measurement["primary_summary"] == {
        "statistic": "median",
        "inferential_statistics": False,
    }
    gate = row["accounting_gate"]
    assert gate["exact_records_per_run"] == 5000
    assert gate["xml_digest_must_match_across_stock_and_candidate_runs"] is True


def test_p2_33_source_and_cache_boundary_match_pinned_diagnostic_corpus() -> None:
    row = _load()
    source = row["source"]
    assert source["size_bytes"] == 799_084_544
    assert source["sha256"] == (
        "efbc4d4cd450eddf7665f5965b0f6cfe30088f8f69225886e1d433329fb950cb"
    )
    assert source["record_subset"] == "FIRST_5000_RECORDS"
    cache = row["cache_policy"]
    assert cache["true_cold_os_cache"] == "NOT_MEASURED"
    assert cache["between_run_os_cache_state"] == "UNCONTROLLED"
    assert cache["cold_cache_speed_claim"] == "NOT_CLAIMED"


def test_p2_33_protocol_is_one_pass_and_does_not_authorize_product_patch() -> None:
    row = _load()
    protocol = row["protocol"]
    assert protocol["contract_must_merge_before_canonical_execution"] is True
    assert protocol["permanent_lock_required"] is True
    assert protocol["duplicate_canonical_execution_allowed"] is False
    assert protocol["first_completed_or_failed_execution_is_canonical"] is True
    assert protocol["replace_result_for_better_numbers"] is False
    assert protocol["product_code_change_before_result"] is False
    assert protocol["product_code_change_as_part_of_benchmark"] is False
    decision = row["decision_rule"]
    assert decision["semantic_equivalence_required_before_any_performance_interpretation"] is True
    assert decision["benchmark_outcome_does_not_auto_authorize_product_patch"] is True


def test_p2_33_claim_boundary_remains_narrow() -> None:
    claim = _load()["claim_boundary"]
    assert claim["candidate_comparison"] == "NOT_YET_MEASURED"
    assert claim["candidate_general_speedup"] == "NOT_ESTABLISHED"
    assert claim["true_cold_cache_performance"] == "NOT_MEASURED"
    assert claim["general_full_pipeline_speedup"] == "NOT_CLAIMED"
    assert claim["statistical_benchmark"] is False


def test_p2_33_does_not_modify_p2_32_diagnosis_contract() -> None:
    p2_32 = yaml.safe_load(P2_32.read_text(encoding="utf-8"))
    assert p2_32["status"] == "CLOSE_POSTHOC_CANDIDATE_IDENTIFIED"
    assert p2_32["decision"]["product_code_change"] is False
    assert p2_32["claim_boundary"]["candidate_general_speedup"] == "NOT_ESTABLISHED"
