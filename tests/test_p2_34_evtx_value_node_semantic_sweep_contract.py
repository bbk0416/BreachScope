from __future__ import annotations

import hashlib
from pathlib import Path

import yaml


ROOT = Path(__file__).resolve().parents[1]
CONTRACT = ROOT / "performance" / "p2_34_evtx_value_node_semantic_sweep_contract.yaml"
RUNNER = ROOT / "scripts" / "p2_34_evtx_value_node_semantic_sweep.py"
P2_33 = ROOT / "performance" / "p2_33_evtx_value_node_memo_result.yaml"


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _load() -> dict:
    return yaml.safe_load(CONTRACT.read_text(encoding="utf-8"))


def test_p2_34_is_preregistered_before_canonical_execution() -> None:
    row = _load()
    assert row["benchmark_id"] == (
        "p2-34-windows-evtx-value-node-semantic-sweep-v1"
    )
    assert row["status"] == "PREREGISTERED_BEFORE_CANONICAL_EXECUTION"
    assert row["measurement"]["purpose"] == "semantic_equivalence_only"
    assert row["predecessor"]["phase"] == "P2-33"
    assert row["predecessor"]["status"] == "COMPLETED"
    assert row["predecessor"]["product_adoption"] == "NOT_DECIDED"


def test_p2_34_runner_and_predecessor_hashes_are_frozen() -> None:
    row = _load()
    assert row["runner"]["sha256"] == _sha256(RUNNER)
    assert row["runner"]["sha256"] == (
        "e30620f3dca7f95c11b3305ce11600e8a3e299a95bfac295c24a267e6d9936e3"
    )
    assert row["predecessor"]["result_sha256"] == _sha256(P2_33)
    assert row["predecessor"]["result_sha256"] == (
        "35768c31be9fbbcbeb7a1c7d3c7440ad06e999473d20c0ef77a8e6d514ce62f8"
    )


def test_p2_34_dependency_candidate_is_identical_to_p2_33() -> None:
    dep = _load()["dependency"]
    assert dep["package"] == "python-evtx"
    assert dep["version"] == "0.8.1"
    assert dep["nodes_py_sha256"] == (
        "a1b8ce8de6219ff54af9e65a0aacf70f5167567c6036225f355cfc2063cbcaeb"
    )
    assert dep["value_node_children_source_sha256"] == (
        "7dd92b06690a1ec1a16658551ba54a65a15496c21c047eb5646e460c84e50533"
    )
    candidate = dep["candidate"]
    assert candidate["identical_to_p2_33_candidate"] is True
    assert candidate["product_monkey_patch"] is False
    assert candidate["fork_created"] is False
    assert candidate["vendor_copy_created"] is False


def test_p2_34_pins_archive_and_all_352_extracted_files() -> None:
    row = _load()
    source = row["source"]
    assert source["archive"]["size_bytes"] == 70_844_052
    assert source["archive"]["sha256"] == (
        "d48f1b328d48db6c6dfaa9b6e232dbb454d93e833c6e1248efc0faf690b6808e"
    )
    corpus = source["extracted_corpus"]
    assert corpus["file_count"] == 352
    assert corpus["total_bytes"] == 876_675_072
    assert corpus["path_size_manifest_sha256"] == (
        "a9b870148219041b787cc1f8e4e7ca1fc2f543c11c45b91e7d51d5c84271fc6e"
    )


def test_p2_34_measurement_is_breadth_first_semantic_gate() -> None:
    row = _load()
    measurement = row["measurement"]
    assert measurement["file_selection"] == "ALL_352_SORTED_EVTX_FILES"
    assert measurement["records_per_file"] == 25
    assert measurement["record_selection"] == "FIRST_UP_TO_25_RECORDS_PER_FILE"
    assert measurement["all_records_when_file_has_fewer_than_limit"] is True
    assert measurement["fresh_child_process_each_variant"] is True
    assert measurement["variant_order"] == ["stock", "candidate"]
    assert measurement["require_exact_semantic_projection_match"] is True
    assert measurement["performance_comparison_allowed"] is False
    assert measurement["detection_stage_executed"] is False
    assert measurement["breachscope_event_parser_executed"] is False


def test_p2_34_runner_uses_exact_candidate_and_projection_comparison() -> None:
    source = RUNNER.read_text(encoding="utf-8")
    assert (
        "nodes.ValueNode.children = nodes.memoize(nodes.ValueNode.children)"
        in source
    )
    assert "stock_projection != candidate_projection" in source
    assert 'corpus_dir.rglob("*.evtx")' in source
    assert "elapsed_seconds_descriptive_only" in source


def test_p2_34_protocol_is_one_pass_and_fail_closed() -> None:
    row = _load()
    protocol = row["protocol"]
    assert protocol["contract_must_merge_before_canonical_execution"] is True
    assert protocol["permanent_lock_required"] is True
    assert protocol["duplicate_canonical_execution_allowed"] is False
    assert protocol["first_completed_or_failed_execution_is_canonical"] is True
    assert protocol["replace_result_for_better_outcome"] is False
    assert protocol["product_code_change_before_result"] is False
    assert protocol["product_code_change_as_part_of_gate"] is False

    decision = row["decision_rule"]
    assert decision["any_semantic_mismatch_rejects_candidate_for_product_adoption"] is True
    assert (
        decision["exact_semantic_match_is_required_but_not_sufficient_for_product_adoption"]
        is True
    )
    assert decision["passing_gate_does_not_auto_authorize_product_patch"] is True
    assert decision["performance_result_from_this_gate_must_not_be_used_for_speed_claim"] is True


def test_p2_34_claim_boundary_remains_narrow() -> None:
    claim = _load()["claim_boundary"]
    assert claim["semantic_equivalence_scope"] == "NOT_YET_MEASURED"
    assert claim["all_records_semantic_equivalence"] == "NOT_EVALUATED"
    assert claim["performance_comparison"] == "NOT_EVALUATED"
    assert claim["candidate_general_speedup"] == "NOT_CLAIMED"
    assert claim["product_adoption"] == "NOT_DECIDED"
    assert claim["statistical_benchmark"] is False
