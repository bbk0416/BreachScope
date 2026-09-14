from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
WORKFLOW = ROOT / ".github" / "workflows" / "p2_14e_final_blind_one_pass.yml"
RUNNER = ROOT / "scripts" / "p2_14e_one_pass_blind_score.py"


def test_p2_14e_workflow_is_manual_only_and_main_guarded():
    text = WORKFLOW.read_text(encoding="utf-8")
    assert "workflow_dispatch:" in text
    assert "\n  push:" not in text
    assert "\n  pull_request:" not in text
    assert "\n  schedule:" not in text
    assert "refs/heads/main" in text
    assert "RUN-P2-14E-CANONICAL-ONCE" in text
    assert "cancel-in-progress: false" in text


def test_p2_14e_uses_exact_frozen_detector_and_bound_corpus():
    workflow = WORKFLOW.read_text(encoding="utf-8")
    runner = RUNNER.read_text(encoding="utf-8")
    frozen = "13eb8f6ac93cf29817ca3ed885e8dc18b8fbb2fb"
    archive_sha = "99e0ca3dae2f7582d9757dfe41b4f1fb149b197fe3bb751613760087f2d68594"
    manifest_sha = "33ace64e0154e14698c462ae185c60acee54a3ee88023d0cb792d86cf76dcb5a"

    assert frozen in workflow
    assert frozen in runner
    assert archive_sha in runner
    assert manifest_sha in runner
    assert "BOUND_EVTX_FILE_COUNT = 278" in runner
    assert "BOUND_RECORD_COUNT = 37364" in runner
    assert "FROZEN_RULE_COUNT = 66" in runner


def test_p2_14e_has_exactly_one_detector_invocation_and_no_label_metrics():
    runner = RUNNER.read_text(encoding="utf-8")
    assert runner.count("apply_rules(events, rules)") == 1
    assert "load_labels" not in runner
    assert "confusion_from_flagged" not in runner
    assert '"precision":' not in runner
    assert '"recall":' not in runner
    assert '"false_positive_rate":' not in runner
    assert '"event_level_ground_truth": "NOT_AVAILABLE"' in runner
    assert '"production_precision": "NOT_CLAIMED"' in runner
    assert '"production_recall": "NOT_CLAIMED"' in runner
    assert '"production_false_positive_rate": "NOT_CLAIMED"' in runner


def test_p2_14e_canonical_outputs_match_frozen_contract():
    runner = RUNNER.read_text(encoding="utf-8")
    required = (
        '"corpus_identity"',
        '"detector_identity"',
        '"total_records"',
        '"parsed_records"',
        '"parse_errors"',
        '"findings"',
        '"flagged_events"',
        '"detected_rule_count"',
        '"findings_by_rule"',
        '"flagged_events_by_rule"',
        '"per_file_record_counts"',
        '"per_file_finding_counts"',
        '"canonical_result_sha256"',
        '"flagged_event_metadata"',
    )
    for field in required:
        assert field in runner
    assert "excluding canonical_result_sha256" in runner


def test_p2_14e_workflow_preserves_canonical_artifact():
    text = WORKFLOW.read_text(encoding="utf-8")
    assert "if: success()" in text
    assert "p2_14e_result.json" in text
    assert "p2_14e_result.file.sha256" in text
    assert "p2_14e_run_metadata.json" in text
    assert "p2-14e-final-blind-one-pass-result" in text
