from pathlib import Path

import yaml


ROOT = Path(__file__).resolve().parents[1]
RECORD = ROOT / "external_baseline" / "p2_14b_final_blind_holdout_selection.yaml"


def test_p2_14b_selection_is_byte_bound_without_scoring() -> None:
    data = yaml.safe_load(RECORD.read_text(encoding="utf-8"))

    assert data["schema"] == "breachscope.p2_14b_final_blind_holdout_selection.v1"
    assert data["selection_status"] == "SELECTED_AND_BYTE_BOUND"
    assert data["selection_basis"]["detector_outcomes_inspected_before_selection"] is False

    corpus = data["selected_corpus"]
    assert corpus["repository"] == "sbousseaden/EVTX-ATTACK-SAMPLES"
    assert corpus["source_commit"] == "4ceed2f4706daf601c212a8f91c113dd85349a2c"
    assert corpus["archive_size_bytes"] == 6053609
    assert corpus["archive_sha256"] == "99e0ca3dae2f7582d9757dfe41b4f1fb149b197fe3bb751613760087f2d68594"
    assert corpus["evtx_file_count"] == 278
    assert corpus["sorted_evtx_path_manifest_sha256"] == "33ace64e0154e14698c462ae185c60acee54a3ee88023d0cb792d86cf76dcb5a"

    execution = data["binding_execution"]
    assert execution["github_actions_run_id"] == 34769408395
    assert execution["artifact_id"] == 10321975153
    assert execution["artifact_digest_sha256"] == "e9c800de247471c893f4c5ddc2a19107eb74f910097fb2aa48ff9f37bae7844b"
    assert execution["detector_executed"] is False
    assert execution["scoring_performed"] is False

    claims = data["claim_boundary"]
    assert claims["final_blind_holdout"] is False
    assert claims["event_level_ground_truth"] == "NOT_AVAILABLE"
    for key in (
        "production_accuracy",
        "production_detection_rate",
        "production_precision",
        "production_recall",
        "production_false_positive_rate",
    ):
        assert claims[key] == "NOT_CLAIMED"
