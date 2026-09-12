from __future__ import annotations

from pathlib import Path
import yaml

ROOT = Path(__file__).resolve().parents[1]
BINDING = ROOT / 'external_baseline' / 'p2_12b_apt29_day1_binding.yaml'


def _load():
    return yaml.safe_load(BINDING.read_text(encoding='utf-8'))


def test_p2_12b_bytes_and_detector_are_frozen_before_scoring() -> None:
    d = _load()
    assert d['schema'] == 'breachscope.p2_12b_fresh_external_binding.v1'
    assert d['frozen_detector'] == {
        'repo_commit': '13eb8f6ac93cf29817ca3ed885e8dc18b8fbb2fb',
        'rules_tree_sha256': '9f823a189530528a47b11c5519b02dc9b97473b8c0f6a8e0c13e1ed8d04b5e92',
        'rule_count': 66,
    }
    src = d['source_binding']
    assert src['archive_sha256'] == '98a073140860560d70080ace9142961be4f64b4862bae892d62d0f254d0fdbe5'
    assert src['archive_size_bytes'] == 13944973
    assert src['zip_entry_count'] == 1
    assert src['total_uncompressed_bytes'] == 385334029
    assert src['payload_name'] == 'apt29_evals_day1_manual_2020-05-01225525.json'


def test_p2_12b_source_labels_and_v19_2_denominator_are_frozen() -> None:
    d = _load()
    plan = d['emulation_plan_binding']
    attack = d['attack_version_binding']
    assert plan['sha256'] == '053e70c6ba95eac481b370f8b1545ec3f1f00306c828634741a8c7399719c228'
    assert plan['day1_source_technique_count'] == 45
    assert len(plan['day1_source_techniques']) == 45
    assert attack['release'] == 'Enterprise ATT&CK v19.2'
    assert attack['pinned_commit'] == '6cda5ad8462c79e14fbb872f4e09059b18e0cfc4'
    assert attack['active_exact_id_count'] == 27
    assert len(attack['active_exact_ids']) == 27
    assert attack['inactive_exact_id_count'] == 18
    assert len(attack['inactive_exact_ids']) == 18
    assert attack['missing_exact_id_count'] == 0
    assert set(attack['active_exact_ids']).isdisjoint(attack['inactive_exact_ids'])
    assert set(attack['active_exact_ids']) | set(attack['inactive_exact_ids']) == set(plan['day1_source_techniques'])


def test_p2_12b_scoring_contract_is_precommitted_without_results() -> None:
    d = _load()
    score = d['scoring_contract']
    state = d['protocol_state']
    claims = d['claim_boundary']
    assert score['primary_metric'] == 'active_technique_coverage'
    assert score['denominator'] == 27
    assert score['inactive_legacy_ids'] == 'REPORT_SEPARATELY_NOT_SILENTLY_REMAPPED'
    assert score['event_level_precision'] == 'NOT_CLAIMED'
    assert score['event_level_recall'] == 'NOT_CLAIMED'
    assert score['event_level_false_positive_rate'] == 'NOT_CLAIMED'
    assert state['selection_committed_before_archive_download'] is True
    assert state['archive_bytes_bound_before_detection'] is True
    assert state['expected_labels_bound_before_detection'] is True
    assert state['attack_version_and_denominator_bound_before_detection'] is True
    assert state['detector_executed_on_selected_archive'] is False
    assert state['detector_results_viewed'] is False
    assert state['day2_reserved_unseen'] is True
    assert state['tuning_before_first_score_forbidden'] is True
    assert claims['fresh_external_holdout_result'] == 'NOT_YET_MEASURED'
    assert claims['compound_technique_coverage'] == 'NOT_YET_MEASURED'
