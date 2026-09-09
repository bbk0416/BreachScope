from pathlib import Path

OLD_HASH = "af3b2db0fcef1a74a2728483a7db2b8df028f91be205448a03285a2a58ed960e"
NEW_HASH = "c8aab1fc9dfb54e634f4da12c81bbeb1693f3decef747b543a20bff6153a6409"


def patch_chain() -> None:
    path = Path("external_baseline/current_detection_evidence.yaml")
    text = path.read_text(encoding="utf-8")
    assert "current_evidence_id: p2-10f-current-detection-evidence" in text
    assert "p2-10g-hidden-run-key" not in text
    text = text.replace(
        "current_evidence_id: p2-10f-current-detection-evidence",
        "current_evidence_id: p2-10g-current-detection-evidence",
        1,
    )
    needle = (
        "- remediation_id: p2-10f-service-pathless-7045\n"
        "  measurement_record: external_baseline/results/p2_10f_851214ff/measurement.yaml\n"
    )
    replacement = needle + (
        "- remediation_id: p2-10g-hidden-run-key\n"
        "  measurement_record: external_baseline/results/p2_10g_ab76f3a3/measurement.yaml\n"
    )
    assert needle in text
    path.write_text(text.replace(needle, replacement, 1), encoding="utf-8")


def patch_verifier() -> None:
    path = Path("scripts/verify_current_detection_evidence.py")
    text = path.read_text(encoding="utf-8")
    assert '"p2-10g-hidden-run-key"' not in text
    marker = "\n}\n\n\ndef _verify_live_rule("
    assert marker in text
    spec = r'''
    "p2-10g-hidden-run-key": {
        "label": "P2-10G",
        "schema": "breachscope.p2_10g_remediation_measurement.v1",
        "rule_id": "R-RUNKEY-UNNAMED-13",
        "technique": "T1547.001",
        "severity": "medium",
        "primary": (
            "TargetObject",
            "regex",
            r"\\software\\microsoft\\windows\\currentversion\\run(?:once)?\\$",
        ),
        "conditions": {
            "EventType": ("equals", "SetValue"),
            "event_id": ("equals", "13"),
            "source": ("equals", "Microsoft-Windows-Sysmon"),
        },
        "predicate": {
            "TargetObject_regex": r"\\software\\microsoft\\windows\\currentversion\\run(?:once)?\\$",
            "EventType_equals": "SetValue",
            "event_id_equals": "13",
            "source_equals": "Microsoft-Windows-Sysmon",
        },
        "after_hits": 9,
        "misses": 1,
        "findings": 13,
        "flagged_events": 13,
        "changed_scenario": ("persist-hidden-run-key", "T1547.001"),
        "remaining_misses": ["lm-wmi"],
        "focused_tests": 8,
        "artifact_schema": "breachscope.external_holdout.result.v1",
        "benign_expected": {
            "corpus_total_events_from_p2_09d": 766623,
            "sysmon_records_scanned": 732200,
            "sysmon_chunks_scanned": 11894,
            "sysmon_event13_scanned": 214572,
            "sysmon_event13_setvalue_scanned": 214572,
            "run_or_runonce_targets": 18,
            "hidden_run_targets": 0,
            "exact_predicate_matches": 0,
            "parse_errors": 0,
            "fresh_full_fp_tn_rerun": False,
        },
        "summary": {
            "benign_scope": "pinned public benign Sysmon records",
            "benign_events_scanned": 732200,
            "benign_sysmon_records_scanned": 732200,
            "benign_sysmon_chunks_scanned": 11894,
            "benign_sysmon_event13_scanned": 214572,
            "benign_run_or_runonce_targets": 18,
            "benign_hidden_run_targets": 0,
            "benign_exact_predicate_matches": 0,
            "benign_parse_errors": 0,
        },
    },
'''
    path.write_text(text.replace(marker, "\n" + spec + marker, 1), encoding="utf-8")


def patch_tests() -> None:
    path = Path("tests/test_reproducible_benchmark.py")
    text = path.read_text(encoding="utf-8")
    assert NEW_HASH not in text
    text = text.replace(OLD_HASH, NEW_HASH)
    text = text.replace(
        'assert data["current_attack_scenario_hits"] == 8',
        'assert data["current_attack_scenario_hits"] == 9',
        1,
    )
    text = text.replace(
        'assert len(data["remediations"]) == 6',
        'assert len(data["remediations"]) == 7',
        1,
    )
    p2f_tail = '    assert p2_10f["fresh_full_benign_fpr_for_new_rulepack"] == "NOT_CLAIMED"\n'
    assert text.count(p2f_tail) == 1
    p2g_block = '''

    p2_10g = data["remediations"][6]
    assert p2_10g["remediation_id"] == "p2-10g-hidden-run-key"
    assert p2_10g["attack_scenario_hits_before"] == 8
    assert p2_10g["attack_scenario_hits_after"] == 9
    assert p2_10g["benign_events_scanned"] == 732200
    assert p2_10g["benign_sysmon_records_scanned"] == 732200
    assert p2_10g["benign_sysmon_chunks_scanned"] == 11894
    assert p2_10g["benign_sysmon_event13_scanned"] == 214572
    assert p2_10g["benign_run_or_runonce_targets"] == 18
    assert p2_10g["benign_hidden_run_targets"] == 0
    assert p2_10g["benign_exact_predicate_matches"] == 0
    assert p2_10g["benign_parse_errors"] == 0
    assert p2_10g["fresh_full_benign_fpr_for_new_rulepack"] == "NOT_CLAIMED"
'''
    text = text.replace(p2f_tail, p2f_tail + p2g_block, 1)
    text = text.replace(
        'assert data["current_evidence_id"] == "p2-10f-current-detection-evidence"',
        'assert data["current_evidence_id"] == "p2-10g-current-detection-evidence"',
        1,
    )
    list_needle = '        "p2-10f-service-pathless-7045",\n'
    assert text.count(list_needle) == 1
    text = text.replace(list_needle, list_needle + '        "p2-10g-hidden-run-key",\n', 1)
    path.write_text(text, encoding="utf-8")


def write_measurement() -> None:
    out = Path("external_baseline/results/p2_10g_ab76f3a3")
    out.mkdir(parents=True, exist_ok=True)
    text = r'''schema: breachscope.p2_10g_remediation_measurement.v1
remediation_id: p2-10g-hidden-run-key
measurement_repo_commit: ab76f3a3f41f505ae6c5e73a2dd28bea5562006a
from_rules_tree_sha256: af3b2db0fcef1a74a2728483a7db2b8df028f91be205448a03285a2a58ed960e
to_rules_tree_sha256: c8aab1fc9dfb54e634f4da12c81bbeb1693f3decef747b543a20bff6153a6409
rule_change:
  rule_file: rules/p2_10_event_rules.yml
  rule_id: R-RUNKEY-UNNAMED-13
  name: Hidden Run/RunOnce Registry Value
  severity: medium
  mitre_technique: T1547.001
  predicate:
    TargetObject_regex: '\\software\\microsoft\\windows\\currentversion\\run(?:once)?\\$'
    EventType_equals: SetValue
    event_id_equals: '13'
    source_equals: Microsoft-Windows-Sysmon
attack_external_baseline:
  baseline_id: p2-09c-evtx-attack-samples-v1
  corpus_manifest_sha256: 91fc5c2d719e2d3255fd8164485d763e49e05ee3bd420b0cd0cceda6b926b21d
  labels_sha256: f3b3386978b2e9f8d8650d229c2b9b7e9754dc0fa1b21bda2baf6f68964cf532
  source_files: 10
  events: 202
  before_scenario_hits: 8
  after_scenario_hits: 9
  scenario_misses: 1
  scenario_total: 10
  after_scenario_hit_rate: 0.9
  findings: 13
  flagged_events: 13
  changed_scenario:
    scenario_id: persist-hidden-run-key
    expected_technique: T1547.001
    before_status: miss
    after_status: hit
  remaining_miss_scenarios:
  - lm-wmi
benign_incremental_match_proof:
  baseline_id: p2-09d-nextron-win10-v1
  corpus_sha256: d48f1b328d48db6c6dfaa9b6e232dbb454d93e833c6e1248efc0faf690b6808e
  corpus_total_events_from_p2_09d: 766623
  evtx_files_total_from_p2_09d: 352
  sysmon_source_evtx_files_scanned: 1
  sysmon_records_scanned: 732200
  sysmon_chunks_scanned: 11894
  sysmon_chunks_covered: '0:11894'
  shard_count: 32
  sysmon_event13_scanned: 214572
  sysmon_event13_setvalue_scanned: 214572
  run_or_runonce_targets: 18
  hidden_run_targets: 0
  exact_predicate_matches: 0
  parse_errors: 0
  probe_github_actions_run_id: 34378996152
  probe_commit: 3b91e449b17d0f806d12d29f8c7798294856b5b9
  probe_artifact_id: 10115267079
  probe_artifact_digest_sha256: b44ce8fb3c50da7440b6dcaa6a5c22f408a9650db02cfe63e21ddf3a0df2a39d
  probe_artifact_schema: breachscope.p2_10g.hidden_run_benign_scan.v1
  parser: python-evtx 0.8.1 plus BreachScope EVTX extraction path
  fresh_full_fp_tn_rerun: false
measurement_execution:
  github_actions_run_id: 34380826293
  artifact_id: 10115782747
  artifact_digest_sha256: 931290c4da70d2b7ab93a0b45ef89bff1bd84d17c221be84c82bd0aab9cf7fa5
  artifact_record_schema: breachscope.external_holdout.result.v1
  focused_tests_passed: 8
  detector_runtime_seconds: 0.09567232900000988
  detector_peak_memory_mb: 0.17587661743164062
exact_source:
  pr_code_commit: 72dbd296265e992321378512b3688f120b32681a
  measurement_commit: ab76f3a3f41f505ae6c5e73a2dd28bea5562006a
  rule_file_git_blob_sha1: f867662a28f283ead51f26feffa9a7975d71f66c
  note: The measurement commit and the PR code commit have identical detector/rule content. The later PR commit only corrected Python test-string syntax.
claim_boundary:
  public_known_attack_corpus: true
  final_blind_holdout: false
  production_detection_rate: NOT_CLAIMED
  production_false_positive_rate: NOT_CLAIMED
  fresh_full_benign_fpr_for_new_rulepack: NOT_CLAIMED
  incremental_benign_statement: No Sysmon Event ID 13 SetValue whose TargetObject ended directly at a Run or RunOnce key was observed in the 732,200 Sysmon records from the pinned public benign corpus.
'''
    (out / "measurement.yaml").write_text(text, encoding="utf-8")


def write_doc() -> None:
    text = r'''# P2-10G Hidden Run/RunOnce Value Remediation

## 왜 이 항목을 고쳤는가

P2-10F 이후 고정 외부 공격 baseline은 **8 HIT / 2 MISS / 10 scenario**였습니다.
남은 MISS 중 `persist-hidden-run-key`의 기대 technique은 `T1547.001`입니다.

공개 공격 샘플의 실제 관련 필드는 다음과 같습니다.

```text
source: Microsoft-Windows-Sysmon
event_id: 13
EventType: SetValue
TargetObject: HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run\
```

`RuleName`, 프로세스 경로, 실행 파일 이름, `Details` 값은 룰 조건에 넣지 않았습니다.
특정 샘플 문자열이 아니라 **Run/RunOnce 키 경로 자체에서 끝나는 SetValue**만 사용했습니다.

## 변경

`R-RUNKEY-UNNAMED-13`을 추가했습니다.
조건은 Sysmon Event 13 + `SetValue` + `TargetObject`가 `CurrentVersion\Run\` 또는 `RunOnce\`에서 바로 끝나는 경우입니다.
ATT&CK은 `T1547.001`, severity는 `medium`입니다.
`...\Run\Updater`처럼 값 이름이 있는 일반 변경은 이 룰에 맞지 않습니다.

## 공격 baseline 재측정

```text
PR code commit: 72dbd296265e992321378512b3688f120b32681a
measurement commit: ab76f3a3f41f505ae6c5e73a2dd28bea5562006a
run: 34380826293
artifact ID: 10115782747
artifact ZIP SHA-256: 931290c4da70d2b7ab93a0b45ef89bff1bd84d17c221be84c82bd0aab9cf7fa5
rule tree SHA-256: c8aab1fc9dfb54e634f4da12c81bbeb1693f3decef747b543a20bff6153a6409
```

- before: **8 HIT / 2 MISS / 10**
- after: **9 HIT / 1 MISS / 10**
- rules: **59**
- findings / flagged events: **13 / 13**
- `persist-hidden-run-key`: **MISS → HIT**
- expected/observed technique: `T1547.001`
- focused tests: **8 PASS**

## benign incremental 확인

P2-09D pinned public benign corpus의 Sysmon 원본 전체를 신규 predicate 관점에서 다시 확인했습니다.

- corpus SHA-256: `d48f1b328d48db6c6dfaa9b6e232dbb454d93e833c6e1248efc0faf690b6808e`
- corpus 전체 EVTX 파일 수(P2-09D 기록): **352**
- 이번 신규 scan 대상: Sysmon EVTX **1 file**
- Sysmon records: **732,200**
- chunks: **11,894**, `0:11894` 전체 커버
- Sysmon Event 13: **214,572**
- Run/RunOnce targets: **18**
- unnamed/hidden targets: **0**
- exact predicate matches: **0**
- parse errors: **0**
- benign scan run: `34378996152`
- aggregate artifact: `10115267079`

이는 pinned public benign Sysmon records에서의 **incremental exact-match 관찰값**입니다.
production false positive rate가 0이라는 뜻이 아니며, 현재 59-rule pack의 fresh full benign FPR도 아닙니다.

## 현재 상태

```text
P2-09E 2/10 -> P2-10A 3/10 -> P2-10B 4/10 -> P2-10C 5/10
-> P2-10D 6/10 -> P2-10E 7/10 -> P2-10F 8/10 -> P2-10G 9/10
```

남은 MISS는 `lm-wmi` 하나입니다.

## 말할 수 없는 것

이번 결과로 실제 공격 탐지율 90%, production precision/recall/FPR, 현재 rulepack의 fresh full benign FPR, 기업 환경 대표성, final blind holdout 통과를 주장하지 않습니다.
공격 corpus는 알려진 공개 corpus이며 final blind holdout이 아닙니다.
P2-09D의 `FPR=0.00221752%`는 역사적 rule tree `543b4e02...`에만 적용됩니다.
'''
    Path("docs/P2_10G_HIDDEN_RUN_KEY_REMEDIATION.md").write_text(text, encoding="utf-8")


def main() -> None:
    patch_chain()
    patch_verifier()
    patch_tests()
    write_measurement()
    write_doc()


if __name__ == "__main__":
    main()
