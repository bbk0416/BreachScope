#!/usr/bin/env python3
from pathlib import Path

OLD_HASH = "c8aab1fc9dfb54e634f4da12c81bbeb1693f3decef747b543a20bff6153a6409"
NEW_HASH = "371e73c4447cbce853dbdf936bdc40141bb4b0b496c11bcd63c41f8c42d0969f"
REMEDIATION_ID = "p2-10h-wmi-4688-parent-correlation"
ANALYZER_BLOB = "f7e395ba66d3461ffed0a4c9b5b37f86ae585ff7"

# 1) Current evidence chain.
chain_path = Path("external_baseline/current_detection_evidence.yaml")
chain = chain_path.read_text(encoding="utf-8")
assert "current_evidence_id: p2-10g-current-detection-evidence" in chain
assert REMEDIATION_ID not in chain
chain = chain.replace(
    "current_evidence_id: p2-10g-current-detection-evidence",
    "current_evidence_id: p2-10h-current-detection-evidence",
    1,
)
needle = (
    "- remediation_id: p2-10g-hidden-run-key\n"
    "  measurement_record: external_baseline/results/p2_10g_ab76f3a3/measurement.yaml\n"
)
assert needle in chain
chain = chain.replace(
    needle,
    needle
    + "- remediation_id: p2-10h-wmi-4688-parent-correlation\n"
      "  measurement_record: external_baseline/results/p2_10h_652b7cad/measurement.yaml\n",
    1,
)
chain_path.write_text(chain, encoding="utf-8", newline="\n")

# 2) Current evidence verifier: bind P2-10H to both live rule semantics and analyzer blob.
verifier_path = Path("scripts/verify_current_detection_evidence.py")
verifier = verifier_path.read_text(encoding="utf-8")
assert REMEDIATION_ID not in verifier
assert "import hashlib\n" not in verifier
verifier = verifier.replace("import argparse\nimport json\n", "import argparse\nimport hashlib\nimport json\n", 1)

execution_marker = "\ndef _verify_execution(\n"
assert execution_marker in verifier
blob_helper = '''\ndef _git_blob_sha1(path: Path) -> str:\n    data = path.read_bytes()\n    header = f"blob {len(data)}".encode("ascii") + bytes([0])\n    return hashlib.sha1(header + data).hexdigest()\n\n\n'''
verifier = verifier.replace(execution_marker, blob_helper + execution_marker, 1)

spec_marker = "\n}\n\n\ndef _verify_live_rule("
assert spec_marker in verifier
spec = r'''
    "p2-10h-wmi-4688-parent-correlation": {
        "label": "P2-10H",
        "schema": "breachscope.p2_10h_remediation_measurement.v1",
        "rule_id": "R-WMI-WMIPRVSE-CHILD-4688",
        "technique": "T1047",
        "severity": "medium",
        "primary": (
            "_breachscope.resolved_security_4688_parent_process_name",
            "endswith",
            r"\wbem\WmiPrvSE.exe",
        ),
        "conditions": {
            "event_id": ("equals", "4688"),
            "source": ("equals", "Microsoft-Windows-Security-Auditing"),
        },
        "predicate": {
            "resolved_parent_endswith": r"\wbem\WmiPrvSE.exe",
            "event_id_equals": "4688",
            "source_equals": "Microsoft-Windows-Security-Auditing",
        },
        "engine_expected": {
            "kind": "security_4688_parent_pid_correlation",
            "parent_window_seconds": 300,
            "same_host_required": True,
            "forward_only": True,
            "parent_pid_field": "ProcessId",
            "new_pid_field": "NewProcessId",
            "new_process_name_field": "NewProcessName",
            "derived_parent_field": "_breachscope.resolved_security_4688_parent_process_name",
            "parallel_pre_enrichment_before_chunking": True,
        },
        "analyzer_file": "breachscope/analyzer.py",
        "analyzer_blob_sha1": "f7e395ba66d3461ffed0a4c9b5b37f86ae585ff7",
        "after_hits": 10,
        "misses": 0,
        "findings": 14,
        "flagged_events": 14,
        "changed_scenario": ("lm-wmi", "T1047"),
        "remaining_misses": [],
        "focused_tests": 8,
        "artifact_schema": "breachscope.external_holdout.result.v1",
        "benign_expected": {
            "corpus_total_events_from_p2_09d": 766623,
            "evtx_files_total": 352,
            "non_sysmon_source_files_scanned": 351,
            "non_sysmon_events_scanned": 34423,
            "security_4688": 78,
            "parent_pid_resolved_within_300s": 64,
            "wmiprvse_parent_children_broad": 0,
            "wmiprvse_parent_children_wbem": 0,
            "exact_predicate_matches": 0,
            "parse_errors": 0,
            "timestamp_parse_errors_4688": 0,
            "fresh_full_fp_tn_rerun": False,
        },
        "summary": {
            "benign_scope": "pinned public benign non-Sysmon events",
            "benign_events_scanned": 34423,
            "benign_non_sysmon_events_scanned": 34423,
            "benign_security_4688": 78,
            "benign_parent_pid_resolved_within_300s": 64,
            "benign_wmiprvse_parent_children_wbem": 0,
            "benign_exact_predicate_matches": 0,
            "benign_parse_errors": 0,
            "analyzer_git_blob_sha1": "f7e395ba66d3461ffed0a4c9b5b37f86ae585ff7",
        },
    },
'''
verifier = verifier.replace(spec_marker, "\n" + spec + spec_marker, 1)

verify_rule_line = "    _verify_live_rule(repo, change, spec, label)\n"
assert verifier.count(verify_rule_line) == 1
engine_check = r'''

    if "engine_expected" in spec:
        engine = _mapping(record.get("engine_change"), f"{label} engine_change")
        for key, expected in _mapping(spec["engine_expected"], f"{label} engine spec").items():
            _require(engine.get(key), expected, f"{label} engine {key}")

        exact_source = _mapping(record.get("exact_source"), f"{label} exact_source")
        analyzer_file = str(spec["analyzer_file"])
        analyzer_blob = str(spec["analyzer_blob_sha1"])
        _require(exact_source.get("analyzer_file"), analyzer_file, f"{label} analyzer file")
        _require(
            exact_source.get("analyzer_git_blob_sha1"),
            analyzer_blob,
            f"{label} recorded analyzer blob",
        )
        analyzer_path = _relative_file(repo, analyzer_file, f"{label} analyzer file")
        _require(_git_blob_sha1(analyzer_path), analyzer_blob, f"live {label} analyzer blob")
'''
verifier = verifier.replace(verify_rule_line, verify_rule_line + engine_check, 1)
verifier_path.write_text(verifier, encoding="utf-8", newline="\n")

# 3) Reproducibility/current-evidence tests.
test_path = Path("tests/test_reproducible_benchmark.py")
tests = test_path.read_text(encoding="utf-8")
assert NEW_HASH not in tests
tests = tests.replace(OLD_HASH, NEW_HASH)
tests = tests.replace(
    'assert data["current_attack_scenario_hits"] == 9',
    'assert data["current_attack_scenario_hits"] == 10',
    1,
)
tests = tests.replace(
    'assert len(data["remediations"]) == 7',
    'assert len(data["remediations"]) == 8',
    1,
)
g_tail = '    assert p2_10g["fresh_full_benign_fpr_for_new_rulepack"] == "NOT_CLAIMED"\n'
assert tests.count(g_tail) == 1
h_block = r'''

    p2_10h = data["remediations"][7]
    assert p2_10h["remediation_id"] == "p2-10h-wmi-4688-parent-correlation"
    assert p2_10h["attack_scenario_hits_before"] == 9
    assert p2_10h["attack_scenario_hits_after"] == 10
    assert p2_10h["benign_events_scanned"] == 34423
    assert p2_10h["benign_non_sysmon_events_scanned"] == 34423
    assert p2_10h["benign_security_4688"] == 78
    assert p2_10h["benign_parent_pid_resolved_within_300s"] == 64
    assert p2_10h["benign_wmiprvse_parent_children_wbem"] == 0
    assert p2_10h["benign_exact_predicate_matches"] == 0
    assert p2_10h["benign_parse_errors"] == 0
    assert p2_10h["analyzer_git_blob_sha1"] == "f7e395ba66d3461ffed0a4c9b5b37f86ae585ff7"
    assert p2_10h["fresh_full_benign_fpr_for_new_rulepack"] == "NOT_CLAIMED"
'''
tests = tests.replace(g_tail, g_tail + h_block, 1)
tests = tests.replace(
    'assert data["current_evidence_id"] == "p2-10g-current-detection-evidence"',
    'assert data["current_evidence_id"] == "p2-10h-current-detection-evidence"',
    1,
)
list_needle = '        "p2-10g-hidden-run-key",\n'
assert tests.count(list_needle) == 1
tests = tests.replace(
    list_needle,
    list_needle + '        "p2-10h-wmi-4688-parent-correlation",\n',
    1,
)
test_path.write_text(tests, encoding="utf-8", newline="\n")

# 4) Permanent machine-readable P2-10H measurement record.
record_dir = Path("external_baseline/results/p2_10h_652b7cad")
record_dir.mkdir(parents=True, exist_ok=True)
record = r'''schema: breachscope.p2_10h_remediation_measurement.v1
remediation_id: p2-10h-wmi-4688-parent-correlation
measurement_repo_commit: 652b7cad94af0c9eb2dab8c66931c2a258ced925
from_rules_tree_sha256: c8aab1fc9dfb54e634f4da12c81bbeb1693f3decef747b543a20bff6153a6409
to_rules_tree_sha256: 371e73c4447cbce853dbdf936bdc40141bb4b0b496c11bcd63c41f8c42d0969f
rule_change:
  rule_file: rules/p2_10_event_rules.yml
  rule_id: R-WMI-WMIPRVSE-CHILD-4688
  name: WMI Provider Host Child Process
  severity: medium
  mitre_technique: T1047
  predicate:
    resolved_parent_endswith: '\wbem\WmiPrvSE.exe'
    event_id_equals: '4688'
    source_equals: Microsoft-Windows-Security-Auditing
engine_change:
  kind: security_4688_parent_pid_correlation
  parent_window_seconds: 300
  same_host_required: true
  forward_only: true
  parent_pid_field: ProcessId
  new_pid_field: NewProcessId
  new_process_name_field: NewProcessName
  derived_parent_field: _breachscope.resolved_security_4688_parent_process_name
  parallel_pre_enrichment_before_chunking: true
attack_external_baseline:
  baseline_id: p2-09c-evtx-attack-samples-v1
  corpus_manifest_sha256: 91fc5c2d719e2d3255fd8164485d763e49e05ee3bd420b0cd0cceda6b926b21d
  labels_sha256: f3b3386978b2e9f8d8650d229c2b9b7e9754dc0fa1b21bda2baf6f68964cf532
  source_files: 10
  events: 202
  before_scenario_hits: 9
  after_scenario_hits: 10
  scenario_misses: 0
  scenario_total: 10
  after_scenario_hit_rate: 1.0
  findings: 14
  flagged_events: 14
  changed_scenario:
    scenario_id: lm-wmi
    expected_technique: T1047
    before_status: miss
    after_status: hit
  remaining_miss_scenarios: []
benign_incremental_match_proof:
  baseline_id: p2-09d-nextron-win10-v1
  corpus_sha256: d48f1b328d48db6c6dfaa9b6e232dbb454d93e833c6e1248efc0faf690b6808e
  corpus_total_events_from_p2_09d: 766623
  evtx_files_total: 352
  non_sysmon_source_files_scanned: 351
  non_sysmon_events_scanned: 34423
  security_4688: 78
  parent_pid_resolved_within_300s: 64
  wmiprvse_parent_children_broad: 0
  wmiprvse_parent_children_wbem: 0
  exact_predicate_matches: 0
  parse_errors: 0
  timestamp_parse_errors_4688: 0
  probe_github_actions_run_id: 34384477247
  probe_commit: ae67c7ba1fdafbe1a4e6ef0c949214c4a99af457
  probe_artifact_id: 10117248190
  probe_artifact_digest_sha256: bc6a4ed11ef039ae57c678c08104ec58adc3bca71d11ed9a4aac5ab6b6100ff6
  parser: python-evtx 0.8.1 plus BreachScope EVTX extraction path
  fresh_full_fp_tn_rerun: false
measurement_execution:
  github_actions_run_id: 34384324593
  artifact_id: 10117109156
  artifact_digest_sha256: cb9bb8babd935bc4b6570671b18f0dbfe8edf0539ed7d02603906063e7eb5ccc
  artifact_record_schema: breachscope.external_holdout.result.v1
  focused_tests_passed: 8
  focused_test_github_actions_run_id: 34383958657
  detector_runtime_seconds: 0.12603693399999827
  detector_peak_memory_mb: 0.17678451538085938
exact_source:
  pr_code_commit: 4c8c9234978051fa58995dcee05cbad9fca081c0
  measurement_commit: 652b7cad94af0c9eb2dab8c66931c2a258ced925
  analyzer_file: breachscope/analyzer.py
  analyzer_git_blob_sha1: f7e395ba66d3461ffed0a4c9b5b37f86ae585ff7
  rule_file_git_blob_sha1: 3a2f853fd6c8232f7d919913fd711d7f18785108
  note: The measurement commit has identical analyzer and rule content to the PR code commit and adds only the measurement workflow.
claim_boundary:
  public_known_attack_corpus: true
  final_blind_holdout: false
  production_detection_rate: NOT_CLAIMED
  production_false_positive_rate: NOT_CLAIMED
  fresh_full_benign_fpr_for_new_rulepack: NOT_CLAIMED
  incremental_benign_statement: No Security 4688 child whose recent same-host parent PID resolved to a wbem WmiPrvSE.exe path was observed in the 34,423 non-Sysmon events from the pinned public benign corpus.
'''
(record_dir / "measurement.yaml").write_text(record, encoding="utf-8", newline="\n")

# 5) Human-readable remediation record.
doc_path = Path("docs/P2_10H_WMI_PARENT_CORRELATION.md")
doc = r'''# P2-10H WMI 4688 Parent Correlation

## 왜 이 항목을 고쳤는가

P2-10G 이후 고정 공개 공격 baseline은 **9 HIT / 1 MISS / 10 scenario**였습니다.
남은 MISS는 `lm-wmi` 하나였고, 기대 technique은 `T1047`입니다.

샘플의 Security 4688 두 건을 확인했습니다.

- 먼저 `C:\Windows\System32\wbem\WmiPrvSE.exe`가 PID `0xae8`로 생성됨
- 약 31ms 뒤 다음 4688의 부모 `ProcessId`가 같은 `0xae8`
- 따라서 두 이벤트를 이어 보면 WMI provider host가 자식 프로세스를 만든 관계가 확인됨

자식 실행 파일 이름 `calc.exe`는 룰 조건에 넣지 않았습니다.
또 4688 관계만으로 원격 실행 자체가 증명된다고 쓰지 않습니다. `lm-wmi`의 T1047 맵핑은 고정 공개 corpus의 upstream WMI 시나리오 출처를 기준으로 합니다.

## 변경

`breachscope/analyzer.py`에서 Security 4688의 부모 PID를 같은 호스트의 앞선 4688과 연결합니다.

- 현재 이벤트의 `ProcessId`를 부모 PID로 사용
- 앞선 이벤트의 `NewProcessId`와 연결
- 같은 호스트만 연결
- 부모 이벤트가 먼저 나와야 함
- 최대 300초 이내만 인정
- 병렬 분석에서는 chunk를 나누기 전에 먼저 관계를 계산

그 결과를 내부 필드 `_breachscope.resolved_security_4688_parent_process_name`에 넣습니다.

새 룰 `R-WMI-WMIPRVSE-CHILD-4688`은 다음 조건만 봅니다.

- Security Event 4688
- source `Microsoft-Windows-Security-Auditing`
- 복원된 부모 경로가 `\wbem\WmiPrvSE.exe`로 끝남
- ATT&CK `T1047`
- severity `medium`

## 공개 공격 baseline 재측정

```text
PR code commit: 4c8c9234978051fa58995dcee05cbad9fca081c0
measurement commit: 652b7cad94af0c9eb2dab8c66931c2a258ced925
run: 34384324593
artifact ID: 10117109156
artifact digest: cb9bb8babd935bc4b6570671b18f0dbfe8edf0539ed7d02603906063e7eb5ccc
rule tree SHA-256: 371e73c4447cbce853dbdf936bdc40141bb4b0b496c11bcd63c41f8c42d0969f
analyzer blob SHA-1: f7e395ba66d3461ffed0a4c9b5b37f86ae585ff7
```

- before: **9 HIT / 1 MISS / 10**
- after: **10 HIT / 0 MISS / 10**
- rules: **60**
- findings / flagged events: **14 / 14**
- `lm-wmi`: **MISS → HIT**
- expected/observed technique: `T1047`
- events: **202**

이는 고정된 알려진 공개 공격 corpus의 scenario 결과입니다.
**실제 공격 탐지율 100%**라는 뜻이 아닙니다.

## benign incremental 확인

P2-09D에 사용한 고정 공개 benign corpus에서 non-Sysmon EVTX를 새 상관조건으로 다시 확인했습니다.

- corpus SHA-256: `d48f1b328d48db6c6dfaa9b6e232dbb454d93e833c6e1248efc0faf690b6808e`
- 전체 EVTX: **352**
- non-Sysmon EVTX: **351**
- non-Sysmon events: **34,423**
- Security 4688: **78**
- 300초 이내 부모 PID 복원: **64**
- `WmiPrvSE.exe` 부모-자식 broad matches: **0**
- `\wbem\WmiPrvSE.exe` strict matches: **0**
- parse errors: **0**
- timestamp parse errors: **0**
- run: `34384477247`
- artifact ID: `10117248190`
- artifact digest: `bc6a4ed11ef039ae57c678c08104ec58adc3bca71d11ed9a4aac5ab6b6100ff6`

이는 pinned public benign corpus에서의 **incremental exact-match 관찰값**입니다.
production false positive rate가 0이라는 뜻이 아니며, 현재 60-rule pack의 fresh full benign FPR도 아닙니다.

## 현재 공개 공격 baseline 상태

```text
P2-09E 2/10 -> P2-10A 3/10 -> P2-10B 4/10 -> P2-10C 5/10
-> P2-10D 6/10 -> P2-10E 7/10 -> P2-10F 8/10 -> P2-10G 9/10
-> P2-10H 10/10
```

## 말할 수 없는 것

이번 결과로 production precision/recall/FPR, 실제 공격 탐지율 100%, 기업 환경 대표성, final blind holdout 통과를 주장하지 않습니다.
공격 corpus는 이미 알려진 공개 corpus이며 final blind holdout이 아닙니다.
P2-09D의 `FPR=0.00221752%`는 역사적 rule tree `543b4e02...`에만 적용됩니다.
'''
doc_path.write_text(doc, encoding="utf-8", newline="\n")

print("P2-10H permanent evidence patch applied")
