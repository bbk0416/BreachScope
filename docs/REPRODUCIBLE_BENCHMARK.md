# P2-09E Reproducible Detection-Evidence Benchmark

## 목적

P2-09E는 P2-09C 공격-side external baseline과 P2-09D benign baseline을 **하나의 재현 가능한 evidence bundle**로 묶습니다.

이 단계의 목적은 새로운 탐지 룰을 추가하거나 더 좋은 숫자를 만드는 것이 아닙니다. 이미 측정한 결과가 어떤 source, commit, rule tree, 라벨 기준에서 나왔는지 고정하고, 저장소 안에서 기계적으로 다시 확인할 수 있게 만드는 것입니다.

이 문서에서 benchmark는 **detection-evidence benchmark**를 뜻합니다. 처리속도나 처리량 benchmark가 아닙니다.

## 고정 benchmark manifest

기준 파일:

```text
external_baseline/p2_09e_benchmark.yaml
```

두 구성요소를 묶습니다.

### Attack external baseline — P2-09C

- baseline: `p2-09c-evtx-attack-samples-v1`
- measured commit: `2a1631f6633ee40dcc47524675dc9dbda541e01d`
- rules SHA-256: `543b4e02ebb48d5e33eeb4405a6d489487a05d07ffebda4ba31206a059dae3ce`
- source files: **10**
- converted events: **202**
- scenario result: **2 HIT / 8 MISS / 10 total**
- scenario hit rate: **20.0%**
- findings: **3**
- event-level precision/recall/FPR: **NOT CLAIMED**

기록 파일:

```text
external_baseline/results/p2_09c_main_2a1631f/measurement.yaml
```

### Benign external baseline — P2-09D

- baseline: `p2-09d-nextron-win10-v1`
- measured commit: `789c1f45b35599adbb5816c69c2e1e5c586584c9`
- rules SHA-256: `543b4e02ebb48d5e33eeb4405a6d489487a05d07ffebda4ba31206a059dae3ce`
- source EVTX files: **352**
- non-empty EVTX files: **97**
- benign events: **766,623**
- FP: **17**
- TN: **766,606**
- observed event-level FPR: **0.00221752%**
- findings: **19**
- production FPR: **NOT CLAIMED**

기록 파일:

```text
external_baseline/results/p2_09d_main_789c1f45/measurement.yaml
```

## 두 결과를 함께 묶을 수 있는 이유

P2-09C와 P2-09D는 측정 commit이 다릅니다. 그래서 commit이 다르다는 사실을 숨기지 않습니다.

GitHub compare로 `2a1631f6633ee40dcc47524675dc9dbda541e01d`부터 `789c1f45b35599adbb5816c69c2e1e5c586584c9`까지 확인했을 때 변경된 파일은 P2-09C/P2-09D 문서, evidence, runner, test 파일뿐이었습니다.

이 구간에서 다음 탐지 의미 파일은 변경되지 않았습니다.

- `rules/`
- `breachscope/analyzer.py`
- BreachScope product detection engine files

두 측정의 rule tree SHA-256도 동일합니다.

따라서 이 benchmark는 **같은 고정 rule tree의 attack-side 관찰값과 benign-side 관찰값을 한 묶음으로 보여 주는 역사적 evidence snapshot**입니다.

## P2-10 이후의 상태

P2-10A부터 탐지 룰이 실제로 변경됩니다. 따라서 P2-09E의 rule hash와 현재 `rules/` hash가 달라지는 것이 정상입니다.

이 경우 아래 명령은 일부러 FAIL합니다.

```cmd
python scripts\verify_reproducible_benchmark.py
```

이 실패는 P2-09E evidence가 망가졌다는 뜻이 아닙니다. **현재 룰이 P2-09E 당시 룰과 더 이상 같지 않다는 사실을 숨기지 않는 보호장치**입니다.

현재 룰까지 포함한 evidence chain은 다음 명령으로 확인합니다.

```cmd
python scripts\verify_current_detection_evidence.py
```

기계 판독용 JSON:

```cmd
python scripts\verify_current_detection_evidence.py --json
```

P2-10B 이후 정상 출력의 핵심은 다음과 같습니다.

```text
Current detection evidence verification: PASS
Attack external baseline: 2/10 -> 4/10 scenario hits
p2-10a-scheduled-task-4698: benign incremental predicate matches=0 / 34423 non-Sysmon events
p2-10b-wmi-xsl: benign incremental predicate matches=0 / 732200 Sysmon records
Fresh full benign FPR for current rulepack: NOT CLAIMED
Production accuracy/FPR: NOT CLAIMED
```

현재 evidence chain manifest:

```text
external_baseline/current_detection_evidence.yaml
```

현재 chain은 다음 순서를 고정합니다.

```text
P2-09E 543b4e02... / 2 HIT
  -> P2-10A 8ade507d... / 3 HIT
  -> P2-10B a21e4a7b... / 4 HIT
```

## verifier가 확인하는 것

`verify_reproducible_benchmark.py`는 P2-09E rule hash가 현재 rule hash와 같은지까지 검사합니다. 따라서 룰 변경 후에는 stale 상태를 fail-closed로 알립니다.

`verify_current_detection_evidence.py`는 다음을 검사합니다.

1. P2-09E attack/benign source, result, metric, claim boundary가 여전히 서로 맞는지
2. P2-09E의 base rule hash
3. 각 remediation record의 `from_rules_tree_sha256` → `to_rules_tree_sha256` 연결
4. P2-10A 실제 rule YAML이 Security Event ID 4698, `Microsoft-Windows-Security-Auditing`, `T1053.005` 조건과 맞는지
5. P2-10A 외부 공격 corpus가 P2-09C와 같은 manifest/labels hash인지
6. P2-10A 공격 scenario가 **2/10 → 3/10**으로 바뀌고 `exec-scheduled-task`가 MISS → HIT인지
7. P2-10A pinned benign corpus 34,423 non-Sysmon events에서 새 predicate match가 0인지
8. P2-10B 실제 rule YAML이 `wmic`, `/format:"http`, Sysmon Event ID 1, `Microsoft-Windows-Sysmon`, `T1047` 조건과 맞는지
9. P2-10B 외부 공격 corpus가 같은 P2-09C manifest/labels hash인지
10. P2-10B 공격 scenario가 **3/10 → 4/10**으로 바뀌고 `exec-wmi-xsl`이 MISS → HIT인지
11. P2-10B에서 `lm-wmi`가 근거 없이 함께 HIT로 바뀌지 않고 MISS로 남았는지
12. pinned benign Sysmon **732,200 records**에서 raw `wmic` 후보 29건을 제품 parser로 다시 확인했고 새 predicate match가 0인지
13. 현재 `rules/` tree SHA-256이 remediation chain의 마지막 hash와 같은지
14. production accuracy/FPR, final blind holdout, 새 룰팩의 fresh full benign FPR을 주장하지 않는지

## 전체 재실행

공격 baseline을 원본부터 다시 실행하려면:

```cmd
python scripts\run_external_baseline.py
```

benign baseline을 원본부터 다시 실행하려면:

```cmd
python scripts\run_benign_baseline_cached.py
```

두 full rerun은 upstream 외부 자료 다운로드가 필요합니다. source contract의 commit/release/SHA-256과 맞지 않으면 실행 결과를 같은 benchmark 결과로 취급하면 안 됩니다.

P2-09D의 `win10-client.tgz`에는 약 799MB 크기의 Sysmon Operational EVTX가 포함되어 있습니다. GitHub hosted runner의 단일 45분 실행에서는 완료되지 않아 기록된 P2-09D 결과는 동일 parser/normalizer/rules를 유지한 distributed full-corpus 측정으로 얻었습니다. 이 distributed 실행시간은 제품 처리성능 benchmark가 아닙니다.

## 결과 해석

### P2-09E 역사적 snapshot으로 말할 수 있는 것

- rule hash `543b4e02...` 상태에서 고정된 공개 공격 세트 10 scenario 중 기대 technique 2개를 hit했습니다.
- 같은 rule hash 상태에서 고정된 공개 goodware corpus 766,623 events 중 17 events가 flagged됐습니다.
- 이 FPR은 해당 공개 corpus에서의 관찰값이며 production FPR이 아닙니다.

### P2-10A evidence로 추가로 말할 수 있는 것

- `Security-Auditing + Event ID 4698` 룰을 추가한 rule hash `8ade507d...`에서 같은 공개 공격 세트가 **3 HIT / 7 MISS**가 됐습니다.
- 개선된 scenario는 `exec-scheduled-task` / `T1053.005`입니다.
- 새 predicate는 pinned benign corpus의 **34,423 non-Sysmon events에서 0건**이었습니다.

### P2-10B current evidence로 추가로 말할 수 있는 것

- `WMIC + remote /format URL + Sysmon Event ID 1` 룰을 추가한 rule hash `a21e4a7b...`에서 같은 공개 공격 세트가 **4 HIT / 6 MISS**가 됐습니다.
- 개선된 scenario는 `exec-wmi-xsl` / `T1047`입니다.
- `lm-wmi`는 이번 변경으로 억지로 넓히지 않아 **MISS 유지**입니다.
- pinned benign Sysmon **732,200 records**를 확인했고, raw `wmic` 후보는 29건이었지만 새 predicate와 일치한 이벤트는 **0건**이었습니다.
- 이번 확인은 새 룰의 incremental predicate proof이며, 현재 54-rule pack으로 전체 766,623 events의 FP/TN/FPR을 새로 계산한 것은 아닙니다.

다음은 말할 수 없습니다.

- 실제 공격 전체 탐지율이 40%다
- 실제 precision 또는 recall이 40%다
- 현재 rulepack의 production FPR이 0.00221752%다
- 현재 54-rule pack 전체 benign FPR을 fresh하게 재측정했다
- 기업 SOC 환경의 alert quality가 검증됐다
- final blind holdout을 통과했다
- BreachScope가 다른 탐지 엔진보다 빠르다
- distributed 실행시간이 제품 throughput을 증명한다

## P2-09E 완료 기준

P2-09E는 이미 다음 조건으로 닫힌 역사적 단계입니다.

- P2-09C measured result가 영구 기록되어 있음
- P2-09D measured result가 영구 기록되어 있음
- 두 결과의 source/rule/metric 계약을 하나의 manifest가 묶음
- 당시 offline verifier가 PASS
- 당시 Linux/Windows 전체 회귀 CI가 PASS
- benchmark claim boundary가 문서와 manifest에 명시됨
- P2-09E 단계에서는 탐지 룰을 benchmark 숫자에 맞추기 위해 수정하지 않음
