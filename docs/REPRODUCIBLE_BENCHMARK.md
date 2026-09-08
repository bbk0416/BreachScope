# P2-09E Reproducible Detection-Evidence Benchmark

## 목적

P2-09E는 P2-09C 공격-side external baseline과 P2-09D benign baseline을 **하나의 재현 가능한 evidence bundle**로 묶습니다.

이 단계의 목적은 새로운 탐지 룰을 추가하거나 더 좋은 숫자를 만드는 것이 아닙니다. 이미 측정한 결과가 어떤 source, commit, rule tree, 라벨 기준에서 나왔는지 고정하고, 저장소 안에서 기계적으로 다시 확인할 수 있게 만드는 것입니다.

이 문서에서 benchmark는 **detection-evidence benchmark**를 뜻합니다. 처리속도나 처리량 benchmark가 아닙니다.

## 고정 P2-09E benchmark manifest

기준 파일:

```text
external_baseline/p2_09e_benchmark.yaml
```

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

기록:

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

기록:

```text
external_baseline/results/p2_09d_main_789c1f45/measurement.yaml
```

## P2-09C와 P2-09D를 함께 묶을 수 있는 이유

두 측정의 commit은 다르지만 rule tree SHA-256은 같습니다.

`2a1631f6633ee40dcc47524675dc9dbda541e01d`부터 `789c1f45b35599adbb5816c69c2e1e5c586584c9`까지의 변경은 P2-09C/P2-09D 문서, evidence, runner, test 파일이었고 `rules/`, analyzer, product detection semantics는 바뀌지 않았습니다.

따라서 P2-09E는 **같은 고정 rule tree의 attack-side 관찰값과 benign-side 관찰값을 묶은 역사적 snapshot**입니다.

## P2-10 이후의 현재 evidence chain

P2-10A부터 탐지 룰이 실제로 변경됩니다. 따라서 역사적 P2-09E verifier는 현재 live rule hash와 다르다는 이유로 일부러 FAIL합니다.

```cmd
python scripts\verify_reproducible_benchmark.py
```

이 실패는 P2-09E 기록이 깨졌다는 뜻이 아닙니다. 현재 룰이 당시 룰과 더 이상 같지 않다는 사실을 숨기지 않는 fail-closed 동작입니다.

현재 rule tree까지 포함한 연결된 근거는 다음 명령으로 확인합니다.

```cmd
python scripts\verify_current_detection_evidence.py
```

JSON 출력:

```cmd
python scripts\verify_current_detection_evidence.py --json
```

P2-10D 이후 핵심 출력은 다음 의미를 가집니다.

```text
Current detection evidence verification: PASS
Attack external baseline: 2/10 -> 6/10 scenario hits
p2-10a-scheduled-task-4698: benign incremental predicate matches=0 / 34423 non-Sysmon events
p2-10b-wmi-xsl: benign incremental predicate matches=0 / 732200 Sysmon records
p2-10c-domain-admins-4661: benign incremental predicate matches=0 / 34423 non-Sysmon events
p2-10d-lsass-access-1010: benign incremental predicate matches=0 / 732200 Sysmon records
Fresh full benign FPR for current rulepack: NOT CLAIMED
Production accuracy/FPR: NOT CLAIMED
```

manifest:

```text
external_baseline/current_detection_evidence.yaml
```

현재 chain:

```text
P2-09E 543b4e02... / 2 HIT
  -> P2-10A 8ade507d... / 3 HIT
  -> P2-10B a21e4a7b... / 4 HIT
  -> P2-10C 9fff876a... / 5 HIT
  -> P2-10D f6561197... / 6 HIT
```

## P2-10A

추가 룰은 Security-Auditing Event ID 4698 scheduled task creation입니다.

- rule hash: `8ade507d...`
- 공격 scenario: **2/10 → 3/10**
- 개선: `exec-scheduled-task` / `T1053.005`
- pinned benign non-Sysmon events: **34,423**
- exact new-predicate match: **0**

이 값은 새 predicate의 incremental 확인이며 현재 rulepack 전체의 fresh benign FPR이 아닙니다.

## P2-10B

추가 룰은 WMIC remote XSL execution입니다.

- 조건: `wmic` + `/format:"http` + Sysmon Event ID 1
- rule hash: `a21e4a7b...`
- 공격 scenario: **3/10 → 4/10**
- 개선: `exec-wmi-xsl` / `T1047`
- `lm-wmi`: **MISS 유지**
- pinned benign Sysmon records: **732,200**
- exact new-predicate match: **0**

상세 기록:

```text
docs/P2_10B_WMI_XSL_REMEDIATION.md
external_baseline/results/p2_10b_927a2a63/measurement.yaml
```

## P2-10C

추가 룰은 Domain Admins SAM group object 접근을 나타내는 좁은 Security 4661 조건입니다.

- `source == Microsoft-Windows-Security-Auditing`
- `event_id == 4661`
- `ObjectType == SAM_GROUP`
- `ObjectName` regex `-512$`
- `ObjectServer == Security Account Manager`
- ATT&CK `T1087.002`
- rule hash: `9fff876a481f972ac88dcccb1044b38b8df22c390f74375034a72eca7a1a8fa0`

공격 baseline:

- same public 10-scenario / 202-event corpus
- before: **4 HIT / 6 MISS**
- after: **5 HIT / 5 MISS**
- findings: **7**
- changed scenario: `discovery-domain-admins`
- expected technique: `T1087.002`

benign incremental proof:

- pinned non-Sysmon EVTX files: **351**
- events scanned: **34,423**
- Security 4661: **0**
- exact new-predicate match: **0**
- probe run: `34235448799`

P2-10C 측정 과정에서는 external evaluator가 EVTX 변환 record의 nested `raw`를 한 번 더 감싸는 구체적인 재구성 버그도 확인했습니다. 보정 후 새 룰을 넣지 않은 P2-10B 54-rule control run에서 결과가 **4/10, findings 5 그대로**임을 확인한 뒤 P2-10C를 재측정했습니다.

- evaluator control run: `34237083371`
- P2-10C measurement run: `34238713665`
- measurement artifact: `10061000192`
- artifact ZIP SHA-256: `979bcd74bbad5e9d26e035011e99e8afaf2f5c49f59d47a69ff0500a02c2a3c7`

상세 기록:

```text
docs/P2_10C_DOMAIN_ADMINS_REMEDIATION.md
external_baseline/results/p2_10c_2bc093de/measurement.yaml
```

## P2-10D

추가 룰은 Sysmon Event ID 10에서 LSASS를 대상으로 access mask `0x1010`을 사용한 process access를 찾는 좁은 조건입니다.

- `source == Microsoft-Windows-Sysmon`
- `event_id == 10`
- `TargetImage` endswith `\lsass.exe`
- `GrantedAccess` regex `^0x0*1010$`
- ATT&CK `T1003.001`
- rule hash: `f6561197677172b671646a49a84a2ff1d3cc9d661f23ee2862037ac5ca16292e`

공격 baseline:

- same public 10-scenario / 202-event corpus
- before: **5 HIT / 5 MISS**
- after: **6 HIT / 4 MISS**
- findings: **8**
- flagged events: **8**
- changed scenario: `ca-lsass-mimikatz`
- expected technique: `T1003.001`

benign incremental proof:

- pinned Sysmon records: **732,200**
- Sysmon chunks: **11,894**
- broad LSASS Event 10 target: **61**
- exact `LSASS + GrantedAccess 0x1010` predicate: **0**
- probe run: `34243188619`

measurement:

- commit: `ce1ada8b1ddcf075e3258a7b2f2abf309ac9b034`
- run: `34244428149`
- focused tests: **6 PASS**
- artifact: `10063365810`
- artifact ZIP SHA-256: `bc6b2e81c5c4f55a727f6788b537e2f6c49525fd7de2096d2ae58459a26c8c4c`

상세 기록:

```text
docs/P2_10D_LSASS_REMEDIATION.md
external_baseline/results/p2_10d_ce1ada8b/measurement.yaml
```

## current verifier가 확인하는 것

`verify_current_detection_evidence.py`는 최소한 다음을 확인합니다.

1. P2-09E attack/benign 기록과 claim boundary
2. 역사적 base rule hash `543b4e02...`
3. 각 remediation의 `from_rules_tree_sha256` → `to_rules_tree_sha256` 연결
4. P2-10A live rule 조건과 2→3 attack scenario 변화
5. P2-10B live rule 조건과 3→4 변화
6. P2-10C live rule 조건과 4→5 변화
7. P2-10D live LSASS/Event 10/GrantedAccess 조건과 5→6 변화
8. 각 단계의 지정된 pinned benign 범위 exact match 0
9. P2-10C evaluator reconstruction control 결과
10. 마지막 remediation hash가 실제 live `rules/` tree SHA-256과 같은지
11. production accuracy/FPR, final blind holdout, current rulepack fresh full benign FPR을 주장하지 않는지

## 전체 재실행

공격 baseline 원본 재실행:

```cmd
python scripts\run_external_baseline.py
```

benign baseline 원본 재실행:

```cmd
python scripts\run_benign_baseline_cached.py
```

두 full rerun은 upstream 외부 자료 다운로드가 필요합니다. source contract의 commit/release/SHA-256과 다르면 같은 benchmark 결과로 취급하면 안 됩니다.

P2-09D의 약 799MB Sysmon EVTX는 GitHub hosted runner 단일 45분 작업에서 완료되지 않았고, 기록된 P2-09D 결과는 동일 parser/normalizer/rules를 유지한 distributed full-corpus 측정으로 얻었습니다. 그 실행시간은 제품 성능 benchmark가 아닙니다.

## 결과 해석

말할 수 있는 것:

- 역사적 P2-09E rule hash에서 공개 공격 10 scenario 중 2개 expected technique을 hit했습니다.
- 같은 역사적 rule hash에서 공개 benign corpus 766,623 events 중 17 events가 flagged됐습니다.
- P2-10A/B/C/D의 각각의 좁은 rule 변경은 같은 공개 공격 baseline에서 scenario coverage를 2→3→4→5→6으로 늘렸습니다.
- 각 새 predicate의 지정된 pinned benign 범위에서 exact match 0을 관찰했습니다.

말할 수 없는 것:

- 실제 공격 전체 탐지율이 60%다
- 실제 precision 또는 recall이 60%다
- 현재 56-rule pack의 production FPR이 0.00221752%다
- 현재 56-rule pack 전체 benign FPR을 fresh하게 다시 측정했다
- 기업 SOC 환경 대표성이 검증됐다
- final blind holdout을 통과했다
- BreachScope가 다른 탐지 엔진보다 빠르다

P2-09D의 `FP=17 / TN=766,606 / FPR=0.00221752%`는 rule hash `543b4e02...`에만 적용되는 역사적 공개-corpus 관찰값입니다.
