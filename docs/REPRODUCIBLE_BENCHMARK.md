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

따라서 이 benchmark는 **같은 고정 rule tree의 attack-side 관찰값과 benign-side 관찰값을 한 묶음으로 보여 주는 evidence bundle**입니다.

## 빠른 검증

저장소 root에서 실행합니다.

```cmd
python scripts\verify_reproducible_benchmark.py
```

이 검증은 네트워크를 사용하지 않습니다.

정상 출력 예:

```text
P2-09E benchmark verification: PASS
Attack external baseline: 2/10 scenario hits (20.0%)
Benign external baseline: FP=17 TN=766606 FPR=0.00221752%
Production accuracy/FPR: NOT CLAIMED
Performance benchmark: NOT CLAIMED
```

기계 판독용 JSON:

```cmd
python scripts\verify_reproducible_benchmark.py --json
```

## verifier가 확인하는 것

`verify_reproducible_benchmark.py`는 다음을 검사합니다.

1. benchmark manifest schema와 benchmark type
2. 현재 `rules/` tree SHA-256
3. P2-09C source contract와 measured result의 baseline ID
4. P2-09C measured commit과 rule hash
5. P2-09C 10 source / 202 events / 2 HIT / 8 MISS / findings 3
6. P2-09C event-level precision/recall/FPR가 `NOT_CLAIMED`인지
7. P2-09D source contract와 measured result의 baseline ID
8. P2-09D corpus SHA-256과 asset size가 source contract와 일치하는지
9. P2-09D 352 source / 766,623 events / FP 17 / TN 766,606 / findings 19
10. `FP + TN = events`인지
11. FPR을 FP와 전체 event 수에서 다시 계산했을 때 기록값과 같은지
12. production accuracy/FPR, final blind holdout, performance benchmark를 주장하지 않는지

검증에 사용한 manifest/source/result 파일들의 SHA-256을 다시 묶어 `evidence_bundle_sha256`도 출력합니다. 이 값은 해당 저장소 상태에서 benchmark evidence 파일들이 정확히 같은지 확인하는 편의용 digest입니다.

## 전체 재실행

기록된 evidence만 확인할 때는 외부 다운로드가 필요 없습니다.

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

이 benchmark로 말할 수 있는 것은 다음입니다.

- 고정된 공개 공격 세트 10 scenario에서 현재 고정 rule tree가 기대 technique 2개를 hit했다.
- 고정된 공개 goodware corpus 766,623 events에서 17 events가 flagged됐다.
- 두 결과의 source와 rule tree가 고정되어 있고 저장소에서 기록값의 내부 일관성을 다시 확인할 수 있다.

다음은 말할 수 없습니다.

- 실제 공격 전체 탐지율이 20%다
- 실제 precision 또는 recall이 20%다
- production FPR이 0.00221752%다
- 기업 SOC 환경의 alert quality가 검증됐다
- final blind holdout을 통과했다
- BreachScope가 다른 탐지 엔진보다 빠르다
- 이번 distributed 실행시간이 제품 throughput을 증명한다

## P2-09E 완료 기준

P2-09E는 다음이 모두 만족될 때 닫습니다.

- P2-09C measured result가 영구 기록되어 있음
- P2-09D measured result가 영구 기록되어 있음
- 두 결과의 source/rule/metric 계약을 하나의 manifest가 묶음
- offline verifier가 PASS
- Linux/Windows 전체 회귀 CI가 PASS
- benchmark claim boundary가 문서와 manifest에 명시됨
- 탐지 룰을 benchmark 숫자에 맞추기 위해 수정하지 않음
