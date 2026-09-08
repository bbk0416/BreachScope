# P2-09C 외부 공격 baseline

## 목적

P2-09C는 BreachScope의 현재 룰셋을 공개 외부 Windows 공격 샘플에 그대로 적용해 **어떤 ATT&CK 기법을 잡고 어떤 기법을 놓치는지** 기록합니다.

이 단계에서 탐지 룰을 고치지 않습니다. 미탐도 결과 그대로 남깁니다.

## 이 결과가 의미하는 것

주 지표는 **scenario expected-technique hit rate**입니다.

예를 들어 한 EVTX 샘플이 `T1003.001`을 나타내는 것으로 upstream에서 식별되어 있고, BreachScope가 그 파일 안의 이벤트 중 하나 이상에서 `T1003.001` 탐지를 내면 해당 scenario를 `hit`으로 기록합니다.

반대로 기대한 기법이 한 번도 나오지 않으면 `miss`입니다.

## 이 결과가 의미하지 않는 것

이 데이터는 공개되어 있고 프로젝트가 이미 알고 있는 corpus입니다. 따라서 다음을 주장하면 안 됩니다.

- final blind holdout
- production detection accuracy
- event-level precision / recall
- real-world false-positive rate
- enterprise Windows 환경 검증

공개 공격 EVTX 파일 안에는 공격 이벤트 외의 주변 이벤트도 들어갈 수 있습니다. 그래서 P2-09C는 각 이벤트를 임의로 `malicious`로 표시하지 않고 전부 `ignore`로 둡니다.

**실제 benign 로그의 오탐률은 P2-09D에서 별도로 측정합니다.**

## 고정된 소스

소스 정의는 `external_baseline/p2_09c_sources.yaml`에 있습니다.

P2-09C v1 실행 세트는 다음 공개 저장소의 특정 commit과 Git blob을 고정합니다.

- `sbousseaden/EVTX-ATTACK-SAMPLES`
- commit `4ceed2f4706daf601c212a8f91c113dd85349a2c`
- 10개 EVTX 샘플
- 각 파일의 경로, 파일 크기, Git blob SHA-1을 recipe에 고정
- 다운로드 후 SHA-256을 계산해 실제 평가 manifest와 결과에 기록

`OTRF/Security-Datasets`도 provider commit은 고정했지만 P2-09C v1 실행 세트에는 포함하지 않습니다. 현재 단계에서 원본 ZIP의 바이트 체크섬을 동일한 수준으로 미리 고정하지 못했기 때문입니다. 체크섬 없이 자동으로 최신 데이터를 가져오지는 않습니다.

## 원본 데이터 취급

BreachScope 저장소에는 외부 원본 EVTX를 넣지 않습니다.

실행기가 upstream에서 직접 내려받아 다음 ignored 경로에 둡니다.

```text
out/external_baseline/p2_09c/corpus/
```

외부 데이터 사용 조건은 각 upstream 저장소의 현재 조건을 따라야 합니다. BreachScope는 해당 원본을 재배포하지 않습니다.

## 실행 전 조건

기존 `scripts/evaluate_external_holdout.py`가 룰 상태를 고정할 때 Git working tree가 깨끗해야 합니다.

따라서 실제 baseline은 병합된 commit 또는 깨끗한 평가 branch에서 실행합니다.

## recipe만 확인

네트워크를 사용하지 않고 소스 고정값과 형식을 검사합니다.

```cmd
python scripts\run_external_baseline.py --validate-only
```

정상 출력의 핵심은 다음과 같습니다.

```text
P2-09C source recipe: PASS
Network access: NOT USED
Detection rules executed: NO
```

## 전체 baseline 실행

Windows CMD 기준:

```cmd
python scripts\run_external_baseline.py
```

특정 샘플만 확인하려면 `--asset`을 사용할 수 있습니다.

```cmd
python scripts\run_external_baseline.py --asset evtx-ca-lsass-mimikatz
```

여러 개를 고를 때는 옵션을 반복합니다.

```cmd
python scripts\run_external_baseline.py --asset evtx-ca-lsass-mimikatz --asset evtx-de-security-log-cleared
```

## 실행 순서

실행기는 다음 순서를 지킵니다.

1. 현재 repository commit과 rule tree를 freeze
2. pinned commit/path에서 외부 파일 다운로드
3. 예상 파일 크기와 Git blob SHA-1 확인
4. SHA-256 계산
5. `external_baseline` evaluator manifest 생성
6. detector를 실행하지 않고 event index 생성
7. 모든 event label을 `ignore`로 생성
8. 기존 external holdout evaluator로 score
9. scenario hit/miss 요약 생성

탐지 룰은 이 과정에서 수정하지 않습니다.

## 생성 파일

기본 출력 위치:

```text
out/external_baseline/p2_09c/
```

주요 파일:

- `rules_freeze.json`: 평가한 commit/rule tree
- `manifest.yaml`: 실제 다운로드된 corpus SHA-256과 scenario 기대 기법
- `event_index.jsonl`: detection 실행 전 event index
- `labels_ignore.jsonl`: event-level ground truth를 주장하지 않는 label 파일
- `result.json`: 기존 evaluator의 원본 측정 결과
- `summary.json`: P2-09C 해석 경계를 적용한 요약
- `SUMMARY.md`: 사람이 읽기 쉬운 scenario hit/miss 표

## 결과 판정

P2-09C에서는 숫자가 낮다는 이유만으로 실패 처리하지 않습니다.

목적은 현재 상태를 숨기지 않고 측정하는 것입니다.

결과를 볼 때는 다음 순서로 판단합니다.

1. source hash 검증이 모두 통과했는가
2. corpus ingest가 정상 동작했는가
3. 10개 scenario 중 어떤 기법이 hit/miss인가
4. miss가 telemetry 부족인지, normalization 문제인지, rule coverage 문제인지 구분 가능한가
5. 그 결과가 실제로 다음 개발 우선순위를 바꿀 만큼 중요한가

P2-09C가 끝난 뒤에도 **실제 benign false positive 자료가 없으면 탐지 정확도를 주장할 수 없습니다.** 다음 단계는 P2-09D입니다.

## 2026-09-08 실측 결과

merged main commit `2a1631f6633ee40dcc47524675dc9dbda541e01d`에서 고정된 10개 EVTX를 실제로 실행했습니다.

- **2 HIT / 8 MISS / 10 total**
- scenario hit rate **20.0%**
- findings **3**
- converted events **202**
- event-level precision / recall / FPR **NOT CLAIMED**

같은 commit과 corpus를 GitHub Actions에서 두 번 실행해 repo/rule/corpus hash, source hash, findings 수, scenario 결과가 동일한 것도 확인했습니다.

영구 기록:

- `external_baseline/results/p2_09c_main_2a1631f/README.md`
- `external_baseline/results/p2_09c_main_2a1631f/measurement.yaml`
- `external_baseline/results/p2_09c_main_2a1631f/telemetry.yaml`

8개 MISS의 주된 원인은 해당 ATT&CK technique ID 자체가 없는 것이 아니라, 현재 native rules가 `command_line` 패턴에 많이 의존해 Event ID와 이벤트별 필드가 핵심 증거인 외부 EVTX를 놓치는 구조였습니다. P2-09C에서는 이 결과를 근거로 rule을 수정하지 않고 그대로 보존합니다.
