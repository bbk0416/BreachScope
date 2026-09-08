# P2-09D Real Benign Baseline

## 목적

P2-09D는 BreachScope가 **정상 Windows 로그에서 얼마나 자주 탐지를 내는지** 측정합니다.

P2-09C가 공개 공격 샘플에서 ATT&CK 기법 hit/miss를 봤다면, P2-09D는 goodware/일반 사용자 활동 로그에서 **FP / TN / FPR**을 봅니다.

탐지 룰은 측정 전에 고치지 않습니다. 먼저 현재 상태를 기록하고, 실제 결과가 보여 주는 문제만 다음 변경 후보로 삼습니다.

## 고정된 benign 소스

P2-09D v1은 다음 공개 자료를 사용합니다.

- Repository: `NextronSystems/evtx-baseline`
- Release: `v0.8.4`
- Release asset: `win10-client.tgz`
- Asset ID: `371540503`
- Size: `70,844,052 bytes`
- SHA-256: `d48f1b328d48db6c6dfaa9b6e232dbb454d93e833c6e1248efc0faf690b6808e`
- License: `Apache-2.0`

소스 계약은 `external_baseline/p2_09d_benign_sources.yaml`에 고정합니다.

## 라벨 기준

라벨 방식은 `benign_by_source_intent`입니다.

- upstream이 goodware/user-activity baseline으로 만든 corpus입니다.
- BreachScope 결과를 보고 정상 이벤트만 골라낸 자료가 아닙니다.
- 이 baseline의 이벤트는 모두 `benign`으로 점수 계산합니다.
- 각 이벤트를 사람이 하나씩 다시 판정한 것은 아닙니다.

따라서 측정 FPR은 **이 고정 corpus에서의 관찰값**이며 production FPR로 표현하지 않습니다.

## 주 지표

기존 `scripts/evaluate_external_holdout.py`의 confusion matrix 계약을 그대로 사용합니다.

- `FP`: benign 이벤트인데 BreachScope가 하나 이상의 finding을 낸 이벤트
- `TN`: benign 이벤트이고 finding이 없는 이벤트
- `FPR = FP / (FP + TN)`

추가 기록값:

- 전체 benign 이벤트 수
- 전체 source 파일 수
- finding 수
- flagged event 수
- 이벤트 1,000개당 flagged event 수
- 이벤트 1,000개당 finding 수
- source별 event/flagged 수
- detector 실행 시간
- detector peak memory

## 첫 전체 실행에서 확인된 실제 문제

병합된 P2-09D 최초 구현을 정확한 main SHA에서 GitHub Actions로 실행했을 때, `Run P2-09D real benign baseline` 단계가 **45분 workflow 제한을 초과해 cancelled**됐습니다.

확인된 범위:

- exact main checkout: PASS
- locked dependency install: PASS
- clean repository state: PASS
- rules freeze: PASS
- 전체 benign baseline 완료: FAIL — 45분 timeout
- measurement artifact: 생성되지 않음

원인은 기존 경로가 evaluator의 `index`와 `score`에서 EVTX corpus를 각각 다시 읽기 때문에 비싼 EVTX 파싱이 중복되는 구조였습니다.

또한 evaluator 결과의 corpus 키는 `ignored_events`인데 초기 summary helper는 `ignore`를 검사하고 있었습니다. 전체 실행이 끝까지 갔더라도 summary 단계에서 계약 불일치가 발생할 수 있는 상태였습니다.

이 두 문제는 탐지 룰 문제가 아니라 **baseline 실행 경로 문제**입니다.

## 현재 권장 실행 경로

전체 P2-09D 실행은 다음 runner를 사용합니다.

```cmd
python scripts\run_benign_baseline_cached.py
```

네트워크 timeout을 늘리려면:

```cmd
python scripts\run_benign_baseline_cached.py --timeout 300
```

recipe만 확인하려면:

```cmd
python scripts\run_benign_baseline_cached.py --validate-only
```

정상 출력의 핵심:

```text
P2-09D cached source recipe: PASS
Network access: NOT USED
Detection rules executed: NO
```

## cached runner가 하는 일

1. 현재 repository commit과 rule tree를 freeze합니다.
2. `win10-client.tgz`를 다운로드합니다.
3. archive size와 SHA-256을 확인합니다.
4. archive 내부 EVTX만 안전한 경로로 추출합니다.
5. 각 EVTX SHA-256을 계산합니다.
6. **각 EVTX를 정확히 한 번 JSONL로 변환해 저장합니다.**
7. 기존 external holdout manifest를 JSONL 기준으로 만듭니다.
8. 기존 evaluator의 `index`를 실행합니다.
9. 모든 event를 `benign_by_source_intent`로 라벨링합니다.
10. 기존 evaluator의 `score`를 실행합니다.
11. evaluator의 `ignored_events` 계약을 확인한 뒤 FP/TN/FPR 요약을 만듭니다.

핵심은 탐지 계산 방식을 바꾸는 것이 아니라 **EVTX 파싱 결과를 재사용하는 것**입니다. index와 score의 평가 계약은 그대로 유지합니다.

## 생성 파일

기본 경로:

```text
out/external_baseline/p2_09d/
```

주요 파일:

- `raw/win10-client.tgz`: 검증된 upstream archive
- `corpus_evtx/`: archive에서 추출한 원본 EVTX
- `corpus_jsonl/`: 한 번만 변환해 재사용하는 JSONL
- `rules_freeze.json`: 평가한 repository/rule 상태
- `manifest.yaml`: JSONL SHA-256과 source provenance
- `event_index.jsonl`: detection 실행 전 event index
- `labels_benign.jsonl`: benign-by-source-intent label
- `result.json`: 기존 evaluator 원본 결과
- `summary.json`: P2-09D 해석 경계를 포함한 요약
- `SUMMARY.md`: 사람이 읽기 쉬운 오탐 요약

원본 archive/EVTX는 `out/` 아래에만 두고 저장소에 재배포하지 않습니다.

## 이 결과가 의미하지 않는 것

다음 표현은 하지 않습니다.

- production false-positive rate
- enterprise-wide false-positive rate
- 모든 Windows 환경의 정상 로그 대표값
- SOC 운영 환경의 최종 alert quality
- final blind holdout

실제 기업 환경은 설치 프로그램, 관리 도구, 사용자 행동, 감사 정책, Sysmon 설정이 다릅니다.

## 결과 판정

P2-09D는 임의의 합격 FPR 숫자를 미리 정하지 않습니다.

실제 숫자가 나오면 다음 순서로 봅니다.

1. source SHA-256이 맞는가
2. EVTX ingest가 끝까지 정상 동작하는가
3. benign 이벤트 중 몇 개가 flagged 되는가
4. 어떤 source에서 flagged가 몰리는가
5. 현재 룰 조건이 일반 관리/사용자 행동과 충돌하는가
6. 실제로 수정할 가치가 있는가

P2-09D가 끝나면 다음 단계는 **P2-09E Reproducible Benchmark**입니다.
