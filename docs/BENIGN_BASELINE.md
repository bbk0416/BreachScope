# P2-09D Real Benign Baseline

## 목적

P2-09D는 BreachScope가 **정상 Windows 로그에서 얼마나 자주 탐지를 내는지** 측정합니다.

P2-09C가 공개 공격 샘플에서 어떤 ATT&CK 기법을 잡는지 확인했다면, P2-09D는 반대로 goodware/일반 사용자 활동 로그에서 발생하는 오탐을 봅니다.

이 단계에서도 탐지 룰을 먼저 고치지 않습니다. 현재 상태를 그대로 측정하고, 결과가 실제 개발 우선순위를 바꿀 때만 다음 변경을 합니다.

## 고정된 benign 소스

P2-09D v1은 다음 공개 자료를 사용합니다.

- Repository: `NextronSystems/evtx-baseline`
- Release: `v0.8.4`
- Release asset: `win10-client.tgz`
- Asset ID: `371540503`
- Size: `70,844,052 bytes`
- SHA-256: `d48f1b328d48db6c6dfaa9b6e232dbb454d93e833c6e1248efc0faf690b6808e`
- License: `Apache-2.0`

Upstream은 이 저장소를 소프트웨어 설치와 기본 사용자 활동을 포함한 **goodware EVTX baseline**으로 설명합니다.

소스 계약은 `external_baseline/p2_09d_benign_sources.yaml`에 고정합니다.

## 라벨 기준

P2-09D v1의 라벨 방식은 `benign_by_source_intent`입니다.

뜻은 단순합니다.

- 이 자료는 upstream에서 goodware/user-activity baseline으로 만들어졌습니다.
- BreachScope 결과를 본 뒤 정상/악성을 골라낸 자료가 아닙니다.
- 따라서 이 baseline에 포함된 이벤트는 전부 `benign`으로 점수 계산합니다.
- 다만 각 이벤트를 사람이 하나씩 다시 판정한 것은 아닙니다.

이 차이를 숨기지 않습니다.

## 주 지표

기존 `scripts/evaluate_external_holdout.py`의 confusion matrix를 그대로 사용합니다.

- `FP`: benign 이벤트인데 BreachScope가 하나 이상의 finding을 낸 이벤트
- `TN`: benign 이벤트이고 finding이 없는 이벤트
- `FPR = FP / (FP + TN)`

추가로 다음 값을 기록합니다.

- 전체 benign 이벤트 수
- 전체 EVTX 파일 수
- finding 수
- flagged event 수
- 이벤트 1,000개당 flagged event 수
- 이벤트 1,000개당 finding 수
- source EVTX별 event/flagged 수
- 실행 시간
- peak memory

## 이 결과가 의미하지 않는 것

P2-09D의 숫자를 다음처럼 표현하면 안 됩니다.

- production false-positive rate
- enterprise-wide false-positive rate
- 모든 Windows 환경의 정상 로그 대표값
- SOC 운영 환경에서의 최종 alert quality
- final blind holdout

이 baseline은 **고정된 공개 goodware corpus 한 개에서의 오탐 관찰값**입니다.

실제 기업 환경은 설치 프로그램, 관리 도구, 사용자 행동, 감사 정책, Sysmon 설정이 모두 다릅니다.

## 원본 데이터 취급

외부 원본 archive와 EVTX는 저장소에 commit하지 않습니다.

기본 실행 위치는 다음과 같습니다.

```text
out/external_baseline/p2_09d/
```

runner는 다음을 수행합니다.

1. 현재 repository commit과 rule tree freeze
2. `win10-client.tgz` 다운로드
3. archive size와 SHA-256 확인
4. archive 내부의 EVTX만 안전한 경로로 추출
5. 각 EVTX SHA-256 계산
6. 기존 external holdout manifest 생성
7. detector 실행 전 event index 생성
8. 모든 event를 `benign_by_source_intent`로 라벨링
9. 기존 evaluator로 score
10. FPR와 source별 flagged 통계 생성

archive path traversal은 거부합니다.

## recipe만 확인

네트워크와 detection을 사용하지 않고 source pin 형식만 검사합니다.

Windows CMD:

```cmd
python scripts\run_benign_baseline.py --validate-only
```

정상 출력의 핵심은 다음과 같습니다.

```text
P2-09D source recipe: PASS
Network access: NOT USED
Detection rules executed: NO
```

## 전체 baseline 실행

Windows CMD:

```cmd
python scripts\run_benign_baseline.py
```

기본 네트워크 timeout은 120초입니다. 필요하면 변경할 수 있습니다.

```cmd
python scripts\run_benign_baseline.py --timeout 300
```

## 생성 파일

```text
out/external_baseline/p2_09d/
```

주요 파일:

- `raw/win10-client.tgz`: 검증된 upstream archive
- `corpus/`: archive에서 추출한 EVTX
- `rules_freeze.json`: 평가한 repository/rule 상태
- `manifest.yaml`: EVTX별 SHA-256과 source provenance
- `event_index.jsonl`: detection 실행 전 event index
- `labels_benign.jsonl`: benign-by-source-intent label
- `result.json`: 기존 evaluator의 원본 결과
- `summary.json`: P2-09D 해석 경계를 포함한 요약
- `SUMMARY.md`: 사람이 읽기 쉬운 오탐 요약

원본 archive/EVTX는 `out/` 아래에만 두고 저장소에 재배포하지 않습니다.

## 결과 판정

P2-09D는 임의의 합격 FPR 숫자를 미리 만들지 않습니다.

먼저 실제 숫자를 기록한 뒤 다음 순서로 봅니다.

1. source SHA-256이 맞는가
2. EVTX ingest가 끝까지 정상 동작하는가
3. benign 이벤트 중 몇 개가 flagged 되는가
4. 어떤 source EVTX에서 flagged가 몰리는가
5. 현재 룰의 조건이 일반 관리/사용자 행동과 충돌하는가
6. 그 문제가 실제로 수정할 가치가 있는가

오탐이 발견되면 그때 처음 룰 수정 후보가 생깁니다.

P2-09D가 끝나면 다음 단계는 **P2-09E Reproducible Benchmark**입니다.
