# P2-11B Atomic-EVTX External Baseline

## 왜 이 평가를 했는가

P2-10H까지 기존 `sbousseaden/EVTX-ATTACK-SAMPLES` 10개 시나리오는 모두 HIT가 됐습니다.
하지만 같은 공개 corpus를 계속 보면서 룰을 고치면 그 10/10이 다른 데이터에서도 통하는지 알 수 없습니다.

그래서 P2-11A에서 detector를 먼저 고정한 뒤, 다른 공개 source인 `arniki/atomic-evtx`에서 새 평가 세트를 선택했습니다.

이 평가는 **final blind holdout이 아닙니다.**
source는 공개돼 있고 Atomic Red Team 기반이므로 이전 공개 공격 데이터와 attack framework 계열까지 완전히 독립적이라고 말할 수 없습니다.
따라서 평가 등급은 `external_baseline`으로 고정했습니다.

## detector freeze

```text
repo commit: 674615ef3c92d5b4bbc4dec71f566d49de0454f4
rule tree SHA-256: 371e73c4447cbce853dbdf936bdc40141bb4b0b496c11bcd63c41f8c42d0969f
rules: 60
analyzer blob SHA-1: f7e395ba66d3461ffed0a4c9b5b37f86ae585ff7
P2-10 rule file blob SHA-1: 3a2f853fd6c8232f7d919913fd711d7f18785108
```

## 결과를 보기 전에 고정한 것

source repo:

```text
arniki/atomic-evtx
commit: 8de5fa8f158b4d72d1e3c6f07053162c90ee6238
full_list_of_attacks_simulated.csv blob: 7c02b63efccc611d8e53e5173561866183f46581
manifest SHA-256: 81d3abbe3d07aa6d153fd17c5b5274137aa853e95fd489a183ed5d7230651f8e
```

선택 규칙도 결과를 보기 전에 정했습니다.

- 6개 category 고정
  - credential-access
  - defense-evasion
  - discovery
  - lateral-movement
  - execution
  - persistence
- 각 category에서 source CSV에 처음 나오는 2개 행 선택
- 총 12개 scenario
- TTP ID의 마지막 Atomic test 번호를 떼고 남은 ATT&CK ID를 scenario-level expected technique으로 사용

선택을 고정한 commit:

```text
7541214400507afddca40a22f2adb22504fc3946
```

그 뒤 선택된 12개 디렉터리의 EVTX를 내려받아 **60개 파일 전체를 SHA-256으로 고정**했습니다.

```text
byte-binding run: 34388844124
artifact ID: 10118796880
artifact SHA-256: 58ad166a8eecb9f71ba1c5510b7aa54421f3089795eabda7993972c83334116d
EVTX files: 60
bytes: 9,420,800
```

이 단계에서는 BreachScope detector를 실행하지 않았습니다.

## event-level 라벨 처리

이 source에는 우리가 독립적으로 믿을 수 있는 event-level malicious/benign 라벨이 없습니다.
따라서 event-level precision/recall/FPR을 만들기 위해 임의로 이벤트를 악성이라고 표시하지 않았습니다.

모든 이벤트는 evaluator의 `ignore` 라벨을 사용했습니다.
평가 대상은 사전에 고정한 **scenario-level expected technique**뿐입니다.

12개 scenario는 각각 별도로 index한 뒤 labels SHA-256을 고정했습니다.
12개 전부 index/label 준비가 끝난 뒤에만 detector를 실행했습니다.

## one-time external baseline 결과

```text
score plan frozen commit: cb86f4b5dbde0c517c395217e2fcf2a9a213a6cf
score workflow head: 30f67ebb8f75d642f1c37aeab1255a6051c2cd48
run: 34389538790
artifact ID: 10119080561
artifact SHA-256: 289a5384e99da9a5d9a7d0c83b4688991e9925158aab8f45c354a61d85d20ee5
aggregate result SHA-256: 89a309b8b59c5602afb4e3de1136fe53d9284463a8e409625f6a633629071a11
```

결과:

```text
scenario total: 12
HIT: 0
MISS: 12
scenario hit rate: 0.0
rules: 60
events: 902
findings: 82
flagged events: 78
```

12개 expected technique은 모두 관측되지 않았습니다.

| Scenario | Expected | Result |
|---|---|---|
| T1003-1 | T1003 | MISS |
| T1003-2 | T1003 | MISS |
| T1006-1 | T1006 | MISS |
| T1027-2 | T1027 | MISS |
| T1007-1 | T1007 | MISS |
| T1007-2 | T1007 | MISS |
| T1021.001-1 | T1021.001 | MISS |
| T1021.001-2 | T1021.001 | MISS |
| T1047-1 | T1047 | MISS |
| T1047-2 | T1047 | MISS |
| T1136.001-4 | T1136.001 | MISS |
| T1136.001-5 | T1136.001 | MISS |

반면 다른 technique findings는 있었습니다.
scenario 단위 관측 횟수는 다음과 같습니다.

```text
T1070.001: 12/12
T1021.006: 7/12
T1059.001: 2/12
T1087.001: 1/12
T1135: 1/12
```

이 값들은 event-level ground truth가 없기 때문에 정탐·오탐으로 판정하지 않습니다.
특히 source 생성 과정의 로그 정리나 주변 activity가 섞였을 가능성도 있으므로 진단용으로만 봅니다.

## 이 결과가 뜻하는 것

가장 중요한 사실은 다음입니다.

**기존 공개 공격 baseline의 10/10은 이 새 12개 외부 시나리오로 일반화되지 않았습니다.**

이것은 숨길 실패가 아니라 현재 detector의 범위를 더 정확하게 보여주는 결과입니다.
기존 10/10은 특정 고정 corpus에서의 결과였고, production 탐지율 100%라고 말하면 안 된다는 기존 claim boundary가 맞았음을 다시 확인했습니다.

다만 이번 0/12 역시 production 탐지율 0%라는 뜻은 아닙니다.
12개 public Atomic-EVTX scenario에 한정된 scenario-level 결과입니다.

## 다음 단계 규칙

이제 이 12개 결과를 이미 봤기 때문에, 이 데이터를 사용해 룰을 고치는 작업은 **새 blind 평가가 아니라 calibration**입니다.

따라서 앞으로는 다음을 지킵니다.

1. P2-11B 0/12 결과는 수정하지 않고 영구 보존
2. 이 12개를 분석·개선에 쓰면 `external_calibration`으로 명시
3. 개선 뒤 같은 12개가 좋아져도 그것을 새로운 untouched external baseline이나 final blind 결과라고 표현하지 않음
4. 다음 독립 baseline이 필요하면 또 다른 source/selection을 detector 결과 보기 전에 새로 고정

## 말할 수 없는 것

이번 결과로 다음을 주장하지 않습니다.

- production 탐지율 0% 또는 100%
- production precision / recall / FPR
- event-level false-positive rate
- 기업 환경 대표성
- final blind holdout 통과 또는 실패

P2-09D의 `0.00221752%` 역시 역사적 52-rule tree에만 적용되며 현재 60-rule detector의 FPR이 아닙니다.
