# P2-10C Domain Admins 4661 Remediation

## 왜 이 항목을 고쳤는가

P2-10B 이후 고정 외부 공격 baseline은 **4 HIT / 6 MISS / 10 scenario**였습니다.

남은 MISS 중 `discovery-domain-admins`는 기대 technique이 `T1087.002`였고, 샘플 안에 Windows Security Event ID 4661의 SAM group 접근 기록이 실제로 존재했습니다.

목표 이벤트의 핵심 값은 다음과 같습니다.

```text
source: Microsoft-Windows-Security-Auditing
event_id: 4661
ObjectType: SAM_GROUP
ObjectName: ...-512
ObjectServer: Security Account Manager
```

Windows 도메인 SID에서 마지막 RID `512`는 Domain Admins 그룹을 가리키므로, 이번 변경은 이름 문자열이 아니라 이 좁은 SAM group object 조건을 사용합니다.

## 변경

추가 룰:

```text
R-DOMAIN-ADMINS-4661
```

조건:

- `source == Microsoft-Windows-Security-Auditing`
- `event_id == 4661`
- `ObjectType == SAM_GROUP`
- `ObjectName` regex `-512$`
- `ObjectServer == Security Account Manager`
- ATT&CK: `T1087.002`
- severity: `low`

이번 변경은 `discovery-domain-admins` 하나를 대상으로 합니다. 다른 MISS를 같은 이유로 넓히지 않았습니다.

## benign 사전 확인

고정 benign corpus는 P2-09D와 같은 `NextronSystems/evtx-baseline v0.8.4`의 `win10-client.tgz`입니다.

```text
archive SHA-256: d48f1b328d48db6c6dfaa9b6e232dbb454d93e833c6e1248efc0faf690b6808e
```

새 룰의 source가 Security-Auditing이므로 Sysmon EVTX는 제외하고 non-Sysmon 전체를 제품 EVTX 변환 경로로 읽었습니다.

결과:

- non-Sysmon EVTX files: **351**
- events: **34,423**
- Security Event ID 4661: **0**
- `4661 + SAM_GROUP`: **0**
- `SAM_GROUP + RID -512`: **0**
- 새 룰 exact predicate match: **0**

probe:

```text
GitHub Actions run: 34235448799
```

이 값은 새 predicate에 대한 incremental 확인입니다. 현재 55-rule pack 전체를 대상으로 766,623 benign events의 FP/TN/FPR을 다시 계산한 값이 아닙니다.

## external evaluator에서 발견한 측정 버그

첫 P2-10C 공격 재측정에서는 새 룰 집중 테스트가 통과했지만 scenario 결과가 **4/10 그대로**였습니다.

원인은 룰이 아니라 `scripts/evaluate_external_holdout.py`의 Event 재구성 경로였습니다.

EVTX 변환 JSON은 EventData를 이미 다음처럼 보관합니다.

```text
converted_record["raw"]["ObjectName"]
```

그런데 evaluator는 변환된 전체 record를 다시 `Event.raw`에 넣어 실제 평가에서는 다음처럼 한 단계 더 중첩됐습니다.

```text
Event.raw["raw"]["ObjectName"]
```

제품 analyzer가 보는 구조와 evaluator가 보는 구조가 달라 raw EventData field 룰이 평가에서 사라진 것입니다.

보정은 좁게 했습니다.

- 변환 record의 `raw`가 mapping이면 그것을 `Event.raw`로 사용
- legacy flat JSONL record는 기존처럼 전체 record를 `Event.raw`로 사용

회귀 테스트도 추가했습니다.

- nested converted raw payload 재구성
- legacy flat raw 유지

## evaluator 보정 control run

새 Domain Admins 룰 없이 P2-10B의 54-rule 상태에서 evaluator 보정만 적용해 같은 공격 baseline을 다시 실행했습니다.

결과는 보정 전과 같았습니다.

- rules tree SHA-256: `a21e4a7b4ae9060e2cdbb77d4a7233c85d96fb16d4d97eeddbc27f948ad99aa1`
- rules: **54**
- scenario: **4 HIT / 6 MISS / 10**
- findings: **5**
- raw reconstruction tests: **2 PASS**

control run:

```text
GitHub Actions run: 34237083371
```

따라서 **4→5 변화는 evaluator 보정 자체가 기존 결과를 올린 것이 아니라 새 raw-field 룰이 실제 평가 경로에서 보이게 된 뒤 발생한 변화**로 구분할 수 있습니다.

## 공격 baseline 재측정

측정 commit:

```text
2bc093de022559958029933582d530be5b718c8b
```

새 rule tree SHA-256:

```text
9fff876a481f972ac88dcccb1044b38b8df22c390f74375034a72eca7a1a8fa0
```

같은 P2-09C 공개 공격 corpus 10 files / 202 events를 다시 실행했습니다.

- before: **4 HIT / 6 MISS / 10**
- after: **5 HIT / 5 MISS / 10**
- rules: **55**
- findings: **7**
- flagged events: **7**
- `discovery-domain-admins`: **MISS → HIT**
- expected technique: `T1087.002`
- detector runtime: **0.120470558 s**
- peak traced memory: **0.171333313 MB**
- focused rule tests: **6 PASS**

`discovery-domain-admins` source file은 기존 1 flagged event에서 3 flagged events가 됐습니다. 새 4661 predicate가 두 이벤트를 추가로 flag한 결과와 일치합니다.

남은 MISS는 다음 5개입니다.

```text
ca-lsass-mimikatz
lm-powershell-remoting
lm-wmi
lm-remote-service
persist-hidden-run-key
```

측정 실행:

```text
GitHub Actions run: 34238713665
artifact ID: 10061000192
artifact ZIP SHA-256: 979bcd74bbad5e9d26e035011e99e8afaf2f5c49f59d47a69ff0500a02c2a3c7
```

영구 기록:

```text
external_baseline/results/p2_10c_2bc093de/measurement.yaml
```

## evidence chain

현재 탐지 근거는 다음 순서로 이어집니다.

```text
P2-09E historical snapshot
  2/10 attack scenario hits
        ↓
P2-10A Security 4698
  3/10
        ↓
P2-10B WMIC remote XSL
  4/10
        ↓
P2-10C Domain Admins Security 4661
  5/10
```

기계 검증:

```cmd
python scripts\verify_current_detection_evidence.py
```

verifier는 각 remediation의 from/to rule hash 연결, 실제 live rule 조건, 고정 공격 corpus hash, benign incremental proof, 마지막 live `rules/` tree hash까지 확인합니다.

## 말할 수 없는 것

이번 결과로 다음을 주장하지 않습니다.

- 실제 공격 탐지율이 50%라는 주장
- production precision/recall/FPR
- 현재 55-rule pack의 fresh full benign FPR
- 기업 환경 대표성
- final blind holdout 통과

공격 corpus의 202 events는 event-level GT를 주장하지 않아 모두 `ignore`로 취급합니다. 따라서 이 공격 재측정의 event-level precision/recall/FPR은 **NOT CLAIMED**입니다.

P2-09D의 `FP=17 / TN=766,606 / FPR=0.00221752%`도 이전 P2-09E rule tree의 역사적 측정값입니다. 현재 55-rule pack의 FPR로 재사용하지 않습니다.
