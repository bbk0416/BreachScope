# P2-10G Hidden Run/RunOnce Value Remediation

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
- aggregate artifact SHA-256: `b44ce8fb3c50da7440b6dcaa6a5c22f408a9650db02cfe63e21ddf3a0df2a39d`

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