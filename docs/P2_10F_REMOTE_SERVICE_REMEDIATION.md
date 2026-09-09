# P2-10F Pathless Service Executable Remediation

## 왜 이 항목을 고쳤는가

P2-10E 이후 고정 외부 공격 baseline은 **7 HIT / 3 MISS / 10 scenario**였습니다.

남은 MISS 중 `lm-remote-service`의 기대 technique은 `T1569.002`였고, 공개 공격 샘플 `LM_Remote_Service02_7045.evtx`에는 Service Control Manager Event ID 7045가 3건 존재했습니다.

핵심 값은 다음과 같습니다.

```text
source: Service Control Manager
event_id: 7045
ServiceName: spoolfool / spoolsv / remotesvc
ImagePath: cmd.exe / cmd.exe / calc.exe
ServiceType: user mode service
StartType: auto start
AccountName: LocalSystem
```

`ServiceName`, `cmd.exe`, `calc.exe`는 룰 조건에 넣지 않았습니다. 특정 공개 샘플 문자열에 맞추지 않기 위해, `ImagePath`의 첫 실행 파일이 경로 구분자나 드라이브 문자가 없는 pathless executable인 경우만 사용했습니다.

또한 Event ID 7045만으로 서비스가 원격에서 생성됐다고 확정할 수 없습니다. 이 룰은 **Service Control Manager 7045에서 pathless executable을 사용하는 서비스 설치**를 탐지하며, 공개 corpus 시나리오의 기대 technique인 `T1569.002`에 매핑합니다.

## 변경

추가 룰:

```text
R-SERVICE-PATHLESS-7045
```

조건:

- `source == Service Control Manager`
- `event_id == 7045`
- `ImagePath` regex:

```text
^\s*(?:\x22[^\x22\\/:]+\.exe\x22|[^\\/: \t]+\.exe)(?:\s+.*)?$
```

- ATT&CK: `T1569.002`
- severity: `medium`

이 regex는 다음을 허용합니다.

```text
cmd.exe
cmd.exe /c whoami
"calc.exe"
```

다음처럼 경로가 명시된 실행 파일은 제외합니다.

```text
C:\Windows\System32\cmd.exe
"C:\Windows\System32\cmd.exe" /c whoami
\\server\share\svc.exe
```

## 공격 baseline 재측정

P2-10F detector/rule content를 고정한 PR code commit:

```text
cd39a667d1b97f38a88b5cd980a21d3539a0b33c
```

공식 GitHub Actions 측정 commit:

```text
851214ffb9f31862c1d25aa1f93dd158e6ea8d09
```

측정 commit은 위 PR code commit과 같은 detector/rule content를 사용하고 측정 workflow만 추가했습니다.

공식 canonical rule tree SHA-256:

```text
af3b2db0fcef1a74a2728483a7db2b8df028f91be205448a03285a2a58ed960e
```

`rules/p2_10_event_rules.yml` Git blob SHA-1:

```text
e834658e354070d97a2def28e8f82474cee280e9
```

같은 P2-09C 공개 공격 corpus 10 files / 202 events를 다시 실행했습니다.

- before: **7 HIT / 3 MISS / 10**
- after: **8 HIT / 2 MISS / 10**
- rules: **58**
- findings: **12**
- flagged events: **12**
- `lm-remote-service`: **MISS → HIT**
- expected/observed technique: `T1569.002`
- focused P2-10F rule tests: **8 PASS**
- P2-10A..F focused tests: **36 PASS** (로컬 관찰)
- detector runtime observation: **0.11079527000000411 s**
- peak traced memory observation: **0.17452621459960938 MB**

측정 실행:

```text
GitHub Actions run: 34374215028
artifact ID: 10113166748
artifact ZIP SHA-256: d966599fabb86cba6867cdf5682bbc0a19bf500ad1074bf1720309d330ba9e96
```

영구 기록:

```text
external_baseline/results/p2_10f_851214ff/measurement.yaml
```

## benign incremental 확인

같은 P2-09D pinned public benign corpus를 새 predicate 관점에서 확인했습니다.

- corpus archive SHA-256: `d48f1b328d48db6c6dfaa9b6e232dbb454d93e833c6e1248efc0faf690b6808e`
- EVTX files: **352**
- total events: **766,623**
- Service Control Manager Event ID 7045: **26**
- pathless `ImagePath` matches: **0**
- exact new-predicate matches: **0**
- parse errors: **0**
- fresh full FP/TN rerun: **false**

이 값은 새 predicate에 대한 **pinned public benign corpus의 incremental exact-match 관찰값**입니다. production false positive rate가 0이라는 뜻이 아니며, 현재 58-rule pack 전체의 fresh benign FPR도 아닙니다.

## evidence chain

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
        ↓
P2-10D LSASS Process Access 0x1010
  6/10
        ↓
P2-10E WinRM wsmprovhost child
  7/10
        ↓
P2-10F SCM 7045 pathless service executable
  8/10
```

기계 검증:

```cmd
python scripts\verify_current_detection_evidence.py
```

## 남은 MISS

```text
lm-wmi
persist-hidden-run-key
```

## 말할 수 없는 것

이번 결과로 다음을 주장하지 않습니다.

- 실제 공격 탐지율이 80%라는 주장
- production precision/recall/FPR
- 현재 58-rule pack의 fresh full benign FPR
- Event ID 7045가 원격 서비스 생성을 직접 증명한다는 주장
- pathless service executable이 항상 악성이라는 주장
- 기업 환경 대표성
- final blind holdout 통과

공격 corpus는 이미 알려진 공개 corpus이며 final blind holdout이 아닙니다.

P2-09D의 `FP=17 / TN=766,606 / FPR=0.00221752%`는 역사적 rule tree `543b4e02...`에만 적용되는 공개 benign corpus 관찰값입니다. 현재 58-rule pack의 FPR로 재사용하지 않습니다.
