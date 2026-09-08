# P2-10D LSASS Process Access Remediation

## 왜 이 항목을 고쳤는가

P2-10C 이후 고정 외부 공격 baseline은 **5 HIT / 5 MISS / 10 scenario**였습니다.

남은 MISS 중 `ca-lsass-mimikatz`는 기대 technique이 `T1003.001`이었고, 공격 샘플에 Sysmon Event ID 10의 LSASS process-access 기록이 실제로 존재했습니다.

목표 이벤트의 핵심 값은 다음과 같습니다.

```text
source: Microsoft-Windows-Sysmon
event_id: 10
TargetImage: ...\lsass.exe
GrantedAccess: 0x00001010
```

샘플의 실행 파일 이름은 룰 조건에 넣지 않았습니다. 이번 룰은 프로세스 이름 문자열이 아니라 **LSASS 대상 + process-access event + access mask**만 사용합니다.

## 후보 비교

같은 pinned benign Sysmon corpus를 8개 shard로 전체 스캔했습니다.

- Sysmon records: **732,200 / 732,200**
- Sysmon chunks: **11,894**
- LSASS Event 10 target: **61**
- LSASS + GrantedAccess `0x1010`: **0**
- Event 1 parent `wsmprovhost.exe`: **0**
- Run Key Event 13 SetValue: **15**

따라서 broad LSASS 접근 자체는 정상 데이터에도 존재하고, Run Key 조건도 정상 충돌이 있었습니다. P2-10D는 더 좁은 `LSASS + 0x1010` 조건만 채택했습니다.

benign probe:

```text
GitHub Actions run: 34243188619
probe commit: 05cc74869740bf393eaba5bdd2be6f3d358c0ec6
```

## 변경

추가 룰:

```text
R-LSASS-ACCESS-1010
```

조건:

- `source == Microsoft-Windows-Sysmon`
- `event_id == 10`
- `TargetImage` endswith `\lsass.exe`
- `GrantedAccess` regex `^0x0*1010$`
- ATT&CK: `T1003.001`
- severity: `medium`

`^0x0*1010$`은 샘플의 `0x00001010`과 같은 값을 `0x1010`처럼 패딩 없이 기록한 경우도 같은 access mask로 처리합니다.

## 공격 baseline 재측정

측정 commit:

```text
ce1ada8b1ddcf075e3258a7b2f2abf309ac9b034
```

새 rule tree SHA-256:

```text
f6561197677172b671646a49a84a2ff1d3cc9d661f23ee2862037ac5ca16292e
```

같은 P2-09C 공개 공격 corpus 10 files / 202 events를 다시 실행했습니다.

- before: **5 HIT / 5 MISS / 10**
- after: **6 HIT / 4 MISS / 10**
- rules: **56**
- findings: **8**
- flagged events: **8**
- `ca-lsass-mimikatz`: **MISS → HIT**
- expected technique: `T1003.001`
- focused rule tests: **6 PASS**
- detector runtime observation: **0.127926386 s**
- peak traced memory observation: **0.172901154 MB**

측정 실행:

```text
GitHub Actions run: 34244428149
artifact ID: 10063365810
artifact ZIP SHA-256: bc6b2e81c5c4f55a727f6788b537e2f6c49525fd7de2096d2ae58459a26c8c4c
```

영구 기록:

```text
external_baseline/results/p2_10d_ce1ada8b/measurement.yaml
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
        ↓
P2-10D LSASS Process Access 0x1010
  6/10
```

기계 검증:

```cmd
python scripts\verify_current_detection_evidence.py
```

verifier는 각 remediation의 from/to rule hash 연결, 실제 live rule 조건, 고정 공격 corpus hash, benign incremental proof, 마지막 live `rules/` tree hash를 확인합니다.

## 남은 MISS

```text
lm-powershell-remoting
lm-wmi
lm-remote-service
persist-hidden-run-key
```

## 말할 수 없는 것

이번 결과로 다음을 주장하지 않습니다.

- 실제 공격 탐지율이 60%라는 주장
- production precision/recall/FPR
- 현재 56-rule pack의 fresh full benign FPR
- 기업 환경 대표성
- final blind holdout 통과

공격 corpus의 202 events는 event-level GT를 주장하지 않아 모두 `ignore`로 취급합니다. 따라서 공격 재측정의 event-level precision/recall/FPR은 **NOT CLAIMED**입니다.

P2-09D의 `FP=17 / TN=766,606 / FPR=0.00221752%`는 이전 역사적 rule tree에 묶인 값입니다. 현재 56-rule pack의 FPR로 재사용하지 않습니다.
