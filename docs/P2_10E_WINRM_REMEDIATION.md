# P2-10E WinRM wsmprovhost Child Process Remediation

## 왜 이 항목을 고쳤는가

P2-10D 이후 고정 외부 공격 baseline은 **6 HIT / 4 MISS / 10 scenario**였습니다.

남은 MISS 중 `lm-powershell-remoting`의 기대 technique은 `T1021.006`이었고, 공개 공격 샘플에는 Sysmon Event ID 1에서 `wsmprovhost.exe`가 부모 프로세스인 기록이 실제로 존재했습니다.

목표 이벤트의 핵심 값은 다음과 같습니다.

```text
source: Microsoft-Windows-Sysmon
event_id: 1
Image: C:\Windows\System32\HOSTNAME.EXE
ParentImage: C:\Windows\System32\wsmprovhost.exe
ParentCommandLine: C:\Windows\system32\wsmprovhost.exe -Embedding
```

자식 프로세스 이름 `HOSTNAME.EXE`는 룰 조건에 넣지 않았습니다. 특정 샘플 문자열에 맞추지 않고, Sysmon process creation에서 `wsmprovhost.exe`가 parent인 조건만 사용했습니다.

`wsmprovhost.exe`는 정상 WinRM 관리 작업에서도 사용될 수 있습니다. 따라서 이 룰은 PowerShell Remoting을 확정하는 직접 증거라기보다 **WinRM provider host가 자식 프로세스를 만든 행위**를 탐지하는 좁은 신호로 해석해야 합니다.

## 변경

추가 룰:

```text
R-WINRM-WSMPROVHOST-CHILD
```

조건:

- `source == Microsoft-Windows-Sysmon`
- `event_id == 1`
- `ParentImage` endswith `\wsmprovhost.exe`
- ATT&CK: `T1021.006`
- severity: `medium`

## 공격 baseline 재측정

공식 GitHub Actions 측정 commit:

```text
147a92083f8c7c8acb488b1c2aab30971d0e48bb
```

공식 canonical rule tree SHA-256:

```text
73b0571509f261ce415d8c5c3a325fc04accd309f1f30bbce30464b08728d59c
```

같은 P2-09C 공개 공격 corpus 10 files / 202 events를 다시 실행했습니다.

- before: **6 HIT / 4 MISS / 10**
- after: **7 HIT / 3 MISS / 10**
- rules: **57**
- findings: **9**
- flagged events: **9**
- `lm-powershell-remoting`: **MISS → HIT**
- expected technique: `T1021.006`
- focused rule tests: **5 PASS**
- detector runtime observation: **0.136122188 s**
- peak traced memory observation: **0.173435211 MB**

측정 실행:

```text
GitHub Actions run: 34342646853
artifact ID: 10100380267
artifact ZIP SHA-256: cc49a50bdf5014a15a4e81cce20e4870e374e494c65f02b8b3fa2718cf97179b
```

영구 기록:

```text
external_baseline/results/p2_10e_147a9208/measurement.yaml
```

## benign incremental 확인

같은 P2-09D pinned public benign corpus의 Sysmon records 전체를 새 predicate 기준으로 확인했습니다.

- corpus total events: **766,623**
- Sysmon records: **732,200**
- Sysmon Event ID 1: **2,149**
- exact new-predicate match: **0**
- parse errors: **0**
- fresh full FP/TN rerun: **false**

이 값은 새 predicate의 **incremental exact-match 관찰값**입니다. 현재 57-rule pack 전체의 fresh benign FPR을 뜻하지 않습니다.

## rule tree hash의 Windows/Linux 차이

초기 Windows 작업트리에서는 같은 룰 내용이 CRLF로 체크아웃되어 raw rule tree SHA-256이 다음 값으로 계산됐습니다.

```text
da9abfc4326c74d9e479f1262233cbb601317321b966dbb47c81053798d6f9d1
```

GitHub Actions Linux checkout에서는 LF 기준으로 다음 값이 나왔습니다.

```text
73b0571509f261ce415d8c5c3a325fc04accd309f1f30bbce30464b08728d59c
```

두 값의 차이는 줄바꿈 때문이었습니다. Windows에서 rule YAML의 CRLF/CR을 LF로 정규화해 계산했을 때 GitHub Actions 값과 정확히 일치했습니다.

이후 rule tree hash 계산은 YAML 파일의 줄바꿈을 LF로 정규화한 뒤 계산하도록 수정했습니다. 따라서 현재 canonical rule tree SHA-256은 OS와 관계없이 다음 값입니다.

```text
73b0571509f261ce415d8c5c3a325fc04accd309f1f30bbce30464b08728d59c
```

개별 룰 파일의 Git blob은 측정 후 변경하지 않았습니다.

```text
rules/p2_10_event_rules.yml blob:
479970f5fdbaca6c49d0627aaa91e84a03c1db64
```

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
```

기계 검증:

```cmd
python scripts\verify_current_detection_evidence.py
```

## 남은 MISS

```text
lm-wmi
lm-remote-service
persist-hidden-run-key
```

## 말할 수 없는 것

이번 결과로 다음을 주장하지 않습니다.

- 실제 공격 탐지율이 70%라는 주장
- production precision/recall/FPR
- 현재 57-rule pack의 fresh full benign FPR
- `wsmprovhost.exe` child process가 항상 PowerShell Remoting이라는 주장
- 기업 환경 대표성
- final blind holdout 통과

공격 corpus는 이미 알려진 공개 corpus이며 final blind holdout이 아닙니다.

P2-09D의 `FP=17 / TN=766,606 / FPR=0.00221752%`는 역사적 rule tree `543b4e02...`에만 적용되는 공개 benign corpus 관찰값입니다. 현재 57-rule pack의 FPR로 재사용하지 않습니다.
