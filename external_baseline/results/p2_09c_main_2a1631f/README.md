# P2-09C measured external baseline

이 디렉터리는 P2-09C runner 자체가 아니라 **실제로 측정한 결과**를 기록합니다.

## 측정 대상

- evaluated commit: `2a1631f6633ee40dcc47524675dc9dbda541e01d`
- rules tree SHA-256: `543b4e02ebb48d5e33eeb4405a6d489487a05d07ffebda4ba31206a059dae3ce`
- corpus: pinned `sbousseaden/EVTX-ATTACK-SAMPLES` 10 files
- upstream commit: `4ceed2f4706daf601c212a8f91c113dd85349a2c`
- evaluation class: `external_baseline`
- final blind holdout: **NO**

공개되어 있고 프로젝트가 이미 알고 있는 공격 corpus이므로 이 결과를 production detection accuracy나 final blind holdout으로 표현하면 안 됩니다.

## 실제 결과

- scenarios: **2 HIT / 8 MISS / 10 total**
- scenario hit rate: **20.0%**
- findings: **3**
- converted events: **202**
- event-level labels: **202 ignore**
- event-level precision / recall / FPR: **NOT CLAIMED**

HIT:

- `T1070.001` — Windows Security log clearing
- `T1218.010` — Regsvr32 proxy execution

MISS:

- `T1003.001` — LSASS credential dumping
- `T1053.005` — Scheduled Task
- `T1047` — WMI execution (2 scenarios)
- `T1021.006` — PowerShell Remoting / WinRM
- `T1569.002` — Service Execution
- `T1547.001` — Registry Run Keys / Startup Folder
- `T1087.002` — Domain Account Discovery

## 재현성 확인

같은 merged main commit을 GitHub Actions에서 두 번 독립 실행했습니다.

- run `34197507789`
- run `34197718156`

두 실행에서 다음 값은 모두 같았습니다.

- evaluated repo commit
- rules tree hash
- corpus manifest/labels hash
- 10 source SHA-256
- 2 HIT / 8 MISS
- findings 3
- 모든 scenario outcome

실행시간만 약 `0.1017s`와 `0.0902s`로 달랐습니다. 이 값은 P2-09C 탐지 단계의 관찰값일 뿐이며 성능 benchmark로 사용하지 않습니다.

## MISS 원인 확인

두 번째 실행에서는 detector 실행 전 `event_index.jsonl`도 별도로 확인했습니다. 아래 내용은 그 index와 현재 native rule을 대조한 결과입니다.

| Scenario | 외부 EVTX에서 확인한 canonical telemetry | 현재 rule 형태 | 판단 |
| --- | --- | --- | --- |
| LSASS / `T1003.001` | Sysmon Event 10, canonical `command_line` 없음 | `command_line`에서 `lsass.exe`, `sekurlsa::logonpasswords` 등을 검색 | **event-field coverage gap** |
| Scheduled Task / `T1053.005` | Security 4698/4699, `command_line` 없음 | `command_line`에서 `schtasks /create` 검색 | **event-based coverage gap** |
| WMI XSL / `T1047` | Sysmon command line에 `wmic process list /format:<url>` 존재 | `wmic process call create`만 검색 | **rule pattern too narrow** |
| PowerShell Remoting / `T1021.006` | Sysmon 1의 canonical command line은 `HOSTNAME.EXE` | `enter-pssession`, `invoke-command`, `winrs`, `winrm invoke` 검색 | **process-context coverage gap** |
| WMI lateral / `T1047` | Security 4624/4688, canonical `command_line` 없음 | WMI rule은 `command_line` 문자열 검색 | **event/context coverage gap** |
| Remote Service / `T1569.002` | System 7045, `command_line` 없음 | `command_line`에서 PsExec/PAExec/Admin$ 계열 검색 | **service-event coverage gap** |
| Run Key / `T1547.001` | Sysmon 13, canonical `command_line` 없음 | `command_line`에서 `reg add ...\\Run` 검색 | **registry-event coverage gap** |
| Domain Admins / `T1087.002` | Security 4661 중심, `command_line` 없음 | `command_line`에서 ADFind 계열 검색 | **object-access/event coverage gap** |

즉 이번 8개 MISS를 단순히 “ATT&CK technique rule이 없다”고 보면 틀립니다. 현재 룰셋은 해당 technique ID를 상당수 갖고 있지만 **명령줄 패턴에 많이 의존**하고 있어, Windows Event ID와 이벤트별 필드 자체가 증거인 외부 EVTX에서 놓치는 경우가 많았습니다.

`discovery-domain-admins` 샘플에는 Security 1102도 1건 포함되어 있어 `T1070.001` finding이 추가로 관찰됐습니다. 이 데이터의 모든 이벤트는 `ignore`이므로 이것을 false positive라고 부를 근거는 없습니다.

## 해석 경계

이 결과로 말할 수 있는 것은 하나입니다.

> 현재 52-rule 상태의 BreachScope를 이 고정된 공개 외부 공격 세트에 그대로 적용했을 때, 기대 ATT&CK scenario 10개 중 2개를 hit했다.

다음은 말할 수 없습니다.

- 실제 공격 전체의 탐지율이 20%다
- precision/recall이 20%다
- 실제 Windows 환경에서 false-positive rate가 낮다
- production detection quality가 검증됐다

P2-09C에서는 이 결과를 보고 탐지 룰을 수정하지 않습니다. 다음 단계는 **P2-09D real benign baseline**입니다.
