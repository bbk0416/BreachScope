# P2-10H WMI 4688 Parent Correlation

## 왜 이 항목을 고쳤는가

P2-10G 이후 고정 공개 공격 baseline은 **9 HIT / 1 MISS / 10 scenario**였습니다.
남은 MISS는 `lm-wmi` 하나였고, 기대 technique은 `T1047`입니다.

샘플의 Security 4688 두 건을 확인했습니다.

- 먼저 `C:\Windows\System32\wbem\WmiPrvSE.exe`가 PID `0xae8`로 생성됨
- 약 31ms 뒤 다음 4688의 부모 `ProcessId`가 같은 `0xae8`
- 따라서 두 이벤트를 이어 보면 WMI provider host가 자식 프로세스를 만든 관계가 확인됨

자식 실행 파일 이름 `calc.exe`는 룰 조건에 넣지 않았습니다.
또 4688 관계만으로 원격 실행 자체가 증명된다고 쓰지 않습니다. `lm-wmi`의 T1047 맵핑은 고정 공개 corpus의 upstream WMI 시나리오 출처를 기준으로 합니다.

## 변경

`breachscope/analyzer.py`에서 Security 4688의 부모 PID를 같은 호스트의 앞선 4688과 연결합니다.

- 현재 이벤트의 `ProcessId`를 부모 PID로 사용
- 앞선 이벤트의 `NewProcessId`와 연결
- 같은 호스트만 연결
- 부모 이벤트가 먼저 나와야 함
- 최대 300초 이내만 인정
- 병렬 분석에서는 chunk를 나누기 전에 먼저 관계를 계산

그 결과를 내부 필드 `_breachscope.resolved_security_4688_parent_process_name`에 넣습니다.

새 룰 `R-WMI-WMIPRVSE-CHILD-4688`은 다음 조건만 봅니다.

- Security Event 4688
- source `Microsoft-Windows-Security-Auditing`
- 복원된 부모 경로가 `\wbem\WmiPrvSE.exe`로 끝남
- ATT&CK `T1047`
- severity `medium`

## 공개 공격 baseline 재측정

```text
PR code commit: 4c8c9234978051fa58995dcee05cbad9fca081c0
measurement commit: 652b7cad94af0c9eb2dab8c66931c2a258ced925
run: 34384324593
artifact ID: 10117109156
artifact digest: cb9bb8babd935bc4b6570671b18f0dbfe8edf0539ed7d02603906063e7eb5ccc
rule tree SHA-256: 371e73c4447cbce853dbdf936bdc40141bb4b0b496c11bcd63c41f8c42d0969f
analyzer blob SHA-1: f7e395ba66d3461ffed0a4c9b5b37f86ae585ff7
```

현재 evidence verifier는 위 analyzer Git blob SHA-1도 live 파일과 비교하므로, 상관관계 코드가 바뀌면 현재 evidence chain은 fail-closed합니다.

- before: **9 HIT / 1 MISS / 10**
- after: **10 HIT / 0 MISS / 10**
- rules: **60**
- findings / flagged events: **14 / 14**
- `lm-wmi`: **MISS → HIT**
- expected/observed technique: `T1047`
- events: **202**

이는 고정된 알려진 공개 공격 corpus의 scenario 결과입니다.
**실제 공격 탐지율 100%**라는 뜻이 아닙니다.

## benign incremental 확인

P2-09D에 사용한 고정 공개 benign corpus에서 non-Sysmon EVTX를 새 상관조건으로 다시 확인했습니다.

- corpus SHA-256: `d48f1b328d48db6c6dfaa9b6e232dbb454d93e833c6e1248efc0faf690b6808e`
- 전체 EVTX: **352**
- non-Sysmon EVTX: **351**
- non-Sysmon events: **34,423**
- Security 4688: **78**
- 300초 이내 부모 PID 복원: **64**
- `WmiPrvSE.exe` 부모-자식 broad matches: **0**
- `\wbem\WmiPrvSE.exe` strict matches: **0**
- parse errors: **0**
- timestamp parse errors: **0**
- run: `34384477247`
- artifact ID: `10117248190`
- artifact digest: `bc6a4ed11ef039ae57c678c08104ec58adc3bca71d11ed9a4aac5ab6b6100ff6`

이는 pinned public benign corpus에서의 **incremental exact-match 관찰값**입니다.
production false positive rate가 0이라는 뜻이 아니며, 현재 60-rule pack의 fresh full benign FPR도 아닙니다.

## 현재 공개 공격 baseline 상태

```text
P2-09E 2/10 -> P2-10A 3/10 -> P2-10B 4/10 -> P2-10C 5/10
-> P2-10D 6/10 -> P2-10E 7/10 -> P2-10F 8/10 -> P2-10G 9/10
-> P2-10H 10/10
```

## 말할 수 없는 것

이번 결과로 production precision/recall/FPR, 실제 공격 탐지율 100%, 기업 환경 대표성, final blind holdout 통과를 주장하지 않습니다.
공격 corpus는 이미 알려진 공개 corpus이며 final blind holdout이 아닙니다.
P2-09D의 `FPR=0.00221752%`는 역사적 rule tree `543b4e02...`에만 적용됩니다.
