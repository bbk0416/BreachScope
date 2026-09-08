# P2-10A Scheduled Task Remediation

## 왜 이 항목을 먼저 고쳤는가

P2-09C 외부 공격 baseline에서 `exec-scheduled-task`는 Security Event ID 4698/4699를 포함했지만 기존 `R-SCHTASKS-Create` 룰은 `command_line`의 `schtasks /create`만 봐서 `T1053.005`를 놓쳤습니다.

P2-10 시작 전 pinned benign corpus를 먼저 확인했습니다.

- 전체 non-Sysmon EVTX: **351 files / 34,423 events**
- `Microsoft-Windows-Security-Auditing + 4698`: **0 events**
- `Microsoft-Windows-Security-Auditing + 4699`: **0 events**
- `Service Control Manager + 7045`: **26 events**

따라서 generic 7045 service-install detection은 먼저 넣지 않았습니다. 실제 benign 7045에는 Intel driver, Edge elevation service, print service, VirtualBox driver 같은 정상 설치/서비스 이벤트가 포함되어 있었습니다.

## 변경

추가 룰:

```text
R-SCHTASK-4698
```

조건:

- `event_id == 4698`
- `source == Microsoft-Windows-Security-Auditing`
- ATT&CK: `T1053.005`
- severity: `low`

기존 command-line 룰 `R-SCHTASKS-Create`는 그대로 유지합니다.

4699 삭제 이벤트는 새 룰에 포함하지 않습니다. P2-09C의 실제 miss를 해결하는 데 필요하지 않고, Scheduled Task 생성과 삭제를 같은 탐지 의미로 묶지 않기 위해서입니다.

## 실제 측정

측정 commit:

```text
b198604cf24f3537938f963b525aebdb0670d584
```

새 rule tree SHA-256:

```text
8ade507d0abf4a0495b44cde4268245dab8c5f9d58d2eb5b47ebee8b7a5de185
```

GitHub Actions run:

```text
34216569909
```

artifact:

```text
ID: 10052084903
SHA-256: bb00edad756b75a6b00a6a1d8bcfb59fe266e738f606339aca2e7a027277fa5d
```

### Attack-side

같은 pinned P2-09C 공격 corpus를 다시 실행했습니다.

- before: **2 HIT / 8 MISS / 10**
- after: **3 HIT / 7 MISS / 10**
- findings: **3 → 4**
- `exec-scheduled-task`: **MISS → HIT**
- expected technique: `T1053.005`

이 숫자는 실제 공격 전체의 탐지율 또는 precision/recall을 뜻하지 않습니다.

### Benign-side incremental proof

같은 pinned `NextronSystems/evtx-baseline v0.8.4` archive를 SHA-256으로 다시 확인한 뒤 Sysmon을 제외한 모든 EVTX를 실제 parser로 읽었습니다.

- source files scanned: **351**
- events scanned: **34,423**
- exact new predicate matches: **0**

P2-09D에서 Sysmon Operational source는 **732,200 events**였습니다. 새 룰은 `source == Microsoft-Windows-Security-Auditing`을 요구하므로 Sysmon provider를 대상으로 하지 않습니다.

이번 변경 후 전체 766,623 events를 새 룰팩으로 다시 점수화해 FP/TN/FPR을 새로 계산한 것은 아닙니다. 따라서 **새 rulepack의 fresh full benign FPR은 주장하지 않습니다.**

## evidence chain

P2-09E는 rule hash `543b4e02...`의 역사적 snapshot으로 그대로 남깁니다.

현재 rulepack까지 연결하는 파일:

```text
external_baseline/current_detection_evidence.yaml
external_baseline/results/p2_10a_b198604c/measurement.yaml
```

검증:

```cmd
python scripts\verify_current_detection_evidence.py
```

기존 P2-09E verifier가 새 rule hash에서 실패하는 것은 의도된 동작입니다. 설명되지 않은 rule drift를 조용히 허용하지 않기 위해서입니다.
