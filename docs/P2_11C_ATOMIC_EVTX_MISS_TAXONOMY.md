# P2-11C Atomic-EVTX 12 MISS 원인 분석

## 결론

P2-11B의 `0 HIT / 12 MISS`는 단일 원인으로 설명되지 않는다.

이번 단계에서 P2-11B와 동일한 12개 Atomic-EVTX 시나리오, 60개 EVTX 파일을 다시 읽어 실제 이벤트를 확인했다. 총 902개 이벤트가 파싱됐고 parser error는 0이었다. 따라서 현재 확인된 12개 MISS를 단순한 EVTX parser 실패로 설명할 근거는 없다.

가장 먼저 고칠 가치가 높은 항목은 **Security Event 4720 기반 local account creation 탐지**다. `T1136.001-4`와 `T1136.001-5` 모두 4720 이벤트가 실제로 존재하며, 이 이벤트는 실행 도구나 Atomic 테스트 이름에 의존하지 않고 계정 생성 자체를 기록한다.

그 다음 후보는 서비스 탐색(`T1007`), raw-volume access(`T1006`)다. WMI query와 RDP client 실행은 로그에는 분명히 보이지만 정상 관리 작업과 겹칠 가능성이 커서 benign 비교가 먼저 필요하다.

## 분석 범위

- 분석 등급: `external_calibration`
- 기준 main commit: `ff279db1593bee8fd6f4d247de3670e86eaa574b`
- P2-11B에서 사용한 frozen detector: `674615ef3c92d5b4bbc4dec71f566d49de0454f4`
- frozen rule tree SHA-256: `371e73c4447cbce853dbdf936bdc40141bb4b0b496c11bcd63c41f8c42d0969f`
- source: `arniki/atomic-evtx`
- pinned source commit: `8de5fa8f158b4d72d1e3c6f07053162c90ee6238`
- P2-11B aggregate result SHA-256: `89a309b8b59c5602afb4e3de1136fe53d9284463a8e409625f6a633629071a11`
- P2-11C probe run: `34431613536`
- probe artifact ID: `10134693051`
- probe artifact digest SHA-256: `8cc51f57ffa87c7cff484395e634d83a52fc6372530fbae327464f275ab787b7`
- parsed events: 902
- parse errors: 0

이 분석은 이미 결과가 공개된 P2-11B 12개 시나리오를 다시 본 것이다. 따라서 여기서 얻은 정보를 이용한 이후의 수정과 재실행은 `external_calibration`이다.

## 12개 MISS 분류

| 시나리오 | 실제 관측 근거 | 원인 | 판단 |
|---|---|---|---|
| `T1003-1` | Sysmon 1: `gsecdump.exe -a` 실행 | 현재 직접 근거가 도구 이름 중심 | **보류** |
| `T1003-2` | Sysmon 1: NPPSpy DLL/NetworkProvider 설정 PowerShell | 명령 안에는 근거가 있으나 NPPSpy 설정에 강하게 묶임. 이 캡처에는 Sysmon 13 없음 | **보류** |
| `T1006-1` | Sysmon 1: PowerShell `IO.FileStream`으로 `\\.\C:` raw-volume read | T1006 rule 없음 | **후보** |
| `T1027-2` | Sysmon 1: 실제 `powershell.exe -EncodedCommand ...` | 기존 rule은 이를 `T1059.001`로 탐지. P2-11B 기대값은 `T1027` | **매핑 검토** |
| `T1007-1` | Sysmon 1: `sc.exe query`, `sc.exe query state= all` | T1007 rule 없음 | **우선 후보** |
| `T1007-2` | Sysmon 1: `net.exe start`, `net1.exe start` | T1007 rule 없음 | **우선 후보** |
| `T1021.001-1` | Sysmon 1: `cmdkey /generic:TERMSRV/...`, `mstsc.exe /v:` | 기존 T1021.001 rule은 RDP enable/config 쪽만 봄 | **후보지만 소음 주의** |
| `T1021.001-2` | Sysmon 1: RDP-Tcp `PortNumber=4489`, firewall 4489 설정 | 로그는 RDP 설정 변경을 증명하지만 실제 RDP session 사용은 증명하지 않음 | **보류** |
| `T1047-1` | Sysmon 1: `WMIC.exe useraccount get /ALL /format:csv` | 기존 T1047 rule은 create/XSL/WmiPrvSE-child 형태만 봄 | **후보지만 소음 주의** |
| `T1047-2` | Sysmon 1: `WMIC.exe process get ... /format:csv` | 일반 WMI query가 current rule 범위 밖 | **후보지만 소음 주의** |
| `T1136.001-4` | Security 4720 + Sysmon `net user /add` | 직접 계정 생성 이벤트가 있으나 T1136.001 rule 없음 | **최우선 후보** |
| `T1136.001-5` | Security 4720 + Sysmon `New-LocalUser` | 직접 계정 생성 이벤트가 있으나 T1136.001 rule 없음 | **최우선 후보** |

## 무엇부터 손댈지

1. **Security 4720 → T1136.001**
   - 두 시나리오를 하나의 일반적인 Windows 이벤트 조건으로 설명할 수 있다.
   - `net.exe`, PowerShell, 계정 이름 등 실행 방식과 샘플 문자열을 하드코딩할 필요가 없다.
   - 실제 추가 전 pinned public benign corpus에서 4720 빈도를 먼저 센다.

2. **Service discovery → T1007**
   - `sc query`와 `net start`가 실제 command line에 존재한다.
   - 정상 관리자도 쓸 수 있으므로 benign 빈도와 표현을 먼저 비교한다.

3. **Raw-volume read → T1006**
   - PowerShell command line에 device-path read가 명확하다.
   - Atomic 전용 문자열이 아닌 일반적인 raw-volume access 의미로 좁힐 수 있는지 benign과 비교한다.

4. **Encoded PowerShell → T1027 매핑 검토**
   - 이미 `T1059.001` 탐지는 동작했다.
   - 점수를 맞추기 위해 기존 매핑을 바꾸면 안 된다.
   - 독립적으로 정당화되는 경우에만 같은 행위에 추가 ATT&CK tag를 줄지 검토한다.

5. **WMIC query / mstsc 실행**
   - 실제 technique 사용 흔적은 있으나 정상 관리 작업과 겹칠 가능성이 높다.
   - 빈도가 높으면 탐지 rule보다는 저위험 technique telemetry로 취급하는 편이 맞을 수 있다.

## 이번 단계에서 추가하지 않을 것

`T1003-1`을 맞히기 위해 `gsecdump` 문자열만 추가하지 않는다. `T1003-2`도 `NPPSpy` 문자열만 추가하지 않는다. 이런 방식은 새 공개 corpus에 맞춰 이름을 외우는 것에 가깝다.

`T1021.001-2`는 RDP port 변경과 firewall 변경은 보이지만 실제 RDP 연결을 직접 보여주지 않는다. 이 한 시나리오의 점수를 올리기 위해 무조건 `T1021.001` hit로 만들지 않는다.

## P2-11B 기록은 바꾸지 않는다

P2-11B의 결과는 계속 **`0 HIT / 12 MISS`**다. P2-11C 이후 같은 12개를 다시 실행해 결과가 좋아지더라도 그것은 calibration 결과다. P2-11B를 소급해서 수정하거나 새 blind baseline처럼 표현하지 않는다.

또한 이 데이터에는 독립적인 event-level malicious/benign label이 없다. 따라서 event-level precision, recall, FPR 및 production detection rate는 주장하지 않는다.

기계 판독 가능한 전체 분류는 `external_baseline/p2_11c_atomic_miss_taxonomy.json`에 기록한다.
