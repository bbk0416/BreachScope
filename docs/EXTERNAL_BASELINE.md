# P2-09C 외부 공격 baseline

## 목적

P2-09C는 BreachScope의 현재 룰셋을 공개 외부 Windows 공격 샘플에 그대로 적용해 **어떤 ATT&CK 기법을 잡고 어떤 기법을 놓치는지** 기록합니다.

이 단계에서 탐지 룰을 고치지 않습니다. 미탐도 결과 그대로 남깁니다.

## 이 결과가 의미하는 것

주 지표는 **scenario expected-technique hit rate**입니다.

예를 들어 한 EVTX 샘플이 `T1003.001`을 나타내는 것으로 upstream에서 식별되어 있고, BreachScope가 그 파일 안의 이벤트 중 하나 이상에서 `T1003.001` 탐지를 내면 해당 scenario를 `hit`으로 기록합니다.

반대로 기대한 기법이 한 번도 나오지 않으면 `miss`입니다.

## 이 결과가 의미하지 않는 것

이 데이터는 공개되어 있고 프로젝트가 이미 알고 있는 corpus입니다. 따라서 다음을 주장하면 안 됩니다.

- final blind holdout
- production detection accuracy
- event-level precision / recall
- real-world false-positive rate
- enterprise Windows 환경 검증

공개 공격 EVTX 파일 안에는 공격 이벤트 외의 주변 이벤트도 들어갈 수 있습니다. 그래서 P2-09C는 각 이벤트를 임의로 `malicious`로 표시하지 않고 전부 `ignore`로 둡니다.

**실제 benign 로그의 오탐률은 P2-09D에서 별도로 측정합니다.**

## 고정된 소스

소스 정의는 `external_baseline/p2_09c_sources.yaml`에 있습니다.

P2-09C v1 실행 세트는 다음 공개 저장소의 특정 commit과 Git blob을 고정합니다.

- `sbousseaden/EVTX-ATTACK-SAMPLES`
- commit `4ceed2f4706daf601c212a8f91c113dd85349a2c`
- 10개 EVTX 샘플
- 각 파일의 경로, 파일 크기, Git blob SHA-1을 recipe에 고정
- 다운로드 후 SHA-256을 계산해 실제 평가 manifest와 결과에 기록

`OTRF/Security-Datasets`도 provider commit은 고정했지만 P2-09C v1 실행 세트에는 포함하지 않습니다. 현재 단계에서 원본 ZIP의 바이트 체크섬을 동일한 수준으로 미리 고정하지 못했기 때문입니다. 체크섬 없이 자동으로 최신 데이터를 가져오지는 않습니다.

## 원본 데이터 취급

BreachScope 저장소에는 외부 원본 EVTX를 넣지 않습니다.

실행기가 upstream에서 직접 내려받아 다음 ignored 경로에 둡니다.

```text
out/external_baseline/p2_09c/corpus/
```

외부 데이터 사용 조건은 각 upstream 저장소의 현재 조건을 따라야 합니다. BreachScope는 해당 원본을 재배포하지 않습니다.

## 실행 전 조건

기존 `scripts/evaluate_external_holdout.py`가 룰 상태를 고정할 때 Git working tree가 깨끗해야 합니다.

따라서 실제 baseline은 병합된 commit 또는 깨끗한 평가 branch에서 실행합니다.

## recipe만 확인

네트워크를 사용하지 않고 소스 고정값과 형식을 검사합니다.

```cmd
python scripts\run_external_baseline.py --validate-only
```

정상 출력의 핵심은 다음과 같습니다.

```text
P2-09C source recipe: PASS
Network access: NOT USED
Detection rules executed: NO
```

## 전체 baseline 실행

Windows CMD 기준:

```cmd
python scripts\run_external_baseline.py
```

특정 샘플만 확인하려면 `--asset`을 사용할 수 있습니다.

```cmd
python scripts\run_external_baseline.py --asset evtx-ca-lsass-mimikatz
```

여러 개를 고를 때는 옵션을 반복합니다.

```cmd
python scripts\run_external_baseline.py --asset evtx-ca-lsass-mimikatz --asset evtx-de-security-log-cleared
```

## 실행 순서

실행기는 다음 순서를 지킵니다.

1. 현재 repository commit과 rule tree를 freeze
2. pinned commit/path에서 외부 파일 다운로드
3. 예상 파일 크기와 Git blob SHA-1 확인
4. SHA-256 계산
5. `external_baseline` evaluator manifest 생성
6. detector를 실행하지 않고 event index 생성
7. 모든 event label을 `ignore`로 생성
8. 기존 external holdout evaluator로 score
9. scenario hit/miss 요약 생성

탐지 룰은 이 과정에서 수정하지 않습니다.

## 생성 파일

기본 출력 위치:

```text
out/external_baseline/p2_09c/
```

주요 파일:

- `rules_freeze.json`: 평가한 commit/rule tree
- `manifest.yaml`: 실제 다운로드된 corpus SHA-256과 scenario 기대 기법
- `event_index.jsonl`: detection 실행 전 event index
- `labels_ignore.jsonl`: event-level ground truth를 주장하지 않는 label 파일
- `result.json`: 기존 evaluator의 원본 측정 결과
- `summary.json`: P2-09C 해석 경계를 적용한 요약
- `SUMMARY.md`: 사람이 읽기 쉬운 scenario hit/miss 표

## 결과 판정

P2-09C에서는 숫자가 낮다는 이유만으로 실패 처리하지 않습니다.

목적은 현재 상태를 숨기지 않고 측정하는 것입니다.

결과를 볼 때는 다음 순서로 판단합니다.

1. source hash 검증이 모두 통과했는가
2. corpus ingest가 정상 동작했는가
3. 10개 scenario 중 어떤 기법이 hit/miss인가
4. miss가 telemetry 부족인지, normalization 문제인지, rule coverage 문제인지 구분 가능한가
5. 그 결과가 실제로 다음 개발 우선순위를 바꿀 만큼 중요한가

P2-09C가 끝난 뒤에도 **실제 benign false positive 자료가 없으면 탐지 정확도를 주장할 수 없습니다.** 다음 단계는 P2-09D입니다.

## 2026-09-08 실측 결과

merged main commit `2a1631f6633ee40dcc47524675dc9dbda541e01d`에서 고정된 10개 EVTX를 실제로 실행했습니다.

- **2 HIT / 8 MISS / 10 total**
- scenario hit rate **20.0%**
- findings **3**
- converted events **202**
- event-level precision / recall / FPR **NOT CLAIMED**

같은 commit과 corpus를 GitHub Actions에서 두 번 실행해 repo/rule/corpus hash, source hash, findings 수, scenario 결과가 동일한 것도 확인했습니다.

영구 기록:

- `external_baseline/results/p2_09c_main_2a1631f/README.md`
- `external_baseline/results/p2_09c_main_2a1631f/measurement.yaml`
- `external_baseline/results/p2_09c_main_2a1631f/telemetry.yaml`

8개 MISS의 주된 원인은 해당 ATT&CK technique ID 자체가 없는 것이 아니라, 현재 native rules가 `command_line` 패턴에 많이 의존해 Event ID와 이벤트별 필드가 핵심 증거인 외부 EVTX를 놓치는 구조였습니다. P2-09C에서는 이 결과를 근거로 rule을 수정하지 않고 그대로 보존합니다.

## 2026-09-25 후속 독립 데이터셋 후보 검토

P2-35M 이후에는 새 canonical 평가 번호를 자동으로 만들지 않습니다. 다음 평가 후보는 현재 BreachScope가 사용하지 않은 source family이면서, Windows telemetry와 공격/정상 ground truth를 현재 detector와 독립적인 방식으로 제공해야 합니다. 2026-09-25 기준 공개 후보를 검토한 결과는 다음과 같습니다.

### Windows-APT 2025

- source: Mendeley Data `Windows-APT 2025`, version 4
- DOI: `10.17632/b8fmtzvpy8.4`
- URL: https://data.mendeley.com/datasets/b8fmtzvpy8/4
- BreachScope repository search hit before this note: 0
- Windows 10 환경에서 Caldera로 36개 APT-inspired scenario를 실행하고 Wazuh/Sysmon telemetry를 수집합니다.
- 공개 논문은 약 102,000개 log record, 38,393 general log, 63,620 malicious log를 보고합니다.
- `scenario_manifest.csv`와 `validation_summary.csv`가 있고, 각 scenario를 반복 실행하며 Caldera operation status와 Wazuh logs를 사람이 확인했다고 설명합니다.
- 장점: 기존 BreachScope source family와 겹치지 않고, Windows host telemetry, 정상/공격 데이터, scenario intent, validation metadata를 함께 제공합니다.
- 제한: 개별 log의 MITRE mapping은 Wazuh/Sysmon rule mapping 영향을 받으며 정상 activity에도 MITRE-tagged event가 존재할 수 있다고 upstream이 명시합니다.
- 따라서 이 데이터만으로 event-level production recall/FPR을 주장하지 않습니다. 사용할 경우 먼저 label provenance와 scenario/time-window ground truth를 별도로 고정해야 합니다.

### COMISET

- source: Zenodo `COMISET: Dataset for the analysis of malicious events in Windows systems`
- DOI: `10.5281/zenodo.15375146`
- URL: https://zenodo.org/records/15375146
- BreachScope repository search hit before this note: 0
- Windows LAB/REAL 두 환경에서 약 250 million event를 제공하고 MITRE ATT&CK label을 포함합니다.
- 공개 데이터는 JSON/CSV event 형태이며 raw EVTX corpus가 아닙니다.
- upstream 논문은 EBDS가 rule pattern과 event를 match해 MITRE label을 실시간 부여했다고 설명합니다.
- 따라서 COMISET의 label을 BreachScope detector의 독립적인 event-level oracle로 취급하지 않습니다. source-family 일반화나 JSON normalization 연구에는 후보가 될 수 있지만 production recall/FPR ground truth로는 부족합니다.

### CAM-LDS

- source: Zenodo `Cyber Attack Manifestations - Log Data Set (CAM-LDS)`
- DOI: `10.5281/zenodo.18861762`
- URL: https://zenodo.org/records/18861762
- attack execution log와 time-based technique ground truth를 제공하는 점은 강합니다.
- 그러나 dataset 자체가 Linux 기반이고 benign user behavior simulation이 활성화되지 않은 attack-manifestation corpus입니다.
- 따라서 현재 Windows 중심 BreachScope detector의 production recall/FPR 평가 후보로 사용하지 않습니다.

### MITRE BRAWL Public Game 001

- source: `mitre/brawl-public-game-001`
- upstream master commit: `7ec51fac8fc05ea01da210f604b821ef52818173`
- archive path: `brawl-public-game-001.zip`
- archive Git blob SHA-1: `257a4ed9dcba427f75cc11da286f44004ed6c7c0`
- archive size: `4,967,769` bytes
- license: CC-BY-4.0
- BreachScope repository search hit before this note: 0
- raw archive/event contents inspected before this note: NO
- environment: Windows 8.1 workstations 16대 + Windows Server 2012 R2 domain controller 1대
- telemetry: Sysmon, Windows Event Logs, computer properties
- attack oracle: CALDERA red bot이 별도 BSF(BRAWL Shared Format)로 실제 공격 행동을 기록하며, BSF step은 ATT&CK technique ID와 관련 event를 묶을 수 있습니다.
- upstream은 Sysmon/Windows Event와 BSF의 시간 의미를 별도로 설명하며, BSF에는 `time`, `happened_after`, `happened_before` 같은 attack-side 시간 정보가 있습니다.
- 장점: 탐지 규칙이 만든 라벨이 아니라 red bot 자체의 실행 기록이므로, 현재까지 검토한 후보 중 공격 행동 ground truth 독립성이 가장 강합니다.
- 제한: 이 공개 game에는 CALDERA red bot만 참여했고 Grey bot이 없었습니다. upstream도 자격 증명 관점에서 Game Board가 sterile하다고 설명합니다. 따라서 realistic benign background나 production FPR 평가용 corpus로 취급하지 않습니다.
- 제한: 현재 BreachScope JSONL collector는 BRAWL의 `data_model.fields.*` 구조를 직접 정규화하지 않습니다. raw corpus를 열기 전에 documented schema만으로 adapter를 구현하고 synthetic fixture로 고정해야 합니다.
- 현재 상태: independent attack-ground-truth holdout 후보 1순위. raw ZIP은 preregistration/adapter freeze 전까지 열지 않습니다.

이 후보를 사용할 경우 첫 평가는 attack-side BSF step/technique coverage만 대상으로 하고, benign FPR이나 production recall을 함께 주장하지 않습니다. BSF step과 telemetry event 사이의 matching rule, 허용 time window, host/command-line/object-action 매칭 우선순위를 detector 실행 전에 고정해야 합니다.

### 현재 결정

위 네 후보를 검토했지만 새 P2 canonical one-pass evaluation은 아직 시작하지 않습니다. BRAWL은 공격 ground truth 후보 1순위로 보존하되, raw corpus 미열람 상태를 유지하고 documented schema 기반 adapter와 scoring contract를 먼저 고정합니다.

다음 canonical 평가를 시작하려면 최소한 다음 조건을 모두 만족해야 합니다.

1. 현재 BreachScope가 아직 사용하지 않은 독립 source family
2. Windows host telemetry 또는 BreachScope가 의미 손실 없이 정규화할 수 있는 원본 event
3. detector rule과 독립적인 attack execution oracle 또는 event-level malicious/benign ground truth
4. benign label provenance가 명시되어 있고 단순히 "탐지 룰이 울리지 않음"을 benign으로 정의하지 않을 것
5. source version/bytes/hash와 selection rule을 detector 실행 전에 고정할 수 있을 것
6. event-level ground truth가 없는 경우 scenario hit rate와 observed flagged-event fraction만 보고 production accuracy/recall/FPR은 계속 `NOT_CLAIMED`

이 조건을 만족하는 corpus가 확보되기 전까지 P2-35M을 현재 rulepack의 마지막 sealed fresh-source revalidation으로 유지합니다.