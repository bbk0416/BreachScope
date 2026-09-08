# P2-09D measured benign baseline

이 디렉터리는 P2-09D runner 자체가 아니라 **실제로 측정한 최종 결과**를 기록합니다.

## 측정 대상

- evaluated commit: `789c1f45b35599adbb5816c69c2e1e5c586584c9`
- rules tree SHA-256: `543b4e02ebb48d5e33eeb4405a6d489487a05d07ffebda4ba31206a059dae3ce`
- corpus: `NextronSystems/evtx-baseline` `v0.8.4` `win10-client.tgz`
- corpus SHA-256: `d48f1b328d48db6c6dfaa9b6e232dbb454d93e833c6e1248efc0faf690b6808e`
- label policy: `benign_by_source_intent`
- evaluation class: `external_baseline`

## 실제 결과

- source EVTX files: **352**
- EVTX files with events: **97**
- benign events: **766,623**
- FP: **17**
- TN: **766,606**
- observed event-level FPR: **0.00221752%**
- flagged events / 1,000: **0.022175**
- findings: **19**
- findings / 1,000: **0.024784**

이 FPR은 이 고정 public goodware corpus에서 관찰된 값입니다. production 또는 enterprise-wide FPR로 표현하지 않습니다.

## 측정 실행

대형 Sysmon EVTX 때문에 단일 GitHub runner에서 두 번 45분 timeout이 발생했습니다. 최종 측정은 동일 parser, normalizer, event identity, rule tree, `apply_rules()`를 유지한 채 full corpus를 여러 runner로 나눠 처리했습니다.

- source shard run: `34212244466`
- aggregate-only correction run: `34213957530`
- final aggregate artifact ID: `10050951142`
- final aggregate artifact SHA-256: `caf8d0f021a14004a6d659edca8ae28495cc733d675d1d4f5fedb9970029d14f`

분산 방식은 작은 실제 EVTX에서 monolithic scoring과 event-key set, flagged-key set, finding 수가 모두 같은지 먼저 확인했고 이 gate가 PASS한 뒤 사용했습니다.

Sysmon `11,894` chunks는 `0:11894` 범위를 정확히 한 번씩 처리했습니다. 전체 shard 사이 event identity 중복도 없었습니다.

## aggregate 보정

첫 aggregate는 `expected 352 source files, got 97`로 실패했습니다. 탐지 결과 문제가 아니라 `source_events`가 이벤트가 한 건 이상 있는 파일만 포함해서, 빈 EVTX 255개가 파일 수 회계에서 빠진 문제였습니다.

최종 aggregate에서는 pinned archive 자체에서 `.evtx` 파일을 다시 세어 **352개**임을 확인하고, 이벤트가 있는 파일은 별도로 **97개**로 기록했습니다. 기존 9개 shard 측정 결과는 재사용했습니다.

## 해석 경계

다음은 말할 수 있습니다.

> 현재 고정 rule tree를 Nextron `win10-client.tgz`의 766,623개 이벤트에 적용했을 때, 17개 이벤트가 하나 이상의 finding으로 flagged되어 관찰 FPR은 0.00221752%였다.

다음은 말할 수 없습니다.

- production FPR이 0.00221752%다
- 모든 Windows 환경에서 같은 오탐률이 나온다
- 기업 SOC 환경을 대표한다
- 각 이벤트를 사람이 정상이라고 개별 판정했다
- 이번 실행시간을 제품 성능 benchmark로 쓸 수 있다

원본 archive와 EVTX는 저장소에 재배포하지 않습니다.
