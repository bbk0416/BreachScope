# P2-11A Post-Remediation Freeze

## 목적

P2-10H까지 고정 공개 공격 baseline의 10개 scenario가 모두 HIT가 됐습니다.
이 시점부터 같은 공개 공격 corpus를 보고 룰을 더 수정하면 과적합 위험이 커집니다.

그래서 P2-11A는 탐지 코드를 추가하지 않고, **새 holdout을 고르기 전에 현재 detector 상태를 먼저 고정**합니다.

## 고정한 상태

```text
repo commit: 674615ef3c92d5b4bbc4dec71f566d49de0454f4
rule tree SHA-256: 371e73c4447cbce853dbdf936bdc40141bb4b0b496c11bcd63c41f8c42d0969f
rule files: 3
analyzer blob SHA-1: f7e395ba66d3461ffed0a4c9b5b37f86ae585ff7
P2-10 rule file blob SHA-1: 3a2f853fd6c8232f7d919913fd711d7f18785108
```

freeze 시점의 working tree는 clean이었고, `verify_current_detection_evidence.py --json`도 PASS였습니다.
그 verifier가 기록한 현재 공개 공격 baseline 상태는 10 HIT / 10 scenario입니다.

## Freeze 실행 증거

```text
GitHub Actions run: 34387750493
artifact ID: 10118367041
artifact SHA-256: 54f1e1ad5e7d145afab0b6e7f63086c2b387d345feb740c5058e3e7b8544aebf
workflow head: b349ed8c7a7becd0aacb1abb0bbef80e04029801
```

workflow는 측정용 branch의 코드를 freeze한 것이 아닙니다.
실행 중 `ref: 674615ef3c92d5b4bbc4dec71f566d49de0454f4`를 명시해 **P2-10H merge가 끝난 exact main commit을 다시 checkout한 뒤** freeze했습니다.

artifact에는 다음 세 파일이 들어 있습니다.

- `p2-11a-rules-freeze.json`
- `p2-11a-source-hashes.json`
- `current-detection-evidence.json`

## 이 시점에 아직 하지 않은 것

P2-11A 기록 시점에는 새 holdout corpus를 아직 선택하지 않았고, 새 holdout score도 실행하지 않았습니다.
따라서 이 문서는 final blind holdout 결과가 아닙니다.

## 다음 단계 원칙

새 평가 세트는 기존에 룰 수정에 사용한 다음 두 source와 분리해야 합니다.

- `sbousseaden/EVTX-ATTACK-SAMPLES`
- `NextronSystems/evtx-baseline`

새 corpus를 사용할 때는 저장소의 `docs/EXTERNAL_HOLDOUT_EVALUATION.md` 절차를 그대로 따릅니다.

1. 이미 만든 P2-11A freeze를 기준점으로 유지
2. corpus를 선택하고 SHA-256으로 고정
3. detection rule을 실행하지 않고 먼저 index
4. ground truth를 별도로 준비하고 label hash를 고정
5. 그 뒤 한 번 score
6. 결과를 본 뒤 룰을 수정하면 그 라운드를 blind 결과라고 부르지 않음

독립적인 labeler와 실제 unseen provenance를 확보하지 못하면 `final_blind_holdout`이라고 과장하지 않고 `external_baseline` 또는 그에 맞는 평가 등급으로 기록합니다.

## 말할 수 없는 것

현재 공개 공격 baseline의 10/10은 다음을 뜻하지 않습니다.

- production 탐지율 100%
- production precision / recall / FPR
- 기업 환경 대표성
- final blind holdout 통과

P2-09D의 과거 FPR `0.00221752%`도 현재 60-rule detector에 적용하지 않습니다.
