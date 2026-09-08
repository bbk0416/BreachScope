# BreachScope 성능 상태

이 문서는 **현재 저장소에서 재현 가능한 사실만** 기록합니다.

과거 문서에 있던 1,000 / 10,000 / 100,000 / 1,000,000 이벤트 처리 시간, 메모리 사용량, “병렬 처리 2~4배 향상”, “SQLite 배치 삽입 5~10배 향상” 같은 숫자는 이번 P2-09A Truth Pass에서 제거했습니다.

이유는 간단합니다. 현재 저장소에는 그 숫자들을 동일 조건에서 재현하고 결과를 검증하는 benchmark runner와 원본 결과가 연결되어 있지 않습니다. 따라서 그 수치를 현재 성능 보장처럼 유지하지 않습니다.

## 현재 코드에서 확인되는 동작

### 1. 이벤트는 일반 실행에서 메모리에 모입니다

`Pipeline.collect_events()`는 정규화된 이벤트를 최종적으로 리스트로 구성합니다.

- `max_events`가 있으면 지정 개수까지만 리스트에 담습니다.
- 제한이 없으면 전체 normalized iterator를 리스트로 변환합니다.

따라서 현재 기본 파이프라인을 **완전한 streaming 분석기**로 표현하면 안 됩니다. 큰 corpus에서는 메모리 사용량을 실제 측정해야 합니다.

### 2. 병렬 처리는 detection 단계에 적용됩니다

현재 `Pipeline.analyze()`는 병렬 처리가 활성화되어 있고 이벤트가 충분히 많을 때 `apply_rules_parallel()` 경로를 사용할 수 있습니다.

이 기능이 존재한다는 것과 전체 파이프라인이 몇 배 빨라진다는 것은 다른 주장입니다. 수집, 상관분석, 시나리오 처리, 리포트 생성까지 포함한 end-to-end 성능 향상률은 별도 benchmark로 측정해야 합니다.

### 3. SQLite 최적화 모듈은 존재합니다

`breachscope/storage.py`에는 SQLite 기반 저장소와 WAL, index, batch insert 관련 구현이 있습니다.

다만 현재 기본 CLI/Web 분석 흐름의 case lifecycle을 SQLite가 전부 담당하는 구조로 보기는 어렵습니다. 기본 case history는 filesystem과 case-history index를 사용합니다.

따라서 SQLite 설정을 근거로 전체 제품 처리량을 추정하지 않습니다.

### 4. 실행 시간 로그는 성능 측정 보조자료입니다

Pipeline은 주요 단계 시간을 로그로 남깁니다. 이 값은 개별 실행 상태를 보는 데 유용하지만, 동일 corpus/동일 commit/동일 하드웨어에서 반복 측정하지 않은 단일 로그를 공식 benchmark로 사용하지 않습니다.

## 현재 성능 주장 범위

현재 공개적으로 말할 수 있는 범위는 다음 정도입니다.

- 대량 이벤트용 병렬 detection 경로가 구현되어 있다.
- `max_events`로 입력 이벤트 수를 제한할 수 있다.
- SQLite WAL 및 batch 저장 구현이 존재한다.
- 주요 pipeline 단계별 실행 시간을 관찰할 수 있다.

현재 공개 근거 없이 말하지 않는 항목:

- “100만 이벤트를 몇 초 안에 처리한다.”
- “병렬 처리가 항상 2~4배 빠르다.”
- “메모리 사용량이 이벤트당 일정하다.”
- “대규모 enterprise 로그를 production 수준으로 검증했다.”
- “Hayabusa/Chainsaw보다 빠르다.”

## P2-09 benchmark 요구사항

공식 성능 수치를 다시 넣으려면 최소한 아래 조건을 만족해야 합니다.

### 고정해야 할 정보

- BreachScope commit SHA
- rules directory hash 또는 rule manifest
- Python 버전
- OS
- CPU 모델 / 논리 코어 수
- RAM
- 입력 corpus 이름과 SHA-256
- 입력 이벤트 수
- 입력 파일 수와 총 크기
- redaction/PDF/Hayabusa 등 실행 옵션
- parallel on/off와 worker 수

### 최소 측정 항목

- 전체 wall-clock time
- ingest/normalize time
- detection time
- correlation time
- scenario time
- report/export time
- peak RSS 또는 동등한 peak memory
- findings/chains/scenarios 수
- 정상 종료 여부

### 최소 규모

같은 benchmark runner로 최소 다음 구간을 측정하는 것을 권장합니다.

- 10k events
- 100k events
- 1m events

1m 이벤트 실행이 메모리 부족이나 비현실적 시간 때문에 실패한다면, 실패 자체를 결과로 기록합니다. 숫자를 만들기 위해 입력을 바꾸지 않습니다.

### 비교 방법

병렬 성능 비교는 최소 다음 두 조건을 같은 corpus에서 실행합니다.

1. single/non-parallel detection
2. parallel detection with recorded worker count

성능 향상률은 측정 결과에서 계산하며 미리 목표값을 정하지 않습니다.

## detection 정확도와 성능은 별개입니다

빠르게 처리하는 것과 잘 탐지하는 것은 다른 문제입니다.

- 성능 benchmark: 시간·메모리·처리량
- detection evaluation: TP/FP/TN/FN, precision, recall, FPR
- scenario evaluation: expected scenario/technique hit 여부

내장 synthetic corpus의 통과 여부를 대용량 실전 성능이나 production accuracy 증거로 사용하지 않습니다.

## 현재 권장 사용

대규모 운영에 투입하기 전에는 실제 사용할 로그와 비슷한 corpus로 직접 측정하세요.

```bash
python scripts/run.py --input <corpus> --rules rules --out out/report
```

탐지 품질은 별도로 다음 도구를 사용합니다.

```bash
python scripts/evaluate_detection_corpus.py
python scripts/evaluate_external_holdout.py --help
```

## 다음 작업

P2-09에서는 임의의 성능 숫자를 문서에 다시 넣는 대신, **재현 가능한 benchmark runner + 결과 manifest**를 먼저 추가하는 것이 목표입니다.
