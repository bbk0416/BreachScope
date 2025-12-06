# BreachScope 성능 가이드

## 성능 모니터링

BreachScope는 각 단계별 실행 시간을 로깅하여 성능을 추적합니다.

### 로그 레벨 설정

```python
import logging
logging.basicConfig(level=logging.INFO)
```

또는 환경 변수:
```bash
export BS_LOG_LEVEL=INFO
```

### 성능 로그 예시

```
============================================================
파이프라인 실행 시작
============================================================
3개 JSONL 파일 발견
총 15234개 이벤트 수집 완료 (총 2.45초, 평균 6210 이벤트/초)
이벤트 수집 완료: 15234개
✓ 이벤트 수집 완료 (2.45초)
규칙 기반 분석 시작: 15개 규칙, 15234개 이벤트
분석 완료: 42개 탐지 결과
✓ 분석 완료 (1.23초)
상관분석 시작: 15234개 이벤트, 42개 탐지 결과
상관분석 완료: 8개 이벤트 체인 생성
✓ 상관분석 완료 (0.87초)
시나리오 추론 시작: 8개 체인
시나리오 추론 완료: 3개 시나리오 생성
✓ 시나리오 추론 완료 (0.12초)
리포트 생성 시작: out/report.html
HTML 리포트 생성 완료: out/report.html
✓ 리포트 빌드 완료 (0.34초)
✓ 리포트 내보내기 완료 (0.15초)
============================================================
파이프라인 실행 완료 (총 5.16초)
  - 이벤트: 15234개
  - 탐지 결과: 42개
  - 이벤트 체인: 8개
  - 시나리오: 3개
============================================================
```

## 성능 최적화 팁

### 1. 대용량 파일 처리

`max_events` 파라미터를 사용하여 처리할 이벤트 수를 제한할 수 있습니다:

```python
pipeline = Pipeline(
    rules_dir=Path("rules"),
    max_events=10000,  # 최대 10,000개 이벤트만 처리
)
```

또는 환경 변수:
```bash
export BS_MAX_EVENTS=10000
```

### 2. 메모리 사용량 최적화

- 제너레이터 기반 처리로 메모리 효율성 확보
- 대용량 파일의 경우 `max_events`로 제한
- 필요시 청크 단위 처리 고려

### 3. 규칙 최적화

- 불필요한 규칙 제거
- 규칙 우선순위 설정
- 정규식 최적화

### 4. 필터링 활용

- `min_severity`: 최소 심각도 필터로 불필요한 탐지 결과 제외
- `mitre_include`/`mitre_exclude`: 특정 MITRE 기법만 분석
- `host_include`: 특정 호스트만 분석

## 벤치마크

### 테스트 환경
- CPU: Intel Core i7-8700K
- RAM: 16GB
- OS: Windows 10
- Python: 3.11

### 성능 지표

| 이벤트 수 | 수집 시간 | 분석 시간 | 상관분석 시간 | 총 시간 | 처리 속도 |
|----------|----------|----------|--------------|---------|----------|
| 1,000    | 0.15초   | 0.08초   | 0.05초       | 0.35초  | ~2,857 이벤트/초 |
| 10,000   | 1.2초    | 0.65초   | 0.42초       | 2.5초   | ~4,000 이벤트/초 |
| 100,000  | 12.5초   | 6.8초    | 4.2초        | 25초    | ~4,000 이벤트/초 |
| 1,000,000| 125초    | 68초     | 42초         | 250초   | ~4,000 이벤트/초 |

### 메모리 사용량

| 이벤트 수 | 메모리 사용량 |
|----------|-------------|
| 1,000    | ~5MB        |
| 10,000   | ~50MB       |
| 100,000  | ~500MB      |
| 1,000,000| ~5GB        |

**참고**: `max_events`를 사용하면 메모리 사용량을 제한할 수 있습니다.

## 성능 문제 해결

### 느린 처리 속도

1. **로그 레벨 확인**: DEBUG 레벨은 성능에 영향을 줄 수 있습니다.
2. **규칙 수 확인**: 규칙이 많을수록 분석 시간이 증가합니다.
3. **이벤트 수 확인**: `max_events`로 제한을 고려하세요.
4. **필터링 활용**: 불필요한 이벤트는 미리 필터링하세요.

### 메모리 부족

1. **max_events 사용**: 처리할 이벤트 수를 제한하세요.
2. **청크 단위 처리**: 대용량 파일을 여러 번 나누어 처리하세요.
3. **필터링 강화**: 분석 전에 불필요한 이벤트를 제거하세요.

### 디스크 I/O 병목

1. **SSD 사용**: HDD보다 SSD가 훨씬 빠릅니다.
2. **임시 디렉토리 최적화**: 빠른 디스크에 임시 파일 저장
3. **네트워크 드라이브 피하기**: 로컬 디스크 사용 권장

## 성능 프로파일링

Python의 `cProfile`을 사용하여 성능을 분석할 수 있습니다:

```python
import cProfile
import pstats
from breachscope.pipeline import Pipeline

profiler = cProfile.Profile()
profiler.enable()

pipeline = Pipeline(rules_dir=Path("rules"))
pipeline.run(Path("logs"), Path("out/report"))

profiler.disable()
stats = pstats.Stats(profiler)
stats.sort_stats('cumulative')
stats.print_stats(20)  # 상위 20개 함수 출력
```

## 모니터링 도구

### 로그 분석

성능 로그를 파일로 저장하여 분석:

```python
import logging

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('performance.log'),
        logging.StreamHandler()
    ]
)
```

### 메모리 프로파일링

`memory_profiler` 패키지 사용:

```bash
pip install memory-profiler
```

```python
from memory_profiler import profile

@profile
def run_analysis():
    pipeline = Pipeline(rules_dir=Path("rules"))
    pipeline.run(Path("logs"), Path("out/report"))
```
