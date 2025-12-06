# BreachScope 개발 진행 기록

## 개요
PDF 문서 "BreachScope 시스템 아키텍처 기획 및 설계 연구"를 기반으로 핵심 기능을 구현했습니다.

## 구현 완료 항목

### 1. 시간 기반 상관분석 엔진 (correlator.py) ✅
**구현일**: 2024년
**상태**: 완료

**주요 기능**:
- 이벤트 간 시간적 연관성 분석
- 상관 규칙 기반 체인 생성
- 기본 상관 규칙:
  - 다운로드 → 실행 체인 (download_exec)
  - 인코딩된 명령 → 실행 (encoded_exec)
  - 네트워크 연결 → 데이터 전송 (network_data)
- 세션 기반 상관분석 (로그온 세션별 이벤트 그룹화)
- 체인 신뢰도 계산

**데이터 구조**:
- `EventChain`: 연관된 이벤트들의 체인
- `CorrelationRule`: 상관분석 규칙 정의

**사용 예시**:
```python
from breachscope.correlator import correlate_events, get_chain_summary

chains = correlate_events(events, findings)
summary = get_chain_summary(chains)
```

### 2. 시나리오 기반 추론 모듈 (scenario.py) ✅
**구현일**: 2024년
**상태**: 완료

**주요 기능**:
- 이벤트 체인으로부터 공격 시나리오 자동 추론
- MITRE ATT&CK 기반 시나리오 템플릿 매칭
- 시나리오 신뢰도 계산
- 기본 시나리오 템플릿:
  - 피싱 이메일을 통한 백도어 설치
  - 인코딩된 명령을 통한 자격증명 탈취
  - 웹 다운로드를 통한 C2 통신
  - WMI를 통한 측면 이동

**데이터 구조**:
- `Scenario`: 공격 시나리오
- `ScenarioTemplate`: 시나리오 템플릿

**사용 예시**:
```python
from breachscope.scenario import infer_scenarios, get_scenario_summary

scenarios = infer_scenarios(chains, findings)
summary = get_scenario_summary(scenarios)
```

### 3. 데이터 저장소 모듈 (storage.py) ✅
**구현일**: 2024년
**상태**: 완료

**주요 기능**:
- SQLite 기반 영구 저장소
- 이벤트, Finding, Chain, Scenario 저장
- 중복 방지 (event_hash 기반)
- 인덱싱:
  - timestamp, host, source (이벤트)
  - severity, mitre_technique (Finding)
  - chain_type (Chain)
  - attack_stage (Scenario)
- 쿼리 기능:
  - `query_events()`: 이벤트 검색
  - `query_findings()`: 탐지 결과 검색
  - `get_statistics()`: 통계 정보

**데이터베이스 스키마**:
- `events`: 이벤트 저장
- `findings`: 탐지 결과 저장
- `chains`: 이벤트 체인 저장
- `chain_events`: 체인-이벤트 관계
- `scenarios`: 시나리오 저장
- `scenario_chains`: 시나리오-체인 관계

**사용 예시**:
```python
from breachscope.storage import BreachScopeDB

with BreachScopeDB(Path("breachscope.db")) as db:
    event_id_map = db.store_events(events)
    db.store_findings(findings, event_id_map, events)
    db.store_chains(chains, event_id_map, events)
    db.store_scenarios(scenarios)
```

### 4. 파이프라인 통합 ✅
**구현일**: 2024년
**상태**: 완료

**변경 사항**:
- `pipeline.py`에 상관분석 및 시나리오 추론 통합
- `run_pipeline()` 함수에서 자동 실행:
  1. 이벤트 수집 및 정규화
  2. 규칙 기반 분석
  3. **시간 기반 상관분석** (신규)
  4. **시나리오 기반 추론** (신규)
  5. 리포트 생성

**리포트 요약에 추가된 정보**:
- `chains`: 체인 통계
- `scenarios`: 시나리오 통계

### 5. 보고서 템플릿 고도화 ✅
**구현일**: 2024년
**상태**: 완료

**추가된 섹션**:
1. **이벤트 체인 분석**
   - 체인 통계 (총 개수, 평균 신뢰도, 타입별 분포)
   - 상세 체인 목록 (이벤트별 상세 정보)

2. **공격 시나리오 추론**
   - 시나리오 통계 (총 개수, 평균 신뢰도, 공격 단계별 분포)
   - 상세 시나리오 목록 (MITRE 기법, 연관 체인)

**템플릿 파일**: `templates/report.html.j2`

### 6. 스키마 확장 ✅
**구현일**: 2024년
**상태**: 완료

**추가된 데이터 클래스** (`schemas.py`):
- `EventChain`: 이벤트 체인
- `Scenario`: 공격 시나리오

**Report 클래스 확장**:
- `chains: List[EventChain]` 필드 추가
- `scenarios: List[Scenario]` 필드 추가

## 아키텍처 개선 사항

### 이전 MVP vs 현재 구현

| 구성요소 | 이전 MVP | 현재 구현 |
|---------|---------|----------|
| 상관분석 | ❌ 미구현 | ✅ 시간 기반 상관분석 |
| 시나리오 추론 | ❌ 미구현 | ✅ 템플릿 기반 시나리오 추론 |
| 데이터 저장소 | ❌ 메모리만 | ✅ SQLite 영구 저장 |
| 세션 분석 | ❌ 미구현 | ✅ 세션 기반 상관 |
| Chain Analyzer | ❌ 미구현 | ✅ 이벤트 체인 생성 |
| 리포트 고도화 | ⚠️ 기본 리포트 | ✅ 체인/시나리오 섹션 추가 |

## 다음 단계 (향후 개선)

### 우선순위 높음
1. **고급 디코더 확장**
   - PowerShell 난독화 해제
   - VBA 디스크램블
   - 문자열 치환 난독화

2. **성능 최적화**
   - 대용량 로그 처리 최적화
   - 인덱싱 성능 개선
   - 병렬 처리 강화

### 우선순위 중간
3. **시나리오 템플릿 확장**
   - 더 많은 공격 시나리오 추가
   - 사용자 정의 템플릿 지원

4. **타임라인 시각화**
   - JavaScript 기반 인터랙티브 타임라인
   - 체인 시각화

### 우선순위 낮음
5. **머신러닝 기반 추론**
   - 이벤트 패턴 학습
   - 이상 탐지

6. **협업 기능**
   - 코멘트 추가
   - 태그 관리

## 기술 스택

### 신규 의존성
- 없음 (표준 라이브러리만 사용)

### 기존 의존성
- `jinja2`: HTML 템플릿
- `pyyaml`: YAML 규칙 파싱
- `fastapi`: 웹 프레임워크 (FastAPI 기반 웹 UI)
- `uvicorn`: ASGI 서버

## 테스트 권장 사항

1. **상관분석 테스트**
   - 다운로드-실행 체인 생성 확인
   - 세션 기반 그룹화 확인

2. **시나리오 추론 테스트**
   - 템플릿 매칭 확인
   - 신뢰도 계산 검증

3. **저장소 테스트**
   - 대용량 데이터 저장/조회
   - 중복 방지 확인

4. **리포트 생성 테스트**
   - 체인/시나리오 섹션 렌더링 확인

## 참고 문서

- 원본 설계 문서: `BreachScope 시스템 아키텍처 기획 및 설계 연구.pdf`
- 유사 시스템: Velociraptor, KAPE, Timesketch

## 변경 이력

### 2024년 - 주요 기능 구현
- 시간 기반 상관분석 엔진 구현
- 시나리오 기반 추론 모듈 구현
- 데이터 저장소 모듈 구현
- 파이프라인 통합
- 보고서 템플릿 고도화
