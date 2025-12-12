# BreachScope 프로젝트 구조

## 개선된 디렉토리 구조

```
BreachScope/
├── breachscope/              # 핵심 패키지
│   ├── __init__.py          # 패키지 초기화 (경로 및 로깅 설정)
│   ├── common/              # 공통 유틸리티 (신규)
│   │   ├── __init__.py
│   │   ├── paths.py         # 경로 관리
│   │   └── logging.py       # 로깅 설정
│   ├── schemas.py           # 데이터 모델
│   ├── config.py            # 설정 관리
│   ├── exceptions.py        # 예외 정의
│   ├── utils.py             # 유틸리티 함수
│   ├── attack.py            # MITRE ATT&CK 매핑
│   ├── cli.py               # CLI 인터페이스
│   ├── pipeline.py         # 메인 파이프라인
│   ├── collector.py         # 이벤트 수집
│   ├── normalizer.py        # 정규화
│   ├── analyzer.py          # 규칙 기반 분석
│   ├── correlator.py        # 시간 기반 상관분석
│   ├── scenario.py          # 시나리오 추론
│   ├── decoder.py           # 디코딩
│   ├── ingest.py            # 데이터 수집
│   ├── validator.py         # 검증
│   ├── storage.py           # SQLite 저장소
│   ├── reporting.py         # 리포트 생성
│   └── rules.py             # 규칙 로딩
│
├── api/                      # 웹 API 애플리케이션
│   ├── main.py              # FastAPI 앱 진입점
│   ├── routers/             # API 라우터
│   │   ├── analyze.py       # 분석 API
│   │   ├── health.py        # 헬스 체크
│   │   ├── report.py        # 리포트 API
│   │   ├── rules.py         # 규칙 API
│   │   └── web.py           # 웹 UI
│   ├── services/            # 비즈니스 로직 서비스
│   │   ├── analysis_service.py  # 분석 서비스
│   │   └── workdir_service.py   # 작업 디렉토리 서비스
│   ├── dependencies.py      # 의존성 주입
│   └── middleware.py        # 미들웨어
│
├── rules/                    # 탐지 규칙 (YAML)
│   ├── README.txt
│   └── *.yml
│
├── templates/                # 리포트 템플릿
│   ├── report.html.j2
│   └── web_index.html
│
├── scripts/                  # 실행 스크립트
│   ├── run.py               # CLI 실행 스크립트
│   ├── run_demo.ps1         # 데모 실행 (PowerShell)
│   └── cleanup_temp.py      # 임시 파일 정리 스크립트
│
├── docs/                     # 문서 (개선됨)
│   ├── QUICKSTART.md        # 빠른 시작
│   ├── USAGE.md             # 사용 가이드
│   ├── WEB_UI_GUIDE.md      # 웹 UI 가이드
│   ├── API_DOCUMENTATION.md # API 문서
│   ├── PERFORMANCE.md       # 성능 가이드
│   ├── ARCHITECTURE.md      # 아키텍처 문서
│   ├── CHANGELOG.md         # 변경 이력
│   ├── PROGRESS.md          # 개발 진행 기록
│   ├── IMPROVEMENTS_SUMMARY.md # 개선 사항 요약
│   └── STRUCTURE.md         # 프로젝트 구조 (이 문서)
│
├── out/                      # 출력 디렉토리 (Git 제외)
│   └── report.*             # 생성된 리포트
│
├── .gitignore               # Git 제외 파일 목록
├── requirements.txt         # Python 의존성
└── README.md                # 프로젝트 개요
```

## 주요 개선 사항

### 1. 문서 구조화
- **이전**: 루트에 8개 문서 파일 혼재
- **개선**: `docs/` 디렉토리로 통합
- **효과**: 프로젝트 루트 정리, 문서 접근성 향상

### 2. 스크립트 통합
- **이전**: 루트에 실행 스크립트 분산
- **개선**: `scripts/` 디렉토리로 통합, 래퍼 스크립트 제공
- **효과**: 스크립트 관리 용이, 실행 방법 통일

### 3. 공통 유틸리티 모듈
- **이전**: `sys.path` 조작이 여러 곳에 분산
- **개선**: `breachscope/common/` 패키지로 통합
- **효과**: 경로 관리 일관성, 로깅 설정 통일

### 4. 모듈 구조
- **현재**: 평면적 구조 (모든 모듈이 같은 레벨)
- **향후**: 계층 구조로 개선 예정 (core, analysis, processing 등)

## 모듈 의존성

```
breachscope/
├── common/          # 독립적 (다른 모듈에 의존 없음)
├── schemas.py       # 독립적 (데이터 모델만)
├── config.py        # 독립적 (설정만)
├── exceptions.py    # 독립적 (예외만)
├── utils.py         # schemas 의존
├── attack.py        # 독립적 (MITRE 매핑)
│
├── collector.py     # schemas 의존
├── normalizer.py    # schemas 의존
├── decoder.py       # 독립적
├── rules.py         # schemas 의존
├── analyzer.py      # schemas, decoder, utils 의존
│
├── correlator.py    # schemas, utils 의존
├── scenario.py      # schemas, correlator 의존
│
├── storage.py       # schemas 의존
├── reporting.py     # schemas, attack 의존
│
└── pipeline.py      # 모든 모듈 의존 (오케스트레이션)
```

## 실행 경로

### CLI 실행
```bash
# 방법 1: 래퍼 스크립트 (권장)
./run.bat --demo          # Windows
./run.sh --demo           # Linux/Mac

# 방법 2: 직접 실행
python scripts/run.py --demo

# 방법 3: 모듈로 실행
python -m breachscope.cli --demo
```

### 웹 UI 실행
```bash
# 방법 1: 래퍼 스크립트 (권장)
./run_web_fastapi.bat     # Windows
./run_web_fastapi.sh      # Linux/Mac

# 방법 2: 직접 실행
python -m uvicorn api.main:app --host 0.0.0.0 --port 8501 --reload
```

## 향후 개선 계획

### Phase 2: 모듈 계층 구조화
- `breachscope/core/`: 파이프라인, 수집, 분석
- `breachscope/analysis/`: 상관분석, 시나리오
- `breachscope/processing/`: 디코딩, 수집, 검증
- `breachscope/storage/`: 저장소
- `breachscope/reporting/`: 리포트 생성

### Phase 3: 테스트 구조
- `tests/` 디렉토리 생성
- 단위 테스트, 통합 테스트 분리

### Phase 4: 설정 통합
- 단일 설정 로더
- 환경별 설정 파일 지원
