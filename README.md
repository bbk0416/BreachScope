# BreachScope

**BreachScope**는 디지털 포렌식 및 사고 대응(DFIR)을 위한 자동화된 로그 분석 도구입니다. Windows 이벤트 로그와 다양한 보안 로그를 분석하여 공격 시나리오를 자동으로 탐지하고 시각화합니다.

**작성자**: bbk0416 (bbk0416@gmail.com)

## 주요 기능

- 🔍 **규칙 기반 탐지**: YAML 기반 탐지 규칙으로 의심스러운 활동 자동 탐지
- 🔗 **시간 기반 상관분석**: 이벤트 간 시간적 연관성을 분석하여 공격 체인 생성
- 🎯 **시나리오 추론**: MITRE ATT&CK 기반 공격 시나리오 자동 추론 (12개 기본 템플릿 + 사용자 정의 템플릿 지원)
- 📊 **시각화 리포트**: HTML, JSON, CSV 형식의 상세 분석 리포트 생성 (인터랙티브 타임라인 포함)
- 🪟 **Windows 이벤트 로그 수집**: `wevtutil.exe`를 사용한 자동 로그 수집
- 🌐 **웹 UI**: FastAPI 기반 웹 인터페이스 제공
- ⚡ **고성능**: O(n log n) 복잡도의 최적화된 상관분석 알고리즘, SQLite WAL 모드, 병렬 처리 지원
- 🧹 **자동 정리**: 임시 파일 자동 정리 기능

## 빠른 시작

### 설치

```bash
# 저장소 클론
git clone https://github.com/bbk0416/BreachScope.git
cd BreachScope

# 의존성 설치
pip install -r requirements.txt
```

### 기본 사용법

```bash
# 데모 실행 (샘플 로그 자동 생성)
python scripts/run.py --demo
# 또는 래퍼 스크립트 사용
./run.bat --demo  # Windows
./run.sh --demo   # Linux/Mac

# 실제 로그 분석
python scripts/run.py --input logs/ --rules rules/ --out out/report

# Windows 이벤트 로그 자동 수집 및 분석
python scripts/run.py --collect-evtx --collect-logs Security,System --collect-hours 24
```

### 웹 UI 실행

```bash
# Windows
run_web_fastapi.bat

# Linux/Mac
./run_web_fastapi.sh

# 또는 직접 실행
python -m uvicorn api.main:app --host 0.0.0.0 --port 8501 --reload
```

브라우저에서 `http://localhost:8501`로 접속하세요.

## 프로젝트 구조

```
BreachScope/
├── breachscope/          # 핵심 모듈 패키지
│   ├── pipeline.py       # 메인 파이프라인
│   ├── collector.py      # 이벤트 수집
│   ├── analyzer.py       # 규칙 기반 분석
│   ├── correlator.py     # 시간 기반 상관분석
│   ├── scenario.py       # 시나리오 추론
│   ├── reporting.py      # 리포트 생성
│   └── ...
├── api/                  # API 애플리케이션
│   ├── main.py          # FastAPI 앱 진입점
│   ├── routers/         # API 라우터
│   ├── services/        # 비즈니스 로직 서비스
│   └── dependencies.py  # 의존성 주입
├── rules/                # 탐지 규칙 (YAML)
├── templates/            # 리포트 템플릿
├── scripts/              # 실행 스크립트
│   ├── run.py           # CLI 실행 스크립트
│   ├── run_demo.ps1     # 데모 실행 (PowerShell)
│   └── cleanup_temp.py  # 임시 파일 정리 스크립트
├── tests/                # 테스트 코드
└── docs/                 # 문서
```

## 문서

### 시작하기
- [빠른 시작 가이드](docs/QUICKSTART.md)
- [사용자 가이드](docs/USAGE.md)

### 가이드
- [웹 UI 가이드](docs/WEB_UI_GUIDE.md)
- [API 문서](docs/API_DOCUMENTATION.md)
- [성능 가이드](docs/PERFORMANCE.md)
- [시스템 아키텍처 기획 및 설계 연구](docs/ARCHITECTURE.md)

### 개발
- [개선 사항 요약](docs/IMPROVEMENTS_SUMMARY.md)
- [변경 이력](docs/CHANGELOG.md)
- [개발 진행 기록](docs/PROGRESS.md)

## 주요 개념

### 이벤트 (Event)
분석 대상이 되는 로그 항목. 타임스탬프, 호스트, 소스, 이벤트 ID 등의 정보를 포함합니다.

### 탐지 결과 (Finding)
규칙에 의해 매칭된 의심스러운 활동. 심각도, MITRE ATT&CK 기법, 매칭된 값 등을 포함합니다.

### 이벤트 체인 (Event Chain)
시간적으로 연관된 이벤트들의 그룹. 예: 다운로드 → 실행, 인코딩된 명령 → 실행 등.

### 시나리오 (Scenario)
이벤트 체인으로부터 추론된 공격 시나리오. MITRE ATT&CK 기법과 공격 단계를 포함합니다.

## 탐지 규칙 작성

규칙은 YAML 형식으로 작성합니다:

```yaml
title: Suspicious PowerShell
id: rule-001
severity: high
mitre_technique: T1059.001
field: command_line
pattern: "powershell.*-enc"
```

자세한 내용은 `rules/README.txt`를 참조하세요.

## 환경 변수

```bash
export BS_REDACT=1          # 민감 정보 마스킹 (기본값: 1)
export BS_LOG_LEVEL=INFO   # 로그 레벨 (기본값: INFO)
export BS_MAX_EVENTS=10000 # 최대 이벤트 수 (기본값: 무제한)
```

## 성능

- **처리 속도**: 약 4,000 이벤트/초
- **메모리 사용량**: 이벤트 1,000개당 약 5MB
- **최적화**: O(n log n) 복잡도의 상관분석 알고리즘

자세한 성능 정보는 [PERFORMANCE.md](docs/PERFORMANCE.md)를 참조하세요.

## 요구사항

- Python 3.8 이상
- Windows (이벤트 로그 수집 기능 사용 시)
- 선택적: `python-evtx` (EVTX 파일 변환)
- 선택적: `weasyprint` (PDF 리포트 생성)

## 버전

현재 버전: **1.0.0**

## 라이선스

이 프로젝트는 [MIT License](LICENSE)를 따릅니다.

MIT License는 자유롭게 사용, 수정, 배포할 수 있는 오픈소스 라이선스입니다. 자세한 내용은 [LICENSE](LICENSE) 파일을 참조하세요.

## 기여

BreachScope 프로젝트에 기여를 환영합니다! 기여 방법은 [CONTRIBUTING.md](CONTRIBUTING.md)를 참조하세요.

### 기여 방법

1. **이슈 리포트**: 버그나 기능 개선 아이디어를 [GitHub Issues](https://github.com/bbk0416/BreachScope/issues)에 등록
2. **코드 기여**: Pull Request를 통해 코드 기여
3. **문서 개선**: 문서 오류 수정 또는 개선
4. **테스트 코드**: 테스트 커버리지 향상

자세한 내용은 [기여 가이드](CONTRIBUTING.md)를 확인해주세요.

## 변경 이력

주요 변경 사항은 [CHANGELOG.md](docs/CHANGELOG.md)를 참조하세요.

## 유지보수

### 임시 파일 정리

```bash
# 임시 파일 정리 스크립트 실행
python scripts/cleanup_temp.py --yes
```

프로젝트 내 및 시스템 임시 디렉토리의 BreachScope 관련 임시 파일을 자동으로 정리합니다.

## 참고 자료

- [MITRE ATT&CK Framework](https://attack.mitre.org/)
- [Sigma Rules](https://github.com/SigmaHQ/sigma)
- 원본 설계 문서: `BreachScope 시스템 아키텍처 기획 및 설계 연구.pdf`

## 지원

### 이슈 리포트

버그 리포트나 기능 요청은 [GitHub Issues](https://github.com/bbk0416/BreachScope/issues)를 사용해주세요.

### 질문

기술적 질문이나 사용법 문의도 GitHub Issues를 통해 남겨주시면 도와드리겠습니다.

---

**BreachScope** - 자동화된 디지털 포렌식 분석 도구
