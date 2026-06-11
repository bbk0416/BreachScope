# BreachScope

[![CI](https://github.com/bbk0416/BreachScope/actions/workflows/ci.yml/badge.svg)](https://github.com/bbk0416/BreachScope/actions/workflows/ci.yml)
[![Docker Build](https://github.com/bbk0416/BreachScope/actions/workflows/docker.yml/badge.svg)](https://github.com/bbk0416/BreachScope/actions/workflows/docker.yml)
[![Release](https://github.com/bbk0416/BreachScope/actions/workflows/release.yml/badge.svg)](https://github.com/bbk0416/BreachScope/actions/workflows/release.yml)
![Python](https://img.shields.io/badge/python-3.10%2B-blue)
![License](https://img.shields.io/badge/license-MIT-green)

**BreachScope**는 디지털 포렌식 및 사고 대응(DFIR)을 위한 자동화된 로그 분석 도구입니다. Windows 이벤트 로그와 다양한 보안 로그를 분석하여 공격 시나리오를 자동으로 탐지하고 시각화합니다.

**작성자**: bbk0416 (bbk0416@gmail.com)

## 주요 기능

- 🔍 **규칙 기반 탐지**: YAML 기반 50개 룰팩으로 의심스러운 활동 자동 탐지
- 🔗 **시간 기반 상관분석**: 이벤트 간 시간적 연관성을 분석하여 공격 체인 생성
- 🎯 **시나리오 추론**: MITRE ATT&CK 기반 공격 시나리오 자동 추론 (12개 기본 템플릿 + 사용자 정의 템플릿 지원)
- 📊 **시각화 리포트**: HTML, JSON, CSV, 한글 PDF 형식의 상세 분석 리포트 생성 (인터랙티브 타임라인 포함)
- 🧾 **케이스 패키지**: HTML/JSON/CSV/IOC CSV/룰 카탈로그/한글 PDF/manifest를 ZIP으로 묶고 산출물 SHA-256 해시 제공
- 📌 **위험도 요약**: Risk Score, 호스트별 위험도, 조사 포커스, 우선 조치 권고 자동 생성
- 🧭 **사고 타임라인/ATT&CK 커버리지**: 탐지 결과와 룰팩 커버리지를 시간순·전술별로 재구성
- 🧩 **IOC 후보 추출**: URL, IP, 도메인, 해시, 파일 경로 후보를 별도 CSV로 추출
- 🪟 **Windows 이벤트 로그 수집**: `wevtutil.exe`를 사용한 자동 로그 수집
- 🌐 **웹 콘솔 대시보드**: 업로드 직후 Risk/호스트/ATT&CK/IOC/타임라인 미리보기와 산출물 다운로드 제공
- 🔐 **제품 배포 옵션**: Docker Compose, API Key 보호, 관리자 로그인(HttpOnly 세션), 로그인 실패 잠금, 영구 데이터 볼륨, 운영 환경 변수 템플릿 제공
- 🗂️ **케이스 이력 관리**: 최근 분석 목록, 케이스 ID 기반 재열람/다운로드/삭제/보존정리 API 제공
- 🧭 **감사 로그/Audit Trail**: 로그인, 분석, 다운로드, 케이스 삭제/정리/백업 이벤트를 JSONL/CSV로 기록하고 무결성 해시 제공
- 💾 **운영 백업**: 케이스 이력, 케이스 파일, 감사 로그를 ZIP 백업으로 묶고 SHA-256 무결성 확인 제공
- 🩺 **운영 관측성**: Liveness/Readiness, Prometheus 메트릭, 설정 진단, 합성 셀프테스트 API 제공
- 🚀 **CI/CD·릴리즈 자동화**: GitHub Actions, Docker smoke test, 릴리즈 ZIP/checksum/manifest 생성, 빌드 메타데이터 API 제공
- 🧷 **정적 쇼케이스**: GitHub Pages에 올릴 수 있는 랜딩 페이지, 소셜 프리뷰 SVG, 데모 리포트 번들을 자동 생성
- ✅ **Go-Live 안전장치**: `.env` 랜덤 시크릿 생성, 운영 전 인증/쿠키/문서노출/감사로그/데이터 경로 최종 점검 제공
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
python scripts/run.py --demo --export-json --export-csv
# out/report.html, out/report.json, out/report.csv, out/report.iocs.csv, out/report.rules.csv, out/report.manifest.json, out/report.zip 생성
# PDF까지 필요하면 --pdf 옵션 추가: out/report.pdf 생성
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

브라우저에서 `http://localhost:8501`로 접속하세요. 분석 완료 후 Risk 카드, Top Findings, 사고 타임라인, ATT&CK 커버리지, 호스트 위험도, IOC 요약을 웹에서 바로 확인할 수 있습니다. 전체 산출물은 HTML/JSON/CSV/IOC CSV/룰 CSV/Manifest/ZIP/PDF로 다운로드됩니다. 최근 분석은 케이스 이력에 저장되어 웹에서 다시 열 수 있고, 운영 관리 패널에서 백업 생성/케이스 정리를 수행할 수 있습니다. 상태/진단 패널에서 메트릭, 설정 점검, 셀프테스트도 실행할 수 있고, 로그인/분석/다운로드/삭제/백업 같은 운영 이벤트는 감사 로그 패널에서 확인할 수 있습니다.



### Docker Compose 배포

```bash
python scripts/init_env.py --production --https --output .env
# .env 검토 후 실행
docker compose up --build
```

브라우저에서 `http://localhost:8000`으로 접속합니다. `BS_ADMIN_PASSWORD`를 설정한 경우 웹 UI의 **배포 보안 > 관리자 로그인**으로 로그인하면 HttpOnly 세션 쿠키가 발급됩니다. 자동화/API 클라이언트는 `BS_API_KEY`를 `X-API-Key` 또는 `Authorization: Bearer` 헤더로 전달하면 됩니다.

운영 배포 권장값:

```bash
BS_API_KEY=<long-random-api-secret>
BS_ADMIN_PASSWORD=<operator-console-password>
BS_SESSION_SECRET=<long-random-session-secret>
BS_SESSION_TTL_SECONDS=28800
BS_AUTH_MAX_FAILURES=5
BS_AUTH_LOCKOUT_SECONDS=300
BS_AUTH_RATE_LIMIT_PATH=/data/auth_rate_limit.json
BS_DISABLE_DOCS=1
BS_CASES_ROOT=/data/cases
BS_CASE_HISTORY_PATH=/data/case_history.json
BS_AUDIT_ENABLED=1
BS_AUDIT_LOG_PATH=/data/audit.jsonl
BS_AUDIT_CHAIN_SECRET=change-me-audit-chain-secret
BS_BACKUP_ROOT=/data/backups
```

자세한 내용은 [배포 가이드](docs/DEPLOYMENT.md)와 [보안 정책](SECURITY.md)을 참고하세요.

### Makefile 명령

```bash
make setup       # 개발 의존성 설치
make test        # compileall + pytest
make demo-all    # 10개 내장 사고 시나리오 전체 실행 + PDF 생성
make web         # 로컬 웹 콘솔 실행
make docker-up   # Docker Compose 실행
make release     # dist/ 릴리즈 ZIP + SHA256SUMS + manifest 생성
make demo-pack  # 제출/시연용 demo pack 생성
make showcase   # GitHub Pages용 정적 쇼케이스 생성
make publish-prep # 공개 직전 최종 핸드오프 패키지 생성
make ci-local    # test + demo-all + validate + release 로컬 일괄 검증
```


### 프로젝트 공개 전 점검

```bash
python scripts/project_check.py --strict
python scripts/project_check.py --markdown --output out/project_readiness.md
```

웹 콘솔에서는 다음 API로 동일한 공개/릴리즈 준비 상태를 확인할 수 있습니다.

```http
GET /api/ops/project-check
```

데모 발표 흐름은 [데모 스크립트](docs/DEMO_SCRIPT.md), 포트폴리오 설명 문구는 [포트폴리오 피치](docs/PORTFOLIO_PITCH.md), 공개 전 점검 기준은 [프로젝트 준비도 점검](docs/PROJECT_READINESS.md)을 참고하세요.

### 제출/시연용 Demo Pack 생성

```bash
python scripts/build_demo_pack.py --clean
# 빠른 검증용: python scripts/build_demo_pack.py --clean --no-pdf
```

`out/demo_pack/breachscope-demo-pack.zip`에는 HTML/PDF/JSON/CSV/IOC/룰 카탈로그 리포트와 5분 시연 스크립트, 포트폴리오 피치, GitHub 업로드 체크리스트, SHA-256 checksum이 함께 들어갑니다. 자세한 내용은 [Demo Pack Builder](docs/DEMO_PACK.md)를 참고하세요.

### GitHub Pages용 정적 Showcase 생성

```bash
python scripts/build_showcase.py --clean
# 빠른 검증용: python scripts/build_showcase.py --clean --no-pdf
```

`out/showcase/index.html`은 브라우저에서 바로 열 수 있는 랜딩 페이지이고, `out/showcase/breachscope-showcase.zip`에는 랜딩 페이지, 소셜 프리뷰 SVG, 데모 리포트, 요약 JSON, SHA-256 checksum이 함께 들어갑니다. 자세한 내용은 [Static Showcase](docs/SHOWCASE.md)를 참고하세요.

### 공개 직전 Publish Prep 패키지 생성

```bash
python scripts/publish_prep.py --clean
# 빠른 검증용: python scripts/publish_prep.py --clean --no-pdf
```

`out/publish/breachscope-public-launch-pack.zip`에는 릴리즈 ZIP/checksum/manifest, Demo Pack, Showcase, 공개 명령어, 릴리즈 노트 초안, 최종 요약 문서가 함께 들어갑니다. ZIP 내부에 `__pycache__`, `.env`, `.pyc`, 로컬 DB/로그 파일이 섞이지 않았는지도 검사합니다. 자세한 내용은 [Public Publish Prep](docs/PUBLISH_PREP.md)를 참고하세요.

```http
GET /api/ops/publish-prep-preview
```

### 운영 전 Go-Live 점검

```bash
python scripts/init_env.py --production --https --output .env
python scripts/go_live_check.py --deployment-mode production
python scripts/go_live_check.py --deployment-mode production --markdown --output out/go_live.md
```

웹 콘솔의 **상태/진단 > Go-Live 점검** 또는 API에서도 확인할 수 있습니다.

```http
GET /api/ops/go-live?deployment_mode=production
```

자세한 첫 배포 절차는 [Go-Live 체크리스트](docs/GO_LIVE.md)를 참고하세요.

### CI/CD와 릴리즈 자동화

GitHub Actions 워크플로가 포함되어 있습니다.

```text
.github/workflows/ci.yml       # Python 3.10/3.11/3.12 테스트 + CLI smoke + 룰팩 검증
.github/workflows/docker.yml   # Docker 이미지 빌드 + 컨테이너 health/API smoke test
.github/workflows/release.yml  # 태그 릴리즈 시 패키지/checksum/manifest 생성
```

로컬 릴리즈 번들 생성:

```bash
python scripts/build_release.py --clean
# dist/breachscope-<version>-source.zip
# dist/SHA256SUMS.txt
# dist/release_manifest.json
```

운영 중 배포 버전 확인:

```http
GET /api/ops/release-info
```

자세한 내용은 [CI/CD 가이드](docs/CI_CD.md)와 [릴리즈 절차](docs/RELEASE.md)를 참고하세요.

### 웹 미리보기 API

분석 완료 후 `work_dir` 기준으로 대시보드용 요약 JSON을 다시 조회할 수 있습니다.

```bash
GET /api/report-preview/{work_dir}
```

반환 데이터에는 Risk Score, Executive Summary, Top Findings, 사고 타임라인, ATT&CK 커버리지, 호스트별 위험도, IOC 후보 개수, 룰팩 커버리지가 포함됩니다.

### 케이스 이력 API

분석 완료 후 응답에 `case_id`가 포함됩니다. 파일 시스템 경로를 직접 URL에 노출하지 않고 케이스 ID로 다시 열거나 다운로드할 수 있습니다.

```bash
GET /api/cases?limit=20
GET /api/cases/{case_id}
GET /api/cases/{case_id}/report?file_type=html
POST /api/cases/prune?keep_last=50&older_than_days=30&dry_run=true
DELETE /api/cases/{case_id}
```

기본 케이스 저장 위치는 `~/.breachscope/cases`이며, `BS_CASES_ROOT`와 `BS_CASE_HISTORY_PATH` 환경 변수로 변경할 수 있습니다. `prune` API는 기본 dry-run으로 오래된 케이스 정리 후보를 먼저 보여주고, `dry_run=false`일 때만 실제 삭제합니다.

### 감사 로그 API

운영 이벤트는 기본적으로 `~/.breachscope/audit.jsonl`에 JSONL로 누적됩니다. 웹 UI의 감사 로그 패널에서도 최근 이벤트를 볼 수 있습니다.

```http
GET /api/audit?limit=100
GET /api/audit/export?file_type=jsonl
GET /api/audit/export?file_type=csv
GET /api/audit/integrity
```

기록 대상 예시는 다음과 같습니다.

```text
auth.login / auth.logout / auth.denied
analysis.run
case.view / case.download / case.delete / case.prune
backup.create / backup.download / backup.delete
```

비밀번호, API Key, 세션 토큰 같은 민감 필드는 자동으로 `<redacted>` 처리합니다. `BS_AUDIT_CHAIN_SECRET`을 설정하면 감사 로그 파일에 대한 HMAC-SHA256도 `/api/audit/integrity`에서 확인할 수 있습니다.

### 백업 API

케이스 이력, 케이스 산출물, 감사 로그를 ZIP으로 묶어 보관할 수 있습니다. 백업 ZIP은 기본적으로 `~/.breachscope/backups`에 저장되며 `BS_BACKUP_ROOT`로 변경할 수 있습니다.

```http
GET /api/backups?limit=20
POST /api/backups?include_cases=true&include_audit=true
GET /api/backups/{backup_id}/download
GET /api/backups/{backup_id}/integrity
DELETE /api/backups/{backup_id}
```

각 백업은 SHA-256 해시와 파일 목록 manifest를 함께 보관합니다.

### 운영 상태/진단 API

배포 후 상태 확인과 모니터링을 위해 다음 API를 제공합니다. `/api/health/*`는 인증 설정과 무관하게 probe 용도로 사용할 수 있고, 메트릭/진단/셀프테스트는 인증을 설정한 배포에서는 보호됩니다.

```http
GET /api/health/live
GET /api/health/ready
GET /api/metrics
GET /api/metrics.json
GET /api/ops/config-check
POST /api/ops/self-test
```

- `/api/health/live`: 프로세스 생존 여부와 uptime 확인
- `/api/health/ready`: 케이스/감사/백업 경로 쓰기 가능 여부, 룰팩/템플릿/데모 시나리오 준비 상태 확인
- `/api/metrics`: Prometheus text format
- `/api/metrics.json`: 웹 콘솔용 JSON 메트릭
- `/api/ops/config-check`: 인증, 세션 시크릿, Secure 쿠키, API 문서 노출, 저장 경로, 룰팩 상태 진단
- `/api/ops/self-test`: 합성 `powershell_downloader` 시나리오로 파이프라인과 산출물 생성을 end-to-end 검증

Dockerfile과 docker-compose.yml의 healthcheck는 readiness/liveness 엔드포인트를 사용합니다.

### 한글 PDF 리포트

`--pdf` 옵션 또는 웹 UI의 PDF 생성 체크박스를 사용하면 고객 제출용 한글 요약 PDF가 생성됩니다. PDF에는 Risk Score, 경영진 요약, 우선 조치 권고, Top Findings, 호스트별 위험도, 타임라인, ATT&CK 커버리지, IOC 요약, 초동대응 체크리스트, 오탐 확인 질문이 포함됩니다.

```bash
python scripts/run.py --demo-scenario all --export-json --export-csv --pdf
```

기본은 ReportLab 기반 PDF입니다. 한글 폰트는 시스템에 설치된 NanumGothic/Malgun Gothic 등을 자동 탐지합니다. 운영 환경에서 폰트를 명시하려면 다음 환경 변수를 사용하세요.

```bash
export BS_PDF_FONT_REGULAR=/path/to/Korean-Regular.ttf
export BS_PDF_FONT_BOLD=/path/to/Korean-Bold.ttf
```

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
- [배포 가이드](docs/DEPLOYMENT.md)
- [제품 브리프](docs/PRODUCT_BRIEF.md)
- [보안 정책](SECURITY.md)

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

- Python 3.10 이상
- Windows (이벤트 로그 수집 기능 사용 시)
- 선택적: `python-evtx` (EVTX 파일 변환)
- 선택적: `reportlab` (한글 PDF 리포트 생성, 권장)
- 선택적: `weasyprint` (HTML→PDF 폴백 렌더링)

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


## 내장 사고 시나리오 샘플

BreachScope에는 제품 시연과 회귀 테스트를 위한 합성 JSONL 사고 시나리오가 포함되어 있습니다. 실제 침해 데이터가 아니며 `example.local`, `SIMULATED`, 데모 파일명을 사용합니다.

```bash
# 사용 가능한 시나리오 확인
python scripts/run.py --list-demo-scenarios

# 특정 시나리오 분석
python scripts/run.py --demo-scenario ransomware_preparation --export-json --export-csv

# 10개 시나리오 전체 분석
python scripts/run.py --demo-scenario all --export-json --export-csv

# 샘플 JSONL을 원하는 폴더로 내보내기
python scripts/run.py --export-demo-scenarios samples/scenarios
```

기본 제공 시나리오 범위는 PowerShell downloader, credential dump, ransomware preparation, lateral movement, AD discovery, LOLBins proxy execution, cloud exfiltration, persistence, defense evasion, user data collection입니다.


### 케이스 워크플로

담당자/상태/태그/분석 메모/종결 요약을 케이스별로 저장할 수 있습니다. 자세한 내용은 [docs/CASE_WORKFLOW.md](docs/CASE_WORKFLOW.md)를 참고하세요.
