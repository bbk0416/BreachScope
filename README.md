# BreachScope

[![CI](https://github.com/bbk0416/BreachScope/actions/workflows/ci.yml/badge.svg)](https://github.com/bbk0416/BreachScope/actions/workflows/ci.yml)
[![Docker Build](https://github.com/bbk0416/BreachScope/actions/workflows/docker.yml/badge.svg)](https://github.com/bbk0416/BreachScope/actions/workflows/docker.yml)
[![Release](https://github.com/bbk0416/BreachScope/actions/workflows/release.yml/badge.svg)](https://github.com/bbk0416/BreachScope/actions/workflows/release.yml)
![Python](https://img.shields.io/badge/python-3.10%2B-blue)
![License](https://img.shields.io/badge/license-MIT-green)

**BreachScope**는 Windows Event Log를 중심으로 탐지 결과를 상관분석하고, 조사 가능한 사건 흐름·케이스·리포트로 연결하는 DFIR 분석 도구입니다.

이 프로젝트의 강점은 탐지 엔진 자체의 속도 경쟁보다는 **입력 → 정규화 → 탐지 → 상관분석 → 시나리오 → 케이스 → 리포트**를 한 흐름으로 묶는 데 있습니다.

## 현재 상태

- 공개 릴리즈: `v1.0.0`
- 패키지 메타데이터 상태: Beta
- Python: 3.10 / 3.11 / 3.12 CI
- 기본 CI 실행 환경: Ubuntu
- Windows 네이티브 수집 기능은 존재하지만 Windows runner 기반 지속 검증은 아직 별도 보강이 필요합니다.
- 내장 demo/evaluation 데이터는 **합성(synthetic) 회귀 데이터**입니다. 실제 기업 환경의 탐지 정확도나 오탐률을 증명하지 않습니다.
- 외부 holdout 평가 도구(`scripts/evaluate_external_holdout.py`)는 포함되어 있지만, 이 README는 아직 독립 외부 corpus의 production-grade precision/recall 결과를 주장하지 않습니다.

따라서 현재 BreachScope는 **포트폴리오, 연구, 내부 DFIR 보조, 사고 triage** 용도로 보는 것이 맞습니다. 사람의 확인 없이 자동 차단·법적 판단·기업 전사 운영을 맡기는 production-grade DFIR 플랫폼으로 주장하지 않습니다.

## 주요 기능

- **규칙 기반 탐지**: 프로젝트 내장 YAML 룰팩과 선택적 외부 탐지 backend를 사용합니다.
- **Hayabusa 연동**: Hayabusa 결과를 BreachScope Finding으로 받아 후단 상관분석·시나리오·리포팅에 연결할 수 있습니다.
- **시간/세션 기반 상관분석**: 호스트·사용자·Windows 세션과 이벤트 시간을 이용해 관련 증거를 체인으로 묶습니다.
- **시나리오 매칭**: ATT&CK technique과 chain pattern을 이용한 기본 템플릿 및 사용자 정의 템플릿을 지원합니다.
- **EVTX 처리**: `python-evtx`를 이용한 EVTX 변환과 JSONL 분석을 지원합니다.
- **Windows 로그 수집**: Windows에서 `wevtutil.exe`를 이용해 이벤트 로그를 수집할 수 있습니다.
- **일부 Windows artifact 모듈**: Browser History, Prefetch, Registry, USB 관련 수집/분류 모듈이 있습니다. 현재 제품의 주 분석 흐름은 Windows Event Log 중심이며, 종합 포렌식 artifact suite 전체를 대체한다고 주장하지 않습니다.
- **리포트**: HTML, JSON, CSV, IOC CSV, 룰 카탈로그 CSV, PDF, manifest, case ZIP을 생성할 수 있습니다.
- **웹/API**: FastAPI 기반 분석·케이스·보고서·운영 API와 웹 콘솔을 제공합니다.
- **케이스 이력**: 분석 결과 재열람, 다운로드, 삭제, 보존 정리를 지원합니다.
- **감사 로그**: 로그인, 분석, 조회, 다운로드, 삭제 등 운영 이벤트를 기록하고 무결성 확인 기능을 제공합니다.
- **백업/운영 점검**: 케이스 백업, health/readiness, project check, quality gate, go-live check를 제공합니다.
- **Docker/릴리즈**: Docker, Compose, GitHub Actions, release ZIP/checksum/manifest 생성 절차를 포함합니다.

## 빠른 시작

### 설치

```bash
git clone https://github.com/bbk0416/BreachScope.git
cd BreachScope
pip install -r requirements.txt
```

### 안전한 데모

```bash
python scripts/run.py --demo --export-json --export-csv
```

내장 사고 시나리오 전체를 실행하려면:

```bash
python scripts/run.py --demo-scenario all --out out/report --export-json --export-csv --pdf
```

### JSONL 분석

```bash
python scripts/run.py --input logs/ --rules rules/ --out out/report
```

### EVTX 변환 후 분석

```bash
python scripts/run.py --input evtx/ --ingest-evtx --out out/report
```

### Windows 이벤트 로그 직접 수집

Windows에서 실행합니다.

```bash
python scripts/run.py --collect-evtx --collect-logs Security,System --collect-hours 24
```

### 웹 콘솔

Windows:

```bat
run_web_fastapi.bat
```

Linux/macOS:

```bash
./run_web_fastapi.sh
```

직접 실행:

```bash
python -m uvicorn api.main:app --host 0.0.0.0 --port 8501 --reload
```

## Docker

운영용 환경 파일을 먼저 생성하고 값을 검토합니다.

```bash
python scripts/init_env.py --production --https --output .env
docker compose up --build
```

인터넷에 바로 노출하는 대신 내부망/VPN 또는 HTTPS reverse proxy 뒤에서 사용하는 것을 권장합니다. 보안 기본값과 제한은 [SECURITY.md](SECURITY.md)를 확인하세요.

## 검증 명령

### 테스트

```bash
pytest -q
```

### 룰팩 검증

```bash
python scripts/run.py --validate-rules
```

### 프로젝트/품질/배포 점검

```bash
python scripts/project_check.py --strict
python scripts/quality_gate.py --strict
python scripts/go_live_check.py --deployment-mode production
```

이 점수들은 **프로젝트 구성·문서·운영 준비 상태를 확인하는 gate**이며 실제 탐지 precision/recall 점수가 아닙니다.

### 내장 detection corpus

```bash
python scripts/evaluate_detection_corpus.py
```

내장 corpus는 회귀 테스트용 synthetic 데이터입니다. production 정확도 근거로 사용하지 않습니다.

### 외부 holdout 평가

```bash
python scripts/evaluate_external_holdout.py --help
```

외부 데이터 평가 시에는 최소한 다음을 함께 기록해야 합니다.

- BreachScope commit SHA
- rule pack hash
- corpus/source와 SHA-256
- labeling 기준
- TP / FP / TN / FN
- precision / recall / false-positive rate
- scenario hit 결과
- 실행 시간과 peak memory

외부 baseline 방법은 저장소의 evaluation 문서를 참고하세요.

## 성능에 대한 현재 입장

현재 저장소는 병렬 detection 경로와 SQLite WAL 기반 저장 모듈을 포함하지만, **재현 가능한 benchmark runner로 고정된 대용량 성능 수치를 아직 공개 근거로 삼지 않습니다.**

따라서 다음과 같은 표현은 현재 프로젝트의 보장사항이 아닙니다.

- “100만 이벤트를 N초에 처리한다”
- “병렬 처리로 항상 2~4배 빨라진다”
- “일정 메모리 안에서 대용량 전체를 streaming 처리한다”

현재 파이프라인은 일반 실행에서 정규화된 이벤트를 메모리 리스트로 구성합니다. 대규모 운영 성능은 별도 재현 benchmark가 필요합니다. 자세한 내용은 [docs/PERFORMANCE.md](docs/PERFORMANCE.md)를 확인하세요.

## 아키텍처

현재 구현 기준 아키텍처는 [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md)에 정리되어 있습니다.

핵심 흐름은 다음과 같습니다.

```text
EVTX / JSONL / Windows collection
            ↓
      ingest / normalize
            ↓
 native rules + optional Hayabusa
            ↓
         findings
            ↓
 correlation (time/host/user/session)
            ↓
     scenario matching
            ↓
 report / IOC / case package
            ↓
 case history / audit / backup / web API
```

## 프로젝트가 주장하지 않는 것

BreachScope는 현재 다음을 주장하지 않습니다.

- Hayabusa/Chainsaw보다 빠른 EVTX 탐지 엔진
- 모든 Windows forensic artifact를 포괄하는 수집 플랫폼
- 90% 이상의 실전 탐지 정확도
- 사람 검토 없이 사용할 수 있는 자동 사고 판정 시스템
- 대규모 엔터프라이즈 멀티테넌트/HA 서비스
- 외부 독립 평가로 검증된 production-ready 탐지 제품

## 문서

- [현재 아키텍처](docs/ARCHITECTURE.md)
- [성능/benchmark 상태](docs/PERFORMANCE.md)
- [배포](docs/DEPLOYMENT.md)
- [보안 정책](SECURITY.md)
- [CI/CD](docs/CI_CD.md)
- [릴리즈](docs/RELEASE.md)
- [Go-Live](docs/GO_LIVE.md)
- [Project Readiness](docs/PROJECT_READINESS.md)

## 라이선스

MIT License
