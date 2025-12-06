# BreachScope 사용 가이드

## 📋 사전 요구사항

### 필수 패키지 설치
```bash
pip install -r requirements.txt
```

**필수 패키지**:
- `jinja2>=3.1` - HTML 템플릿
- `pyyaml>=6.0` - YAML 규칙 파싱
- `fastapi>=0.104` - 웹 프레임워크
- `uvicorn[standard]>=0.24` - ASGI 서버
- `python-multipart>=0.0.6` - 파일 업로드 지원

**선택 패키지**:
- `weasyprint>=62` - PDF 리포트 생성
- `python-evtx>=0.6` - EVTX 파일 변환

## 🚀 실행 방법

### 1. CLI로 실행 (권장)

#### 기본 실행
```bash
python -m breachscope.cli --input <로그폴더> --rules rules --out out/report
```

#### 데모 실행 (샘플 로그 자동 생성)
```bash
python -m breachscope.cli --demo --rules rules --out out/report
```

#### 옵션 포함 실행
```bash
python -m breachscope.cli \
  --input <로그폴더> \
  --rules rules \
  --out out/report \
  --min-severity medium \
  --mitre-include T1059.001 \
  --export-json \
  --export-csv
```

#### EVTX 파일 변환 포함
```bash
python -m breachscope.cli \
  --input <EVTX파일폴더> \
  --ingest-evtx \
  --rules rules \
  --out out/report
```

### 2. PowerShell 스크립트로 실행 (Windows)

```powershell
.\scripts\run_demo.ps1
```

### 3. 웹 UI로 실행

```bash
# Windows
run_web_fastapi.bat

# Linux/Mac
./run_web_fastapi.sh
```

또는 직접 실행:
```bash
python -m uvicorn web.app_fastapi:app --host 0.0.0.0 --port 8501
```

브라우저에서 `http://localhost:8501` 접속

## 📝 주요 옵션 설명

### 필수 옵션
- `--rules`: 규칙 파일이 있는 폴더 경로
- `--out`: 출력 파일 경로 접두어 (확장자 제외)

### 입력 옵션
- `--input`: 입력 로그 폴더 (JSONL 파일)
- `--demo`: 데모용 샘플 로그 자동 생성
- `--ingest-evtx`: EVTX 파일을 JSONL로 자동 변환

### 필터 옵션
- `--min-severity`: 최소 심각도 (`low`, `medium`, `high`, `critical`)
- `--mitre-include`: 포함할 MITRE 기법 (쉼표 구분, 예: `T1059.001,T1105`)
- `--mitre-exclude`: 제외할 MITRE 기법 (쉼표 구분)
- `--host-include`: 포함할 호스트 (쉼표 구분)

### 출력 옵션
- `--export-json`: JSON 리포트도 생성
- `--export-csv`: CSV 리포트도 생성
- `--pdf`: PDF 리포트 생성 (WeasyPrint 필요)
- `--no-redact`: 민감 정보 마스킹 비활성화
- `--open`: 생성 후 브라우저로 HTML 리포트 열기

### 검증 옵션
- `--validate-rules`: 규칙만 검증하고 종료
- `--validate-input`: 입력 로그 유효성 검사 후 종료

### CI/CD 옵션
- `--fail-on-findings`: 탐지 발생 시 종료 코드 1
- `--fail-threshold N`: 탐지 건수가 N 이상이면 실패 처리

## 📂 입력 데이터 형식

### JSONL 형식
각 줄이 JSON 객체인 형식:
```json
{"timestamp": "2024-01-01T10:00:00Z", "host": "WS-01", "source": "ProcessCreate", "event_id": "4688", "user": "CORP\\alice", "command_line": "powershell.exe -enc AAAABBBB"}
{"timestamp": "2024-01-01T10:01:00Z", "host": "WS-01", "source": "ProcessCreate", "event_id": "4688", "user": "CORP\\alice", "command_line": "cmd.exe /c echo test"}
```

**필수 필드**:
- `timestamp`: 타임스탬프 (ISO 8601 형식)
- `host`: 호스트명
- `source`: 이벤트 소스
- `event_id`: 이벤트 ID (선택)

**선택 필드**:
- `user`: 사용자명
- `command_line`: 명령줄
- `level`: 로그 레벨

### EVTX 형식
Windows 이벤트 로그 파일 (`.evtx`)
- `--ingest-evtx` 옵션 사용 시 자동 변환
- `python-evtx` 패키지 필요

## 📊 출력 파일

### HTML 리포트
- 기본 출력 형식
- `out/report.html` 생성
- 브라우저에서 열람 가능

### JSON 리포트
- `--export-json` 옵션 사용 시
- `out/report.json` 생성
- 프로그래밍 방식으로 처리 가능

### CSV 리포트
- `--export-csv` 옵션 사용 시
- `out/report.csv` 생성
- Excel 등에서 열람 가능

### PDF 리포트
- `--pdf` 옵션 사용 시
- `out/report.pdf` 생성
- WeasyPrint 패키지 필요

## 🔧 Python 코드로 사용

### 기존 방식 (함수형)
```python
from pathlib import Path
from breachscope.pipeline import run_pipeline

html_path, count = run_pipeline(
    input_dir=Path("logs"),
    rules_dir=Path("rules"),
    out_prefix=Path("out/report"),
    export_json_flag=True,
    export_csv_flag=True,
    min_severity="medium",
)
print(f"탐지 {count}건, 리포트: {html_path}")
```

### 새로운 방식 (클래스 기반, 권장)
```python
from pathlib import Path
from breachscope.pipeline import Pipeline

# 파이프라인 생성
pipeline = Pipeline(
    rules_dir=Path("rules"),
    min_severity="medium",
    mitre_include=["T1059.001"],
)

# 단계별 실행
pipeline.collect_events(Path("logs"))
pipeline.analyze()
pipeline.correlate()
pipeline.infer_scenarios()

# 리포트 생성
pipeline.build_report()
html_path = pipeline.export_report(
    Path("out/report"),
    export_json=True,
    export_csv=True,
)

# 또는 한 번에 실행
html_path, count = pipeline.run(
    Path("logs"),
    Path("out/report"),
    export_json=True,
    export_csv=True,
)
```

## 🎯 사용 예시

### 예시 1: 기본 분석
```bash
python -m breachscope.cli --demo --rules rules --out out/report
```

### 예시 2: 실제 로그 분석
```bash
python -m breachscope.cli \
  --input C:\logs \
  --rules rules \
  --out out/report \
  --export-json \
  --export-csv \
  --open
```

### 예시 3: 필터링 적용
```bash
python -m breachscope.cli \
  --input logs \
  --rules rules \
  --out out/report \
  --min-severity high \
  --mitre-include T1059.001,T1105 \
  --host-include WS-01,WS-02
```

### 예시 4: EVTX 변환
```bash
python -m breachscope.cli \
  --input C:\Windows\System32\winevt\Logs \
  --ingest-evtx \
  --rules rules \
  --out out/report
```

### 예시 5: 규칙 검증
```bash
python -m breachscope.cli --validate-rules --rules rules
```

### 예시 6: 입력 검증
```bash
python -m breachscope.cli --validate-input --input logs --rules rules
```

## 🌐 웹 UI 사용

### 실행
```bash
python -m uvicorn web.app_fastapi:app --host 0.0.0.0 --port 8501
```

### 기능
1. **로그 업로드**: JSONL 또는 EVTX 파일 업로드
2. **규칙 선택**: 저장소 규칙 사용 또는 직접 업로드
3. **옵션 설정**: 심각도, MITRE 필터 등 설정
4. **분석 실행**: 분석 버튼 클릭
5. **리포트 다운로드**: HTML, JSON, CSV 다운로드

## ⚙️ 설정 파일

프로젝트 루트에 `breachscope.yaml` 파일을 생성하여 기본 설정 가능:

```yaml
rules: rules
min_severity: medium
mitre_include:
  - T1059.001
  - T1105
export_json: true
export_csv: true
```

CLI 인자가 설정 파일보다 우선합니다.

## 🐛 문제 해결

### 규칙이 로드되지 않음
- `--rules` 경로 확인
- YAML 파일 형식 확인
- `--validate-rules`로 규칙 검증

### 이벤트가 분석되지 않음
- JSONL 파일 형식 확인
- 필수 필드 (timestamp, host, source) 확인
- `--validate-input`으로 입력 검증

### 리포트가 생성되지 않음
- 출력 디렉토리 쓰기 권한 확인
- Jinja2 패키지 설치 확인

### PDF 생성 실패
- WeasyPrint 패키지 설치 필요
- 또는 `--pdf` 옵션 제거

## 📚 추가 정보

- 상세 문서: `PROGRESS.md`
- 변경 이력: `CHANGELOG.md`
- 개선 사항: `IMPROVEMENTS.md`
- 리팩토링: `REFACTORING.md`
