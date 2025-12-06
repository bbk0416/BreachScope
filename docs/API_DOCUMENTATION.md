# BreachScope API 문서

## 웹 API 엔드포인트

### GET `/`
메인 페이지를 반환합니다.

**응답**: HTML 페이지

---

### POST `/api/analyze`
로그 파일을 분석하고 리포트를 생성합니다.

**요청 형식**: `multipart/form-data`

**파라미터**:
- `files` (List[UploadFile], 선택): 업로드할 로그 파일 (JSONL 또는 EVTX)
- `use_repo_rules` (bool, 기본값: True): 저장소의 rules/ 디렉토리 사용 여부
- `min_severity` (str, 기본값: "medium"): 최소 심각도 필터 (low, medium, high, critical)
- `mitre_include` (str, 선택): 포함할 MITRE 기법 (쉼표 구분, 예: "T1059.001,T1105")
- `mitre_exclude` (str, 선택): 제외할 MITRE 기법 (쉼표 구분)
- `host_include` (str, 선택): 포함할 호스트 (쉼표 구분)
- `redact` (bool, 기본값: True): 민감 정보 마스킹 여부
- `render_pdf` (bool, 기본값: False): PDF 리포트 생성 여부
- `do_evtx` (bool, 기본값: False): EVTX 파일 자동 변환 여부
- `collect_evtx` (bool, 기본값: False): Windows 이벤트 로그 자동 수집 여부
- `collect_logs` (str, 선택): 수집할 로그 이름 (쉼표 구분, 예: "Security,System")
- `collect_hours` (int, 선택): 최근 N시간만 수집 (0이면 전체)
- `work_dir` (str, 선택): 작업 디렉토리 경로

**응답**:
```json
{
  "success": true,
  "count": 10,
  "html_path": "/path/to/report.html",
  "json_path": "/path/to/report.json",
  "csv_path": "/path/to/report.csv",
  "pdf_path": "/path/to/report.pdf",
  "work_dir": "/path/to/work/directory"
}
```

**에러 응답**:
```json
{
  "error": "분석 오류",
  "message": "오류 메시지",
  "details": {}
}
```

---

### GET `/api/report/{work_dir:path}`
생성된 리포트 파일을 다운로드합니다.

**파라미터**:
- `work_dir` (path): 작업 디렉토리 경로
- `file_type` (str, 기본값: "html"): 파일 타입 (html, json, csv, pdf)

**응답**: 파일 다운로드

---

### GET `/api/rules`
사용 가능한 규칙 목록을 조회합니다.

**응답**:
```json
{
  "count": 5,
  "rules": [
    {
      "id": "rule-001",
      "name": "Suspicious PowerShell",
      "description": "의심스러운 PowerShell 명령 탐지",
      "severity": "high",
      "mitre_technique": "T1059.001"
    }
  ]
}
```

---

### GET `/api/health`
서비스 상태를 확인합니다.

**응답**:
```json
{
  "status": "healthy",
  "version": "1.0.0"
}
```

## Python API

### Pipeline 클래스

```python
from breachscope.pipeline import Pipeline
from pathlib import Path

# 파이프라인 초기화
pipeline = Pipeline(
    rules_dir=Path("rules"),
    min_severity="medium",
    mitre_include=["T1059.001"],
    max_events=10000,  # 대용량 파일 처리 시 제한
)

# 전체 파이프라인 실행
html_path, count = pipeline.run(
    input_dir=Path("logs"),
    out_prefix=Path("out/report"),
    export_json=True,
    export_csv=True,
    render_pdf=False,
)
```

### 단계별 실행

```python
# 1. 이벤트 수집
events = pipeline.collect_events(Path("logs"))

# 2. 규칙 기반 분석
findings = pipeline.analyze()

# 3. 상관분석
chains = pipeline.correlate()

# 4. 시나리오 추론
scenarios = pipeline.infer_scenarios()

# 5. 리포트 생성
report = pipeline.build_report()

# 6. 리포트 내보내기
html_path = pipeline.export_report(
    Path("out/report"),
    export_json=True,
    export_csv=True,
)
```

## 환경 변수

- `BS_REDACT`: 민감 정보 마스킹 여부 ("0"이면 비활성화, 기본값: "1")
- `BS_LOG_LEVEL`: 로그 레벨 (DEBUG, INFO, WARNING, ERROR, 기본값: INFO)
- `BS_MAX_EVENTS`: 최대 이벤트 수 (기본값: 무제한)

## 설정 파일

`breachscope.yaml` 파일을 통해 설정을 관리할 수 있습니다:

```yaml
redact: true
default_severity: medium
time_window_default: 300
log_level: INFO
max_events: 10000
```
