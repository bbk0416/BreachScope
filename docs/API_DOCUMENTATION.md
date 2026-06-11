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
  "case_id": "case-20260611-120000-ab12cd34",
  "risk_score": 73,
  "risk_level": "high",
  "preview": {},
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
- `file_type` (str, 기본값: "html"): 파일 타입 (html, json, csv, iocs, rules, manifest, zip, pdf)

**응답**: 파일 다운로드

---


### GET `/api/cases`
최근 분석 케이스 목록을 반환합니다.

**파라미터**:
- `limit` (int, 기본값: 20, 최대 100): 반환할 케이스 수

**응답**:
```json
{
  "success": true,
  "cases": [
    {
      "case_id": "case-20260611-120000-ab12cd34",
      "created_at": "2026-06-11T12:00:00Z",
      "risk_score": 73,
      "risk_level": "high",
      "finding_count": 10,
      "hosts": ["WS-01"],
      "artifacts": {"html": true, "json": true, "zip": true}
    }
  ]
}
```

---

### GET `/api/cases/{case_id}`
케이스 메타데이터와 대시보드 미리보기를 반환합니다.

---

### GET `/api/cases/{case_id}/report`
케이스 ID 기준으로 산출물을 다운로드합니다.

**파라미터**:
- `file_type` (str): html, json, csv, iocs, rules, manifest, zip, pdf

---

### DELETE `/api/cases/{case_id}`
케이스 이력에서 제거합니다. 기본적으로 안전한 케이스 작업 디렉토리도 함께 삭제합니다.

**파라미터**:
- `remove_files` (bool, 기본값: true): 산출물 파일 삭제 여부

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


## Case Workflow

### GET `/api/cases/workflow/summary`
Returns a board-style summary grouped by workflow status, assignee, and effective severity.

### PATCH `/api/cases/{case_id}/workflow`
Updates analyst-owned triage fields without modifying generated evidence artifacts.

Request body:

```json
{
  "workflow_status": "investigating",
  "assignee": "analyst-a",
  "tags": ["powershell", "priority-high"],
  "notes": "Investigation notes",
  "severity_override": "critical",
  "closure_summary": "Final disposition",
  "title": "Case title"
}
```

Every successful or failed update is recorded as `case.workflow.update` in the audit log.

## Operational Go-Live API

### GET `/api/ops/go-live`

Runs final deployment readiness checks against the current runtime configuration. Use `deployment_mode=production` before exposing the console to shared users.

```http
GET /api/ops/go-live?deployment_mode=production
```

The response includes status, score, individual checks, and next steps for missing production safeguards such as placeholder secrets, missing authentication, exposed API docs, insecure cookies, disabled audit logging, or non-writable data paths.

## Demo Pack Preview

```http
GET /api/ops/demo-pack-preview
```

Returns a lightweight preview of the public demo/handoff package: recommended build command, default output directory, expected documents/reports, built-in scenario count, sample event count, and rulepack coverage summary. This endpoint does not generate files.

## Static Showcase Preview

```http
GET /api/ops/showcase-preview
```

Returns a lightweight preview of the GitHub Pages static showcase package: recommended build command, output directory, entrypoint, included assets, built-in scenario count, event count, and rulepack coverage summary. This endpoint does not generate files.

## Public Publish Prep Preview

```http
GET /api/ops/publish-prep-preview
```

Returns a lightweight preview of the final public-launch package. The preview lists the recommended command, output directory, expected release/demo/showcase sections, scenario count, event count, and rulepack coverage summary. This endpoint does not generate files.
