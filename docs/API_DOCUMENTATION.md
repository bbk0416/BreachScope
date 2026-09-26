# BreachScope API 문서

## 웹 API 엔드포인트

### 인증 및 Rule Lifecycle RBAC
기본 호환 모드는 기존과 동일합니다. `BS_AUTHOR_PASSWORD`, `BS_REVIEWER_PASSWORD`, `BS_OPERATOR_PASSWORD`가 모두 비어 있으면 단일 admin/API-key 권한으로 동작합니다.

역할 계정을 설정하면 `/api/auth/login`의 `username`에 `admin`, `author`, `reviewer`, `operator` 중 하나를 사용합니다. 임의 username은 새로운 주체가 되지 않고 admin 경로로 처리됩니다.

- author: tuning profile 및 rule draft 생성/수정/validate
- reviewer: validated draft approve/publish
- operator: published rule activate/deactivate/rollback, `use_custom_rules=true` 분석
- admin/API key: 전체 권한

역할 분리가 켜진 경우 non-admin reviewer는 자신이 마지막으로 작성/수정한 현재 draft 버전을 승인할 수 없습니다. 권한 부족은 HTTP 403, 자기승인 차단은 workflow state conflict로 HTTP 409를 반환합니다.

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
- `rule_include` (str, 선택): 이번 분석에 포함할 룰 ID (쉼표 구분). 비우면 전체 룰을 사용합니다.
- `rule_exclude` (str, 선택): 이번 분석에서 제외할 룰 ID (쉼표 구분). 원본 YAML은 변경하지 않습니다.
- `use_custom_rules` (bool, 기본값: False): activation manifest에서 활성화된 published custom rule을 이번 분석에 포함합니다. 활성 artifact는 SHA-256과 runtime loader를 다시 확인합니다.
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
  "custom_rule_activation": {
    "enabled_for_analysis": false,
    "loaded_custom_rule_count": 0,
    "effective_custom_rule_ids": [],
    "canonical_rulepack_modified": false
  },
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

### GET `/api/rules/profiles`
저장된 룰 튜닝 프로필 목록을 조회합니다. 목록 응답에는 현재 버전과 revision 수가 포함되며 전체 revision 본문은 포함하지 않습니다.

### GET `/api/rules/profiles/{profile_id}`
단일 프로필과 저장된 revision 이력을 조회합니다.

### POST `/api/rules/profiles`
권한: author 또는 admin.

분석 단위 룰 include/exclude 조합을 새 프로필로 저장합니다. 존재하지 않는 룰 ID 또는 include/exclude 중복은 400으로 거부합니다.

요청 필드: name, description, rule_include, rule_exclude.

### PUT `/api/rules/profiles/{profile_id}`
권한: author 또는 admin.

프로필을 새 버전으로 갱신합니다. `expected_version`이 현재 버전과 다르면 409를 반환합니다.

### DELETE `/api/rules/profiles/{profile_id}?expected_version=N`
권한: author 또는 admin.

현재 버전이 일치할 때만 프로필을 삭제합니다. 생성/수정/삭제는 감사 로그에 기록됩니다.

---

### GET `/api/rules/authoring/drafts`
커스텀 룰 draft 목록을 조회합니다. 이 저장소는 canonical `rules/`와 분리됩니다.

### POST `/api/rules/authoring/drafts`
권한: author 또는 admin.

새 룰 draft를 저장합니다. 단순 저장 단계에서는 runtime regex 검증이나 canonical ID 충돌 검사를 아직 통과할 필요가 없습니다.

### POST `/api/rules/authoring/drafts/{draft_id}/validate`
권한: author 또는 admin.

현재 버전을 실제 BreachScope runtime loader로 검증합니다. 잘못된 regex, loader 오류, canonical rule ID 충돌은 400으로 거부합니다.

### POST `/api/rules/authoring/drafts/{draft_id}/approve`
권한: reviewer 또는 admin.

validation PASS인 현재 버전에 검토 메모와 승인자를 기록합니다. 내용이 수정되면 validation/approval은 초기화됩니다.

### POST `/api/rules/authoring/drafts/{draft_id}/publish`
권한: reviewer 또는 admin.

승인된 현재 버전을 별도 versioned YAML artifact로 publish합니다. publish 자체는 canonical 73-rule detector를 변경하지 않습니다.

### GET `/api/rules/activation`
현재 custom-rule activation manifest와 version history를 조회합니다. 최초 상태는 version 0 / active=[] 입니다.

### POST `/api/rules/activation/activate`
권한: operator 또는 admin.

publish된 특정 draft/version을 activation manifest에 등록합니다. `expected_version`, `draft_id`, `published_version`을 받으며 publish artifact의 SHA-256과 runtime loader를 다시 검증합니다. 같은 draft의 이전 활성 버전은 새 버전으로 교체됩니다.

### POST `/api/rules/activation/deactivate`
권한: operator 또는 admin.

현재 활성 상태의 draft를 제거합니다. `expected_version` 불일치 시 409를 반환합니다.

### POST `/api/rules/activation/rollback`
권한: operator 또는 admin.

이전 activation manifest snapshot을 새 manifest 버전으로 복원합니다. 복원 대상 publish artifact도 다시 SHA-256 검증합니다.

활성화된 custom rule은 분석에 자동 적용되지 않습니다. `/api/analyze`에서 `use_custom_rules=true`를 명시해야 하며, 해당 분석 리포트에는 custom rule provenance와 canonical detection evidence 비적용 경계가 기록됩니다.

---

### GET `/api/health`
서비스 상태를 확인합니다.

**응답**:
```json
{
  "status": "healthy",
  "version": "2.1.2"
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