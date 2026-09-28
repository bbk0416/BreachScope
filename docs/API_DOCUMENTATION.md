# BreachScope API 문서

## 웹 API 엔드포인트

### 인증 및 Rule Lifecycle RBAC
기본 호환 모드는 기존과 동일합니다. `BS_AUTHOR_PASSWORD`, `BS_REVIEWER_PASSWORD`, `BS_OPERATOR_PASSWORD`가 모두 비어 있으면 단일 admin/API-key 권한으로 동작합니다.

역할 계정을 설정하면 `/api/auth/login`의 `username`에 `admin`, `author`, `reviewer`, `operator` 중 하나를 사용합니다. 임의 username은 새로운 주체가 되지 않고 admin 경로로 처리됩니다.

- author: tuning profile 및 rule draft 생성/수정/validate
- reviewer: validated draft approve/publish
- operator: published rule activate/deactivate/rollback, `use_custom_rules=true` 분석
- admin/global API key: deployment 전체 권한
- organization-bound API key: 바인딩된 organization 안에서 admin 수준 권한

역할 분리가 켜진 경우 non-admin reviewer는 자신이 마지막으로 작성/수정한 현재 draft 버전을 승인할 수 없습니다. 권한 부족은 HTTP 403, 자기승인 차단은 workflow state conflict로 HTTP 409를 반환합니다.

OIDC SSO를 사용할 수 있습니다. `GET /api/auth/oidc/login`이 Authorization Code + PKCE 흐름을 시작하고, 등록 callback은 `GET /api/auth/oidc/callback`입니다. SCIM을 사용하지 않을 때는 ID token의 issuer/audience/signature/nonce를 확인한 뒤 `BS_OIDC_ROLE_CLAIM` 값(기본 `groups`)을 `BS_OIDC_*_VALUES`와 정확히 비교해 하나의 BreachScope role로 매핑합니다. `BS_OIDC_ORGANIZATION_CLAIM`을 설정하면 해당 claim은 정확히 하나의 안전한 organization ID로 매핑됩니다. SCIM이 설정되면 OIDC `sub`와 SCIM `externalId`를 정확히 매칭하고 SCIM의 active/role/organization을 권한 원본으로 사용합니다. SCIM-managed OIDC session은 매 요청마다 다시 확인되므로 disable/delete/role·organization 변경이 기존 session을 즉시 무효화합니다. Global `BS_API_KEY` 클라이언트는 `X-BreachScope-Organization` 헤더로 retained-case, audit, custom-rule lifecycle, object-storage, backup HTTP scope를 선택할 수 있습니다. `BS_ORGANIZATION_API_KEYS`의 key는 하나의 organization에 고정되며 헤더를 생략하거나 같은 organization만 지정할 수 있습니다. 다른 organization selector는 403, 잘못된 selector는 400입니다. 브라우저 세션은 이 헤더로 organization을 덮어쓸 수 없습니다.

### SCIM 2.0 provisioning

SCIM은 전용 `Authorization: Bearer <BS_SCIM_BEARER_TOKEN>`으로 `/api/scim/v2/*`를 호출합니다. 일반 BreachScope API key와 분리되어 있습니다.

지원 endpoint:
- `GET /api/scim/v2/ServiceProviderConfig`
- `GET /api/scim/v2/ResourceTypes`, `GET /api/scim/v2/ResourceTypes/User`, `GET /api/scim/v2/ResourceTypes/Group`
- `GET /api/scim/v2/Schemas`, `GET /api/scim/v2/Schemas/{schema_id}`
- `GET/POST /api/scim/v2/Users`
- `GET/PUT/PATCH/DELETE /api/scim/v2/Users/{id}`
- `GET/POST /api/scim/v2/Groups`
- `GET/PUT/PATCH/DELETE /api/scim/v2/Groups/{id}`
- `POST /api/scim/v2/Bulk`

Users list는 `id`, `userName`, `externalId`의 exact `eq` filter를, Groups list는 `id`, `displayName`의 exact `eq` filter를 지원하며 둘 다 `startIndex`/`count` pagination을 사용합니다. User/Group 응답은 ETag를 반환하며 PUT/PATCH/DELETE의 `If-Match`를 검사합니다. Group member는 기존 SCIM User 또는 Group ID를 받을 수 있습니다. 응답의 `members[].type`은 `User` 또는 `Group`이며, nested Group membership은 재귀적으로 OIDC 권한 계산에 반영됩니다. 자기참조/순환 Group graph는 400으로 거부하고, 하위 Group 삭제 시 상위 Group의 해당 참조를 함께 제거합니다.

Active user는 OIDC `sub`와 연결할 `externalId`가 필요합니다. role+organization은 User extension `urn:breachscope:params:scim:schemas:extension:1.0:User` 또는 Group extension `urn:breachscope:params:scim:schemas:extension:1.0:Group`에서 올 수 있습니다. Group extension도 `role`, `organizationId`를 사용합니다. User 직접 assignment와 모든 Group assignment를 합친 결과가 정확히 하나의 `(role, organizationId)` pair로 해석될 때만 OIDC 로그인을 허용합니다. 같은 pair가 User와 Group에 중복되는 것은 허용하지만 서로 다른 pair가 동시에 존재하면 fail-closed입니다. User/group membership/assignment 변경이나 Group 삭제는 기존 OIDC 세션에 다음 요청부터 즉시 반영됩니다.

현재 구현은 single-instance JSON-backed Users/Groups provisioning subset입니다. Users와 Groups는 각각 `BS_SCIM_USER_STORE_PATH`, `BS_SCIM_GROUP_STORE_PATH`에 저장됩니다. Bulk는 RFC 7644 형태의 `BulkRequest`/`BulkResponse`로 Users/Groups POST·PUT·PATCH·DELETE, POST `bulkId`, `bulkId:` cross-reference, operation `version`, `failOnErrors`를 지원합니다. 한 요청은 최대 100 operations / 1 MiB이며, Bulk는 원자적 트랜잭션이 아니라 처리된 operation별 결과를 반환합니다. password provisioning, sort, external identity DB, multi-replica directory write는 지원하지 않습니다.

### Organization-specific RBAC policy

`BS_ORGANIZATION_RBAC_POLICIES`는 기존 server-enforced role gate의 permission을 organization별로 부분 override합니다. 지원 permission은 `rule.author`, `rule.review`, `rule.operate`, `analysis.custom_rules`, `case.object_storage`입니다. 정책에 없는 organization/role은 기존 built-in permission을 유지하고, 특정 role에 `[]`를 지정하면 그 organization에서 해당 role의 role-gated 작업을 모두 차단합니다. 브라우저/OIDC admin과 organization-bound API key도 현재 organization의 admin policy를 따릅니다. Global `BS_API_KEY`는 deployment break-glass/admin credential이므로 이 policy를 우회합니다.

`GET /api/auth/status`는 secret 없이 `organization_rbac_policy_settings_present`, `organization_rbac_policy_config_valid`, policy organization count, 현재 인증 주체의 `active_permissions`를 반환합니다. malformed JSON, unknown role, unknown permission은 role-gated 요청에서 fail-closed 처리되고 go-live/config-check에서도 실패로 표시됩니다.

### Backup API organization scope

`GET/POST /api/backups`와 download/integrity/delete 경로는 현재 organization의 backup namespace만 사용합니다. 생성되는 ZIP에는 현재 organization의 case metadata/artifacts, audit events, rule-tuning profiles, custom-rule authoring/publication artifacts, activation state만 포함됩니다. 다른 organization의 backup ID는 404로 처리됩니다. `BS_DEFAULT_ORGANIZATION_ID`는 기존 `BS_BACKUP_ROOT`를 그대로 사용하고, non-default organization은 `BS_BACKUP_ROOT/organizations/<organization_id>/` 아래에 저장됩니다.

### Audit API organization scope

`GET /api/audit`, `GET /api/audit/export`, `GET /api/audit/integrity`는 현재 인증 주체의 organization 범위만 반환합니다. Global API key는 `X-BreachScope-Organization`으로 organization을 선택할 수 있고, organization-bound API key는 credential에 저장된 organization만 사용할 수 있습니다. 브라우저 세션은 서명된 세션의 organization에 고정되어 이 헤더로 덮어쓸 수 없습니다. `organization_id`가 없는 기존 audit row는 `BS_DEFAULT_ORGANIZATION_ID`에 속한 것으로 처리합니다.

`/api/audit/integrity`는 공유 JSONL 파일 전체의 물리적 byte hash가 아니라, 현재 organization에 속한 모든 유효 audit event를 canonical JSONL 형태로 직렬화한 논리적 SHA-256을 반환합니다. `BS_AUDIT_CHAIN_SECRET`이 설정되어 있으면 같은 organization-scoped 논리 스트림에 대한 HMAC-SHA256도 반환합니다. 물리 JSONL 저장 파일 자체는 deployment-wide append-only 저장소입니다.

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
  "artifact_encryption": {
    "enabled": false,
    "encrypted_file_count": 0,
    "algorithm": null,
    "plaintext_retained": null
  },
  "html_path": "/path/to/report.html",
  "json_path": "/path/to/report.json",
  "csv_path": "/path/to/report.csv",
  "pdf_path": "/path/to/report.pdf",
  "work_dir": "/path/to/work/directory"
}
```

`BS_ARTIFACT_ENCRYPTION_KEY`를 설정하면 retained case의 업로드 입력과 `report.*` 산출물은 분석 완료 후 AES-256-GCM으로 암호화되어 `.enc` 파일로 저장됩니다. 응답의 artifact path는 암호화가 활성화된 경우 `.enc` 경로를 가리킵니다. 웹 preview와 report 다운로드는 디스크에 평문을 다시 저장하지 않고 메모리에서 복호화합니다. 키가 없거나 잘못되면 암호화된 케이스 preview/download는 HTTP 503으로 fail-closed 합니다.

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

암호화된 retained case에서도 같은 파일명을 유지해 복호화된 바이트를 반환합니다. `BS_ARTIFACT_ENCRYPTION_KEY`가 현재 저장 시점 키와 다르면 HTTP 503을 반환합니다.

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

### POST `/api/cases/{case_id}/object-storage/replicate`
권한: operator 또는 admin.

로컬 retained case를 S3-compatible object storage에 복제합니다. `BS_ARTIFACT_ENCRYPTION_KEY`가 활성화되어 있고 case 내부 파일이 모두 `.enc` ciphertext여야 합니다. 새 replica는 `<BS_OBJECT_STORAGE_PREFIX>/orgs/<organization_id>/<case_id>` namespace를 사용하고 v2 manifest에 organization ID를 기록합니다. 동일한 case ID라도 organization이 다르면 object key가 겹치지 않습니다. 이미 remote replica metadata가 있으면 409로 거부합니다.

### POST `/api/cases/{case_id}/object-storage/restore?overwrite=false`
권한: operator 또는 admin.

저장된 remote manifest metadata를 기준으로 case를 복원합니다. manifest SHA-256, 각 object의 size/SHA-256, AES-GCM 인증과 organization namespace 일치를 통과해야 하며 기본값은 기존 non-empty 로컬 case를 덮어쓰지 않습니다. 기존 v1 replica처럼 organization metadata가 없는 legacy remote는 `BS_DEFAULT_ORGANIZATION_ID`에서만 복원할 수 있습니다. 웹 UI는 안전한 기본 복원만 제공하고 `overwrite=true`는 노출하지 않습니다.

### DELETE `/api/cases/{case_id}/object-storage?forget=false`
권한: operator 또는 admin.

기본 동작은 현재 organization namespace의 remote object와 manifest를 삭제한 뒤 case index의 replica metadata를 지웁니다. 다른 organization으로 기록된 replica는 삭제할 수 없고, legacy v1 remote는 `BS_DEFAULT_ORGANIZATION_ID`에서만 삭제할 수 있습니다. `forget=true`는 remote storage를 건드리지 않고 metadata만 삭제하는 비상 복구 옵션이며 orphan object를 만들 수 있습니다. 웹 UI에는 이 옵션을 노출하지 않습니다.

---

### DELETE `/api/cases/{case_id}`
케이스 이력에서 제거합니다. 기본적으로 안전한 케이스 작업 디렉토리도 함께 삭제합니다. remote replica metadata가 남아 있으면 orphan object 방지를 위해 409로 거부됩니다.

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

### Rule lifecycle organization scope

Rule-tuning profiles, custom-rule drafts/publications, and activation state are resolved from the active organization. API-key clients select that organization with X-BreachScope-Organization; browser sessions remain bound to the signed session organization and cannot override it with that header. BS_DEFAULT_ORGANIZATION_ID uses the configured legacy base paths, while non-default organizations use separate derived storage namespaces. Analyses with use_custom_rules=true load only the active custom rules for the request organization. The canonical built-in rules/ pack is unchanged and remains deployment-wide/read-only.

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