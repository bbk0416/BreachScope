# BreachScope Deployment Guide

## 1. Local development

```bash
python -m venv .venv
source .venv/bin/activate  # Windows: .venv\\Scripts\\activate
python -m pip install -e . reportlab pytest
python -m pytest -q
uvicorn api.main:app --reload
```

Open the web console at `http://127.0.0.1:8000`.

## 2. Docker Compose

```bash
cp .env.example .env
# edit BS_API_KEY, BS_ADMIN_PASSWORD, and BS_SESSION_SECRET before sharing the service
docker compose up --build
```

By default Compose publishes BreachScope only on `127.0.0.1:8000`. If port 8000 is unavailable, choose another host port without changing the container port:

```bash
BS_HOST_PORT=18000 docker compose up --build
```

For an intentionally shared deployment behind HTTPS, a VPN, or a reverse proxy, set `BS_BIND_ADDRESS=0.0.0.0` (or a specific host interface) explicitly. Do not expose the plain HTTP container port directly to the internet.

Case history and generated reports are stored in the `breachscope-data` Docker volume.

## 3. Production checklist

- Set `BS_API_KEY` to a long random value only for trusted deployment-wide automation. For delegated clients, prefer organization-bound keys in `BS_ORGANIZATION_API_KEYS`.
- Set `BS_ADMIN_PASSWORD` and `BS_SESSION_SECRET` for browser console login. Browser sessions are signed and stored in an HttpOnly cookie.
- Optional rule-lifecycle RBAC: set `BS_AUTHOR_PASSWORD`, `BS_REVIEWER_PASSWORD`, and/or `BS_OPERATOR_PASSWORD`. If none are set, the existing single-admin behavior is preserved.
- Optional OIDC SSO: set issuer/client/redirect plus exact claim-to-role mappings. OIDC uses Authorization Code + PKCE, state/nonce verification, provider JWKS signature verification, and then issues the same HttpOnly BreachScope session cookie.
- RBAC permissions: author = profile/draft create-update-validate, reviewer = approve-publish, operator = activate-deactivate-rollback and custom-rule opt-in analysis; admin/global API key retain deployment-wide access, while organization-bound API keys have admin-level access only in their bound organization.
- Set `BS_DISABLE_DOCS=1` if API docs should not be public.
- Keep `BS_AUDIT_ENABLED=1` for shared deployments so login, analysis, download, and deletion events are retained.
- Serve behind HTTPS or a VPN.
- Mount persistent storage for `/data`.
- Back up `/data/case_history.json` and `/data/cases`.
- Define a retention policy for uploaded logs and generated reports.
- Run `python scripts/run.py --validate-rules` after changing rules.
- Run `python -m pytest -q` before shipping a release.

## 4. Useful environment variables

| Variable | Purpose | Default |
|---|---|---|
| `BS_BIND_ADDRESS` | Docker Compose host bind address | `127.0.0.1` |
| `BS_HOST_PORT` | Docker Compose published host port | `8000` |
| `BS_API_KEY` | Optional deployment-wide API key. May select an organization with `X-BreachScope-Organization`. | unset |
| `BS_ORGANIZATION_API_KEYS` | Optional JSON object mapping organization IDs to unique organization-bound API keys. | `{}` |
| `BS_ADMIN_PASSWORD` | Optional admin web-console password. Admin can perform all operations. | unset |
| `BS_AUTHOR_PASSWORD` | Optional author account password for tuning/draft create-update-validate. | unset |
| `BS_REVIEWER_PASSWORD` | Optional reviewer account password for approve/publish. | unset |
| `BS_OPERATOR_PASSWORD` | Optional operator account password for activation/rollback and custom-rule opt-in analysis. | unset |
| `BS_OIDC_ISSUER_URL` | OIDC issuer. HTTPS required except loopback development. | unset |
| `BS_OIDC_CLIENT_ID` | OIDC client ID | unset |
| `BS_OIDC_CLIENT_SECRET` | Optional confidential-client secret. Do not commit. | unset |
| `BS_OIDC_REDIRECT_URI` | Exact registered callback URI, usually `https://host/api/auth/oidc/callback` | unset |
| `BS_OIDC_SCOPES` | Space-separated scopes; `openid` is always enforced. | `openid profile email` |
| `BS_OIDC_ROLE_CLAIM` | Claim path used for role mapping. Dotted paths are supported. | `groups` |
| `BS_OIDC_ORGANIZATION_CLAIM` | Optional claim path that must resolve to exactly one organization ID for the signed browser session. | unset |
| `BS_OIDC_DEFAULT_ROLE` | Optional fallback role when no claim value matches. Blank is fail-closed. | unset |
| `BS_OIDC_ADMIN_VALUES` | Exact comma-separated claim values mapped to admin. | unset |
| `BS_OIDC_AUTHOR_VALUES` | Exact comma-separated claim values mapped to author. | unset |
| `BS_OIDC_REVIEWER_VALUES` | Exact comma-separated claim values mapped to reviewer. | unset |
| `BS_OIDC_OPERATOR_VALUES` | Exact comma-separated claim values mapped to operator. | unset |
| `BS_OIDC_TOKEN_AUTH_METHOD` | `client_secret_basic`, `client_secret_post`, or `none`. | auto |
| `BS_SESSION_SECRET` | Secret used to sign browser session cookies and OIDC flow state. OIDC requires an explicit value. | falls back to API key/password for non-OIDC login |
| `BS_SESSION_TTL_SECONDS` | Browser session lifetime in seconds. Minimum 300. | 28800 |
| `BS_COOKIE_SECURE` | Force Secure cookies. Use `1` behind HTTPS. | auto |
| `BS_DISABLE_DOCS` | Disable `/api/docs` and `/api/redoc` when `1` | `0` |
| `BS_CASES_ROOT` | Case artifact root directory | `~/.breachscope/cases` |
| `BS_CASE_HISTORY_PATH` | Case metadata JSON path | `~/.breachscope/case_history.json` |
| `BS_DEFAULT_ORGANIZATION_ID` | Default organization for local/password sessions and legacy case/audit/custom-rule storage compatibility | `default` |
| `BS_AUDIT_ENABLED` | Enable append-only JSONL audit trail | `1` |
| `BS_AUDIT_LOG_PATH` | Audit JSONL path | `~/.breachscope/audit.jsonl` |
| `BS_RULE_TUNING_PATH` | Base JSON path for the default organization's versioned rule-tuning profiles; non-default organizations use a derived `rule_tuning_organizations/<org>/` path | `~/.breachscope/rule_tuning_profiles.json` |
| `BS_RULE_AUTHORING_ROOT` | Base draft/review/published custom-rule root; non-default organizations use `organizations/<org>/` below this root | `~/.breachscope/rule_authoring` |
| `BS_RULE_ACTIVATION_PATH` | Base activation manifest for the default organization; non-default organizations use a derived `rule_activation_organizations/<org>/` path | `~/.breachscope/rule_activation.json` |
| `BS_ARTIFACT_ENCRYPTION_KEY` | Optional URL-safe base64 32-byte key for AES-256-GCM encryption of retained case inputs/reports | unset |
| `BS_OBJECT_STORAGE_PROVIDER` | Optional remote case replica provider. Currently `s3` only. | unset |
| `BS_OBJECT_STORAGE_BUCKET` | S3-compatible bucket for encrypted case replicas | unset |
| `BS_OBJECT_STORAGE_PREFIX` | Object-key prefix for case replicas | `breachscope/cases` |
| `BS_OBJECT_STORAGE_REGION` | Optional AWS SDK region | unset |
| `BS_OBJECT_STORAGE_ENDPOINT_URL` | Optional S3-compatible endpoint URL (for example MinIO/R2) | unset |
| `BS_AUDIT_CHAIN_SECRET` | Optional HMAC key for audit integrity checks | unset |
| `BS_WEB_CLEANUP_AFTER_ANALYSIS` | Delete web workdir after analysis when `1` | `0` |
| `BS_PDF_FONT_REGULAR` | Override Korean PDF regular font | auto-detect |
| `BS_PDF_FONT_BOLD` | Override Korean PDF bold font | auto-detect |


### OIDC SSO example

```bash
BS_OIDC_ISSUER_URL=https://idp.example.com/realms/security
BS_OIDC_CLIENT_ID=breachscope
BS_OIDC_CLIENT_SECRET=<provider-client-secret>
BS_OIDC_REDIRECT_URI=https://breachscope.example.com/api/auth/oidc/callback
BS_OIDC_ROLE_CLAIM=groups
BS_OIDC_ORGANIZATION_CLAIM=tenant.id
BS_OIDC_ADMIN_VALUES=breachscope-admins
BS_OIDC_AUTHOR_VALUES=breachscope-authors
BS_OIDC_REVIEWER_VALUES=breachscope-reviewers
BS_OIDC_OPERATOR_VALUES=breachscope-operators
BS_SESSION_SECRET=<separate-32+-character-random-secret>
BS_COOKIE_SECURE=1
```

The browser starts SSO at `GET /api/auth/oidc/login`. The callback is `GET /api/auth/oidc/callback`. Claim values are matched exactly. Admin mapping wins if present; multiple matching non-admin roles are rejected instead of choosing an arbitrary privilege. If `BS_OIDC_ORGANIZATION_CLAIM` is configured, that claim must resolve to exactly one safe organization ID and is embedded in the signed local session. A local BreachScope session is issued only after ID-token issuer/audience/signature/nonce checks. IdP group or organization changes are not continuously introspected; they take effect on the next SSO login or after the local session expires. Local logout clears BreachScope's session but does not attempt provider-wide logout.

Retained-case list/detail/workflow/delete/prune/report/object-storage API operations and audit list/export/integrity responses are scoped to the active organization. The global `BS_API_KEY` may select the organization with `X-BreachScope-Organization`. Organization-bound keys in `BS_ORGANIZATION_API_KEYS` default to their bound organization and reject a different organization selector. Browser sessions ignore that header and remain bound to their signed session organization. New S3 case replicas use `<BS_OBJECT_STORAGE_PREFIX>/orgs/<organization_id>/<case_id>`; legacy v1 replicas without organization metadata are accepted only from `BS_DEFAULT_ORGANIZATION_ID`. The audit JSONL file remains one deployment-wide append-only physical store, while HTTP audit reads are filtered by organization. Rule-tuning profiles, custom-rule authoring/published artifacts, and activation manifests are also organization-scoped. BS_DEFAULT_ORGANIZATION_ID keeps the configured base tuning/authoring/activation paths for backward compatibility; non-default organizations use derived organization namespaces. The canonical built-in rule pack remains deployment-wide and read-only. This is not full tenant isolation because organization-specific RBAC policy and SCIM/user lifecycle remain deployment-wide/future work.

## 5. API-key examples

`BS_ORGANIZATION_API_KEYS` uses JSON, for example `{"soc-blue":"<random-secret>","soc-red":"<random-secret>"}`. Organization IDs are normalized with the same safe identifier rules used elsewhere. Secrets must be unique and must not reuse `BS_API_KEY`.

```bash
curl -H "X-API-Key: $BS_API_KEY" http://127.0.0.1:8000/api/cases
curl -H "X-API-Key: $BS_API_KEY" -H "X-BreachScope-Organization: soc-blue" http://127.0.0.1:8000/api/cases
# Organization-bound key: no organization header is required.
curl -H "X-API-Key: $SOC_BLUE_API_KEY" http://127.0.0.1:8000/api/cases
curl -H "Authorization: Bearer $BS_API_KEY" http://127.0.0.1:8000/api/rules
curl -H "X-API-Key: $BS_API_KEY" -H "X-BreachScope-Organization: soc-blue" http://127.0.0.1:8000/api/audit?limit=20

# Browser-login status check
curl http://127.0.0.1:8000/api/auth/status
```

## 운영 관측성/상태 확인

Dockerfile은 `/api/health/live`, docker-compose.yml은 `/api/health/ready`를 healthcheck로 사용합니다.

```http
GET /api/health/live
GET /api/health/ready
GET /api/metrics
GET /api/metrics.json
GET /api/ops/config-check
POST /api/ops/self-test
```

- `live`: 프로세스 생존, uptime, Python/platform 정보
- `ready`: `/data` 계열 저장소 쓰기 가능 여부, 룰팩/템플릿/시나리오 준비 상태
- `metrics`: Prometheus text format
- `metrics.json`: 웹 콘솔 상태/진단 패널용 JSON
- `config-check`: 인증/세션/쿠키/API 문서/저장 경로/룰팩 진단
- `self-test`: 합성 로그로 분석 파이프라인과 산출물 생성 end-to-end 확인

공유 배포에서 `BS_API_KEY` 또는 admin/author/reviewer/operator 브라우저 로그인 비밀번호 중 하나라도 설정하면 메트릭/진단/셀프테스트 API도 보호됩니다. health probe 엔드포인트는 오케스트레이터가 접근할 수 있도록 공개 상태를 유지합니다.

## 운영 안정성 옵션

### 로그인 실패 잠금

브라우저 로그인은 고정 identity별로 로컬 JSON 파일 기반 실패 횟수를 추적합니다.

```bash
BS_AUTH_MAX_FAILURES=5
BS_AUTH_LOCKOUT_SECONDS=300
BS_AUTH_RATE_LIMIT_PATH=/data/auth_rate_limit.json
```

동일 IP/사용자 조합에서 실패 횟수가 기준을 넘으면 지정 시간 동안 429 응답을 반환합니다. API Key 방식 자동화에는 영향을 주지 않습니다.

### 백업

소규모/내부 배포에서는 아래 API로 케이스 이력, 케이스 파일, 감사 로그를 ZIP으로 백업할 수 있습니다.

```bash
BS_BACKUP_ROOT=/data/backups
```

```http
The built-in backup API is organization-scoped. Each ZIP contains only the active organization's case metadata/artifacts, audit events, and custom-rule lifecycle stores. The default organization writes directly under `BS_BACKUP_ROOT`; non-default organizations use `BS_BACKUP_ROOT/organizations/<organization_id>/`. A backup ID from another organization resolves as 404. Use an external volume/filesystem snapshot when a deployment-wide backup is required.

POST /api/backups?include_cases=true&include_audit=true
GET /api/backups
GET /api/backups/{backup_id}/download
GET /api/backups/{backup_id}/integrity
```

대규모 운영에서는 이 기능과 별개로 Docker volume 또는 호스트 디스크 스냅샷을 함께 운용하는 것을 권장합니다.

### S3-compatible 원격 케이스 replica

로컬 케이스 저장은 기본/기준 저장소로 유지됩니다. 선택적으로 operator/admin이 **이미 AES-256-GCM으로 client-side 암호화된 retained case**를 S3-compatible bucket에 복제하고, 로컬 파일이 없을 때 다시 복원할 수 있습니다. 평문 파일이 하나라도 남아 있는 case는 원격 복제가 거부됩니다.

```bash
BS_ARTIFACT_ENCRYPTION_KEY=<32-byte-url-safe-base64-key>
BS_OBJECT_STORAGE_PROVIDER=s3
BS_OBJECT_STORAGE_BUCKET=breachscope-cases
BS_OBJECT_STORAGE_PREFIX=breachscope/cases
BS_OBJECT_STORAGE_REGION=ap-northeast-2
# MinIO/R2 같은 S3-compatible 서비스에서만 필요
BS_OBJECT_STORAGE_ENDPOINT_URL=
```

AWS access key를 BreachScope 전용 변수로 저장하지 않습니다. boto3의 표준 credential chain(AWS 환경변수, profile, IAM role/workload identity 등)을 사용합니다. bucket은 private으로 유지하고 최소 권한만 부여합니다. Docker Compose는 `.env`를 container에 전달하므로 위 설정도 그대로 전달됩니다.

```http
POST   /api/cases/{case_id}/object-storage/replicate
POST   /api/cases/{case_id}/object-storage/restore?overwrite=false
DELETE /api/cases/{case_id}/object-storage?forget=false
```

복제는 object 파일을 먼저 업로드하고 `case_manifest.json`을 마지막에 기록합니다. case index에는 remote manifest의 SHA-256과 bucket/key metadata가 남습니다. 복원 시 manifest SHA-256, 각 object의 크기/SHA-256, AES-GCM 인증을 모두 확인한 뒤 임시 디렉터리를 원자적으로 교체합니다. 기본 restore는 비어 있지 않은 로컬 case를 덮어쓰지 않습니다.

원격 replica metadata가 있는 case는 일반 case 삭제와 retention prune이 차단됩니다. 먼저 원격 replica를 삭제해야 합니다. `forget=true`는 원격 저장소 장애나 out-of-band 삭제 후 **metadata만 강제로 제거하는 복구 옵션**이라 remote orphan을 만들 수 있으므로 API에서 명시적으로 사용할 때만 허용합니다. readiness/config-check는 네트워크나 bucket 권한을 probe하지 않고 정적 설정과 client-side encryption 전제만 확인합니다.

### 케이스 보존 정리

오래된 케이스는 dry-run으로 후보를 먼저 확인한 뒤 삭제합니다.

```http
POST /api/cases/prune?keep_last=50&older_than_days=30&dry_run=true
POST /api/cases/prune?keep_last=50&older_than_days=30&dry_run=false
```

`keep_last` 개수만큼 최신 케이스는 항상 보존됩니다.

## CI/CD와 릴리즈 메타데이터

Docker 빌드 또는 CI에서 아래 값을 주입하면 운영 API에서 배포 버전을 확인할 수 있습니다.

```bash
BS_BUILD_VERSION=X.Y.Z
BS_BUILD_SHA=<git sha>
BS_BUILD_TAG=vX.Y.Z
BS_BUILD_TIME=<build timestamp>
```

확인 API:

```http
GET /api/ops/release-info
```

Dockerfile은 OCI label도 함께 설정합니다.

```text
org.opencontainers.image.title
org.opencontainers.image.description
org.opencontainers.image.source
org.opencontainers.image.revision
org.opencontainers.image.version
org.opencontainers.image.created
```

GitHub Actions 구성은 다음 문서를 참고하세요.

- [CI/CD 운영 가이드](CI_CD.md)
- [릴리즈 절차](RELEASE.md)

## Go-Live guardrails

Before a shared deployment, generate a fresh `.env` instead of copying placeholder secrets:

```bash
python scripts/init_env.py --production --https --output .env
python scripts/go_live_check.py --deployment-mode production
```

The same check is available from the web console status panel and API:

```http
GET /api/ops/go-live?deployment_mode=production
```

See [Go-Live Checklist](GO_LIVE.md) for the first-run sequence.
