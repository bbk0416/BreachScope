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

Case history and generated reports are stored in the `breachscope-data` Docker volume.

## 3. Production checklist

- Set `BS_API_KEY` to a long random value for automation/API clients.
- Set `BS_ADMIN_PASSWORD` and `BS_SESSION_SECRET` for browser console login. Browser sessions are signed and stored in an HttpOnly cookie.
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
| `BS_API_KEY` | Optional API key for protected API routes and integrations | unset |
| `BS_ADMIN_PASSWORD` | Optional web-console password. Enables HttpOnly session login. | unset |
| `BS_SESSION_SECRET` | Secret used to sign browser session cookies. | falls back to API key/password |
| `BS_SESSION_TTL_SECONDS` | Browser session lifetime in seconds. Minimum 300. | 28800 |
| `BS_COOKIE_SECURE` | Force Secure cookies. Use `1` behind HTTPS. | auto |
| `BS_DISABLE_DOCS` | Disable `/api/docs` and `/api/redoc` when `1` | `0` |
| `BS_CASES_ROOT` | Case artifact root directory | `~/.breachscope/cases` |
| `BS_CASE_HISTORY_PATH` | Case metadata JSON path | `~/.breachscope/case_history.json` |
| `BS_AUDIT_ENABLED` | Enable append-only JSONL audit trail | `1` |
| `BS_AUDIT_LOG_PATH` | Audit JSONL path | `~/.breachscope/audit.jsonl` |
| `BS_AUDIT_CHAIN_SECRET` | Optional HMAC key for audit integrity checks | unset |
| `BS_WEB_CLEANUP_AFTER_ANALYSIS` | Delete web workdir after analysis when `1` | `0` |
| `BS_PDF_FONT_REGULAR` | Override Korean PDF regular font | auto-detect |
| `BS_PDF_FONT_BOLD` | Override Korean PDF bold font | auto-detect |

## 5. API-key examples

```bash
curl -H "X-API-Key: $BS_API_KEY" http://127.0.0.1:8000/api/cases
curl -H "Authorization: Bearer $BS_API_KEY" http://127.0.0.1:8000/api/rules
curl -H "X-API-Key: $BS_API_KEY" http://127.0.0.1:8000/api/audit?limit=20

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

공유 배포에서 `BS_API_KEY` 또는 `BS_ADMIN_PASSWORD`를 설정하면 메트릭/진단/셀프테스트 API도 보호됩니다. health probe 엔드포인트는 오케스트레이터가 접근할 수 있도록 공개 상태를 유지합니다.

## 운영 안정성 옵션

### 로그인 실패 잠금

브라우저 관리자 로그인은 로컬 JSON 파일 기반으로 실패 횟수를 추적합니다.

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
POST /api/backups?include_cases=true&include_audit=true
GET /api/backups
GET /api/backups/{backup_id}/download
GET /api/backups/{backup_id}/integrity
```

대규모 운영에서는 이 기능과 별개로 Docker volume 또는 호스트 디스크 스냅샷을 함께 운용하는 것을 권장합니다.

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
BS_BUILD_VERSION=v1.0.0
BS_BUILD_SHA=<git sha>
BS_BUILD_TAG=v1.0.0
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
