# Go-Live Checklist

BreachScope can run as a local demo without authentication, but a shared or production deployment needs stricter runtime settings. The go-live checker reviews the **current environment** rather than only the source tree.

## Generate `.env` safely

Do not copy `.env.example` as-is for shared deployments. Generate a new file with random secrets:

```bash
python scripts/init_env.py --production --https --output .env
```

The generated file sets fresh values for:

- `BS_API_KEY`
- `BS_ADMIN_PASSWORD`
- `BS_SESSION_SECRET`
- `BS_AUDIT_CHAIN_SECRET`
- `BS_DEPLOYMENT_MODE=production`
- `BS_DISABLE_DOCS=1`
- `BS_COOKIE_SECURE=1`

Review the generated `.env` before starting the service.

For delegated automation, `BS_ORGANIZATION_API_KEYS` may be used instead of the deployment-wide `BS_API_KEY`. It is a JSON object mapping organization IDs to unique 24+ character random secrets. Organization-bound keys cannot switch to another organization with `X-BreachScope-Organization`. Malformed JSON, duplicate normalized organizations, duplicate secrets, or reuse of `BS_API_KEY` fails the authentication readiness check.

The bootstrap command intentionally keeps optional rule-lifecycle RBAC accounts disabled. To enable them, manually set one or more of `BS_AUTHOR_PASSWORD`, `BS_REVIEWER_PASSWORD`, and `BS_OPERATOR_PASSWORD` to long random values. The admin account remains the default first-run login.

`BS_ORGANIZATION_RBAC_POLICIES` may further restrict those built-in roles per organization. It is a partial JSON override using only `rule.author`, `rule.review`, `rule.operate`, `analysis.custom_rules`, and `case.object_storage`. Omitted roles keep defaults; an empty list denies every role-gated permission for that role. Invalid JSON, unknown roles, and unknown permission names fail the go-live check. The global `BS_API_KEY` remains the deployment break-glass override.

OIDC can replace local browser passwords for shared deployments. Set `BS_OIDC_ISSUER_URL`, `BS_OIDC_CLIENT_ID`, the exact registered `BS_OIDC_REDIRECT_URI`, and a strong `BS_SESSION_SECRET`. Without SCIM, configure at least one exact role mapping such as `BS_OIDC_OPERATOR_VALUES=breachscope-operators`; with SCIM, role/organization come from the SCIM user instead. `BS_OIDC_CLIENT_SECRET` is optional for public PKCE clients and required when using `client_secret_basic` or `client_secret_post`. Partial OIDC settings fail the production authentication check.

To enable SCIM lifecycle enforcement, set a unique 24+ character `BS_SCIM_BEARER_TOKEN`. Persist `BS_SCIM_USER_STORE_PATH` + `BS_SCIM_GROUP_STORE_PATH` for JSON, use `BS_SCIM_DATABASE_PATH` for local SQLite, or set `BS_SCIM_STORAGE_BACKEND=postgres` with a secret `BS_SCIM_DATABASE_URL` for shared multi-replica identity state. Provision users through `/api/scim/v2/Users` and optional role/organization groups through `/api/scim/v2/Groups`. Provision `externalId` as the exact OIDC `sub`; an active user must resolve to exactly one effective role+organization from direct User assignment and/or Group membership. Conflicting assignments are denied. When OIDC+SCIM are enabled, zero active users triggers a go-live warning. The SCIM bearer token must not reuse an API key, password, session secret, or OIDC client secret. If changing SCIM storage backends, pause provisioning, run the dry-run and migration procedure in `docs/SCIM_MIGRATION.md`, switch configuration only after verification, then run this go-live checker before resuming provisioning.

At-rest case artifact encryption is also opt-in. To enable it, generate 32 random bytes and store them as URL-safe base64 in `BS_ARTIFACT_ENCRYPTION_KEY`. Keep this key outside backups of the encrypted case directory; losing or changing it makes retained encrypted cases unreadable.

```bash
python -c "import base64,secrets; print(base64.urlsafe_b64encode(secrets.token_bytes(32)).decode().rstrip('='))"
```

S3-compatible remote replica가 필요하면 artifact encryption을 먼저 켠 뒤 object storage를 설정합니다. boto3 표준 credential chain을 사용하므로 별도 BreachScope access-key 변수는 없습니다.

```bash
BS_OBJECT_STORAGE_PROVIDER=s3
BS_OBJECT_STORAGE_BUCKET=breachscope-cases
BS_OBJECT_STORAGE_PREFIX=breachscope/cases
BS_OBJECT_STORAGE_REGION=ap-northeast-2
# 선택: MinIO/R2 등
BS_OBJECT_STORAGE_ENDPOINT_URL=
```

Go-Live/Readiness는 provider, bucket, client-side encryption 같은 정적 전제만 검사합니다. bucket 존재 여부나 실제 IAM 권한은 네트워크 probe하지 않으므로 배포 전에 테스트 case 한 건으로 replicate → archive → remote-only preview/report read → restore를 직접 확인해야 합니다. `archive`는 remote 전체 복원 검증을 통과하기 전에는 로컬 payload를 삭제하지 않으며, remote-only read가 끝난 뒤에는 `bs_web_remote_*` 임시 복원 경로가 남지 않는지도 확인합니다.

## Run the go-live checker

```bash
python scripts/go_live_check.py --deployment-mode production
python scripts/go_live_check.py --deployment-mode production --markdown --output out/go_live.md
```

Web/API equivalent:

```http
GET /api/ops/go-live?deployment_mode=production
```

The checker covers:

> In a source checkout, Go-Live also evaluates the repository quality gate and project-readiness gate. The production Docker image is intentionally smaller and omits repository-only files such as `.github/` and `tests/`; inside that runtime image those two source-repository checks are reported separately as `repository_checks.status=not_applicable`. They must pass before the image is built.

- Runtime authentication is enabled through API key, local password login, or a complete OIDC configuration.
- Placeholder secrets are not still in use.
- Optional artifact-encryption key is valid when configured.
- Optional S3-compatible object-storage configuration requires a bucket and client-side artifact encryption.
- Browser session secret is long and separate.
- API documentation is disabled for production.
- Secure cookies are enabled for HTTPS deployments.
- Session TTL is within a reasonable range.
- Case, audit, and backup paths are writable.
- Audit trail is enabled.
- Project readiness and quality gate still pass.

## First deployment flow

```bash
python scripts/init_env.py --production --https --output .env
make test
make demo-all
make validate
make project-check
make quality-gate
python scripts/go_live_check.py --deployment-mode production
make docker-up
```

After the service starts:

1. Open `/api/health/ready` and confirm readiness.
2. Log in with the generated `BS_ADMIN_PASSWORD`.
3. Run the web console self-test.
4. Create one backup and verify its SHA-256 integrity.
5. Download the audit log once to confirm export permissions.
6. Rotate secrets if the generated `.env` was ever shared.
