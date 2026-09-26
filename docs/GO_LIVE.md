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

The bootstrap command intentionally keeps optional rule-lifecycle RBAC accounts disabled. To enable them, manually set one or more of `BS_AUTHOR_PASSWORD`, `BS_REVIEWER_PASSWORD`, and `BS_OPERATOR_PASSWORD` to long random values. The admin account remains the default first-run login.

At-rest case artifact encryption is also opt-in. To enable it, generate 32 random bytes and store them as URL-safe base64 in `BS_ARTIFACT_ENCRYPTION_KEY`. Keep this key outside backups of the encrypted case directory; losing or changing it makes retained encrypted cases unreadable.

```bash
python -c "import base64,secrets; print(base64.urlsafe_b64encode(secrets.token_bytes(32)).decode().rstrip('='))"
```

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

- Runtime authentication is enabled.
- Placeholder secrets are not still in use.
- Optional artifact-encryption key is valid when configured.
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
