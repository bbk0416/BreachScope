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

- Runtime authentication is enabled.
- Placeholder secrets are not still in use.
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
