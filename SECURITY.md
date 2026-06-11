# Security Policy

BreachScope processes sensitive security logs. Treat deployments as internal tools unless you have added external-grade authentication, TLS, retention controls, and review workflows.

## Recommended deployment defaults

- Set a long random `BS_API_KEY` for API clients and `BS_ADMIN_PASSWORD` + `BS_SESSION_SECRET` for browser console users before exposing the web console.
- Put the service behind HTTPS, for example Nginx, Caddy, Cloudflare Tunnel, or a private VPN.
- Keep case data under a dedicated data volume such as `/data`.
- Disable public API docs in production with `BS_DISABLE_DOCS=1`.
- Do not upload real customer logs to public demo instances.
- Review generated IOC and findings before using them for blocking decisions.
- Keep audit logging enabled for shared deployments and archive `/api/audit/integrity` output with important cases.

## Authentication behavior

When both `BS_API_KEY` and `BS_ADMIN_PASSWORD` are unset, authentication is disabled for local demos.

When `BS_API_KEY` is set, protected API calls accept one of the following:

```text
X-API-Key: <key>
Authorization: Bearer <key>
?api_key=<key>
```

The query-string form exists for browser download links. Prefer headers for scripts and integrations.

When `BS_ADMIN_PASSWORD` is set, browser users can sign in through `/api/auth/login`. Successful login sets an HttpOnly `bs_session` cookie signed with `BS_SESSION_SECRET` when available. Use `BS_COOKIE_SECURE=1` behind HTTPS to force Secure cookies.

## Vulnerability reporting

If you discover a vulnerability in BreachScope, do not publish exploit details first. Open a private report or contact the maintainer with the affected version, reproduction steps, and impact summary so the issue can be triaged safely.

## Supported use

The bundled scenarios are synthetic and safe demonstration data. The project is intended for defensive log analysis, incident triage, portfolio demonstration, and internal SOC/DFIR workflows.


## Audit trail

BreachScope records operator-facing events to an append-only JSONL file when `BS_AUDIT_ENABLED` is not disabled. The default path is `~/.breachscope/audit.jsonl`, and Docker deployments should map it to persistent storage such as `/data/audit.jsonl`.

Recorded actions include successful/failed login attempts, unauthorized API requests, analysis runs, case views, artifact downloads, and case deletion. Passwords, API keys, cookies, tokens, and session values are redacted before writing.

Use `/api/audit/export?file_type=jsonl`, `/api/audit/export?file_type=csv`, and `/api/audit/integrity` to review and archive the trail. For stronger tamper evidence, set `BS_AUDIT_CHAIN_SECRET` so the integrity endpoint also returns an HMAC-SHA256 over the audit file.

## Login lockout and operational backups

BreachScope supports local brute-force protection for the browser administrator login:

```bash
BS_AUTH_MAX_FAILURES=5
BS_AUTH_LOCKOUT_SECONDS=300
BS_AUTH_RATE_LIMIT_PATH=/data/auth_rate_limit.json
```

The lockout is keyed by client IP and username. Keep `BS_SESSION_SECRET` long and random, and set `BS_COOKIE_SECURE=1` behind HTTPS.

For small/internal deployments, `/api/backups` can create local ZIP backups of case history, case artifacts, and audit logs. Protect the backup directory with filesystem permissions, because backups may contain sensitive incident evidence even when reports are redacted.


## 릴리즈 위생

- `scripts/build_release.py`는 `.env`, `out/`, `dist/`, 감사 로그(`*.jsonl`), SQLite/DB 파일, 캐시 디렉토리를 릴리즈 ZIP에서 제외합니다.
- GitHub Actions 릴리즈 워크플로는 테스트와 데모 산출물 생성 후 `SHA256SUMS.txt`와 `release_manifest.json`을 생성합니다.
- 운영 배포 버전은 `/api/ops/release-info`에서 확인할 수 있습니다.
