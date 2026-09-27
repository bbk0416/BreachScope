# Security Policy

BreachScope processes sensitive security logs. Treat deployments as internal tools unless you have added external-grade authentication, TLS, retention controls, and review workflows.

## Recommended deployment defaults

- Set a long random `BS_API_KEY` for API clients and configure browser authentication with either local passwords or OIDC SSO. Browser sessions and OIDC flow state require a strong `BS_SESSION_SECRET`.
- Put the service behind HTTPS, for example Nginx, Caddy, Cloudflare Tunnel, or a private VPN.
- Keep case data under a dedicated data volume such as `/data`.
- For retained local cases, optionally set `BS_ARTIFACT_ENCRYPTION_KEY` to URL-safe base64 encoding of exactly 32 random bytes. BreachScope then stores case inputs/reports as AES-256-GCM ciphertext and decrypts downloads/previews in memory.
- S3-compatible remote case replication accepts only those client-side encrypted `.enc` artifacts. Keep the bucket private, use least-privilege IAM, and let boto3 resolve credentials from the standard AWS SDK credential chain rather than storing credentials in case metadata. `BS_OBJECT_STORAGE_ENDPOINT_URL` is deployment-controlled and should point only to an intended S3-compatible service.
- Remote replica metadata blocks ordinary case deletion/pruning so remote objects are not orphaned accidentally. `forget=true` clears metadata without deleting remote objects and is an emergency recovery option only.
- Treat `BS_RELEASE_SIGNING_PRIVATE_KEY` as an offline/release secret. Do not commit it, include it in release bundles, or use the embedded signature public key alone as an authenticity trust anchor. Publish the Ed25519 public key or its SHA-256 fingerprint through a separate trusted channel.
- Disable public API docs in production with `BS_DISABLE_DOCS=1`.
- Do not upload real customer logs to public demo instances.
- Review generated IOC and findings before using them for blocking decisions.
- Keep audit logging enabled for shared deployments and archive `/api/audit/integrity` output with important cases.

## Authentication behavior

When `BS_API_KEY`, all local login passwords, and all `BS_OIDC_*` settings are unset, authentication is disabled for local demos. Any partial OIDC configuration enables the authentication boundary but is treated as misconfigured for production until issuer/client/redirect/session-secret/role mapping are complete.

When `BS_API_KEY` is set, protected API calls accept one of the following:

```text
X-API-Key: <key>
Authorization: Bearer <key>
```

### v2 authentication migration

Starting with source version `2.0.0`, query-string API-key authentication (`?api_key=...`) is no longer accepted. Existing clients must send the key in the `X-API-Key` header or `Authorization: Bearer` header. Also, `/api/info` is protected whenever runtime authentication is enabled; it is no longer an authentication-exempt endpoint as it was in `v1.0.0`.

When `BS_ADMIN_PASSWORD` is set, browser users can sign in as `admin` through `/api/auth/login`. Optional fixed identities `author`, `reviewer`, and `operator` are enabled by `BS_AUTHOR_PASSWORD`, `BS_REVIEWER_PASSWORD`, and `BS_OPERATOR_PASSWORD`. Successful login sets an HttpOnly `bs_session` cookie with the fixed subject/role, signed with `BS_SESSION_SECRET` when available. Unknown usernames cannot create arbitrary identities; they fall back to the fixed admin identity path. Use `BS_COOKIE_SECURE=1` behind HTTPS to force Secure cookies.

OIDC SSO is opt-in through `BS_OIDC_ISSUER_URL`, `BS_OIDC_CLIENT_ID`, `BS_OIDC_REDIRECT_URI`, `BS_SESSION_SECRET`, and at least one exact claim-to-role mapping (or an explicit `BS_OIDC_DEFAULT_ROLE`). BreachScope uses Authorization Code + PKCE with signed flow state, nonce validation, provider discovery/JWKS verification, issuer/audience checks, and rejects HMAC ID-token algorithms. The resulting local session records `authn=oidc`. Multiple matching non-admin roles are denied rather than privilege-ranked. Optional `BS_OIDC_ORGANIZATION_CLAIM` mapping requires exactly one safe organization ID and binds it into the signed session. Retained-case APIs and audit list/export/integrity responses enforce that organization boundary; API-key clients may choose the organization with `X-BreachScope-Organization`, while browser sessions cannot override their signed organization with a header. New S3 replicas use organization-scoped object-key namespaces under `<prefix>/orgs/<organization_id>/<case_id>`. Legacy v1 replicas without organization metadata remain readable/deletable only from `BS_DEFAULT_ORGANIZATION_ID`. Full tenant isolation is still incomplete for deployment-wide rule stores and organization-specific RBAC/SCIM policy. Removing the deployment's OIDC role mapping invalidates existing local OIDC sessions for that role, but upstream IdP group or organization changes are otherwise observed on the next login/session expiry rather than continuously introspected.

Rule-lifecycle authorization is server-enforced: author can create/update/validate tuning profiles and rule drafts; reviewer can approve/publish; operator can activate/deactivate/rollback published custom rules and run analyses with `use_custom_rules=true`; admin and the single API key retain full access. When no role-specific password is configured, legacy single-admin behavior is preserved. A non-admin reviewer cannot approve a current draft version whose latest writer is the same subject.

## Vulnerability reporting

If you discover a vulnerability in BreachScope, do not publish exploit details first. Open a private report or contact the maintainer with the affected version, reproduction steps, and impact summary so the issue can be triaged safely.

## Supported use

The bundled scenarios are synthetic and safe demonstration data. The project is intended for defensive log analysis, incident triage, portfolio demonstration, and internal SOC/DFIR workflows.


## Audit trail

BreachScope records operator-facing events to an append-only JSONL file when `BS_AUDIT_ENABLED` is not disabled. The default path is `~/.breachscope/audit.jsonl`, and Docker deployments should map it to persistent storage such as `/data/audit.jsonl`.

Recorded actions include successful/failed login attempts, unauthorized API requests, analysis runs, case views, artifact downloads, and case deletion. Audit entries include the resolved organization ID when available. Passwords, API keys, cookies, tokens, and session values are redacted before writing.

Use `/api/audit/export?file_type=jsonl`, `/api/audit/export?file_type=csv`, and `/api/audit/integrity` to review and archive the trail. HTTP audit list/export/integrity responses are scoped to the active organization; legacy events without an organization ID belong to `BS_DEFAULT_ORGANIZATION_ID`. The append-only JSONL file remains a deployment-wide physical store. The integrity endpoint returns SHA-256 over the complete logical event set visible to the active organization, and `BS_AUDIT_CHAIN_SECRET` adds an HMAC-SHA256 over that same organization-scoped logical stream. `AuditLogService.verify_chain()` remains available internally for whole-file operational checks.

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
