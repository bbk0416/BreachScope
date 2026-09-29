# Security Policy

BreachScope processes sensitive security logs. Treat deployments as internal tools unless you have added external-grade authentication, TLS, retention controls, and review workflows.

## Recommended deployment defaults

- Set a long random deployment-wide `BS_API_KEY` for trusted automation, or configure organization-bound API keys with `BS_ORGANIZATION_API_KEYS` for delegated clients. Configure browser authentication with either local passwords or OIDC SSO. Browser sessions and OIDC flow state require a strong `BS_SESSION_SECRET`.
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

When `BS_API_KEY`, `BS_ORGANIZATION_API_KEYS`, all local login passwords, and all `BS_OIDC_*` settings are unset, authentication is disabled for local demos. Any malformed organization-key JSON or partial OIDC configuration keeps the authentication boundary fail-closed; go-live reports the invalid configuration.

When a global or organization-bound API key is configured, protected API calls accept one of the following:

```text
X-API-Key: <key>
Authorization: Bearer <key>
```

### v2 authentication migration

Starting with source version `2.0.0`, query-string API-key authentication (`?api_key=...`) is no longer accepted. Existing clients must send the key in the `X-API-Key` header or `Authorization: Bearer` header. Also, `/api/info` is protected whenever runtime authentication is enabled; it is no longer an authentication-exempt endpoint as it was in `v1.0.0`.

When `BS_ADMIN_PASSWORD` is set, browser users can sign in as `admin` through `/api/auth/login`. Optional fixed identities `author`, `reviewer`, and `operator` are enabled by `BS_AUTHOR_PASSWORD`, `BS_REVIEWER_PASSWORD`, and `BS_OPERATOR_PASSWORD`. Successful login sets an HttpOnly `bs_session` cookie with the fixed subject/role, signed with `BS_SESSION_SECRET` when available. Unknown usernames cannot create arbitrary identities; they fall back to the fixed admin identity path. Use `BS_COOKIE_SECURE=1` behind HTTPS to force Secure cookies.

OIDC SSO is opt-in through `BS_OIDC_ISSUER_URL`, `BS_OIDC_CLIENT_ID`, `BS_OIDC_REDIRECT_URI`, and `BS_SESSION_SECRET`. Without SCIM, configure at least one exact claim-to-role mapping (or `BS_OIDC_DEFAULT_ROLE`) and optionally `BS_OIDC_ORGANIZATION_CLAIM`. With `BS_SCIM_BEARER_TOKEN` configured, SCIM becomes the OIDC role/organization authority: SCIM `externalId` must exactly match OIDC `sub`. An active user may receive role+organization directly from the BreachScope User extension, from SCIM Group membership, or from both when they resolve to the same pair; zero or conflicting effective assignments are denied. BreachScope uses Authorization Code + PKCE with signed flow state, nonce validation, provider discovery/JWKS verification, issuer/audience checks, and rejects HMAC ID-token algorithms. Existing SCIM-managed OIDC sessions are revalidated on every request, so user disable/delete, direct assignment changes, group membership/assignment changes, or group deletion invalidate stale sessions immediately. The current SCIM scope supports JSON, local SQLite, and networked PostgreSQL identity storage. PostgreSQL mutations acquire one shared advisory transaction lock before reading identity state; If-Match/Bulk version checks and writes remain inside that transaction so cooperating BreachScope replicas do not silently overwrite concurrent SCIM changes. Multi-table authorization reads use a PostgreSQL REPEATABLE READ read-only snapshot so OIDC User+Group resolution observes one consistent committed state. JSON and SQLite remain single-host storage choices. Bulk supports bounded Users/Groups POST/PUT/PATCH/DELETE with `bulkId` cross-references, a maximum of 100 operations and 1 MiB per request, and per-operation partial-failure responses; the entire Bulk request is not one atomic transaction. Nested Group membership is resolved transitively, cyclic/self-referential group graphs are rejected, and deleting a nested group removes parent references before the next OIDC authorization check. List sorting is supported only for the documented non-secret User/Group attributes and is applied before pagination. Password provisioning is not implemented; PostgreSQL HA, credential rotation, backup, and provisioning remain operator responsibilities. Without SCIM, removing an OIDC role mapping invalidates sessions for that role, while upstream IdP group or organization changes are observed on the next login/session expiry rather than continuously introspected. Retained-case APIs and audit list/export/integrity responses enforce the active organization boundary. The global `BS_API_KEY` may choose an organization with `X-BreachScope-Organization`. Keys in `BS_ORGANIZATION_API_KEYS` are bound to exactly one organization: the header may be omitted or match that organization, but a different organization is rejected. Browser sessions cannot override their signed organization with a header. New S3 replicas use organization-scoped object-key namespaces under `<prefix>/orgs/<organization_id>/<case_id>`. Legacy v1 replicas without organization metadata remain readable/deletable only from `BS_DEFAULT_ORGANIZATION_ID`. Rule-tuning profiles, custom-rule authoring/published artifacts, and activation manifests are stored in organization-scoped namespaces; the configured default organization keeps the legacy base paths for compatibility. The canonical built-in rule pack remains deployment-wide and read-only. Organization-specific permission overrides are available for the existing server-enforced RBAC gates.

SCIM provisioning uses only the dedicated `BS_SCIM_BEARER_TOKEN` on `/api/scim/v2/*`; do not reuse a BreachScope API key, password, session secret, or OIDC client secret. Persist `BS_SCIM_USER_STORE_PATH` + `BS_SCIM_GROUP_STORE_PATH` for JSON, `BS_SCIM_DATABASE_PATH` for SQLite, or supply `BS_SCIM_DATABASE_URL` only through secret runtime configuration for PostgreSQL. The PostgreSQL URL may contain credentials and is never returned by config/go-live status. Backend switching does not migrate identity data implicitly. The bundled migration CLI reads PostgreSQL URLs only from named environment variables, never emits those URLs, rejects non-empty targets unless `--replace` is explicit, and verifies the copied identity snapshot after writing. `--replace` backups contain user names, OIDC `externalId`, roles, organizations, and memberships, so protect them as identity data. SCIM identity storage is deployment-wide state and is intentionally separate from organization-scoped case backups.

Rule-lifecycle authorization is server-enforced: author can create/update/validate tuning profiles and rule drafts; reviewer can approve/publish; operator can activate/deactivate/rollback published custom rules and run analyses with `use_custom_rules=true`. `BS_ORGANIZATION_RBAC_POLICIES` can partially override the role-gated permissions per organization using `rule.author`, `rule.review`, `rule.operate`, `analysis.custom_rules`, and `case.object_storage`; omitted roles keep their built-in permissions and an empty list removes all role-gated permissions for that role. Browser/OIDC admin sessions and organization-bound API keys follow the active organization policy. The deployment-wide global API key intentionally bypasses organization RBAC policy as a break-glass/admin override. When no role-specific password or organization policy is configured, legacy single-admin behavior is preserved. A non-admin reviewer cannot approve a current draft version whose latest writer is the same subject.

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

For small/internal deployments, `/api/backups` creates organization-scoped ZIP backups containing only the active organization's case metadata/artifacts, audit events, and custom-rule lifecycle stores. The default organization keeps the base `BS_BACKUP_ROOT`; non-default organizations use separate `organizations/<organization_id>/` backup directories. Protect the backup root with filesystem permissions because backups may contain sensitive incident evidence even when reports are redacted. Use external volume snapshots for deployment-wide recovery.


## 릴리즈 위생

- `scripts/build_release.py`는 `.env`, `out/`, `dist/`, 감사 로그(`*.jsonl`), SQLite/DB 파일, 캐시 디렉토리를 릴리즈 ZIP에서 제외합니다.
- GitHub Actions 릴리즈 워크플로는 테스트와 데모 산출물 생성 후 `SHA256SUMS.txt`와 `release_manifest.json`을 생성합니다.
- 운영 배포 버전은 `/api/ops/release-info`에서 확인할 수 있습니다.