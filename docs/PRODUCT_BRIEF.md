# BreachScope Product Brief

## One-liner

BreachScope turns Windows-oriented security logs into an incident triage package: risk score, ATT&CK mapping, IOC candidates, timeline, host risk, case ZIP, manifest hashes, Korean PDF reports, and protected operator access.

## Target users

- Small SOC teams that need fast first-pass triage.
- Security consultants who need consistent incident report output.
- Students and job applicants who need a credible DFIR portfolio project.
- Internal IT/security teams that receive Windows logs but do not have a full SIEM workflow.

## Demo script

1. Start the web console.
2. Run the built-in `all` demo scenario from CLI or upload scenario JSONL files.
3. Show the dashboard cards: Risk Score, findings, hosts, ATT&CK coverage.
4. Open the timeline tab and explain the attack sequence.
5. Download the case ZIP and Korean PDF.
6. Open case history and re-open the previous case by case ID.
7. Show the deployment security panel: browser login uses an HttpOnly session cookie, while API clients can still use `X-API-Key`.

## Packaging tiers for a commercial direction

| Tier | Positioning | Included |
|---|---|---|
| Free / Portfolio | Local triage and demo | CLI, web console, synthetic scenarios |
| Consultant | Repeatable customer reports | PDF template, case package, manifest, custom branding |
| Team | Shared incident workspace | API key, administrator login, HttpOnly sessions, case history, persistent Docker deployment |
| Enterprise | Organization-grade workflow | SSO, RBAC, object storage, audit log, retention policy |

## Gaps before real commercial use

- More real-world EVTX fixture testing.
- OIDC SSO can bind a signed session to one organization. Retained-case operations, audit reads, built-in backups, rule-tuning profiles, custom-rule authoring/published artifacts, activation state, and S3 replica namespaces are organization-scoped. The canonical built-in rule pack remains deployment-wide/read-only. Organization-bound delegated API keys, organization-specific RBAC permission overrides, and a single-instance SCIM 2.0 Users provisioning subset with immediate OIDC session lifecycle enforcement are supported. SCIM Groups/Bulk, external identity-database storage, and multi-replica concurrent provisioning remain future work.
- S3-compatible encrypted retained-case replication/restore uses organization-scoped object-key namespaces. Primary remote storage, multi-region lifecycle/retention, and provider IAM automation remain future work.
- Rule lifecycle supports local accounts or OIDC-mapped author/reviewer/operator roles, organization-specific permission overrides, non-admin reviewer self-approval blocking, and a deployment-wide global API-key break-glass override. Canonical detector YAML remains unchanged.
- Release manifests now support optional Ed25519 detached signatures; external CI/CD runner policy, signing-key custody, and trusted public-key distribution remain operational work.
