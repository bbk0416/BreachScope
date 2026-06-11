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
- RBAC/SSO and per-organization permissions beyond the built-in single-admin login.
- Encrypted object storage for reports and uploads.
- Rule tuning UI and analyst feedback loop.
- Signed release artifacts and CI/CD.
