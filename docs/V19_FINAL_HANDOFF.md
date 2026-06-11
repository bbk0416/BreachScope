# v19 Final Handoff

v19 adds first-deployment guardrails around the already productized DFIR console.

## Added

- `scripts/init_env.py`: creates a deployment-ready `.env` with random secrets.
- `scripts/go_live_check.py`: final runtime go-live checker.
- `GET /api/ops/go-live`: web/API endpoint for production readiness checks.
- Web console **Go-Live 점검** button in the status/diagnostics panel.
- `docs/GO_LIVE.md`: first-run deployment checklist.

## Why it matters

Earlier checks validated source quality, release packaging, and repository hygiene. v19 validates the settings that most often break real deployments: placeholder secrets, missing authentication, exposed API docs, insecure cookies, unwritable data paths, and disabled audit logging.
