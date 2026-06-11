# Quality Gate

BreachScope includes a lightweight pre-publication quality/security gate for release reviews. It is designed to catch mistakes that are easy to miss before pushing a public portfolio repository or tagging a release.

## Run locally

```bash
python scripts/quality_gate.py
python scripts/quality_gate.py --strict
python scripts/quality_gate.py --markdown --output out/quality_gate.md
python scripts/quality_gate.py --json --output out/quality_gate.json
```

`--strict` returns a non-zero exit code on warnings as well as failures, which is useful for CI.

## What it checks

- **Forbidden runtime files**: `.env`, local DB files, audit JSONL logs, case history state, and generated output directories should not be committed.
- **Secret scan**: high-confidence patterns such as private keys, cloud access keys, GitHub tokens, Slack tokens, Stripe live keys, and long secret-like environment assignments.
- **Large files**: warns when unusually large source files are committed.
- **Markdown links**: verifies internal Markdown links and blocks unsafe link targets.
- **Release hygiene**: confirms the source-release iterator excludes generated artifacts and local state.
- **Security/release docs**: confirms deployment, release, CI/CD, and vulnerability handling guidance exist.

The scanner intentionally ignores bundled synthetic demo logs under `samples/scenarios/*.jsonl` because those are safe demonstration fixtures, not runtime audit logs.

## API

```http
GET /api/ops/quality-gate
```

The API returns the same structured result used by the CLI:

```json
{
  "success": true,
  "status": "pass",
  "score": 100,
  "summary": {"checks": 6, "passed": 6, "warnings": 0, "failed": 0}
}
```

## CI usage

The default CI workflow runs the strict gate after tests, demo artifact generation, rule validation, release packaging, and project readiness checks.

```bash
make quality-gate
make ci-local
```

## Notes

This gate is not a replacement for a full commercial SAST/secret-scanning platform. It is a deterministic project-level guardrail that makes public release mistakes much less likely.
