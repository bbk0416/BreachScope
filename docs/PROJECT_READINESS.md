# Project Readiness Check

BreachScope includes a lightweight readiness checker for release reviews and portfolio polish.

It does **not** replace the full test suite. Instead, it checks whether the repository has the expected public-project and productization assets:

- core project files such as README, SECURITY, CONTRIBUTING, LICENSE, pyproject, requirements
- deployment files such as Dockerfile, Compose, `.env.example`
- GitHub Actions workflows
- issue and pull request templates
- operator documentation
- rulepack size and ATT&CK coverage
- built-in demo scenario coverage
- test/documentation depth

The checker also does **not** validate whether public detection-performance claims are supported by external evidence. Before a release or portfolio update, compare any accuracy, precision, recall, detection-rate, false-positive-rate, or production-readiness wording against the sealed evidence and claim boundary in `docs/EXTERNAL_HOLDOUT_EVALUATION.md` and `docs/evidence/p2_14e_canonical_one_pass_result.md`.

## Run locally

```bash
python scripts/project_check.py
```

Strict mode fails on warnings as well as failures:

```bash
python scripts/project_check.py --strict
```

JSON output:

```bash
python scripts/project_check.py --json
```

Markdown report:

```bash
python scripts/project_check.py --markdown --output out/project_readiness.md
```

## API

When the web console is running:

```http
GET /api/ops/project-check
```

In protected deployments, send the same API key/session authentication used by the rest of the operations API.

## Recommended release gate

Before tagging a release:

```bash
make ci-local
python scripts/project_check.py --strict
```

Then perform a manual evidence/claim check: public wording must not exceed what the sealed external-holdout evidence actually supports. P2-14E records operational outputs from one frozen one-pass run; it does not establish production accuracy, precision, recall, detection rate, or false-positive rate.