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
