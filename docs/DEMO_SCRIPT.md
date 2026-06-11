# BreachScope Demo Script

This script is designed for a 3–5 minute portfolio, interview, or stakeholder demo.

## 1. Open with the product sentence

> BreachScope is an internal DFIR console that turns Windows/security logs into a prioritized incident report, case package, Korean PDF, IOC list, audit trail, and analyst workflow.

## 2. Run the built-in attack scenarios

```bash
python scripts/run.py --demo-scenario all --out out/demo/report --export-json --export-csv --pdf
```

Point out the generated artifacts:

```text
out/demo/report.html
out/demo/report.pdf
out/demo/report.json
out/demo/report.csv
out/demo/report.iocs.csv
out/demo/report.rules.csv
out/demo/report.manifest.json
out/demo/report.zip
```

## 3. Explain what the report answers

- What happened? Risk score, executive summary, and attack timeline.
- Where did it happen? Host risk summary and affected host list.
- How does it map to ATT&CK? Tactic/technique coverage and matched rules.
- What should the analyst do first? Recommended actions and triage checklist.
- What should be searched elsewhere? IOC CSV with URL/IP/domain/hash/path candidates.
- How do we preserve delivery integrity? Manifest and SHA-256 hashes.

## 4. Show the web console

```bash
make web
```

Open `http://127.0.0.1:8000` or the configured port.

Suggested walkthrough:

1. Upload logs or run a sample scenario.
2. Show Risk Score, Top Findings, Timeline, ATT&CK, Hosts, and Charts tabs.
3. Open recent case history and reload an earlier case.
4. Edit workflow fields: assignee, status, tags, analyst notes, closure summary.
5. Open audit log to show login/analysis/download/delete events.
6. Open operations panels: backup, prune dry-run, metrics, config check, self-test.

## 5. Close with the engineering highlights

- 50-rule Windows-focused detection pack with ATT&CK coverage summary.
- 10 synthetic incident scenarios for safe repeatable demos.
- Case history, workflow, audit trail, backups, retention pruning, and health checks.
- API key plus HttpOnly session authentication for internal deployments.
- Docker Compose, GitHub Actions CI, Docker smoke tests, release checksum/manifest automation.

## 6. Suggested final line

> I built it as a product-shaped security project: not only detections, but also reporting, evidence packaging, operations, and release automation.
