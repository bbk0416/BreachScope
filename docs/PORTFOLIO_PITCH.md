# Portfolio Pitch

## One-liner

BreachScope is a product-shaped DFIR console that analyzes Windows/security logs, maps findings to MITRE ATT&CK, and produces analyst-ready case packages and Korean PDF reports.

## 30-second version

I built BreachScope to show that I can take a security idea beyond a simple script. It includes a 50-rule detection pack, 10 synthetic incident scenarios, IOC extraction, attack timelines, risk scoring, case history, analyst workflow, audit logs, backups, health checks, Docker deployment, and GitHub Actions release automation. The goal is to turn raw logs into a prioritized incident package that an analyst or manager can actually use.

## 60-second version

BreachScope starts from JSONL or collected Windows event logs and runs a YAML-based detection engine mapped to MITRE ATT&CK. The output is not just a list of hits: it builds a risk score, executive summary, incident timeline, host risk summary, recommended actions, false-positive questions, IOC CSV, rule catalog, manifest hashes, ZIP package, and Korean PDF report. I also added the operational pieces that real internal tools need: web console, case history, workflow status, analyst notes, authentication, audit trail, backup/prune APIs, health/readiness, Prometheus metrics, configuration diagnostics, self-test, Docker Compose, CI, and release checksums.

## What to emphasize in an interview

- Detection engineering: YAML rules, ATT&CK mapping, severity, IOC extraction.
- DFIR workflow: timeline, host risk, triage checklist, evidence manifest.
- Product thinking: web dashboard, case history, workflow fields, PDF delivery.
- Operations: auth, audit log, backup, retention, health checks, metrics.
- Engineering discipline: tests, CI, Docker smoke test, release artifact manifest.

## Honest limitations

- It is a portfolio/internal-console project, not a certified forensic suite.
- Real customer deployment would need additional log parsers, RBAC, database migration strategy, retention policy review, and production security review.
- Rules are useful for demonstration and triage, but should be tuned against each organization’s baseline to reduce false positives.
