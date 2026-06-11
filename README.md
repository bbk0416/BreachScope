# BreachScope Static Showcase

This folder is a static, GitHub-Pages-ready showcase for BreachScope.

## Open first

1. `index.html` — landing page for reviewers
2. `reports/breachscope_showcase_report.html` — full HTML demo report
3. `reports/breachscope_showcase_report.pdf` — Korean PDF report
4. `data/showcase_summary.json` — machine-readable metrics
5. `SHA256SUMS.txt` — artifact integrity checksums

## Snapshot

- Version: `1.0.0`
- Demo events: **48**
- Findings: **53**
- Risk: **100/100 (critical)**
- Rulepack: **50 rules / 40 techniques / 96.9% coverage**

## Regenerate

```bash
python scripts/build_showcase.py --clean
```
