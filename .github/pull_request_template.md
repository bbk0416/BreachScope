## Summary

-

## Validation

- [ ] `python -m compileall -q breachscope api scripts tests`
- [ ] `pytest -q`
- [ ] `python scripts/run.py --validate-rules`
- [ ] `python scripts/run.py --demo-scenario all --out out_pr/report --export-json --export-csv --pdf`
- [ ] `python scripts/project_check.py --strict`

## Safety / data handling

- [ ] I did not commit real customer logs, credentials, tokens, or private indicators.
- [ ] New logs or scenarios are synthetic/sanitized.
- [ ] Report/UI output that renders log-controlled values is escaped or otherwise safe.

## Notes for reviewers

