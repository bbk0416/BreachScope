# Demo Pack Builder

`build_demo_pack.py` creates a shareable handoff bundle for GitHub README images, portfolio review, client demos, or interview walkthroughs.

It runs the built-in synthetic incident scenarios, generates the standard BreachScope analysis artifacts, and adds presentation-ready Markdown files.

## Build

```bash
python scripts/build_demo_pack.py --clean
```

Fast mode without PDF rendering:

```bash
python scripts/build_demo_pack.py --clean --no-pdf
```

Default output:

```text
out/demo_pack/
├── README.md
├── 02_DEMO_WALKTHROUGH.md
├── 03_PORTFOLIO_PITCH.md
├── 04_RELEASE_NOTES.md
├── 05_GITHUB_UPLOAD_CHECKLIST.md
├── 06_SCREENSHOT_GUIDE.md
├── demo_pack_manifest.json
├── demo_pack_result.json
├── SHA256SUMS.txt
├── breachscope-demo-pack.zip
├── reports/
│   ├── breachscope_demo_report.html
│   ├── breachscope_demo_report.pdf
│   ├── breachscope_demo_report.json
│   ├── breachscope_demo_report.csv
│   ├── breachscope_demo_report.iocs.csv
│   ├── breachscope_demo_report.rules.csv
│   ├── breachscope_demo_report.manifest.json
│   └── breachscope_demo_report.zip
└── samples/scenarios/*.jsonl
```

## What this is for

Use the demo pack when you need a polished, offline-friendly package that explains the project without making the reviewer run commands first.

Recommended opening order:

1. `README.md`
2. `reports/breachscope_demo_report.html`
3. `reports/breachscope_demo_report.pdf`
4. `02_DEMO_WALKTHROUGH.md`
5. `03_PORTFOLIO_PITCH.md`

## API preview

The web/API layer exposes a lightweight preview of what the demo pack contains:

```http
GET /api/ops/demo-pack-preview
```

This endpoint does not build files; it only returns scenario counts, rulepack summary, recommended command, and expected artifacts.

## Safety note

The included scenarios are synthetic logs only. They use `example.local`, `SIMULATED`, and placeholder values so the project can demonstrate DFIR workflows without shipping real customer logs or weaponized payloads.
