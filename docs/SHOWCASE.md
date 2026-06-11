# Static Showcase

The static showcase is a GitHub-Pages-ready landing page for reviewers who want
to understand BreachScope before cloning or running it.

It is different from the Demo Pack:

- **Demo Pack**: downloadable handoff bundle for offline review.
- **Static Showcase**: small static site with a landing page, summary metrics,
  social preview SVG, and links to generated demo reports.

## Build

```bash
python scripts/build_showcase.py --clean
# faster local check without PDF rendering
python scripts/build_showcase.py --clean --no-pdf
```

Output:

```text
out/showcase/index.html
out/showcase/assets/showcase.css
out/showcase/assets/social-preview.svg
out/showcase/data/showcase_summary.json
out/showcase/reports/breachscope_showcase_report.html
out/showcase/reports/breachscope_showcase_report.pdf
out/showcase/showcase_manifest.json
out/showcase/SHA256SUMS.txt
out/showcase/breachscope-showcase.zip
```

## Publish with GitHub Pages

1. Run `python scripts/build_showcase.py --clean`.
2. Upload the contents of `out/showcase` to a Pages branch or a `/docs` Pages
   folder in a separate public portfolio repository.
3. Open `index.html` first.
4. Use `assets/social-preview.svg` as the README/social preview image.

The generated page is static HTML/CSS. It does not require a backend, database,
API key, or network access.

## Integrity

Every generated artifact is listed in:

```text
out/showcase/showcase_manifest.json
out/showcase/SHA256SUMS.txt
```

These files make it easier to prove which demo report and landing page were
actually shared with a reviewer.

## API preview

The web console also exposes a lightweight preview:

```http
GET /api/ops/showcase-preview
```

This endpoint returns the recommended command, default output path, included
assets, scenario count, event count, rule count, and ATT&CK coverage.
