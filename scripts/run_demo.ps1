$ErrorActionPreference = 'Stop'

# Create output folder if not exists
New-Item -ItemType Directory -Force -Path out | Out-Null

# Install minimal deps if missing
python -m pip show jinja2 1>$null 2>$null; if ($LASTEXITCODE -ne 0) { python -m pip install jinja2 }
python -m pip show pyyaml 1>$null 2>$null; if ($LASTEXITCODE -ne 0) { python -m pip install pyyaml }

# Run demo (HTML + JSON + CSV)
python -m breachscope.cli --demo --rules rules --out out/report --export-json --export-csv --open

Write-Host "완료: out/report.html이 생성되었습니다." -ForegroundColor Green
