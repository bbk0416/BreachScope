.PHONY: setup test demo demo-all demo-pack showcase publish-prep web validate release project-check quality-gate go-live init-env ci-local docker-build docker-up docker-down clean

setup:
	python -m pip install --upgrade pip
	python -m pip install -e . reportlab pytest

test:
	python -m compileall -q breachscope api scripts tests
	python -m pytest -q

demo:
	python scripts/run.py --demo --export-json --export-csv --pdf

demo-all:
	python scripts/run.py --demo-scenario all --out out/report --export-json --export-csv --pdf

validate:
	python scripts/run.py --validate-rules

release:
	python scripts/build_release.py --clean

demo-pack:
	python scripts/build_demo_pack.py --clean

showcase:
	python scripts/build_showcase.py --clean

publish-prep:
	python scripts/publish_prep.py --clean

project-check:
	python scripts/project_check.py --strict

quality-gate:
	python scripts/quality_gate.py --strict

go-live:
	python scripts/go_live_check.py --deployment-mode production

init-env:
	python scripts/init_env.py --production --https --output .env

ci-local: test demo-all validate release project-check quality-gate demo-pack showcase publish-prep

web:
	uvicorn api.main:app --host 127.0.0.1 --port 8000 --reload

docker-build:
	docker build -t breachscope:local .

docker-up:
	test -f .env || cp .env.example .env
	docker compose up --build

docker-down:
	docker compose down

clean:
	rm -rf out out_* .pytest_cache **/__pycache__
