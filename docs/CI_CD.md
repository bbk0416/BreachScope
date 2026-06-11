# CI/CD 운영 가이드

BreachScope v16부터 GitHub Actions 기반 CI, Docker 빌드 검증, 릴리즈 번들 생성 흐름을 포함합니다.

## 워크플로 구성

| Workflow | Trigger | 목적 |
|---|---|---|
| `.github/workflows/ci.yml` | push, pull request, manual | Python 3.10/3.11/3.12 테스트, CLI 데모 산출물 생성, 룰팩 검증 |
| `.github/workflows/docker.yml` | push, pull request, manual | Docker 이미지 빌드, 컨테이너 health/API smoke test |
| `.github/workflows/release.yml` | `v*` tag, manual | 테스트 후 Python package/source ZIP/checksum/manifest 생성, 태그 릴리즈 업로드 |

## CI에서 확인하는 것

```bash
python -m compileall -q breachscope api scripts tests
pytest -q
python scripts/run.py --demo-scenario all --out out_ci/report --export-json --export-csv --pdf
python scripts/run.py --validate-rules
```

생성 확인 대상:

```text
report.html
report.json
report.csv
report.iocs.csv
report.rules.csv
report.manifest.json
report.zip
report.pdf
```

## Docker smoke test

Docker workflow는 이미지를 빌드한 뒤 컨테이너를 띄워 다음 엔드포인트를 확인합니다.

```http
GET /api/health/live
GET /api/health/ready
GET /api/info
GET /api/ops/release-info
```

`/api/info`와 `/api/ops/release-info`는 `BS_API_KEY`가 설정된 상태에서 `X-API-Key` 헤더로 접근합니다.

## Release workflow

태그를 push하면 릴리즈 워크플로가 실행됩니다.

```bash
git tag v1.0.0
git push origin v1.0.0
```

생성 산출물:

```text
breachscope-<version>-source.zip
breachscope-<version>.tar.gz / .whl
SHA256SUMS.txt
release_manifest.json
```

`release_manifest.json`에는 버전, git SHA/tag, 생성 시간, 산출물 크기와 SHA-256이 포함됩니다.

## 로컬에서 CI 비슷하게 돌리기

```bash
make ci-local
```

또는 단계별 실행:

```bash
make test
make demo-all
make validate
make release
```

## 빌드 메타데이터

Docker/CI 환경에서 다음 값을 주입할 수 있습니다.

```bash
BS_BUILD_VERSION=v1.0.0
BS_BUILD_SHA=<git sha>
BS_BUILD_TAG=v1.0.0
BS_BUILD_TIME=<build timestamp>
```

웹/API에서 확인:

```http
GET /api/ops/release-info
```
