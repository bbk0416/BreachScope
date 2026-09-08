# CI/CD 운영 가이드

BreachScope v16부터 GitHub Actions 기반 CI, Docker 빌드 검증, 릴리즈 번들 생성 흐름을 포함합니다.

## 워크플로 구성

| Workflow | Trigger | 목적 |
|---|---|---|
| `.github/workflows/ci.yml` | push, pull request, manual | Ubuntu Python 3.10/3.11/3.12 회귀 테스트와 Windows Python 3.11 네이티브 검증 |
| `.github/workflows/docker.yml` | push, pull request, manual | Docker 이미지 빌드, 컨테이너 health/API smoke test |
| `.github/workflows/release.yml` | `v*` tag, manual | 테스트 후 Python package/source ZIP/checksum/manifest 생성, 태그 릴리즈 업로드 |

## Ubuntu CI에서 확인하는 것

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

Ubuntu CI, release, Docker는 저장소의 SHA-256 해시가 포함된 Python별 lock을 사용합니다. 이 lock은 `scripts/compile_dependency_locks.py`에서 `x86_64-unknown-linux-gnu` 대상으로 생성되므로 Windows 설치에 재사용하지 않습니다.

## Windows 네이티브 CI

`windows-latest` / Python 3.11 lane은 Linux에서 모의하기 어려운 Windows 동작을 실제 Windows runner에서 확인합니다.

Windows에서는 Linux 전용 lock 대신 `pyproject.toml`의 platform marker가 적용되도록 `pip install -e ".[dev]"`로 설치하고 `pip check`로 의존성 일관성을 확인합니다. 예를 들어 `uvicorn[standard]`의 Windows 미지원 선택 의존성은 Windows에서 설치 대상이 되지 않아야 합니다.

- 전체 `pytest -q`
- Windows `Path` 동작을 사용하는 work directory boundary 테스트
- `python-evtx` 변환 경로 계약 테스트
- `msvcrt` 기반 case-history 파일 잠금 경로
- `wevtutil.exe`로 System 로그를 EVTX로 내보낸 뒤 JSONL로 변환하는 smoke test
- PDF를 제외한 CLI demo 산출물 생성
- 룰팩 검증

이 lane은 **Windows에서 코드 경로가 실제로 실행되고 회귀하지 않는지** 확인하기 위한 것입니다. 실제 기업 환경의 이벤트 양, 보안 제품 간섭, 권한 정책, 도메인 환경, 장기 운영 안정성까지 검증했다는 뜻은 아닙니다.

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

Linux/macOS에서는:

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

Windows 네이티브 동작의 기준은 로컬 모의가 아니라 GitHub Actions의 `windows-latest` lane 결과입니다.

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
