# 릴리즈 절차

이 문서는 BreachScope를 GitHub 릴리즈 또는 고객 전달용 ZIP으로 묶을 때 사용하는 절차입니다.

## 1. 릴리즈 전 점검

```bash
make test
make demo-all
make validate
```

확인 포인트:

- 테스트 전체 통과
- 10개 내장 시나리오 전체 실행 성공
- `report.pdf` 한글 깨짐 없음
- `report.manifest.json`과 `report.zip` 생성
- 룰팩 50개 및 ATT&CK 커버리지 출력 정상

## 2. 로컬 릴리즈 번들 생성

```bash
python scripts/build_release.py --clean
```

생성 위치:

```text
dist/breachscope-<version>-source.zip
dist/SHA256SUMS.txt
dist/release_manifest.json
```

`dist/SHA256SUMS.txt`로 ZIP 무결성을 확인할 수 있습니다.

```bash
sha256sum -c dist/SHA256SUMS.txt
```

## 3. GitHub 태그 릴리즈

```bash
git tag v1.0.0
git push origin v1.0.0
```

태그가 `v*` 형식이면 `.github/workflows/release.yml`이 실행되어 테스트, 패키징, checksum 생성 후 GitHub Release에 업로드합니다.

## 4. 전달 패키지에서 제외되는 파일

릴리즈 ZIP은 다음을 제외합니다.

```text
.git/
.env
out/
out_*/
dist/
build/
.pytest_cache/
__pycache__/
*.pyc
*.sqlite / *.db / *.jsonl / *.log
```

즉, 로컬 비밀값, 분석 결과, 감사 로그, 임시 산출물은 기본적으로 릴리즈 ZIP에 들어가지 않습니다.

## 5. 운영 버전 확인

운영 배포 후 다음 API로 실제 배포 빌드를 확인합니다.

```http
GET /api/ops/release-info
```

응답에는 버전, git SHA/tag, Python 버전, 플랫폼, 빌드 번호가 포함됩니다.
