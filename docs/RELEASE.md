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
- 현재 룰팩 검증 및 ATT&CK 커버리지 출력 정상

### 평가 증거 / 공개 문구 확인

릴리즈 노트, README, 포트폴리오, 고객 전달 문구에서 탐지 성능을 언급할 경우 다음 문서와 반드시 맞춰 확인합니다.

- `docs/EXTERNAL_HOLDOUT_EVALUATION.md`
- `docs/evidence/p2_14e_canonical_one_pass_result.md`

P2-14E는 고정된 corpus·rule pack·scoring contract로 수행한 한 번의 final blind one-pass 결과를 봉인한 기록입니다. 여기서 나온 event/finding/rule-hit 수치는 **operational output**으로만 다룹니다. 별도의 authoritative ground truth가 없으므로 이 결과를 production accuracy, precision, recall, detection rate, false-positive rate의 근거로 표현하지 않습니다.

이미 봉인된 P2-14E 결과를 더 좋아 보이게 만들기 위한 재실행, threshold 조정, rule tuning, denominator 변경은 기존 final-blind claim을 보존하는 릴리즈 절차에 포함하지 않습니다.

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

`pyproject.toml`의 `project.version`이 릴리즈 버전의 단일 기준입니다. 태그의 선행 `v`를 제외한 값과 패키지 버전이 정확히 같아야 합니다. 예를 들어 `project.version = "1.1.0"`이면 태그는 `v1.1.0`이어야 합니다.

태그 생성 전에 로컬에서 확인할 수 있습니다.

```bash
python scripts/verify_release_version.py --tag v1.1.0
```

그 다음 동일한 버전으로 태그를 생성합니다.

```bash
git tag v1.1.0
git push origin v1.1.0
```

태그가 `v*` 형식이면 `.github/workflows/release.yml`이 실행됩니다. workflow는 태그와 `pyproject.toml` 버전이 다르면 패키징 전에 실패하며, 일치할 때만 테스트, source ZIP, Python wheel/sdist, checksum, manifest를 생성한 뒤 GitHub Release에 업로드합니다.

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
