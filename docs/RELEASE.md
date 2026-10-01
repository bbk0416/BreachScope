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

릴리즈 노트, README, 포트폴리오, 고객 전달 문구에서 탐지 성능을 언급할 경우 **현재 evidence chain**을 먼저 확인합니다.

- `external_baseline/current_detection_evidence.yaml`
- `external_baseline/p2_36c_current_rulepack_fresh_source_revalidation_result.yaml`
- `docs/EXTERNAL_HOLDOUT_EVALUATION.md`

현재 73-rule detector의 fresh revalidation은 P2-36C입니다. 2개 attack fixture 중 1개가 HIT였고 source-intent benign 112,411 events 중 1개가 flagged됐지만, fixture hit fraction은 event-level recall이 아니며 이 benign 비율도 confirmed 또는 production false-positive rate가 아닙니다. Production accuracy, precision, recall, false-positive rate는 계속 `NOT_CLAIMED`입니다.

`docs/evidence/p2_14e_canonical_one_pass_result.md`와 P2-35M 등 이전 rulepack 결과는 역사 evidence로 보존합니다. 이미 봉인된 canonical 결과를 더 좋아 보이게 만들기 위한 재실행, threshold 조정, rule tuning, denominator 변경은 릴리즈 절차에 포함하지 않습니다.

## 2. 로컬 릴리즈 번들 생성

```bash
python scripts/build_release.py --clean
```

생성 위치:

```text
dist/breachscope-<version>-source.zip
dist/SHA256SUMS.txt
dist/release_manifest.json
dist/release_manifest.sig.json  # BS_RELEASE_SIGNING_PRIVATE_KEY 설정 시
```

`dist/SHA256SUMS.txt`로 ZIP 무결성을 확인할 수 있습니다.

```bash
sha256sum -c dist/SHA256SUMS.txt
```

### 선택형 Ed25519 릴리즈 서명

`BS_RELEASE_SIGNING_PRIVATE_KEY`에 URL-safe base64 형식의 32바이트 Ed25519 private seed를 넣으면 `scripts/build_release.py`가 `release_manifest.sig.json`을 함께 생성합니다. private key는 release artifact나 manifest에 기록하지 않습니다.

키쌍은 한 번 생성해 private key는 별도 secret store에 보관하고, public key 또는 SHA-256 fingerprint는 별도 신뢰 채널에 공개합니다. 예시:

```bash
python -c "from breachscope.release_signing import generate_release_signing_keypair as g; import json; print(json.dumps(g(), indent=2))"
```

서명 생성:

```bash
export BS_RELEASE_SIGNING_PRIVATE_KEY=<private-key>
python scripts/build_release.py --clean
```

검증은 두 단계가 있습니다. embedded public key만 사용하면 파일과 서명의 cryptographic consistency만 확인합니다. 배포자 진위까지 확인하려면 trusted public key를 별도로 전달해야 합니다.

```bash
python scripts/verify_release_signature.py --manifest dist/release_manifest.json --signature dist/release_manifest.sig.json
python scripts/verify_release_signature.py --manifest dist/release_manifest.json --signature dist/release_manifest.sig.json --public-key <trusted-public-key>
```

두 번째 방식이 실제 authenticity 확인에 사용하는 권장 방식입니다.

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
