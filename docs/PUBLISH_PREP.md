# Public Publish Prep

`publish_prep.py`는 GitHub 공개 직전 마지막 산출물을 한 번에 묶는 핸드오프 빌더입니다.

이 도구는 기존 릴리즈 ZIP, Demo Pack, Static Showcase를 모두 생성한 뒤, ZIP 내부에 `__pycache__`, `.env`, `.pyc`, 로컬 DB/로그 같은 파일이 들어가지 않았는지 검사합니다.

## 실행

```bash
python scripts/publish_prep.py --clean
```

빠른 검증용으로 PDF 렌더링을 생략할 수 있습니다.

```bash
python scripts/publish_prep.py --clean --no-pdf
```

## 생성물

기본 출력 위치는 `out/publish`입니다.

```text
out/publish/
├── dist/
│   ├── breachscope-1.0.0-source.zip
│   ├── SHA256SUMS.txt
│   └── release_manifest.json
├── demo_pack/
│   └── breachscope-demo-pack.zip
├── showcase/
│   ├── index.html
│   └── breachscope-showcase.zip
├── PUBLIC_LAUNCH_SUMMARY.md
├── GITHUB_PUBLISH_COMMANDS.md
├── RELEASE_NOTE_DRAFT.md
├── publish_manifest.json
├── SHA256SUMS.txt
└── breachscope-public-launch-pack.zip
```

## 점검하는 것

- Project Readiness
- Quality Gate
- Production profile 기준 Go-Live Check
- 릴리즈 ZIP 위생 검사
- Demo Pack ZIP 위생 검사
- Showcase ZIP 위생 검사
- 최종 public launch ZIP checksum 생성

## API Preview

웹/운영 API에서 포함 항목을 가볍게 확인할 수 있습니다.

```http
GET /api/ops/publish-prep-preview
```

## GitHub 공개 순서

```bash
make ci-local
python scripts/publish_prep.py --clean
git status
git add .
git commit -m "Prepare BreachScope public release"
git push -u origin main
git tag v1.0.0
git push origin v1.0.0
```

## 주의

`out/`, `dist/`, `.env`, `*.jsonl`, `*.db`, `*.log`는 커밋하지 않습니다. 실제 고객 로그나 기관 로그도 절대 포함하지 않습니다.
