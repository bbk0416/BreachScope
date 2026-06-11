# GitHub Publish Commands

## 1. Final local checks

```bash
make ci-local
python scripts/publish_prep.py --clean
```

## 2. Push source

```bash
git status
git add .
git commit -m "Prepare BreachScope public release"
git branch -M main
git remote add origin https://github.com/bbk0416/BreachScope.git  # 이미 있으면 생략
git push -u origin main
```

## 3. Create the first release tag

```bash
git tag v1.0.0
git push origin v1.0.0
```

## 4. Enable GitHub Pages

- Repository Settings → Pages
- Source: GitHub Actions 또는 `/docs`/`gh-pages` 전략 중 선택
- 정적 결과물은 `out/publish/showcase/index.html` 기준으로 확인

## 5. Do not commit

- `.env`
- `out/`, `dist/`, `*.jsonl`, `*.db`, `*.log`
- 실제 고객/기관 로그
- API Key, 관리자 비밀번호, 세션 시크릿
