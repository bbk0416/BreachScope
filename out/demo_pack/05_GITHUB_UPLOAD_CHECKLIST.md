# GitHub Upload Checklist

## Before push

- [ ] `python scripts/quality_gate.py --strict` 통과
- [ ] `python scripts/project_check.py --strict` 통과
- [ ] `.env` 파일이 커밋되지 않았는지 확인
- [ ] `dist/`, `out/`, `*.jsonl`, `*.db`, `*.log`가 커밋되지 않았는지 확인
- [ ] README 첫 문단과 데모 명령 확인

## First release

```bash
python scripts/build_release.py --clean
git tag v1.0.0
git push origin v1.0.0
```

## First production run

```bash
python scripts/init_env.py --production --https --output .env
python scripts/go_live_check.py --deployment-mode production
docker compose up --build
```
