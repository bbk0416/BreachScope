# Dependency Locking

BreachScope keeps `pyproject.toml` and `requirements.txt` as human-maintained
compatibility ranges. CI, release validation, and the Docker runtime install
from committed **per-Python SHA-256 lock files**.

## Locked targets

- Python 3.10.21 / Linux x86-64 → `requirements-lock-py310.txt`
- Python 3.11.16 / Linux x86-64 → `requirements-lock-py311.txt`
- Python 3.12.14 / Linux x86-64 → `requirements-lock-py312.txt`

`.python-version` records 3.11.16 as the reference development/release runtime.

## Regenerating locks

The lock compiler uses `uv pip compile` with an explicit target platform and
Python patch version, so a Windows workstation can resolve the same Linux CI
targets without Docker.

Use the pinned resolver:

```cmd
python -m pip install uv==0.12.8
python scripts\compile_dependency_locks.py
python scripts\verify_dependency_locks.py --strict
```

The compiler also fixes the resolver candidate cutoff to
`2026-09-01T00:00:00Z`. Intentional future dependency refreshes should update
that cutoff in the same reviewed change.

## Install contract

CI selects the lock that matches the exact matrix Python runtime and installs
it with `pip --require-hashes`. The local project is then installed with
`--no-deps --no-build-isolation` so pip does not resolve a second dependency
graph.

The release workflow uses Python 3.11.16, the py311 lock, and
`python -m build --no-isolation`.

The Dockerfile pins its Python runtime to `python:3.11.16-slim-bookworm`,
installs the py311 lock with hash enforcement, and uses the locked
setuptools/wheel for the editable project install.

## Scope

This is dependency/runtime determinism, not complete supply-chain immutability.
GitHub Actions are still referenced by major tags and the Debian base/apt
repositories are not pinned by immutable digest/snapshot. Those remain separate
supply-chain hardening work.
