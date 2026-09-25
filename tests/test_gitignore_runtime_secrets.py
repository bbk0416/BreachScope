from pathlib import Path


def test_runtime_env_files_are_gitignored_but_example_is_trackable():
    root = Path(__file__).resolve().parents[1]
    patterns = {
        line.strip()
        for line in (root / ".gitignore").read_text(encoding="utf-8").splitlines()
        if line.strip() and not line.lstrip().startswith("#")
    }

    assert ".env" in patterns
    assert ".env.*" in patterns
    assert "!.env.example" in patterns
