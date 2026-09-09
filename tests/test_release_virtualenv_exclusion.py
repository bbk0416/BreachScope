from pathlib import Path

from breachscope.release import iter_release_files, should_exclude


def test_release_excludes_virtualenv_directories(tmp_path: Path) -> None:
    keep = tmp_path / "breachscope" / "module.py"
    keep.parent.mkdir(parents=True)
    keep.write_text("ok\n", encoding="utf-8")

    for rel in [".venv/Lib/site-packages/pkg.py", "venv/lib/pkg.py", "env/lib/pkg.py", "tools/.venv/lib/pkg.py"]:
        path = tmp_path / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("junk\n", encoding="utf-8")

    files = [p.relative_to(tmp_path).as_posix() for p in iter_release_files(tmp_path)]
    assert files == ["breachscope/module.py"]
    assert should_exclude(".venv/Lib/site-packages/pkg.py")
    assert should_exclude("tools/.venv/lib/pkg.py")
