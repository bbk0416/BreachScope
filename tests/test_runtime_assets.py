from pathlib import Path

from breachscope.rules import load_rules
from breachscope.runtime_paths import default_rules_dir, default_templates_dir, resolve_rules_dir


def _files(path: Path) -> dict[str, bytes]:
    return {
        item.name: item.read_bytes()
        for item in sorted(path.iterdir())
        if item.is_file() and item.name != "__init__.py"
    }


def test_packaged_runtime_assets_match_source_canonical_files():
    root = Path(__file__).resolve().parents[1]
    packaged = root / "breachscope" / "runtime_data"

    assert _files(packaged / "rules") == _files(root / "rules")
    assert _files(packaged / "templates") == _files(root / "templates")


def test_packaged_rulepack_loads_current_rules():
    root = Path(__file__).resolve().parents[1]
    packaged_rules = root / "breachscope" / "runtime_data" / "rules"
    source_rules = root / "rules"

    assert len(load_rules(packaged_rules)) == len(load_rules(source_rules)) == 69


def test_source_checkout_prefers_canonical_runtime_directories():
    root = Path(__file__).resolve().parents[1]

    assert default_rules_dir().resolve() == (root / "rules").resolve()
    assert default_templates_dir().resolve() == (root / "templates").resolve()


def test_default_rules_resolution_uses_canonical_rules_outside_repo_cwd(tmp_path, monkeypatch):
    root = Path(__file__).resolve().parents[1]
    monkeypatch.chdir(tmp_path)
    assert resolve_rules_dir("rules").resolve() == (root / "rules").resolve()
