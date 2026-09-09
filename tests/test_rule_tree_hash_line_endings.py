from pathlib import Path

from scripts.evaluate_external_holdout import rules_tree_hash
from scripts.verify_reproducible_benchmark import _rules_tree_hash


def _write_rules(root: Path, newline: bytes) -> Path:
    rules = root / "rules"
    rules.mkdir(parents=True)
    (rules / "a.yml").write_bytes(b"- id: A" + newline + b"  pattern: x" + newline)
    (rules / "b.yaml").write_bytes(b"- id: B" + newline + b"  pattern: y" + newline)
    return rules


def test_rule_tree_hash_is_independent_of_line_endings(tmp_path: Path) -> None:
    lf = _write_rules(tmp_path / "lf", bytes([10]))
    crlf = _write_rules(tmp_path / "crlf", bytes([13, 10]))

    assert rules_tree_hash(lf) == rules_tree_hash(crlf)
    assert _rules_tree_hash(lf) == _rules_tree_hash(crlf)
    assert rules_tree_hash(lf) == _rules_tree_hash(lf)
