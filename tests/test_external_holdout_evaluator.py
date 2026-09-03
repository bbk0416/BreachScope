from __future__ import annotations

import hashlib
import importlib.util
import json
from pathlib import Path

import pytest
import yaml

SCRIPT = Path(__file__).resolve().parents[1] / "scripts" / "evaluate_external_holdout.py"
SPEC = importlib.util.spec_from_file_location("external_holdout", SCRIPT)
assert SPEC and SPEC.loader
holdout = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(holdout)


def _sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _event(command: str, event_id: str = "4688") -> dict:
    return {
        "timestamp": "2026-01-01T00:00:00Z",
        "host": "WS-01",
        "source": "ProcessCreate",
        "event_id": event_id,
        "user": "CORP\\alice",
        "command_line": command,
        "raw": {"CommandLine": command},
    }


def _manifest(tmp_path: Path, corpus: Path) -> Path:
    manifest = {
        "schema": holdout.SCHEMA,
        "kind": "external_blind_holdout",
        "protocol": {
            "independent_from_rule_authoring": True,
            "ground_truth_prepared_without_breachscope_findings": True,
            "final_holdout_seen_before_rule_freeze": False,
        },
        "provenance": {
            "source": "unit-test protocol fixture only",
            "license_or_permission": "test fixture",
        },
        "files": [
            {
                "path": corpus.name,
                "sha256": _sha(corpus),
                "format": "jsonl",
            }
        ],
    }
    path = tmp_path / "manifest.yaml"
    path.write_text(yaml.safe_dump(manifest, sort_keys=False), encoding="utf-8")
    return path


def test_event_key_is_stable_and_field_sensitive():
    a = _event("cmd.exe /c whoami")
    b = dict(reversed(list(a.items())))
    assert holdout.event_key(a) == holdout.event_key(b)
    assert holdout.event_key(a) != holdout.event_key(_event("cmd.exe /c hostname"))


def test_manifest_requires_explicit_blind_protocol(tmp_path: Path):
    corpus = tmp_path / "events.jsonl"
    corpus.write_text(json.dumps(_event("whoami")) + "\n", encoding="utf-8")
    path = _manifest(tmp_path, corpus)
    data = yaml.safe_load(path.read_text(encoding="utf-8"))
    data["protocol"]["final_holdout_seen_before_rule_freeze"] = True
    path.write_text(yaml.safe_dump(data, sort_keys=False), encoding="utf-8")

    with pytest.raises(holdout.HoldoutError, match="final_holdout_seen_before_rule_freeze"):
        holdout.load_manifest(path)


def test_corpus_hash_mismatch_fails_closed(tmp_path: Path):
    corpus = tmp_path / "events.jsonl"
    corpus.write_text(json.dumps(_event("whoami")) + "\n", encoding="utf-8")
    manifest = _manifest(tmp_path, corpus)
    corpus.write_text(json.dumps(_event("hostname")) + "\n", encoding="utf-8")

    with pytest.raises(holdout.HoldoutError, match="hash mismatch"):
        holdout.load_corpus_records(holdout.load_manifest(manifest), tmp_path)


def test_index_contains_no_findings_or_detector_output(tmp_path: Path):
    corpus = tmp_path / "events.jsonl"
    corpus.write_text(
        json.dumps(_event("whoami")) + "\n" + json.dumps(_event("hostname", "1")) + "\n",
        encoding="utf-8",
    )
    manifest = _manifest(tmp_path, corpus)
    records = holdout.load_corpus_records(holdout.load_manifest(manifest), tmp_path)
    out = tmp_path / "index.jsonl"
    holdout.write_index(records, out)

    rows = [json.loads(x) for x in out.read_text(encoding="utf-8").splitlines()]
    assert len(rows) == 2
    assert all("event_key" in row for row in rows)
    assert all(row["label"] == "" for row in rows)
    text = out.read_text(encoding="utf-8").lower()
    assert "finding" not in text
    assert "rule_id" not in text
    assert "matched_value" not in text


def test_labels_must_cover_exact_event_set(tmp_path: Path):
    records = [
        {"event_key": "a" * 64},
        {"event_key": "b" * 64},
    ]
    labels = {
        "a" * 64: {"label": "benign", "expected_techniques": []},
    }
    with pytest.raises(holdout.HoldoutError, match="coverage must be exact"):
        holdout.require_complete_labels(records, labels)


def test_confusion_matrix_accounting():
    records = [
        {"event_key": "a" * 64},
        {"event_key": "b" * 64},
        {"event_key": "c" * 64},
        {"event_key": "d" * 64},
    ]
    labels = {
        "a" * 64: {"label": "malicious"},
        "b" * 64: {"label": "malicious"},
        "c" * 64: {"label": "benign"},
        "d" * 64: {"label": "benign"},
    }
    flagged = {"a" * 64, "c" * 64}
    assert holdout.confusion_from_flagged(records, labels, flagged) == {
        "tp": 1,
        "fp": 1,
        "tn": 1,
        "fn": 1,
    }
