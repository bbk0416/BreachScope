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



def test_load_labels_accepts_ignore_and_preserves_exact_coverage(tmp_path: Path):
    path = tmp_path / "labels.jsonl"
    rows = [
        {"event_key": "a" * 64, "label": "malicious"},
        {"event_key": "b" * 64, "label": "benign"},
        {"event_key": "c" * 64, "label": "ignore"},
    ]
    path.write_text("".join(json.dumps(row) + "\n" for row in rows), encoding="utf-8")
    labels = holdout.load_labels(path)
    assert labels["c" * 64]["label"] == "ignore"
    holdout.require_complete_labels(
        [
            {"event_key": "a" * 64},
            {"event_key": "b" * 64},
            {"event_key": "c" * 64},
        ],
        labels,
    )


def test_ignore_is_excluded_from_confusion_denominator():
    records = [
        {"event_key": "a" * 64},
        {"event_key": "b" * 64},
        {"event_key": "c" * 64},
    ]
    labels = {
        "a" * 64: {"label": "malicious"},
        "b" * 64: {"label": "benign"},
        "c" * 64: {"label": "ignore"},
    }
    flagged = {"a" * 64, "c" * 64}
    assert holdout.confusion_from_flagged(records, labels, flagged) == {
        "tp": 1,
        "fp": 0,
        "tn": 1,
        "fn": 0,
    }


def test_external_calibration_records_nonblind_attestations(tmp_path: Path):
    corpus = tmp_path / "events.jsonl"
    corpus.write_text(json.dumps(_event("whoami")) + "\\n", encoding="utf-8")
    path = _manifest(tmp_path, corpus)
    data = yaml.safe_load(path.read_text(encoding="utf-8"))
    data["evaluation_class"] = "external_calibration"
    data["protocol"]["independent_from_rule_authoring"] = False
    data["protocol"]["final_holdout_seen_before_rule_freeze"] = True
    path.write_text(yaml.safe_dump(data, sort_keys=False), encoding="utf-8")

    loaded = holdout.load_manifest(path)
    assert loaded["evaluation_class"] == "external_calibration"


def test_final_blind_still_requires_independent_and_unseen(tmp_path: Path):
    corpus = tmp_path / "events.jsonl"
    corpus.write_text(json.dumps(_event("whoami")) + "\\n", encoding="utf-8")
    path = _manifest(tmp_path, corpus)
    data = yaml.safe_load(path.read_text(encoding="utf-8"))
    data["evaluation_class"] = "final_blind_holdout"
    data["protocol"]["independent_from_rule_authoring"] = False
    path.write_text(yaml.safe_dump(data, sort_keys=False), encoding="utf-8")

    with pytest.raises(holdout.HoldoutError, match="independent_from_rule_authoring"):
        holdout.load_manifest(path)


def test_scenario_manifest_rejects_unknown_source_file(tmp_path: Path):
    corpus = tmp_path / "events.jsonl"
    corpus.write_text(json.dumps(_event("whoami")) + "\\n", encoding="utf-8")
    path = _manifest(tmp_path, corpus)
    data = yaml.safe_load(path.read_text(encoding="utf-8"))
    data["scenarios"] = [
        {
            "scenario_id": "scenario-1",
            "source_files": ["missing.jsonl"],
            "expected_techniques": ["T1059.001"],
        }
    ]
    path.write_text(yaml.safe_dump(data, sort_keys=False), encoding="utf-8")

    with pytest.raises(holdout.HoldoutError, match="unknown source_files"):
        holdout.load_manifest(path)


def test_scenario_outcome_requires_all_expected_techniques():
    manifest = {
        "scenarios": [
            {
                "scenario_id": "s1",
                "source_files": ["attack.jsonl"],
                "expected_techniques": ["T1003", "T1059.001"],
            }
        ]
    }
    records = [
        {"event_key": "a" * 64, "source_file": "attack.jsonl"},
        {"event_key": "b" * 64, "source_file": "attack.jsonl"},
    ]
    partial = holdout.scenario_outcomes(
        manifest,
        records,
        {"a" * 64: {"T1003"}, "b" * 64: set()},
    )
    assert partial["hits"] == 0
    assert partial["misses"] == 1
    assert partial["outcomes"][0]["technique_recall"] == 0.5
    assert partial["outcomes"][0]["status"] == "miss"

    complete = holdout.scenario_outcomes(
        manifest,
        records,
        {"a" * 64: {"T1003"}, "b" * 64: {"T1059.001"}},
    )
    assert complete["hits"] == 1
    assert complete["misses"] == 0
    assert complete["outcomes"][0]["status"] == "hit"
