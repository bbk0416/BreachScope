#!/usr/bin/env python3
"""Prepare DEDALE Winlogbeat data for P2-37 without running detection rules.

This tool deliberately keeps source preparation separate from scoring:
1. normalize: read only the full Winlogbeat corpus, select the frozen test
   window, and emit flat Windows JSONL plus a label-free provider identity map.
2. bind-labels: after BreachScope's external-holdout index exists, read the
   provider class-1/class-2 label files, reconcile them exactly to the selected
   corpus, and emit evaluator labels.

No detector code is imported or executed here.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import sqlite3
import sys
import tempfile
from contextlib import contextmanager
from datetime import datetime, timezone
from itertools import zip_longest
from pathlib import Path
from typing import Any, Iterable, Iterator, Mapping

CLASS1_NAME = "malicious_events_class_1.jsonl"
CLASS2_NAME = "malicious_events_class_2.jsonl"


class DedalePreparationError(RuntimeError):
    pass


def _json_bytes(value: Any) -> bytes:
    return (
        json.dumps(
            value,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
        )
        + "\n"
    ).encode("utf-8")


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _mapping(value: Any) -> Mapping[str, Any]:
    return value if isinstance(value, Mapping) else {}


def _parse_time(value: Any, label: str) -> datetime:
    text = str(value or "").strip()
    if not text:
        raise DedalePreparationError(f"{label} timestamp is required")
    if text.endswith("Z"):
        text = text[:-1] + "+00:00"
    try:
        parsed = datetime.fromisoformat(text)
    except ValueError as exc:
        raise DedalePreparationError(
            f"{label} timestamp is not ISO-8601: {value!r}"
        ) from exc
    if parsed.tzinfo is None:
        raise DedalePreparationError(f"{label} timestamp must include timezone")
    return parsed.astimezone(timezone.utc)


def _window(start: str, end: str) -> tuple[datetime, datetime]:
    start_dt = _parse_time(start, "start")
    end_dt = _parse_time(end, "end")
    if start_dt >= end_dt:
        raise DedalePreparationError("start must be earlier than end")
    return start_dt, end_dt


def _in_window(row: Mapping[str, Any], start: datetime, end: datetime) -> bool:
    timestamp = _parse_time(row.get("@timestamp"), "event")
    return start <= timestamp < end


def _require_winlogbeat(row: Mapping[str, Any]) -> None:
    agent = _mapping(row.get("agent"))
    agent_type = str(agent.get("type") or "").strip().casefold()
    if agent_type != "winlogbeat":
        raise DedalePreparationError(
            f"selected event is not Winlogbeat: agent.type={agent_type!r}"
        )


def _provider_identity_payload(row: Mapping[str, Any]) -> dict[str, str]:
    winlog = _mapping(row.get("winlog"))
    event = _mapping(row.get("event"))
    host = _mapping(row.get("host"))

    timestamp = str(row.get("@timestamp") or "").strip()
    hostname = str(host.get("name") or winlog.get("computer_name") or "").strip()
    channel = str(winlog.get("channel") or "").strip()
    record_id = str(winlog.get("record_id") or "").strip()
    event_id = str(winlog.get("event_id") or event.get("code") or "").strip()

    required = {
        "@timestamp": timestamp,
        "host": hostname,
        "winlog.channel": channel,
        "winlog.record_id": record_id,
        "event_id": event_id,
    }
    missing = [key for key, value in required.items() if not value]
    if missing:
        raise DedalePreparationError(
            "DEDALE Winlogbeat identity is incomplete: " + ", ".join(missing)
        )

    return {
        "timestamp": timestamp,
        "host": hostname,
        "channel": channel,
        "record_id": record_id,
        "event_id": event_id,
    }


def provider_identity(row: Mapping[str, Any]) -> str:
    payload = _provider_identity_payload(row)
    canonical = json.dumps(
        payload,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    ).encode("utf-8")
    return hashlib.sha256(canonical).hexdigest()


def _entity_user(row: Mapping[str, Any], event_data: Mapping[str, Any]) -> str:
    direct = event_data.get("User")
    if direct not in (None, ""):
        return str(direct)

    user = _mapping(row.get("user"))
    name = str(user.get("name") or "").strip()
    domain = str(user.get("domain") or "").strip()
    if name:
        return f"{domain}\\{name}" if domain else name

    winlog_user = _mapping(_mapping(row.get("winlog")).get("user"))
    name = str(winlog_user.get("name") or "").strip()
    domain = str(winlog_user.get("domain") or "").strip()
    if name:
        return f"{domain}\\{name}" if domain else name
    return ""


def normalize_winlogbeat_row(row: Mapping[str, Any]) -> dict[str, Any]:
    _require_winlogbeat(row)
    identity = _provider_identity_payload(row)

    winlog = _mapping(row.get("winlog"))
    event = _mapping(row.get("event"))
    event_data = _mapping(winlog.get("event_data"))
    process = _mapping(row.get("process"))
    parent = _mapping(process.get("parent"))
    process_pe = _mapping(process.get("pe"))

    flat: dict[str, Any] = dict(event_data)
    flat.update(
        {
            "timestamp": identity["timestamp"],
            "Hostname": identity["host"],
            "SourceName": str(
                winlog.get("provider_name")
                or event.get("provider")
                or ""
            ).strip(),
            "EventID": identity["event_id"],
            "Channel": identity["channel"],
            "RecordNumber": identity["record_id"],
        }
    )

    command_line = str(
        event_data.get("CommandLine")
        or process.get("command_line")
        or ""
    ).strip()
    if command_line:
        flat["CommandLine"] = command_line

    executable = str(
        event_data.get("Image")
        or process.get("executable")
        or ""
    ).strip()
    if executable:
        flat["Image"] = executable

    parent_executable = str(
        event_data.get("ParentImage")
        or parent.get("executable")
        or ""
    ).strip()
    if parent_executable:
        flat["ParentImage"] = parent_executable

    original_name = str(
        event_data.get("OriginalFileName")
        or process_pe.get("original_file_name")
        or ""
    ).strip()
    if original_name:
        flat["OriginalFileName"] = original_name

    user = _entity_user(row, event_data)
    if user:
        flat["User"] = user

    if process:
        flat["process"] = dict(process)

    message = row.get("message")
    if isinstance(message, str) and message:
        flat["message"] = message

    return flat


def _iter_jsonl(paths: Iterable[Path]) -> Iterator[tuple[Path, int, dict[str, Any]]]:
    for path in paths:
        with path.open("r", encoding="utf-8") as handle:
            for line_number, line in enumerate(handle, 1):
                text = line.strip()
                if not text:
                    continue
                try:
                    row = json.loads(text)
                except json.JSONDecodeError as exc:
                    raise DedalePreparationError(
                        f"invalid JSONL row: {path}:{line_number}: {exc}"
                    ) from exc
                if not isinstance(row, dict):
                    raise DedalePreparationError(
                        f"JSONL row must be an object: {path}:{line_number}"
                    )
                yield path, line_number, row


def _source_paths(root: Path) -> list[Path]:
    paths = sorted(
        path
        for path in root.rglob("*.jsonl")
        if path.is_file()
    )
    if not paths:
        raise DedalePreparationError(f"no JSONL files found under {root}")
    return paths


def _row_digest(row: Mapping[str, Any]) -> str:
    canonical = json.dumps(
        row,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    ).encode("utf-8")
    return hashlib.sha256(canonical).hexdigest()


@contextmanager
def _temporary_db(prefix: str) -> Iterator[sqlite3.Connection]:
    with tempfile.NamedTemporaryFile(
        prefix=prefix,
        suffix=".sqlite3",
        delete=False,
    ) as temp:
        path = Path(temp.name)
    conn = sqlite3.connect(path)
    try:
        conn.execute("PRAGMA journal_mode=OFF")
        conn.execute("PRAGMA synchronous=OFF")
        yield conn
    finally:
        conn.close()
        path.unlink(missing_ok=True)


def normalize_corpus(
    *,
    winlogbeat_root: Path,
    out_corpus: Path,
    out_identity_map: Path,
    start: str,
    end: str,
) -> dict[str, Any]:
    start_dt, end_dt = _window(start, end)
    root = winlogbeat_root.resolve()
    paths = _source_paths(root)

    out_corpus.parent.mkdir(parents=True, exist_ok=True)
    out_identity_map.parent.mkdir(parents=True, exist_ok=True)

    selected = 0
    outside_window = 0
    source_rows = 0
    selected_files: set[str] = set()

    try:
        with _temporary_db("p2-37-normalize-") as conn:
            conn.execute(
                "CREATE TABLE seen (provider_identity TEXT PRIMARY KEY)"
            )
            with (
                out_corpus.open("wb") as corpus_handle,
                out_identity_map.open("wb") as identity_handle,
            ):
                for path, line_number, row in _iter_jsonl(paths):
                    source_rows += 1
                    _require_winlogbeat(row)
                    if not _in_window(row, start_dt, end_dt):
                        outside_window += 1
                        continue

                    provider_id = provider_identity(row)
                    try:
                        conn.execute(
                            "INSERT INTO seen(provider_identity) VALUES (?)",
                            (provider_id,),
                        )
                    except sqlite3.IntegrityError as exc:
                        raise DedalePreparationError(
                            "duplicate provider identity in selected DEDALE corpus: "
                            f"{provider_id}"
                        ) from exc

                    normalized = normalize_winlogbeat_row(row)
                    selected += 1
                    rel = path.relative_to(root).as_posix()
                    selected_files.add(rel)

                    corpus_handle.write(_json_bytes(normalized))
                    identity_handle.write(
                        _json_bytes(
                            {
                                "record_index": selected,
                                "provider_identity": provider_id,
                                "source_file": rel,
                                "source_line": line_number,
                                "source_row_sha256": _row_digest(row),
                            }
                        )
                    )

            if selected == 0:
                raise DedalePreparationError(
                    "selected DEDALE test window contains zero Winlogbeat events"
                )
    except Exception:
        out_corpus.unlink(missing_ok=True)
        out_identity_map.unlink(missing_ok=True)
        raise

    return {
        "status": "PASS",
        "detection_rules_executed": False,
        "labels_read": False,
        "window_start": start_dt.isoformat(),
        "window_end": end_dt.isoformat(),
        "source_jsonl_files": len(paths),
        "selected_source_files": len(selected_files),
        "source_rows": source_rows,
        "outside_window_rows": outside_window,
        "selected_rows": selected,
        "normalized_corpus_sha256": _sha256_file(out_corpus),
        "identity_map_sha256": _sha256_file(out_identity_map),
    }


def _load_identity_map(conn: sqlite3.Connection, path: Path) -> int:
    conn.execute(
        """
        CREATE TABLE selected (
            record_index INTEGER PRIMARY KEY,
            provider_identity TEXT NOT NULL UNIQUE,
            class_label TEXT
        )
        """
    )
    count = 0
    for _, line_number, row in _iter_jsonl([path]):
        try:
            record_index = int(row["record_index"])
            provider_id = str(row["provider_identity"])
        except (KeyError, TypeError, ValueError) as exc:
            raise DedalePreparationError(
                f"invalid identity-map row at line {line_number}"
            ) from exc
        if record_index != count + 1:
            raise DedalePreparationError(
                "identity-map record_index must be contiguous from 1"
            )
        if len(provider_id) != 64:
            raise DedalePreparationError(
                f"invalid provider identity at line {line_number}"
            )
        try:
            conn.execute(
                """
                INSERT INTO selected(record_index, provider_identity, class_label)
                VALUES (?, ?, NULL)
                """,
                (record_index, provider_id),
            )
        except sqlite3.IntegrityError as exc:
            raise DedalePreparationError(
                f"duplicate provider identity in identity map: {provider_id}"
            ) from exc
        count += 1
    if count == 0:
        raise DedalePreparationError("identity map is empty")
    return count


def _label_paths(labels_dir: Path, filename: str) -> list[Path]:
    paths = sorted(
        path
        for path in labels_dir.rglob(filename)
        if path.is_file()
    )
    if not paths:
        raise DedalePreparationError(
            f"{filename} not found under {labels_dir}"
        )
    return paths


def _apply_provider_class(
    *,
    conn: sqlite3.Connection,
    paths: list[Path],
    class_label: str,
    start: datetime,
    end: datetime,
) -> int:
    count = 0
    seen: set[str] = set()
    for path, line_number, row in _iter_jsonl(paths):
        _require_winlogbeat(row)
        if not _in_window(row, start, end):
            raise DedalePreparationError(
                "provider ground-truth event falls outside frozen test window: "
                f"{path}:{line_number}"
            )
        provider_id = provider_identity(row)
        if provider_id in seen:
            raise DedalePreparationError(
                f"duplicate provider ground-truth identity: {provider_id}"
            )
        seen.add(provider_id)

        existing = conn.execute(
            "SELECT class_label FROM selected WHERE provider_identity = ?",
            (provider_id,),
        ).fetchone()
        if existing is None:
            raise DedalePreparationError(
                "provider ground-truth event is not an exact subset of selected "
                f"Winlogbeat events: {provider_id}"
            )
        if existing[0] is not None:
            raise DedalePreparationError(
                "provider ground-truth identity appears in more than one class: "
                f"{provider_id}"
            )
        conn.execute(
            "UPDATE selected SET class_label = ? WHERE provider_identity = ?",
            (class_label, provider_id),
        )
        count += 1
    return count


def _iter_index(path: Path) -> Iterator[dict[str, Any]]:
    for _, line_number, row in _iter_jsonl([path]):
        event_key = str(row.get("event_key") or "").strip()
        try:
            record_index = int(row["record_index"])
        except (KeyError, TypeError, ValueError) as exc:
            raise DedalePreparationError(
                f"invalid evaluator index record_index at line {line_number}"
            ) from exc
        if len(event_key) != 64 or any(
            ch not in "0123456789abcdef" for ch in event_key
        ):
            raise DedalePreparationError(
                f"invalid evaluator event_key at line {line_number}"
            )
        yield {
            "event_key": event_key,
            "record_index": record_index,
        }


def bind_labels(
    *,
    evaluator_index: Path,
    identity_map: Path,
    winlogbeat_labels_dir: Path,
    out_labels: Path,
    start: str,
    end: str,
) -> dict[str, Any]:
    start_dt, end_dt = _window(start, end)
    out_labels.parent.mkdir(parents=True, exist_ok=True)

    class1_paths = _label_paths(winlogbeat_labels_dir, CLASS1_NAME)
    class2_paths = _label_paths(winlogbeat_labels_dir, CLASS2_NAME)

    malicious = 0
    ignored = 0
    benign = 0

    try:
        with _temporary_db("p2-37-labels-") as conn:
            selected_count = _load_identity_map(conn, identity_map)
            malicious = _apply_provider_class(
                conn=conn,
                paths=class1_paths,
                class_label="malicious",
                start=start_dt,
                end=end_dt,
            )
            ignored = _apply_provider_class(
                conn=conn,
                paths=class2_paths,
                class_label="ignore",
                start=start_dt,
                end=end_dt,
            )

            class_rows = conn.execute(
                """
                SELECT record_index, class_label
                FROM selected
                ORDER BY record_index
                """
            )

            index_rows = _iter_index(evaluator_index)
            with out_labels.open("wb") as handle:
                for expected_index, pair in enumerate(
                    zip_longest(index_rows, class_rows),
                    1,
                ):
                    index_row, class_row = pair
                    if index_row is None or class_row is None:
                        raise DedalePreparationError(
                            "evaluator index and identity map row counts differ"
                        )
                    record_index, class_label = class_row
                    if (
                        index_row["record_index"] != record_index
                        or record_index != expected_index
                    ):
                        raise DedalePreparationError(
                            "evaluator index order does not match identity map"
                        )
                    label = class_label or "benign"
                    if label == "benign":
                        benign += 1
                    note = {
                        "malicious": "DEDALE provider class 1",
                        "ignore": "DEDALE provider class 2 attack-related context",
                        "benign": (
                            "DEDALE complement after exact class-1/class-2 "
                            "subset reconciliation"
                        ),
                    }[label]
                    handle.write(
                        _json_bytes(
                            {
                                "event_key": index_row["event_key"],
                                "label": label,
                                "expected_techniques": [],
                                "notes": note,
                            }
                        )
                    )

            if malicious + ignored + benign != selected_count:
                raise DedalePreparationError(
                    "label accounting does not cover the selected corpus exactly"
                )
    except Exception:
        out_labels.unlink(missing_ok=True)
        raise

    return {
        "status": "PASS",
        "detection_rules_executed": False,
        "window_start": start_dt.isoformat(),
        "window_end": end_dt.isoformat(),
        "selected_events": malicious + ignored + benign,
        "malicious_class_1": malicious,
        "ignored_class_2": ignored,
        "benign_complement": benign,
        "labels_sha256": _sha256_file(out_labels),
    }


def parser() -> argparse.ArgumentParser:
    ap = argparse.ArgumentParser(
        description="Prepare DEDALE Winlogbeat external-holdout material."
    )
    sub = ap.add_subparsers(dest="command", required=True)

    normalize = sub.add_parser(
        "normalize",
        help="Normalize the full Winlogbeat corpus without reading labels.",
    )
    normalize.add_argument("--winlogbeat-root", required=True)
    normalize.add_argument("--out-corpus", required=True)
    normalize.add_argument("--out-identity-map", required=True)
    normalize.add_argument("--start", required=True)
    normalize.add_argument("--end", required=True)

    labels = sub.add_parser(
        "bind-labels",
        help="Bind DEDALE class-1/class-2 labels after evaluator indexing.",
    )
    labels.add_argument("--index", required=True)
    labels.add_argument("--identity-map", required=True)
    labels.add_argument("--winlogbeat-labels-dir", required=True)
    labels.add_argument("--out-labels", required=True)
    labels.add_argument("--start", required=True)
    labels.add_argument("--end", required=True)

    return ap


def main(argv: list[str] | None = None) -> int:
    args = parser().parse_args(argv)
    try:
        if args.command == "normalize":
            result = normalize_corpus(
                winlogbeat_root=Path(args.winlogbeat_root),
                out_corpus=Path(args.out_corpus),
                out_identity_map=Path(args.out_identity_map),
                start=args.start,
                end=args.end,
            )
        else:
            result = bind_labels(
                evaluator_index=Path(args.index),
                identity_map=Path(args.identity_map),
                winlogbeat_labels_dir=Path(args.winlogbeat_labels_dir),
                out_labels=Path(args.out_labels),
                start=args.start,
                end=args.end,
            )
        print(json.dumps(result, indent=2, sort_keys=True))
        return 0
    except DedalePreparationError as exc:
        print(f"P2-37 DEDALE PREPARATION ERROR: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
