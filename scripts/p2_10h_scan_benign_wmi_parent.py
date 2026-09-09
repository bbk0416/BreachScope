#!/usr/bin/env python3
from __future__ import annotations

import hashlib
import json
import tarfile
import urllib.request
from datetime import datetime, timezone
from pathlib import Path

from Evtx.Evtx import Evtx

from breachscope.ingest import _extract_from_xml

ARCHIVE_URL = "https://github.com/NextronSystems/evtx-baseline/releases/download/v0.8.4/win10-client.tgz"
ARCHIVE_SHA256 = "d48f1b328d48db6c6dfaa9b6e232dbb454d93e833c6e1248efc0faf690b6808e"
WINDOW_SECONDS = 300.0


def sha256(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def parse_time(value: object) -> datetime | None:
    text = str(value or "").strip()
    if not text:
        return None
    try:
        dt = datetime.fromisoformat(text.replace("Z", "+00:00"))
    except ValueError:
        return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt


def hex_pid(value: object) -> int | None:
    text = str(value or "").strip()
    if not text:
        return None
    try:
        return int(text, 16) if text.lower().startswith("0x") else int(text)
    except ValueError:
        return None


def is_security_4688(row: dict) -> bool:
    return (
        str(row.get("source") or "").casefold() == "microsoft-windows-security-auditing"
        and str(row.get("event_id") or "") == "4688"
    )


def main() -> int:
    root = Path("out/p2_10h_wmi_benign")
    root.mkdir(parents=True, exist_ok=True)
    archive = root / "win10-client.tgz"
    extracted = root / "corpus"

    if not archive.exists():
        urllib.request.urlretrieve(ARCHIVE_URL, archive)
    digest = sha256(archive)
    print("SHA256=", digest)
    if digest != ARCHIVE_SHA256:
        raise SystemExit(f"archive SHA mismatch: {digest}")

    if not extracted.exists():
        extracted.mkdir(parents=True)
        with tarfile.open(archive, "r:gz") as tf:
            tf.extractall(extracted)

    files = sorted(extracted.rglob("*.evtx"))
    counters = {
        "evtx_files_total": len(files),
        "evtx_files_scanned_non_sysmon": 0,
        "sysmon_files_skipped": 0,
        "non_sysmon_records": 0,
        "security_4688": 0,
        "parent_pid_resolved_within_300s": 0,
        "wmiprvse_parent_children_broad": 0,
        "wmiprvse_parent_children_wbem": 0,
        "parse_errors": 0,
        "timestamp_parse_errors_4688": 0,
    }
    matches: list[dict] = []

    for fp in files:
        recent: dict[tuple[str, int], tuple[datetime, str]] = {}
        try:
            with Evtx(str(fp)) as log:
                records = iter(log.records())
                try:
                    first = next(records)
                except StopIteration:
                    counters["evtx_files_scanned_non_sysmon"] += 1
                    continue

                try:
                    first_row = _extract_from_xml(first.xml()) or {}
                except Exception:
                    counters["parse_errors"] += 1
                    first_row = {}

                if str(first_row.get("source") or "").casefold() == "microsoft-windows-sysmon":
                    counters["sysmon_files_skipped"] += 1
                    continue

                counters["evtx_files_scanned_non_sysmon"] += 1
                rows = [first_row]
                for record in records:
                    try:
                        rows.append(_extract_from_xml(record.xml()) or {})
                    except Exception:
                        counters["parse_errors"] += 1

                for row in rows:
                    if not row:
                        continue
                    counters["non_sysmon_records"] += 1
                    if not is_security_4688(row):
                        continue
                    counters["security_4688"] += 1
                    raw = row.get("raw") if isinstance(row.get("raw"), dict) else {}
                    ts = parse_time(row.get("timestamp"))
                    if ts is None:
                        counters["timestamp_parse_errors_4688"] += 1
                        continue
                    host = str(row.get("host") or "").casefold()
                    parent_pid = hex_pid(raw.get("ProcessId"))
                    new_pid = hex_pid(raw.get("NewProcessId"))
                    new_name = str(raw.get("NewProcessName") or "")

                    if parent_pid is not None:
                        parent = recent.get((host, parent_pid))
                        if parent is not None:
                            parent_ts, parent_name = parent
                            delta = (ts - parent_ts).total_seconds()
                            if 0.0 <= delta <= WINDOW_SECONDS:
                                counters["parent_pid_resolved_within_300s"] += 1
                                low_parent = parent_name.casefold()
                                broad = low_parent.endswith("\\wmiprvse.exe")
                                strict = low_parent.endswith("\\wbem\\wmiprvse.exe")
                                if broad:
                                    counters["wmiprvse_parent_children_broad"] += 1
                                if strict:
                                    counters["wmiprvse_parent_children_wbem"] += 1
                                if broad:
                                    matches.append({
                                        "file": fp.relative_to(extracted).as_posix(),
                                        "timestamp": str(row.get("timestamp") or ""),
                                        "host": str(row.get("host") or ""),
                                        "delta_seconds": delta,
                                        "parent_pid": parent_pid,
                                        "parent_process": parent_name,
                                        "child_process": new_name,
                                        "child_subject_sid": str(raw.get("SubjectUserSid") or ""),
                                        "child_subject_user": str(raw.get("SubjectUserName") or ""),
                                    })

                    if new_pid is not None and new_name:
                        recent[(host, new_pid)] = (ts, new_name)
        except Exception as exc:
            counters["parse_errors"] += 1
            print("FILE_ERROR=", fp, repr(exc))

    for key, value in counters.items():
        print(f"{key.upper()}={value}")
    print("MATCHES=" + json.dumps(matches, ensure_ascii=False, sort_keys=True))

    if counters["evtx_files_total"] != 352:
        raise SystemExit("expected 352 EVTX files")
    if counters["non_sysmon_records"] != 34423:
        raise SystemExit(f"expected 34423 non-Sysmon records, got {counters['non_sysmon_records']}")
    if counters["parse_errors"] != 0 or counters["timestamp_parse_errors_4688"] != 0:
        raise SystemExit("scan contained parse errors")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
