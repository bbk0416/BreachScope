from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import os
import sys
import time
import zipfile
from pathlib import Path
from typing import Any, Mapping

REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

import yaml

SCHEMA = "breachscope.p2_35f_socbed_source_oracle.v1"
ANALYSIS_ID = "p2-35f-socbed-source-derived-oracle-v1"


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def write_json(path: Path, payload: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(path.suffix + ".tmp")
    tmp.write_text(
        json.dumps(payload, indent=2, ensure_ascii=False) + "\n",
        encoding="utf-8",
        newline="\n",
    )
    os.replace(tmp, path)


def acquire_global_lock(lock_path: Path) -> None:
    lock_path.parent.mkdir(parents=True, exist_ok=True)
    try:
        fd = os.open(str(lock_path), os.O_CREAT | os.O_EXCL | os.O_WRONLY)
    except FileExistsError as exc:
        raise RuntimeError(
            f"analysis id already permanently locked: {lock_path}"
        ) from exc
    try:
        os.write(
            fd,
            (
                json.dumps(
                    {
                        "analysis_id": ANALYSIS_ID,
                        "pid": os.getpid(),
                        "created_unix": time.time(),
                    }
                )
                + "\n"
            ).encode("utf-8"),
        )
    finally:
        os.close(fd)


def load_predecessor_runner(repo: Path, contract: Mapping[str, Any]):
    cfg = contract["predecessor_runner"]
    path = (repo / str(cfg["path"])).resolve()
    if sha256_file(path) != cfg["sha256"]:
        raise RuntimeError("P2-35E predecessor runner SHA mismatch")
    spec = importlib.util.spec_from_file_location("p2_35e_frozen_runner", path)
    if spec is None or spec.loader is None:
        raise RuntimeError("cannot load P2-35E predecessor runner")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _raw_value(event: Any, key: str) -> str:
    raw = getattr(event, "raw", None)
    if not isinstance(raw, Mapping):
        return ""
    wanted = key.casefold()
    for raw_key, value in raw.items():
        if str(raw_key).casefold() == wanted and value not in (None, ""):
            return str(value)
    nested = raw.get("event_data")
    if isinstance(nested, Mapping):
        for raw_key, value in nested.items():
            if str(raw_key).casefold() == wanted and value not in (None, ""):
                return str(value)
    return ""


def _event_key(event: Any) -> tuple[str, str, str, str, str]:
    return (
        str(getattr(event, "timestamp", "") or ""),
        str(getattr(event, "host", "") or ""),
        str(getattr(event, "source", "") or ""),
        str(getattr(event, "event_id", "") or ""),
        _raw_value(event, "event_record_id") or _raw_value(event, "RecordId"),
    )


def oracle_match(action: str, event: Any) -> bool:
    command_line = str(getattr(event, "command_line", "") or "").casefold()
    image = _raw_value(event, "Image").casefold()
    target_object = _raw_value(event, "TargetObject").casefold()
    details = _raw_value(event, "Details").casefold()
    event_id = str(getattr(event, "event_id", "") or "")

    if action == "misc_download_malware":
        return (
            "invoke-webrequest" in command_line
            and "http://172.18.1.1/meterpreter_bind_tcp.exe" in command_line
            and "c:\\windows\\meterpreter_bind_tcp.exe" in command_line
        )

    if action == "misc_set_autostart":
        registry_match = (
            "currentversion\\run" in target_object
            and (
                "meterpreter bind tcp" in target_object
                or "meterpreter_bind_tcp.exe" in details
            )
        )
        command_match = (
            "reg add" in command_line
            and "currentversion\\run" in command_line
            and "meterpreter_bind_tcp.exe" in command_line
        )
        return registry_match or command_match

    if action == "misc_execute_malware":
        return event_id == "1" and image.endswith("\\meterpreter_bind_tcp.exe")

    raise RuntimeError(f"unsupported oracle action: {action}")


def event_projection(event: Any) -> dict[str, Any]:
    return {
        "timestamp": str(getattr(event, "timestamp", "") or ""),
        "host": str(getattr(event, "host", "") or ""),
        "source": str(getattr(event, "source", "") or ""),
        "event_id": str(getattr(event, "event_id", "") or ""),
        "event_record_id": _raw_value(event, "event_record_id")
        or _raw_value(event, "RecordId"),
        "image": _raw_value(event, "Image"),
        "command_line": str(getattr(event, "command_line", "") or ""),
        "target_object": _raw_value(event, "TargetObject"),
        "details": _raw_value(event, "Details"),
    }


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Run preregistered P2-35F source-derived oracle audit."
    )
    parser.add_argument("--contract", required=True)
    parser.add_argument("--archive", required=True)
    parser.add_argument("--out-dir", required=True)
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    if sys.version_info[:2] != (3, 11):
        raise SystemExit("P2-35F requires Python 3.11")
    if sys.platform != "win32":
        raise SystemExit("P2-35F requires Windows")

    repo = REPO_ROOT
    script = Path(__file__).resolve()
    contract_path = Path(args.contract).resolve()
    archive_path = Path(args.archive).resolve()
    out_dir = Path(args.out_dir).resolve()

    contract = yaml.safe_load(contract_path.read_text(encoding="utf-8"))
    if contract["analysis_id"] != ANALYSIS_ID:
        raise RuntimeError("analysis id mismatch")
    runner_sha = sha256_file(script)
    if runner_sha != contract["runner"]["sha256"]:
        raise RuntimeError("runner SHA mismatch")

    predecessor = load_predecessor_runner(repo, contract)
    product = predecessor.verify_product(repo, contract)

    source = contract["source"]
    archive_cfg = source["dataset_archive"]
    if archive_path.stat().st_size != archive_cfg["size_bytes"]:
        raise RuntimeError("dataset archive size mismatch")
    archive_sha = sha256_file(archive_path)
    if archive_sha != archive_cfg["sha256"]:
        raise RuntimeError("dataset archive SHA256 mismatch")

    if out_dir.exists():
        raise RuntimeError("output directory already exists before canonical lock acquisition")

    global_lock_rel = Path(str(contract["runner"]["global_lock_file"]))
    if global_lock_rel.is_absolute() or ".." in global_lock_rel.parts:
        raise RuntimeError("global lock path must be repository-relative")
    global_lock_path = (repo / global_lock_rel).resolve()
    try:
        global_lock_path.relative_to(repo.resolve())
    except ValueError as exc:
        raise RuntimeError("global lock path escapes repository root") from exc

    acquire_global_lock(global_lock_path)
    out_dir.mkdir(parents=True, exist_ok=False)

    result_path = out_dir / contract["runner"]["result_file"]
    result: dict[str, Any] = {
        "schema": SCHEMA,
        "analysis_id": ANALYSIS_ID,
        "status": "started",
        "contract_sha256": sha256_file(contract_path),
        "runner_sha256": runner_sha,
        "predecessor_runner_sha256": contract["predecessor_runner"]["sha256"],
        "product": product,
        "source": {
            "archive_size_bytes": archive_path.stat().st_size,
            "archive_sha256": archive_sha,
        },
    }
    write_json(result_path, result)

    try:
        selected_cfg = source["selected_windows_member"]
        timing_cfg = source["timing_anchor_member"]
        with zipfile.ZipFile(archive_path, "r") as zf:
            selected_info = zf.getinfo(selected_cfg["path"])
            timing_info = zf.getinfo(timing_cfg["path"])
            if selected_info.file_size != selected_cfg["size_bytes"]:
                raise RuntimeError("selected Windows member size mismatch")
            if timing_info.file_size != timing_cfg["size_bytes"]:
                raise RuntimeError("timing anchor member size mismatch")
            selected_bytes = zf.read(selected_info)
            timing_bytes = zf.read(timing_info)

        selected_sha = sha256_bytes(selected_bytes)
        timing_sha = sha256_bytes(timing_bytes)
        if selected_sha != selected_cfg["sha256"]:
            raise RuntimeError("selected Windows member SHA256 mismatch")
        if timing_sha != timing_cfg["sha256"]:
            raise RuntimeError("timing anchor member SHA256 mismatch")

        timeline = predecessor.parse_attackconsole_timeline(
            timing_bytes.decode("utf-8", errors="strict"),
            list(contract["timeline"]["expected_attack_order"]),
        )
        windows = predecessor.build_step_windows(
            timeline,
            int(contract["timeline"]["maximum_step_window_seconds"]),
        )
        windows_by_attack = {row["attack"]: row for row in windows}

        raw_rows: list[dict[str, Any]] = []
        for line_no, line in enumerate(
            selected_bytes.decode("utf-8", errors="strict").splitlines(), 1
        ):
            if not line.strip():
                continue
            try:
                row = json.loads(line)
            except json.JSONDecodeError as exc:
                raise RuntimeError(
                    f"invalid selected JSONL at line {line_no}: {exc}"
                ) from exc
            if not isinstance(row, dict):
                raise RuntimeError(f"selected JSONL row {line_no} is not an object")
            raw_rows.append(row)

        adapted = [predecessor.adapt_winlogbeat_row(row) for row in raw_rows]

        from breachscope.normalizer import normalize
        from breachscope.rules import load_rules
        from breachscope.analyzer import apply_rules

        events = list(normalize(iter(adapted)))
        rules = load_rules(repo / "rules")
        findings = list(apply_rules(events, rules))

        finding_keys: dict[tuple[str, str, str, str, str], list[Any]] = {}
        for finding in findings:
            finding_keys.setdefault(_event_key(finding.event), []).append(finding)

        oracle_results: dict[str, Any] = {}
        for action, cfg in contract["oracle_actions"].items():
            if cfg["disposition"] != "EVALUATED_SOURCE_DERIVED_ORACLE":
                oracle_results[action] = {
                    "disposition": cfg["disposition"],
                    "reason": cfg["reason"],
                }
                continue

            window = windows_by_attack[action]
            oracle_events = []
            for event in events:
                ts = predecessor._parse_timestamp(event.timestamp)
                if not (window["start"] <= ts < window["end"]):
                    continue
                if oracle_match(action, event):
                    oracle_events.append(event)

            oracle_keys = {_event_key(event) for event in oracle_events}
            bound_findings = [
                finding
                for key in oracle_keys
                for finding in finding_keys.get(key, [])
            ]
            finding_rule_ids = sorted(
                {str(getattr(finding, "rule_id", "") or "") for finding in bound_findings}
            )
            finding_techniques = sorted(
                {
                    str(tech)
                    for finding in bound_findings
                    for tech in (
                        getattr(finding, "mitre_techniques", None)
                        or (
                            [getattr(finding, "mitre_technique")]
                            if getattr(finding, "mitre_technique", None)
                            else []
                        )
                    )
                }
            )

            oracle_results[action] = {
                "disposition": cfg["disposition"],
                "predicate_id": cfg["predicate_id"],
                "window_start": window["start_timestamp"],
                "window_end": window["end_timestamp"],
                "oracle_event_count": len(oracle_events),
                "oracle_event_finding_bound_count": sum(
                    1 for key in oracle_keys if key in finding_keys
                ),
                "finding_count_on_oracle_events": len(bound_findings),
                "finding_rule_ids_on_oracle_events": finding_rule_ids,
                "finding_techniques_on_oracle_events": finding_techniques,
                "action_observable_in_selected_source": bool(oracle_events),
                "any_finding_bound_to_oracle_event": bool(bound_findings),
                "oracle_events": [event_projection(event) for event in oracle_events],
            }

        evaluated = [
            row
            for row in oracle_results.values()
            if row["disposition"] == "EVALUATED_SOURCE_DERIVED_ORACLE"
        ]
        result.update(
            {
                "status": "completed",
                "source": {
                    **result["source"],
                    "selected_windows_member": {
                        "path": selected_cfg["path"],
                        "size_bytes": selected_info.file_size,
                        "sha256": selected_sha,
                    },
                    "timing_anchor_member": {
                        "path": timing_cfg["path"],
                        "size_bytes": timing_info.file_size,
                        "sha256": timing_sha,
                    },
                },
                "measurement": {
                    "raw_jsonl_rows": len(raw_rows),
                    "events": len(events),
                    "findings": len(findings),
                    "oracle_results": oracle_results,
                    "evaluated_action_count": len(evaluated),
                    "actions_with_oracle_telemetry": sum(
                        row["action_observable_in_selected_source"] for row in evaluated
                    ),
                    "actions_with_findings_bound_to_oracle_events": sum(
                        row["any_finding_bound_to_oracle_event"] for row in evaluated
                    ),
                    "oracle_event_count": sum(
                        row["oracle_event_count"] for row in evaluated
                    ),
                    "oracle_events_with_findings": sum(
                        row["oracle_event_finding_bound_count"] for row in evaluated
                    ),
                },
                "claim_boundary": dict(contract["claim_boundary"]),
            }
        )
        write_json(result_path, result)
        return 0
    except Exception as exc:
        result["status"] = "failed"
        result["exception"] = f"{type(exc).__name__}: {exc}"
        write_json(result_path, result)
        raise


if __name__ == "__main__":
    raise SystemExit(main())
