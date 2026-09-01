"""Optional Hayabusa detection backend adapter.

P0-10 contract:
- Hayabusa remains an external backend; its rules are not reinterpreted.
- Input is EVTX (single file or a directory containing .evtx).
- Output is JSONL via dfir-timeline using the super-verbose profile.
- Only alert levels low/med/high/crit become BreachScope Findings by default.
- Original Hayabusa records are preserved under Event.raw["hayabusa"].
"""
from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
import tempfile
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional

from .schemas import Event, Finding

HAYABUSA_MIN_MAJOR = 4
_ATTACK_RE = re.compile(r"\bT\d{4}(?:\.\d{3})?\b", re.IGNORECASE)


class HayabusaError(RuntimeError):
    """Raised when the optional Hayabusa backend was explicitly requested and fails."""


def _truthy(value: str | None) -> bool:
    return str(value or "").strip().casefold() in {"1", "true", "yes", "on"}


def hayabusa_enabled() -> bool:
    return _truthy(os.getenv("BS_HAYABUSA_ENABLED"))


def _runtime_roots() -> List[Path]:
    roots: List[Path] = []
    local = os.getenv("LOCALAPPDATA")
    if local:
        roots.append(Path(local) / "BreachScope" / "tools" / "hayabusa")
    roots.append(Path.home() / ".breachscope" / "tools" / "hayabusa")
    return roots


def resolve_hayabusa_executable(explicit: str | Path | None = None) -> Path:
    candidates: List[Path] = []

    if explicit:
        candidates.append(Path(explicit).expanduser())

    env_path = os.getenv("BS_HAYABUSA_EXE")
    if env_path:
        candidates.append(Path(env_path).expanduser())

    for name in ("hayabusa.exe", "hayabusa"):
        found = shutil.which(name)
        if found:
            candidates.append(Path(found))

    for root in _runtime_roots():
        if not root.exists():
            continue
        for candidate in sorted(root.rglob("hayabusa*.exe"), reverse=True):
            if "live-response" not in candidate.name.casefold():
                candidates.append(candidate)

    seen = set()
    for candidate in candidates:
        try:
            candidate = candidate.resolve()
        except OSError:
            pass
        key = str(candidate).casefold()
        if key in seen:
            continue
        seen.add(key)
        if candidate.is_file():
            return candidate

    raise HayabusaError(
        "Hayabusa executable not found. Set BS_HAYABUSA_EXE or install the "
        "Windows x64 release into the BreachScope runtime tools directory."
    )


def _evtx_mode(input_path: Path) -> tuple[str, Path] | None:
    input_path = Path(input_path)
    if input_path.is_file() and input_path.suffix.casefold() == ".evtx":
        return "-f", input_path
    if input_path.is_dir() and any(input_path.rglob("*.evtx")):
        return "-d", input_path
    return None


def build_hayabusa_command(
    executable: Path,
    input_path: Path,
    output_path: Path,
) -> List[str]:
    mode = _evtx_mode(Path(input_path))
    if mode is None:
        raise HayabusaError(f"No EVTX input found: {input_path}")

    input_flag, evtx_path = mode
    return [
        str(executable),
        "dfir-timeline",
        input_flag,
        str(evtx_path),
        "-t",
        "jsonl",
        "-o",
        str(output_path),
        "-w",
        "-q",
        "-N",
        "-O",
        "-p",
        "super-verbose",
        "-C",
    ]


def _run_command(command: List[str], *, cwd: Path, timeout: int) -> subprocess.CompletedProcess:
    return subprocess.run(
        command,
        cwd=str(cwd),
        capture_output=True,
        text=True,
        timeout=timeout,
        check=False,
    )


def _severity(level: Any) -> str | None:
    value = str(level or "").strip().casefold()
    mapping = {
        "crit": "critical",
        "critical": "critical",
        "high": "high",
        "med": "medium",
        "medium": "medium",
        "low": "low",
    }
    return mapping.get(value)


def _first_scalar(mapping: Dict[str, Any], keys: Iterable[str]) -> Optional[str]:
    for key in keys:
        value = mapping.get(key)
        if value is None:
            continue
        if isinstance(value, (str, int, float, bool)):
            text = str(value).strip()
            if text:
                return text
    return None


def _mitre_technique(record: Dict[str, Any]) -> Optional[str]:
    candidates = [
        record.get("MitreTags"),
        record.get("MitreTechniques"),
        record.get("Tags"),
    ]
    for value in candidates:
        if value is None:
            continue
        if isinstance(value, list):
            text = " ".join(str(v) for v in value)
        else:
            text = str(value)
        match = _ATTACK_RE.search(text)
        if match:
            return match.group(0).upper()
    return None


def _matched_context(details: Dict[str, Any]) -> str:
    if not details:
        return ""
    text = json.dumps(details, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
    return text[:2000]


def finding_from_hayabusa_record(
    record: Dict[str, Any],
    *,
    include_informational: bool = False,
) -> Finding | None:
    if not isinstance(record, dict):
        raise HayabusaError("Hayabusa JSONL record must be an object")

    raw_level = str(record.get("Level") or "").strip()
    severity = _severity(raw_level)
    if severity is None:
        if include_informational and raw_level.casefold() in {"info", "informational"}:
            severity = "low"
        else:
            return None

    title = str(record.get("RuleTitle") or "").strip()
    if not title:
        return None

    details = record.get("Details")
    if not isinstance(details, dict):
        details = {}

    event_id_value = record.get("EventID")
    event_id = None if event_id_value is None else str(event_id_value)

    command_line = _first_scalar(
        details,
        ("CmdLine", "CommandLine", "Commandline", "Command", "Cmd"),
    )
    user = _first_scalar(
        details,
        ("User", "TgtUser", "TargetUserName", "AccountName", "SrcUser"),
    )
    matched_value = command_line or _first_scalar(
        details,
        ("Path", "Proc", "Image", "TargetFilename", "TgtIP", "SrcIP"),
    )

    source = str(
        record.get("Provider")
        or record.get("Channel")
        or "hayabusa"
    )

    event = Event(
        timestamp=str(record.get("Timestamp") or ""),
        host=str(record.get("Computer") or ""),
        source=source,
        event_id=event_id,
        level=raw_level or severity,
        user=user,
        command_line=command_line,
        raw={
            "detection_backend": "hayabusa",
            "hayabusa": record,
        },
    )

    rule_id = str(record.get("RuleID") or "").strip()
    if not rule_id:
        normalized = re.sub(r"[^a-z0-9]+", "-", title.casefold()).strip("-")
        rule_id = f"hayabusa:{normalized or 'detection'}"

    return Finding(
        rule_id=rule_id,
        rule_name=title,
        severity=severity,
        mitre_technique=_mitre_technique(record),
        event=event,
        matched_value=matched_value,
        matched_context=_matched_context(details) or None,
    )


def parse_hayabusa_jsonl(
    path: Path,
    *,
    include_informational: bool = False,
) -> List[Finding]:
    findings: List[Finding] = []
    seen = set()

    with Path(path).open("r", encoding="utf-8-sig") as handle:
        for line_number, line in enumerate(handle, start=1):
            line = line.strip()
            if not line:
                continue
            try:
                record = json.loads(line)
            except json.JSONDecodeError as exc:
                raise HayabusaError(
                    f"Invalid Hayabusa JSONL at line {line_number}: {exc}"
                ) from exc

            finding = finding_from_hayabusa_record(
                record,
                include_informational=include_informational,
            )
            if finding is None:
                continue

            hb = finding.event.raw.get("hayabusa", {})
            key = (
                finding.rule_id,
                finding.event.timestamp,
                finding.event.host,
                finding.event.event_id,
                str(hb.get("RecordID") or ""),
            )
            if key in seen:
                continue
            seen.add(key)
            findings.append(finding)

    return findings


def run_hayabusa_findings(
    input_path: Path,
    *,
    executable: str | Path | None = None,
    timeout: int | None = None,
    include_informational: bool = False,
) -> List[Finding]:
    input_path = Path(input_path)
    if _evtx_mode(input_path) is None:
        # Optional backend is irrelevant to JSONL-only/demo inputs.
        return []

    exe = resolve_hayabusa_executable(executable)
    timeout = timeout or int(os.getenv("BS_HAYABUSA_TIMEOUT", "600") or "600")

    with tempfile.TemporaryDirectory(prefix="breachscope_hayabusa_") as temp:
        output = Path(temp) / "timeline.jsonl"
        command = build_hayabusa_command(exe, input_path, output)
        result = _run_command(command, cwd=exe.parent, timeout=timeout)

        if result.returncode != 0:
            stderr = (result.stderr or "").strip()
            stdout = (result.stdout or "").strip()
            detail = stderr or stdout or f"exit {result.returncode}"
            raise HayabusaError(f"Hayabusa dfir-timeline failed: {detail[:2000]}")

        if not output.exists():
            raise HayabusaError("Hayabusa completed without creating JSONL output")

        return parse_hayabusa_jsonl(
            output,
            include_informational=include_informational,
        )
