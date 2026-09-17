"""Evidence-backed cross-host remote execution correlation."""
from __future__ import annotations

import bisect
import re
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Iterable, List, Optional

from .schemas import Event
from .utils import get_event_identity_key, parse_timestamp

_REMOTE_WINDOW = timedelta(minutes=2)
_REMOTE_BACKWARD_SKEW = timedelta(seconds=5)
_REMOTE_SERVICE_DEFINITION_LOOKBACK = timedelta(minutes=30)
_REMOTE_LOGON_TYPES = {"3"}
_REMOTE_SOURCE_EVENT_IDS = {"1", "4104", "4688"}
_SERVICE_EVENT_IDS = {"7045", "4697"}
_PROCESS_EVENT_IDS = {"1", "4688"}
_COMPUTERNAME_RE = re.compile(
    r"(?i)-computername\s+(?:['\"])?([A-Za-z0-9_.-]+)"
)
_PSEXEC_RE = re.compile(
    r"(?i)\bpsexec(?:64)?(?:\.exe)?\b[^\r\n]*?\\\\([A-Za-z0-9_.-]+)"
)
_REMOTE_PS_RE = re.compile(
    r"(?i)\b(?:invoke-command|enter-pssession|new-pssession)\b"
)
_REMOTE_SC_RE = re.compile(
    r'(?i)\bsc(?:\.exe)?\b["]?\s+\\\\(?P<target>[A-Za-z0-9_.-]+)'
    r'\s+(?P<operation>create|start)\s+'
    r'(?:"(?P<quoted>[^"\r\n]+)"|(?P<bare>[^\s"]+))'
)


@dataclass(frozen=True)
class RemoteExecutionMatch:
    events: List[Event]
    source_host: str
    target_host: str
    method: str
    operation: str = ""
    service_name: str = ""


@dataclass(frozen=True)
class _RemoteSourceTarget:
    method: str
    target: str
    operation: str = ""
    service_name: str = ""

def _norm_host(value: object) -> str:
    return str(value or "").strip().rstrip(".").casefold()


def _host_aliases(value: object) -> set[str]:
    full = _norm_host(value)
    if not full:
        return set()
    short = full.split(".", 1)[0]
    return {full, short}


def _account_leaf(value: object) -> str:
    text = str(value or "").strip().casefold()
    if not text:
        return ""
    if "\\" in text:
        text = text.rsplit("\\", 1)[-1]
    if "/" in text:
        text = text.rsplit("/", 1)[-1]
    if "@" in text:
        text = text.split("@", 1)[0]
    return text


def _iter_mappings(value: object) -> Iterable[dict]:
    if not isinstance(value, dict):
        return
    stack = [value]
    seen: set[int] = set()
    while stack:
        current = stack.pop()
        marker = id(current)
        if marker in seen:
            continue
        seen.add(marker)
        yield current
        stack.extend(v for v in current.values() if isinstance(v, dict))

def _raw_values(event: Event, *names: str) -> List[str]:
    wanted = {name.casefold() for name in names}
    values: List[str] = []
    for mapping in _iter_mappings(event.raw or {}):
        for key, value in mapping.items():
            if str(key).casefold() not in wanted:
                continue
            if isinstance(value, (str, int, float)) and str(value).strip():
                values.append(str(value).strip())
    return values


def _first_raw(event: Event, *names: str) -> str:
    values = _raw_values(event, *names)
    return values[0] if values else ""


def _source_texts(event: Event) -> List[str]:
    values: List[str] = []
    if event.command_line:
        values.append(str(event.command_line))
    values.extend(_raw_values(event, "CommandLine", "ProcessCommandLine"))
    if str(event.event_id or "") == "4104":
        values.extend(_raw_values(event, "ScriptBlockText"))
    return list(dict.fromkeys(value for value in values if value.strip()))


def _source_targets(event: Event) -> List[_RemoteSourceTarget]:
    if str(event.event_id or "") not in _REMOTE_SOURCE_EVENT_IDS:
        return []
    result: List[_RemoteSourceTarget] = []
    for text in _source_texts(event):
        if _REMOTE_PS_RE.search(text):
            for match in _COMPUTERNAME_RE.finditer(text):
                result.append(_RemoteSourceTarget("powershell", match.group(1)))
        for match in _PSEXEC_RE.finditer(text):
            result.append(_RemoteSourceTarget("psexec", match.group(1)))
        for match in _REMOTE_SC_RE.finditer(text):
            service_name = match.group("quoted") or match.group("bare") or ""
            result.append(_RemoteSourceTarget(
                "scm", match.group("target"), match.group("operation").casefold(), service_name
            ))
    return list(dict.fromkeys(result))

def _event_account(event: Event) -> str:
    if str(event.event_id or "") == "4624":
        return _account_leaf(
            _first_raw(event, "TargetUserName", "TargetUser", "AccountName")
            or event.user
        )
    return _account_leaf(
        event.user
        or _first_raw(event, "User", "SubjectUserName", "TargetUserName", "AccountName")
    )


def _is_remote_logon(event: Event, source: Event) -> bool:
    if str(event.event_id or "") != "4624":
        return False
    if _first_raw(event, "LogonType") not in _REMOTE_LOGON_TYPES:
        return False
    source_user = _event_account(source)
    target_user = _event_account(event)
    if source_user and target_user and source_user != target_user:
        return False
    return True


def _is_psexesvc_service(event: Event) -> bool:
    if str(event.event_id or "") not in _SERVICE_EVENT_IDS:
        return False
    values = _raw_values(event, "ServiceName", "ServiceFileName", "ImagePath")
    return any("psexesvc" in value.casefold() for value in values)


def _is_psexesvc_process(event: Event) -> bool:
    if str(event.event_id or "") not in _PROCESS_EVENT_IDS:
        return False
    texts = []
    if event.command_line:
        texts.append(str(event.command_line))
    texts.extend(
        _raw_values(event, "CommandLine", "ProcessCommandLine", "Image", "NewProcessName")
    )
    return any("psexesvc" in text.casefold() for text in texts)


def _is_winrm_process(event: Event) -> bool:
    if str(event.event_id or "") not in _PROCESS_EVENT_IDS:
        return False
    texts = []
    if event.command_line:
        texts.append(str(event.command_line))
    texts.extend(_raw_values(event, "CommandLine", "Image", "NewProcessName"))
    return any("wsmprovhost.exe" in text.casefold() for text in texts)


def _norm_service_name(value: object) -> str:
    return " ".join(str(value or "").strip().strip("\"'").casefold().split())


def _service_definition_matches(event: Event, service_name: str) -> bool:
    if str(event.event_id or "") not in _SERVICE_EVENT_IDS:
        return False
    wanted = _norm_service_name(service_name)
    if not wanted:
        return False
    return any(
        _norm_service_name(value) == wanted
        for value in _raw_values(event, "ServiceName")
    )


def _service_file(event: Event) -> str:
    return _first_raw(event, "ServiceFileName", "ImagePath")

def _norm_command_text(value: object) -> str:
    text = str(value or "").strip().casefold()
    text = re.sub(r"\s+", " ", text)
    if len(text) >= 2 and text[0] == text[-1] == '"':
        text = text[1:-1].strip()
    return text


def _service_process_matches(event: Event, service_file: str) -> bool:
    if str(event.event_id or "") not in _PROCESS_EVENT_IDS:
        return False
    wanted = _norm_command_text(service_file)
    if not wanted:
        return False
    texts: List[str] = []
    if event.command_line:
        texts.append(str(event.command_line))
    texts.extend(_raw_values(event, "CommandLine", "ProcessCommandLine"))
    return any(_norm_command_text(text) == wanted for text in texts)


def _dedupe_events(events: Iterable[Event]) -> List[Event]:
    unique: List[Event] = []
    seen: set[str] = set()
    for event in events:
        key = get_event_identity_key(event)
        if key in seen:
            continue
        seen.add(key)
        unique.append(event)
    unique.sort(key=lambda event: parse_timestamp(event.timestamp) or datetime.min)
    return unique

def find_remote_execution_matches(events: List[Event]) -> List[RemoteExecutionMatch]:
    """Return explicit source->target remote execution evidence pairs."""
    timed: List[tuple[datetime, Event]] = []
    hosts: dict[str, List[tuple[datetime, Event]]] = {}
    aliases: dict[str, set[str]] = {}
    display: dict[str, str] = {}

    for event in events:
        timestamp = parse_timestamp(event.timestamp)
        host = _norm_host(event.host)
        if timestamp is None or not host:
            continue
        timed.append((timestamp, event))
        hosts.setdefault(host, []).append((timestamp, event))
        display.setdefault(host, str(event.host))
        for alias in _host_aliases(event.host):
            aliases.setdefault(alias, set()).add(host)

    for entries in hosts.values():
        entries.sort(key=lambda item: item[0])
    timed.sort(key=lambda item: item[0])

    def resolve(token: str) -> Optional[str]:
        candidates = aliases.get(_norm_host(token), set())
        return next(iter(candidates)) if len(candidates) == 1 else None

    matches: List[RemoteExecutionMatch] = []
    seen: set[tuple] = set()
    seen_operations: set[tuple] = set()

    for source_ts, source in timed:
        source_host = _norm_host(source.host)
        for candidate in _source_targets(source):
            method = candidate.method
            target_token = candidate.target
            target_host = resolve(target_token)
            if not target_host or target_host == source_host:
                continue
            marker = (
                get_event_identity_key(source), target_host, method,
                candidate.operation, _norm_service_name(candidate.service_name),
            )
            if marker in seen:
                continue
            seen.add(marker)

            entries = hosts.get(target_host, [])
            timestamps = [item[0] for item in entries]
            start = bisect.bisect_left(timestamps, source_ts - _REMOTE_BACKWARD_SKEW)
            end = bisect.bisect_right(timestamps, source_ts + _REMOTE_WINDOW)
            window = entries[start:end]

            auth = next(
                (event for _, event in window if _is_remote_logon(event, source)),
                None,
            )
            evidence: List[Event] = []

            if method == "powershell":
                winrm_process = next(
                    (event for _, event in window if _is_winrm_process(event)),
                    None,
                )
                if auth is None or winrm_process is None:
                    continue
                evidence.extend([auth, winrm_process])

            if method == "psexec":
                psexec_service = next(
                    (event for _, event in window if _is_psexesvc_service(event)),
                    None,
                )
                psexec_process = next(
                    (event for _, event in window if _is_psexesvc_process(event)),
                    None,
                )
                if auth is None or (psexec_service is None and psexec_process is None):
                    continue
                evidence.append(auth)
                if psexec_service is not None:
                    evidence.append(psexec_service)
                if psexec_process is not None:
                    evidence.append(psexec_process)

            if method == "scm":
                service_name = candidate.service_name
                if candidate.operation == "create":
                    service_event = next(
                        (event for _, event in window if _service_definition_matches(event, service_name)),
                        None,
                    )
                    if service_event is None:
                        continue
                    evidence.append(service_event)
                elif candidate.operation == "start":
                    definition_start = bisect.bisect_left(
                        timestamps, source_ts - _REMOTE_SERVICE_DEFINITION_LOOKBACK
                    )
                    definition_end = bisect.bisect_right(
                        timestamps, source_ts + _REMOTE_BACKWARD_SKEW
                    )
                    definitions = [
                        event for _, event in entries[definition_start:definition_end]
                        if _service_definition_matches(event, service_name) and _service_file(event)
                    ]
                    if not definitions:
                        continue
                    service_event = definitions[-1]
                    service_file = _service_file(service_event)
                    process_event = next(
                        (event for _, event in window if _service_process_matches(event, service_file)),
                        None,
                    )
                    if process_event is None:
                        continue
                    evidence.extend([service_event, process_event])
                else:
                    continue

            operation = (
                source_host, target_host, method, candidate.operation,
                _norm_service_name(candidate.service_name),
                tuple(get_event_identity_key(event) for event in evidence),
            )
            if operation in seen_operations:
                continue
            seen_operations.add(operation)

            chain_events = _dedupe_events([source, *evidence])
            if len({_norm_host(event.host) for event in chain_events}) < 2:
                continue

            matches.append(
                RemoteExecutionMatch(
                    events=chain_events,
                    source_host=str(source.host),
                    target_host=display.get(target_host, target_token),
                    method=method,
                    operation=candidate.operation,
                    service_name=candidate.service_name,
                )
            )

    return matches
