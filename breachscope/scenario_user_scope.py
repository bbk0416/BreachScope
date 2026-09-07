"""User-aware scenario evidence scoping for P2-07J/P2-07K/P2-07L.

P0-05 isolates scenario evidence by host/session. P2-07I introduced bounded
``activity`` chains keyed by host + user, so scenario inference must preserve
that user boundary instead of merging different users back together solely
because they share a host. P2-07K also enforces that Windows session/logon IDs
are host-local identifiers and must never correlate evidence across hosts.
P2-07L aligns scenario session identity with the correlator: explicit
``SessionId``/``session_id``/``TargetLogonId`` or canonical session identity
is authoritative; ``SubjectLogonId`` and ambiguous generic ``LogonId`` values
must not create cross-session bridges.
"""
from __future__ import annotations

import hashlib
from collections.abc import Mapping

from .utils import get_event_key


def _scalar(value):
    if isinstance(value, (list, tuple, set)):
        for item in value:
            scalar = _scalar(item)
            if scalar not in (None, ""):
                return scalar
        return None
    return value


def _norm(value):
    value = _scalar(value)
    if value is None:
        return None
    text = str(value).strip()
    return text.casefold() if text else None


def scope(obj, _depth=0, _seen=None):
    """Return normalized host/user/authoritative-session evidence."""
    empty = {"hosts": set(), "users": set(), "sessions": set()}
    if obj is None or _depth > 4:
        return empty

    if _seen is None:
        _seen = set()

    oid = id(obj)
    if oid in _seen:
        return empty
    _seen.add(oid)

    hosts = set()
    users = set()
    sessions = set()

    def add_host(value):
        value = _norm(value)
        if value:
            hosts.add(value)

    def add_user(value):
        value = _norm(value)
        if value:
            users.add(value)

    def add_session(value):
        value = _norm(value)
        if value:
            sessions.add(value)

    if isinstance(obj, Mapping):
        items = list(obj.items())
    elif isinstance(obj, (str, bytes, int, float, bool)):
        items = []
    else:
        try:
            items = list(vars(obj).items())
        except (TypeError, AttributeError):
            items = []

    for key, value in items:
        lname = str(key).casefold()

        if lname in {"host", "hostname", "computer", "computername"}:
            if isinstance(value, Mapping):
                add_host(
                    value.get("name")
                    or value.get("hostname")
                    or value.get("computer")
                )
            else:
                add_host(value)
        elif lname in {"user", "username"}:
            if isinstance(value, Mapping):
                add_user(
                    value.get("name")
                    or value.get("username")
                    or value.get("user")
                )
            else:
                add_user(value)
        elif lname in {
            "session_id",
            "sessionid",
            "targetlogonid",
        }:
            if isinstance(value, Mapping):
                add_session(
                    value.get("id")
                    or value.get("session_id")
                )
            else:
                add_session(value)

        if lname == "canonical" and isinstance(value, Mapping):
            host_obj = value.get("host")
            if isinstance(host_obj, Mapping):
                add_host(host_obj.get("name"))
            user_obj = value.get("user")
            if isinstance(user_obj, Mapping):
                add_user(user_obj.get("name") or user_obj.get("username"))
            session_obj = value.get("session")
            if isinstance(session_obj, Mapping):
                add_session(session_obj.get("id"))

        if (
            lname
            in {
                "event",
                "events",
                "evidence",
                "finding",
                "findings",
                "raw",
                "canonical",
                "members",
                "items",
            }
            or isinstance(value, (list, tuple, set, dict))
        ):
            children = value if isinstance(value, (list, tuple, set)) else [value]
            for child in children:
                nested = scope(child, _depth + 1, _seen)
                hosts.update(nested["hosts"])
                users.update(nested["users"])
                sessions.update(nested["sessions"])

    return {"hosts": hosts, "users": users, "sessions": sessions}


def related(left, right):
    """Relate evidence without crossing host-local session or user boundaries."""
    left_sessions = left["sessions"]
    right_sessions = right["sessions"]
    left_hosts = left["hosts"]
    right_hosts = right["hosts"]

    if left_sessions and right_sessions:
        if not (left_sessions & right_sessions):
            return False
        # Windows LogonId/SessionId values are host-local. A matching numeric
        # value without a matching host must not join evidence components.
        return bool(left_hosts and right_hosts and left_hosts & right_hosts)

    left_users = left["users"]
    right_users = right["users"]

    # Once either side carries user identity, both host and user must agree.
    # A host-only chain is deliberately not allowed to bridge Alice and Bob.
    if left_users or right_users:
        if not (left_users and right_users and left_hosts and right_hosts):
            return False
        return bool(left_hosts & right_hosts) and bool(left_users & right_users)

    if left_hosts and right_hosts:
        return bool(left_hosts & right_hosts)

    return False


def partition_chains(chains):
    chains = list(chains or [])
    if len(chains) <= 1:
        return [chains] if chains else []

    scopes = [scope(chain) for chain in chains]
    parent = list(range(len(chains)))

    def find(index):
        while parent[index] != index:
            parent[index] = parent[parent[index]]
            index = parent[index]
        return index

    def union(a, b):
        ra, rb = find(a), find(b)
        if ra != rb:
            parent[rb] = ra

    for i in range(len(chains)):
        for j in range(i + 1, len(chains)):
            if related(scopes[i], scopes[j]):
                union(i, j)

    groups = {}
    for index, chain in enumerate(chains):
        groups.setdefault(find(index), []).append(chain)

    return list(groups.values())


def component_scope(chains):
    merged = {"hosts": set(), "users": set(), "sessions": set()}
    for chain in chains:
        chain_scope = scope(chain)
        merged["hosts"].update(chain_scope["hosts"])
        merged["users"].update(chain_scope["users"])
        merged["sessions"].update(chain_scope["sessions"])
    return merged


def filter_findings(findings, component):
    selected = []
    for finding in findings or []:
        finding_scope = scope(finding)

        if finding_scope["sessions"] and component["sessions"]:
            if (
                finding_scope["sessions"] & component["sessions"]
                and finding_scope["hosts"]
                and component["hosts"]
                and finding_scope["hosts"] & component["hosts"]
            ):
                selected.append(finding)
            continue

        if finding_scope["users"] or component["users"]:
            if (
                finding_scope["users"]
                and component["users"]
                and finding_scope["hosts"]
                and component["hosts"]
                and finding_scope["users"] & component["users"]
                and finding_scope["hosts"] & component["hosts"]
            ):
                selected.append(finding)
            continue

        if finding_scope["hosts"] and component["hosts"]:
            if finding_scope["hosts"] & component["hosts"]:
                selected.append(finding)

    return selected


def component_namespace(chains):
    component = component_scope(chains)
    identity_parts = []

    for host in sorted(component["hosts"]):
        identity_parts.append(f"host:{host}")
    for user in sorted(component["users"]):
        identity_parts.append(f"user:{user}")
    for session in sorted(component["sessions"]):
        identity_parts.append(f"session:{session}")

    for chain in chains or []:
        identity_parts.append(f"chain_type:{getattr(chain, 'chain_type', '')}")
        for event in getattr(chain, "events", None) or []:
            identity_parts.append(f"event:{get_event_key(event)}")

    if not identity_parts:
        identity_parts.append("empty-component")

    payload = "\n".join(sorted(set(identity_parts)))
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()[:16]


def install(target_module):
    """Install the P2-07J/P2-07K/P2-07L scope functions into scenario."""
    target_module._bs_p005_scope = scope
    target_module._bs_p005_related = related
    target_module._bs_p005_partition_chains = partition_chains
    target_module._bs_p005_component_scope = component_scope
    target_module._bs_p005_filter_findings = filter_findings
    target_module._bs_p206b_component_namespace = component_namespace


# BREACHSCOPE_P2_07L_AUTHORITATIVE_SESSION_SCOPE_V1
