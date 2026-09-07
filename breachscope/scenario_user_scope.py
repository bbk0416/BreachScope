"""User-aware scenario evidence scoping for P2-07J/P2-07K/P2-07L/P2-07R/P2-07S/P2-07T/P2-07U.

P0-05 isolates scenario evidence by host/session. P2-07I introduced bounded
``activity`` chains keyed by host + user, so scenario inference must preserve
that user boundary instead of merging different users back together solely
because they share a host. P2-07K also enforces that Windows session/logon IDs
are host-local identifiers and must never correlate evidence across hosts.
P2-07L aligns scenario session identity with the correlator: explicit
``SessionId``/``session_id``/``TargetLogonId`` or canonical session identity
is authoritative; ``SubjectLogonId`` and ambiguous generic ``LogonId`` values
must not create cross-session bridges. P2-07R prevents a canonical session
that was derived only from one of those non-authoritative raw fields from
silently reintroducing the forbidden bridge. P2-07S keeps scenario session
validity aligned with the correlator so placeholder IDs such as ``0x0`` cannot
become cross-user evidence bridges. P2-07T canonicalizes equivalent hexadecimal
Windows session-ID spellings so scenario identity stays aligned with correlation.
P2-07U gives native ``TargetLogonId`` precedence over compatibility session
aliases in scenario scope, matching the correlator's P2-07Q contract.
"""
from __future__ import annotations

import hashlib
from collections.abc import Mapping

from .utils import get_event_key


_BS_P207S_INVALID_SESSION_IDS = {"0", "0x0", "-", "none", "null"}


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


def _session_norm(value):
    """Return a canonical, non-placeholder Windows session identifier."""
    if isinstance(value, (list, tuple, set)):
        for item in value:
            normalized = _session_norm(item)
            if normalized:
                return normalized
        return None

    normalized = _norm(value)
    if not normalized:
        return None

    # Match P2-07O correlation semantics: equivalent hexadecimal LogonId
    # spellings such as 0X00012345 and 0x12345 identify the same session.
    if len(normalized) > 2 and normalized[:2] == "0x":
        try:
            normalized = f"0x{int(normalized[2:], 16):x}"
        except ValueError:
            # Preserve malformed/non-numeric legacy values rather than
            # inventing a different identifier.
            pass

    if normalized in _BS_P207S_INVALID_SESSION_IDS:
        return None
    return normalized


def _mapping_session_provenance(mapping):
    """Return authoritative/forbidden raw session IDs and field presence."""
    authoritative = set()
    forbidden = set()
    authoritative_present = False

    if not isinstance(mapping, Mapping):
        return authoritative, forbidden, authoritative_present

    sources = [mapping]
    folded = {str(key).casefold(): value for key, value in mapping.items()}
    event_data = folded.get("event_data")
    if isinstance(event_data, Mapping):
        sources.append(event_data)

    source_fields = [
        {str(key).casefold(): value for key, value in source.items()}
        for source in sources
    ]

    # P2-07Q established TargetLogonId as authoritative when present. Apply
    # that precedence across the flattened raw mapping and its EventData copy,
    # so a compatibility SessionId cannot become a second scenario identity.
    target_present = any("targetlogonid" in fields for fields in source_fields)
    if target_present:
        authoritative_present = True
        for fields in source_fields:
            if "targetlogonid" not in fields:
                continue
            value = _session_norm(fields.get("targetlogonid"))
            if value:
                authoritative.add(value)
    else:
        for fields in source_fields:
            for name in ("session_id", "sessionid"):
                if name not in fields:
                    continue
                authoritative_present = True
                value = _session_norm(fields.get(name))
                if value:
                    authoritative.add(value)

    for fields in source_fields:
        for name in ("subjectlogonid", "logonid", "logon_id"):
            value = _session_norm(fields.get(name))
            if value:
                forbidden.add(value)

    return authoritative, forbidden, authoritative_present


def _canonical_session_allowed(parent, session_id):
    """Reject canonical IDs that conflict with authoritative raw provenance."""
    canonical_id = _session_norm(session_id)
    if not canonical_id:
        return False

    authoritative, forbidden, authoritative_present = _mapping_session_provenance(parent)

    # When the source exposes an authoritative session field, canonical
    # evidence must agree with its valid value. Presence of an invalid native
    # TargetLogonId also fails closed instead of falling back to a compatibility
    # SessionId or a conflicting canonical session.
    if authoritative_present:
        return canonical_id in authoritative

    # Canonical-only normalized input remains supported. But if raw provenance
    # says the same value came only from SubjectLogonId/ambiguous LogonId, P2-07L
    # requires that value to stay contextual rather than become session identity.
    if canonical_id in forbidden:
        return False

    return True


def scope(obj, _depth=0, _seen=None, _suppress_compat_session=False):
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
        value = _session_norm(value)
        if value:
            sessions.add(value)

    if isinstance(obj, Mapping):
        items = list(obj.items())
        folded_keys = {str(key).casefold() for key, _ in items}
        target_logon_id_present = "targetlogonid" in folded_keys
    elif isinstance(obj, (str, bytes, int, float, bool)):
        items = []
        target_logon_id_present = False
    else:
        try:
            items = list(vars(obj).items())
        except (TypeError, AttributeError):
            items = []
        target_logon_id_present = False

    suppress_compat_session = _suppress_compat_session or target_logon_id_present

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
        elif lname == "targetlogonid":
            if isinstance(value, Mapping):
                add_session(
                    value.get("id")
                    or value.get("session_id")
                )
            else:
                add_session(value)
        elif lname in {"session_id", "sessionid"} and not suppress_compat_session:
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
                canonical_id = session_obj.get("id")
                if _canonical_session_allowed(obj, canonical_id):
                    add_session(canonical_id)

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
                child_suppress_compat = (
                    suppress_compat_session and lname == "event_data"
                )
                nested = scope(
                    child,
                    _depth + 1,
                    _seen,
                    child_suppress_compat,
                )
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
    """Install the P2-07J/P2-07K/P2-07L/P2-07R/P2-07S/P2-07T/P2-07U scope functions."""
    target_module._bs_p005_scope = scope
    target_module._bs_p005_related = related
    target_module._bs_p005_partition_chains = partition_chains
    target_module._bs_p005_component_scope = component_scope
    target_module._bs_p005_filter_findings = filter_findings
    target_module._bs_p206b_component_namespace = component_namespace


# BREACHSCOPE_P2_07L_AUTHORITATIVE_SESSION_SCOPE_V1
# BREACHSCOPE_P2_07R_CANONICAL_SESSION_PROVENANCE_V1
# BREACHSCOPE_P2_07S_INVALID_SESSION_IDS_V1
# BREACHSCOPE_P2_07T_CANONICAL_SCENARIO_SESSION_IDS_V1
# BREACHSCOPE_P2_07U_TARGET_LOGON_ID_SCENARIO_PRECEDENCE_V1
