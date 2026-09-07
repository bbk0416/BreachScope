"""Host-scope explicit Windows logon-session chains for P2-07M/P2-07N/P2-07O/P2-07P/P2-07Q/P2-07V/P2-07W/P2-07Y/P2-07Z.

Windows LogonId/SessionId values are local to one host. P2-07I established
which fields may define an explicit successful session, P2-07M scoped those
identifiers to a host, P2-07N prevents a reused identifier on the same host
from merging distinct logon lifecycles, P2-07O canonicalizes equivalent
hexadecimal identifier spellings before correlation, P2-07P retains
user-initiated logoff evidence (Security Event 4647) in the explicit session,
P2-07Q gives the native Windows TargetLogonId field precedence over
compatibility SessionId aliases when both are present, P2-07V rejects
malformed values that claim hexadecimal Windows LogonId syntax, P2-07W
exposes reused-logon lifecycle identity to downstream scenario scoping,
P2-07Y preserves that reuse marker even when an earlier lifecycle is incomplete,
and P2-07Z removes duplicate copies of the same explicit lifecycle event before
segmenting a Windows logon session.
"""
from __future__ import annotations

import hashlib
from collections import defaultdict


def install(target_module):
    """Install host-scoped, lifecycle-bounded explicit-session correlation."""
    original = target_module._correlate_by_session
    raw_explicit_session_id = target_module._bs_p207i_explicit_session_id
    invalid_session_ids = target_module._BS_P207I_INVALID_SESSION_IDS
    auth_event_ids = target_module._BS_P207I_AUTH_EVENT_IDS
    parse_timestamp = target_module._parse_timestamp
    event_identity_key = target_module.get_event_identity_key

    def canonical_session_id(session_id):
        """Canonicalize valid hexadecimal Windows session identifiers."""
        value = str(session_id).strip()
        if value[:2].casefold() == "0x":
            digits = value[2:]
            if not digits or any(ch not in "0123456789abcdefABCDEF" for ch in digits):
                return None
            return f"0x{int(digits, 16):x}"
        return value

    def explicit_session_id(event):
        raw = event.raw if isinstance(event.raw, dict) else {}
        event_id = getattr(event, "event_id", None)

        # For native Windows logon lifecycle events, TargetLogonId is the
        # authoritative session identifier. Compatibility SessionId aliases
        # may exist in normalized/raw payloads, but they must not override a
        # concrete TargetLogonId that identifies a different session.
        if event_id in ("4624", "4634", "4647") and "TargetLogonId" in raw:
            value = raw.get("TargetLogonId")
            if value is None or not str(value).strip():
                return None
            canonical = canonical_session_id(value)
            if not canonical or canonical.casefold() in invalid_session_ids:
                return None
            return canonical

        session_id = raw_explicit_session_id(event)

        # Security Event 4647 is a user-initiated logoff. It has no legacy
        # P2-07I compatibility fallback; without TargetLogonId it cannot safely
        # establish an explicit Windows session identity.
        if not session_id:
            return None

        canonical = canonical_session_id(session_id)
        if not canonical or canonical.casefold() in invalid_session_ids:
            return None
        return canonical

    # P2-07I's original correlator resolves these module globals when invoked.
    # Replace the extractor and classify 4647 as authentication evidence so a
    # malformed/missing LogonId cannot fall back into a generic activity chain.
    target_module._bs_p207i_explicit_session_id = explicit_session_id
    auth_event_ids.add("4647")

    def lifecycle_segments(grouped_events):
        """Split one host/session-id group at authoritative logon boundaries."""
        timestamped = []
        seen_event_keys = set()
        for event in grouped_events:
            # The collector intentionally yields every JSONL row, so overlapping
            # exports can present the same EVTX record more than once. Treat one
            # correlation-safe event identity as one lifecycle observation. This
            # prevents duplicate 4624 events from resetting a lifecycle and
            # duplicate 4647/4634 events from inflating session evidence.
            event_key = str(event_identity_key(event))
            if event_key in seen_event_keys:
                continue
            seen_event_keys.add(event_key)

            timestamp = parse_timestamp(event.timestamp)
            if timestamp is not None:
                timestamped.append((timestamp, event))

        # At an identical timestamp, keep the lifecycle order deterministic:
        # successful logon -> initiated logoff -> completed logoff.
        event_order = {"4624": 0, "4647": 1, "4634": 2}
        timestamped.sort(
            key=lambda item: (
                item[0],
                event_order.get(item[1].event_id, 1),
                str(event_identity_key(item[1])),
            )
        )

        segments = []
        current = []

        for _, event in timestamped:
            if event.event_id == "4624":
                # Every successful-logon event starts a new lifecycle. If a
                # prior lifecycle never emitted a completed logoff, do not let
                # the next logon with a reused ID bridge the two sessions.
                if len(current) >= 2:
                    segments.append(current)
                current = [event]
                continue

            if event.event_id == "4647" and current:
                # 4647 records that this account initiated logoff. Keep it as
                # session evidence. If 4634 is absent from the collected data,
                # this still provides a valid end observation for the chain.
                current.append(event)
                continue

            if event.event_id == "4634" and current:
                current.append(event)
                segments.append(current)
                current = []

        if len(current) >= 2:
            segments.append(current)

        return segments

    def lifecycle_token(events):
        first_identity = str(event_identity_key(events[0])).encode("utf-8")
        return hashlib.sha256(first_identity).hexdigest()[:10]

    def correlate_by_host_session(events, findings):
        explicit_groups = defaultdict(list)
        fallback_events = []

        for event in events or []:
            session_id = explicit_session_id(event)
            if not session_id:
                fallback_events.append(event)
                continue

            # A Windows session ID has meaning only with its originating host.
            # Do not fabricate a global session identity when host is absent.
            host = (getattr(event, "host", None) or "").strip()
            if host:
                explicit_groups[(host.casefold(), session_id)].append(event)

        chains = []

        for (host_key, session_id), grouped_events in sorted(explicit_groups.items()):
            lifecycles = lifecycle_segments(grouped_events)
            # P2-07Y: an incomplete earlier lifecycle may contain only its 4624
            # and therefore be intentionally omitted from `lifecycles`. The ID
            # was still reused, so downstream scenario scoping must retain the
            # concrete lifecycle marker on any later valid chain. Count unique
            # successful-logon observations using the strong event identity so
            # a duplicate copy of the same EVTX record is not mistaken for reuse.
            logon_starts = {
                str(event_identity_key(event))
                for event in grouped_events
                if event.event_id == "4624"
            }
            reused_id = len(lifecycles) > 1 or len(logon_starts) > 1

            for lifecycle_events in lifecycles:
                # Reuse the already-tested P2-07I implementation inside one
                # authoritative logon lifecycle. It still owns finding
                # attachment, confidence, and timestamp semantics.
                lifecycle_chains = original(lifecycle_events, findings)
                for chain in lifecycle_chains:
                    if chain.chain_type != "session" or not chain.events:
                        continue
                    base_id = f"session_{host_key}_{session_id}"
                    if reused_id:
                        base_id = f"{base_id}_{lifecycle_token(chain.events)}"
                        # P2-07N's suffix is not merely display uniqueness: it
                        # identifies one concrete lifecycle of a reused Windows
                        # LogonId. Expose it explicitly so scenario grouping
                        # cannot collapse distinct lifecycles back together.
                        chain.session_instance_id = base_id
                    chain.chain_id = base_id
                    chain.description = (
                        f"호스트 {host_key} 세션 {session_id}의 활동"
                    )
                chains.extend(lifecycle_chains)

        # Non-explicit events keep the P2-07I bounded host/user activity
        # behavior unchanged. Failed/invalid authentication events remain
        # excluded by the original implementation.
        chains.extend(original(fallback_events, findings))
        return chains

    target_module._correlate_by_session = correlate_by_host_session


# BREACHSCOPE_P2_07M_HOST_SCOPED_SESSION_CHAINS_V1
# BREACHSCOPE_P2_07N_SESSION_LIFECYCLE_BOUNDARIES_V1
# BREACHSCOPE_P2_07O_CANONICAL_SESSION_IDS_V1
# BREACHSCOPE_P2_07P_USER_INITIATED_LOGOFF_V1
# BREACHSCOPE_P2_07Q_TARGET_LOGON_ID_PRECEDENCE_V1
# BREACHSCOPE_P2_07V_REJECT_MALFORMED_HEX_SESSION_IDS_V1
# BREACHSCOPE_P2_07W_SESSION_LIFECYCLE_IDENTITY_V1
# BREACHSCOPE_P2_07Y_INCOMPLETE_REUSE_LIFECYCLE_MARKER_V1
# BREACHSCOPE_P2_07Z_DEDUPLICATE_SESSION_LIFECYCLE_EVENTS_V1
