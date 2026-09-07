"""Host-scope explicit Windows logon-session chains for P2-07M.

Windows LogonId/SessionId values are local to one host. P2-07I established
which fields may define an explicit successful session; this installer keeps
that contract and partitions those explicit events by host before delegating
to the existing correlator implementation.
"""
from __future__ import annotations

from collections import defaultdict


def install(target_module):
    """Install host-scoped explicit-session correlation into correlator."""
    original = target_module._correlate_by_session
    explicit_session_id = target_module._bs_p207i_explicit_session_id

    def correlate_by_host_session(events, findings):
        explicit_by_host = defaultdict(list)
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
                explicit_by_host[host.casefold()].append(event)

        chains = []

        # Reuse the already-tested P2-07I session implementation inside each
        # host boundary. It still owns session eligibility, timestamp ordering,
        # finding attachment, and confidence semantics.
        for host_key, host_events in sorted(explicit_by_host.items()):
            host_chains = original(host_events, findings)
            for chain in host_chains:
                if chain.chain_type != "session" or not chain.events:
                    continue
                session_id = explicit_session_id(chain.events[0])
                if not session_id:
                    continue
                chain.chain_id = f"session_{host_key}_{session_id}"
                chain.description = f"호스트 {host_key} 세션 {session_id}의 활동"
            chains.extend(host_chains)

        # Non-explicit events keep the P2-07I bounded host/user activity
        # behavior unchanged. Failed/invalid authentication events remain
        # excluded by the original implementation.
        chains.extend(original(fallback_events, findings))
        return chains

    target_module._correlate_by_session = correlate_by_host_session


# BREACHSCOPE_P2_07M_HOST_SCOPED_SESSION_CHAINS_V1
