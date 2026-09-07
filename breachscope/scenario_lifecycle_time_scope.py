"""Time-bound scenario assignment for reused Windows LogonId lifecycles.

P2-07W preserves the correlator-issued identity of each reused LogonId
lifecycle, but a generic chain could still be attached to whichever lifecycle
was encountered first. P2-07X assigns generic evidence to a reused lifecycle
only when scope and observed time overlap identify exactly one lifecycle.
"""
from __future__ import annotations

from .utils import parse_timestamp


def _norm(value):
    if value is None:
        return None
    text = str(value).strip()
    return text.casefold() if text else None


def _chain_session_instance(chain):
    if getattr(chain, "chain_type", None) != "session":
        return None
    return _norm(getattr(chain, "session_instance_id", None))


def _chain_time_bounds(chain):
    """Return the observed inclusive time range for one chain."""
    timestamps = []
    for event in getattr(chain, "events", None) or []:
        timestamp = parse_timestamp(getattr(event, "timestamp", None))
        if timestamp is not None:
            timestamps.append(timestamp)

    if timestamps:
        return min(timestamps), max(timestamps)

    start = parse_timestamp(getattr(chain, "start_time", None))
    end = parse_timestamp(getattr(chain, "end_time", None))
    if start is None and end is None:
        return None
    if start is None:
        start = end
    if end is None:
        end = start
    if end < start:
        start, end = end, start
    return start, end


def _time_bounds_overlap(left, right):
    if left is None or right is None:
        return False
    left_start, left_end = left
    right_start, right_end = right
    return left_start <= right_end and right_start <= left_end


def install(target_module):
    """Install deterministic time-bounded reused-lifecycle partitioning."""
    legacy_partition = target_module._bs_p005_partition_chains
    scope = target_module._bs_p005_scope
    related = target_module._bs_p005_related

    def partition_chains(chains):
        chains = list(chains or [])
        if len(chains) <= 1:
            return [chains] if chains else []

        instances = [_chain_session_instance(chain) for chain in chains]
        if not any(instances):
            # P2-07X is intentionally narrow. Cases without a reused LogonId
            # retain the already-tested P2-07W partition behavior unchanged.
            return legacy_partition(chains)

        scopes = [scope(chain) for chain in chains]
        bounds = [_chain_time_bounds(chain) for chain in chains]
        lifecycle_indices = [
            index for index, instance in enumerate(instances) if instance
        ]

        lifecycle_groups = {}
        lifecycle_order = []
        generic_indices = []

        for index, instance in enumerate(instances):
            if not instance:
                generic_indices.append(index)
                continue
            if instance not in lifecycle_groups:
                lifecycle_groups[instance] = []
                lifecycle_order.append(instance)
            lifecycle_groups[instance].append(chains[index])

        unresolved = []
        for generic_index in generic_indices:
            candidates = set()
            for lifecycle_index in lifecycle_indices:
                if not related(scopes[generic_index], scopes[lifecycle_index]):
                    continue
                if not _time_bounds_overlap(
                    bounds[generic_index], bounds[lifecycle_index]
                ):
                    continue
                candidates.add(instances[lifecycle_index])

            if len(candidates) == 1:
                lifecycle_groups[next(iter(candidates))].append(
                    chains[generic_index]
                )
            else:
                # No matching lifecycle means the evidence was observed outside
                # every concrete reused session. Multiple matches are ambiguous.
                # In both cases, fail closed instead of choosing by input order.
                unresolved.append(chains[generic_index])

        groups = [lifecycle_groups[instance] for instance in lifecycle_order]
        groups.extend(legacy_partition(unresolved))

        # Keep output ordering stable with respect to the caller's chain order.
        positions = {id(chain): index for index, chain in enumerate(chains)}
        groups.sort(
            key=lambda group: min(positions.get(id(chain), len(chains)) for chain in group)
        )
        return groups

    target_module._bs_p005_partition_chains = partition_chains


# BREACHSCOPE_P2_07X_SESSION_LIFECYCLE_TIME_BOUNDS_V1
