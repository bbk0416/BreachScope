from __future__ import annotations

import inspect
from datetime import datetime, timezone
from types import SimpleNamespace

import pytest

from breachscope import correlator


def _event(*, host: str, user: str):
    # Keep the synthetic object intentionally broad so the legacy field
    # accessor can read attributes or raw values without needing the entire
    # public Event constructor shape.
    return SimpleNamespace(
        timestamp=datetime(2026, 9, 1, tzinfo=timezone.utc),
        host=host,
        user=user,
        source="ProcessCreate",
        event_id=4688,
        level="info",
        command_line="cmd.exe /c whoami",
        raw={
            "host": host,
            "user": user,
            "canonical": {
                "host": {"name": host},
                "user": {"name": user},
            },
        },
    )


def _call_common_key(left, right, fields):
    func = correlator._extract_common_key
    sig = inspect.signature(func)
    params = list(sig.parameters.values())

    field_idx = None
    for idx, param in enumerate(params):
        lowered = param.name.casefold()
        if lowered in {"fields", "required_fields"} or "field" in lowered:
            field_idx = idx
            break

    assert field_idx is not None, (
        "_extract_common_key no longer exposes a fields/required_fields "
        "parameter; P0-03 must be revisited."
    )

    other = [p for i, p in enumerate(params) if i != field_idx]
    values = []

    if len(other) == 2:
        event_values = iter([left, right])
        for idx, param in enumerate(params):
            if idx == field_idx:
                values.append(fields)
            else:
                values.append(next(event_values))
        return func(*values)

    if len(other) == 1:
        name = other[0].name.casefold()
        pair = [left, right] if "event" in name else (left, right)
        for idx, param in enumerate(params):
            values.append(fields if idx == field_idx else pair)
        return func(*values)

    pytest.fail(
        "Unexpected _extract_common_key signature: "
        f"{sig}. P0-03 refuses to guess."
    )


def test_required_fields_use_and_semantics_not_or():
    left = _event(host="WIN-A", user="alice")
    right = _event(host="WIN-A", user="bob")

    # Historical bug: same host caused an immediate success even though the
    # explicitly required user field differed.
    assert not _call_common_key(left, right, ["host", "user"])


def test_required_fields_match_when_every_field_matches():
    left = _event(host="WIN-A", user="alice")
    right = _event(host="WIN-A", user="alice")

    key = _call_common_key(left, right, ["host", "user"])
    assert key
    assert "&&" in str(key)


def test_single_required_field_preserves_legacy_behavior():
    left = _event(host="WIN-A", user="alice")
    same_host = _event(host="WIN-A", user="bob")
    other_host = _event(host="WIN-B", user="alice")

    assert _call_common_key(left, same_host, ["host"])
    assert not _call_common_key(left, other_host, ["host"])


def test_missing_required_field_cannot_be_ignored():
    left = _event(host="WIN-A", user="")
    right = _event(host="WIN-A", user="")

    # If user is explicitly required, a host-only match is insufficient.
    assert not _call_common_key(left, right, ["host", "user"])
