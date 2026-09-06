from __future__ import annotations

from datetime import datetime
from types import SimpleNamespace

from breachscope.artifacts import usb
from breachscope.artifacts.classifier import ArtifactCategory, ArtifactClassifier


REG_OUTPUT = r"""
HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Enum\USB\VID_1234&PID_5678\SERIAL-001
    FriendlyName    REG_SZ    Example USB Device
"""


def test_usb_registry_observation_does_not_claim_collection_time_as_connection_time(monkeypatch):
    monkeypatch.setattr(usb.platform, "system", lambda: "Windows")
    monkeypatch.setattr(
        usb.subprocess,
        "run",
        lambda *args, **kwargs: SimpleNamespace(returncode=0, stdout=REG_OUTPUT),
    )

    events = usb.collect_usb_history()

    assert len(events) == 1
    event = events[0]
    assert event["source"] == "USB"
    assert event["event_id"] == "usb_registry_device_observed"
    assert event["event_type"] == "artifact_observation"
    assert event["command_line"] == ""

    observed = datetime.fromisoformat(event["timestamp"])
    assert observed.tzinfo is not None

    raw = event["raw"]
    assert raw["device_id"] == "SERIAL-001"
    assert raw["property"] == "FriendlyName"
    assert raw["value"] == "Example USB Device"
    assert raw["observation_time"] == event["timestamp"]
    assert raw["timestamp_source"] == "collection_time"
    assert raw["connection_time_verified"] is False
    assert raw["connection_times"] == []


def test_usb_observation_keeps_user_activity_classification(monkeypatch):
    monkeypatch.setattr(usb.platform, "system", lambda: "Windows")
    monkeypatch.setattr(
        usb.subprocess,
        "run",
        lambda *args, **kwargs: SimpleNamespace(returncode=0, stdout=REG_OUTPUT),
    )

    event = usb.collect_usb_history()[0]

    assert ArtifactClassifier.classify_event(event) is ArtifactCategory.USER_ACTIVITY


def test_usb_non_windows_behavior_is_unchanged(monkeypatch):
    monkeypatch.setattr(usb.platform, "system", lambda: "Linux")

    assert usb.collect_usb_history() == []


def test_usb_failed_registry_query_returns_no_observations(monkeypatch):
    monkeypatch.setattr(usb.platform, "system", lambda: "Windows")
    monkeypatch.setattr(
        usb.subprocess,
        "run",
        lambda *args, **kwargs: SimpleNamespace(returncode=1, stdout=""),
    )

    assert usb.collect_usb_history() == []
