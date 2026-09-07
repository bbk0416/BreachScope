from __future__ import annotations

from datetime import datetime
from types import SimpleNamespace

from breachscope.artifacts import usb
from breachscope.artifacts.classifier import ArtifactCategory, ArtifactClassifier


REG_OUTPUT = r"""
HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Enum\USB\VID_1234&PID_5678\SERIAL-001
    FriendlyName    REG_SZ    Example USB Device
"""

REG_OUTPUT_WITH_BOTH_NAMES = r"""
HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Enum\USB\VID_1234&PID_5678\SERIAL-001
    FriendlyName    REG_SZ    Example USB Device
    DeviceDesc      REG_SZ    USB Mass Storage Device
"""

REG_OUTPUT_TWO_INSTANCES = r"""
HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Enum\USB\VID_1234&PID_5678\SERIAL-001
    FriendlyName    REG_SZ    Example USB Device
    DeviceDesc      REG_SZ    USB Mass Storage Device
HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Enum\USB\VID_ABCD&PID_EF01\SERIAL-002
    DeviceDesc      REG_SZ    Second USB Device
"""


def _mock_registry_query(monkeypatch, output: str) -> None:
    monkeypatch.setattr(usb.platform, "system", lambda: "Windows")
    monkeypatch.setattr(
        usb.subprocess,
        "run",
        lambda *args, **kwargs: SimpleNamespace(returncode=0, stdout=output),
    )


def test_usb_registry_observation_does_not_claim_collection_time_as_connection_time(monkeypatch):
    _mock_registry_query(monkeypatch, REG_OUTPUT)

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
    assert raw["registry_key"] == r"HKLM\SYSTEM\CurrentControlSet\Enum\USB"
    assert raw["instance_registry_key"] == (
        r"HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Enum\USB"
        r"\VID_1234&PID_5678\SERIAL-001"
    )
    assert raw["hardware_id"] == "VID_1234&PID_5678"
    assert raw["device_id"] == "SERIAL-001"
    assert raw["property"] == "FriendlyName"
    assert raw["value"] == "Example USB Device"
    assert raw["properties"] == {"FriendlyName": "Example USB Device"}
    assert raw["observation_time"] == event["timestamp"]
    assert raw["timestamp_source"] == "collection_time"
    assert raw["connection_time_verified"] is False
    assert raw["connection_times"] == []


def test_usb_registry_observation_merges_name_properties_per_instance(monkeypatch):
    _mock_registry_query(monkeypatch, REG_OUTPUT_WITH_BOTH_NAMES)

    events = usb.collect_usb_history()

    assert len(events) == 1
    raw = events[0]["raw"]
    assert raw["hardware_id"] == "VID_1234&PID_5678"
    assert raw["device_id"] == "SERIAL-001"
    assert raw["property"] == "FriendlyName"
    assert raw["value"] == "Example USB Device"
    assert raw["properties"] == {
        "FriendlyName": "Example USB Device",
        "DeviceDesc": "USB Mass Storage Device",
    }
    assert raw["timestamp_source"] == "collection_time"
    assert raw["connection_time_verified"] is False
    assert raw["connection_times"] == []


def test_usb_registry_observation_keeps_distinct_instances_separate(monkeypatch):
    _mock_registry_query(monkeypatch, REG_OUTPUT_TWO_INSTANCES)

    events = usb.collect_usb_history()

    assert len(events) == 2
    by_device_id = {event["raw"]["device_id"]: event["raw"] for event in events}

    assert by_device_id["SERIAL-001"]["properties"] == {
        "FriendlyName": "Example USB Device",
        "DeviceDesc": "USB Mass Storage Device",
    }
    assert by_device_id["SERIAL-002"]["property"] == "DeviceDesc"
    assert by_device_id["SERIAL-002"]["value"] == "Second USB Device"
    assert by_device_id["SERIAL-002"]["properties"] == {
        "DeviceDesc": "Second USB Device"
    }


def test_usb_registry_observation_is_classified_as_registry_artifact(monkeypatch):
    _mock_registry_query(monkeypatch, REG_OUTPUT)

    event = usb.collect_usb_history()[0]

    assert ArtifactClassifier.classify_event(event) is ArtifactCategory.REGISTRY_ARTIFACTS


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
