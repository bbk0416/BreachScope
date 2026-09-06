from __future__ import annotations

from pathlib import Path

import pytest

from breachscope.artifacts import registry


def test_offline_registry_hive_request_fails_closed_on_non_windows(tmp_path, monkeypatch):
    monkeypatch.setattr(registry.platform, "system", lambda: "Linux")

    with pytest.raises(NotImplementedError, match="오프라인 레지스트리 하이브 파싱"):
        registry.collect_registry(registry_hives=[tmp_path / "NTUSER.DAT"])


def test_offline_registry_hive_request_fails_closed_even_for_empty_list(monkeypatch):
    monkeypatch.setattr(registry.platform, "system", lambda: "Windows")

    with pytest.raises(NotImplementedError, match="빈 결과를 정상 수집 결과로 처리하지 않습니다"):
        registry.collect_registry(registry_hives=[])


def test_direct_offline_hive_parser_does_not_return_false_empty_result(tmp_path):
    with pytest.raises(NotImplementedError, match="오프라인 레지스트리 하이브 파싱"):
        registry._parse_registry_hive(Path(tmp_path / "SOFTWARE"))


def test_live_registry_non_windows_behavior_is_unchanged(monkeypatch):
    monkeypatch.setattr(registry.platform, "system", lambda: "Linux")

    assert registry.collect_registry() == []


def test_live_registry_windows_path_still_returns_collected_events(monkeypatch):
    expected = [{"source": "Registry", "event_type": "autorun_entry"}]
    monkeypatch.setattr(registry.platform, "system", lambda: "Windows")
    monkeypatch.setattr(registry, "_collect_live_registry", lambda: expected)

    assert registry.collect_registry() == expected
