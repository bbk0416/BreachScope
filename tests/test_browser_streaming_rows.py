from __future__ import annotations

from contextlib import contextmanager
from pathlib import Path

import pytest

from breachscope.artifacts import browser


class _StreamingCursor:
    def __init__(self, rows):
        self._rows = rows

    def execute(self, _query):
        return self

    def __iter__(self):
        return iter(self._rows)

    def fetchall(self):
        raise AssertionError("browser collector must not materialize all rows with fetchall()")


class _Connection:
    def __init__(self, rows):
        self._rows = rows

    def cursor(self):
        return _StreamingCursor(self._rows)


@contextmanager
def _snapshot(rows):
    yield _Connection(rows)


@pytest.mark.parametrize(
    ("collector_name", "source", "row"),
    [
        (
            "_collect_chrome_history",
            "Chrome",
            (1, "https://example.test/chrome", "Chrome", 1, 13380163200000000, 13380163200000000),
        ),
        (
            "_collect_edge_history",
            "Edge",
            (2, "https://example.test/edge", "Edge", 1, 13380163200000000, 13380163200000000),
        ),
        (
            "_collect_firefox_history",
            "Firefox",
            (3, "https://example.test/firefox", "Firefox", 1, 1700000000.0, 1700000000.0),
        ),
    ],
)
def test_browser_collectors_stream_cursor_rows_without_fetchall(
    monkeypatch, collector_name, source, row
):
    history_path = Path("/tmp/Profile 1/History")
    monkeypatch.setattr(browser.platform, "system", lambda: "Windows")
    monkeypatch.setattr(browser, "_profile_databases", lambda *_args: [history_path])
    monkeypatch.setattr(browser, "_open_sqlite_snapshot", lambda _path: _snapshot([row]))

    events = getattr(browser, collector_name)()

    assert len(events) == 1
    assert events[0]["source"] == source
    assert events[0]["raw"]["profile"] == "Profile 1"
