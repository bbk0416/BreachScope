from datetime import datetime, timezone
from pathlib import Path
import sqlite3

import pytest

from breachscope.artifacts import browser


def _make_sqlite_fixture(path: Path) -> None:
    with sqlite3.connect(path) as conn:
        conn.execute("CREATE TABLE marker (value TEXT)")
        conn.execute("INSERT INTO marker(value) VALUES ('copied')")


def _make_chromium_history(path: Path, url: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with sqlite3.connect(path) as conn:
        conn.execute(
            """
            CREATE TABLE urls (
                url TEXT,
                title TEXT,
                visit_count INTEGER,
                last_visit_time INTEGER
            )
            """
        )
        conn.execute(
            "INSERT INTO urls(url, title, visit_count, last_visit_time) VALUES (?, ?, ?, ?)",
            (url, "fixture", 1, 13_222_310_400_000_000),
        )


def test_browser_sqlite_snapshot_is_private_copy_and_cleans_up(tmp_path):
    source_path = tmp_path / "History"
    _make_sqlite_fixture(source_path)

    with browser._open_sqlite_snapshot(source_path) as conn:
        snapshot_path = Path(conn.execute("PRAGMA database_list").fetchone()[2])
        snapshot_dir = snapshot_path.parent

        assert snapshot_path != source_path
        assert snapshot_path.exists()
        assert snapshot_dir.name.startswith("breachscope_browser_")
        assert conn.execute("SELECT value FROM marker").fetchone()[0] == "copied"

    assert not snapshot_dir.exists()


def test_browser_sqlite_snapshot_cleans_up_after_parse_error(tmp_path):
    source_path = tmp_path / "History"
    _make_sqlite_fixture(source_path)

    snapshot_dir = None
    with pytest.raises(RuntimeError, match="parse failed"):
        with browser._open_sqlite_snapshot(source_path) as conn:
            snapshot_path = Path(conn.execute("PRAGMA database_list").fetchone()[2])
            snapshot_dir = snapshot_path.parent
            raise RuntimeError("parse failed")

    assert snapshot_dir is not None
    assert not snapshot_dir.exists()


@pytest.mark.parametrize(
    ("collector", "relative_path", "source"),
    [
        (
            browser._collect_chrome_history,
            "AppData/Local/Google/Chrome/User Data/Default/History",
            "Chrome",
        ),
        (
            browser._collect_edge_history,
            "AppData/Local/Microsoft/Edge/User Data/Default/History",
            "Edge",
        ),
    ],
)
def test_chromium_history_keeps_url_out_of_command_line(
    monkeypatch,
    tmp_path,
    collector,
    relative_path,
    source,
):
    url = "https://example.test/invoke-expression"
    _make_chromium_history(tmp_path / relative_path, url)

    monkeypatch.setattr(browser.platform, "system", lambda: "Windows")
    monkeypatch.setattr(browser.Path, "home", classmethod(lambda cls: tmp_path))

    events = collector()

    assert len(events) == 1
    event = events[0]
    assert event["source"] == source
    assert event["event_id"] == "browser_visit"
    assert event["raw"]["url"] == url
    assert "command_line" not in event


@pytest.mark.parametrize(
    ("collector", "relative_path"),
    [
        (
            browser._collect_chrome_history,
            "AppData/Local/Google/Chrome/User Data/Default/History",
        ),
        (
            browser._collect_edge_history,
            "AppData/Local/Microsoft/Edge/User Data/Default/History",
        ),
    ],
)
def test_chromium_history_requires_actual_visit_and_source_timestamp(
    monkeypatch,
    tmp_path,
    collector,
    relative_path,
):
    history_path = tmp_path / relative_path
    history_path.parent.mkdir(parents=True, exist_ok=True)
    valid_time = 13_222_310_400_000_000

    with sqlite3.connect(history_path) as conn:
        conn.execute(
            """
            CREATE TABLE urls (
                url TEXT,
                title TEXT,
                visit_count INTEGER,
                last_visit_time INTEGER
            )
            """
        )
        conn.executemany(
            "INSERT INTO urls(url, title, visit_count, last_visit_time) VALUES (?, ?, ?, ?)",
            [
                ("https://valid.example", "valid", 1, valid_time),
                ("https://unvisited.example", "unvisited", 0, valid_time + 1),
                ("https://missing-time.example", "missing", 1, None),
                ("https://zero-time.example", "zero", 1, 0),
            ],
        )

    monkeypatch.setattr(browser.platform, "system", lambda: "Windows")
    monkeypatch.setattr(browser.Path, "home", classmethod(lambda cls: tmp_path))

    events = collector()

    assert [event["raw"]["url"] for event in events] == ["https://valid.example"]
    assert events[0]["raw"]["visit_count"] == 1


def test_firefox_history_skips_rows_without_source_visit_time(monkeypatch, tmp_path):
    profile_dir = tmp_path / ".mozilla" / "firefox" / "fixture.default"
    profile_dir.mkdir(parents=True)
    history_path = profile_dir / "places.sqlite"

    with sqlite3.connect(history_path) as conn:
        conn.execute(
            """
            CREATE TABLE moz_places (
                url TEXT,
                title TEXT,
                visit_count INTEGER,
                last_visit_date INTEGER
            )
            """
        )
        conn.executemany(
            "INSERT INTO moz_places(url, title, visit_count, last_visit_date) VALUES (?, ?, ?, ?)",
            [
                ("https://valid.example", "valid", 1, 1_700_000_000_000_000),
                ("https://missing.example", "missing", 1, None),
            ],
        )

    monkeypatch.setattr(browser.platform, "system", lambda: "Linux")
    monkeypatch.setattr(browser.Path, "home", classmethod(lambda cls: tmp_path))

    events = browser._collect_firefox_history()

    assert len(events) == 1
    event = events[0]
    assert event["raw"]["url"] == "https://valid.example"
    assert "command_line" not in event
    expected_time = datetime.fromtimestamp(1_700_000_000, tz=timezone.utc).isoformat()
    assert event["timestamp"] == expected_time
    assert event["raw"]["last_visit_time"] == expected_time
    assert "https://missing.example" not in {item["raw"]["url"] for item in events}
