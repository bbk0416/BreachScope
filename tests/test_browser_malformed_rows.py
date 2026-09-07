from pathlib import Path
import sqlite3

import pytest

from breachscope.artifacts import browser


CHROMIUM_TIME = 13_222_310_400_000_000
FIREFOX_TIME = 1_700_000_000_000_000
SQLITE_MAX_INTEGER = 9_223_372_036_854_775_807


def _create_chromium_schema(path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with sqlite3.connect(path) as conn:
        conn.execute(
            """
            CREATE TABLE urls (
                id INTEGER PRIMARY KEY,
                url TEXT,
                title TEXT,
                visit_count INTEGER,
                last_visit_time INTEGER
            )
            """
        )
        conn.execute(
            """
            CREATE TABLE visits (
                id INTEGER PRIMARY KEY,
                url INTEGER,
                visit_time INTEGER
            )
            """
        )


def _create_firefox_schema(path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with sqlite3.connect(path) as conn:
        conn.execute(
            """
            CREATE TABLE moz_places (
                id INTEGER PRIMARY KEY,
                url TEXT,
                title TEXT,
                visit_count INTEGER,
                last_visit_date INTEGER
            )
            """
        )
        conn.execute(
            """
            CREATE TABLE moz_historyvisits (
                id INTEGER PRIMARY KEY,
                place_id INTEGER,
                visit_date INTEGER
            )
            """
        )


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
def test_chromium_malformed_visit_timestamp_does_not_abort_profile(
    monkeypatch,
    tmp_path,
    collector,
    relative_path,
    source,
):
    history_path = tmp_path / relative_path
    _create_chromium_schema(history_path)

    with sqlite3.connect(history_path) as conn:
        conn.executemany(
            "INSERT INTO urls(id, url, title, visit_count, last_visit_time) VALUES (?, ?, ?, ?, ?)",
            [
                (1, "https://malformed.example", "bad", 1, SQLITE_MAX_INTEGER),
                (2, "https://valid.example", "valid", 1, CHROMIUM_TIME),
            ],
        )
        conn.executemany(
            "INSERT INTO visits(id, url, visit_time) VALUES (?, ?, ?)",
            [
                (201, 1, SQLITE_MAX_INTEGER),
                (202, 2, CHROMIUM_TIME),
            ],
        )

    monkeypatch.setattr(browser.platform, "system", lambda: "Windows")
    monkeypatch.setattr(browser.Path, "home", classmethod(lambda cls: tmp_path))

    events = collector()

    assert len(events) == 1
    assert events[0]["source"] == source
    assert events[0]["raw"]["visit_id"] == 202
    assert events[0]["raw"]["url"] == "https://valid.example"


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
def test_chromium_invalid_last_visit_metadata_keeps_valid_visit(
    monkeypatch,
    tmp_path,
    collector,
    relative_path,
):
    history_path = tmp_path / relative_path
    _create_chromium_schema(history_path)

    with sqlite3.connect(history_path) as conn:
        conn.execute(
            "INSERT INTO urls(id, url, title, visit_count, last_visit_time) VALUES (?, ?, ?, ?, ?)",
            (1, "https://valid.example", "valid", 1, SQLITE_MAX_INTEGER),
        )
        conn.execute(
            "INSERT INTO visits(id, url, visit_time) VALUES (?, ?, ?)",
            (201, 1, CHROMIUM_TIME),
        )

    monkeypatch.setattr(browser.platform, "system", lambda: "Windows")
    monkeypatch.setattr(browser.Path, "home", classmethod(lambda cls: tmp_path))

    events = collector()

    assert len(events) == 1
    assert events[0]["raw"]["visit_id"] == 201
    assert events[0]["raw"]["last_visit_time"] == ""
    assert events[0]["raw"]["visit_time"] == events[0]["timestamp"]


def test_firefox_malformed_visit_timestamp_does_not_abort_profile(monkeypatch, tmp_path):
    history_path = tmp_path / ".mozilla/firefox/fixture.default/places.sqlite"
    _create_firefox_schema(history_path)

    with sqlite3.connect(history_path) as conn:
        conn.executemany(
            "INSERT INTO moz_places(id, url, title, visit_count, last_visit_date) VALUES (?, ?, ?, ?, ?)",
            [
                (1, "https://malformed.example", "bad", 1, SQLITE_MAX_INTEGER),
                (2, "https://valid.example", "valid", 1, FIREFOX_TIME),
            ],
        )
        conn.executemany(
            "INSERT INTO moz_historyvisits(id, place_id, visit_date) VALUES (?, ?, ?)",
            [
                (201, 1, SQLITE_MAX_INTEGER),
                (202, 2, FIREFOX_TIME),
            ],
        )

    monkeypatch.setattr(browser.platform, "system", lambda: "Linux")
    monkeypatch.setattr(browser.Path, "home", classmethod(lambda cls: tmp_path))

    events = browser._collect_firefox_history()

    assert len(events) == 1
    assert events[0]["source"] == "Firefox"
    assert events[0]["raw"]["visit_id"] == 202
    assert events[0]["raw"]["url"] == "https://valid.example"


def test_firefox_invalid_last_visit_metadata_keeps_valid_visit(monkeypatch, tmp_path):
    history_path = tmp_path / ".mozilla/firefox/fixture.default/places.sqlite"
    _create_firefox_schema(history_path)

    with sqlite3.connect(history_path) as conn:
        conn.execute(
            "INSERT INTO moz_places(id, url, title, visit_count, last_visit_date) VALUES (?, ?, ?, ?, ?)",
            (1, "https://valid.example", "valid", 1, SQLITE_MAX_INTEGER),
        )
        conn.execute(
            "INSERT INTO moz_historyvisits(id, place_id, visit_date) VALUES (?, ?, ?)",
            (201, 1, FIREFOX_TIME),
        )

    monkeypatch.setattr(browser.platform, "system", lambda: "Linux")
    monkeypatch.setattr(browser.Path, "home", classmethod(lambda cls: tmp_path))

    events = browser._collect_firefox_history()

    assert len(events) == 1
    assert events[0]["raw"]["visit_id"] == 201
    assert events[0]["raw"]["last_visit_time"] == ""
    assert events[0]["raw"]["visit_time"] == events[0]["timestamp"]
