from pathlib import Path
import sqlite3

import pytest

from breachscope.artifacts import browser


CHROMIUM_TIME = 13_222_310_400_000_000
FIREFOX_TIME = 1_700_000_000_000_000
VISIT_ROWS = 1001


def _make_chromium_history(path: Path) -> None:
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
        conn.execute(
            "INSERT INTO urls(id, url, title, visit_count, last_visit_time) VALUES (?, ?, ?, ?, ?)",
            (
                1,
                "https://complete.example",
                "complete",
                VISIT_ROWS,
                CHROMIUM_TIME + VISIT_ROWS - 1,
            ),
        )
        conn.executemany(
            "INSERT INTO visits(id, url, visit_time) VALUES (?, ?, ?)",
            [
                (visit_id, 1, CHROMIUM_TIME + visit_id - 1)
                for visit_id in range(1, VISIT_ROWS + 1)
            ],
        )


def _make_firefox_history(path: Path) -> None:
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
        conn.execute(
            "INSERT INTO moz_places(id, url, title, visit_count, last_visit_date) VALUES (?, ?, ?, ?, ?)",
            (
                1,
                "https://complete.example",
                "complete",
                VISIT_ROWS,
                FIREFOX_TIME + VISIT_ROWS - 1,
            ),
        )
        conn.executemany(
            "INSERT INTO moz_historyvisits(id, place_id, visit_date) VALUES (?, ?, ?)",
            [
                (visit_id, 1, FIREFOX_TIME + visit_id - 1)
                for visit_id in range(1, VISIT_ROWS + 1)
            ],
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
def test_chromium_history_preserves_visits_beyond_legacy_1000_cap(
    monkeypatch,
    tmp_path,
    collector,
    relative_path,
    source,
):
    _make_chromium_history(tmp_path / relative_path)

    monkeypatch.setattr(browser.platform, "system", lambda: "Windows")
    monkeypatch.setattr(browser.Path, "home", classmethod(lambda cls: tmp_path))

    events = collector()

    assert len(events) == VISIT_ROWS
    assert events[0]["source"] == source
    assert events[0]["raw"]["visit_id"] == VISIT_ROWS
    assert events[-1]["raw"]["visit_id"] == 1
    assert {event["raw"]["visit_id"] for event in events} == set(
        range(1, VISIT_ROWS + 1)
    )


def test_firefox_history_preserves_visits_beyond_legacy_1000_cap(
    monkeypatch,
    tmp_path,
):
    history_path = (
        tmp_path
        / ".mozilla"
        / "firefox"
        / "fixture.default"
        / "places.sqlite"
    )
    _make_firefox_history(history_path)

    monkeypatch.setattr(browser.platform, "system", lambda: "Linux")
    monkeypatch.setattr(browser.Path, "home", classmethod(lambda cls: tmp_path))

    events = browser._collect_firefox_history()

    assert len(events) == VISIT_ROWS
    assert events[0]["source"] == "Firefox"
    assert events[0]["raw"]["visit_id"] == VISIT_ROWS
    assert events[-1]["raw"]["visit_id"] == 1
    assert {event["raw"]["visit_id"] for event in events} == set(
        range(1, VISIT_ROWS + 1)
    )
