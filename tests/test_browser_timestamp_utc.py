import sqlite3

import pytest

from breachscope.artifacts import browser


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
def test_chromium_history_emits_explicit_utc_timestamp(
    monkeypatch,
    tmp_path,
    collector,
    relative_path,
):
    history_path = tmp_path / relative_path
    history_path.parent.mkdir(parents=True, exist_ok=True)

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
        conn.execute(
            "INSERT INTO urls(url, title, visit_count, last_visit_time) VALUES (?, ?, ?, ?)",
            ("https://utc.example", "utc", 1, 13_222_310_400_000_000),
        )

    monkeypatch.setattr(browser.platform, "system", lambda: "Windows")
    monkeypatch.setattr(browser.Path, "home", classmethod(lambda cls: tmp_path))

    events = collector()

    assert len(events) == 1
    assert events[0]["timestamp"] == "2020-01-01T00:00:00+00:00"
    assert events[0]["raw"]["last_visit_time"] == "2020-01-01T00:00:00+00:00"


def test_firefox_history_emits_explicit_utc_timestamp(monkeypatch, tmp_path):
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
        conn.execute(
            "INSERT INTO moz_places(url, title, visit_count, last_visit_date) VALUES (?, ?, ?, ?)",
            ("https://utc.example", "utc", 1, 1_700_000_000_000_000),
        )

    monkeypatch.setattr(browser.platform, "system", lambda: "Linux")
    monkeypatch.setattr(browser.Path, "home", classmethod(lambda cls: tmp_path))

    events = browser._collect_firefox_history()

    assert len(events) == 1
    assert events[0]["timestamp"] == "2023-11-14T22:13:20+00:00"
    assert events[0]["raw"]["last_visit_time"] == "2023-11-14T22:13:20+00:00"
