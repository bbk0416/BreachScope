from datetime import datetime
import sqlite3

from breachscope.artifacts import browser


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
    expected_time = datetime.fromtimestamp(1_700_000_000).isoformat()
    assert event["timestamp"] == expected_time
    assert event["raw"]["last_visit_time"] == expected_time
    assert "https://missing.example" not in {item["raw"]["url"] for item in events}
