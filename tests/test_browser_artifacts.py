from datetime import datetime, timezone
from pathlib import Path
import shutil
import sqlite3

import pytest

from breachscope.artifacts import browser


CHROMIUM_TIME = 13_222_310_400_000_000
FIREFOX_TIME = 1_700_000_000_000_000


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
            (1, url, "fixture", 1, CHROMIUM_TIME),
        )
        conn.execute(
            "INSERT INTO visits(id, url, visit_time) VALUES (?, ?, ?)",
            (101, 1, CHROMIUM_TIME),
        )


def _make_firefox_history(path: Path, url: str) -> None:
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
            (1, url, "fixture", 1, FIREFOX_TIME),
        )
        conn.execute(
            "INSERT INTO moz_historyvisits(id, place_id, visit_date) VALUES (?, ?, ?)",
            (101, 1, FIREFOX_TIME),
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


def test_browser_sqlite_snapshot_includes_committed_wal_rows(tmp_path):
    source_path = tmp_path / "History"
    writer = sqlite3.connect(source_path)
    try:
        assert writer.execute("PRAGMA journal_mode=WAL").fetchone()[0].lower() == "wal"
        writer.execute("PRAGMA wal_autocheckpoint=0")
        writer.execute("CREATE TABLE marker (value TEXT)")
        writer.commit()
        writer.execute("PRAGMA wal_checkpoint(TRUNCATE)")

        writer.execute("INSERT INTO marker(value) VALUES ('wal-only')")
        writer.commit()

        wal_path = Path(f"{source_path}-wal")
        assert wal_path.exists()
        assert wal_path.stat().st_size > 0

        main_only = tmp_path / "main-only.db"
        shutil.copy2(source_path, main_only)
        with sqlite3.connect(main_only) as main_only_conn:
            assert main_only_conn.execute("SELECT COUNT(*) FROM marker").fetchone()[0] == 0

        with browser._open_sqlite_snapshot(source_path) as snapshot_conn:
            rows = snapshot_conn.execute("SELECT value FROM marker").fetchall()

        assert rows == [("wal-only",)]
    finally:
        writer.close()


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
    assert event["raw"]["profile"] == "Default"
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
    valid_time = CHROMIUM_TIME

    with sqlite3.connect(history_path) as conn:
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
        conn.executemany(
            "INSERT INTO urls(id, url, title, visit_count, last_visit_time) VALUES (?, ?, ?, ?, ?)",
            [
                (1, "https://valid.example", "valid", 1, valid_time),
                (2, "https://unvisited.example", "unvisited", 0, valid_time + 1),
                (3, "https://missing-time.example", "missing", 1, None),
                (4, "https://zero-time.example", "zero", 1, 0),
            ],
        )
        conn.executemany(
            "INSERT INTO visits(id, url, visit_time) VALUES (?, ?, ?)",
            [
                (101, 1, valid_time),
                (102, 3, None),
                (103, 4, 0),
            ],
        )

    monkeypatch.setattr(browser.platform, "system", lambda: "Windows")
    monkeypatch.setattr(browser.Path, "home", classmethod(lambda cls: tmp_path))

    events = collector()

    assert [event["raw"]["url"] for event in events] == ["https://valid.example"]
    assert events[0]["raw"]["visit_count"] == 1
    assert events[0]["raw"]["visit_id"] == 101
    assert events[0]["raw"]["visit_time"] == events[0]["timestamp"]


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
def test_chromium_history_preserves_repeated_visit_rows(
    monkeypatch,
    tmp_path,
    collector,
    relative_path,
):
    history_path = tmp_path / relative_path
    history_path.parent.mkdir(parents=True, exist_ok=True)
    earlier = CHROMIUM_TIME
    later = CHROMIUM_TIME + 5_000_000

    with sqlite3.connect(history_path) as conn:
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
            (1, "https://repeat.example", "repeat", 2, later),
        )
        conn.executemany(
            "INSERT INTO visits(id, url, visit_time) VALUES (?, ?, ?)",
            [(101, 1, earlier), (102, 1, later)],
        )

    monkeypatch.setattr(browser.platform, "system", lambda: "Windows")
    monkeypatch.setattr(browser.Path, "home", classmethod(lambda cls: tmp_path))

    events = collector()

    assert [event["raw"]["visit_id"] for event in events] == [102, 101]
    assert [event["raw"]["url"] for event in events] == [
        "https://repeat.example",
        "https://repeat.example",
    ]
    assert len({event["timestamp"] for event in events}) == 2
    assert all(event["raw"]["visit_count"] == 2 for event in events)


@pytest.mark.parametrize(
    ("collector", "profile_root"),
    [
        (
            browser._collect_chrome_history,
            "AppData/Local/Google/Chrome/User Data",
        ),
        (
            browser._collect_edge_history,
            "AppData/Local/Microsoft/Edge/User Data",
        ),
    ],
)
def test_chromium_history_collects_all_profiles_with_provenance(
    monkeypatch,
    tmp_path,
    collector,
    profile_root,
):
    root = tmp_path / profile_root
    _make_chromium_history(root / "Default" / "History", "https://default.example")
    _make_chromium_history(root / "Profile 2" / "History", "https://profile2.example")

    monkeypatch.setattr(browser.platform, "system", lambda: "Windows")
    monkeypatch.setattr(browser.Path, "home", classmethod(lambda cls: tmp_path))

    events = collector()

    assert {(event["raw"]["profile"], event["raw"]["url"]) for event in events} == {
        ("Default", "https://default.example"),
        ("Profile 2", "https://profile2.example"),
    }


def test_firefox_history_skips_rows_without_source_visit_time(monkeypatch, tmp_path):
    profile_dir = tmp_path / ".mozilla" / "firefox" / "fixture.default"
    profile_dir.mkdir(parents=True)
    history_path = profile_dir / "places.sqlite"

    with sqlite3.connect(history_path) as conn:
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
        conn.executemany(
            "INSERT INTO moz_places(id, url, title, visit_count, last_visit_date) VALUES (?, ?, ?, ?, ?)",
            [
                (1, "https://valid.example", "valid", 1, FIREFOX_TIME),
                (2, "https://missing.example", "missing", 1, None),
            ],
        )
        conn.executemany(
            "INSERT INTO moz_historyvisits(id, place_id, visit_date) VALUES (?, ?, ?)",
            [(101, 1, FIREFOX_TIME), (102, 2, None)],
        )

    monkeypatch.setattr(browser.platform, "system", lambda: "Linux")
    monkeypatch.setattr(browser.Path, "home", classmethod(lambda cls: tmp_path))

    events = browser._collect_firefox_history()

    assert len(events) == 1
    event = events[0]
    assert event["raw"]["url"] == "https://valid.example"
    assert event["raw"]["profile"] == "fixture.default"
    assert event["raw"]["visit_id"] == 101
    assert "command_line" not in event
    expected_time = datetime.fromtimestamp(1_700_000_000, tz=timezone.utc).isoformat()
    assert event["timestamp"] == expected_time
    assert event["raw"]["visit_time"] == expected_time
    assert event["raw"]["last_visit_time"] == expected_time
    assert "https://missing.example" not in {item["raw"]["url"] for item in events}


def test_firefox_history_preserves_repeated_visit_rows(monkeypatch, tmp_path):
    profile_dir = tmp_path / ".mozilla" / "firefox" / "fixture.default"
    profile_dir.mkdir(parents=True)
    history_path = profile_dir / "places.sqlite"
    earlier = FIREFOX_TIME
    later = FIREFOX_TIME + 5_000_000

    with sqlite3.connect(history_path) as conn:
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
            (1, "https://repeat.example", "repeat", 2, later),
        )
        conn.executemany(
            "INSERT INTO moz_historyvisits(id, place_id, visit_date) VALUES (?, ?, ?)",
            [(101, 1, earlier), (102, 1, later)],
        )

    monkeypatch.setattr(browser.platform, "system", lambda: "Linux")
    monkeypatch.setattr(browser.Path, "home", classmethod(lambda cls: tmp_path))

    events = browser._collect_firefox_history()

    assert [event["raw"]["visit_id"] for event in events] == [102, 101]
    assert [event["raw"]["url"] for event in events] == [
        "https://repeat.example",
        "https://repeat.example",
    ]
    assert len({event["timestamp"] for event in events}) == 2
    assert all(event["raw"]["visit_count"] == 2 for event in events)


def test_firefox_history_collects_all_profiles_with_provenance(monkeypatch, tmp_path):
    profile_root = tmp_path / ".mozilla" / "firefox"
    _make_firefox_history(
        profile_root / "alpha.default-release" / "places.sqlite",
        "https://alpha.example",
    )
    _make_firefox_history(
        profile_root / "beta.profile" / "places.sqlite",
        "https://beta.example",
    )

    monkeypatch.setattr(browser.platform, "system", lambda: "Linux")
    monkeypatch.setattr(browser.Path, "home", classmethod(lambda cls: tmp_path))

    events = browser._collect_firefox_history()

    assert {(event["raw"]["profile"], event["raw"]["url"]) for event in events} == {
        ("alpha.default-release", "https://alpha.example"),
        ("beta.profile", "https://beta.example"),
    }
