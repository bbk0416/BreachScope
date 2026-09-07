"""
브라우저 이력 수집 모듈
Chrome, Edge, Firefox 등의 브라우저 기록을 수집합니다.
"""
from contextlib import contextmanager
import json
import logging
import platform
import sqlite3
import tempfile
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Dict, Iterator, List, Optional

logger = logging.getLogger(__name__)


@contextmanager
def _open_sqlite_snapshot(source_path: Path) -> Iterator[sqlite3.Connection]:
    """브라우저 DB를 read-only로 열어 WAL까지 포함한 일관된 임시 snapshot을 만듭니다."""
    with tempfile.TemporaryDirectory(prefix="breachscope_browser_") as temp_dir:
        temp_db = Path(temp_dir) / "history.db"
        source_uri = f"{source_path.resolve().as_uri()}?mode=ro"

        source_conn = sqlite3.connect(source_uri, uri=True)
        try:
            snapshot_conn = sqlite3.connect(str(temp_db))
            try:
                source_conn.backup(snapshot_conn)
            finally:
                snapshot_conn.close()
        finally:
            source_conn.close()

        conn = sqlite3.connect(str(temp_db))
        try:
            yield conn
        finally:
            conn.close()


def _chromium_visit_time_utc(last_visit_time: int) -> datetime:
    """Chromium WebKit microseconds since 1601-01-01 UTC -> aware UTC datetime."""
    return datetime(1601, 1, 1, tzinfo=timezone.utc) + timedelta(
        microseconds=last_visit_time
    )


def _firefox_visit_time_utc(visit_timestamp: float) -> datetime:
    """Firefox Unix timestamp seconds -> aware UTC datetime."""
    return datetime.fromtimestamp(visit_timestamp, tz=timezone.utc)


def _chromium_visit_time_iso_or_empty(value: object) -> str:
    """잘못된 Chromium timestamp 하나가 프로필 전체 수집을 중단하지 않게 합니다."""
    if not value:
        return ""
    try:
        return _chromium_visit_time_utc(value).isoformat()  # type: ignore[arg-type]
    except (OverflowError, OSError, TypeError, ValueError):
        return ""


def _firefox_visit_time_iso_or_empty(value: object) -> str:
    """잘못된 Firefox timestamp 하나가 프로필 전체 수집을 중단하지 않게 합니다."""
    if not value:
        return ""
    try:
        return _firefox_visit_time_utc(value).isoformat()  # type: ignore[arg-type]
    except (OverflowError, OSError, TypeError, ValueError):
        return ""


def _profile_databases(profile_root: Path, database_name: str) -> List[Path]:
    """프로필 루트 바로 아래에 존재하는 브라우저 DB를 결정적인 순서로 반환합니다."""
    return sorted(
        path
        for path in profile_root.glob(f"*/{database_name}")
        if path.is_file()
    )


def collect_browser_history(
    output_dir: Optional[Path] = None,
    browsers: Optional[List[str]] = None,
) -> List[Dict]:
    """
    브라우저 이력 수집

    Args:
        output_dir: 출력 디렉토리 (사용하지 않음, 호환성용)
        browsers: 수집할 브라우저 목록 (None이면 모두 수집)

    Returns:
        정규화된 이벤트 목록
    """
    if browsers is None:
        browsers = ["chrome", "edge", "firefox"]

    events = []

    for browser in browsers:
        try:
            browser_events = _collect_browser(browser)
            events.extend(browser_events)
        except Exception as e:
            logger.debug(f"{browser} 브라우저 이력 수집 실패: {e}")
            continue

    logger.info(f"브라우저 이벤트 {len(events)}개 수집 완료")
    return events


def _collect_browser(browser: str) -> List[Dict]:
    """특정 브라우저의 이력 수집"""
    events = []

    if browser.lower() == "chrome":
        events.extend(_collect_chrome_history())
    elif browser.lower() == "edge":
        events.extend(_collect_edge_history())
    elif browser.lower() == "firefox":
        events.extend(_collect_firefox_history())

    return events


def _collect_chrome_history() -> List[Dict]:
    """Chrome 브라우저 이력 수집"""
    events = []

    if platform.system() == "Windows":
        profile_root = Path.home() / "AppData/Local/Google/Chrome/User Data"
    elif platform.system() == "Darwin":  # macOS
        profile_root = Path.home() / "Library/Application Support/Google/Chrome"
    else:  # Linux
        profile_root = Path.home() / ".config/google-chrome"

    history_paths = _profile_databases(profile_root, "History")
    if not history_paths:
        logger.debug(f"Chrome 이력 파일을 찾을 수 없습니다: {profile_root}")
        return events

    for history_path in history_paths:
        profile_name = history_path.parent.name
        try:
            # Chrome History는 SQLite 데이터베이스이며 파일이 잠겨있을 수 있으므로
            # 전용 임시 디렉토리의 복사본을 열어 분석합니다.
            with _open_sqlite_snapshot(history_path) as conn:
                cursor = conn.cursor()

                # urls는 URL별 집계이고 visits가 개별 방문 행입니다. DFIR 타임라인은
                # 개별 visits.visit_time을 기준으로 구성해 이전 방문을 잃지 않습니다.
                cursor.execute("""
                    SELECT
                        visits.id,
                        urls.url,
                        urls.title,
                        urls.visit_count,
                        visits.visit_time,
                        urls.last_visit_time
                    FROM visits
                    JOIN urls ON urls.id = visits.url
                    WHERE visits.visit_time IS NOT NULL
                      AND visits.visit_time > 0
                    ORDER BY visits.visit_time DESC
                """)

                for row in cursor:
                    (
                        visit_id,
                        url,
                        title,
                        visit_count,
                        visit_timestamp,
                        last_visit_timestamp,
                    ) = row

                    visit_time = _chromium_visit_time_iso_or_empty(visit_timestamp)
                    if not visit_time:
                        logger.debug(
                            f"Chrome 잘못된 방문 시각 건너뜀 ({profile_name}, visit_id={visit_id})"
                        )
                        continue

                    last_visit_time = _chromium_visit_time_iso_or_empty(
                        last_visit_timestamp
                    )

                    event = {
                        "timestamp": visit_time,
                        "host": "",
                        "source": "Chrome",
                        "event_id": "browser_visit",
                        "event_type": "web_activity",
                        "user": "",
                        "raw": {
                            "url": url,
                            "title": title,
                            "visit_count": visit_count,
                            "visit_id": visit_id,
                            "visit_time": visit_time,
                            "last_visit_time": last_visit_time,
                            "profile": profile_name,
                        },
                    }
                    events.append(event)

        except Exception as e:
            logger.debug(f"Chrome 프로필 이력 파싱 실패 ({profile_name}): {e}")

    return events


def _collect_edge_history() -> List[Dict]:
    """Edge 브라우저 이력 수집 (Chrome과 유사)"""
    events = []

    if platform.system() == "Windows":
        profile_root = Path.home() / "AppData/Local/Microsoft/Edge/User Data"
    else:
        logger.debug("Edge는 Windows에서만 지원됩니다.")
        return events

    history_paths = _profile_databases(profile_root, "History")
    if not history_paths:
        logger.debug(f"Edge 이력 파일을 찾을 수 없습니다: {profile_root}")
        return events

    for history_path in history_paths:
        profile_name = history_path.parent.name
        try:
            with _open_sqlite_snapshot(history_path) as conn:
                cursor = conn.cursor()

                cursor.execute("""
                    SELECT
                        visits.id,
                        urls.url,
                        urls.title,
                        urls.visit_count,
                        visits.visit_time,
                        urls.last_visit_time
                    FROM visits
                    JOIN urls ON urls.id = visits.url
                    WHERE visits.visit_time IS NOT NULL
                      AND visits.visit_time > 0
                    ORDER BY visits.visit_time DESC
                """)

                for row in cursor:
                    (
                        visit_id,
                        url,
                        title,
                        visit_count,
                        visit_timestamp,
                        last_visit_timestamp,
                    ) = row

                    visit_time = _chromium_visit_time_iso_or_empty(visit_timestamp)
                    if not visit_time:
                        logger.debug(
                            f"Edge 잘못된 방문 시각 건너뜀 ({profile_name}, visit_id={visit_id})"
                        )
                        continue

                    last_visit_time = _chromium_visit_time_iso_or_empty(
                        last_visit_timestamp
                    )

                    event = {
                        "timestamp": visit_time,
                        "host": "",
                        "source": "Edge",
                        "event_id": "browser_visit",
                        "event_type": "web_activity",
                        "user": "",
                        "raw": {
                            "url": url,
                            "title": title,
                            "visit_count": visit_count,
                            "visit_id": visit_id,
                            "visit_time": visit_time,
                            "last_visit_time": last_visit_time,
                            "profile": profile_name,
                        },
                    }
                    events.append(event)

        except Exception as e:
            logger.debug(f"Edge 프로필 이력 파싱 실패 ({profile_name}): {e}")

    return events


def _collect_firefox_history() -> List[Dict]:
    """Firefox 브라우저 이력 수집"""
    events = []

    if platform.system() == "Windows":
        profile_root = Path.home() / "AppData/Roaming/Mozilla/Firefox/Profiles"
    elif platform.system() == "Darwin":  # macOS
        profile_root = Path.home() / "Library/Application Support/Firefox/Profiles"
    else:  # Linux
        profile_root = Path.home() / ".mozilla/firefox"

    history_paths = _profile_databases(profile_root, "places.sqlite")
    if not history_paths:
        logger.debug(f"Firefox 이력 파일을 찾을 수 없습니다: {profile_root}")
        return events

    for history_path in history_paths:
        profile_name = history_path.parent.name
        try:
            with _open_sqlite_snapshot(history_path) as conn:
                cursor = conn.cursor()

                # moz_places는 URL별 집계이고 moz_historyvisits가 개별 방문 행입니다.
                cursor.execute("""
                    SELECT
                        moz_historyvisits.id,
                        moz_places.url,
                        moz_places.title,
                        moz_places.visit_count,
                        moz_historyvisits.visit_date / 1000000.0 AS visit_time,
                        moz_places.last_visit_date / 1000000.0 AS last_visit_time
                    FROM moz_historyvisits
                    JOIN moz_places ON moz_places.id = moz_historyvisits.place_id
                    WHERE moz_historyvisits.visit_date IS NOT NULL
                      AND moz_historyvisits.visit_date > 0
                    ORDER BY moz_historyvisits.visit_date DESC
                """)

                for row in cursor:
                    (
                        visit_id,
                        url,
                        title,
                        visit_count,
                        visit_timestamp,
                        last_visit_timestamp,
                    ) = row

                    visit_time = _firefox_visit_time_iso_or_empty(visit_timestamp)
                    if not visit_time:
                        logger.debug(
                            f"Firefox 잘못된 방문 시각 건너뜀 ({profile_name}, visit_id={visit_id})"
                        )
                        continue

                    last_visit_time = _firefox_visit_time_iso_or_empty(
                        last_visit_timestamp
                    )

                    event = {
                        "timestamp": visit_time,
                        "host": "",
                        "source": "Firefox",
                        "event_id": "browser_visit",
                        "event_type": "web_activity",
                        "user": "",
                        "raw": {
                            "url": url,
                            "title": title,
                            "visit_count": visit_count,
                            "visit_id": visit_id,
                            "visit_time": visit_time,
                            "last_visit_time": last_visit_time,
                            "profile": profile_name,
                        },
                    }
                    events.append(event)

        except Exception as e:
            logger.debug(f"Firefox 프로필 이력 파싱 실패 ({profile_name}): {e}")

    return events
