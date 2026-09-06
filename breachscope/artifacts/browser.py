"""
브라우저 이력 수집 모듈
Chrome, Edge, Firefox 등의 브라우저 기록을 수집합니다.
"""
from contextlib import contextmanager
import json
import logging
import platform
import shutil
import sqlite3
import tempfile
from datetime import datetime
from pathlib import Path
from typing import Dict, Iterator, List, Optional

logger = logging.getLogger(__name__)


@contextmanager
def _open_sqlite_snapshot(source_path: Path) -> Iterator[sqlite3.Connection]:
    """잠길 수 있는 브라우저 DB를 안전한 임시 복사본으로 열고 정리합니다."""
    with tempfile.TemporaryDirectory(prefix="breachscope_browser_") as temp_dir:
        temp_db = Path(temp_dir) / "history.db"
        shutil.copy2(source_path, temp_db)
        conn = sqlite3.connect(str(temp_db))
        try:
            yield conn
        finally:
            conn.close()


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
        history_path = Path.home() / "AppData/Local/Google/Chrome/User Data/Default/History"
    elif platform.system() == "Darwin":  # macOS
        history_path = Path.home() / "Library/Application Support/Google/Chrome/Default/History"
    else:  # Linux
        history_path = Path.home() / ".config/google-chrome/Default/History"

    if not history_path.exists():
        logger.debug(f"Chrome 이력 파일을 찾을 수 없습니다: {history_path}")
        return events

    try:
        # Chrome History는 SQLite 데이터베이스이며 파일이 잠겨있을 수 있으므로
        # 전용 임시 디렉토리의 복사본을 열어 분석합니다.
        with _open_sqlite_snapshot(history_path) as conn:
            cursor = conn.cursor()

            # 방문 기록 조회
            cursor.execute("""
                SELECT url, title, visit_count, last_visit_time
                FROM urls
                ORDER BY last_visit_time DESC
                LIMIT 1000
            """)

            for row in cursor.fetchall():
                url, title, visit_count, last_visit_time = row

                # Chrome 타임스탬프는 1601-01-01부터의 마이크로초
                # Unix 타임스탬프로 변환
                chrome_epoch = datetime(1601, 1, 1)
                unix_timestamp = chrome_epoch.timestamp() + (last_visit_time / 1000000)
                visit_time = datetime.fromtimestamp(unix_timestamp)

                event = {
                    "timestamp": visit_time.isoformat(),
                    "host": "",
                    "source": "Chrome",
                    "event_id": "browser_visit",
                    "event_type": "web_activity",
                    "user": "",
                    "command_line": url,
                    "raw": {
                        "url": url,
                        "title": title,
                        "visit_count": visit_count,
                        "last_visit_time": visit_time.isoformat(),
                    },
                }
                events.append(event)

    except Exception as e:
        logger.debug(f"Chrome 이력 파싱 실패: {e}")

    return events


def _collect_edge_history() -> List[Dict]:
    """Edge 브라우저 이력 수집 (Chrome과 유사)"""
    events = []

    if platform.system() == "Windows":
        history_path = Path.home() / "AppData/Local/Microsoft/Edge/User Data/Default/History"
    else:
        logger.debug("Edge는 Windows에서만 지원됩니다.")
        return events

    if not history_path.exists():
        logger.debug(f"Edge 이력 파일을 찾을 수 없습니다: {history_path}")
        return events

    # Chrome과 동일한 방식으로 처리
    try:
        with _open_sqlite_snapshot(history_path) as conn:
            cursor = conn.cursor()

            cursor.execute("""
                SELECT url, title, visit_count, last_visit_time
                FROM urls
                ORDER BY last_visit_time DESC
                LIMIT 1000
            """)

            for row in cursor.fetchall():
                url, title, visit_count, last_visit_time = row

                chrome_epoch = datetime(1601, 1, 1)
                unix_timestamp = chrome_epoch.timestamp() + (last_visit_time / 1000000)
                visit_time = datetime.fromtimestamp(unix_timestamp)

                event = {
                    "timestamp": visit_time.isoformat(),
                    "host": "",
                    "source": "Edge",
                    "event_id": "browser_visit",
                    "event_type": "web_activity",
                    "user": "",
                    "command_line": url,
                    "raw": {
                        "url": url,
                        "title": title,
                        "visit_count": visit_count,
                        "last_visit_time": visit_time.isoformat(),
                    },
                }
                events.append(event)

    except Exception as e:
        logger.debug(f"Edge 이력 파싱 실패: {e}")

    return events


def _collect_firefox_history() -> List[Dict]:
    """Firefox 브라우저 이력 수집"""
    events = []

    if platform.system() == "Windows":
        profile_path = Path.home() / "AppData/Roaming/Mozilla/Firefox/Profiles"
    elif platform.system() == "Darwin":  # macOS
        profile_path = Path.home() / "Library/Application Support/Firefox/Profiles"
    else:  # Linux
        profile_path = Path.home() / ".mozilla/firefox"

    if not profile_path.exists():
        logger.debug(f"Firefox 프로파일을 찾을 수 없습니다: {profile_path}")
        return events

    # 기본 프로파일 찾기
    profiles = list(profile_path.glob("*.default*"))
    if not profiles:
        logger.debug("Firefox 기본 프로파일을 찾을 수 없습니다.")
        return events

    history_path = profiles[0] / "places.sqlite"
    if not history_path.exists():
        logger.debug(f"Firefox 이력 파일을 찾을 수 없습니다: {history_path}")
        return events

    try:
        with _open_sqlite_snapshot(history_path) as conn:
            cursor = conn.cursor()

            # Firefox places.sqlite 구조
            cursor.execute("""
                SELECT url, title, visit_count, last_visit_date/1000000 as visit_time
                FROM moz_places
                WHERE visit_count > 0
                  AND last_visit_date IS NOT NULL
                ORDER BY last_visit_date DESC
                LIMIT 1000
            """)

            for row in cursor.fetchall():
                url, title, visit_count, visit_timestamp = row

                if visit_timestamp is None:
                    logger.debug("Firefox 방문시각이 없는 이력 행은 건너뜁니다.")
                    continue
                visit_time = datetime.fromtimestamp(visit_timestamp)

                event = {
                    "timestamp": visit_time.isoformat(),
                    "host": "",
                    "source": "Firefox",
                    "event_id": "browser_visit",
                    "event_type": "web_activity",
                    "user": "",
                    "command_line": url,
                    "raw": {
                        "url": url,
                        "title": title,
                        "visit_count": visit_count,
                        "last_visit_time": visit_time.isoformat(),
                    },
                }
                events.append(event)

    except Exception as e:
        logger.debug(f"Firefox 이력 파싱 실패: {e}")

    return events
