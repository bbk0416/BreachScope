from __future__ import annotations

from pathlib import Path
from typing import Optional, List
import tempfile
import json
import sys
import subprocess
import platform
import logging
import os

logger = logging.getLogger(__name__)


def _extract_from_xml(xml_text: str) -> dict:
    try:
        import xml.etree.ElementTree as ET
        root = ET.fromstring(xml_text)
        ns = "{http://schemas.microsoft.com/win/2004/08/events/event}"
        get = lambda p: (root.find(p) or {}).get("SystemTime") if p.endswith("TimeCreated") else None
        sys_node = root.find(f"{ns}System")
        ev_node = root.find(f"{ns}EventData") or root.find(f"{ns}UserData")
        ts = ""
        if sys_node is not None:
            time_node = sys_node.find(f"{ns}TimeCreated")
            if time_node is not None:
                ts = time_node.attrib.get("SystemTime", "")
            computer = (sys_node.find(f"{ns}Computer").text if sys_node.find(f"{ns}Computer") is not None else "")
            provider = (sys_node.find(f"{ns}Provider").attrib.get("Name", "") if sys_node.find(f"{ns}Provider") is not None else "")
            event_id = (sys_node.find(f"{ns}EventID").text if sys_node.find(f"{ns}EventID") is not None else "")
            level = (sys_node.find(f"{ns}Level").text if sys_node.find(f"{ns}Level") is not None else "")
        else:
            computer = provider = event_id = level = ""

        cmdline = user = ""
        if ev_node is not None:
            # Look for Data elements with Name attributes (common in Windows logs)
            for d in ev_node.findall(f"{ns}Data"):
                name = d.attrib.get("Name", "").lower()
                text = (d.text or "")
                if not text:
                    continue
                if not cmdline and name in ("commandline", "processcommandline"):
                    cmdline = text
                if not user and name in ("subjectuserName".lower(), "targetuserName".lower(), "user"):
                    user = text

        return {
            "timestamp": ts,
            "host": computer or "",
            "source": provider or "WindowsEventLog",
            "event_id": event_id or "",
            "level": level or "",
            "user": user or "",
            "command_line": cmdline or "",
        }
    except Exception:
        return {}


def convert_evtx_dir(input_dir: Path) -> Optional[Path]:
    """Convert all .evtx files under input_dir into JSONL files in a temp folder.
    Returns the new directory path or None if conversion failed or none found.
    """
    evtx_files = list(input_dir.rglob("*.evtx"))
    if not evtx_files:
        return None
    try:
        from Evtx.Evtx import Evtx  # python-evtx
    except Exception:
        print("[ingest] python-evtx가 설치되어 있지 않아 .evtx 변환을 건너뜁니다.", file=sys.stderr)
        return None

    out_dir = Path(tempfile.mkdtemp(prefix="breachscope_evtx_"))
    for fp in evtx_files:
        out_path = out_dir / (fp.stem + ".jsonl")
        with open(fp, "rb") as f, out_path.open("w", encoding="utf-8") as out:
            try:
                with Evtx(f) as log:
                    for record in log.records():
                        data = _extract_from_xml(record.xml())
                        if data:
                            out.write(json.dumps(data, ensure_ascii=False) + "\n")
            except Exception:
                # If a file fails, skip it but continue others
                continue
    return out_dir


def collect_windows_logs(
    output_dir: Optional[Path] = None,
    log_names: Optional[List[str]] = None,
    hours: Optional[int] = None,
) -> Optional[Path]:
    """
    Windows 이벤트 로그를 자동으로 수집하여 EVTX 파일로 저장합니다.

    Args:
        output_dir: EVTX 파일을 저장할 디렉토리 (None이면 임시 디렉토리 사용)
        log_names: 수집할 이벤트 로그 이름 목록 (None이면 기본 로그 수집)
        hours: 최근 N시간의 이벤트만 수집 (None이면 전체)

    Returns:
        수집된 EVTX 파일이 있는 디렉토리 경로, 실패 시 None

    Examples:
        >>> # 기본 로그 수집 (Security, System, Application)
        >>> collect_windows_logs()

        >>> # 특정 로그만 수집
        >>> collect_windows_logs(log_names=["Security", "System"])

        >>> # 최근 24시간만 수집
        >>> collect_windows_logs(hours=24)
    """
    if platform.system() != "Windows":
        logger.error("Windows 이벤트 로그 수집은 Windows 시스템에서만 가능합니다.")
        return None

    # wevtutil.exe 경로 확인
    wevtutil = "wevtutil.exe"
    try:
        result = subprocess.run(
            [wevtutil, "el"],
            capture_output=True,
            text=True,
            timeout=10,
        )
        if result.returncode != 0:
            logger.error(f"wevtutil.exe 실행 실패: {result.stderr}")
            return None
    except FileNotFoundError:
        logger.error("wevtutil.exe를 찾을 수 없습니다. Windows 시스템이 아닙니다.")
        return None
    except Exception as e:
        logger.error(f"wevtutil.exe 확인 중 오류: {e}")
        return None

    # 출력 디렉토리 설정 (안전한 임시 디렉토리 생성)
    if output_dir is None:
        # 여러 방법으로 임시 디렉토리 생성 시도
        import time
        import random

        # 프로젝트 루트 찾기 (breachscope 패키지 기준)
        project_root = None
        try:
            import breachscope
            if hasattr(breachscope, '__file__'):
                project_root = Path(breachscope.__file__).parent.parent
        except:
            pass

        temp_dirs = [
            # 방법 1: 프로젝트 디렉토리 내 임시 폴더 (가장 안전)
            lambda: (project_root or Path.cwd()) / ".breachscope_temp" / f"collect_{os.getpid()}_{int(time.time())}_{random.randint(1000, 9999)}",
            # 방법 2: 현재 작업 디렉토리
            lambda: Path.cwd() / ".breachscope_temp" / f"collect_{os.getpid()}_{int(time.time())}_{random.randint(1000, 9999)}",
            # 방법 3: 사용자 홈 디렉토리
            lambda: Path.home() / ".breachscope_temp" / f"collect_{os.getpid()}_{int(time.time())}_{random.randint(1000, 9999)}",
            # 방법 4: 표준 tempfile.mkdtemp (최후의 수단)
            lambda: Path(tempfile.mkdtemp(prefix="breachscope_collect_")),
        ]

        output_dir = None
        for idx, create_dir in enumerate(temp_dirs, 1):
            try:
                candidate_dir = create_dir()
                if not candidate_dir.exists():
                    candidate_dir.mkdir(parents=True, exist_ok=True)

                # 쓰기 권한 확인
                test_file = candidate_dir / ".test_write"
                test_file.write_text("test")
                test_file.unlink()

                output_dir = candidate_dir
                logger.info(f"임시 디렉토리 생성 성공 (방법 {idx}): {output_dir}")
                break
            except (PermissionError, OSError) as e:
                logger.warning(f"임시 디렉토리 생성 실패 (방법 {idx}): {e}, 다음 방법 시도...")
                # 실패한 디렉토리 정리 시도
                try:
                    if candidate_dir.exists():
                        candidate_dir.rmdir()
                except:
                    pass
                continue

        if output_dir is None:
            error_msg = "모든 임시 디렉토리 생성 방법 실패. 관리자 권한으로 실행하거나 디스크 공간을 확인하세요."
            logger.error(error_msg)
            return None
    else:
        output_dir = Path(output_dir)
        try:
            # 디렉토리가 이미 존재하는지 확인
            if output_dir.exists():
                # 쓰기 권한 확인
                test_file = output_dir / ".test_write"
                try:
                    test_file.write_text("test")
                    test_file.unlink()
                except (PermissionError, OSError) as e:
                    logger.error(f"디렉토리 쓰기 권한 없음: {output_dir} - {e}")
                    # 자체 임시 디렉토리 사용 (여러 방법 시도)
                    import time
                    import random
                    project_root = None
                    try:
                        import breachscope
                        if hasattr(breachscope, '__file__'):
                            project_root = Path(breachscope.__file__).parent.parent
                    except:
                        pass

                    temp_dirs = [
                        lambda: (project_root or Path.cwd()) / ".breachscope_temp" / f"collect_{os.getpid()}_{int(time.time())}_{random.randint(1000, 9999)}",
                        lambda: Path.cwd() / ".breachscope_temp" / f"collect_{os.getpid()}_{int(time.time())}_{random.randint(1000, 9999)}",
                        lambda: Path.home() / ".breachscope_temp" / f"collect_{os.getpid()}_{int(time.time())}_{random.randint(1000, 9999)}",
                        lambda: Path(tempfile.mkdtemp(prefix="breachscope_collect_")),
                    ]
                    output_dir = None
                    for create_dir in temp_dirs:
                        try:
                            candidate_dir = create_dir()
                            if not candidate_dir.exists():
                                candidate_dir.mkdir(parents=True, exist_ok=True)
                            test_file = candidate_dir / ".test_write"
                            test_file.write_text("test")
                            test_file.unlink()
                            output_dir = candidate_dir
                            logger.info(f"대체 디렉토리 사용: {output_dir}")
                            break
                        except:
                            continue
                    if output_dir is None:
                        logger.error("대체 디렉토리 생성도 실패")
                        return None
            else:
                # 디렉토리 생성 시도
                output_dir.mkdir(parents=True, exist_ok=True)
                # 쓰기 권한 확인
                test_file = output_dir / ".test_write"
                test_file.write_text("test")
                test_file.unlink()
        except (PermissionError, OSError) as e:
            logger.error(f"디렉토리 생성/권한 확인 실패: {output_dir} - {e}")
            # 자체 임시 디렉토리 사용
            try:
                output_dir = Path(tempfile.mkdtemp(prefix="breachscope_collect_"))
                logger.info(f"대체 디렉토리 사용: {output_dir}")
            except Exception:
                logger.error("대체 디렉토리 생성도 실패")
                return None

    # 기본 로그 목록
    default_logs = [
        "Security",
        "System",
        "Application",
        "Microsoft-Windows-PowerShell/Operational",
    ]

    if log_names is None:
        log_names = default_logs

    # 시간 필터 생성
    time_filter = ""
    if hours is not None:
        from datetime import datetime, timedelta
        end_time = datetime.now()
        start_time = end_time - timedelta(hours=hours)
        # wevtutil 날짜 형식: YYYY-MM-DDTHH:MM:SS
        time_filter = f"*[System[TimeCreated[@SystemTime>='{start_time.isoformat()}']]]"

    collected_files = []
    failed_logs = []

    for log_name in log_names:
        # 로그 이름에서 파일명으로 사용할 수 없는 문자 제거
        safe_name = log_name.replace("/", "_").replace("\\", "_").replace(":", "_")
        evtx_path = output_dir / f"{safe_name}.evtx"

        try:
            # wevtutil epl 명령어로 이벤트 로그 내보내기
            cmd = [wevtutil, "epl", log_name, str(evtx_path)]
            if time_filter:
                cmd.extend(["/q", f"/c:{time_filter}"])

            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=300,  # 5분 타임아웃
            )

            if result.returncode == 0 and evtx_path.exists() and evtx_path.stat().st_size > 0:
                collected_files.append(evtx_path)
                logger.info(f"✓ {log_name} 수집 완료: {evtx_path} ({evtx_path.stat().st_size} bytes)")
            else:
                failed_logs.append(log_name)
                if evtx_path.exists():
                    try:
                        evtx_path.unlink()  # 빈 파일 삭제
                    except (PermissionError, OSError):
                        pass  # 삭제 실패해도 계속 진행

                error_msg = result.stderr or result.stdout or "알 수 없는 오류"
                # 권한 오류인지 확인
                if "Access is denied" in error_msg or "Permission" in error_msg or "권한" in error_msg:
                    logger.warning(f"✗ {log_name} 수집 실패: 권한 부족 (관리자 권한 필요)")
                else:
                    logger.warning(f"✗ {log_name} 수집 실패: {error_msg}")

        except subprocess.TimeoutExpired:
            failed_logs.append(log_name)
            logger.error(f"✗ {log_name} 수집 타임아웃 (5분 초과)")
        except PermissionError as e:
            failed_logs.append(log_name)
            logger.error(f"✗ {log_name} 수집 중 권한 오류: {e} (관리자 권한 필요)")
        except Exception as e:
            failed_logs.append(log_name)
            logger.error(f"✗ {log_name} 수집 중 오류: {e}")

    if not collected_files:
        logger.error("수집된 이벤트 로그 파일이 없습니다.")
        return None

    logger.info(f"총 {len(collected_files)}개 로그 파일 수집 완료: {output_dir}")
    if failed_logs:
        logger.warning(f"수집 실패한 로그: {', '.join(failed_logs)}")

    return output_dir
