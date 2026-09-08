"""
분석 서비스 레이어
비즈니스 로직 처리
"""
import os
import shutil
from pathlib import Path
from typing import List, Optional, Dict, Any
from .upload_policy import (
    UploadBudget,
    UploadLimitError,
    stream_upload_to_path,
    validate_file_count,
)
from .path_boundary import is_safe_managed_delete
import logging
import json

from breachscope.pipeline import Pipeline
from breachscope.ingest import convert_evtx_dir, collect_windows_logs
from breachscope.config import Config
from api.services.workdir_service import WorkDirectoryService
from api.services.report_preview import build_preview
from api.services.case_history import CaseHistoryService

logger = logging.getLogger(__name__)

MAX_UPLOAD_NAME_COLLISION_RETRIES = 8


def _unique_upload_path(upload_dir: Path, safe_name: str, reserved_paths: List[Path]) -> Path:
    """Return a basename-preserving path without overwriting existing evidence."""
    upload_dir = Path(upload_dir)
    safe_name = Path(safe_name).name
    if not safe_name:
        raise ValueError("upload filename must have a basename")

    occupied = {Path(path).name.casefold() for path in reserved_paths}
    if upload_dir.exists():
        try:
            occupied.update(path.name.casefold() for path in upload_dir.iterdir())
        except OSError:
            # The exclusive-create writer remains the final no-overwrite guard.
            # If collision discovery is unavailable, retries are bounded below.
            pass

    if safe_name.casefold() not in occupied:
        return upload_dir / safe_name

    path_name = Path(safe_name)
    suffixes = "".join(path_name.suffixes)
    stem = safe_name[:-len(suffixes)] if suffixes else safe_name
    index = 2
    while True:
        candidate_name = f"{stem}_{index}{suffixes}"
        if candidate_name.casefold() not in occupied:
            return upload_dir / candidate_name
        index += 1


def _cleanup_failed_analysis(
    work: Path,
    work_dir: Optional[str],
    created_upload_paths: List[Path],
) -> None:
    """Remove request-created evidence without deleting a user-supplied workdir."""
    for uploaded_path in created_upload_paths:
        try:
            uploaded_path.unlink(missing_ok=True)
        except OSError:
            logger.warning("실패한 분석의 업로드 파일 정리 실패: %s", uploaded_path)

    if work_dir and str(work_dir).strip():
        return

    try:
        if work.exists() and is_safe_managed_delete(work):
            shutil.rmtree(work, ignore_errors=True)
    except Exception as exc:
        logger.warning("실패한 분석 작업 디렉토리 정리 실패: %s - %s", work, exc)


def _cleanup_successful_analysis(work: Path) -> bool:
    """Delete an auto-managed successful case and report whether deletion actually completed."""
    if not work.exists():
        return True

    try:
        if not is_safe_managed_delete(work):
            logger.warning("분석 후 작업 디렉토리 자동 정리 경계 검사 실패: %s", work)
            return False
        shutil.rmtree(work)
    except Exception as exc:
        logger.warning("분석 후 작업 디렉토리 정리 실패: %s - %s", work, exc)
        return False

    if work.exists():
        logger.warning("분석 후 작업 디렉토리 정리 후에도 경로가 남아 있음: %s", work)
        return False

    logger.debug("분석 후 작업 디렉토리 자동 정리 완료: %s", work)
    return True


class AnalysisService:
    """분석 서비스"""

    def __init__(self):
        self.workdir_service = WorkDirectoryService()

    async def analyze(
        self,
        files: Optional[List[Any]] = None,
        use_repo_rules: bool = True,
        min_severity: Optional[str] = "medium",
        mitre_include: Optional[str] = None,
        mitre_exclude: Optional[str] = None,
        host_include: Optional[str] = None,
        redact: bool = True,
        render_pdf: bool = False,
        do_evtx: bool = False,
        collect_evtx: bool = False,
        collect_logs: Optional[str] = None,
        collect_hours: Optional[int] = None,
        work_dir: Optional[str] = None,
    ) -> Dict[str, Any]:
        """
        로그 분석 실행

        Returns:
            분석 결과 딕셔너리
        """
        # P1-02: redaction is request-local and passed into Pipeline.
        # BREACHSCOPE_P1_01_STREAMING_UPLOAD_V1
        validate_file_count(files or [])

        # 작업 디렉토리 생성
        work = self.workdir_service.create_work_directory(work_dir)
        cleanup_after_analysis = (
            not (work_dir and str(work_dir).strip())
            and os.getenv("BS_WEB_CLEANUP_AFTER_ANALYSIS", "0") == "1"
        )
        collected_dir = None  # collect_windows_logs에서 생성된 임시 디렉토리
        converted_dirs = []  # convert_evtx_dir에서 생성된 임시 디렉토리들
        upload_budget = UploadBudget()
        created_upload_paths = []

        try:
            # 입력 디렉토리 설정
            if work_dir and work_dir.strip():
                in_dir = work
            else:
                in_dir = work / "input"
                in_dir.mkdir(parents=True, exist_ok=True)

            # Windows 이벤트 로그 자동 수집
            if collect_evtx:
                log_names = None
                if collect_logs:
                    log_names = [x.strip() for x in collect_logs.split(",") if x.strip()]

                collected_dir = collect_windows_logs(
                    output_dir=None,
                    log_names=log_names,
                    hours=collect_hours,
                )
                if collected_dir:
                    in_dir = collected_dir
                    do_evtx = True
                    logger.info(f"Windows 이벤트 로그 수집 완료: {collected_dir}")

            # 파일 저장 (파일이 업로드된 경우)
            saved_paths = []
            if files:
                upload_dir = in_dir
                for file in files:
                    if not hasattr(file, 'filename') or not file.filename:
                        continue

                    safe_name = Path(file.filename).name
                    if not safe_name:
                        continue
                    # Path traversal 방지: 브라우저가 보낸 파일명은 항상 basename만 사용
                    # P2-08C/D/E: 기존 증거를 덮어쓰지 않고 원자적 이름 충돌도 재시도한다.
                    collision_retries = 0
                    while True:
                        file_path = _unique_upload_path(upload_dir, safe_name, saved_paths)
                        try:
                            written_bytes = await stream_upload_to_path(
                                file,
                                file_path,
                                upload_budget,
                                filename=safe_name,
                            )
                        except FileExistsError:
                            collision_retries += 1
                            if collision_retries >= MAX_UPLOAD_NAME_COLLISION_RETRIES:
                                logger.error(
                                    "업로드 이름 충돌 재시도 한도 초과: %s (%s회)",
                                    safe_name,
                                    collision_retries,
                                )
                                raise
                            logger.warning(
                                "업로드 이름 충돌 감지, 새 이름으로 재시도: %s",
                                file_path,
                            )
                            continue
                        except (PermissionError, OSError) as e:
                            logger.error(f"파일 저장 실패: {file_path} - {e}")
                            raise

                        created_upload_paths.append(file_path)
                        saved_paths.append(file_path)
                        logger.info(
                            f"파일 저장 완료: {file_path} "
                            f"({written_bytes} bytes)"
                        )
                        break

            # 규칙 디렉토리 설정
            if use_repo_rules:
                rules_dir = Path("rules").resolve()
            else:
                rules_dir = work / "rules"
                rules_dir.mkdir(parents=True, exist_ok=True)

            # EVTX 변환
            if do_evtx or collect_evtx:
                if collect_evtx and in_dir.exists():
                    converted = convert_evtx_dir(in_dir)
                    if converted:
                        in_dir = converted
                        converted_dirs.append(converted)
                        logger.info(f"EVTX 변환 완료: {converted}")
                    else:
                        logger.warning("EVTX 변환 실패: python-evtx가 설치되어 있지 않거나 변환할 파일이 없습니다.")

                if saved_paths and any(p.suffix.lower() == ".evtx" for p in saved_paths):
                    upload_dir = saved_paths[0].parent
                    converted = convert_evtx_dir(upload_dir)
                    if converted:
                        if not collect_evtx:
                            in_dir = converted
                        converted_dirs.append(converted)
                        logger.info(f"업로드된 EVTX 파일 변환 완료: {converted}")

            # 파이프라인 실행
            def split_csv(s: str) -> Optional[List[str]]:
                return [x.strip() for x in s.split(",") if x.strip()] if s else None

            config = Config.from_env()
            max_events = config.max_events

            pipeline = Pipeline(
                rules_dir=rules_dir,
                min_severity=min_severity,
                mitre_include=split_csv(mitre_include) if mitre_include else None,
                mitre_exclude=split_csv(mitre_exclude) if mitre_exclude else None,
                host_include=split_csv(host_include) if host_include else None,
                max_events=max_events,
                redact=redact,
            )

            out_prefix = work / "out" / "report"
            out_prefix.parent.mkdir(parents=True, exist_ok=True)

            html_path, count = pipeline.run(
                input_dir=in_dir,
                out_prefix=out_prefix,
                export_json=True,
                export_csv=True,
                render_pdf=render_pdf,
            )

            # 리포트 파일 경로
            json_path = out_prefix.with_suffix(".json")
            csv_path = out_prefix.with_suffix(".csv")
            iocs_path = out_prefix.with_suffix(".iocs.csv")
            rule_catalog_path = out_prefix.with_suffix(".rules.csv")
            pdf_path = out_prefix.with_suffix(".pdf") if render_pdf else None
            manifest_path = out_prefix.with_suffix(".manifest.json")
            package_path = out_prefix.with_suffix(".zip")

            risk = {}
            executive_summary = []
            preview = {}
            report_data = None
            case_record = None
            if json_path.exists():
                try:
                    report_data = json.loads(json_path.read_text(encoding="utf-8"))
                    summary = report_data.get("summary", {})
                    risk = summary.get("risk", {}) or {}
                    executive_summary = summary.get("executive_summary", []) or []
                    preview = build_preview(report_data)
                except Exception as e:
                    logger.warning(f"리포트 요약 읽기 실패: {e}")

            cleanup_succeeded = False
            if cleanup_after_analysis:
                cleanup_succeeded = _cleanup_successful_analysis(work)

            if report_data is not None and not cleanup_succeeded:
                try:
                    case_record = CaseHistoryService().register_case(work, report_data)
                except Exception as e:
                    logger.warning(f"케이스 이력 저장 실패: {e}")

            retain_artifact_paths = not cleanup_succeeded
            return {
                "success": True,
                "count": count,
                "case_id": case_record.case_id if case_record else None,
                "case": case_record.__dict__ if case_record else None,
                "risk_score": risk.get("score", 0),
                "risk_level": risk.get("level", "none"),
                "executive_summary": executive_summary,
                "preview": preview,
                "html_path": str(html_path) if retain_artifact_paths and Path(html_path).exists() else None,
                "json_path": str(json_path) if retain_artifact_paths and json_path.exists() else None,
                "csv_path": str(csv_path) if retain_artifact_paths and csv_path.exists() else None,
                "iocs_path": str(iocs_path) if retain_artifact_paths and iocs_path.exists() else None,
                "rule_catalog_path": str(rule_catalog_path) if retain_artifact_paths and rule_catalog_path.exists() else None,
                "pdf_path": str(pdf_path) if retain_artifact_paths and pdf_path and pdf_path.exists() else None,
                "manifest_path": str(manifest_path) if retain_artifact_paths and manifest_path.exists() else None,
                "package_path": str(package_path) if retain_artifact_paths and package_path.exists() else None,
                "work_dir": str(work) if retain_artifact_paths and work.exists() else None,
            }
        except UploadLimitError:
            _cleanup_failed_analysis(work, work_dir, created_upload_paths)
            raise
        except Exception:
            _cleanup_failed_analysis(work, work_dir, created_upload_paths)
            raise

        finally:
            # collect_windows_logs에서 생성된 임시 디렉토리 정리
            if collected_dir and collected_dir.exists():
                try:
                    # collected_dir이 work 디렉토리와 다른 경우에만 정리
                    if collected_dir != work and str(collected_dir) != str(work):
                        shutil.rmtree(collected_dir, ignore_errors=True)
                        logger.debug(f"임시 수집 디렉토리 정리 완료: {collected_dir}")
                except Exception as e:
                    logger.warning(f"임시 수집 디렉토리 정리 실패: {collected_dir} - {e}")

            # convert_evtx_dir에서 생성된 임시 디렉토리들 정리
            for converted_dir in converted_dirs:
                if converted_dir and converted_dir.exists():
                    try:
                        # converted_dir이 work 디렉토리와 다른 경우에만 정리
                        if converted_dir != work and str(converted_dir) != str(work):
                            shutil.rmtree(converted_dir, ignore_errors=True)
                            logger.debug(f"임시 EVTX 변환 디렉토리 정리 완료: {converted_dir}")
                    except Exception as e:
                        logger.warning(f"임시 EVTX 변환 디렉토리 정리 실패: {converted_dir} - {e}")


# BREACHSCOPE_P2_08C_DUPLICATE_UPLOAD_BASENAME_V1
# BREACHSCOPE_P2_08E_RETRY_UPLOAD_NAME_COLLISION_V1
# BREACHSCOPE_P2_08F_FAILED_ANALYSIS_EVIDENCE_CLEANUP_V1
# BREACHSCOPE_P2_08G_SUCCESS_CLEANUP_POLICY_V1
# BREACHSCOPE_P2_08H_NO_STALE_CLEANUP_PATHS_V1
# BREACHSCOPE_P2_08I_CLEANUP_OUTCOME_CONSISTENCY_V1
