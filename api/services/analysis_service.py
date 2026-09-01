"""
분석 서비스 레이어
비즈니스 로직 처리
"""
import os
import tempfile
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
        # Redaction 설정
        os.environ["BS_REDACT"] = "1" if redact else "0"

        # BREACHSCOPE_P1_01_STREAMING_UPLOAD_V1
        validate_file_count(files or [])

        # 작업 디렉토리 생성
        work = self.workdir_service.create_work_directory(work_dir)
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
                    file_path = upload_dir / safe_name
                    try:
                        written_bytes = await stream_upload_to_path(
                            file,
                            file_path,
                            upload_budget,
                            filename=safe_name,
                        )
                        created_upload_paths.append(file_path)
                        saved_paths.append(file_path)
                        logger.info(
                            f"파일 저장 완료: {file_path} "
                            f"({written_bytes} bytes)"
                        )
                    except (PermissionError, OSError) as e:
                        logger.error(f"파일 저장 실패: {file_path} - {e}")
                        raise

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
            case_record = None
            if json_path.exists():
                try:
                    report_data = json.loads(json_path.read_text(encoding="utf-8"))
                    summary = report_data.get("summary", {})
                    risk = summary.get("risk", {}) or {}
                    executive_summary = summary.get("executive_summary", []) or []
                    preview = build_preview(report_data)
                    case_record = CaseHistoryService().register_case(work, report_data)
                except Exception as e:
                    logger.warning(f"리포트 요약/케이스 이력 저장 실패: {e}")

            return {
                "success": True,
                "count": count,
                "case_id": case_record.case_id if case_record else None,
                "case": case_record.__dict__ if case_record else None,
                "risk_score": risk.get("score", 0),
                "risk_level": risk.get("level", "none"),
                "executive_summary": executive_summary,
                "preview": preview,
                "html_path": str(html_path),
                "json_path": str(json_path) if json_path.exists() else None,
                "csv_path": str(csv_path) if csv_path.exists() else None,
                "iocs_path": str(iocs_path) if iocs_path.exists() else None,
                "rule_catalog_path": str(rule_catalog_path) if rule_catalog_path.exists() else None,
                "pdf_path": str(pdf_path) if pdf_path and pdf_path.exists() else None,
                "manifest_path": str(manifest_path) if manifest_path.exists() else None,
                "package_path": str(package_path) if package_path.exists() else None,
                "work_dir": str(work),
            }
        except UploadLimitError:
            for _uploaded_path in created_upload_paths:
                try:
                    _uploaded_path.unlink(missing_ok=True)
                except OSError:
                    pass

            if not (work_dir and work_dir.strip()):
                try:
                    if work.exists() and is_safe_managed_delete(work):
                        shutil.rmtree(work, ignore_errors=True)
                except Exception:
                    pass
            raise

        finally:
            # 웹 UI는 분석 직후 다운로드 링크를 제공하므로 기본적으로 작업 디렉토리를 보존합니다.
            # 자동 정리가 필요하면 BS_WEB_CLEANUP_AFTER_ANALYSIS=1 로 명시적으로 활성화하세요.
            should_cleanup_work = (
                not (work_dir and work_dir.strip())
                and os.getenv("BS_WEB_CLEANUP_AFTER_ANALYSIS", "0") == "1"
            )

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

            # 작업 디렉토리 정리 (시스템 임시 디렉토리인 경우에만)
            if should_cleanup_work and work.exists():
                try:
                    # 시스템 임시 디렉토리인지 확인 (bs_web_ 접두사)
                    if work.name.startswith("bs_web_") or str(work).startswith(str(Path(tempfile.gettempdir()))):
                        shutil.rmtree(work, ignore_errors=True)
                        logger.debug(f"임시 작업 디렉토리 정리 완료: {work}")
                except Exception as e:
                    logger.warning(f"임시 작업 디렉토리 정리 실패: {work} - {e}")
