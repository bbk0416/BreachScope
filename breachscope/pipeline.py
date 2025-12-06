"""
파이프라인 모듈
이벤트 수집부터 리포트 생성까지의 전체 프로세스를 관리합니다.
"""
from pathlib import Path
from typing import List, Dict, Any, Optional
import os
import logging
import time
from datetime import datetime, timezone

logger = logging.getLogger(__name__)

from .collector import load_jsonl_events
from .normalizer import normalize
from .analyzer import apply_rules
from .correlator import correlate_events, get_chain_summary
from .scenario import infer_scenarios, get_scenario_summary
from .reporting import build_summary, render_html, maybe_render_pdf, export_json, export_csv
from .schemas import Rule, Report, Finding, EventChain, Event
from .rules import load_rules
from .utils import parse_timestamp as _parse_ts
from .exceptions import (
    EventCollectionError,
    CorrelationError,
    ScenarioInferenceError,
    ReportGenerationError,
)


class Pipeline:
    """
    BreachScope 분석 파이프라인

    이벤트 수집, 분석, 상관분석, 시나리오 추론, 리포트 생성을 관리합니다.
    """

    def __init__(
        self,
        rules_dir: Path,
        min_severity: Optional[str] = None,
        mitre_include: Optional[List[str]] = None,
        mitre_exclude: Optional[List[str]] = None,
        host_include: Optional[List[str]] = None,
        max_events: Optional[int] = None,
    ):
        """
        파이프라인 초기화

        Args:
            rules_dir: 규칙 파일 디렉토리
            min_severity: 최소 심각도 필터
            mitre_include: 포함할 MITRE 기법 목록
            mitre_exclude: 제외할 MITRE 기법 목록
            host_include: 포함할 호스트 목록
            max_events: 최대 이벤트 수 (None이면 제한 없음, 대용량 파일 처리 시 유용)
        """
        self.rules_dir = rules_dir
        self.min_severity = min_severity
        self.mitre_include = mitre_include
        self.mitre_exclude = mitre_exclude
        self.host_include = host_include
        self.max_events = max_events

        # 파이프라인 상태
        self.rules: Optional[List[Rule]] = None
        self.events: Optional[List[Event]] = None
        self.findings: Optional[List[Finding]] = None
        # 타입 힌트를 위해 TYPE_CHECKING 사용
        from typing import TYPE_CHECKING
        if TYPE_CHECKING:
            from .correlator import EventChain as CorrelatorEventChain
            from .scenario import Scenario as ScenarioType
            self.chains: Optional[List[CorrelatorEventChain]] = None
            self.scenarios: Optional[List[ScenarioType]] = None
        else:
            self.chains: Optional[List] = None  # correlator.EventChain
            self.scenarios: Optional[List] = None  # scenario.Scenario
        self.report: Optional[Report] = None

    def load_rules(self) -> List[Rule]:
        """
        규칙 로드

        Returns:
            로드된 Rule 리스트
        """
        if self.rules is None:
            self.rules = load_rules(self.rules_dir)
        return self.rules

    def collect_events(self, input_dir: Path) -> List[Event]:
        """
        이벤트 수집 및 정규화

        Args:
            input_dir: 입력 로그 디렉토리

        Returns:
            정규화된 이벤트 리스트

        Raises:
            EventCollectionError: 이벤트 수집 실패 시
        """
        try:
            events_iter = load_jsonl_events(input_dir)
            normalized_iter = normalize(events_iter)

            # max_events 제한이 있으면 제한 적용
            if self.max_events:
                events_list = []
                for i, event in enumerate(normalized_iter):
                    if i >= self.max_events:
                        logger.warning(f"이벤트 수가 최대 제한({self.max_events})에 도달했습니다. 나머지 이벤트는 무시됩니다.")
                        break
                    events_list.append(event)
                self.events = events_list
            else:
                # 제너레이터를 리스트로 변환
                self.events = list(normalized_iter)

            logger.info(f"이벤트 수집 완료: {len(self.events)}개")
            return self.events
        except Exception as e:
            raise EventCollectionError(
                f"이벤트 수집 실패: {input_dir}",
                details={"input_dir": str(input_dir), "error": str(e)}
            ) from e

    def analyze(self) -> List[Finding]:
        """
        규칙 기반 분석 실행

        Returns:
            탐지 결과 리스트
        """
        if self.events is None:
            raise ValueError("이벤트를 먼저 수집해야 합니다. collect_events()를 호출하세요.")
        if self.rules is None:
            self.load_rules()

        logger.info(f"규칙 기반 분석 시작: {len(self.rules)}개 규칙, {len(self.events)}개 이벤트")
        findings = list(apply_rules(self.events, self.rules))
        self.findings = self._filter_findings(findings)
        logger.info(f"분석 완료: {len(self.findings)}개 탐지 결과")
        return self.findings

    def correlate(self) -> List:
        """
        시간 기반 상관분석 실행

        Returns:
            이벤트 체인 리스트

        Raises:
            CorrelationError: 상관분석 실패 시
        """
        if self.findings is None:
            raise CorrelationError("분석을 먼저 실행해야 합니다. analyze()를 호출하세요.")
        if self.events is None:
            raise CorrelationError("이벤트를 먼저 수집해야 합니다. collect_events()를 호출하세요.")

        try:
            logger.info(f"상관분석 시작: {len(self.events)}개 이벤트, {len(self.findings)}개 탐지 결과")
            self.chains = correlate_events(self.events, self.findings)
            logger.info(f"상관분석 완료: {len(self.chains)}개 이벤트 체인 생성")
            return self.chains
        except Exception as e:
            raise CorrelationError(
                "상관분석 실패",
                details={"error": str(e)}
            ) from e

    def infer_scenarios(self) -> List:
        """
        시나리오 기반 추론 실행

        Returns:
            시나리오 리스트

        Raises:
            ScenarioInferenceError: 시나리오 추론 실패 시
        """
        if self.chains is None:
            raise ScenarioInferenceError("상관분석을 먼저 실행해야 합니다. correlate()를 호출하세요.")
        if self.findings is None:
            raise ScenarioInferenceError("분석을 먼저 실행해야 합니다. analyze()를 호출하세요.")

        try:
            logger.info(f"시나리오 추론 시작: {len(self.chains)}개 체인")
            self.scenarios = infer_scenarios(self.chains, self.findings)
            logger.info(f"시나리오 추론 완료: {len(self.scenarios)}개 시나리오 생성")
            return self.scenarios
        except Exception as e:
            raise ScenarioInferenceError(
                "시나리오 추론 실패",
                details={"error": str(e)}
            ) from e

    def build_report(self) -> Report:
        """
        리포트 객체 생성

        Returns:
            Report 객체
        """
        if self.findings is None:
            raise ValueError("분석을 먼저 실행해야 합니다. analyze()를 호출하세요.")

        chain_summary = get_chain_summary(self.chains) if self.chains else {}
        scenario_summary = get_scenario_summary(self.scenarios) if self.scenarios else {}

        summary = build_summary(self.findings)
        summary["generated_at"] = datetime.now(timezone.utc).isoformat()
        summary["rules"] = {"count": len(self.rules) if self.rules else 0}
        summary["filters"] = {
            "min_severity": (self.min_severity or ""),
            "mitre_include": (self.mitre_include or []),
            "mitre_exclude": (self.mitre_exclude or []),
            "host_include": (self.host_include or []),
        }
        summary["time_histogram"] = self._time_histogram(self.findings)
        summary["chains"] = chain_summary
        summary["scenarios"] = scenario_summary

        # EventChain 변환 (correlator.EventChain -> schemas.EventChain)
        converted_chains = []
        if self.chains:
            for chain in self.chains:
                converted_chains.append(EventChain(
                    chain_id=chain.chain_id,
                    events=chain.events,
                    findings=chain.findings,
                    start_time=chain.start_time.isoformat() if chain.start_time else None,
                    end_time=chain.end_time.isoformat() if chain.end_time else None,
                    description=chain.description,
                    confidence=chain.confidence,
                    chain_type=chain.chain_type,
                ))

        self.report = Report(
            summary=summary,
            findings=self.findings,
            events=self.events or [],
            chains=converted_chains,
            scenarios=self.scenarios or [],
        )
        return self.report

    def export_report(
        self,
        out_prefix: Path,
        export_json: bool = False,
        export_csv: bool = False,
        render_pdf: bool = False,
    ) -> Path:
        """
        리포트를 파일로 내보내기

        Args:
            out_prefix: 출력 파일 경로 접두어
            export_json: JSON 내보내기 여부
            export_csv: CSV 내보내기 여부
            render_pdf: PDF 렌더링 여부

        Returns:
            생성된 HTML 파일 경로
        """
        if self.report is None:
            self.build_report()

        out_html = out_prefix.with_suffix(".html")
        out_pdf = out_prefix.with_suffix(".pdf")

        logger.info(f"리포트 생성 시작: {out_html}")
        render_html(self.report, out_html)
        logger.info(f"HTML 리포트 생성 완료: {out_html}")

        if render_pdf:
            logger.info("PDF 생성 시작...")
            maybe_render_pdf(out_html, out_pdf)
            logger.info(f"PDF 리포트 생성 완료: {out_pdf}")

        redact = (os.getenv("BS_REDACT", "1") != "0")
        if export_json:
            from .reporting import export_json as export_json_func
            export_json_func(self.report, out_prefix.with_suffix(".json"), redact=redact)
        if export_csv:
            from .reporting import export_csv as export_csv_func
            export_csv_func(self.report, out_prefix.with_suffix(".csv"), redact=redact)

        return out_html

    def run(
        self,
        input_dir: Path,
        out_prefix: Path,
        export_json: bool = False,
        export_csv: bool = False,
        render_pdf: bool = False,
    ) -> tuple[Path, int]:
        """
        전체 파이프라인 실행

        Args:
            input_dir: 입력 로그 디렉토리
            out_prefix: 출력 파일 경로 접두어
            export_json: JSON 내보내기 여부
            export_csv: CSV 내보내기 여부
            render_pdf: PDF 렌더링 여부

        Returns:
            (HTML 파일 경로, 탐지 건수) 튜플
        """
        start_time = time.time()
        logger.info("=" * 60)
        logger.info("파이프라인 실행 시작")
        logger.info("=" * 60)

        # 파이프라인 실행 (단계별 시간 측정)
        step_start = time.time()
        self.collect_events(input_dir)
        logger.info(f"✓ 이벤트 수집 완료 ({time.time() - step_start:.2f}초)")

        step_start = time.time()
        self.analyze()
        logger.info(f"✓ 분석 완료 ({time.time() - step_start:.2f}초)")

        step_start = time.time()
        self.correlate()
        logger.info(f"✓ 상관분석 완료 ({time.time() - step_start:.2f}초)")

        step_start = time.time()
        self.infer_scenarios()
        logger.info(f"✓ 시나리오 추론 완료 ({time.time() - step_start:.2f}초)")

        step_start = time.time()
        self.build_report()
        logger.info(f"✓ 리포트 빌드 완료 ({time.time() - step_start:.2f}초)")

        step_start = time.time()
        html_path = self.export_report(out_prefix, export_json, export_csv, render_pdf)
        logger.info(f"✓ 리포트 내보내기 완료 ({time.time() - step_start:.2f}초)")

        total_time = time.time() - start_time
        logger.info("=" * 60)
        logger.info(f"파이프라인 실행 완료 (총 {total_time:.2f}초)")
        logger.info(f"  - 이벤트: {len(self.events) if self.events else 0}개")
        logger.info(f"  - 탐지 결과: {len(self.findings) if self.findings else 0}개")
        logger.info(f"  - 이벤트 체인: {len(self.chains) if self.chains else 0}개")
        logger.info(f"  - 시나리오: {len(self.scenarios) if self.scenarios else 0}개")
        logger.info("=" * 60)

        return html_path, len(self.findings) if self.findings else 0

    def _filter_findings(
        self,
        findings: List[Finding],
    ) -> List[Finding]:
        """탐지 결과 필터링"""
        if not findings:
            return findings

        _SEV_ORDER = {"low": 1, "medium": 2, "high": 3, "critical": 4}
        res: List[Finding] = []
        min_order = _SEV_ORDER.get((self.min_severity or "").lower(), 0)
        include_set = set(x.upper() for x in (self.mitre_include or []))
        exclude_set = set(x.upper() for x in (self.mitre_exclude or []))
        host_set = set(h.lower() for h in (self.host_include or []))

        for f in findings:
            if min_order and _SEV_ORDER.get((f.severity or "").lower(), 0) < min_order:
                continue
            tech = (f.mitre_technique or "").upper()
            if include_set and tech not in include_set:
                continue
            if exclude_set and tech in exclude_set:
                continue
            if host_set and (f.event.host or "").lower() not in host_set:
                continue
            res.append(f)
        return res

    def _time_histogram(self, findings: List[Finding]) -> Dict[str, int]:
        """시간별 히스토그램 생성"""
        buckets: Dict[str, int] = {}
        for f in findings:
            dt = _parse_ts(f.event.timestamp)
            if not dt:
                key = "unknown"
            else:
                if not dt.tzinfo:
                    dt = dt.replace(tzinfo=timezone.utc)
                key = dt.strftime("%Y-%m-%d %H:00")
            buckets[key] = buckets.get(key, 0) + 1
        return buckets


# 하위 호환성을 위한 함수형 인터페이스
def run_pipeline(
    input_dir: Path,
    rules_dir: Path,
    out_prefix: Path,
    export_json_flag: bool = False,
    export_csv_flag: bool = False,
    render_pdf: bool = False,
    min_severity: str | None = None,
    mitre_include: list[str] | None = None,
    mitre_exclude: list[str] | None = None,
    host_include: list[str] | None = None,
    max_events: int | None = None,
) -> tuple[Path, int]:
    """
    파이프라인 실행 (하위 호환성 함수)

    이 함수는 Pipeline 클래스의 래퍼입니다.
    새로운 코드는 Pipeline 클래스를 직접 사용하는 것을 권장합니다.

    Args:
        input_dir: 입력 로그 디렉토리
        rules_dir: 규칙 파일 디렉토리
        out_prefix: 출력 파일 경로 접두어
        export_json_flag: JSON 내보내기 여부
        export_csv_flag: CSV 내보내기 여부
        render_pdf: PDF 렌더링 여부
        min_severity: 최소 심각도 필터
        mitre_include: 포함할 MITRE 기법 목록
        mitre_exclude: 제외할 MITRE 기법 목록
        host_include: 포함할 호스트 목록
        max_events: 최대 이벤트 수 (None이면 제한 없음)

    Returns:
        (HTML 파일 경로, 탐지 건수) 튜플
    """
    # Config에서 max_events 가져오기 (인자로 전달되지 않은 경우)
    if max_events is None:
        from .config import Config
        config = Config.from_env()
        max_events = config.max_events

    pipeline = Pipeline(
        rules_dir=rules_dir,
        min_severity=min_severity,
        mitre_include=mitre_include,
        mitre_exclude=mitre_exclude,
        host_include=host_include,
        max_events=max_events,
    )
    return pipeline.run(
        input_dir=input_dir,
        out_prefix=out_prefix,
        export_json=export_json_flag,
        export_csv=export_csv_flag,
        render_pdf=render_pdf,
    )
