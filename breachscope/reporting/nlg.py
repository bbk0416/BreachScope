"""
자연어 생성 (NLG) 모듈
템플릿 기반 자연어 생성으로 보고서의 서술형 내용을 생성합니다.
"""
from typing import Dict, List, Any, Optional
from datetime import datetime
import logging

logger = logging.getLogger(__name__)


class NLGTemplate:
    """자연어 생성 템플릿"""

    # 한국어 템플릿
    TEMPLATES_KO = {
        "finding_detection": "{hostname} 시스템에서 {datetime}에 {rule_name} 규칙이 탐지되었습니다.",
        "process_execution": "{hostname} 시스템에서 {datetime}에 프로세스 '{process_name}'이 실행되었습니다.",
        "credential_dumping": "{hostname} 시스템에서 {datetime}에 실행된 프로세스 '{process_name}'에서 자격증명 덤프 도구가 탐지되었습니다.",
        "network_connection": "{hostname} 시스템에서 {datetime}에 {destination}로의 네트워크 연결이 확인되었습니다.",
        "file_download": "{hostname} 시스템에서 {datetime}에 {url}에서 파일을 다운로드했습니다.",
        "chain_description": "{start_time}부터 {end_time}까지 {event_count}개의 이벤트가 연관되어 {chain_type} 체인을 형성했습니다.",
        "scenario_description": "{scenario_name} 시나리오가 {confidence:.1%}의 신뢰도로 식별되었습니다. 이 시나리오는 {attack_stage} 단계의 공격을 나타냅니다.",
        "summary_intro": "본 보고서는 {total_findings}개의 탐지 결과와 {total_chains}개의 이벤트 체인, {total_scenarios}개의 공격 시나리오를 분석한 결과입니다.",
        "mitre_technique": "{technique_id} ({technique_name}) 기법이 {count}회 탐지되었습니다.",
    }

    # 영어 템플릿
    TEMPLATES_EN = {
        "finding_detection": "Rule {rule_name} was detected on {hostname} system at {datetime}.",
        "process_execution": "Process '{process_name}' was executed on {hostname} system at {datetime}.",
        "credential_dumping": "Credential dumping tool was detected in process '{process_name}' executed on {hostname} system at {datetime}.",
        "network_connection": "Network connection to {destination} was confirmed from {hostname} system at {datetime}.",
        "file_download": "File was downloaded from {url} on {hostname} system at {datetime}.",
        "chain_description": "{event_count} events were correlated from {start_time} to {end_time}, forming a {chain_type} chain.",
        "scenario_description": "Scenario {scenario_name} was identified with {confidence:.1%} confidence. This scenario represents an attack at the {attack_stage} stage.",
        "summary_intro": "This report analyzes {total_findings} findings, {total_chains} event chains, and {total_scenarios} attack scenarios.",
        "mitre_technique": "Technique {technique_id} ({technique_name}) was detected {count} times.",
    }

    def __init__(self, language: str = "ko"):
        """
        Args:
            language: 언어 ("ko" 또는 "en")
        """
        self.language = language
        self.templates = self.TEMPLATES_KO if language == "ko" else self.TEMPLATES_EN

    def generate(self, template_key: str, **kwargs) -> str:
        """
        템플릿을 사용하여 자연어 생성

        Args:
            template_key: 템플릿 키
            **kwargs: 템플릿 변수

        Returns:
            생성된 자연어 문장
        """
        template = self.templates.get(template_key)
        if not template:
            logger.warning(f"템플릿을 찾을 수 없습니다: {template_key}")
            return f"[템플릿 없음: {template_key}]"

        try:
            # 날짜 포맷팅
            if "datetime" in kwargs and kwargs["datetime"]:
                if isinstance(kwargs["datetime"], str):
                    try:
                        dt = datetime.fromisoformat(kwargs["datetime"].replace("Z", "+00:00"))
                        kwargs["datetime"] = dt.strftime("%Y-%m-%d %H:%M:%S")
                    except:
                        pass

            return template.format(**kwargs)
        except KeyError as e:
            logger.warning(f"템플릿 변수 누락: {e}")
            return template

    def generate_finding_description(self, finding: Any) -> str:
        """Finding에 대한 자연어 설명 생성"""
        from ..schemas import Finding

        if not isinstance(finding, Finding):
            return ""

        hostname = finding.event.host or "알 수 없는 호스트"
        datetime_str = finding.event.timestamp or ""

        # MITRE 기법에 따른 템플릿 선택
        mitre_tech = finding.mitre_technique or ""

        if "T1003" in mitre_tech or "credential" in finding.rule_name.lower():
            return self.generate(
                "credential_dumping",
                hostname=hostname,
                datetime=datetime_str,
                process_name=finding.event.command_line[:50] if finding.event.command_line else "알 수 없음",
            )
        elif "T1105" in mitre_tech or "download" in finding.rule_name.lower():
            # URL 추출 시도
            url = "알 수 없음"
            if finding.event.command_line:
                import re
                url_match = re.search(r'https?://[^\s]+', finding.event.command_line)
                if url_match:
                    url = url_match.group(0)

            return self.generate(
                "file_download",
                hostname=hostname,
                datetime=datetime_str,
                url=url,
            )
        else:
            return self.generate(
                "finding_detection",
                hostname=hostname,
                datetime=datetime_str,
                rule_name=finding.rule_name,
            )

    def generate_chain_description(self, chain: Any) -> str:
        """EventChain에 대한 자연어 설명 생성"""
        start_time = chain.start_time or "알 수 없음"
        end_time = chain.end_time or "알 수 없음"
        event_count = len(chain.events) if hasattr(chain, 'events') else 0
        chain_type = chain.chain_type or "알 수 없음"

        return self.generate(
            "chain_description",
            start_time=start_time,
            end_time=end_time,
            event_count=event_count,
            chain_type=chain_type,
        )

    def generate_scenario_description(self, scenario: Any) -> str:
        """Scenario에 대한 자연어 설명 생성"""
        scenario_name = scenario.name if hasattr(scenario, 'name') else "알 수 없음"
        confidence = scenario.confidence if hasattr(scenario, 'confidence') else 0.0
        attack_stage = scenario.attack_stage if hasattr(scenario, 'attack_stage') else "알 수 없음"

        return self.generate(
            "scenario_description",
            scenario_name=scenario_name,
            confidence=confidence,
            attack_stage=attack_stage,
        )

    def generate_summary_intro(self, report: Any) -> str:
        """리포트 요약 소개 문장 생성"""
        total_findings = len(report.findings) if hasattr(report, 'findings') else 0
        total_chains = len(report.chains) if hasattr(report, 'chains') else 0
        total_scenarios = len(report.scenarios) if hasattr(report, 'scenarios') else 0

        return self.generate(
            "summary_intro",
            total_findings=total_findings,
            total_chains=total_chains,
            total_scenarios=total_scenarios,
        )



