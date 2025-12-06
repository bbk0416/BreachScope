"""
시나리오 기반 추론 모듈
이벤트 체인을 분석하여 공격 시나리오를 자동으로 식별하고 재구성합니다.
"""
from dataclasses import dataclass, field
from typing import List, Dict, Optional, Set, Any
from collections import defaultdict

from .schemas import EventChain, Scenario, Event, Finding
from .correlator import EventChain as CorrelatorEventChain


# MITRE ATT&CK 공격 단계 매핑
ATTACK_STAGES = {
    "T1078": "persistence",  # Valid Accounts
    "T1059.001": "execution",  # PowerShell
    "T1105": "command_and_control",  # Ingress Tool Transfer
    "T1047": "execution",  # WMI
    "T1218.005": "defense_evasion",  # Mshta
    "T1547.001": "persistence",  # Registry Run Keys
    "T1053.005": "execution",  # Scheduled Task
    "T1197": "command_and_control",  # BITS Jobs
    "T1003": "credential_access",  # OS Credential Dumping
    "T1071": "command_and_control",  # Application Layer Protocol
    "T1021": "lateral_movement",  # Remote Services
    "T1566": "initial_access",  # Phishing
    "T1203": "execution",  # Exploitation for Client Execution
}


@dataclass
class ScenarioTemplate:
    """공격 시나리오 템플릿"""
    template_id: str
    name: str
    description: str
    required_techniques: List[str]  # 필수 MITRE 기법
    optional_techniques: List[str]  # 선택적 MITRE 기법
    chain_patterns: List[str]  # 체인 패턴 (예: "download_exec", "encoded_exec")
    attack_stage: str
    confidence_weights: Dict[str, float] = field(default_factory=dict)


def infer_scenarios(
    chains: List[CorrelatorEventChain],
    findings: List[Finding],
) -> List[Scenario]:
    """
    이벤트 체인과 탐지 결과로부터 공격 시나리오를 추론합니다.

    Args:
        chains: 상관분석으로 생성된 이벤트 체인
        findings: 규칙 기반 탐지 결과

    Returns:
        추론된 공격 시나리오 목록
    """
    if not chains:
        return []

    # 시나리오 템플릿 로드
    templates = _get_scenario_templates()

    scenarios: List[Scenario] = []

    # 각 템플릿에 대해 매칭 시도
    for template in templates:
        matched_chains: List[CorrelatorEventChain] = []
        matched_techniques: Set[str] = set()

        # 체인 패턴 매칭
        for chain in chains:
            if chain.chain_type in template.chain_patterns:
                matched_chains.append(chain)

        # Finding에서 MITRE 기법 추출
        for finding in findings:
            if finding.mitre_technique:
                tech = finding.mitre_technique.upper()
                if tech in template.required_techniques or tech in template.optional_techniques:
                    matched_techniques.add(tech)

        # 필수 기법이 모두 있는지 확인
        required_met = all(
            tech in matched_techniques or any(
                tech.startswith(t.split(".")[0]) for t in matched_techniques
            )
            for tech in template.required_techniques
        )

        if required_met and matched_chains:
            # 신뢰도 계산
            confidence = _calculate_scenario_confidence(
                template, matched_chains, matched_techniques, findings
            )

            # EventChain을 schemas.EventChain으로 변환
            converted_chains = _convert_chains(matched_chains)

            scenario = Scenario(
                scenario_id=f"scenario_{len(scenarios)+1}_{template.template_id}",
                name=template.name,
                description=template.description,
                mitre_techniques=list(matched_techniques),
                chains=converted_chains,
                confidence=confidence,
                attack_stage=template.attack_stage,
            )
            scenarios.append(scenario)

    # 체인 기반 시나리오 추론 (템플릿 없이)
    chain_based = _infer_from_chains(chains, findings)
    scenarios.extend(chain_based)

    # 신뢰도 순으로 정렬
    scenarios.sort(key=lambda s: s.confidence, reverse=True)

    return scenarios


def _get_scenario_templates() -> List[ScenarioTemplate]:
    """기본 시나리오 템플릿 반환"""
    return [
        # 피싱 → 실행 → 백도어 설치
        ScenarioTemplate(
            template_id="phishing_backdoor",
            name="피싱 이메일을 통한 백도어 설치",
            description="피싱 이메일 수신 후 악성 파일 실행 및 백도어 설치",
            required_techniques=["T1566", "T1059.001"],  # Phishing, PowerShell
            optional_techniques=["T1547.001", "T1053.005"],  # Persistence
            chain_patterns=["download_exec", "encoded_exec"],
            attack_stage="initial_access",
        ),
        # 인코딩된 명령 실행 → 자격증명 탈취
        ScenarioTemplate(
            template_id="encoded_cred_dump",
            name="인코딩된 명령을 통한 자격증명 탈취",
            description="Base64 인코딩된 PowerShell 명령 실행 후 자격증명 덤프",
            required_techniques=["T1059.001"],  # PowerShell
            optional_techniques=["T1003"],  # OS Credential Dumping
            chain_patterns=["encoded_exec"],
            attack_stage="credential_access",
        ),
        # 웹 다운로드 → 실행 → C2 통신
        ScenarioTemplate(
            template_id="download_c2",
            name="웹 다운로드를 통한 C2 통신",
            description="웹에서 악성 파일 다운로드 후 실행 및 C2 서버 통신",
            required_techniques=["T1105", "T1071"],  # Ingress Tool Transfer, C2 Protocol
            optional_techniques=["T1059.001"],
            chain_patterns=["download_exec", "network_data"],
            attack_stage="command_and_control",
        ),
        # WMI를 통한 원격 실행
        ScenarioTemplate(
            template_id="wmi_lateral",
            name="WMI를 통한 측면 이동",
            description="WMI를 이용한 원격 시스템에서의 프로세스 실행",
            required_techniques=["T1047"],  # WMI
            optional_techniques=["T1021"],  # Remote Services
            chain_patterns=[],
            attack_stage="lateral_movement",
        ),
    ]


def _calculate_scenario_confidence(
    template: ScenarioTemplate,
    chains: List[CorrelatorEventChain],
    techniques: Set[str],
    findings: List[Finding],
) -> float:
    """시나리오 신뢰도 계산"""
    confidence = 0.3  # 기본값

    # 필수 기법 매칭
    required_count = len([t for t in template.required_techniques if t in techniques])
    confidence += (required_count / len(template.required_techniques)) * 0.3

    # 선택적 기법 매칭
    optional_count = len([t for t in template.optional_techniques if t in techniques])
    if template.optional_techniques:
        confidence += (optional_count / len(template.optional_techniques)) * 0.2

    # 체인 매칭
    if chains:
        confidence += min(0.2, len(chains) * 0.1)

    # Finding 개수
    if findings:
        confidence += min(0.1, len(findings) * 0.02)

    return min(1.0, confidence)


def _convert_chains(chains: List[CorrelatorEventChain]) -> List[EventChain]:
    """CorrelatorEventChain을 schemas.EventChain으로 변환"""
    from .schemas import EventChain

    result = []
    for chain in chains:
        result.append(EventChain(
            chain_id=chain.chain_id,
            events=chain.events,
            findings=chain.findings,
            start_time=chain.start_time.isoformat() if chain.start_time else None,
            end_time=chain.end_time.isoformat() if chain.end_time else None,
            description=chain.description,
            confidence=chain.confidence,
            chain_type=chain.chain_type,
        ))
    return result


def _infer_from_chains(
    chains: List[CorrelatorEventChain],
    findings: List[Finding],
) -> List[Scenario]:
    """체인 패턴으로부터 시나리오 추론 (템플릿 없이)"""
    scenarios: List[Scenario] = []

    # 체인 타입별로 그룹화
    chains_by_type: Dict[str, List[CorrelatorEventChain]] = defaultdict(list)
    for chain in chains:
        chains_by_type[chain.chain_type].append(chain)

    # 다운로드-실행 체인
    if "download_exec" in chains_by_type:
        download_chains = chains_by_type["download_exec"]
        techniques = set()
        for finding in findings:
            if finding.mitre_technique:
                techniques.add(finding.mitre_technique.upper())

        converted_chains = _convert_chains(download_chains)
        scenario = Scenario(
            scenario_id=f"scenario_chain_download_{len(scenarios)}",
            name="웹 다운로드 및 실행",
            description="웹에서 파일을 다운로드한 후 실행한 활동",
            mitre_techniques=list(techniques) if techniques else ["T1105"],
            chains=converted_chains,
            confidence=0.6,
            attack_stage="execution",
        )
        scenarios.append(scenario)

    # 인코딩된 실행 체인
    if "encoded_exec" in chains_by_type:
        encoded_chains = chains_by_type["encoded_exec"]
        techniques = {"T1059.001"}  # PowerShell
        for finding in findings:
            if finding.mitre_technique:
                techniques.add(finding.mitre_technique.upper())

        converted_chains = _convert_chains(encoded_chains)
        scenario = Scenario(
            scenario_id=f"scenario_chain_encoded_{len(scenarios)}",
            name="인코딩된 명령 실행",
            description="난독화된 PowerShell 명령 실행",
            mitre_techniques=list(techniques),
            chains=converted_chains,
            confidence=0.7,
            attack_stage="defense_evasion",
        )
        scenarios.append(scenario)

    return scenarios


def get_scenario_summary(scenarios: List[Scenario]) -> Dict[str, Any]:
    """시나리오 요약 통계 반환"""
    if not scenarios:
        return {
            "total_scenarios": 0,
            "by_stage": {},
            "avg_confidence": 0.0,
            "unique_techniques": [],
        }

    by_stage: Dict[str, int] = defaultdict(int)
    all_techniques: Set[str] = set()
    total_confidence = 0.0

    for scenario in scenarios:
        by_stage[scenario.attack_stage] += 1
        all_techniques.update(scenario.mitre_techniques)
        total_confidence += scenario.confidence

    return {
        "total_scenarios": len(scenarios),
        "by_stage": dict(by_stage),
        "avg_confidence": total_confidence / len(scenarios) if scenarios else 0.0,
        "unique_techniques": sorted(list(all_techniques)),
    }
