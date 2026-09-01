"""
시나리오 기반 추론 모듈
이벤트 체인을 분석하여 공격 시나리오를 자동으로 식별하고 재구성합니다.
"""
import yaml
import logging
from dataclasses import dataclass, field
from typing import List, Dict, Optional, Set, Any
from collections import defaultdict
from pathlib import Path

from .schemas import EventChain, Scenario, Event, Finding
from .correlator import EventChain as CorrelatorEventChain

logger = logging.getLogger(__name__)


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
    "T1021.001": "lateral_movement",  # Remote Desktop Protocol
    "T1566": "initial_access",  # Phishing
    "T1203": "execution",  # Exploitation for Client Execution
    "T1543.003": "persistence",  # Create or Modify System Process: Windows Service
    "T1055": "defense_evasion",  # Process Injection
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


def _bs_p005_legacy_infer_scenarios(
    chains: List[CorrelatorEventChain],
    findings: List[Finding],
    custom_templates_dir: Optional[Path] = None,
) -> List[Scenario]:
    """
    이벤트 체인과 탐지 결과로부터 공격 시나리오를 추론합니다.

    Args:
        chains: 상관분석으로 생성된 이벤트 체인
        findings: 규칙 기반 탐지 결과
        custom_templates_dir: 사용자 정의 템플릿 디렉토리 경로 (선택적)

    Returns:
        추론된 공격 시나리오 목록
    """
    if not chains:
        return []

    # 시나리오 템플릿 로드 (기본 + 사용자 정의)
    templates = _get_scenario_templates(custom_templates_dir)

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
                _bs_p006_attack_requirement_satisfied(t, tech) for t in matched_techniques
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


def _get_scenario_templates(custom_templates_dir: Optional[Path] = None) -> List[ScenarioTemplate]:
    """
    시나리오 템플릿 반환 (기본 + 사용자 정의)

    Args:
        custom_templates_dir: 사용자 정의 템플릿 디렉토리 경로

    Returns:
        시나리오 템플릿 리스트
    """
    templates = [
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
        # 레지스트리 영구성 설정
        ScenarioTemplate(
            template_id="registry_persistence",
            name="레지스트리 영구성 설정",
            description="레지스트리 Run/RunOnce 키를 통한 자동 실행 설정",
            required_techniques=["T1547.001"],  # Registry Run Keys
            optional_techniques=["T1059.001", "T1053.005"],  # PowerShell, Scheduled Task
            chain_patterns=[],
            attack_stage="persistence",
        ),
        # 스케줄된 작업을 통한 실행
        ScenarioTemplate(
            template_id="scheduled_task_execution",
            name="스케줄된 작업을 통한 실행",
            description="스케줄된 작업 생성 및 실행을 통한 공격",
            required_techniques=["T1053.005"],  # Scheduled Task
            optional_techniques=["T1059.001", "T1547.001"],  # PowerShell, Registry
            chain_patterns=[],
            attack_stage="execution",
        ),
        # BITS를 통한 데이터 전송
        ScenarioTemplate(
            template_id="bits_data_transfer",
            name="BITS를 통한 데이터 전송",
            description="Background Intelligent Transfer Service를 이용한 데이터 전송",
            required_techniques=["T1197"],  # BITS Jobs
            optional_techniques=["T1105", "T1071"],  # Ingress Tool Transfer, C2 Protocol
            chain_patterns=["network_data"],
            attack_stage="command_and_control",
        ),
        # RDP를 통한 측면 이동
        ScenarioTemplate(
            template_id="rdp_lateral",
            name="RDP를 통한 측면 이동",
            description="원격 데스크톱 프로토콜을 이용한 측면 이동",
            required_techniques=["T1021.001"],  # Remote Desktop Protocol
            optional_techniques=["T1078", "T1003"],  # Valid Accounts, Credential Dumping
            chain_patterns=[],
            attack_stage="lateral_movement",
        ),
        # 파일리스 공격 (PowerShell 메모리 실행)
        ScenarioTemplate(
            template_id="fileless_attack",
            name="파일리스 공격",
            description="디스크에 파일을 남기지 않고 메모리에서 직접 실행",
            required_techniques=["T1059.001"],  # PowerShell
            optional_techniques=["T1218.005", "T1055"],  # Mshta, Process Injection
            chain_patterns=["encoded_exec"],
            attack_stage="defense_evasion",
        ),
        # 자격증명 덤프
        ScenarioTemplate(
            template_id="credential_dumping",
            name="자격증명 덤프",
            description="시스템 자격증명 추출 및 덤프",
            required_techniques=["T1003"],  # OS Credential Dumping
            optional_techniques=["T1059.001", "T1047"],  # PowerShell, WMI
            chain_patterns=[],
            attack_stage="credential_access",
        ),
        # 서비스 생성 및 실행
        ScenarioTemplate(
            template_id="service_creation",
            name="서비스 생성 및 실행",
            description="Windows 서비스 생성을 통한 영구성 및 실행",
            required_techniques=["T1543.003"],  # Create or Modify System Process: Windows Service
            optional_techniques=["T1059.001", "T1547.001"],  # PowerShell, Registry
            chain_patterns=[],
            attack_stage="persistence",
        ),
    ]

    # 사용자 정의 템플릿 로드
    if custom_templates_dir:
        custom_templates = _load_custom_templates(custom_templates_dir)
        templates.extend(custom_templates)

    return templates


def _load_custom_templates(templates_dir: Path) -> List[ScenarioTemplate]:
    """
    YAML 파일에서 사용자 정의 시나리오 템플릿 로드

    Args:
        templates_dir: 템플릿 파일이 있는 디렉토리

    Returns:
        로드된 시나리오 템플릿 리스트
    """
    templates: List[ScenarioTemplate] = []

    if not templates_dir.exists() or not templates_dir.is_dir():
        logger.debug(f"템플릿 디렉토리가 존재하지 않습니다: {templates_dir}")
        return templates

    # YAML 파일 검색
    for ext in ("*.yml", "*.yaml"):
        for template_file in templates_dir.rglob(ext):
            try:
                data = yaml.safe_load(template_file.read_text(encoding="utf-8"))
                if not data:
                    continue

                # 단일 템플릿 또는 리스트로 처리
                if isinstance(data, dict):
                    data = [data]

                for template_data in data or []:
                    try:
                        template = _parse_template_from_dict(template_data)
                        if template:
                            templates.append(template)
                            logger.debug(f"사용자 정의 템플릿 로드: {template.template_id}")
                    except Exception as e:
                        logger.warning(f"템플릿 파싱 실패 ({template_file}): {e}")
                        continue
            except Exception as e:
                logger.warning(f"템플릿 파일 로드 실패 ({template_file}): {e}")
                continue

    logger.info(f"사용자 정의 템플릿 {len(templates)}개 로드 완료")
    return templates


def _parse_template_from_dict(data: Dict[str, Any]) -> Optional[ScenarioTemplate]:
    """
    딕셔너리에서 시나리오 템플릿 파싱

    Args:
        data: 템플릿 데이터 딕셔너리

    Returns:
        ScenarioTemplate 객체 또는 None
    """
    try:
        # 필수 필드 확인
        template_id = data.get("template_id") or data.get("id")
        name = data.get("name") or data.get("title")
        description = data.get("description", "")
        required_techniques = data.get("required_techniques", [])
        optional_techniques = data.get("optional_techniques", [])
        chain_patterns = data.get("chain_patterns", [])
        attack_stage = data.get("attack_stage", "execution")

        if not template_id or not name:
            logger.warning("템플릿에 template_id 또는 name이 없습니다")
            return None

        # 리스트가 아닌 경우 변환
        if not isinstance(required_techniques, list):
            required_techniques = [required_techniques] if required_techniques else []
        if not isinstance(optional_techniques, list):
            optional_techniques = [optional_techniques] if optional_techniques else []
        if not isinstance(chain_patterns, list):
            chain_patterns = [chain_patterns] if chain_patterns else []

        return ScenarioTemplate(
            template_id=str(template_id),
            name=str(name),
            description=str(description),
            required_techniques=[str(t).upper() for t in required_techniques],
            optional_techniques=[str(t).upper() for t in optional_techniques],
            chain_patterns=[str(p) for p in chain_patterns],
            attack_stage=str(attack_stage),
            confidence_weights=data.get("confidence_weights", {}),
        )
    except Exception as e:
        logger.warning(f"템플릿 파싱 중 오류: {e}")
        return None


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

# BREACHSCOPE_P0_05_SCENARIO_SCOPE_V1
# Scenario inference is evaluated per connected evidence scope instead of the
# global findings pool. Independent hosts/sessions cannot satisfy each other's
# ATT&CK requirements merely because they exist in the same case.
import functools as _bs_p005_functools
import inspect as _bs_p005_inspect
from collections.abc import Mapping as _bs_p005_Mapping


def _bs_p005_get(obj, key, default=None):
    if isinstance(obj, _bs_p005_Mapping):
        return obj.get(key, default)
    return getattr(obj, key, default)


def _bs_p005_scalar(value):
    if isinstance(value, (list, tuple, set)):
        for item in value:
            scalar = _bs_p005_scalar(item)
            if scalar not in (None, ""):
                return scalar
        return None
    return value


def _bs_p005_norm(value):
    value = _bs_p005_scalar(value)
    if value is None:
        return None
    text = str(value).strip()
    return text.casefold() if text else None


def _bs_p005_scope(obj, _depth=0, _seen=None):
    if obj is None or _depth > 4:
        return {"hosts": set(), "sessions": set()}

    if _seen is None:
        _seen = set()

    oid = id(obj)
    if oid in _seen:
        return {"hosts": set(), "sessions": set()}
    _seen.add(oid)

    hosts = set()
    sessions = set()

    def add_host(value):
        value = _bs_p005_norm(value)
        if value:
            hosts.add(value)

    def add_session(value):
        value = _bs_p005_norm(value)
        if value:
            sessions.add(value)

    if isinstance(obj, _bs_p005_Mapping):
        items = list(obj.items())
    elif isinstance(obj, (str, bytes, int, float, bool)):
        items = []
    else:
        try:
            items = list(vars(obj).items())
        except (TypeError, AttributeError):
            items = []

    for key, value in items:
        lname = str(key).casefold()

        if lname in {"host", "hostname", "computer", "computername"}:
            if isinstance(value, _bs_p005_Mapping):
                add_host(
                    value.get("name")
                    or value.get("hostname")
                    or value.get("computer")
                )
            else:
                add_host(value)
        elif lname in {
            "session_id", "sessionid", "logonid", "logon_id",
            "targetlogonid", "subjectlogonid"
        }:
            if isinstance(value, _bs_p005_Mapping):
                add_session(
                    value.get("id")
                    or value.get("session_id")
                    or value.get("logon_id")
                )
            else:
                add_session(value)

        if lname == "canonical" and isinstance(value, _bs_p005_Mapping):
            host_obj = value.get("host")
            if isinstance(host_obj, _bs_p005_Mapping):
                add_host(host_obj.get("name"))
            session_obj = value.get("session")
            if isinstance(session_obj, _bs_p005_Mapping):
                add_session(session_obj.get("id"))

        if (
            lname in {
                "event", "events", "evidence", "finding", "findings",
                "raw", "canonical", "members", "items"
            }
            or isinstance(value, (list, tuple, set, dict))
        ):
            children = value if isinstance(value, (list, tuple, set)) else [value]
            for child in children:
                nested = _bs_p005_scope(child, _depth + 1, _seen)
                hosts.update(nested["hosts"])
                sessions.update(nested["sessions"])

    return {"hosts": hosts, "sessions": sessions}


def _bs_p005_related(left, right):
    left_sessions = left["sessions"]
    right_sessions = right["sessions"]
    if left_sessions and right_sessions:
        return bool(left_sessions & right_sessions)

    left_hosts = left["hosts"]
    right_hosts = right["hosts"]
    if left_hosts and right_hosts:
        return bool(left_hosts & right_hosts)

    return False


def _bs_p005_partition_chains(chains):
    chains = list(chains or [])
    if len(chains) <= 1:
        return [chains] if chains else []

    scopes = [_bs_p005_scope(chain) for chain in chains]
    parent = list(range(len(chains)))

    def find(index):
        while parent[index] != index:
            parent[index] = parent[parent[index]]
            index = parent[index]
        return index

    def union(a, b):
        ra, rb = find(a), find(b)
        if ra != rb:
            parent[rb] = ra

    for i in range(len(chains)):
        for j in range(i + 1, len(chains)):
            if _bs_p005_related(scopes[i], scopes[j]):
                union(i, j)

    groups = {}
    for index, chain in enumerate(chains):
        groups.setdefault(find(index), []).append(chain)

    return list(groups.values())


def _bs_p005_component_scope(chains):
    merged = {"hosts": set(), "sessions": set()}
    for chain in chains:
        scope = _bs_p005_scope(chain)
        merged["hosts"].update(scope["hosts"])
        merged["sessions"].update(scope["sessions"])
    return merged


def _bs_p005_filter_findings(findings, component_scope):
    selected = []
    for finding in findings or []:
        scope = _bs_p005_scope(finding)

        if scope["sessions"] and component_scope["sessions"]:
            if scope["sessions"] & component_scope["sessions"]:
                selected.append(finding)
            continue

        if scope["hosts"] and component_scope["hosts"]:
            if scope["hosts"] & component_scope["hosts"]:
                selected.append(finding)
            continue

        # Unscoped findings stay available elsewhere in the report, but cannot
        # strengthen a scoped attack hypothesis without host/session evidence.

    return selected


@_bs_p005_functools.wraps(_bs_p005_legacy_infer_scenarios)
def infer_scenarios(*args, **kwargs):
    signature = _bs_p005_inspect.signature(_bs_p005_legacy_infer_scenarios)
    bound = signature.bind_partial(*args, **kwargs)

    findings_param = next(
        (name for name in signature.parameters if name.casefold() == "findings"),
        None,
    )
    chains_param = next(
        (name for name in signature.parameters if name.casefold() == "chains"),
        None,
    )

    if (
        findings_param is None
        or chains_param is None
        or findings_param not in bound.arguments
        or chains_param not in bound.arguments
    ):
        return _bs_p005_legacy_infer_scenarios(*args, **kwargs)

    findings = list(bound.arguments[findings_param] or [])
    chains = list(bound.arguments[chains_param] or [])

    if not chains:
        return _bs_p005_legacy_infer_scenarios(*args, **kwargs)

    components = _bs_p005_partition_chains(chains)
    results = []

    for component in components:
        scope = _bs_p005_component_scope(component)
        scoped_findings = _bs_p005_filter_findings(findings, scope)

        call_bound = signature.bind_partial(*args, **kwargs)
        call_bound.arguments[findings_param] = scoped_findings
        call_bound.arguments[chains_param] = component

        partial = _bs_p005_legacy_infer_scenarios(*call_bound.args, **call_bound.kwargs)
        if partial:
            results.extend(list(partial))

    return results

# BREACHSCOPE_P0_06_ATTACK_MATCH_V1
# ATT&CK requirement semantics:
# - exact technique/sub-technique IDs match;
# - a parent requirement (e.g. T1059) may be satisfied by one of its direct/
#   nested sub-techniques (e.g. T1059.001);
# - a sub-technique requirement (e.g. T1059.001) requires that exact ID;
# - sibling sub-techniques never satisfy each other.
import re as _bs_p006_re

_BS_P006_ATTACK_ID_RE = _bs_p006_re.compile(
    r"^T\d{4}(?:\.\d{3})?$",
    _bs_p006_re.IGNORECASE,
)


def _bs_p006_attack_requirement_satisfied(required, observed):
    if required is None or observed is None:
        return False

    required_id = str(required).strip().upper()
    observed_id = str(observed).strip().upper()

    if not _BS_P006_ATTACK_ID_RE.fullmatch(required_id):
        return False
    if not _BS_P006_ATTACK_ID_RE.fullmatch(observed_id):
        return False

    if required_id == observed_id:
        return True

    # Parent templates are intentionally broad. A specific sub-technique
    # template is not: T1059.001 must never be satisfied by T1059.003.
    if "." not in required_id and observed_id.startswith(required_id + "."):
        return True

    return False
