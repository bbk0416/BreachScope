from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional


@dataclass
class Event:
    timestamp: str
    host: str
    source: str
    event_id: Optional[str] = None
    level: Optional[str] = None
    user: Optional[str] = None
    command_line: Optional[str] = None
    raw: Dict[str, Any] = field(default_factory=dict)


@dataclass
class Rule:
    id: str
    name: str
    description: str
    field: str
    pattern: str
    mitre_technique: Optional[str] = None
    severity: str = "medium"
    operator: Optional[str] = None  # regex|contains|startswith|endswith|equals
    fields: Optional[List[str]] = None  # additional fields to check


@dataclass
class Finding:
    rule_id: str
    rule_name: str
    severity: str
    mitre_technique: Optional[str]
    event: Event
    matched_value: Optional[str]
    matched_context: Optional[str] = None


@dataclass
class EventChain:
    """연관된 이벤트들의 체인"""
    chain_id: str
    events: List[Event]
    findings: List[Finding]
    start_time: Optional[str] = None
    end_time: Optional[str] = None
    description: str = ""
    confidence: float = 0.0
    chain_type: str = ""


@dataclass
class Scenario:
    """공격 시나리오"""
    scenario_id: str
    name: str
    description: str
    mitre_techniques: List[str]
    chains: List[EventChain]
    confidence: float = 0.0
    attack_stage: str = ""  # "initial_access", "execution", "persistence", "lateral_movement" 등


@dataclass
class Report:
    summary: Dict[str, Any]
    findings: List[Finding]
    events: List[Event]
    chains: List[EventChain] = field(default_factory=list)
    scenarios: List[Scenario] = field(default_factory=list)
