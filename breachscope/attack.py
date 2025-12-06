MITRE_NAMES = {
    "T1059": "Command and Scripting Interpreter",
    "T1059.001": "Command and Scripting Interpreter: PowerShell",
    "T1105": "Ingress Tool Transfer",
    "T1047": "Windows Management Instrumentation",
    "T1218.005": "Signed Binary Proxy Execution: Mshta",
    "T1547": "Boot or Logon Autostart Execution",
    "T1547.001": "Boot or Logon Autostart Execution: Registry Run Keys/Startup Folder",
    "T1053": "Scheduled Task/Job",
    "T1053.005": "Scheduled Task/Job: Scheduled Task",
    "T1197": "BITS Jobs",
}


def get_mitre_name(code: str | None) -> str:
    if not code:
        return "Unknown"
    c = code.upper()
    # direct match or prefix technique without subtechnique
    return MITRE_NAMES.get(c) or MITRE_NAMES.get(c.split(".")[0], "Unknown")

