from api.services.report_preview import build_preview


def test_build_preview_limits_and_shapes_dashboard_data():
    report_data = {
        "summary": {
            "total_findings": 2,
            "risk": {"score": 73, "level": "high", "unique_hosts": 2, "unique_techniques": 2},
            "executive_summary": ["요약 1", "요약 2"],
            "recommended_actions": ["조치 1"],
            "containment_checklist": [{"priority": "P1", "task": "격리", "why": "증거 보존"}],
            "false_positive_questions": ["정상 작업인가?"],
            "top_findings": [{
                "severity": "high",
                "rule": "LSASS Dump Attempt",
                "mitre_technique": "T1003.001",
                "mitre_name": "LSASS Memory",
                "host": "WS-01",
                "timestamp": "2026-01-01T00:00:00Z",
                "context": "x" * 300,
            }],
            "incident_timeline": [{
                "timestamp": "2026-01-01T00:00:00Z",
                "delta_seconds": None,
                "host": "WS-01",
                "user": "CORP\\alice",
                "severity": "high",
                "tactic": "Credential Access",
                "rule": "LSASS Dump Attempt",
                "context": "ctx",
            }],
            "attack_coverage": [{
                "tactic": "Credential Access",
                "findings": 1,
                "highest_severity": "high",
                "techniques": ["T1003.001"],
                "hosts": ["WS-01"],
            }],
            "host_risk_summary": [{"host": "WS-01", "score": 70, "level": "high", "findings": 1}],
            "indicator_totals": {"url": 1, "domain": 1},
            "severity_counts": {"high": 1, "medium": 1},
            "host_counts": {"WS-02": 3, "WS-01": 1},
            "mitre_counts": {"T1003.001": 1},
            "sample_scenarios": [{"id": "credential_dump_triage", "events": 4, "findings": 3}],
            "rule_pack": {"total_rules": 50, "unique_techniques": 40, "coverage_percent_core_windows": 96.9},
        }
    }

    preview = build_preview(report_data)

    assert preview["risk"]["score"] == 73
    assert preview["total_findings"] == 2
    assert preview["rule_pack"]["total_rules"] == 50
    assert preview["severity_counts"][0] == {"name": "high", "count": 1}
    assert preview["host_counts"][0] == {"name": "WS-02", "count": 3}
    assert preview["top_findings"][0]["context"].endswith("…")
    assert preview["attack_coverage"][0]["tactic"] == "Credential Access"
