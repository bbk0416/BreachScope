from pathlib import Path

import yaml


ROOT = Path(__file__).resolve().parents[1]
SUMMARY = ROOT / "external_baseline" / "windows_apt_2025_source_intake_summary.yaml"


def _summary() -> dict:
    return yaml.safe_load(SUMMARY.read_text(encoding="utf-8"))


def test_windows_apt_upstream_article_does_not_unlock_row_level_partition() -> None:
    data = _summary()
    article = data["upstream_article_review"]

    assert article["doi"] == "10.1016/j.dib.2026.112569"
    assert article["pmcid"] == "PMC12950481"
    assert "38393 general logs" in article["observations"][0]
    assert "63620 malicious logs" in article["observations"][0]
    assert any(
        "normal logs may also contain MITRE tags" in item
        for item in article["observations"]
    )
    assert any(
        "not an explicit row-level malicious-versus-general class field" in item
        for item in article["observations"]
    )
    assert "insufficient" in article["conclusion"]

    label = data["label_provenance"]
    assert label["attack_or_general_partition_identified_without_semantic_rows"] is False
    assert label["ATTACK_or_Wazuh_mitre_mapping_as_independent_oracle"] is False
    assert label["result"] == "NOT_IDENTIFIED_FAIL_CLOSED"

    decision = data["decision"]
    assert decision["phase_1_label_provenance"] == "FAIL_CLOSED"
    assert decision["phase_2_semantic_row_access_authorized"] is False
    assert decision["phase_2_adapter_execution_authorized"] is False
    assert decision["detector_execution_against_windows_apt_authorized"] is False
