from __future__ import annotations

import importlib.metadata
from pathlib import Path

import pytest
import yaml

from breachscope.rules import load_rules, sigma_like_to_rules
from breachscope.sigma_adapter import (
    SigmaIntegrationError,
    convert_supported_sigma_document,
    validate_with_pysigma,
)


def _supported_doc():
    return {
        "title": "Encoded PowerShell",
        "tags": ["attack.t1059.001"],
        "logsource": {"category": "process_creation", "product": "windows"},
        "detection": {
            "selection": {
                "CommandLine|contains": ["-encodedcommand", " -enc "],
            },
            "condition": "selection",
        },
        "level": "high",
    }


def test_pysigma_dependency_is_real_and_current_major():
    version = importlib.metadata.version("pysigma")
    major = int(version.split(".", 1)[0])
    assert major == 1


def test_real_pysigma_parser_accepts_supported_document():
    validate_with_pysigma(_supported_doc())


def test_supported_sigma_subset_preserves_or_values_and_metadata():
    rules = convert_supported_sigma_document(_supported_doc())
    assert len(rules) == 1
    rule = rules[0]
    assert rule.field == "command_line"
    assert rule.operator == "contains"
    assert rule.pattern == "-encodedcommand| -enc "
    assert rule.mitre_technique == "T1059.001"
    assert rule.severity == "high"


def test_rules_module_sigma_entrypoint_uses_strict_adapter():
    rules = sigma_like_to_rules(_supported_doc())
    assert len(rules) == 1
    assert rules[0].pattern == "-encodedcommand| -enc "


def test_boolean_sigma_condition_is_rejected_not_flattened():
    doc = _supported_doc()
    doc["detection"]["filter"] = {"CommandLine|contains": "benign"}
    doc["detection"]["condition"] = "selection and not filter"

    with pytest.raises(SigmaIntegrationError):
        convert_supported_sigma_document(doc)


def test_multifield_selection_is_rejected_not_turned_into_or_rules():
    doc = _supported_doc()
    doc["detection"]["selection"]["Image|endswith"] = "\\\\powershell.exe"

    with pytest.raises(SigmaIntegrationError):
        convert_supported_sigma_document(doc)


def test_unsupported_modifier_is_rejected():
    doc = _supported_doc()
    doc["detection"]["selection"] = {"CommandLine|endswith": "-enc"}

    with pytest.raises(SigmaIntegrationError):
        convert_supported_sigma_document(doc)


def test_pipe_literal_is_rejected_to_avoid_or_semantic_corruption():
    doc = _supported_doc()
    doc["detection"]["selection"] = {"CommandLine|contains": "a|b"}

    with pytest.raises(SigmaIntegrationError):
        convert_supported_sigma_document(doc)


def test_load_rules_fails_closed_for_unsupported_sigma(tmp_path):
    doc = _supported_doc()
    doc["detection"]["selection"] = {
        "CommandLine|contains": "powershell",
        "Image|endswith": "\\\\powershell.exe",
    }
    (tmp_path / "unsupported.yml").write_text(
        yaml.safe_dump(doc, sort_keys=False),
        encoding="utf-8",
    )

    with pytest.raises(SigmaIntegrationError):
        load_rules(tmp_path)


def test_project_sigma_example_is_valid_and_loadable():
    root = Path(__file__).resolve().parents[1]
    example = root / "rules" / "sigma_example.yml"
    doc = yaml.safe_load(example.read_text(encoding="utf-8"))
    validate_with_pysigma(doc)

    converted = convert_supported_sigma_document(doc)
    assert converted
    assert converted[0].operator == "contains"


def test_project_rule_directory_passes_sigma_preflight_and_loads():
    root = Path(__file__).resolve().parents[1]
    rules = load_rules(root / "rules")
    assert rules


def test_p0_09_markers_present():
    import breachscope.rules as rules_module

    source = open(rules_module.__file__, "r", encoding="utf-8").read()
    assert "BREACHSCOPE_P0_09_PYSIGMA_STRICT_V1" in source
