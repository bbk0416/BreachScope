from __future__ import annotations

from types import SimpleNamespace

import pytest

from breachscope import scenario


def _template(*, required, patterns):
    return SimpleNamespace(
        template_id="test_template",
        name="Test Template",
        description="test",
        required_techniques=list(required),
        optional_techniques=[],
        chain_patterns=list(patterns),
        attack_stage="execution",
        confidence_weights={},
    )


def _chain(chain_type="unrelated_chain"):
    return SimpleNamespace(chain_type=chain_type)


def _finding(technique):
    return SimpleNamespace(mitre_technique=technique)


def _isolate_template_engine(monkeypatch, template):
    monkeypatch.setattr(
        scenario,
        "_get_scenario_templates",
        lambda custom_templates_dir=None: [template],
    )
    monkeypatch.setattr(
        scenario,
        "_calculate_scenario_confidence",
        lambda template, chains, techniques, findings: 0.8,
    )
    monkeypatch.setattr(scenario, "_convert_chains", lambda chains: [])
    monkeypatch.setattr(scenario, "_infer_from_chains", lambda chains, findings: [])
    monkeypatch.setattr(
        scenario,
        "Scenario",
        lambda **kwargs: SimpleNamespace(**kwargs),
    )


def test_empty_chain_patterns_mean_no_chain_type_restriction_within_current_scope(monkeypatch):
    template = _template(required=["T1047"], patterns=[])
    _isolate_template_engine(monkeypatch, template)

    result = scenario._bs_p005_legacy_infer_scenarios(
        [_chain("some_other_chain_type")],
        [_finding("T1047")],
    )

    assert len(result) == 1
    assert result[0].scenario_id.endswith("test_template")
    assert result[0].mitre_techniques == ["T1047"]


def test_nonempty_chain_patterns_still_require_matching_chain_type(monkeypatch):
    template = _template(required=["T1047"], patterns=["wmi_lateral"])
    _isolate_template_engine(monkeypatch, template)

    result = scenario._bs_p005_legacy_infer_scenarios(
        [_chain("different_chain")],
        [_finding("T1047")],
    )

    assert result == []


def test_empty_required_techniques_template_is_skipped_during_inference(monkeypatch):
    template = _template(required=[], patterns=[])
    _isolate_template_engine(monkeypatch, template)

    def should_not_run(*args, **kwargs):
        raise AssertionError("confidence must not run for invalid empty-required template")

    monkeypatch.setattr(scenario, "_calculate_scenario_confidence", should_not_run)

    result = scenario._bs_p005_legacy_infer_scenarios(
        [_chain()],
        [_finding("T1047")],
    )

    assert result == []


def test_custom_template_parser_rejects_empty_required_techniques():
    parsed = scenario._parse_template_from_dict(
        {
            "template_id": "empty_required",
            "name": "Empty Required",
            "required_techniques": [],
            "optional_techniques": ["T1059.001"],
            "chain_patterns": ["encoded_exec"],
        }
    )
    assert parsed is None


def test_custom_template_parser_allows_empty_chain_patterns_when_required_exists():
    parsed = scenario._parse_template_from_dict(
        {
            "template_id": "technique_only",
            "name": "Technique Only",
            "required_techniques": ["T1047"],
            "chain_patterns": [],
        }
    )
    assert parsed is not None
    assert parsed.required_techniques == ["T1047"]
    assert parsed.chain_patterns == []


def test_confidence_is_zero_division_safe_for_empty_required_techniques():
    template = _template(required=[], patterns=[])

    confidence = scenario._calculate_scenario_confidence(
        template,
        [],
        set(),
        [],
    )

    assert isinstance(confidence, float)
    assert 0.0 <= confidence <= 1.0


def test_builtin_empty_chain_templates_are_no_longer_intrinsically_unreachable():
    templates = scenario._get_scenario_templates()
    empty_chain_templates = [t for t in templates if not t.chain_patterns]

    assert empty_chain_templates
    assert all(t.required_techniques for t in empty_chain_templates)


def test_p0_08_marker_present():
    source = open(scenario.__file__, "r", encoding="utf-8").read()
    assert "BREACHSCOPE_P0_08_TEMPLATE_INVARIANTS_V1" in source
