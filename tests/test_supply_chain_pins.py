from __future__ import annotations

import importlib.util
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "verify_supply_chain_pins.py"


def _module():
    spec = importlib.util.spec_from_file_location(
        "breachscope_verify_supply_chain_pins",
        SCRIPT,
    )
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


def test_supply_chain_pin_contract_passes():
    module = _module()
    assert module.verify_repo_contract() == []


def test_all_workflow_action_refs_are_immutable_shas():
    module = _module()
    workflow_dir = ROOT / ".github" / "workflows"
    refs = []

    for path in workflow_dir.glob("*.y*ml"):
        refs.extend(
            module.USES_RE.findall(
                path.read_text(encoding="utf-8")
            )
        )

    assert len(refs) == 10
    assert all(
        re.fullmatch(r"[0-9a-f]{40}", ref)
        for _, ref in refs
    )


def test_docker_python_base_is_digest_pinned():
    module = _module()
    text = (ROOT / "Dockerfile").read_text(encoding="utf-8-sig")
    actual = module._docker_base_ref(text)

    assert actual == module.DOCKER_BASE
    assert "@sha256:" in actual


def test_docker_base_parser_tolerates_utf8_bom_and_comments():
    module = _module()
    text = (
        "\ufeff# syntax=docker/dockerfile:1\n"
        "\n"
        f"FROM {module.DOCKER_BASE}\n"
        "RUN true\n"
    )
    assert module._docker_base_ref(text) == module.DOCKER_BASE


def test_dependabot_monitors_action_and_docker_pins():
    text = (ROOT / ".github" / "dependabot.yml").read_text(
        encoding="utf-8"
    )
    assert 'package-ecosystem: "github-actions"' in text
    assert 'package-ecosystem: "docker"' in text
    assert text.count('interval: "weekly"') >= 2


def test_existing_explicit_workflow_permissions_are_preserved():
    module = _module()
    assert module.verify_workflow_permissions() == []
