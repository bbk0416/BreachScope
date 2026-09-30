from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
WORKFLOW = ROOT / ".github" / "workflows" / "ci.yml"


def test_ci_fetches_pinned_historical_evidence_commit() -> None:
    text = WORKFLOW.read_text(encoding="utf-8")
    command = (
        "git fetch --no-tags origin "
        "bad0c88037d489f5b375c120002be74ac6082ffa"
    )
    assert text.count("uses: actions/checkout@") == 3
    assert text.count(command) == 2
    assert "fetch-depth: 0" not in text


def test_ci_python_311_release_steps_match_pinned_matrix_version() -> None:
    text = WORKFLOW.read_text(encoding="utf-8")
    assert "matrix.python-version == '3.11'" not in text
    assert text.count("matrix.python-version == '3.11.16'") == 3


def test_ci_demo_artifact_retention_is_bounded() -> None:
    text = WORKFLOW.read_text(encoding="utf-8")
    assert "name: breachscope-demo-report" in text
    assert "retention-days: 1" in text

def test_ci_runs_clean_install_on_linux_and_macos() -> None:
    text = WORKFLOW.read_text(encoding="utf-8")
    assert "clean-install:" in text
    assert "os: [ubuntu-latest, macos-15-intel]" in text
    assert 'python-version: "3.11.16"' in text
    assert "python scripts/verify_clean_install_e2e.py" in text
    assert "timeout-minutes: 20" in text
