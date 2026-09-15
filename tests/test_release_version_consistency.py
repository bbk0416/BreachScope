from pathlib import Path

import pytest

from api import __version__ as api_version
from api.main import app
from api.services.ops_status import live_status
from breachscope import __version__ as package_version
from breachscope.version import get_build_version, get_project_version

from scripts.verify_release_version import (
    normalize_release_tag,
    read_project_version,
    verify_release_version,
)


def test_normalize_release_tag_accepts_standard_v_prefix():
    assert normalize_release_tag("v1.2.3") == "1.2.3"
    assert normalize_release_tag("1.2.3") == "1.2.3"


def test_normalize_release_tag_rejects_empty_value():
    with pytest.raises(ValueError, match="empty"):
        normalize_release_tag(" v")


def test_read_project_version(tmp_path: Path):
    (tmp_path / "pyproject.toml").write_text(
        '[project]\nname = "breachscope"\nversion = "1.2.3"\n',
        encoding="utf-8",
    )
    assert read_project_version(tmp_path) == "1.2.3"


def test_release_tag_must_match_project_version():
    verify_release_version("v1.2.3", "1.2.3")
    with pytest.raises(ValueError, match="mismatch"):
        verify_release_version("v1.2.4", "1.2.3")

def test_runtime_version_surfaces_match_effective_project_version():
    expected = read_project_version(Path("."))
    assert get_project_version(".") == expected
    assert package_version == expected
    assert api_version == expected
    assert app.version == expected
    assert live_status()["version"] == expected


def test_build_version_override_is_separate_from_project_version(monkeypatch):
    expected = read_project_version(Path("."))
    monkeypatch.setenv("BS_BUILD_VERSION", "ci-build")
    assert get_project_version(".") == expected
    assert get_build_version(".") == "ci-build"
