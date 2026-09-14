from pathlib import Path

import pytest

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
