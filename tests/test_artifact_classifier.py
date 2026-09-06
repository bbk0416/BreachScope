from __future__ import annotations

import pytest

from breachscope.artifacts.classifier import ArtifactCategory, ArtifactClassifier


@pytest.mark.parametrize(
    ("source", "expected"),
    [
        ("Chrome", ArtifactCategory.BROWSER_HISTORY),
        ("chrome", ArtifactCategory.BROWSER_HISTORY),
        ("CHROME", ArtifactCategory.BROWSER_HISTORY),
        ("Edge", ArtifactCategory.BROWSER_HISTORY),
        ("EDGE", ArtifactCategory.BROWSER_HISTORY),
        ("Firefox", ArtifactCategory.BROWSER_HISTORY),
        ("FIREFOX", ArtifactCategory.BROWSER_HISTORY),
        ("Registry", ArtifactCategory.REGISTRY_ARTIFACTS),
        ("REGISTRY", ArtifactCategory.REGISTRY_ARTIFACTS),
        ("USB", ArtifactCategory.USER_ACTIVITY),
        ("usb", ArtifactCategory.USER_ACTIVITY),
    ],
)
def test_source_only_mapping_is_case_insensitive(source, expected):
    event = {
        "source": source,
        "event_id": "",
        "event_type": "",
        "command_line": "",
    }

    assert ArtifactClassifier.classify_event(event) is expected


def test_category_mapping_keys_match_classifier_normalization_contract():
    assert all(key == key.lower() for key in ArtifactClassifier.CATEGORY_MAPPING)
