from __future__ import annotations

import io
import json
import tarfile
from collections import Counter
from pathlib import Path

import scripts.p2_16b_apt3_holdout as p2


def _record(record_number: str = "1") -> dict:
    return {
        "@timestamp": "2019-05-14T22:31:14.252Z",
        "computer_name": "HR001.shire.com",
        "source_name": "Microsoft-Windows-Sysmon",
        "event_id": 1,
        "record_number": record_number,
        "user": {"name": "SYSTEM", "domain": "NT AUTHORITY"},
        "message": "Process Create",
        "event_data": {"Image": r"C:\Windows\System32\cmd.exe"},
    }


def _write_tar(path: Path, lines: list[bytes], member: str = p2.EXPECTED_MEMBER) -> None:
    payload = b"".join(lines)
    info = tarfile.TarInfo(member)
    info.size = len(payload)
    with tarfile.open(path, "w:gz") as tf:
        tf.addfile(info, io.BytesIO(payload))


def test_binding_constants_are_frozen() -> None:
    assert p2.EXPECTED_ARCHIVE_SHA256 == "ab4d1ec4e44102c87946a974f93aa248e49e5001e01fac3f137ec7e61bbc18ed"
    assert p2.FROZEN_PRODUCT_COMMIT == "4514279c0b223483016acf35009ed2985f6a016e"
    assert (p2.DOCUMENTED_SOURCE_HOST, p2.DOCUMENTED_TARGET_HOST) == ("HR001", "HFDC01")


def test_tar_loader_accepts_one_bound_member_and_counts_parse_errors(tmp_path: Path) -> None:
    archive = tmp_path / "sample.tar.gz"
    _write_tar(archive, [(json.dumps(_record()) + "\n").encode(), b"not-json\n"])
    events, parse_errors, hosts = p2._load_events(archive)
    assert len(events) == 1
    assert parse_errors == 1
    # Frozen parser does not alias lowercase computer_name into canonical host.
    assert hosts == Counter({"": 1})


def test_tar_loader_rejects_unexpected_member(tmp_path: Path) -> None:
    archive = tmp_path / "sample.tar.gz"
    _write_tar(archive, [(json.dumps(_record()) + "\n").encode()], member="other.json")
    try:
        p2._load_events(archive)
    except RuntimeError as exc:
        assert "unexpected archive members" in str(exc)
    else:
        raise AssertionError("unexpected member must be rejected")


def test_evaluate_keeps_claim_boundary_without_accuracy_claims(tmp_path: Path, monkeypatch) -> None:
    archive = tmp_path / "bound.tar.gz"
    archive.write_bytes(b"placeholder")
    monkeypatch.setattr(p2, "_assert_frozen_product", lambda _: None)
    monkeypatch.setattr(p2, "_sha256", lambda _: p2.EXPECTED_ARCHIVE_SHA256)
    monkeypatch.setattr(p2, "_load_events", lambda _: ([], 0, Counter()))
    monkeypatch.setattr(p2, "load_rules", lambda _: [])
    monkeypatch.setattr(p2, "rules_tree_hash", lambda _: (p2.EXPECTED_RULES_SHA256, 4))
    monkeypatch.setattr(p2, "apply_rules", lambda events, rules: [])
    monkeypatch.setattr(p2, "correlate_events", lambda events, findings: [])
    monkeypatch.setattr(p2, "infer_scenarios", lambda chains, findings: [])
    result = p2.evaluate(Path.cwd(), archive)
    assert result["analysis_class"] == "independent_external_reconstruction_holdout_one_pass"
    assert result["product_tree_matches_frozen_commit"] is True
    assert result["documented_hr001_hfdc01_chains"] == 0
    assert result["documented_hr001_hfdc01_scenarios"] == 0
    assert set(result["claim_boundary"].values()) >= {"NOT_CLAIMED", "NOT_AVAILABLE"}


def test_canonical_coverage_exposes_lowercase_windows_alias_gap(tmp_path: Path) -> None:
    archive = tmp_path / "sample.tar.gz"
    _write_tar(archive, [(json.dumps(_record()) + "\n").encode()])
    events, _, _ = p2._load_events(archive)
    coverage = p2._canonical_coverage(events)
    assert coverage["events"] == 1
    assert coverage["host_nonempty"] == 0
    assert coverage["raw_computer_name_present"] == 1
    assert coverage["raw_source_name_present"] == 1
    assert coverage["raw_record_number_present"] == 1
