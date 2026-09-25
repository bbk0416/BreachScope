from __future__ import annotations

import argparse
import hashlib
import json
import os
import subprocess
import time
import zipfile
from pathlib import Path
from typing import Any, Iterator

import yaml

from breachscope.analyzer import apply_rules
from breachscope.brawl import event_from_brawl_record, extract_bsf_steps
from breachscope.brawl_score import score_brawl_steps
from breachscope.rules import load_rules
from scripts.evaluate_external_holdout import rules_tree_hash


ANALYSIS_ID = "brawl-independent-attack-step-technique-holdout-v1"
CONTRACT_PATH = Path("external_baseline/brawl_attack_step_scoring_preregistration.yaml")
LOCK_NAME = "BRAWL_ATTACK_STEP_TECHNIQUE_HOLDOUT_V1.lock"
ALLOWED_TYPES = {"game_metadata", "sysmon", "win_event", "computer_properties", "bsf_events"}


class BrawlOnePassError(RuntimeError):
    pass


def _sha256(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def _git_blob_sha1(path: Path) -> str:
    data = path.read_bytes()
    h = hashlib.sha1()
    h.update(f"blob {len(data)}\0".encode("ascii"))
    h.update(data)
    return h.hexdigest()


def _git(repo: Path, *args: str) -> str:
    return subprocess.check_output(["git", *args], cwd=repo, text=True).strip()


def _require_clean_repo(repo: Path) -> None:
    if _git(repo, "status", "--porcelain", "-uall"):
        raise BrawlOnePassError("repository working tree must be clean")


def _iter_json_records(data: bytes, member: str) -> Iterator[dict[str, Any]]:
    try:
        text = data.decode("utf-8-sig").strip()
    except UnicodeDecodeError as exc:
        raise BrawlOnePassError(f"non-UTF-8 data member: {member}") from exc
    if not text:
        return

    try:
        parsed = json.loads(text)
    except json.JSONDecodeError:
        for line_number, line in enumerate(text.splitlines(), start=1):
            if not line.strip():
                continue
            try:
                item = json.loads(line)
            except json.JSONDecodeError as exc:
                raise BrawlOnePassError(
                    f"unsupported JSON framing in {member} line {line_number}: {exc}"
                ) from exc
            if not isinstance(item, dict):
                raise BrawlOnePassError(f"non-object JSON record in {member} line {line_number}")
            yield item
        return

    if isinstance(parsed, dict):
        yield parsed
        return
    if isinstance(parsed, list):
        for index, item in enumerate(parsed):
            if not isinstance(item, dict):
                raise BrawlOnePassError(f"non-object JSON array item in {member}[{index}]")
            yield item
        return
    raise BrawlOnePassError(f"unsupported top-level JSON value in {member}")


def _data_members(archive: zipfile.ZipFile) -> list[zipfile.ZipInfo]:
    members = []
    for info in archive.infolist():
        if info.is_dir():
            continue
        normalized = info.filename.replace("\\", "/").lstrip("/")
        if normalized.startswith("data/") or "/data/" in f"/{normalized}":
            members.append(info)
    if not members:
        raise BrawlOnePassError("archive contains no files under data/")
    return members


def _acquire_lock() -> Path:
    lock_dir = Path.home() / ".breachscope" / "canonical_locks"
    lock_dir.mkdir(parents=True, exist_ok=True)
    lock_path = lock_dir / LOCK_NAME
    payload = {
        "analysis_id": ANALYSIS_ID,
        "pid": os.getpid(),
        "created_unix": time.time(),
    }
    try:
        fd = os.open(lock_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL)
    except FileExistsError as exc:
        raise BrawlOnePassError(f"canonical lock already exists: {lock_path}") from exc
    with os.fdopen(fd, "w", encoding="utf-8") as handle:
        json.dump(payload, handle, sort_keys=True)
        handle.write("\n")
    return lock_path


def run(repo: Path, archive_path: Path) -> dict[str, Any]:
    contract = yaml.safe_load((repo / CONTRACT_PATH).read_text(encoding="utf-8"))
    if contract.get("analysis_id") != ANALYSIS_ID:
        raise BrawlOnePassError("analysis_id mismatch")
    if contract.get("status") != "PREREGISTERED_NOT_RUN":
        raise BrawlOnePassError("contract is not PREREGISTERED_NOT_RUN")

    _require_clean_repo(repo)

    source = contract["source"]
    if archive_path.stat().st_size != source["archive_size_bytes"]:
        raise BrawlOnePassError("archive size mismatch")
    blob_sha1 = _git_blob_sha1(archive_path)
    if blob_sha1 != source["archive_git_blob_sha1"]:
        raise BrawlOnePassError("archive Git blob SHA-1 mismatch")

    adapter = contract["adapter"]
    scorer = contract["scorer"]
    if _sha256(repo / adapter["path"]) != adapter["sha256"]:
        raise BrawlOnePassError("adapter SHA-256 mismatch")
    if _sha256(repo / scorer["path"]) != scorer["sha256"]:
        raise BrawlOnePassError("scorer SHA-256 mismatch")
    if _sha256(repo / adapter["contract"]) != adapter["contract_sha256"]:
        raise BrawlOnePassError("adapter contract SHA-256 mismatch")

    rules_hash, rule_file_count = rules_tree_hash(repo / "rules")
    if rules_hash != contract["preregistration_base"]["current_rules_sha256"]:
        raise BrawlOnePassError("current rules SHA-256 mismatch")

    # The permanent lock is created only after immutable bytes/code/rules are
    # verified and immediately before raw archive contents are opened.
    lock_path = _acquire_lock()

    records_by_type = {name: 0 for name in sorted(ALLOWED_TYPES)}
    events = []
    steps = []
    member_names: list[str] = []

    with zipfile.ZipFile(archive_path) as archive:
        for info in _data_members(archive):
            member_names.append(info.filename)
            for record in _iter_json_records(archive.read(info), info.filename):
                record_type = str(record.get("type") or "").strip()
                if record_type not in ALLOWED_TYPES:
                    raise BrawlOnePassError(
                        f"undocumented record type {record_type!r} in {info.filename}"
                    )
                records_by_type[record_type] += 1
                if record_type in {"sysmon", "win_event"}:
                    event = event_from_brawl_record(record)
                    if event is None:
                        raise BrawlOnePassError("host telemetry adapter returned None")
                    events.append(event)
                elif record_type == "bsf_events":
                    steps.extend(extract_bsf_steps(record))

    rules = load_rules(repo / "rules")
    findings = list(apply_rules(events, rules))
    score = score_brawl_steps(steps, findings)

    return {
        "schema": "breachscope.brawl_attack_step_technique_holdout_result.v1",
        "analysis_id": ANALYSIS_ID,
        "status": "COMPLETED",
        "repo_commit": _git(repo, "rev-parse", "HEAD"),
        "rules_tree_sha256": rules_hash,
        "rule_file_count": rule_file_count,
        "source": {
            "repository": source["repository"],
            "commit": source["commit"],
            "archive_path": source["archive_path"],
            "archive_size_bytes": archive_path.stat().st_size,
            "archive_git_blob_sha1": blob_sha1,
            "archive_sha256": _sha256(archive_path),
            "members": member_names,
            "records_by_type": records_by_type,
        },
        "execution": {
            "lock_path": str(lock_path),
            "host_event_count": len(events),
            "finding_count": len(findings),
            "bsf_step_count": len(steps),
        },
        "score": score,
        "claim_boundaries": contract["claim_boundaries"],
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--archive", required=True)
    parser.add_argument("--output", required=True)
    args = parser.parse_args()

    repo = Path(__file__).resolve().parents[1]
    result = run(repo, Path(args.archive).resolve())
    output = Path(args.output).resolve()
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(result, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(result, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
