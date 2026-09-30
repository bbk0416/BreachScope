#!/usr/bin/env python3
from __future__ import annotations

import argparse
import hashlib
import json
import os
import shutil
import subprocess
import sys
import tarfile
import tempfile
import time
from collections import Counter
from pathlib import Path
from typing import Any, Iterator

import yaml

REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

ANALYSIS_ID = "p2-36c-current-rulepack-fresh-source-revalidation-v1"
SCHEMA = "breachscope.p2_36c_current_rulepack_fresh_source_revalidation.v1"
ATOMIC_REPLACE_RETRY_DELAYS = (0.05, 0.1, 0.2, 0.4, 0.8, 1.6)


def sha256(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def bytes_sha256(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


def text_sha256(path: Path) -> str:
    return bytes_sha256(path.read_bytes().replace(b"\r\n", b"\n"))


def git(repo: Path, *args: str) -> str:
    return subprocess.check_output(
        ["git", "-C", str(repo), *args],
        text=True,
        encoding="utf-8",
    ).strip()


def git_bytes(repo: Path, *args: str) -> bytes:
    return subprocess.check_output(["git", "-C", str(repo), *args])


def atomic_write(path: Path, payload: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name(path.name + f".tmp.{os.getpid()}")
    tmp.write_bytes(
        (json.dumps(payload, indent=2, ensure_ascii=False) + "\n").encode(
            "utf-8"
        )
    )
    for attempt in range(len(ATOMIC_REPLACE_RETRY_DELAYS) + 1):
        try:
            os.replace(tmp, path)
            return
        except PermissionError:
            if attempt >= len(ATOMIC_REPLACE_RETRY_DELAYS):
                raise
            time.sleep(ATOMIC_REPLACE_RETRY_DELAYS[attempt])


def global_lock_path() -> Path:
    return (
        Path.home()
        / ".breachscope"
        / "canonical_locks"
        / "P2_36C_CURRENT_RULEPACK_FRESH_SOURCE_REVALIDATION.lock"
    )


def acquire_global_lock(path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    try:
        fd = os.open(str(path), os.O_CREAT | os.O_EXCL | os.O_WRONLY)
    except FileExistsError as exc:
        raise RuntimeError(
            f"analysis id already permanently locked: {path}"
        ) from exc
    try:
        os.write(
            fd,
            (
                json.dumps(
                    {
                        "analysis_id": ANALYSIS_ID,
                        "pid": os.getpid(),
                        "created_unix": time.time(),
                    }
                )
                + "\n"
            ).encode("utf-8"),
        )
    finally:
        os.close(fd)


def load_product(repo: Path):
    repo = repo.resolve()
    repo_text = str(repo)
    for name in tuple(sys.modules):
        if (
            name == "breachscope"
            or name.startswith("breachscope.")
            or name == "scripts"
            or name == "scripts.evaluate_external_holdout"
        ):
            sys.modules.pop(name, None)
    sys.path[:] = [entry for entry in sys.path if entry != repo_text]
    sys.path.insert(0, repo_text)

    import breachscope.analyzer as analyzer_module
    import breachscope.ingest as ingest_module
    import breachscope.rules as rules_module
    import breachscope.schemas as schemas_module
    import scripts.evaluate_external_holdout as holdout_module

    modules = (
        analyzer_module,
        ingest_module,
        rules_module,
        schemas_module,
        holdout_module,
    )
    for module in modules:
        module_path = Path(module.__file__).resolve()
        try:
            module_path.relative_to(repo)
        except ValueError as exc:
            raise RuntimeError(
                "product module resolved outside frozen product repo: "
                f"{module.__name__} -> {module_path}"
            ) from exc

    return (
        analyzer_module.apply_rules,
        ingest_module._extract_from_xml,
        rules_module.load_rules,
        schemas_module.Event,
        holdout_module.rules_tree_hash,
    )


def verify_product(
    repo: Path,
    contract: dict[str, Any],
    rules_tree_hash,
    load_rules,
) -> dict[str, Any]:
    frozen = contract["frozen_product"]
    head = git(repo, "rev-parse", "HEAD")
    dirty = git(repo, "status", "--porcelain", "-uall")
    rule_hash, rule_files = rules_tree_hash(repo / "rules")
    rules = load_rules(repo / "rules")
    if head != frozen["repo_commit"]:
        raise RuntimeError(f"product commit mismatch: {head}")
    if dirty:
        raise RuntimeError("product worktree is dirty")
    if rule_hash != frozen["rules_tree_sha256"]:
        raise RuntimeError(f"rule tree mismatch: {rule_hash}")
    if len(rules) != int(frozen["rule_count"]):
        raise RuntimeError(f"rule count mismatch: {len(rules)}")
    if rule_files != int(frozen["rule_file_count"]):
        raise RuntimeError(f"rule file count mismatch: {rule_files}")
    return {
        "repo_commit": head,
        "rules_tree_sha256": rule_hash,
        "rule_count": len(rules),
        "rule_file_count": rule_files,
    }


def to_event(xml: str, parser, Event, sequence: int):
    row = parser(xml)
    if not isinstance(row, dict):
        raise ValueError("product XML parser returned non-mapping")
    keys = (
        "timestamp",
        "host",
        "source",
        "event_id",
        "level",
        "user",
        "command_line",
        "raw",
    )
    event = Event(**{key: row.get(key) for key in keys})
    raw = getattr(event, "raw", None)
    if isinstance(raw, dict):
        raw["_p2_36c_sequence"] = sequence
    return event


def iter_evtx_events(
    path: Path,
    parser,
    Event,
    stats: dict[str, int],
) -> Iterator[Any]:
    from Evtx.Evtx import Evtx

    with Evtx(str(path)) as log:
        for record in log.records():
            stats["raw_records"] += 1
            sequence = stats["raw_records"]
            try:
                event = to_event(record.xml(), parser, Event, sequence)
            except Exception:
                stats["parse_errors"] += 1
                continue
            stats["parsed_events"] += 1
            yield event


def finding_techniques(finding: Any) -> list[str]:
    values = list(getattr(finding, "mitre_techniques", None) or [])
    primary = getattr(finding, "mitre_technique", None)
    if primary:
        values.append(primary)
    return sorted(
        {
            str(value).strip().upper()
            for value in values
            if str(value or "").strip()
        }
    )


def score_evtx(
    path: Path,
    apply_rules,
    parser,
    Event,
    rules,
    *,
    allow_empty: bool = False,
) -> dict[str, Any]:
    stats = {
        "raw_records": 0,
        "parsed_events": 0,
        "parse_errors": 0,
    }
    findings = 0
    flagged_sequences: set[int] = set()
    findings_by_rule: Counter[str] = Counter()
    findings_by_technique: Counter[str] = Counter()
    findings_by_source: Counter[str] = Counter()

    event_iter = iter_evtx_events(path, parser, Event, stats)
    for finding in apply_rules(event_iter, rules):
        findings += 1
        findings_by_rule[str(getattr(finding, "rule_id", "") or "")] += 1
        for technique in finding_techniques(finding):
            findings_by_technique[technique] += 1
        source = str(getattr(finding.event, "source", "") or "UNKNOWN")
        findings_by_source[source] += 1
        raw = getattr(finding.event, "raw", None)
        if isinstance(raw, dict):
            sequence = raw.get("_p2_36c_sequence")
            if isinstance(sequence, int):
                flagged_sequences.add(sequence)

    empty = stats["parsed_events"] == 0
    if empty and not allow_empty:
        raise RuntimeError(f"EVTX parsed zero events: {path.name}")

    return {
        **stats,
        "empty": empty,
        "findings": findings,
        "flagged_events": len(flagged_sequences),
        "findings_by_rule": dict(sorted(findings_by_rule.items())),
        "findings_by_technique": dict(
            sorted(findings_by_technique.items())
        ),
        "findings_by_source": dict(sorted(findings_by_source.items())),
    }


def selected_attack_tree_rows(attack_repo: Path) -> list[dict[str, Any]]:
    raw = git_bytes(attack_repo, "ls-tree", "-r", "-z", "HEAD")
    rows: list[dict[str, Any]] = []
    for item in raw.split(b"\0"):
        if not item:
            continue
        meta, path_bytes = item.split(b"\t", 1)
        _, kind, blob = meta.decode("ascii").split(" ")
        path = path_bytes.decode("utf-8")
        if kind != "blob" or not path.casefold().endswith(".evtx"):
            continue
        rows.append({"path": path, "git_blob_sha1": blob})
    rows.sort(key=lambda row: row["path"].casefold())
    return rows


def verify_attack_repo(
    attack_repo: Path,
    contract: dict[str, Any],
) -> dict[str, Any]:
    section = contract["attack_revalidation"]
    source = section["source"]
    expected = section["datasets"]

    head = git(attack_repo, "rev-parse", "HEAD")
    dirty = git(attack_repo, "status", "--porcelain", "-uall")
    if head != source["pinned_commit"]:
        raise RuntimeError(f"attack repo commit mismatch: {head}")
    if dirty:
        raise RuntimeError("attack source repo is dirty")

    readme_blob = git(
        attack_repo,
        "rev-parse",
        f"HEAD:{source['readme_path']}",
    )
    readme_bytes = git_bytes(
        attack_repo,
        "show",
        f"HEAD:{source['readme_path']}",
    )
    if readme_blob != source["readme_git_blob_sha1"]:
        raise RuntimeError("attack README git blob mismatch")
    if len(readme_bytes) != int(source["readme_size_bytes"]):
        raise RuntimeError("attack README size mismatch")
    if bytes_sha256(readme_bytes) != source["readme_sha256"]:
        raise RuntimeError("attack README SHA-256 mismatch")

    selected = selected_attack_tree_rows(attack_repo)
    selected_pairs = [
        (row["path"], row["git_blob_sha1"]) for row in selected
    ]
    expected_pairs = [
        (row["source_path"], row["git_blob_sha1"]) for row in expected
    ]
    if selected_pairs != expected_pairs:
        raise RuntimeError("attack EVTX selector closure mismatch")

    verified: list[dict[str, Any]] = []
    for source_row in expected:
        path = attack_repo / source_row["source_path"]
        if not path.is_file():
            raise RuntimeError(
                f"missing attack fixture: {source_row['source_path']}"
            )
        row = {
            "dataset_id": source_row["dataset_id"],
            "source_path": source_row["source_path"],
            "git_blob_sha1": git(
                attack_repo,
                "rev-parse",
                f"HEAD:{source_row['source_path']}",
            ),
            "size_bytes": path.stat().st_size,
            "sha256": sha256(path),
        }
        for key in ("git_blob_sha1", "size_bytes", "sha256"):
            if row[key] != source_row[key]:
                raise RuntimeError(
                    f"attack {key} mismatch: {source_row['dataset_id']}"
                )
        verified.append(row)

    return {
        "repository": source["repository"],
        "repo_commit": head,
        "readme_git_blob_sha1": readme_blob,
        "readme_sha256": bytes_sha256(readme_bytes),
        "datasets": verified,
    }


def inventory_benign_evtx_members(
    archive: Path,
) -> list[dict[str, Any]]:
    with tarfile.open(archive, "r:gz") as tf:
        rows = [
            {"name": member.name, "size_bytes": member.size}
            for member in tf.getmembers()
            if member.isfile()
            and member.name.casefold().endswith(".evtx")
        ]
    rows.sort(key=lambda row: row["name"].casefold())
    return rows


def inventory_sha256(rows: list[dict[str, Any]]) -> str:
    payload = json.dumps(
        rows,
        ensure_ascii=False,
        separators=(",", ":"),
    ).encode("utf-8")
    return bytes_sha256(payload)


def verify_benign_archive(
    archive: Path,
    contract: dict[str, Any],
) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    section = contract["benign_revalidation"]
    expected = section["archive"]
    if not archive.is_file():
        raise RuntimeError(f"missing benign archive: {archive}")
    if archive.stat().st_size != int(expected["size_bytes"]):
        raise RuntimeError("benign archive size mismatch")
    actual_sha = sha256(archive)
    if actual_sha != expected["sha256"]:
        raise RuntimeError("benign archive SHA-256 mismatch")

    rows = inventory_benign_evtx_members(archive)
    inventory = section["inventory"]
    if len(rows) != int(inventory["evtx_member_count"]):
        raise RuntimeError("benign EVTX member count mismatch")
    total_bytes = sum(int(row["size_bytes"]) for row in rows)
    if total_bytes != int(inventory["total_evtx_bytes"]):
        raise RuntimeError("benign EVTX total bytes mismatch")
    actual_inventory_sha = inventory_sha256(rows)
    if actual_inventory_sha != inventory["inventory_sha256"]:
        raise RuntimeError("benign EVTX inventory SHA-256 mismatch")

    largest = max(rows, key=lambda row: int(row["size_bytes"]))
    gate = section["metadata_size_gate"]
    maximum_allowed = int(gate["maximum_selected_evtx_member_size_bytes"])
    if int(largest["size_bytes"]) > maximum_allowed:
        raise RuntimeError(
            "benign EVTX member exceeds preregistered size gate: "
            f"{largest['name']} {largest['size_bytes']} > {maximum_allowed}"
        )
    if largest["name"] != inventory["maximum_member_name"]:
        raise RuntimeError("benign maximum-member name mismatch")
    if int(largest["size_bytes"]) != int(inventory["maximum_member_size_bytes"]):
        raise RuntimeError("benign maximum-member size mismatch")

    return (
        {
            "asset_name": archive.name,
            "size_bytes": archive.stat().st_size,
            "sha256": actual_sha,
            "evtx_member_count": len(rows),
            "total_evtx_bytes": total_bytes,
            "inventory_sha256": actual_inventory_sha,
            "maximum_member_name": largest["name"],
            "maximum_member_size_bytes": int(largest["size_bytes"]),
            "maximum_allowed_member_size_bytes": maximum_allowed,
            "metadata_size_gate_passed": True,
        },
        rows,
    )


def verify_temp_space(contract: dict[str, Any]) -> dict[str, int]:
    minimum = int(contract["runner"]["temp_free_bytes_min"])
    free = shutil.disk_usage(tempfile.gettempdir()).free
    if free < minimum:
        raise RuntimeError(
            f"insufficient temp free space: {free} < {minimum}"
        )
    return {"temp_free_bytes": free, "minimum_required": minimum}


def write_member_to_temp(
    tf: tarfile.TarFile,
    member: tarfile.TarInfo,
    temp_root: Path,
    ordinal: int,
) -> Path:
    handle = tf.extractfile(member)
    if handle is None:
        raise RuntimeError(f"unable to read tar member: {member.name}")
    digest = hashlib.sha256(member.name.encode("utf-8")).hexdigest()[:16]
    path = temp_root / f"{ordinal:05d}_{digest}.evtx"
    with path.open("wb") as out:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            out.write(chunk)
    return path


def run_attack_revalidation(
    attack_repo: Path,
    contract: dict[str, Any],
    apply_rules,
    parser,
    Event,
    rules,
    payload: dict[str, Any],
    out: Path,
) -> None:
    rows: list[dict[str, Any]] = payload["attack_revalidation"]["datasets"]
    hits = 0
    misses = 0
    errors = 0

    for source in contract["attack_revalidation"]["datasets"]:
        row: dict[str, Any] = {
            "dataset_id": source["dataset_id"],
            "family_label": source["family_label"],
            "source_path": source["source_path"],
            "stage": "started",
        }
        rows.append(row)
        atomic_write(out, payload)
        try:
            metrics = score_evtx(
                attack_repo / source["source_path"],
                apply_rules,
                parser,
                Event,
                rules,
            )
            status = "HIT" if metrics["findings"] else "MISS"
            if status == "HIT":
                hits += 1
            else:
                misses += 1
            row.update(
                stage="completed",
                fixture_status=status,
                **metrics,
            )
        except BaseException as exc:
            errors += 1
            row.update(
                stage="failed",
                fixture_status="ERROR",
                error=f"{type(exc).__name__}: {exc}",
            )
        atomic_write(out, payload)

    count = len(contract["attack_revalidation"]["datasets"])
    payload["attack_revalidation"]["summary"] = {
        "fixture_count": count,
        "hits": hits,
        "misses": misses,
        "errors": errors,
        "fixture_hit_fraction": hits / count if count else None,
    }
    atomic_write(out, payload)


def run_benign_revalidation(
    archive: Path,
    inventory: list[dict[str, Any]],
    apply_rules,
    parser,
    Event,
    rules,
    payload: dict[str, Any],
    out: Path,
) -> None:
    members_out: list[dict[str, Any]] = payload["benign_revalidation"]["members"]
    total_raw = 0
    total_parsed = 0
    total_parse_errors = 0
    total_findings = 0
    total_flagged = 0
    empty_members = 0
    findings_by_rule: Counter[str] = Counter()
    findings_by_technique: Counter[str] = Counter()
    findings_by_source: Counter[str] = Counter()

    with tempfile.TemporaryDirectory(prefix="p2_36c_benign_") as temp_text:
        temp_root = Path(temp_text)
        with tarfile.open(archive, "r:gz") as tf:
            by_name = {
                member.name: member
                for member in tf.getmembers()
                if member.isfile()
                and member.name.casefold().endswith(".evtx")
            }
            for ordinal, item in enumerate(inventory):
                member = by_name.get(item["name"])
                if member is None:
                    raise RuntimeError(
                        f"missing benign EVTX member: {item['name']}"
                    )
                row: dict[str, Any] = {
                    "name": item["name"],
                    "size_bytes": item["size_bytes"],
                    "stage": "started",
                }
                members_out.append(row)
                atomic_write(out, payload)
                temp_path = write_member_to_temp(
                    tf,
                    member,
                    temp_root,
                    ordinal,
                )
                try:
                    metrics = score_evtx(
                        temp_path,
                        apply_rules,
                        parser,
                        Event,
                        rules,
                        allow_empty=True,
                    )
                finally:
                    temp_path.unlink(missing_ok=True)

                member_status = "EMPTY" if metrics["empty"] else "COMPLETED"
                if metrics["empty"]:
                    empty_members += 1
                row.update(
                    stage="completed",
                    member_status=member_status,
                    **metrics,
                )
                total_raw += metrics["raw_records"]
                total_parsed += metrics["parsed_events"]
                total_parse_errors += metrics["parse_errors"]
                total_findings += metrics["findings"]
                total_flagged += metrics["flagged_events"]
                findings_by_rule.update(metrics["findings_by_rule"])
                findings_by_technique.update(
                    metrics["findings_by_technique"]
                )
                findings_by_source.update(metrics["findings_by_source"])
                atomic_write(out, payload)

    if total_parsed == 0:
        raise RuntimeError("benign archive parsed zero events")

    fraction = total_flagged / total_parsed
    payload["benign_revalidation"]["summary"] = {
        "evtx_member_count": len(inventory),
        "empty_member_count": empty_members,
        "nonempty_member_count": len(inventory) - empty_members,
        "raw_records": total_raw,
        "parsed_events": total_parsed,
        "parse_errors": total_parse_errors,
        "findings": total_findings,
        "flagged_events": total_flagged,
        "observed_source_intent_benign_flagged_event_fraction": fraction,
        "observed_source_intent_benign_flagged_event_percent": fraction * 100,
        "findings_by_rule": dict(sorted(findings_by_rule.items())),
        "findings_by_technique": dict(
            sorted(findings_by_technique.items())
        ),
        "findings_by_source": dict(sorted(findings_by_source.items())),
    }
    atomic_write(out, payload)


def run(args: argparse.Namespace) -> int:
    product_repo = Path(args.product_repo).resolve()
    contract_path = Path(args.contract).resolve()
    attack_repo = Path(args.attack_repo).resolve()
    benign_archive = Path(args.benign_archive).resolve()
    out = Path(args.out).resolve()
    contract = yaml.safe_load(
        contract_path.read_text(encoding="utf-8")
    )

    if contract["analysis_id"] != ANALYSIS_ID:
        raise RuntimeError("analysis id mismatch")

    lock = global_lock_path()
    acquire_global_lock(lock)

    payload: dict[str, Any] = {
        "schema": SCHEMA,
        "analysis_id": ANALYSIS_ID,
        "status": "started",
        "contract_sha256": sha256(contract_path),
        "runner_sha256": text_sha256(Path(__file__).resolve()),
        "global_lock_path": str(lock),
        "attack_revalidation": {"datasets": []},
        "benign_revalidation": {"members": []},
    }
    atomic_write(out, payload)

    try:
        if payload["runner_sha256"] != contract["runner"]["sha256"]:
            raise RuntimeError("runner SHA-256 mismatch")

        (
            apply_rules,
            parser,
            load_rules,
            Event,
            rules_tree_hash,
        ) = load_product(product_repo)
        payload["frozen_product"] = verify_product(
            product_repo,
            contract,
            rules_tree_hash,
            load_rules,
        )
        rules = load_rules(product_repo / "rules")

        attack_verification = verify_attack_repo(attack_repo, contract)
        benign_verification, inventory = verify_benign_archive(
            benign_archive,
            contract,
        )
        payload["preflight"] = {
            "temp_space": verify_temp_space(contract),
            "attack": attack_verification,
            "benign": benign_verification,
        }
        payload["status"] = "sources_verified"
        atomic_write(out, payload)

        run_attack_revalidation(
            attack_repo,
            contract,
            apply_rules,
            parser,
            Event,
            rules,
            payload,
            out,
        )
        run_benign_revalidation(
            benign_archive,
            inventory,
            apply_rules,
            parser,
            Event,
            rules,
            payload,
            out,
        )

        payload["claim_boundary"] = contract["claim_boundary"]
        payload["status"] = "completed"
        atomic_write(out, payload)
        print(
            json.dumps(
                {
                    "attack": payload["attack_revalidation"]["summary"],
                    "benign": payload["benign_revalidation"]["summary"],
                },
                ensure_ascii=False,
                sort_keys=True,
            )
        )
        return 0
    except BaseException as exc:
        payload.update(
            status="failed",
            error=f"{type(exc).__name__}: {exc}",
        )
        atomic_write(out, payload)
        return 2


def main() -> int:
    parser = argparse.ArgumentParser(
        description=(
            "Run P2-36C current-73-rule fresh source revalidation."
        )
    )
    parser.add_argument("--product-repo", required=True)
    parser.add_argument("--contract", required=True)
    parser.add_argument("--attack-repo", required=True)
    parser.add_argument("--benign-archive", required=True)
    parser.add_argument("--out", required=True)
    return run(parser.parse_args())


if __name__ == "__main__":
    raise SystemExit(main())
