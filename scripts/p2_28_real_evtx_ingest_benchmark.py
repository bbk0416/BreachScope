#!/usr/bin/env python3
from __future__ import annotations

import argparse
import ctypes
import hashlib
import json
import os
import platform
import shutil
import subprocess
import sys
import tarfile
import time
from ctypes import wintypes
from pathlib import Path
from typing import Any

import yaml

SCHEMA = "breachscope.p2_28_real_evtx_ingest_benchmark.v1"
BENCHMARK_ID = "p2-28-windows-real-evtx-ingest-nextron-win10-v1"


def sha256(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def text_sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes().replace(b"\r\n", b"\n")).hexdigest()


def git(repo: Path, *args: str) -> str:
    return subprocess.check_output(["git", "-C", str(repo), *args], text=True).strip()


def rules_tree_hash(rules_dir: Path) -> tuple[str, int]:
    files = sorted(
        path
        for path in rules_dir.rglob("*")
        if path.is_file() and path.suffix.lower() in {".yml", ".yaml"}
    )
    h = hashlib.sha256()
    for path in files:
        rel = path.relative_to(rules_dir).as_posix()
        h.update(rel.encode("utf-8"))
        h.update(b"\0")
        raw = path.read_bytes().replace(b"\r\n", b"\n").replace(b"\r", b"\n")
        h.update(hashlib.sha256(raw).hexdigest().encode("ascii"))
        h.update(b"\0")
    return h.hexdigest(), len(files)


def peak_working_set_bytes() -> int | None:
    if os.name == "nt":
        class PMC(ctypes.Structure):
            _fields_ = [
                ("cb", wintypes.DWORD),
                ("PageFaultCount", wintypes.DWORD),
                ("PeakWorkingSetSize", ctypes.c_size_t),
                ("WorkingSetSize", ctypes.c_size_t),
                ("QuotaPeakPagedPoolUsage", ctypes.c_size_t),
                ("QuotaPagedPoolUsage", ctypes.c_size_t),
                ("QuotaPeakNonPagedPoolUsage", ctypes.c_size_t),
                ("QuotaNonPagedPoolUsage", ctypes.c_size_t),
                ("PagefileUsage", ctypes.c_size_t),
                ("PeakPagefileUsage", ctypes.c_size_t),
            ]

        kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
        psapi = ctypes.WinDLL("psapi", use_last_error=True)
        kernel32.GetCurrentProcess.restype = wintypes.HANDLE
        psapi.GetProcessMemoryInfo.argtypes = [
            wintypes.HANDLE,
            ctypes.POINTER(PMC),
            wintypes.DWORD,
        ]
        psapi.GetProcessMemoryInfo.restype = wintypes.BOOL
        counters = PMC()
        counters.cb = ctypes.sizeof(PMC)
        ok = psapi.GetProcessMemoryInfo(
            kernel32.GetCurrentProcess(),
            ctypes.byref(counters),
            counters.cb,
        )
        if not ok:
            raise OSError(ctypes.get_last_error(), "GetProcessMemoryInfo failed")
        return int(counters.PeakWorkingSetSize)

    try:
        import resource

        value = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
        return int(value * 1024 if sys.platform != "darwin" else value)
    except Exception:
        return None


def total_physical_memory_bytes() -> int | None:
    if os.name == "nt":
        class MEMORYSTATUSEX(ctypes.Structure):
            _fields_ = [
                ("dwLength", wintypes.DWORD),
                ("dwMemoryLoad", wintypes.DWORD),
                ("ullTotalPhys", ctypes.c_ulonglong),
                ("ullAvailPhys", ctypes.c_ulonglong),
                ("ullTotalPageFile", ctypes.c_ulonglong),
                ("ullAvailPageFile", ctypes.c_ulonglong),
                ("ullTotalVirtual", ctypes.c_ulonglong),
                ("ullAvailVirtual", ctypes.c_ulonglong),
                ("ullAvailExtendedVirtual", ctypes.c_ulonglong),
            ]

        status = MEMORYSTATUSEX()
        status.dwLength = ctypes.sizeof(MEMORYSTATUSEX)
        kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
        if not kernel32.GlobalMemoryStatusEx(ctypes.byref(status)):
            return None
        return int(status.ullTotalPhys)
    return None


def acquire_permanent_lock(path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    try:
        fd = os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY)
    except FileExistsError as exc:
        raise RuntimeError(f"benchmark lock already exists: {path}") from exc
    with os.fdopen(fd, "w", encoding="utf-8") as handle:
        json.dump(
            {
                "benchmark_id": BENCHMARK_ID,
                "pid": os.getpid(),
                "created_unix": time.time(),
            },
            handle,
        )


def load_contract(path: Path) -> dict[str, Any]:
    row = yaml.safe_load(path.read_text(encoding="utf-8"))
    if row.get("benchmark_id") != BENCHMARK_ID:
        raise RuntimeError("benchmark id mismatch")
    return row


def verify_product(repo: Path, contract: dict[str, Any]) -> dict[str, Any]:
    expected = contract["product"]
    head = git(repo, "rev-parse", "HEAD")
    dirty = git(repo, "status", "--porcelain", "-uall")
    rule_hash, rule_files = rules_tree_hash(repo / "rules")
    if head != expected["repo_commit"]:
        raise RuntimeError(f"product commit mismatch: {head}")
    if dirty:
        raise RuntimeError("product worktree must be clean")
    if rule_hash != expected["rules_tree_sha256"]:
        raise RuntimeError(f"rules hash mismatch: {rule_hash}")
    if rule_files != expected["rule_file_count"]:
        raise RuntimeError(f"rule file count mismatch: {rule_files}")
    return {
        "repo_commit": head,
        "rules_tree_sha256": rule_hash,
        "rule_file_count": rule_files,
        "rule_count": expected["rule_count"],
    }


def safe_extract_evtx(archive: Path, out_dir: Path) -> dict[str, Any]:
    out_dir.mkdir(parents=True, exist_ok=False)
    root = out_dir.resolve()
    extracted_files = 0
    extracted_bytes = 0
    relative_paths: list[str] = []

    with tarfile.open(archive, "r:gz") as tf:
        for member in tf.getmembers():
            if not member.isfile() or not member.name.lower().endswith(".evtx"):
                continue
            rel = Path(member.name)
            if rel.is_absolute() or ".." in rel.parts:
                raise RuntimeError(f"unsafe archive member: {member.name}")
            target = (out_dir / rel).resolve()
            if root not in target.parents:
                raise RuntimeError(f"archive member escapes output directory: {member.name}")
            source = tf.extractfile(member)
            if source is None:
                raise RuntimeError(f"cannot read archive member: {member.name}")
            target.parent.mkdir(parents=True, exist_ok=True)
            with source, target.open("wb") as handle:
                shutil.copyfileobj(source, handle, length=1024 * 1024)
            extracted_files += 1
            extracted_bytes += target.stat().st_size
            relative_paths.append(target.relative_to(out_dir).as_posix())

    if not extracted_files:
        raise RuntimeError("archive contains no EVTX files")
    return {
        "evtx_files": extracted_files,
        "evtx_bytes": extracted_bytes,
        "relative_paths": sorted(relative_paths),
    }


def directory_file_stats(path: Path, suffix: str) -> dict[str, int]:
    files = [p for p in path.rglob(f"*{suffix}") if p.is_file()]
    return {
        "files": len(files),
        "bytes": sum(p.stat().st_size for p in files),
    }


def write_json(path: Path, payload: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temp = path.with_suffix(path.suffix + ".tmp")
    temp.write_text(
        json.dumps(payload, indent=2, ensure_ascii=False) + "\n",
        encoding="utf-8",
        newline="\n",
    )
    os.replace(temp, path)


def preflight(args: argparse.Namespace) -> int:
    contract_path = Path(args.contract).resolve()
    product_repo = Path(args.product_repo).resolve()
    contract = load_contract(contract_path)

    if sys.version_info[:2] != (3, 11):
        raise RuntimeError(f"P2-28 requires Python 3.11, got {sys.version.split()[0]}")
    if platform.system() != "Windows":
        raise RuntimeError(f"P2-28 requires Windows, got {platform.system()}")

    actual_runner = text_sha256(Path(__file__).resolve())
    if actual_runner != contract["runner"]["sha256"]:
        raise RuntimeError(f"runner SHA mismatch: {actual_runner}")

    frozen = verify_product(product_repo, contract)
    print(
        json.dumps(
            {
                "status": "PRECHECK_PASS",
                "python": sys.version.split()[0],
                "platform": platform.platform(),
                "runner_sha256": actual_runner,
                "frozen_product": frozen,
            },
            sort_keys=True,
        )
    )
    return 0


def run(args: argparse.Namespace) -> int:
    contract_path = Path(args.contract).resolve()
    product_repo = Path(args.product_repo).resolve()
    archive = Path(args.archive).resolve()
    out_dir = Path(args.out_dir).resolve()
    contract = load_contract(contract_path)

    if sys.version_info[:2] != (3, 11):
        raise RuntimeError(f"P2-28 requires Python 3.11, got {sys.version.split()[0]}")
    if platform.system() != "Windows":
        raise RuntimeError(f"P2-28 requires Windows, got {platform.system()}")

    out_dir.mkdir(parents=True, exist_ok=False)
    lock_path = out_dir / "P2_28_ONE_PASS.lock"
    acquire_permanent_lock(lock_path)

    result_path = out_dir / "result.json"
    payload: dict[str, Any] = {
        "schema": SCHEMA,
        "benchmark_id": BENCHMARK_ID,
        "status": "started",
        "contract_sha256": sha256(contract_path),
        "runner_sha256": text_sha256(Path(__file__).resolve()),
        "python": sys.version,
        "environment": {
            "platform": platform.platform(),
            "machine": platform.machine(),
            "processor": platform.processor(),
            "logical_cpu_count": os.cpu_count(),
            "total_physical_memory_bytes": total_physical_memory_bytes(),
        },
        "stages_seconds": {},
    }
    write_json(result_path, payload)

    try:
        if payload["runner_sha256"] != contract["runner"]["sha256"]:
            raise RuntimeError("runner SHA mismatch")

        payload["frozen_product"] = verify_product(product_repo, contract)

        source = contract["source"]
        actual_archive = {
            "path": str(archive),
            "size_bytes": archive.stat().st_size,
            "sha256": sha256(archive),
        }
        payload["source_archive"] = actual_archive
        if actual_archive["size_bytes"] != source["asset_size_bytes"]:
            raise RuntimeError("source archive size mismatch")
        if actual_archive["sha256"] != source["asset_sha256"]:
            raise RuntimeError("source archive SHA mismatch")

        extract_dir = out_dir / "extracted"
        started = time.perf_counter()
        extracted = safe_extract_evtx(archive, extract_dir)
        payload["stages_seconds"]["extract_evtx"] = round(
            time.perf_counter() - started, 6
        )
        payload["extracted"] = extracted
        if extracted["evtx_files"] != source["expected_source_evtx_files_total"]:
            payload["status"] = "failed_accounting_mismatch"
            payload["accounting_mismatch"] = {
                "field": "source_evtx_files_total",
                "expected": source["expected_source_evtx_files_total"],
                "observed": extracted["evtx_files"],
            }
            write_json(result_path, payload)
            return 3

        sys.path.insert(0, str(product_repo))
        from breachscope.ingest import convert_evtx_dir
        from breachscope.pipeline import Pipeline

        started = time.perf_counter()
        converted_dir = convert_evtx_dir(extract_dir)
        payload["stages_seconds"]["convert_evtx_dir"] = round(
            time.perf_counter() - started, 6
        )
        if converted_dir is None:
            raise RuntimeError("convert_evtx_dir returned no output")
        converted_dir = Path(converted_dir)
        payload["converted_jsonl"] = directory_file_stats(converted_dir, ".jsonl")
        write_json(result_path, payload)

        pipe = Pipeline(
            rules_dir=product_repo / "rules",
            max_events=None,
            enable_parallel=False,
            redact=True,
        )
        started = time.perf_counter()
        events = pipe.collect_events(converted_dir)
        payload["stages_seconds"]["collect_and_normalize"] = round(
            time.perf_counter() - started, 6
        )
        payload["counts"] = {
            "normalized_events": len(events),
            "expected_reference_events": source["expected_reference_events"],
        }
        payload["stages_seconds"]["total_real_evtx_ingest"] = round(
            payload["stages_seconds"]["extract_evtx"]
            + payload["stages_seconds"]["convert_evtx_dir"]
            + payload["stages_seconds"]["collect_and_normalize"],
            6,
        )

        peak = peak_working_set_bytes()
        if peak is None or peak <= 0:
            raise RuntimeError("peak working set was not captured")
        payload["peak_working_set_bytes"] = peak
        payload["peak_working_set_mb"] = round(peak / (1024 * 1024), 3)

        observed_events = len(events)
        expected_events = source["expected_reference_events"]
        if observed_events != expected_events:
            payload["status"] = "failed_accounting_mismatch"
            payload["accounting_mismatch"] = {
                "field": "normalized_events",
                "expected": expected_events,
                "observed": observed_events,
            }
            payload["throughput_events_per_second"] = "NOT_CLAIMED"
            payload["claim_boundary"] = {
                "real_evtx_ingest_performance": "NOT_CLAIMED_DUE_TO_ACCOUNTING_MISMATCH",
                "production_capacity": "NOT_CLAIMED",
                "enterprise_scale_readiness": "NOT_CLAIMED",
                "statistical_benchmark": False,
                "detection_executed": False,
            }
            write_json(result_path, payload)
            return 3

        total_ingest = payload["stages_seconds"]["total_real_evtx_ingest"]
        payload["throughput_events_per_second"] = round(
            observed_events / total_ingest, 3
        )
        payload["status"] = "completed"
        payload["claim_boundary"] = {
            "real_evtx_ingest_performance": "MEASURED_ON_PINNED_P2_09D_CORPUS",
            "single_machine_observation": True,
            "production_capacity": "NOT_CLAIMED",
            "enterprise_scale_readiness": "NOT_CLAIMED",
            "statistical_benchmark": False,
            "cross_tool_speed_comparison": "NOT_CLAIMED",
            "detection_executed": False,
            "detection_accuracy_claimed": False,
        }
        write_json(result_path, payload)
        print(json.dumps(payload, ensure_ascii=False))
        return 0
    except BaseException as exc:
        payload["status"] = "failed"
        payload["error"] = f"{type(exc).__name__}: {exc}"
        payload.setdefault(
            "claim_boundary",
            {
                "real_evtx_ingest_performance": "NOT_MEASURED",
                "production_capacity": "NOT_CLAIMED",
                "enterprise_scale_readiness": "NOT_CLAIMED",
                "detection_executed": False,
            },
        )
        write_json(result_path, payload)
        return 2


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Run the preregistered P2-28 real EVTX ingest benchmark."
    )
    parser.add_argument("--product-repo", required=True)
    parser.add_argument("--contract", required=True)
    parser.add_argument("--preflight", action="store_true")
    parser.add_argument("--archive")
    parser.add_argument("--out-dir")
    args = parser.parse_args()

    if args.preflight:
        return preflight(args)
    if not args.archive or not args.out_dir:
        parser.error("--archive and --out-dir are required for canonical execution")
    return run(args)


if __name__ == "__main__":
    raise SystemExit(main())
