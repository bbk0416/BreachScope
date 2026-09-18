#!/usr/bin/env python3
from __future__ import annotations

import argparse
import ctypes
import hashlib
import json
import os
import platform
import subprocess
import sys
import time
from ctypes import wintypes
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

FROZEN_PRODUCT_COMMIT = "6b63cdead6e524d1ee60e9193b5353a2151767cd"
FROZEN_RULES_SHA256 = "9f823a189530528a47b11c5519b02dc9b97473b8c0f6a8e0c13e1ed8d04b5e92"
SIZES = (10_000, 100_000, 1_000_000)
MAX_WORKERS = 8
SUSPICIOUS_INTERVAL = 1000
SCHEMA = "breachscope.p2_19_peak_memory_benchmark.v1"
BENCHMARK_ID = "p2-19-windows-full-pipeline-peak-memory-10k-100k-1m-v1"
EXPECTED_SOURCE_SHA256 = "e4e85502d926376c9d75745a7f1e81fec6eba38faaa7c5201f03fd2b6e18cc9f"
EXPECTED_SOURCE_SIZE = 454835896


def sha256(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def git(repo: Path, *args: str) -> str:
    return subprocess.check_output(["git", "-C", str(repo), *args], text=True).strip()


def rules_tree_hash(rules_dir: Path) -> tuple[str, int]:
    files = sorted(p for p in rules_dir.rglob("*") if p.is_file() and p.suffix.lower() in {".yml", ".yaml"})
    h = hashlib.sha256()
    for path in files:
        rel = path.relative_to(rules_dir).as_posix()
        h.update(rel.encode("utf-8")); h.update(b"\0")
        raw = path.read_bytes().replace(b"\r\n", b"\n").replace(b"\r", b"\n")
        h.update(hashlib.sha256(raw).hexdigest().encode("ascii")); h.update(b"\0")
    return h.hexdigest(), len(files)


def verify_product(repo: Path) -> dict[str, Any]:
    head = git(repo, "rev-parse", "HEAD")
    dirty = git(repo, "status", "--porcelain", "-uall")
    rule_hash, rule_files = rules_tree_hash(repo / "rules")
    if head != FROZEN_PRODUCT_COMMIT:
        raise RuntimeError(f"product commit mismatch: {head}")
    if dirty:
        raise RuntimeError("product worktree must be clean")
    if rule_hash != FROZEN_RULES_SHA256:
        raise RuntimeError(f"rules hash mismatch: {rule_hash}")
    return {"repo_commit": head, "rules_tree_sha256": rule_hash, "rule_file_count": rule_files}

def generate_source(path: Path) -> dict[str, Any]:
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.exists():
        path.unlink()
    base = datetime(2026, 1, 1, tzinfo=timezone.utc)
    with path.open("w", encoding="utf-8", newline="\n") as f:
        for i in range(1, SIZES[-1] + 1):
            suspicious = (i % SUSPICIOUS_INTERVAL) == 0
            if suspicious:
                image = r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe"
                cmd = 'powershell.exe -NoProfile -ExecutionPolicy Bypass -Command "Write-Output BENCHMARK"'
            else:
                image = r"C:\Windows\System32\notepad.exe"
                cmd = rf'notepad.exe C:\Bench\doc-{i % 1000:04d}.txt'
            ts = (base + timedelta(seconds=i - 1)).isoformat().replace("+00:00", "Z")
            row = {
                "timestamp": ts,
                "computer_name": f"BENCH-{i % 16:02d}",
                "source_name": "Microsoft-Windows-Sysmon",
                "event_id": "1",
                "user": f"LAB\\bench{i % 32:02d}",
                "command_line": cmd,
                "event_data": {
                    "Image": image,
                    "CommandLine": cmd,
                    "ParentImage": r"C:\Windows\explorer.exe",
                    "ProcessId": str(1000 + (i % 50000)),
                    "ParentProcessId": str(500 + (i % 10000)),
                },
                "benchmark": {"sequence": i, "synthetic_suspicious": suspicious},
            }
            f.write(json.dumps(row, separators=(",", ":"), ensure_ascii=False) + "\n")
    return {
        "path": str(path),
        "events": SIZES[-1],
        "size_bytes": path.stat().st_size,
        "sha256": sha256(path),
        "synthetic_suspicious_events": SIZES[-1] // SUSPICIOUS_INTERVAL,
    }


def peak_working_set_bytes() -> int | None:
    if os.name == "nt":
        class PMC(ctypes.Structure):
            _fields_ = [
                ("cb", wintypes.DWORD), ("PageFaultCount", wintypes.DWORD),
                ("PeakWorkingSetSize", ctypes.c_size_t), ("WorkingSetSize", ctypes.c_size_t),
                ("QuotaPeakPagedPoolUsage", ctypes.c_size_t), ("QuotaPagedPoolUsage", ctypes.c_size_t),
                ("QuotaPeakNonPagedPoolUsage", ctypes.c_size_t), ("QuotaNonPagedPoolUsage", ctypes.c_size_t),
                ("PagefileUsage", ctypes.c_size_t), ("PeakPagefileUsage", ctypes.c_size_t),
            ]
        kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
        psapi = ctypes.WinDLL("psapi", use_last_error=True)
        kernel32.GetCurrentProcess.restype = wintypes.HANDLE
        psapi.GetProcessMemoryInfo.argtypes = [wintypes.HANDLE, ctypes.POINTER(PMC), wintypes.DWORD]
        psapi.GetProcessMemoryInfo.restype = wintypes.BOOL
        counters = PMC(); counters.cb = ctypes.sizeof(PMC)
        ok = psapi.GetProcessMemoryInfo(kernel32.GetCurrentProcess(), ctypes.byref(counters), counters.cb)
        if not ok:
            raise OSError(ctypes.get_last_error(), "GetProcessMemoryInfo failed")
        return int(counters.PeakWorkingSetSize)
    try:
        import resource
        value = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
        return int(value * 1024 if sys.platform != "darwin" else value)
    except Exception:
        return None


def acquire_permanent_lock(path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    try:
        fd = os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY)
    except FileExistsError as exc:
        raise RuntimeError(f"benchmark lock already exists: {path}") from exc
    with os.fdopen(fd, "w", encoding="utf-8") as handle:
        json.dump({"benchmark_id": BENCHMARK_ID, "pid": os.getpid(), "created_unix": time.time()}, handle)


def timed(fn):
    start = time.perf_counter()
    value = fn()
    return value, time.perf_counter() - start

def worker(args: argparse.Namespace) -> int:
    repo = Path(args.product_repo).resolve()
    source = Path(args.source).resolve()
    out_dir = Path(args.out_dir).resolve()
    scale = int(args.scale)
    if scale not in SIZES:
        raise RuntimeError(f"unsupported scale: {scale}")
    frozen = verify_product(repo)
    os.environ["BS_HAYABUSA_ENABLED"] = "0"
    os.environ["BS_REDACT"] = "1"
    sys.path.insert(0, str(repo))
    from breachscope.pipeline import Pipeline
    from breachscope.utils import get_event_identity_key

    pipe = Pipeline(
        rules_dir=repo / "rules",
        max_events=scale,
        enable_parallel=True,
        max_workers=MAX_WORKERS,
        redact=True,
    )
    out_dir.mkdir(parents=True, exist_ok=True)
    prefix = out_dir / f"benchmark_{scale}"
    timings: dict[str, float] = {}
    total_start = time.perf_counter()
    _, timings["load_rules"] = timed(pipe.load_rules)
    _, timings["collect"] = timed(lambda: pipe.collect_events(source))
    _, timings["detection"] = timed(pipe.analyze)
    _, timings["correlation"] = timed(pipe.correlate)
    _, timings["scenario"] = timed(pipe.infer_scenarios)
    _, timings["report_build"] = timed(pipe.build_report)
    _, timings["report_export"] = timed(lambda: pipe.export_report(prefix, False, False, False))
    total_seconds = time.perf_counter() - total_start
    peak = peak_working_set_bytes()
    if peak is None or peak <= 0:
        raise RuntimeError("peak working set was not captured")
    result = {
        "benchmark_id": BENCHMARK_ID,
        "schema": SCHEMA,
        "status": "completed",
        "scale_events": scale,
        "frozen_product": frozen,
        "environment": {
            "python": sys.version,
            "platform": platform.platform(),
            "machine": platform.machine(),
            "logical_cpu_count": os.cpu_count(),
            "parallel": True,
            "max_workers": MAX_WORKERS,
            "hayabusa_enabled": False,
        },
        "input": {"sha256": sha256(source), "size_bytes": source.stat().st_size},
        "counts": {
            "events": len(pipe.events or []),
            "findings": len(pipe.findings or []),
            "flagged_events": len({get_event_identity_key(f.event) for f in (pipe.findings or [])}),
            "chains": len(pipe.chains or []),
            "scenarios": len(pipe.scenarios or []),
        },
        "timings_seconds": {k: round(v, 6) for k, v in timings.items()},
        "total_seconds": round(total_seconds, 6),
        "throughput_events_per_second": round(scale / total_seconds, 3),
        "peak_working_set_bytes": peak,
        "peak_working_set_mb": round(peak / (1024 * 1024), 3) if peak else None,
        "artifacts": {
            "html_bytes": prefix.with_suffix(".html").stat().st_size,
            "package_zip_bytes": prefix.with_suffix(".zip").stat().st_size,
        },
    }
    result_path = out_dir / f"result_{scale}.json"
    result_path.write_text(json.dumps(result, indent=2, ensure_ascii=False) + "\n", encoding="utf-8", newline="\n")
    print(json.dumps(result, ensure_ascii=False), flush=True)
    return 0

def orchestrate(args: argparse.Namespace) -> int:
    repo = Path(args.product_repo).resolve()
    out_dir = Path(args.out_dir).resolve()
    out_dir.mkdir(parents=True, exist_ok=True)
    acquire_permanent_lock(out_dir / "P2_19_ONE_PASS.lock")
    source = out_dir / "p2_19_1m.jsonl"
    frozen = verify_product(repo)
    source_info = generate_source(source)
    if source_info["sha256"] != EXPECTED_SOURCE_SHA256 or source_info["size_bytes"] != EXPECTED_SOURCE_SIZE:
        raise RuntimeError("deterministic source does not match the preregistered P2-18 workload")
    results = []
    for scale in SIZES:
        scale_dir = out_dir / str(scale)
        cmd = [
            sys.executable, str(Path(__file__).resolve()),
            "--worker",
            "--product-repo", str(repo),
            "--source", str(source),
            "--out-dir", str(scale_dir),
            "--scale", str(scale),
        ]
        started = time.perf_counter()
        proc = subprocess.run(cmd, text=True, capture_output=True, check=False)
        wall = time.perf_counter() - started
        if proc.returncode != 0:
            failure = {
                "schema": SCHEMA,
                "status": "worker_failed",
                "scale_events": scale,
                "returncode": proc.returncode,
                "stdout": proc.stdout[-4000:],
                "stderr": proc.stderr[-4000:],
                "orchestrator_wall_seconds": wall,
            }
            (out_dir / f"failure_{scale}.json").write_text(
                json.dumps(failure, indent=2, ensure_ascii=False) + "\n",
                encoding="utf-8", newline="\n"
            )
            results.append(failure)
            break
        row = json.loads(proc.stdout.strip().splitlines()[-1])
        row["orchestrator_wall_seconds"] = round(wall, 6)
        results.append(row)
    summary = {
        "schema": "breachscope.p2_19_peak_memory_benchmark_summary.v1",
        "benchmark_id": BENCHMARK_ID,
        "status": "completed" if len(results) == len(SIZES) and all(r.get("status") == "completed" for r in results) else "failed",
        "frozen_product": frozen,
        "source": source_info,
        "measurement_order": list(SIZES),
        "results": results,
        "claim_boundary": {
            "single_machine_observation": True,
            "peak_memory_metric": "PeakWorkingSetSize",
            "statistical_benchmark": False,
            "production_capacity": "NOT_CLAIMED",
            "cross_tool_speed_comparison": "NOT_CLAIMED",
            "enterprise_scale_readiness": "NOT_CLAIMED",
        },
    }
    out_dir.mkdir(parents=True, exist_ok=True)
    (out_dir / "summary.json").write_text(
        json.dumps(summary, indent=2, ensure_ascii=False) + "\n",
        encoding="utf-8", newline="\n"
    )
    print(json.dumps(summary, indent=2, ensure_ascii=False))
    return 0 if summary["status"] == "completed" else 2


def main() -> int:
    if sys.version_info[:2] != (3, 11):
        raise RuntimeError(f"P2-19 requires Python 3.11, got {sys.version.split()[0]}")
    parser = argparse.ArgumentParser(description="Run the preregistered P2-19 BreachScope peak-memory benchmark.")
    parser.add_argument("--product-repo", required=True)
    parser.add_argument("--out-dir", required=True)
    parser.add_argument("--worker", action="store_true")
    parser.add_argument("--source")
    parser.add_argument("--scale", type=int)
    args = parser.parse_args()
    if args.worker:
        if not args.source or args.scale is None:
            parser.error("--worker requires --source and --scale")
        return worker(args)
    return orchestrate(args)


if __name__ == "__main__":
    raise SystemExit(main())
