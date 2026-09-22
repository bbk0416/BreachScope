from __future__ import annotations

import argparse
import ctypes
import hashlib
import importlib.metadata
import inspect
import json
import os
import platform
import statistics
import subprocess
import sys
import time
from pathlib import Path
from typing import Any

import psutil
import yaml


SCHEMA = "breachscope.p2_33_evtx_value_node_memo_benchmark.v1"
BENCHMARK_ID = "p2-33-windows-evtx-value-node-memo-v1"


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def write_json(path: Path, payload: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temp = path.with_suffix(path.suffix + ".tmp")
    temp.write_text(
        json.dumps(payload, indent=2, ensure_ascii=False) + "\n",
        encoding="utf-8",
        newline="\n",
    )
    os.replace(temp, path)


def canonical_digest_update(h: "hashlib._Hash", data: bytes) -> None:
    h.update(len(data).to_bytes(8, "big"))
    h.update(data)


def current_environment() -> dict[str, Any]:
    total_memory = 0
    if sys.platform == "win32":
        class MEMORYSTATUSEX(ctypes.Structure):
            _fields_ = [
                ("dwLength", ctypes.c_ulong),
                ("dwMemoryLoad", ctypes.c_ulong),
                ("ullTotalPhys", ctypes.c_ulonglong),
                ("ullAvailPhys", ctypes.c_ulonglong),
                ("ullTotalPageFile", ctypes.c_ulonglong),
                ("ullAvailPageFile", ctypes.c_ulonglong),
                ("ullTotalVirtual", ctypes.c_ulonglong),
                ("ullAvailVirtual", ctypes.c_ulonglong),
                ("sullAvailExtendedVirtual", ctypes.c_ulonglong),
            ]

        status = MEMORYSTATUSEX()
        status.dwLength = ctypes.sizeof(MEMORYSTATUSEX)
        if ctypes.windll.kernel32.GlobalMemoryStatusEx(ctypes.byref(status)):
            total_memory = int(status.ullTotalPhys)

    return {
        "platform": platform.platform(),
        "machine": platform.machine(),
        "processor": platform.processor(),
        "logical_cpu_count": os.cpu_count(),
        "total_physical_memory_bytes": total_memory,
    }


def verify_environment(contract: dict[str, Any]) -> dict[str, Any]:
    actual = current_environment()
    for key, value in contract["environment"].items():
        if actual.get(key) != value:
            raise RuntimeError(
                f"environment mismatch for {key}: {actual.get(key)!r} != {value!r}"
            )
    return actual


def verify_dependency(contract: dict[str, Any]) -> dict[str, Any]:
    import Evtx.Nodes as nodes

    expected = contract["dependency"]
    version = importlib.metadata.version("python-evtx")
    if version != expected["version"]:
        raise RuntimeError(f"python-evtx version mismatch: {version}")

    nodes_path = Path(inspect.getsourcefile(nodes) or "")
    if not nodes_path.is_file():
        raise RuntimeError("cannot locate Evtx.Nodes source file")
    nodes_sha = sha256_file(nodes_path)
    if nodes_sha != expected["nodes_py_sha256"]:
        raise RuntimeError(f"Evtx.Nodes.py SHA mismatch: {nodes_sha}")

    children_source = inspect.getsource(nodes.ValueNode.children)
    children_sha = hashlib.sha256(children_source.encode("utf-8")).hexdigest()
    if children_sha != expected["value_node_children_source_sha256"]:
        raise RuntimeError(f"ValueNode.children source SHA mismatch: {children_sha}")
    if "@memoize" in children_source:
        raise RuntimeError("stock ValueNode.children is already memoized")

    return {
        "package": "python-evtx",
        "version": version,
        "nodes_py_sha256": nodes_sha,
        "value_node_children_source_sha256": children_sha,
    }


def worker_render(evtx_path: Path, limit: int, variant: str) -> dict[str, Any]:
    from Evtx.Evtx import Evtx
    import Evtx.Nodes as nodes

    if variant == "candidate":
        nodes.ValueNode.children = nodes.memoize(nodes.ValueNode.children)
    elif variant != "stock":
        raise RuntimeError(f"unknown variant: {variant}")

    process = psutil.Process()
    digest = hashlib.sha256()
    count = 0
    rss_start = process.memory_info().rss
    rss_peak = rss_start

    started = time.perf_counter()
    with Evtx(str(evtx_path)) as log:
        for record in log.records():
            if count >= limit:
                break
            xml_text = record.xml()
            raw = xml_text.encode("utf-8")
            canonical_digest_update(digest, raw)
            count += 1
            if count % 25 == 0:
                rss_peak = max(rss_peak, process.memory_info().rss)
    seconds = time.perf_counter() - started

    rss_end = process.memory_info().rss
    rss_peak = max(rss_peak, rss_end)
    return {
        "variant": variant,
        "records": count,
        "seconds": seconds,
        "xml_digest_sha256": digest.hexdigest(),
        "rss_start_bytes": rss_start,
        "rss_peak_bytes": rss_peak,
        "rss_end_bytes": rss_end,
    }


def run_worker(args: argparse.Namespace) -> int:
    payload = worker_render(
        Path(args.evtx).resolve(),
        args.record_limit,
        args.variant,
    )
    print(json.dumps(payload, sort_keys=True))
    return 0


def run_child(
    script: Path,
    evtx_path: Path,
    record_limit: int,
    variant: str,
) -> dict[str, Any]:
    proc = subprocess.run(
        [
            sys.executable,
            str(script),
            "--worker",
            "--variant",
            variant,
            "--evtx",
            str(evtx_path),
            "--record-limit",
            str(record_limit),
        ],
        text=True,
        capture_output=True,
        check=False,
    )
    if proc.returncode != 0:
        raise RuntimeError(
            f"{variant} worker failed ({proc.returncode}): "
            f"{proc.stderr.strip() or proc.stdout.strip()}"
        )
    lines = [line for line in proc.stdout.splitlines() if line.strip()]
    if not lines:
        raise RuntimeError(f"{variant} worker produced no JSON output")
    return json.loads(lines[-1])


def summarize(values: list[float]) -> dict[str, float]:
    return {
        "count": len(values),
        "median": statistics.median(values),
        "mean": statistics.mean(values),
        "min": min(values),
        "max": max(values),
        "max_over_min_ratio": max(values) / min(values),
    }


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Run the preregistered P2-33 python-evtx ValueNode memo benchmark."
    )
    parser.add_argument("--contract")
    parser.add_argument("--evtx")
    parser.add_argument("--out-dir")
    parser.add_argument("--worker", action="store_true")
    parser.add_argument("--variant", choices=("stock", "candidate"))
    parser.add_argument("--record-limit", type=int)
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    if args.worker:
        if not args.variant or not args.evtx or not args.record_limit:
            raise SystemExit("worker requires --variant, --evtx, and --record-limit")
        return run_worker(args)

    if sys.version_info[:2] != (3, 11):
        raise SystemExit("P2-33 requires Python 3.11")
    if sys.platform != "win32":
        raise SystemExit("P2-33 requires Windows")

    required = {
        "--contract": args.contract,
        "--evtx": args.evtx,
        "--out-dir": args.out_dir,
    }
    missing = [name for name, value in required.items() if not value]
    if missing:
        raise SystemExit(f"missing required arguments: {', '.join(missing)}")

    script = Path(__file__).resolve()
    contract_path = Path(args.contract).resolve()
    contract = yaml.safe_load(contract_path.read_text(encoding="utf-8"))
    if contract["benchmark_id"] != BENCHMARK_ID:
        raise RuntimeError("benchmark id mismatch")

    runner_sha = sha256_file(script)
    if runner_sha != contract["runner"]["sha256"]:
        raise RuntimeError("runner SHA mismatch")

    environment = verify_environment(contract)
    dependency = verify_dependency(contract)

    evtx_path = Path(args.evtx).resolve()
    source = contract["source"]
    if evtx_path.stat().st_size != source["size_bytes"]:
        raise RuntimeError("source EVTX size mismatch")
    if sha256_file(evtx_path) != source["sha256"]:
        raise RuntimeError("source EVTX SHA mismatch")

    out_dir = Path(args.out_dir).resolve()
    out_dir.mkdir(parents=True, exist_ok=False)
    lock_path = out_dir / contract["runner"]["lock_file"]
    fd = os.open(str(lock_path), os.O_CREAT | os.O_EXCL | os.O_WRONLY)
    try:
        os.write(
            fd,
            (
                json.dumps(
                    {
                        "benchmark_id": BENCHMARK_ID,
                        "pid": os.getpid(),
                        "created_unix": time.time(),
                    }
                )
                + "\n"
            ).encode("utf-8"),
        )
    finally:
        os.close(fd)

    result_path = out_dir / contract["runner"]["result_file"]
    result: dict[str, Any] = {
        "schema": SCHEMA,
        "benchmark_id": BENCHMARK_ID,
        "status": "started",
        "contract_sha256": sha256_file(contract_path),
        "runner_sha256": runner_sha,
        "python": sys.version,
        "environment": environment,
        "dependency": dependency,
        "source": {
            "path": str(evtx_path),
            "size_bytes": evtx_path.stat().st_size,
            "sha256": sha256_file(evtx_path),
        },
    }
    write_json(result_path, result)

    try:
        measurement = contract["measurement"]
        record_limit = int(measurement["record_limit"])
        order = measurement["variant_order"]
        repetitions = int(measurement["repetitions_per_variant"])
        if len(order) != repetitions:
            raise RuntimeError("variant order length does not match repetitions")

        rows: list[dict[str, Any]] = []
        for repetition, pair in enumerate(order, start=1):
            if sorted(pair) != ["candidate", "stock"]:
                raise RuntimeError(
                    "each variant order row must contain stock and candidate exactly once"
                )
            for variant in pair:
                row = run_child(script, evtx_path, record_limit, variant)
                if row["records"] != record_limit:
                    raise RuntimeError("worker record accounting mismatch")
                row["repetition"] = repetition
                rows.append(row)

        digests = {row["xml_digest_sha256"] for row in rows}
        if len(digests) != 1:
            raise RuntimeError("stock/candidate XML digest mismatch")

        stock_seconds = [row["seconds"] for row in rows if row["variant"] == "stock"]
        candidate_seconds = [
            row["seconds"] for row in rows if row["variant"] == "candidate"
        ]
        stock_peak = [
            float(row["rss_peak_bytes"]) for row in rows if row["variant"] == "stock"
        ]
        candidate_peak = [
            float(row["rss_peak_bytes"])
            for row in rows
            if row["variant"] == "candidate"
        ]

        time_summary = {
            "stock": summarize(stock_seconds),
            "candidate": summarize(candidate_seconds),
        }
        rss_summary = {
            "stock_peak_bytes": summarize(stock_peak),
            "candidate_peak_bytes": summarize(candidate_peak),
        }
        stock_median = time_summary["stock"]["median"]
        candidate_median = time_summary["candidate"]["median"]

        result.update(
            {
                "status": "completed",
                "runs": rows,
                "xml_digest_sha256": next(iter(digests)),
                "time_summary_seconds": time_summary,
                "rss_summary": rss_summary,
                "comparison": {
                    "stock_over_candidate_median_ratio": (
                        stock_median / candidate_median
                    ),
                    "candidate_median_change_percent": (
                        (candidate_median - stock_median)
                        / stock_median
                        * 100.0
                    ),
                },
                "claim_boundary": {
                    "true_cold_os_cache": "NOT_MEASURED",
                    "general_speedup": "NOT_CLAIMED",
                    "full_pipeline_speedup": "NOT_CLAIMED",
                    "production_capacity": "NOT_CLAIMED",
                    "statistical_benchmark": False,
                    "detection_accuracy": "NOT_EVALUATED",
                    "benign_fpr": "NOT_EVALUATED",
                },
            }
        )
        write_json(result_path, result)
        return 0
    except Exception as exc:
        result["status"] = "failed"
        result["exception"] = f"{type(exc).__name__}: {exc}"
        write_json(result_path, result)
        raise


if __name__ == "__main__":
    raise SystemExit(main())
