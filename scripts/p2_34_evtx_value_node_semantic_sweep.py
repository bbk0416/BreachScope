from __future__ import annotations

import argparse
import ctypes
import hashlib
import importlib.metadata
import inspect
import json
import os
import platform
import subprocess
import sys
import time
from pathlib import Path
from typing import Any

import yaml


SCHEMA = "breachscope.p2_34_evtx_value_node_semantic_sweep.v1"
BENCHMARK_ID = "p2-34-windows-evtx-value-node-semantic-sweep-v1"


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


def corpus_inventory(corpus_dir: Path) -> dict[str, Any]:
    files = sorted(
        corpus_dir.rglob("*.evtx"),
        key=lambda path: path.relative_to(corpus_dir).as_posix(),
    )
    h = hashlib.sha256()
    total_bytes = 0
    for path in files:
        rel = path.relative_to(corpus_dir).as_posix()
        size = path.stat().st_size
        total_bytes += size
        h.update(f"{rel}\t{size}\n".encode("utf-8"))
    return {
        "file_count": len(files),
        "total_bytes": total_bytes,
        "path_size_manifest_sha256": h.hexdigest(),
        "files": files,
    }


def verify_corpus(corpus_dir: Path, contract: dict[str, Any]) -> dict[str, Any]:
    actual = corpus_inventory(corpus_dir)
    expected = contract["source"]["extracted_corpus"]
    for key in ("file_count", "total_bytes", "path_size_manifest_sha256"):
        if actual[key] != expected[key]:
            raise RuntimeError(
                f"corpus inventory mismatch for {key}: "
                f"{actual[key]!r} != {expected[key]!r}"
            )
    return {
        "file_count": actual["file_count"],
        "total_bytes": actual["total_bytes"],
        "path_size_manifest_sha256": actual["path_size_manifest_sha256"],
    }


def worker_sweep(
    corpus_dir: Path,
    records_per_file: int,
    variant: str,
) -> dict[str, Any]:
    from Evtx.Evtx import Evtx
    import Evtx.Nodes as nodes

    if variant == "candidate":
        nodes.ValueNode.children = nodes.memoize(nodes.ValueNode.children)
    elif variant != "stock":
        raise RuntimeError(f"unknown variant: {variant}")

    inventory = corpus_inventory(corpus_dir)
    rows: list[dict[str, Any]] = []
    global_digest = hashlib.sha256()
    total_records = 0
    zero_record_files = 0
    started = time.perf_counter()

    for path in inventory["files"]:
        rel = path.relative_to(corpus_dir).as_posix()
        file_digest = hashlib.sha256()
        count = 0
        with Evtx(str(path)) as log:
            for record in log.records():
                if count >= records_per_file:
                    break
                xml_text = record.xml()
                raw = xml_text.encode("utf-8")
                canonical_digest_update(file_digest, raw)
                canonical_digest_update(global_digest, rel.encode("utf-8"))
                canonical_digest_update(global_digest, raw)
                count += 1

        if count == 0:
            zero_record_files += 1
        total_records += count
        rows.append(
            {
                "relative_path": rel,
                "records": count,
                "xml_digest_sha256": file_digest.hexdigest(),
            }
        )

    return {
        "variant": variant,
        "file_count": inventory["file_count"],
        "total_bytes": inventory["total_bytes"],
        "path_size_manifest_sha256": inventory["path_size_manifest_sha256"],
        "records_per_file_limit": records_per_file,
        "total_sampled_records": total_records,
        "zero_record_files": zero_record_files,
        "global_xml_digest_sha256": global_digest.hexdigest(),
        "file_results": rows,
        "elapsed_seconds_descriptive_only": time.perf_counter() - started,
    }


def run_worker(args: argparse.Namespace) -> int:
    payload = worker_sweep(
        Path(args.corpus_dir).resolve(),
        args.records_per_file,
        args.variant,
    )
    print(json.dumps(payload, sort_keys=True))
    return 0


def run_child(
    script: Path,
    corpus_dir: Path,
    records_per_file: int,
    variant: str,
) -> dict[str, Any]:
    proc = subprocess.run(
        [
            sys.executable,
            str(script),
            "--worker",
            "--variant",
            variant,
            "--corpus-dir",
            str(corpus_dir),
            "--records-per-file",
            str(records_per_file),
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


def semantic_projection(payload: dict[str, Any]) -> dict[str, Any]:
    return {
        "file_count": payload["file_count"],
        "total_bytes": payload["total_bytes"],
        "path_size_manifest_sha256": payload["path_size_manifest_sha256"],
        "records_per_file_limit": payload["records_per_file_limit"],
        "total_sampled_records": payload["total_sampled_records"],
        "zero_record_files": payload["zero_record_files"],
        "global_xml_digest_sha256": payload["global_xml_digest_sha256"],
        "file_results": payload["file_results"],
    }


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Run the preregistered P2-34 cross-file semantic sweep."
    )
    parser.add_argument("--contract")
    parser.add_argument("--archive")
    parser.add_argument("--corpus-dir")
    parser.add_argument("--out-dir")
    parser.add_argument("--worker", action="store_true")
    parser.add_argument("--variant", choices=("stock", "candidate"))
    parser.add_argument("--records-per-file", type=int)
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    if args.worker:
        if not args.variant or not args.corpus_dir or not args.records_per_file:
            raise SystemExit(
                "worker requires --variant, --corpus-dir, and --records-per-file"
            )
        return run_worker(args)

    if sys.version_info[:2] != (3, 11):
        raise SystemExit("P2-34 requires Python 3.11")
    if sys.platform != "win32":
        raise SystemExit("P2-34 requires Windows")

    required = {
        "--contract": args.contract,
        "--archive": args.archive,
        "--corpus-dir": args.corpus_dir,
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

    archive_path = Path(args.archive).resolve()
    archive = contract["source"]["archive"]
    if archive_path.stat().st_size != archive["size_bytes"]:
        raise RuntimeError("archive size mismatch")
    if sha256_file(archive_path) != archive["sha256"]:
        raise RuntimeError("archive SHA mismatch")

    corpus_dir = Path(args.corpus_dir).resolve()
    corpus = verify_corpus(corpus_dir, contract)

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
            "archive_path": str(archive_path),
            "archive_size_bytes": archive_path.stat().st_size,
            "archive_sha256": sha256_file(archive_path),
            "corpus_dir": str(corpus_dir),
            **corpus,
        },
    }
    write_json(result_path, result)

    try:
        cfg = contract["measurement"]
        limit = int(cfg["records_per_file"])
        order = cfg["variant_order"]
        if order != ["stock", "candidate"]:
            raise RuntimeError("variant order does not match preregistered design")

        payloads: dict[str, dict[str, Any]] = {}
        for variant in order:
            payload = run_child(script, corpus_dir, limit, variant)
            expected_corpus = contract["source"]["extracted_corpus"]
            for key in ("file_count", "total_bytes", "path_size_manifest_sha256"):
                if payload[key] != expected_corpus[key]:
                    raise RuntimeError(
                        f"{variant} worker corpus mismatch for {key}: {payload[key]}"
                    )
            payloads[variant] = payload

        stock_projection = semantic_projection(payloads["stock"])
        candidate_projection = semantic_projection(payloads["candidate"])
        if stock_projection != candidate_projection:
            raise RuntimeError("stock/candidate semantic sweep mismatch")

        result.update(
            {
                "status": "completed",
                "measurement": {
                    "records_per_file_limit": limit,
                    "variants": payloads,
                    "semantic_projection_identical": True,
                    "total_sampled_records": payloads["stock"][
                        "total_sampled_records"
                    ],
                    "zero_record_files": payloads["stock"]["zero_record_files"],
                    "global_xml_digest_sha256": payloads["stock"][
                        "global_xml_digest_sha256"
                    ],
                },
                "claim_boundary": {
                    "semantic_equivalence_scope": (
                        "FIRST_UP_TO_25_RECORDS_PER_EACH_OF_352_PINNED_EVTX_FILES"
                    ),
                    "all_records_semantic_equivalence": "NOT_EVALUATED",
                    "performance_comparison": "NOT_EVALUATED",
                    "product_adoption": "NOT_AUTHORIZED_BY_THIS_GATE_ALONE",
                    "production_capacity": "NOT_CLAIMED",
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
