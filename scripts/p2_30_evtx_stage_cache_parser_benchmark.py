from __future__ import annotations

import argparse
import hashlib
import json
import os
import platform
import statistics
import subprocess
import sys
import tempfile
import time
from pathlib import Path
from typing import Any

import yaml


SCHEMA = "breachscope.p2_30_evtx_stage_cache_parser_benchmark.v1"
BENCHMARK_ID = "p2-30-windows-evtx-stage-cache-parser-v1"


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
        import ctypes

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
    expected = contract["environment"]
    for key, value in expected.items():
        if actual.get(key) != value:
            raise RuntimeError(
                f"environment mismatch for {key}: {actual.get(key)!r} != {value!r}"
            )
    return actual


def git_text(repo: Path, *args: str) -> str:
    return subprocess.check_output(
        ["git", "-C", str(repo), *args],
        text=True,
        stderr=subprocess.STDOUT,
    ).strip()


def verify_product(repo: Path, spec: dict[str, Any], label: str) -> dict[str, Any]:
    head = git_text(repo, "rev-parse", "HEAD")
    if head != spec["repo_commit"]:
        raise RuntimeError(f"{label} product commit mismatch: {head}")
    status = git_text(repo, "status", "--porcelain")
    if status:
        raise RuntimeError(f"{label} product repo is dirty")
    blob = git_text(repo, "hash-object", "breachscope/ingest.py")
    if blob != spec["parser_git_blob_sha1"]:
        raise RuntimeError(f"{label} ingest.py blob mismatch: {blob}")
    return {
        "repo_commit": head,
        "parser_git_blob_sha1": blob,
    }


def xml_digest_for_pass(evtx_path: Path, limit: int) -> dict[str, Any]:
    from Evtx.Evtx import Evtx

    h = hashlib.sha256()
    count = 0
    started = time.perf_counter()
    with Evtx(str(evtx_path)) as log:
        for record in log.records():
            if count >= limit:
                break
            xml_text = record.xml()
            canonical_digest_update(h, xml_text.encode("utf-8"))
            count += 1
    seconds = time.perf_counter() - started
    return {
        "records": count,
        "seconds": seconds,
        "xml_digest_sha256": h.hexdigest(),
    }


def worker_record_xml(evtx_path: Path, limit: int) -> dict[str, Any]:
    first = xml_digest_for_pass(evtx_path, limit)
    second = xml_digest_for_pass(evtx_path, limit)
    if first["records"] != limit or second["records"] != limit:
        raise RuntimeError("record.xml worker did not produce the exact record limit")
    if first["xml_digest_sha256"] != second["xml_digest_sha256"]:
        raise RuntimeError("record.xml digest changed between immediate passes")
    return {
        "no_in_process_prewarm": first,
        "deliberate_warm": second,
    }


def worker_materialize_xml(evtx_path: Path, limit: int, output: Path) -> dict[str, Any]:
    from Evtx.Evtx import Evtx

    h = hashlib.sha256()
    count = 0
    output.parent.mkdir(parents=True, exist_ok=True)
    with output.open("w", encoding="utf-8", newline="\n") as fh:
        with Evtx(str(evtx_path)) as log:
            for record in log.records():
                if count >= limit:
                    break
                xml_text = record.xml()
                raw = xml_text.encode("utf-8")
                canonical_digest_update(h, raw)
                fh.write(json.dumps(xml_text, ensure_ascii=False))
                fh.write("\n")
                count += 1
    if count != limit:
        raise RuntimeError("materialized XML corpus did not reach exact record limit")
    return {
        "records": count,
        "xml_digest_sha256": h.hexdigest(),
        "xml_corpus_bytes": output.stat().st_size,
    }


def worker_parser(product_repo: Path, xml_corpus: Path) -> dict[str, Any]:
    repo = str(product_repo.resolve())
    cwd = str(Path.cwd().resolve())
    sys.path = [repo] + [
        p for p in sys.path if p not in ("", cwd, repo)
    ]
    from breachscope.ingest import _extract_from_xml

    xmls = [
        json.loads(line)
        for line in xml_corpus.read_text(encoding="utf-8").splitlines()
        if line
    ]
    h = hashlib.sha256()
    started = time.perf_counter()
    for xml_text in xmls:
        row = _extract_from_xml(xml_text)
        raw = json.dumps(
            row,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
        canonical_digest_update(h, raw)
    seconds = time.perf_counter() - started
    return {
        "records": len(xmls),
        "seconds": seconds,
        "normalized_digest_sha256": h.hexdigest(),
    }


def run_worker(args: argparse.Namespace) -> int:
    if args.worker == "record-xml":
        payload = worker_record_xml(Path(args.evtx), args.record_limit)
    elif args.worker == "materialize-xml":
        payload = worker_materialize_xml(
            Path(args.evtx),
            args.record_limit,
            Path(args.xml_corpus),
        )
    elif args.worker == "parser":
        payload = worker_parser(
            Path(args.product_repo),
            Path(args.xml_corpus),
        )
    else:
        raise RuntimeError(f"unknown worker mode: {args.worker}")
    print(json.dumps(payload, sort_keys=True))
    return 0


def run_child(script: Path, argv: list[str]) -> dict[str, Any]:
    proc = subprocess.run(
        [sys.executable, str(script), *argv],
        text=True,
        capture_output=True,
        check=False,
    )
    if proc.returncode != 0:
        raise RuntimeError(
            f"worker failed ({proc.returncode}): {proc.stderr.strip() or proc.stdout.strip()}"
        )
    lines = [line for line in proc.stdout.splitlines() if line.strip()]
    if not lines:
        raise RuntimeError("worker produced no JSON output")
    return json.loads(lines[-1])


def summarize(values: list[float]) -> dict[str, float]:
    return {
        "count": len(values),
        "median_seconds": statistics.median(values),
        "mean_seconds": statistics.mean(values),
        "min_seconds": min(values),
        "max_seconds": max(values),
        "max_over_min_ratio": max(values) / min(values),
    }


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Run the preregistered P2-30 EVTX stage/cache/parser benchmark."
    )
    parser.add_argument("--contract")
    parser.add_argument("--old-product-repo")
    parser.add_argument("--new-product-repo")
    parser.add_argument("--evtx")
    parser.add_argument("--out-dir")
    parser.add_argument(
        "--worker",
        choices=("record-xml", "materialize-xml", "parser"),
    )
    parser.add_argument("--record-limit", type=int)
    parser.add_argument("--xml-corpus")
    parser.add_argument("--product-repo")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    if args.worker:
        return run_worker(args)

    if sys.version_info[:2] != (3, 11):
        raise SystemExit("P2-30 requires Python 3.11")
    if sys.platform != "win32":
        raise SystemExit("P2-30 requires Windows")

    required = {
        "--contract": args.contract,
        "--old-product-repo": args.old_product_repo,
        "--new-product-repo": args.new_product_repo,
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
    actual_runner_sha = sha256_file(script)
    if actual_runner_sha != contract["runner"]["sha256"]:
        raise RuntimeError("runner SHA mismatch")

    environment = verify_environment(contract)
    old_product = verify_product(
        Path(args.old_product_repo).resolve(),
        contract["products"]["old"],
        "old",
    )
    new_product = verify_product(
        Path(args.new_product_repo).resolve(),
        contract["products"]["new"],
        "new",
    )

    evtx_path = Path(args.evtx).resolve()
    source = contract["source"]
    if evtx_path.stat().st_size != source["size_bytes"]:
        raise RuntimeError("source EVTX size mismatch")
    if sha256_file(evtx_path) != source["sha256"]:
        raise RuntimeError("source EVTX SHA mismatch")

    out_dir = Path(args.out_dir).resolve()
    out_dir.mkdir(parents=True, exist_ok=False)
    lock_path = out_dir / "P2_30_ONE_PASS.lock"
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

    result_path = out_dir / "result.json"
    result: dict[str, Any] = {
        "schema": SCHEMA,
        "benchmark_id": BENCHMARK_ID,
        "status": "started",
        "contract_sha256": sha256_file(contract_path),
        "runner_sha256": actual_runner_sha,
        "python": sys.version,
        "environment": environment,
        "products": {
            "old": old_product,
            "new": new_product,
        },
        "source": {
            "path": str(evtx_path),
            "size_bytes": evtx_path.stat().st_size,
            "sha256": sha256_file(evtx_path),
        },
    }
    write_json(result_path, result)

    xml_corpus = out_dir / "_p2_30_xml_corpus.jsonl"
    try:
        cfg = contract["measurement"]
        record_limit = int(cfg["record_limit"])
        repetitions = int(cfg["repetitions"])

        record_runs: list[dict[str, Any]] = []
        for repetition in range(1, repetitions + 1):
            row = run_child(
                script,
                [
                    "--worker",
                    "record-xml",
                    "--evtx",
                    str(evtx_path),
                    "--record-limit",
                    str(record_limit),
                ],
            )
            row["repetition"] = repetition
            record_runs.append(row)

        materialized = run_child(
            script,
            [
                "--worker",
                "materialize-xml",
                "--evtx",
                str(evtx_path),
                "--record-limit",
                str(record_limit),
                "--xml-corpus",
                str(xml_corpus),
            ],
        )

        xml_digests = {
            materialized["xml_digest_sha256"],
            *[
                row["no_in_process_prewarm"]["xml_digest_sha256"]
                for row in record_runs
            ],
            *[
                row["deliberate_warm"]["xml_digest_sha256"]
                for row in record_runs
            ],
        }
        if len(xml_digests) != 1:
            raise RuntimeError("XML corpus digest mismatch across record.xml repetitions")

        order = cfg["parser_order"]
        if len(order) != repetitions:
            raise RuntimeError("parser order length does not match repetitions")

        parser_runs: list[dict[str, Any]] = []
        repos = {
            "old": str(Path(args.old_product_repo).resolve()),
            "new": str(Path(args.new_product_repo).resolve()),
        }
        for repetition, pair in enumerate(order, start=1):
            if sorted(pair) != ["new", "old"]:
                raise RuntimeError("each parser order row must contain old and new exactly once")
            for variant in pair:
                row = run_child(
                    script,
                    [
                        "--worker",
                        "parser",
                        "--product-repo",
                        repos[variant],
                        "--xml-corpus",
                        str(xml_corpus),
                    ],
                )
                if row["records"] != record_limit:
                    raise RuntimeError("parser worker record accounting mismatch")
                row["repetition"] = repetition
                row["variant"] = variant
                parser_runs.append(row)

        normalized_digests = {
            row["normalized_digest_sha256"] for row in parser_runs
        }
        if len(normalized_digests) != 1:
            raise RuntimeError("old/new parser normalized output digest mismatch")

        no_prewarm = [
            row["no_in_process_prewarm"]["seconds"] for row in record_runs
        ]
        deliberate_warm = [
            row["deliberate_warm"]["seconds"] for row in record_runs
        ]
        old_times = [
            row["seconds"] for row in parser_runs if row["variant"] == "old"
        ]
        new_times = [
            row["seconds"] for row in parser_runs if row["variant"] == "new"
        ]

        record_summary = {
            "no_in_process_prewarm": summarize(no_prewarm),
            "deliberate_warm": summarize(deliberate_warm),
        }
        parser_summary = {
            "old": summarize(old_times),
            "new": summarize(new_times),
        }
        old_median = parser_summary["old"]["median_seconds"]
        new_median = parser_summary["new"]["median_seconds"]

        result.update(
            {
                "status": "completed",
                "record_xml_runs": record_runs,
                "materialized_xml_corpus": materialized,
                "parser_runs": parser_runs,
                "record_xml_summary": record_summary,
                "parser_summary": parser_summary,
                "comparison": {
                    "old_over_new_parser_median_ratio": old_median / new_median,
                    "new_parser_median_change_percent": (
                        (new_median - old_median) / old_median * 100.0
                    ),
                    "normalized_output_digest_sha256": next(
                        iter(normalized_digests)
                    ),
                    "record_xml_no_prewarm_max_over_min_ratio": (
                        record_summary["no_in_process_prewarm"]["max_over_min_ratio"]
                    ),
                    "record_xml_warm_max_over_min_ratio": (
                        record_summary["deliberate_warm"]["max_over_min_ratio"]
                    ),
                },
                "claim_boundary": {
                    "true_cold_os_cache": "NOT_MEASURED",
                    "no_in_process_prewarm_is_true_cold": False,
                    "deliberate_warm_is_same_process_immediate_second_pass": True,
                    "parser_comparison": "REPEATED_STAGE_LEVEL_OBSERVATION",
                    "general_full_pipeline_speedup": "NOT_CLAIMED",
                    "production_capacity": "NOT_CLAIMED",
                    "enterprise_scale_readiness": "NOT_CLAIMED",
                    "detection_executed": False,
                    "detection_accuracy": "NOT_EVALUATED",
                    "benign_fpr": "NOT_EVALUATED",
                },
            }
        )
        write_json(result_path, result)
        return 0
    except Exception as exc:
        result["status"] = "failed"
        result["error"] = f"{type(exc).__name__}: {exc}"
        write_json(result_path, result)
        return 2
    finally:
        try:
            xml_corpus.unlink()
        except FileNotFoundError:
            pass


if __name__ == "__main__":
    raise SystemExit(main())
