from __future__ import annotations

import argparse
import html
import itertools
import json
import ntpath
import re
from collections import Counter
from pathlib import Path

from Evtx.Evtx import Evtx

EXPECTED_CORPUS_SHA256 = "d48f1b328d48db6c6dfaa9b6e232dbb454d93e833c6e1248efc0faf690b6808e"
EXPECTED_CHUNKS = 11894
EXPECTED_RECORDS = 732200
EXPECTED_EVENT1 = 2149

EVENT_ID_RE = re.compile(r'<EventID(?:\s+[^>]*)?>(\d+)</EventID>', re.I)
DATA_RE = re.compile(r'<Data\s+Name="([^"]+)">(.*?)</Data>', re.I | re.S)
GET_RE = re.compile(r'(?<!\S)get(?!\S)', re.I)
USERACCOUNT_GET_RE = re.compile(r'\buseraccount\b.\*\bget\b', re.I)
PROCESS_GET_RE = re.compile(r'\bprocess\b.\*\bget\b', re.I)
FORMAT_CSV_RE = re.compile(r'/format\s*:\s*["\']?csv(?:["\']|\s|$)', re.I)
REMOTE_FORMAT_RE = re.compile(r'/format\s*:\s*["\']?https?://', re.I)


def event_data(xml: str) -> dict[str, str]:
    return {name: html.unescape(value) for name, value in DATA_RE.findall(xml)}


def basename(value: object) -> str:
    return ntpath.basename(str(value or "").strip().strip('"')).lower()


def sample(data: dict[str, str]) -> dict[str, str]:
    return {
        "image": data.get("Image", ""),
        "command_line": data.get("CommandLine", ""),
        "user": data.get("User", ""),
        "parent_image": data.get("ParentImage", ""),
        "parent_command_line": data.get("ParentCommandLine", ""),
        "utc_time": data.get("UtcTime", ""),
    }


def scan_shard(args: argparse.Namespace) -> None:
    idx = args.shard_index
    base, rem = divmod(args.total_chunks, args.shard_count)
    start = idx * base + min(idx, rem)
    end = start + base + (1 if idx < rem else 0)
    path = Path(args.evtx)

    with Evtx(str(path)) as log:
        total_chunks = sum(1 for _ in log.chunks())
    if total_chunks != args.total_chunks:
        raise SystemExit(f"expected {args.total_chunks} chunks, got {total_chunks}")

    counters = Counter({
        "records": 0,
        "event1": 0,
        "wmic_event1": 0,
        "wmic_get_any": 0,
        "wmic_get_non_remote_xsl": 0,
        "wmic_useraccount_get": 0,
        "wmic_process_get": 0,
        "wmic_user_or_process_get": 0,
        "wmic_get_format_csv": 0,
        "wmic_get_remote_format_http": 0,
        "xml_errors": 0,
    })
    samples: dict[str, list[dict[str, str]]] = {k: [] for k in (
        "wmic_event1",
        "wmic_get_any",
        "wmic_get_non_remote_xsl",
        "wmic_useraccount_get",
        "wmic_process_get",
        "wmic_get_remote_format_http",
    )}

    with Evtx(str(path)) as log:
        for chunk in itertools.islice(log.chunks(), start, end):
            for record in chunk.records():
                counters["records"] += 1
                try:
                    xml = record.xml()
                except Exception:
                    counters["xml_errors"] += 1
                    continue
                match = EVENT_ID_RE.search(xml)
                if not match or match.group(1) != "1":
                    continue
                counters["event1"] += 1
                data = event_data(xml)
                if basename(data.get("Image")) != "wmic.exe":
                    continue
                counters["wmic_event1"] += 1
                if len(samples["wmic_event1"]) < 10:
                    samples["wmic_event1"].append(sample(data))
                cmd = data.get("CommandLine", "")
                if not GET_RE.search(cmd):
                    continue
                counters["wmic_get_any"] += 1
                if len(samples["wmic_get_any"]) < 10:
                    samples["wmic_get_any"].append(sample(data))

                remote = bool(REMOTE_FORMAT_RE.search(cmd))
                if remote:
                    counters["wmic_get_remote_format_http"] += 1
                    if len(samples["wmic_get_remote_format_http"]) < 10:
                        samples["wmic_get_remote_format_http"].append(sample(data))
                else:
                    counters["wmic_get_non_remote_xsl"] += 1
                    if len(samples["wmic_get_non_remote_xsl"]) < 10:
                        samples["wmic_get_non_remote_xsl"].append(sample(data))

                user_q = bool(USERACCOUNT_GET_RE.search(cmd))
                proc_q = bool(PROCESS_GET_RE.search(cmd))
                if user_q:
                    counters["wmic_useraccount_get"] += 1
                    if len(samples["wmic_useraccount_get"]) < 10:
                        samples["wmic_useraccount_get"].append(sample(data))
                if proc_q:
                    counters["wmic_process_get"] += 1
                    if len(samples["wmic_process_get"]) < 10:
                        samples["wmic_process_get"].append(sample(data))
                if user_q or proc_q:
                    counters["wmic_user_or_process_get"] += 1
                if FORMAT_CSV_RE.search(cmd):
                    counters["wmic_get_format_csv"] += 1

    payload = {
        "schema": "breachscope.p2_11h_t1047_benign_shard.v1",
        "shard": idx,
        "chunk_start": start,
        "chunk_end": end,
        "total_chunks": total_chunks,
        "corpus_sha256": args.corpus_sha256,
        "counters": dict(counters),
        "samples": samples,
    }
    out = Path(args.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(payload, indent=2, ensure_ascii=False), encoding="utf-8")
    print(json.dumps(payload, ensure_ascii=False))


def aggregate(args: argparse.Namespace) -> None:
    files = sorted(Path(args.input_dir).glob("*.json"))
    if len(files) != args.shard_count:
        raise SystemExit(f"expected {args.shard_count} shard files, got {len(files)}")
    rows = [json.loads(p.read_text(encoding="utf-8")) for p in files]
    rows.sort(key=lambda x: int(x["chunk_start"]))
    cursor = 0
    totals: Counter[str] = Counter()
    samples: dict[str, list[dict[str, str]]] = {}
    for row in rows:
        if int(row["chunk_start"]) != cursor:
            raise SystemExit(f"coverage gap/overlap at shard {row['shard']}: {cursor} != {row['chunk_start']}")
        cursor = int(row["chunk_end"])
        if int(row["total_chunks"]) != EXPECTED_CHUNKS:
            raise SystemExit("chunk count mismatch")
        if row["corpus_sha256"] != EXPECTED_CORPUS_SHA256:
            raise SystemExit("corpus hash mismatch")
        totals.update({k: int(v) for k, v in row["counters"].items()})
        for kind, items in row["samples"].items():
            samples.setdefault(kind, []).extend(items)
            samples[kind] = samples[kind][:50]
    if cursor != EXPECTED_CHUNKS:
        raise SystemExit(f"incomplete coverage: {cursor}")
    if totals["records"] != EXPECTED_RECORDS:
        raise SystemExit(f"expected {EXPECTED_RECORDS} records, got {totals['records']}")
    if totals["event1"] != EXPECTED_EVENT1:
        raise SystemExit(f"expected {EXPECTED_EVENT1} Sysmon Event 1 records, got {totals['event1']}")
    if totals["xml_errors"] != 0:
        raise SystemExit(f"xml errors: {totals['xml_errors']}")

    result = {
        "schema": "breachscope.p2_11h_t1047_benign_probe.v1",
        "corpus_sha256": EXPECTED_CORPUS_SHA256,
        "scope": {
            "sysmon_records": totals["records"],
            "sysmon_chunks": EXPECTED_CHUNKS,
            "sysmon_event1": totals["event1"],
            "parse_errors": totals["xml_errors"],
        },
        "candidate_counts": {
            "wmic_event1": totals["wmic_event1"],
            "wmic_get_any": totals["wmic_get_any"],
            "wmic_get_non_remote_xsl": totals["wmic_get_non_remote_xsl"],
            "wmic_useraccount_get": totals["wmic_useraccount_get"],
            "wmic_process_get": totals["wmic_process_get"],
            "wmic_user_or_process_get": totals["wmic_user_or_process_get"],
            "wmic_get_format_csv": totals["wmic_get_format_csv"],
            "wmic_get_remote_format_http": totals["wmic_get_remote_format_http"],
        },
        "samples": samples,
        "claim_boundary": {
            "production_false_positive_rate": "NOT_CLAIMED",
            "fresh_full_rulepack_fpr": "NOT_CLAIMED",
            "note": "Counts apply only to the pinned public benign-by-source-intent Sysmon corpus and these WMIC query candidate predicates.",
        },
    }
    out = Path(args.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(result, indent=2, ensure_ascii=False), encoding="utf-8")
    print(json.dumps(result, ensure_ascii=False))


def parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser()
    sub = p.add_subparsers(dest="mode", required=True)
    s = sub.add_parser("shard")
    s.add_argument("--shard-index", type=int, required=True)
    s.add_argument("--shard-count", type=int, default=16)
    s.add_argument("--total-chunks", type=int, default=EXPECTED_CHUNKS)
    s.add_argument("--evtx", required=True)
    s.add_argument("--corpus-sha256", default=EXPECTED_CORPUS_SHA256)
    s.add_argument("--out", required=True)
    a = sub.add_parser("aggregate")
    a.add_argument("--input-dir", required=True)
    a.add_argument("--shard-count", type=int, default=16)
    a.add_argument("--out", required=True)
    return p


if __name__ == "__main__":
    args = parser().parse_args()
    if args.mode == "shard":
        scan_shard(args)
    else:
        aggregate(args)
