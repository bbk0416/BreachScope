from __future__ import annotations

import argparse
import html
import itertools
import json
import re
from collections import Counter
from pathlib import Path

EXPECTED_CORPUS_SHA256 = "d48f1b328d48db6c6dfaa9b6e232dbb454d93e833c6e1248efc0faf690b6808e"
EXPECTED_CHUNKS = 11894
EXPECTED_RECORDS = 732200
EXPECTED_EVENT1 = 2149

EVENT_ID_RE = re.compile(r'<EventID(?:\s+[^>]*)?>(\d+)</EventID>', re.I)
DATA_RE = re.compile(r'<Data\s+Name="([^"]+)">(.*?)</Data>', re.I | re.S)
SERVICE_NP_RE = re.compile(r'currentcontrolset\\services\\[^\\\s"\']+\\networkprovider', re.I)


def event_data(xml: str) -> dict[str, str]:
    return {name: html.unescape(value) for name, value in DATA_RE.findall(xml)}


def sample(data: dict[str, str]) -> dict[str, str]:
    return {
        "image": data.get("Image", ""),
        "command_line": data.get("CommandLine", ""),
        "user": data.get("User", ""),
        "parent_image": data.get("ParentImage", ""),
        "parent_command_line": data.get("ParentCommandLine", ""),
        "utc_time": data.get("UtcTime", ""),
    }


def predicates(cmd: str) -> dict[str, bool]:
    c = cmd.lower()
    np_any = "networkprovider" in c
    np_order = "currentcontrolset\\control\\networkprovider\\order" in c
    provider_order = "providerorder" in c
    set_item = "set-itemproperty" in c
    service_np = bool(SERVICE_NP_RE.search(c))
    provider_path = "providerpath" in c
    return {
        "networkprovider_any": np_any,
        "networkprovider_order": np_order,
        "providerorder": provider_order,
        "setitem_providerorder": np_order and provider_order and set_item,
        "service_networkprovider": service_np,
        "service_providerpath": service_np and provider_path,
        "order_and_service_providerpath": np_order and provider_order and set_item and service_np and provider_path,
    }


def scan_shard(args: argparse.Namespace) -> None:
    from Evtx.Evtx import Evtx

    idx = args.shard_index
    base, rem = divmod(args.total_chunks, args.shard_count)
    start = idx * base + min(idx, rem)
    end = start + base + (1 if idx < rem else 0)
    path = Path(args.evtx)

    with Evtx(str(path)) as log:
        total_chunks = sum(1 for _ in log.chunks())
    if total_chunks != args.total_chunks:
        raise SystemExit(f"expected {args.total_chunks} chunks, got {total_chunks}")

    keys = (
        "networkprovider_any",
        "networkprovider_order",
        "providerorder",
        "setitem_providerorder",
        "service_networkprovider",
        "service_providerpath",
        "order_and_service_providerpath",
    )
    counters = Counter({"records": 0, "event1": 0, "xml_errors": 0, **{k: 0 for k in keys}})
    samples = {k: [] for k in keys}

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
                pred = predicates(data.get("CommandLine", ""))
                for key, matched in pred.items():
                    if matched:
                        counters[key] += 1
                        if len(samples[key]) < 10:
                            samples[key].append(sample(data))

    payload = {
        "schema": "breachscope.p2_11j_t1003_2_benign_shard.v1",
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
    if cursor != EXPECTED_CHUNKS or totals["records"] != EXPECTED_RECORDS or totals["event1"] != EXPECTED_EVENT1:
        raise SystemExit(f"coverage mismatch: cursor={cursor} records={totals['records']} event1={totals['event1']}")
    if totals["xml_errors"] != 0:
        raise SystemExit(f"xml errors: {totals['xml_errors']}")

    keys = (
        "networkprovider_any",
        "networkprovider_order",
        "providerorder",
        "setitem_providerorder",
        "service_networkprovider",
        "service_providerpath",
        "order_and_service_providerpath",
    )
    result = {
        "schema": "breachscope.p2_11j_t1003_2_benign_probe.v1",
        "corpus_sha256": EXPECTED_CORPUS_SHA256,
        "scope": {
            "sysmon_records": totals["records"],
            "sysmon_chunks": EXPECTED_CHUNKS,
            "sysmon_event1": totals["event1"],
            "parse_errors": totals["xml_errors"],
        },
        "candidate_counts": {k: totals[k] for k in keys},
        "samples": samples,
        "claim_boundary": {
            "production_false_positive_rate": "NOT_CLAIMED",
            "fresh_full_rulepack_fpr": "NOT_CLAIMED",
            "note": "Counts apply only to the pinned public benign-by-source-intent Sysmon corpus and these NetworkProvider configuration candidate predicates.",
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
