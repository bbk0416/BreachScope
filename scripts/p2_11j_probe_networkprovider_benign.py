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
ORDER_RE = re.compile(r'networkprovider\\+order', re.I)
PROVIDERORDER_RE = re.compile(r'providerorder', re.I)
SET_ITEM_RE = re.compile(r'\bset-itemproperty\b', re.I)
SERVICES_NP_RE = re.compile(r'currentcontrolset\\+services\\+[^\s";]+\\+networkprovider\b', re.I)
PROVIDERPATH_RE = re.compile(r'providerpath', re.I)
NEW_ITEM_PROPERTY_RE = re.compile(r'\bnew-itemproperty\b', re.I)


def event_data(xml: str) -> dict[str, str]:
    return {name: html.unescape(value) for name, value in DATA_RE.findall(xml)}


def sample(data: dict[str, str]) -> dict[str, str]:
    return {
        "image": data.get("Image", ""),
        "command_line": data.get("CommandLine", ""),
        "user": data.get("User", ""),
        "parent_image": data.get("ParentImage", ""),
        "utc_time": data.get("UtcTime", ""),
    }


def scan_shard(args: argparse.Namespace) -> None:
    from Evtx.Evtx import Evtx
    idx = args.shard_index
    base, rem = divmod(args.total_chunks, args.shard_count)
    start = idx * base + min(idx, rem)
    end = start + base + (1 if idx < rem else 0)
    path = Path(args.evtx)
    counters = Counter({k: 0 for k in (
        "records", "event1", "networkprovider_any", "providerorder_reference",
        "providerorder_setitem", "service_networkprovider_reference",
        "providerpath_reference", "providerpath_newitem", "combined_candidate", "xml_errors")})
    samples = {k: [] for k in (
        "networkprovider_any", "providerorder_setitem", "providerpath_newitem", "combined_candidate")}
    with Evtx(str(path)) as log:
        total_chunks = sum(1 for _ in log.chunks())
    if total_chunks != args.total_chunks:
        raise SystemExit(f"expected {args.total_chunks} chunks, got {total_chunks}")
    with Evtx(str(path)) as log:
        for chunk in itertools.islice(log.chunks(), start, end):
            for record in chunk.records():
                counters["records"] += 1
                try:
                    xml = record.xml()
                except Exception:
                    counters["xml_errors"] += 1
                    continue
                m = EVENT_ID_RE.search(xml)
                if not m or m.group(1) != "1":
                    continue
                counters["event1"] += 1
                data = event_data(xml)
                cmd = data.get("CommandLine", "")
                low = cmd.lower()
                if "networkprovider" not in low:
                    continue
                counters["networkprovider_any"] += 1
                if len(samples["networkprovider_any"]) < 20:
                    samples["networkprovider_any"].append(sample(data))
                order_ref = bool(ORDER_RE.search(cmd) and PROVIDERORDER_RE.search(cmd))
                if order_ref:
                    counters["providerorder_reference"] += 1
                order_set = bool(order_ref and SET_ITEM_RE.search(cmd))
                if order_set:
                    counters["providerorder_setitem"] += 1
                    if len(samples["providerorder_setitem"]) < 20:
                        samples["providerorder_setitem"].append(sample(data))
                service_ref = bool(SERVICES_NP_RE.search(cmd))
                if service_ref:
                    counters["service_networkprovider_reference"] += 1
                providerpath = bool(service_ref and PROVIDERPATH_RE.search(cmd))
                if providerpath:
                    counters["providerpath_reference"] += 1
                providerpath_new = bool(providerpath and NEW_ITEM_PROPERTY_RE.search(cmd))
                if providerpath_new:
                    counters["providerpath_newitem"] += 1
                    if len(samples["providerpath_newitem"]) < 20:
                        samples["providerpath_newitem"].append(sample(data))
                if order_set and providerpath_new:
                    counters["combined_candidate"] += 1
                    if len(samples["combined_candidate"]) < 20:
                        samples["combined_candidate"].append(sample(data))
    payload = {"schema":"breachscope.p2_11j_networkprovider_benign_shard.v1","shard":idx,"chunk_start":start,"chunk_end":end,"total_chunks":total_chunks,"corpus_sha256":args.corpus_sha256,"counters":dict(counters),"samples":samples}
    out = Path(args.out); out.parent.mkdir(parents=True, exist_ok=True); out.write_text(json.dumps(payload, indent=2, ensure_ascii=False), encoding="utf-8")


def aggregate(args: argparse.Namespace) -> None:
    files = sorted(Path(args.input_dir).glob("*.json"))
    if len(files) != args.shard_count:
        raise SystemExit(f"expected {args.shard_count} shard files, got {len(files)}")
    rows = sorted((json.loads(p.read_text(encoding="utf-8")) for p in files), key=lambda x:int(x["chunk_start"]))
    cursor=0; totals=Counter(); samples={}
    for row in rows:
        if int(row["chunk_start"]) != cursor: raise SystemExit("coverage gap/overlap")
        cursor=int(row["chunk_end"])
        if int(row["total_chunks"]) != EXPECTED_CHUNKS or row["corpus_sha256"] != EXPECTED_CORPUS_SHA256: raise SystemExit("source mismatch")
        totals.update({k:int(v) for k,v in row["counters"].items()})
        for k,items in row["samples"].items(): samples.setdefault(k,[]); samples[k].extend(items); samples[k]=samples[k][:50]
    if cursor != EXPECTED_CHUNKS or totals["records"] != EXPECTED_RECORDS or totals["event1"] != EXPECTED_EVENT1 or totals["xml_errors"] != 0:
        raise SystemExit(f"coverage mismatch cursor={cursor} records={totals['records']} event1={totals['event1']} errors={totals['xml_errors']}")
    result={
        "schema":"breachscope.p2_11j_networkprovider_benign_probe.v1",
        "corpus_sha256":EXPECTED_CORPUS_SHA256,
        "scope":{"sysmon_records":totals["records"],"sysmon_chunks":EXPECTED_CHUNKS,"sysmon_event1":totals["event1"],"parse_errors":totals["xml_errors"]},
        "candidate_counts":{k:totals[k] for k in ("networkprovider_any","providerorder_reference","providerorder_setitem","service_networkprovider_reference","providerpath_reference","providerpath_newitem","combined_candidate")},
        "samples":samples,
        "claim_boundary":{"production_false_positive_rate":"NOT_CLAIMED","fresh_full_rulepack_fpr":"NOT_CLAIMED","note":"Counts apply only to the pinned public benign-by-source-intent Sysmon corpus and the exact NetworkProvider command-line candidate predicates."}}
    out=Path(args.out); out.parent.mkdir(parents=True, exist_ok=True); out.write_text(json.dumps(result, indent=2, ensure_ascii=False), encoding="utf-8"); print(json.dumps(result, ensure_ascii=False))


def parser():
    p=argparse.ArgumentParser(); sub=p.add_subparsers(dest="mode",required=True)
    s=sub.add_parser("shard"); s.add_argument("--shard-index",type=int,required=True); s.add_argument("--shard-count",type=int,default=16); s.add_argument("--total-chunks",type=int,default=EXPECTED_CHUNKS); s.add_argument("--evtx",required=True); s.add_argument("--corpus-sha256",default=EXPECTED_CORPUS_SHA256); s.add_argument("--out",required=True)
    a=sub.add_parser("aggregate"); a.add_argument("--input-dir",required=True); a.add_argument("--shard-count",type=int,default=16); a.add_argument("--out",required=True)
    return p

if __name__ == "__main__":
    args=parser().parse_args(); scan_shard(args) if args.mode=="shard" else aggregate(args)
