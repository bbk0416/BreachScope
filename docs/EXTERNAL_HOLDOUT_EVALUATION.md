# External / Blind Holdout Evaluation

BreachScope's built-in `scripts/evaluate_detection_corpus.py` remains a
**curated synthetic regression gate**. It is useful for preventing known
regressions, but its precision/recall output is not production detection-quality
evidence.

`scripts/evaluate_external_holdout.py` provides a separate protocol for
externally sourced holdout data.

## Evaluation classes

The manifest may declare one of three classes:

- `external_calibration`: public or otherwise non-blind data used to improve
  compatibility, parser behavior, or detection engineering.
- `external_baseline`: externally sourced data used to measure behavior without
  claiming a final blind result.
- `final_blind_holdout`: a final unseen holdout. This class still requires the
  explicit attestations that the corpus is independent of rule authoring and was
  not seen before rule freeze.

If `evaluation_class` is omitted, the evaluator preserves the original P2-05A
behavior and treats the manifest as `final_blind_holdout`.

The tool records these declarations but **does not prove** that they are true.

## Why `ignore` exists

Public attack EVTX and Windows telemetry datasets often contain many contextual
or background events around the actual malicious actions. Treating every event
inside an attack file as malicious would corrupt event-level TP/FP/TN/FN.

Labels are therefore:

- `malicious`: explicitly adjudicated malicious event
- `benign`: explicitly adjudicated benign event
- `ignore`: contextual / unknown / not adjudicated; excluded from event-level
  confusion-matrix denominators

Every event still needs exactly one label. `ignore` is not a shortcut for
missing labels: it is an explicit adjudication state.

Findings on ignored events are retained diagnostically as
`flagged_ignored_events`, but they are not counted as false positives.

## Scenario-level outcomes

A manifest may define `scenarios` independently of event labels. Each scenario
contains:

- `scenario_id`
- one or more `source_files`
- one or more `expected_techniques`

A scenario is a `hit` only when **all expected ATT&CK techniques** are observed
in BreachScope findings across the scenario's source files. Otherwise it is a
`miss`. The result also records matched/missing techniques and technique recall.

Scenario outcomes are independent of event-level malicious/benign/ignore
accounting. This makes public attack datasets useful for external scenario
baselines even when not every contextual event has authoritative event-level
ground truth.

## Protocol

Do not turn the built-in demo corpus into a supposed blind benchmark. Development
fixtures and final holdout evidence have different purposes.

The external protocol is:

1. **Freeze** the exact clean repository commit and rule-tree hash.
2. **Index** external JSONL/EVTX without executing detection rules.
3. Have ground truth prepared separately, ideally by an independent labeler.
4. **Score** only after labels and the corpus are hash-bound.
5. If rules are changed after viewing final holdout outcomes, that round is no
   longer blind and must not be represented as such.

## What the tool enforces

- clean Git work tree at rule freeze and score time
- exact Git commit and rule-tree hash
- SHA-256 for every corpus file
- explicit protocol self-attestations
- stricter independence/unseen attestations for `final_blind_holdout`
- safe corpus-relative paths
- unique event identity keys
- exact label coverage: every scored or ignored event must be labelled once
- optional label-file SHA-256
- event-level TP / FP / TN / FN, precision, recall and false-positive rate on
  `malicious` + `benign` events only
- ignored/context event counts and flagged-ignored diagnostics
- expected-technique accounting on non-ignored event labels
- scenario-level hit/miss and technique recall
- runtime and Python peak-memory measurement
- result claim boundary

## What the tool cannot prove

The evaluator **cannot prove** that:

- a corpus was genuinely independent from rule authoring
- the analyst preparing labels was actually blinded
- ground truth is correct
- the corpus is representative of a real enterprise
- the resulting precision/recall generalizes to production

Those require external evidence and process controls.

## Supported corpus formats

- `.jsonl`: normalized/event dictionaries
- `.evtx`: converted through BreachScope's existing `convert_evtx_dir()` path

Holdout bytes should normally remain **outside the repository**.

## 1. Freeze rules before final scoring

```cmd
python scripts\evaluate_external_holdout.py freeze ^
  --repo . ^
  --rules-dir rules ^
  --out D:\BreachScopeHoldout\rules-freeze.json
```

## 2. Create manifest

Copy `samples/evaluation/external_holdout_manifest.example.yaml` outside the repo
and fill in real provenance, evaluation class, scenario metadata, and SHA-256
values.

## 3. Index without running detection

```cmd
python scripts\evaluate_external_holdout.py index ^
  --manifest D:\BreachScopeHoldout\manifest.yaml ^
  --corpus-root D:\BreachScopeHoldout\corpus ^
  --out D:\BreachScopeHoldout\event-index-to-label.jsonl
```

The index command prints:

```text
Detection rules executed: NO
Findings emitted: NO
```

Label every row separately with `malicious`, `benign`, or `ignore`.

## 4. Bind labels

Compute SHA-256 for the final labels file and optionally put it under
`labels.sha256` in the manifest.

## 5. Score

```cmd
python scripts\evaluate_external_holdout.py score ^
  --repo . ^
  --manifest D:\BreachScopeHoldout\manifest.yaml ^
  --corpus-root D:\BreachScopeHoldout\corpus ^
  --labels D:\BreachScopeHoldout\labels.jsonl ^
  --freeze D:\BreachScopeHoldout\rules-freeze.json ^
  --rules-dir rules ^
  --out D:\BreachScopeHoldout\result.json
```

Optional acceptance gates:

```text
--min-precision
--min-recall
--min-scenario-hit-rate
```

Do not invent a threshold after seeing the first final-blind result and then
pretend it was predetermined.

## Event identity

The holdout accounting key is the SHA-256 of the portable base identity:

- timestamp
- host
- source
- event_id
- user
- command_line

When a record exposes Windows event-log identity metadata, the evaluator also
adds:

- channel
- event_record_id (`EventRecordID`)

The additional fields are conditional so existing generic JSONL events without
Windows record metadata keep the historical base-key behavior. `EventRecordID`
is interpreted together with the channel because Windows event record IDs are
channel-scoped.

If a real corpus still contains two genuinely distinct events with the exact
same available identity fields, the evaluator **fails closed** instead of
silently merging them. The identity contract must not be weakened by falling
back to source-file position merely to make a benchmark pass.
