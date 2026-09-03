# External / Blind Holdout Evaluation

BreachScope's built-in `scripts/evaluate_detection_corpus.py` remains a
**curated synthetic regression gate**. It is useful for preventing known
regressions, but its precision/recall output is not production detection-quality
evidence.

`scripts/evaluate_external_holdout.py` provides a separate protocol for
externally sourced holdout data.

## Why it is separate

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
- safe corpus-relative paths
- unique event identity keys
- exact label coverage: every scored event must be labelled once
- optional label-file SHA-256
- event-level TP / FP / TN / FN, precision, recall and false-positive rate
- expected-technique accounting when labels provide `expected_techniques`
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
and fill in real provenance and SHA-256 values.

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

Label the resulting rows separately. Allowed labels are `malicious` and
`benign`. Every event must have exactly one label before scoring.

## 4. Bind labels

Compute SHA-256 for the final labels file and optionally put it under
`labels.sha256` in the manifest.

## 5. Score once

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

Do not set a precision/recall gate before observing the first true external
baseline unless that threshold was independently predetermined. Optional
`--min-precision` and `--min-recall` exist for later frozen acceptance criteria.

## Event identity limitation

The current holdout accounting key is the SHA-256 of:

- timestamp
- host
- source
- event_id
- user
- command_line

If a real corpus contains two genuinely distinct events with the exact same
identity tuple, the evaluator **fails closed** instead of silently merging them.
That is intentional. The identity contract must then be extended using evidence
available in that corpus (for example record ID) before the benchmark is valid.
