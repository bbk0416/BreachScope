# Detection Evaluation

BreachScope includes a **curated synthetic regression corpus** for the native
detection engine.

## What the gate measures

The evaluator combines:

- the 10 existing attack-scenario JSONL samples under `samples/scenarios/`
  (48 events total), treated as malicious regression events;
- `samples/scenarios/benign_windows_processes.jsonl`, a small synthetic
  benign Windows process corpus;
- the native rulepack loaded from `rules/`.

At event level:

- **TP**: an attack-scenario event generates at least one native Finding.
- **FN**: an attack-scenario event generates no native Finding.
- **FP**: a benign corpus event generates at least one native Finding.
- **TN**: a benign corpus event generates no native Finding.

The regression gate requires:

- precision >= 0.95
- recall >= 0.90
- at least 48 malicious events
- at least 24 benign events

The evaluator also reports per-scenario ATT&CK technique coverage using the
existing `sample_expected_techniques` metadata. Technique coverage is
diagnostic in P1-04 and is **not** a gate because those fields describe the
synthetic scenario and are not a manually adjudicated event-by-event ATT&CK
ground truth.

## What this does NOT prove

These numbers are **not production-world precision or recall**. The corpus is
small and synthetic. It does not represent an enterprise baseline, real user
behavior, real EVTX diversity, or a statistically valid malware/benign sample
population.

This gate exists to detect regressions in a repeatable local corpus. Real EVTX
corpora, organization-specific benign baselines, and independently adjudicated
TP/FP/FN datasets are separate future validation work.

## Run

```cmd
python scripts\evaluate_detection_corpus.py
```

Machine-readable output:

```cmd
python scripts\evaluate_detection_corpus.py --json
```
