# P2-14E Canonical One-Pass Blind Scoring Result

Status: `CANONICAL_ONE_PASS_SCORING_COMPLETED`

This document seals the first successful canonical P2-14E run. It records the result without changing the frozen detector, rules, corpus, threshold, or denominator. The successful canonical scoring run MUST NOT be rerun for result improvement.

## Frozen identities

- BreachScope main/control commit used to prepare the run: `11d2124df63374b2657ab9eb2034ff2903f5e988`
- Frozen detector commit: `13eb8f6ac93cf29817ca3ed885e8dc18b8fbb2fb`
- Frozen rule count: `66`
- Rule file count: `4`
- Rules tree SHA256: `9f823a189530528a47b11c5519b02dc9b97473b8c0f6a8e0c13e1ed8d04b5e92`
- Corpus repository: `sbousseaden/EVTX-ATTACK-SAMPLES`
- Corpus source commit: `4ceed2f4706daf601c212a8f91c113dd85349a2c`
- Archive size: `6053609` bytes
- Archive SHA256: `99e0ca3dae2f7582d9757dfe41b4f1fb149b197fe3bb751613760087f2d68594`
- EVTX path manifest SHA256: `33ace64e0154e14698c462ae185c60acee54a3ee88023d0cb792d86cf76dcb5a`

## Canonical result

- EVTX files: `278`
- Total records: `37364`
- Parsed records: `37364`
- Parse errors: `0`
- Findings: `152`
- Unique flagged events: `134`
- Rules with at least one finding: `37`
- Canonical deterministic payload SHA256: `086f3cc0d48cde4a1eb525eff7dd18a6c7cba4797639282f1804c766b971f3ef`
- Preserved JSON file SHA256: `7374dd7fc92137091e9b7421217a0bf8cdbd92f17f7804b2bb77b063bf16deae`
- Preserved JSON size: `1343351` bytes

The canonical container exited with code `0`. Its recorded runtime was approximately 249 seconds in a Linux Docker environment using Python 3.11.16 and the frozen hash-pinned dependency lock.

## Claim boundary

Event-level ground truth is `NOT_AVAILABLE`. Therefore the result does **not** establish production accuracy, precision, recall, detection rate, or false-positive rate. In particular, `134 / 37364` is a flagged-event fraction and MUST NOT be represented as a false-positive rate.

Corpus file names, directory names, and membership in an attack-sample repository are not event-level labels and MUST NOT be substituted for ground truth.

## One-pass boundary

Two earlier Windows-native attempts terminated before the detector call: one during dependency preflight and one during EVTX parsing after Windows Defender quarantined an intermediate analysis file. They produced no canonical scoring result. The Linux Docker run recorded above is the first successful canonical one-pass scoring completion.

Do not rerun the successful canonical scoring for tuning, threshold selection, denominator changes, rule changes, or result improvement. Any later engineering work must treat this result as sealed evidence and must be clearly separated from this final blind evaluation.