# BRAWL canonical holdout post-hoc miss diagnosis

Status: **POSTHOC_ONLY — canonical result immutable**

This document explains what can and cannot be concluded from the sealed MITRE BRAWL result. It does not modify the canonical result, scoring contract, rulepack, or claim boundaries.

## Sealed result

- analysis: `brawl-independent-attack-step-technique-holdout-v1`
- preregistered product commit: `de4d7da521f3be43720cf5db419baa54d76dd4c3`
- rules SHA-256: `1b27fca60c7b87566a73c20697c1a074ab1806ac25247c5a1e07ee07f65a4df7`
- BRAWL source commit: `7ec51fac8fc05ea01da210f604b821ef52818173`
- host events normalized: **54,236**
- detector findings: **44**
- BSF steps: **96**
- evaluable step × technique pairs: **133**
- HIT / MISS / ERROR: **0 / 133 / 0**
- primary metric: `brawl_attack_step_technique_hit_fraction = 0.0`

This metric is **not event-level recall**. Production accuracy, recall, precision, and FPR remain `NOT_CLAIMED`.

## What is already ruled out

The canonical scorer reported **0 ERROR** and all **96 steps / 133 pairs were evaluable**.

Therefore the 0/133 result is not explained by:

- missing BSF step IDs,
- missing ATT&CK labels in selected steps,
- missing referenced-event hosts,
- malformed BSF time intervals,
- unmapped ATT&CK identifiers in the frozen crosswalk.

BRAWL upstream also states that endpoint/event/bot timestamps should generally be within a few milliseconds of each other. This makes a corpus-wide gross clock-offset explanation less likely, although exact telemetry-to-BSF time alignment still requires post-hoc measurement.

## Current-rule coverage by BRAWL technique

The table below is derived from the sealed result's 133 pair rows and the current `rules/` tree.

| BRAWL label → current ATT&CK | Pairs | Current matching rule IDs | Post-hoc classification |
|---|---:|---|---|
| T1003 → T1003 | 16 | R-LSASS-Dump, R-WDIGEST-Enable, R-SAM-SYSTEM-Save, R-NTDSUTIL-Dump, R-LSASS-ACCESS-1010, R-NETWORK-PROVIDER-CREDENTIAL-CAPTURE-SETUP | Rule coverage exists but is narrow; exact BRAWL credential-dumping command/event shape is not yet extracted. |
| T1060 → T1547.001 | 15 | R-REG-RunKey, R-RUNKEY-UNNAMED-13 | Narrow. One rule requires a specific Run-key command; the other depends on registry telemetry. BRAWL's documented Sysmon object/action list does not include registry events. |
| T1018 → T1018 | 1 | R-NSLOOKUP-Discovery | Very narrow: current coverage is DNS/nslookup-oriented, while the upstream label is broad Remote System Discovery. |
| T1086 → T1059.001 | 19 | R-ENC, R-PS-Bypass, R-PS-DownloadString, R-PS-InvokeExpression | Intentional narrow coverage. Generic PowerShell execution is not enough; current rules require encoded/bypass/download/IEX-like shapes. |
| T1016 → T1016 | 1 | **none** | **Confirmed rule coverage gap.** |
| T1069 → T1069 | 18 | **none** | **Confirmed rule coverage gap.** |
| T1087 → T1087 | 18 | R-DISCOVERY-Account-System, R-ADFind-Discovery, R-DOMAIN-ADMINS-4661, R-DOMAIN-ACCOUNT-DISCOVERY-CMD | Coverage exists but only selected local/domain account command/event shapes are recognized. |
| T1077 → T1021.002 | 15 | **none** | **Confirmed rule coverage gap.** |
| T1105 → T1105 | 15 | R-DL, R-CERTUTIL-Download | Semantic mismatch risk: current rules cover web download/certutil, whereas BRAWL labels the activity Remote File Copy. |
| T1047 → T1047 | 15 | R-WMI-Create, R-WMI-XSL-Remote, R-WMI-WMIPRVSE-CHILD-4688, R-WMI-QUERY-GET | Coverage exists but only selected WMIC/query/provider-child shapes. Upstream Sysmon configuration also excludes some WmiPrvSE CreateRemoteThread telemetry. |

### Confirmed structural gap

Pairs with **no current rule capable of satisfying the expected technique dimension**:

- T1016: 1
- T1069: 18
- T1021.002: 15

Total: **34 / 133 pairs (25.6%)**.

These 34 pairs were structurally unable to become HIT under the frozen current rulepack.

The remaining **99 / 133 pairs** had at least one rule mapped to the expected technique or a satisfying sub-technique. Their MISS status cannot be assigned to a single cause from the sealed result alone.

## Why "rule exists" does not mean the pair should hit

The BRAWL BSF labels describe the attack technique at a relatively broad semantic level. BreachScope rules intentionally detect narrower observable shapes.

Examples:

- BRAWL `PowerShell` does not imply encoded command, execution-policy bypass, DownloadString, or Invoke-Expression.
- BRAWL `Remote File Copy` does not imply web download or certutil.
- BRAWL `Remote System Discovery` does not imply nslookup.
- BRAWL `Credential Dumping` does not imply one of BreachScope's specific LSASS/SAM/NTDS/WDigest command or event patterns.
- BRAWL `Windows Management Instrumentation` does not imply one of the specific WMIC/XSL/query/WmiPrvSE-child patterns currently covered.

Therefore broadening rules merely to make the BRAWL score increase would be post-hoc overfitting.

## Important unresolved question: the 44 findings

The canonical evaluator recorded that the corpus produced **44 BreachScope findings**, but the sealed result only stores finding details when a finding satisfies a pair. Because every pair was MISS, the result does **not** preserve the global distribution of those 44 findings by:

- rule ID,
- ATT&CK technique,
- host,
- timestamp,
- nearest BSF step/event window.

That missing diagnostic information is the next thing to measure.

A post-hoc diagnostic may rerun detection on the already-open corpus, but it must:

1. use a different analysis identifier,
2. state clearly that it is post-hoc,
3. never replace or recompute the sealed 0/133 result,
4. report finding distributions and distance-to-BSF-window only,
5. not change rules before the diagnosis is recorded.

## Next diagnostic questions

For each of the 133 pairs, measure these dimensions independently:

1. **Technique coverage** — does any finding anywhere in the corpus have the expected technique?
2. **Host + technique** — does an expected-technique finding exist on the referenced BSF host, regardless of time?
3. **Host + time** — is there any finding on the correct host inside the referenced BSF event window, regardless of technique?
4. **Technique + time** — is there an expected-technique finding in the time window on a different host?
5. **Nearest expected-technique finding** — if present, how far in time is the nearest same-host finding from the BSF window?
6. **Raw telemetry availability** — does a process/event matching the BSF-described action exist even when no BreachScope rule fires?

This separates:

- missing rule coverage,
- overly narrow rule pattern,
- missing/filtered telemetry,
- adapter normalization gap,
- host mismatch,
- time alignment mismatch.

## Remediation boundary

Do **not** modify current rules and then rerun `brawl-independent-attack-step-technique-holdout-v1`.

Any remediation derived from this result is post-hoc. Candidate rule changes must be developed against independent evidence/synthetic unit tests and validated under a **new analysis ID** using fresh or separately frozen evidence.

The sealed BRAWL result remains historical evidence even if later rulepacks improve.
