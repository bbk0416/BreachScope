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
| T1003 → T1003 | 16 | R-LSASS-Dump, R-WDIGEST-Enable, R-SAM-SYSTEM-Save, R-NTDSUTIL-Dump, R-LSASS-ACCESS-1010, R-NETWORK-PROVIDER-CREDENTIAL-CAPTURE-SETUP | BSF records `powershell -command -` plus a process/open action against `lsass.exe`; current endpoint telemetry/rules do not expose that oracle-level process-open meaning as a matching T1003 finding. |
| T1060 → T1547.001 | 15 | R-REG-RunKey, R-RUNKEY-UNNAMED-13 | BSF/telemetry show `reg add HKLM\\...\\Run`; the command rule targets HKCU syntax and the registry-event rule depends on registry telemetry not emitted by the documented BRAWL Sysmon configuration. |
| T1018 → T1018 | 1 | R-NSLOOKUP-Discovery | BSF records `powershell -command -`; current coverage is nslookup-oriented, so the semantic script body is not observable in the command line used by the rule. |
| T1086 → T1059.001 | 19 | R-ENC, R-PS-Bypass, R-PS-DownloadString, R-PS-InvokeExpression | BSF records `powershell -command -`; current PowerShell rules intentionally require encoded/bypass/download/IEX-like shapes rather than generic PowerShell. |
| T1016 → T1016 | 1 | **none** | **Confirmed rule coverage gap.** |
| T1069 → T1069 | 18 | **none** | **Confirmed rule coverage gap.** |
| T1087 → T1087 | 18 | R-DISCOVERY-Account-System, R-ADFind-Discovery, R-DOMAIN-ADMINS-4661, R-DOMAIN-ACCOUNT-DISCOVERY-CMD | BSF records `powershell -command -`; current rules require specific account-discovery commands/events, while the semantic script body is not present in the command line. |
| T1077 → T1021.002 | 15 | **none** | **Confirmed rule coverage gap.** |
| T1105 → T1105 | 15 | R-DL, R-CERTUTIL-Download | BSF records `cmd /c copy ... \\\\host\\C# BRAWL canonical holdout post-hoc miss diagnosis

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
| T1003 → T1003 | 16 | R-LSASS-Dump, R-WDIGEST-Enable, R-SAM-SYSTEM-Save, R-NTDSUTIL-Dump, R-LSASS-ACCESS-1010, R-NETWORK-PROVIDER-CREDENTIAL-CAPTURE-SETUP | BSF records `powershell -command -` plus a process/open action against `lsass.exe`; current endpoint telemetry/rules do not expose that oracle-level process-open meaning as a matching T1003 finding. |
| T1060 → T1547.001 | 15 | R-REG-RunKey, R-RUNKEY-UNNAMED-13 | BSF/telemetry show `reg add HKLM\\...\\Run`; the command rule targets HKCU syntax and the registry-event rule depends on registry telemetry not emitted by the documented BRAWL Sysmon configuration. |
| T1018 → T1018 | 1 | R-NSLOOKUP-Discovery | BSF records `powershell -command -`; current coverage is nslookup-oriented, so the semantic script body is not observable in the command line used by the rule. |
| T1086 → T1059.001 | 19 | R-ENC, R-PS-Bypass, R-PS-DownloadString, R-PS-InvokeExpression | BSF records `powershell -command -`; current PowerShell rules intentionally require encoded/bypass/download/IEX-like shapes rather than generic PowerShell. |
| T1016 → T1016 | 1 | **none** | **Confirmed rule coverage gap.** |
| T1069 → T1069 | 18 | **none** | **Confirmed rule coverage gap.** |
| T1087 → T1087 | 18 | R-DISCOVERY-Account-System, R-ADFind-Discovery, R-DOMAIN-ADMINS-4661, R-DOMAIN-ACCOUNT-DISCOVERY-CMD | BSF records `powershell -command -`; current rules require specific account-discovery commands/events, while the semantic script body is not present in the command line. |
| T1077 → T1021.002 | 15 | **none** | **Confirmed rule coverage gap.** |
; current T1105 rules cover web download/certutil. Twelve pairs had normalized telemetry in-window; three had none. |
| T1047 → T1047 | 15 | R-WMI-Create, R-WMI-XSL-Remote, R-WMI-WMIPRVSE-CHILD-4688, R-WMI-QUERY-GET | BSF records `wmic /node:... /user:... /password:<redacted> process call create ...`; current simple create rule expects `wmic process call create` contiguously and the other WMI rules cover different shapes. |

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

## Measured post-hoc diagnosis

The separate analysis `brawl-posthoc-miss-diagnosis-v1` reran detection on the already-open, hash-verified BRAWL archive without changing rules and without rerunning the canonical scorer.

Result artifact:

- `external_baseline/results/brawl_posthoc_b306aa7/result.json`
- SHA-256: `a2772d458db5ba783afe6f0af2d181ee7f409d1c7af069af65d668e6229e8500`
- summary: `external_baseline/brawl_posthoc_miss_diagnosis_summary.yaml`

### The 44 findings

All 44 findings were outside the canonical expected-technique set:

- `R-MSBUILD-InlineTask` / `T1127.001`: **29**
- `R-NET-View-Share` / `T1135`: **15**

Therefore none of the canonical BRAWL pairs had an expected-technique finding anywhere in the corpus, not merely outside the host/time window.

### Pair-level diagnosis

All 133 canonical MISS pairs were classified:

- **96** — `TELEMETRY_PRESENT_NO_EXPECTED_TECHNIQUE_FINDING`
- **34** — `NO_CURRENT_RULE_COVERAGE`
- **3** — `NO_NORMALIZED_TELEMETRY_IN_BSF_WINDOW`

The 34 no-rule pairs are exactly:

- T1016: **1**
- T1069: **18**
- T1021.002: **15**

The 96 pairs with telemetry but no expected-technique finding are:

- T1003: **16**
- T1018: **1**
- T1047: **15**
- T1059.001: **19**
- T1087: **18**
- T1105: **12**
- T1547.001: **15**

The three no-telemetry pairs are all **T1105**.

### Concrete root causes

**T1003 / Credential Dumping**

BSF records a PowerShell process with command line `powershell -command -`, plus a second BSF `process/open` event targeting `C:\\Windows\\System32\\lsass.exe`. That process-open fact is part of the red-bot oracle, but the normalized endpoint telemetry used by BreachScope does not provide a matching current-rule observable for these windows. Treating the BSF oracle itself as detector telemetry would leak ground truth into detection and is not allowed.

**T1016 / System Network Configuration Discovery**

The BSF command is `nbtstat -n`. Current rule coverage for T1016 is absent.

**T1069 / Permission Groups Discovery**

BSF records `powershell -command -`. Current T1069 rule coverage is absent, and the actual PowerShell script body is not preserved in the command line.

**T1087 / Account Discovery**

BSF again records `powershell -command -`. Current T1087 rules require specific visible commands/events such as `whoami /all`, `net user`, ADFind, or specific Security events. The script semantics are not present in the observable command line.

**T1018 / Remote System Discovery**

The BSF command is also `powershell -command -`. The current T1018 coverage is nslookup-oriented, so it does not match this opaque PowerShell form.

**T1059.001 / PowerShell**

All 19 pairs use `powershell -command -` at the BSF level. Current PowerShell rules deliberately require stronger suspicious forms such as encoded commands, bypass flags, DownloadString, or Invoke-Expression. Adding a generic `powershell` rule solely for this corpus would be post-hoc overfitting and would likely increase noise.

**T1547.001 / Registry Run Keys**

BRAWL uses `reg add HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run ...`. The current command rule is specific to HKCU, while the other current rule expects registry-event fields. BRAWL's documented Sysmon configuration does not emit registry object/action telemetry, so this is both a rule-shape and telemetry-source mismatch.

**T1021.002 / SMB/Windows Admin Shares**

The BSF command is `net use \\\\host\\C$ ... /user:...`. There is no current T1021.002 rule. Credentials in the post-hoc artifact are redacted.

**T1105 / Ingress Tool Transfer**

BRAWL performs remote file copy with `cmd /c copy local.exe \\\\host\\C$\\remote.exe`. Current T1105 rules cover web download and certutil, not SMB/admin-share copy. Twelve pairs had normalized telemetry in the frozen window; three had none.

**T1047 / Windows Management Instrumentation**

BRAWL uses `wmic /node:... /user:... /password:<redacted> process call create ...`. Current WMI coverage is narrower: the simple create rule looks for the contiguous phrase `wmic process call create`, while other rules target XSL, query, or WmiPrvSE-child forms. The `/node` and credential arguments between `wmic` and `process call create` prevent the simple pattern from matching.

### What this means

The sealed **0/133** result is real and should remain unchanged, but its causes are mixed:

1. **25.6% of pairs are structurally uncovered** by the current ATT&CK mapping/rule set.
2. Most remaining pairs have telemetry but the current detector looks for a narrower observable than the BRAWL red-bot action.
3. Several BRAWL techniques are executed through `powershell -command -`, where semantic script content is hidden from the command-line evidence BreachScope currently uses.
4. Three remote-copy pairs lack normalized endpoint telemetry in the frozen BSF window.
5. The 44 detector findings are real detections, but they are `T1127.001` and `T1135`, not any expected BRAWL pair technique.

This is a **coverage/observable mismatch diagnosis**, not evidence that production recall is 0%.

## Remediation boundary

Do **not** modify current rules and then rerun `brawl-independent-attack-step-technique-holdout-v1`.

Any remediation derived from this result is post-hoc. Candidate rule changes must be developed against independent evidence/synthetic unit tests and validated under a **new analysis ID** using fresh or separately frozen evidence.

The sealed BRAWL result remains historical evidence even if later rulepacks improve.