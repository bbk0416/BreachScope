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

The remaining **99 / 133 pairs** had at least one rule mapped to the expected technique or a satisfying sub-technique. The post-hoc diagnostic has now separated them further:

- **96 / 133**: normalized telemetry existed on the referenced host inside the frozen BSF event window, but BreachScope produced **no finding for the expected technique anywhere in the corpus**.
- **3 / 133**: no normalized telemetry existed on the referenced host inside the frozen BSF window. All three were T1105 pairs.
- **0 / 133**: expected-technique finding on the correct host/time.
- **0 / 133**: pair scoring ERROR.

## Post-hoc finding distribution

The 44 canonical-run findings are now fully accounted for:

| Rule | ATT&CK | Findings |
|---|---|---:|
| R-MSBUILD-InlineTask | T1127.001 | 29 |
| R-NET-View-Share | T1135 | 15 |

No finding anywhere in the 54,236 normalized host events carried any of the preregistered expected techniques. Therefore the canonical 0/133 was not caused by correct-technique findings narrowly missing the host/time window.

## Technique-by-technique diagnosis

### T1003 Credential Dumping — 16 pairs

The BSF attack oracle records `powershell -command -` process creation plus a separate `process/open` action targeting `C:\Windows\System32\lsass.exe`.

Current T1003 rules are built around narrower endpoint observables such as `comsvcs.dll, MiniDump`, `sekurlsa::logonpasswords`, `procdump -ma lsass`, or specific SAM/SYSTEM/NTDS/WDigest/process-access telemetry. The BSF process-open oracle is ground-truth metadata; it is not injected into the detector as endpoint telemetry.

**Classification:** observable/rule-shape mismatch, not a scorer failure.

### T1547.001 Registry Run Keys — 15 pairs

BSF commands use `reg add HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run ...`. Current `R-REG-RunKey` matches the HKCU Run path, while `R-RUNKEY-UNNAMED-13` depends on Sysmon Event ID 13 registry SetValue telemetry.

**Classification:** confirmed command-pattern scope mismatch plus missing matching registry telemetry.

### T1018 Remote System Discovery — 1 pair

The BSF command line is `powershell -command -`. Current T1018 coverage is `R-NSLOOKUP-Discovery`; the actual PowerShell script body is not present in the recorded command line.

**Classification:** narrow rule coverage plus lost semantic command content.

### T1059.001 PowerShell — 19 pairs

BSF records generic `powershell -command -`. Current PowerShell rules intentionally require higher-signal shapes such as encoded commands, execution-policy bypass, DownloadString, or Invoke-Expression.

**Classification:** intentional rule narrowness. Broadening to generic PowerShell solely because of this result would be post-hoc overfitting.

### T1016 System Network Configuration Discovery — 1 pair

BSF records `nbtstat -n`. There is no current T1016 rule.

**Classification:** confirmed rule coverage gap.

### T1069 Permission Groups Discovery — 18 pairs

BSF records `powershell -command -`. There is no current T1069 rule, and the discovery script body is not present in the command line.

**Classification:** confirmed rule coverage gap plus limited command observability.

### T1087 Account Discovery — 18 pairs

BSF records `powershell -command -`. Current T1087 rules cover selected local/domain account command and directory-service shapes; the PowerShell script body is not present in the recorded command line.

**Classification:** existing but non-overlapping rule coverage plus limited command observability.

### T1021.002 SMB/Windows Admin Shares — 15 pairs

BSF records `net use \\host\C$ <redacted> /user:domain\user`. There is no current T1021.002 rule.

**Classification:** confirmed rule coverage gap.

### T1105 Ingress Tool Transfer / Remote File Copy mapping — 15 pairs

BSF records SMB copy operations shaped as `cmd /c copy local.exe \\host\C$\remote.exe`. Current T1105 rules detect web transfer or certutil patterns. Twelve pairs had normalized telemetry in the frozen window but no T1105 finding; three had no normalized telemetry in that window.

**Classification:** strong semantic/rule-shape mismatch, plus a telemetry-availability gap in 3/15 pairs.

### T1047 Windows Management Instrumentation — 15 pairs

BSF records `wmic /node:host /user:... /password:<redacted> process call create ...`. Current `R-WMI-Create` searches for the contiguous literal `wmic process call create`; the inserted remote-connection arguments prevent that simple string from matching. Other WMI rules target remote XSL, query `get`, or specific WmiPrvSE-child telemetry.

**Classification:** confirmed rule-pattern mismatch.

## Aggregate post-hoc classification

| Classification | Pairs | Share |
|---|---:|---:|
| No current rule coverage | 34 | 25.6% |
| Telemetry present, no expected-technique finding | 96 | 72.2% |
| No normalized telemetry in frozen BSF window | 3 | 2.3% |
| Canonical HIT | 0 | 0% |
| Canonical ERROR | 0 | 0% |

The post-hoc result is stored separately from the canonical result:

- `external_baseline/results/brawl_posthoc_b306aa7/result.json`
- `external_baseline/brawl_posthoc_miss_diagnosis_summary.yaml`
- analysis ID: `brawl-posthoc-miss-diagnosis-v1`

Credential-like command arguments from the public game are redacted in the stored post-hoc evidence.

## Interpretation

The sealed 0/133 result is real under the preregistered contract. The diagnosis does **not** justify changing it.

It shows a mixture of limitations:

1. **Missing ATT&CK coverage** — 34 pairs have no current matching rule.
2. **Rule-shape mismatch** — several covered techniques use substantially different BRAWL command/event shapes from current narrow patterns.
3. **Observability loss** — several CALDERA actions appear only as `powershell -command -`, hiding the script semantics from command-line rules.
4. **Telemetry availability** — three T1105 pairs had no normalized event on the referenced host inside the frozen BSF window.
5. **No evidence of scorer malfunction** — every pair was evaluable and the post-hoc analysis found no expected-technique finding that should have been a canonical HIT.

This is useful negative evidence. It identifies where the current rulepack and observable set do not generalize to an independent attack execution corpus without pretending that 0/133 is production recall.

## Remediation boundary

Do **not** modify current rules and then rerun `brawl-independent-attack-step-technique-holdout-v1`.

Any remediation derived from this result is post-hoc. Candidate rule changes must be developed against independent evidence/synthetic unit tests and validated under a **new analysis ID** using fresh or separately frozen evidence.

The sealed BRAWL result remains historical evidence even if later rulepacks improve.