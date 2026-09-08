# P2-10A measured remediation result

- measurement commit: `b198604cf24f3537938f963b525aebdb0670d584`
- old rules SHA-256: `543b4e02ebb48d5e33eeb4405a6d489487a05d07ffebda4ba31206a059dae3ce`
- new rules SHA-256: `8ade507d0abf4a0495b44cde4268245dab8c5f9d58d2eb5b47ebee8b7a5de185`
- changed rule: `R-SCHTASK-4698`
- condition: Security-Auditing Event ID 4698
- ATT&CK: `T1053.005`

Measured on the same pinned P2-09C public attack corpus:

- before: **2 HIT / 8 MISS / 10**
- after: **3 HIT / 7 MISS / 10**
- `exec-scheduled-task`: **MISS -> HIT**
- findings: **4** after the change

Incremental benign check on the pinned P2-09D corpus:

- all 351 non-Sysmon EVTX scanned
- 34,423 non-Sysmon events
- exact new predicate matches: **0**
- Sysmon provider is outside the new rule's required `Microsoft-Windows-Security-Auditing` provider

This is not a fresh full FP/TN/FPR rerun for the new rulepack. Production detection rate and production FPR are not claimed.

Measurement execution:

- GitHub Actions run: `34216569909`
- artifact ID: `10052084903`
- artifact SHA-256: `bb00edad756b75a6b00a6a1d8bcfb59fe266e738f606339aca2e7a027277fa5d`
