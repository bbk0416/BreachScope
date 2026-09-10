# P2-11D Local Account Creation Calibration

P2-11D follows the P2-11C miss taxonomy. It evaluates the highest-priority
`T1136.001` gap without changing the historical P2-11B result.

## Why generic Security 4720 was rejected

The pinned Nextron benign-by-source-intent corpus contains three exact
`Microsoft-Windows-Security-Auditing` Event 4720 records. All three were
created by `S-1-5-18` (`SYSTEM`).

Measured benign probe:

- corpus: `NextronSystems/evtx-baseline` `v0.8.4` `win10-client.tgz`
- archive SHA-256: `d48f1b328d48db6c6dfaa9b6e232dbb454d93e833c6e1248efc0faf690b6808e`
- EVTX files: 352
- non-Sysmon EVTX files: 351
- non-Sysmon events: 34,423
- parse errors: 0
- Security 4720 events: 3
- generic 4720 benign matches: 3

Therefore a bare `4720 -> T1136.001` rule was not adopted.

## Attack-side comparison

The pinned Atomic-EVTX source is
`arniki/atomic-evtx@8de5fa8f158b4d72d1e3c6f07053162c90ee6238`.

For `T1136.001-4` and `T1136.001-5`:

- parsed Security events: 26
- parse errors: 0
- Security 4720 events: 2
- both creators used a non-SYSTEM user SID ending in `-1006`
- both `TargetDomainName` values matched the event host name
- no Atomic-specific account name is used by the candidate rule

## Adopted predicate

`R-LOCAL-ACCOUNT-4720-NONSYSTEM` requires all of:

1. provider is `Microsoft-Windows-Security-Auditing`
2. Event ID is `4720`
3. `SubjectUserSid` is not `S-1-5-18`
4. `TargetDomainName` equals the event host name

Host comparison is case-insensitive and accepts a short host name when the
event host is an FQDN. Missing compared fields fail closed.

The exact candidate produced 0 observed matches among the three Security 4720
events in the pinned benign corpus and 2/2 matches in the two Atomic
calibration scenarios.

## Evidence

Benign probe:

- workflow run: `34432322245`
- artifact ID: `10134963918`
- artifact SHA-256: `270416fcf136564d489eec59ef3eb3da99c45461b15f891318f8668953d25a08`

Attack SID probe:

- workflow run: `34432731759`
- artifact ID: `10135070305`
- artifact SHA-256: `5de4882e4b1913c7761409edfe1d114f0b0541399a30fd73a772ce54a57197ba`

Permanent machine-readable evidence is in
`external_baseline/p2_11d_local_account_calibration.json`.

## Claim boundary

This is external calibration against already-known public datasets.

It is **not** a final blind holdout. Zero observed benign candidate matches is
not production false-positive rate, not current rulepack false-positive rate,
and not a claim of event-level precision or recall. The historical P2-11B
score remains an immutable historical measurement.
