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
event host is an FQDN. Missing compared fields fail closed. The field-to-field
comparison operator is available only inside native-rule `all_of`; it is not a
top-level matcher operator.

The exact predicate produced 0 observed matches among the three Security 4720
events in the pinned benign corpus and matched both Atomic calibration target
events.

## Post-implementation 12-scenario calibration

The implementation was frozen at detector commit:

`456b2a8238837026c8249ae1020b16249715bc04`

The same 12 public Atomic-EVTX scenarios previously scored in P2-11B were then
re-run as `external_calibration`, not as a new baseline.

Measured result:

- P2-11B historical result: 0/12 scenario hits
- P2-11D external calibration: 2/12 scenario hits
- newly hit scenarios: `T1136.001-4`, `T1136.001-5`
- remaining misses: 10/12
- events: 902
- rules: 61
- rule files: 4
- findings: 84
- flagged events: 80
- rules tree SHA-256: `b42725734f70cfc87ccd0122e6ab90da2169d7599b2abaaf22c27050efa0c4d2`

The other ten scenario outcomes remained MISS. This run therefore observed the
intended two scenario-level changes without turning any of the other ten
expected techniques into HITs.

Calibration execution:

- workflow run: `34434077438`
- workflow control head: `60b181021422bbff98998d592d1b13c60d74cb28`
- artifact ID: `10135538509`
- artifact SHA-256: `9f4a28b595c98afbd4f973ade5742654d96eed620f3133617234e5d9db533c11`
- aggregate result SHA-256: `f059c386a85d028938adafe2bc9519a732261d324711654b590e65544dbb1920`

The permanent measurement record is
`external_baseline/results/p2_11d_456b2a82/measurement.yaml`.

## Earlier probe evidence

Benign probe:

- workflow run: `34432322245`
- artifact ID: `10134963918`
- artifact SHA-256: `270416fcf136564d489eec59ef3eb3da99c45461b15f891318f8668953d25a08`

Attack SID probe:

- workflow run: `34432731759`
- artifact ID: `10135070305`
- artifact SHA-256: `5de4882e4b1913c7761409edfe1d114f0b0541399a30fd73a772ce54a57197ba`

Machine-readable probe/evaluation summary is in
`external_baseline/p2_11d_local_account_calibration.json`.

## Claim boundary

This is external calibration against already-known public datasets.

It is **not** a final blind holdout and **not** a fresh external baseline. Zero
observed benign candidate matches is not production false-positive rate and is
not the current rulepack false-positive rate. All Atomic events remained
`ignore` at event level, so event-level precision, recall, and false-positive
rate are not claimed. The historical P2-11B 0/12 result remains unchanged.
