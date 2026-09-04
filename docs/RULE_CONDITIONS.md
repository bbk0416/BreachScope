# Structured native rule conditions

BreachScope historically carried `Rule.field`, but the analyzer candidate path
was centered on its legacy text candidates. P2-05E makes the declared primary
`field` an explicit candidate while preserving the historical text candidates.

Legacy native rules remain valid:

```yaml
field: command_line
operator: contains
pattern: wevtutil cl
```

`fields` remains a legacy schema/loader field and is not redefined here.

For independent constraints on additional event fields, native rules may add
`all_of`. The primary rule matcher must match and every `all_of` condition must
also match.

```yaml
field: event_id
operator: equals
pattern: "104"
all_of:
  - field: source
    operator: equals
    pattern: Microsoft-Windows-Eventlog
```

Each condition has its own `field`, `operator`, and `pattern` and reuses the
existing matcher operators: `regex`, `contains`, `startswith`, `endswith`, and
`equals`.

## T1070.001 calibration boundary

The public P2-05D T1070.001 EVTX first produced a scenario MISS. It showed that
the existing `R-EVENTLOG-Clear` command-line rule covered execution commands but
not the resulting Windows audit events.

`R-EVENTLOG-Clear-Audit-104` and `R-EVENTLOG-Clear-Audit-1102` were added after
observing that calibration corpus. They require both the matching event ID and
`source == Microsoft-Windows-Eventlog`.

A later HIT on the same EVTX is therefore calibrated/tuned evidence only. It is
not blind/generalization evidence, event-level precision/recall evidence, or
production detection-quality proof.


## Finding dedupe for nested Windows event identity

Finding dedupe preserves the historical generic event key and conditionally
appends recursively discovered Windows `Channel + EventRecordID`. Exact
duplicate Windows records remain deduplicated; distinct records and
channel-scoped record IDs remain distinct. This is finding accounting only and
does not create blind or production-quality claims.
