# logging — remote-source advisory at INFO

## MODIFIED Requirements

### Requirement: Warning logs are ordered projections of diagnostics

Every WARNING advisory SHALL originate as a `Diagnostic`; logging MUST NOT be a
second source of truth. For `COLLECT` and `RAISE`, the WARNING SHALL emit after
counts/retention update and before callback/escalation. For `IGNORE`, no WARNING
record SHALL emit. The codes in `archivey.diagnostics._INFO_LOG_CODES`
(`STREAM_REWIND_REDECOMPRESSES`, `MEMBER_NAME_DUPLICATE`,
`MEMBER_READERS_DISAGREE` and `SOURCE_CHANGE_UNDETECTABLE`) SHALL log at INFO instead
of WARNING, at the same point in the emit order: the first reports the caller's access
pattern, not the archive, the next two report shapes of ordinary archives that only a
caller comparing readers asks for, and the last is recorded at every open of a remote
archive whose store cannot pin a version (`fsspec-integration`). An INFO record is below the default level of `logging.basicConfig()` and of the
CLI without `-v`, so such a code reaches a caller there only through
`reader.diagnostics`, `on_diagnostic` or a handler set to INFO.

The record SHALL use the event's named `archivey.*` logger and expose
`diagnostic_code` plus `diagnostic_occurrence_id` in `LogRecord.extra`. Human text
is not a byte-for-byte compatibility contract.

The system SHALL hold no diagnostic collector, reader, stream, backend, or registry
lock while invoking application logging handlers. If a handler raises, normal
Python logging semantics apply: the exception propagates and later
callback/escalation steps for that occurrence do not run.

#### Scenario: diagnostic-log matrix

| Case | Expected |
| --- | --- |
| Diagnostic resolves to default `COLLECT` | Counts/retention update, then one WARNING with `diagnostic_code` and `diagnostic_occurrence_id` |
| `STREAM_REWIND_REDECOMPRESSES` resolves to `COLLECT` | Counts/retention update, then one INFO record |
| `SOURCE_CHANGE_UNDETECTABLE` resolves to `COLLECT` | Counts/retention update, then one INFO record |
| Diagnostic resolves to `IGNORE` | Exact count increments; no log record |
| Application logging handler runs | No Archivey collector/reader/stream/backend/registry lock is held |
| Logging handler raises | Handler exception propagates; callback/escalation for the occurrence do not run |
