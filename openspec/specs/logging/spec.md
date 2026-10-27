# Logging

## Purpose

Standard-library logging projection for Archivey events. The library emits through
the `archivey` hierarchy and never configures output policy.

## Related specs

| Spec | Relationship |
| --- | --- |
| `diagnostics` | Diagnostic log records are ordered projections of diagnostics |
| `format-detection` | Detection conflict advisory events |
| `archive-reading` | Reader/stream diagnostic surfaces that may also log |
| `safe-extraction` | Extraction outcomes and filter decisions |
| `reader-concurrency` | Handlers run without Archivey locks |

## Requirements

### Requirement: Logging under the archivey logger hierarchy

The system SHALL emit all log messages via `logging.getLogger("archivey")` and
children. It MUST NOT configure handlers, levels, filters, or formatters.

The loggers the library uses include, but are not limited to, the following. The
table is illustrative: a logger missing from it is not a contract violation.

| Logger | Events |
| --- | --- |
| `archivey.detection` | Format detection events |
| `archivey.normalization` | Path normalization changes, including warnings when `name` differs from `raw_name` |
| `archivey.extraction` | Extraction events and filter decisions |
| `archivey.diagnostics` | Default logger for a diagnostic's log record. An emit site that names a subsystem logger (`archivey.streams`, `archivey.integrity`, …) logs the record there instead, and most do |
| `archivey.streams` | Stream-layer events: decompressor and member-stream diagnostics, and how a source's seekability was judged |
| `archivey.integrity` | Digest verification, including an expected digest that cannot be checked |
| `archivey.backends` | Backend-specific messages, and the once-per-reader INFO record about re-decoding a solid block. There is one logger for all backends, not one per backend |

#### Scenario: logger-hierarchy matrix

| Case | Expected |
| --- | --- |
| Application configures no handlers on `archivey` or ancestors | No output by default; library installs no handler |
| Magic bytes conflict with extension | `logging.WARNING` on `archivey.detection` |
| Member-name normalization changes logical meaning relative to `raw_name` | Warning on `archivey.normalization` |
| An `open()` or `read()` that decodes again bytes an earlier one on the same reader decoded, because each open decodes its member's solid block from the start (a 7z folder holding more than one member, a solid RAR read through `unrar`, or one solid stream of it read through `unar`); a member's own bytes do not count when the same member is read again | One `logging.INFO` record on `archivey.backends` per reader, giving the bytes decoded again and naming `stream_members()`; not a diagnostic, no `warnings.warn`. A compressed TAR keeps one decoder position across opens, so reading its members in archive order logs nothing, and its backward seeks report `STREAM_REWIND_REDECOMPRESSES` |

### Requirement: Warning logs are ordered projections of diagnostics

Every WARNING advisory SHALL originate as a `Diagnostic`; logging MUST NOT be a
second source of truth. For `COLLECT` and `RAISE`, the WARNING SHALL emit after
counts/retention update and before callback/escalation. For `IGNORE`, no WARNING
record SHALL emit. The codes in `archivey.diagnostics._INFO_LOG_CODES`
(`STREAM_REWIND_REDECOMPRESSES` only) SHALL log at INFO instead of WARNING, in the same
order: they report the caller's access pattern, not the archive. An INFO record is
below the default level of `logging.basicConfig()` and of the CLI without `-v`, so such
a code reaches a caller there only through `reader.diagnostics`, `on_diagnostic` or a
handler set to INFO.

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
| Diagnostic resolves to `IGNORE` | Exact count increments; no log record |
| Application logging handler runs | No Archivey collector/reader/stream/backend/registry lock is held |
| Logging handler raises | Handler exception propagates; callback/escalation for the occurrence do not run |
