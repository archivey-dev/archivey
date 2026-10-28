# diagnostics — salvage step 1 delta

## ADDED Requirements

### Requirement: Report each stretch of damage a walk resumed past

When a member walk finds a damaged header and resumes past it on a position the
format's own checks confirm (`format-rar`), the reader SHALL emit
`ARCHIVE_DAMAGE_SKIPPED` once for each damaged header, at the point the walk resumes,
with this context:

| Code | Variant and required fields |
| --- | --- |
| `ARCHIVE_DAMAGE_SKIPPED` | `DamageSkippedContext`: `kind="damage_skipped"`, `archive_name`, `format`, `volume` (0-based index in a multi-volume set; `None` for a single file), `damaged_at` (offset of the damaged header in its volume), `resumed_at` (offset of the header the walk resumed from), `what` ∈ `{"member_header","service_header","header"}` (read from the damaged type byte, so a hint) |

The code SHALL be in `DiagnosticCodeStr` and SHALL NOT be in `ARCHIVE_INTEGRITY_CODES`:
the pass that emits it always ends in `CorruptionError`, so the default never lets this
damage pass without an error, and `STRICT` SHALL list the same members and raise the
same error as the default. A caller who wants to stop at the first damage names the code
in `DiagnosticPolicy(raise_on=...)`. The default delivery SHALL be a warning.

The diagnostic does not replace the error: the terminal `CorruptionError` still names
the first damaged header. The code is format-neutral, for every walk that later resumes
past damage the same way.

#### Scenario: damage skipped

| Case | Expected |
| --- | --- |
| RAR with one damaged, confirmed FILE header, default policy | One `ARCHIVE_DAMAGE_SKIPPED` with `what="member_header"`; the later members listed; `CorruptionError` at the end |
| The same under `DiagnosticPolicy.STRICT` | The same members, the same diagnostic and the same `CorruptionError` |
| The same with `raise_on={"archive_damage_skipped"}` | `DiagnosticRaisedError` at the damaged header; the members before it listed |
| A damaged header the walk cannot resume past | No `ARCHIVE_DAMAGE_SKIPPED`; `CorruptionError` as before |
