# diagnostics — salvage step 2 (TAR) delta

## MODIFIED Requirements

### Requirement: Report every read of a member listed from a damaged header

When a member walk lists a member from a header that failed its own check and resumes
past it on a position the format's checks confirm (`format-rar`,
`format-tar`), every read, open,
stream or extraction of that member SHALL emit `MEMBER_HEADER_DAMAGED` before any of its
bytes are returned. Listing the member SHALL NOT emit it, so that a policy that raises
on the code refuses that member's read and no other: the listing, the other members and
the `CorruptionError` that ends the pass are unchanged. Its default delivery SHALL be a
warning. The message SHALL say which fields nothing checked (the name, type, mode, times
and flags) and what still checks the member: its own digest where the format has one
(RAR), or only the header its size pointed at where it has none (TAR, `format-tar`). The code is
format-neutral, for every walk that lists a member from a damaged header the same way.

#### Scenario: member header damaged

| Case | Expected |
| --- | --- |
| RAR with one damaged, confirmed FILE header, default policy, `members()` | Every member listed, the damaged one included; no `MEMBER_HEADER_DAMAGED` yet; `CorruptionError` at the end |
| The same, read the damaged member | One `MEMBER_HEADER_DAMAGED`; its bytes, checked by its digest |
| The same under `DiagnosticPolicy.STRICT`, `stream_members()` | The damaged member's read raises `DiagnosticRaisedError`; every other member reads; `CorruptionError` at the end |
| `extract_all()` under the default policy | Every member written, the damaged one under its stored name; one `MEMBER_HEADER_DAMAGED`; then `CorruptionError` |
| A damaged header the walk cannot resume past | No `MEMBER_HEADER_DAMAGED`; `CorruptionError` after the members before it |
| TAR with one damaged, confirmed member header, read the damaged member | One `MEMBER_HEADER_DAMAGED`; its bytes, which nothing but the confirmed size checks |
