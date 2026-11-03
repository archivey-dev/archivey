# archive-reading — verification level redesign delta

## ADDED Requirements

### Requirement: verify_all checks every member and keeps going

Every reader SHALL have `verify_all()`, which reads every listed member to the end,
does not stop at a member's failure, and returns a tuple of `(member, error)` pairs,
one for each member whose read raised an `ArchiveyError`. An empty tuple SHALL mean no
member failed. A member whose password the password input did not supply SHALL be a
failure, returned with its `EncryptionError`. A per-member limit (a decode ratio
breach) SHALL be a member failure.

`verify_all()` SHALL NOT raise a member's failure. It SHALL raise only:
`ArchiveyUsageError` (a closed reader, a call during an active pass, or, on a
streaming-only reader, any call after a pass has started, its own included); the
`ResourceLimitError` that `members_report()` raises when the listing exceeds
`ListingLimits`; an error the caller's diagnostic policy escalates; and errors that
are not `ArchiveyError` (`OSError`, `KeyboardInterrupt`). Damage that stops the listing
SHALL NOT raise: `verify_all()` stops there, and `members_report().error` holds it.
A failed checksum over the archive's whole compressed stream (a `.tar.gz` trailer) that
ends the listing or the pass SHALL make every listed file a failure, returned with that
error, whether or not the listing ran before the call.

After `verify_all()` returns, every listed member that is not among its failures SHALL
have `verified == verifiable`, checks that span members included. On a random-access
reader it SHALL NOT touch streams the caller holds. A second call SHALL re-read the
members whose `verified` is below their `verifiable`, the earlier failures, the
members whose `verifiable` is `NONE`, and the members whose per-frame checks wait on a
read from the start (a `.zst`, `.lz4` or `.xz` member read only past a jump); it MAY
skip any other member. On a
streaming-only reader, `members_report()` after `verify_all()` SHALL return the report
of that same pass without reading again.

Archive-level damage and findings are reported by `members_report()` and
`reader.diagnostics`, never as a verification level.

#### Scenario: verify_all matrix

| Case | Expected |
| --- | --- |
| Intact ZIP | returns `()`; every member `verified == verifiable` |
| ZIP with one member whose CRC fails | returns that member with `CorruptionError`; the other members at `CHECKSUM` |
| Encrypted ZIP, no password given | returns each encrypted member with `EncryptionError` |
| Second call after a password provider now supplies the password | re-reads only the members that failed; returns `()` |
| `.tar.gz` with a matching trailer | returns `()`; every member at `CHECKSUM` |
| `.tar.gz` whose trailer CRC fails, with or without `members()` first | returns every file with `CorruptionError`; so does a second call |
| TAR cut inside the member listing | returns the failures before the cut; `members_report().error` is a `TruncatedError` |
| TAR with no end-of-archive blocks | returns `()`; `reader.diagnostics` holds `ARCHIVE_EOF_MARKER_MISSING` (raises only when the policy escalates it) |
| 7z AES folder with no CRC, truncated | returns the member with `TruncatedError`, on a first and a second call |
| Streaming-only reader, second call | raises `ArchiveyUsageError` |
| Streaming-only reader, call after `stream_members()` has started | raises `ArchiveyUsageError` |
| Streaming-only reader, `members_report()` after `verify_all()` | returns the cached report; reads nothing |
| Random-access reader with a caller stream open at position 100 | the caller's stream stays at position 100 |
