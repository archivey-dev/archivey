## MODIFIED Requirements

### Requirement: Error Policy (OnError) for extraction failures

`OnError.STOP`, `OnError.CONTINUE` and `OnError.KEEP_PARTIAL` SHALL govern per-member
**failures** only — a
non-rejection member-scoped `ArchiveyError`, a permitted read/write `OSError`, or a
per-member ratio violation. A policy **block** (a `FilterRejectionError` from a universal
path-safety check or a policy filter) is NOT a failure: it SHALL always be recorded as a
`BLOCKED` `ExtractionResult`, have its partial output removed, and let extraction
proceed — under **every** `OnError` value. `OnError.STOP`
therefore never stops at a blocked member. What the call does once every member is
processed is `on_blocked`'s ("A refused member raises once the rest are extracted").
Aborting the whole extraction on the first unsafe member (fail-closed strict security)
SHALL be expressed through `AbortOn.BLOCKED_MEMBER`, not through `OnError`.

Under `CONTINUE`, a member-scoped failure records `FAILED`, removes partial output,
and proceeds.

`KEEP_PARTIAL` SHALL act as `CONTINUE`, except for a FILE whose data fails while it is
copied (damaged data, a check at the end of the data, a write error): its file SHALL land
at its destination as a complete one would, under the same overwrite policy, holding the
bytes the member's data gave before the failure, and its result SHALL be `FAILED` with the
error and `path` set to where it landed. The member SHALL be read at
`recover_partial_data=ALL` whatever the config says, so the read whose check of the
member's own verifier (its CRC, digest or declared size) fails returns its bytes into
the kept file, and so a member whose only damage is that check keeps every byte; a
check made inside a decoder (gzip's trailer CRC) can still lose the decoder's last
output. The kept file SHALL get none of the member's
metadata (no stored mode, owner or times). It SHALL count as written for later members:
a later member meets it as an entry this run wrote, and one that replaces it under
`REPLACE` leaves its result `FAILED` with `path=None`. Nothing SHALL be kept when no byte
was written, when the failure came before the copy, when the failure is a refusal, a
resource limit or a diagnostic that halts, in a dry run, when the landing itself fails,
or for a HARDLINK (written, linked or copied from its source). A kept file SHALL NOT be a
source for later hard links or file copies. From a ZIP read from a non-seekable source,
the bytes staged before the failure SHALL be kept until placement, where the member
lands with them as from a file. When the run raises with no report (the same damage ends the
listing, an abort, a halting error), a note on the raised error SHALL name each file
kept before it.

Under `STOP`, a genuine member failure raises immediately and is not converted to a
continued result. Logging-handler and diagnostic-callback exceptions propagate
unchanged.

Diagnostic disposition SHALL remain authoritative for the diagnostics that still fire
during extraction. Per-member extraction *outcomes* are no longer diagnostics, but
reading an archive while extracting still emits reading diagnostics (invalid
timestamps, unresolvable symlinks, unverifiable digests, stream rewinds); a `RAISE`
disposition on any of those SHALL emit `DiagnosticRaisedError` and halt immediately,
even under `OnError.CONTINUE`, returning no report. Global resource guards (`ResourceLimitError` for cumulative bytes,
archive-wide/live ratio, and max entries), `KeyboardInterrupt`, `MemoryError`, and
unexpected programming exceptions are always-stop and are not swallowed.

#### Scenario: OnError matrix

| Case | Expected |
| --- | --- |
| Member blocked by policy/path-safety under `STOP` | `BLOCKED` result; partial output removed; extraction does **not** halt; later members continue |
| Member blocked by policy/path-safety under `CONTINUE` | `BLOCKED` result; partial output removed; later members continue |
| First member blocked, remaining members extractable, under `STOP` | Run completes; `BLOCKED` + later `EXTRACTED` recorded; no exception at the blocked member; the call ends as `on_blocked` says |
| Corrupt member under `CONTINUE` | Partial output removed; `FAILED` result; later members continue |
| Default `STOP` member failure (e.g. `CorruptionError`) | Original error propagates immediately; failing partial file removed; earlier outputs remain (from a ZIP read from a pipe, less the files that could still be links: `format-zip`) |
| Filesystem `OSError` while writing under `CONTINUE` | Partial output removed; `FAILED` result; extraction proceeds |
| A member under a non-directory this run extracted (file `d`, then `d/f` or directory `d/y`) | Per-member `ExtractionError` naming `d`, not a raw `OSError`, under every `OverwritePolicy` |
| A member under a non-directory already in `dest` before the run (`d/f` over the caller's file `d`) | `d` meets `OverwritePolicy` as an explicit `d/` entry would (see the overwrite requirement); under `ERROR` a per-member `ExtractionError`, not a raw `OSError` |
| Cumulative bytes/live ratio/max entries exceed limit under any `OnError` | `ResourceLimitError` propagates and halts; no later member processed |
| Corrupt member under `KEEP_PARTIAL` | `FAILED` result with the error and `path`; the bytes given before the failure stay at `path`; later members continue |
| Cut member (truncated `.tar.gz`) under `KEEP_PARTIAL`, either access mode | The member's prefix stays at its path; the walk then raises the damage, as under `CONTINUE`, with a note naming the kept file |
| Corrupt member under `KEEP_PARTIAL` whose existing destination `OverwritePolicy.ERROR` refuses | `FAILED`, `path=None`; the existing entry is untouched |
| Member over `DecoderLimits.max_ratio` under `KEEP_PARTIAL` | `FAILED` with `ResourceLimitError`; nothing kept |
| Corrupt member under `KEEP_PARTIAL`, dry run | `FAILED`, `path=None`; nothing written |
| Mixed good/corrupt/blocked archive under `CONTINUE` | Extractable members written; report includes `EXTRACTED` plus `FAILED`/`BLOCKED`; no per-member exception escapes; the call ends as `on_blocked` says |
| Reading diagnostic resolves to `RAISE` under `CONTINUE` (e.g. `MEMBER_TIMESTAMP_INVALID`) | `DiagnosticRaisedError` halts; no report returned |
