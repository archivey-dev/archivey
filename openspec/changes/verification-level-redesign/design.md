## Context

`verification-level` (PR 1032) shipped four ordered levels, renamed in PR 1212 to
`NONE`, `PASSWORD`, `LENGTH` and `CHECKSUM` and marked experimental in PR 1213.
`ArchiveStream.verify(level)` (PR 1211) raises a stream to a level: a seekable stream
is left as it was, and a non-seekable one is read to the end, after which reads raise
`ArchiveyUsageError`. The maintainer refined the meaning in the thread "Refine the
verification design". The proposal lists each ruling. This file records how each
rule maps onto the code.

## Decisions

### 1. One definition for the top level

`CHECKSUM` holds when every byte of the member's output passed at least one check that
a wrong byte fails, except by chance at the check's own odds. Where the check sits
does not matter. A file of frames qualifies only if every frame carried a check.

- **xz:** each block carries its check type in the stream flags (None, CRC32, CRC64,
  SHA-256). Check type None in any stream of the file keeps it at `LENGTH`.
- **zstd:** the frame header's Content_Checksum_flag. A frame without it keeps the
  file at `LENGTH`. Skippable frames carry no output and do not count either way.
- **lz4 frame:** either the content checksum or block checksums covering every block.
  Legacy-format frames have none.

Each decoder reports through the same private query the codec check uses today
(`checks_content` becomes per-stream: "content matched" is set only when the decoder
saw a check on every frame and all passed). The seek rule of `verification-level`
Decision 4 is unchanged.

### 2. Keys without proof stay `NONE`

This is unchanged, but now written down. A member whose password nothing can prove
(stored data under AES, or a 7z AES folder with no CRC) has `verified == verifiable ==
NONE`, even after a clean full read. Another member's matching CRC proves the key only
for members of the **same 7z folder**, because folders can use different passwords.
The tests cover both cases.

### 3. One-file 7z folders

When a 7z folder holds exactly one file and that file has no digest, the folder's
unpack digest covers the same bytes, so the reader hands it to the verifier as the
member digest. With several files and only a folder CRC, each file stays at `LENGTH`.

### 4. Where the level lives

The level belongs to the member: `ArchiveMember.verified` and `.verifiable`, filled in
place by the reader like digests. A member stream asks its member, and an
`open_stream()` stream keeps its own. Each check that proves bytes reports to the
member it covers. A check that spans members (7z folder CRC, `.tar.gz` trailer) keeps
the list of members it covers and raises them all when it passes. A listing pass that
decodes data reports to every member it passed. `ArchiveMember.replace()` copies the
level as it stands; the copy does not follow later raises.

### 5. Verify calls

- `stream.verify(*, password_only=False)`: this stream only, PR 1211 rules.
- `reader.verify_all()`: every member, keeps going, returns `(member, error)` pairs.
  Damage that stops the listing ends it without raising; `members_report()` returns it.

The user docs explain it in one line each: `verified` on a member or stream says what
has been proved; `stream.verify()` reads one stream until it reaches `verifiable`;
`reader.verify_all()` does that for every member, without stopping at failures, and
returns the ones that failed.

Both aim at `verifiable` (`stream.verify()` at `PASSWORD` with `password_only`).
`stream.verify()` never reads past its own member; `verify_all()` reads everything.

### 6. The contract

Each item gets a test (tasks group 5).

1. `verify_all()` returns per-member failures and does not raise them. It raises only:
   `ArchiveyUsageError` (closed reader, a call during an active pass, a second call on a
   streaming-only reader); `ResourceLimitError` when the listing exceeds
   `ListingLimits`, as `members_report()` does; an error the caller's diagnostic policy
   escalates; and non-archivey errors (`OSError`, `KeyboardInterrupt`). Damage that stops
   the listing does not raise: `verify_all()` stops there, and `members_report().error`
   holds it. A per-member limit (a decode ratio breach) is a member failure.
2. After `verify_all()`, every listed member has `verified == verifiable`, except the
   members in its returned failures. That includes encrypted members whose password was
   not found. A member whose password nothing can prove has `verifiable == NONE`, so it
   meets the rule at `NONE`.
3. A member stream's `verified` and `verifiable` equal its member's at every moment. A
   read on the stream that proves more raises the member in place.
4. When `verified == verifiable`, `stream.verify()` reads and decodes nothing. On a
   non-seekable stream it still marks the stream consumed, so later reads raise
   `ArchiveyUsageError` (the PR 1211 rule), but that marking does no I/O.
5. `verified` never falls, and `verifiable` never falls once the member is open. A read
   that raises leaves `verified` where it was. `verified <= verifiable` always.
6. A level is never claimed for a check that did not run. Under-reporting is allowed and
   over-reporting is not.
7. A check that spans members (7z folder CRC, `.tar.gz` trailer) raises the members it
   covers when it passes, and not before.
8. Reading `verified` or `verifiable` never reads, decodes or seeks.
9. `stream.verify()` on a seekable stream leaves it as it was (position and what a
   later `read()` returns). On a non-seekable stream it reads to the end, later reads
   raise `ArchiveyUsageError`, and a second call reads nothing and raises the first
   call's error again.
10. `verify_all()` on a random-access reader does not touch streams the caller holds.
    A second call re-reads only members whose `verified` is below their `verifiable`,
    asking the password provider again for those that failed to decrypt.
11. On a streaming-only reader, after `verify_all()`, `members_report()` returns the
    report of that same pass without reading again.
12. To check everything about an archive: `verify_all()`, then `members_report()` (the
    members with their levels, and `error` for damage that stopped the listing), then
    `reader.diagnostics` (archive-level findings such as `ARCHIVE_EOF_MARKER_MISSING`,
    which raise only when the diagnostic policy escalates them). Archive-level damage
    is reported there, never as a verification level.

## Risks / Trade-offs

| Risk | Mitigation |
| --- | --- |
| A decoder binding hides whether a frame had a check | Report `LENGTH` for that codec until the binding exposes it: under-report, never over-report |
| A one-file folder CRC handed over twice (folder check plus member digest) | Hand it over only when the member has no digest of its own |
