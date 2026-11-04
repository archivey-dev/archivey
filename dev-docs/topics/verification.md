# Verification levels

What archivey can say about how much of a member's data it has checked, how each check
feeds that answer, and how the two calls that run the checks behave. The public names are
`Verification`, `ArchiveMember.verified` and `.verifiable`, the same two properties on
`ArchiveStream`, `ArchiveStream.verify()` and `verify_all()` on readers.

Other pages own parts of this, and this page links them rather than repeating them:

- [`docs/errors-and-diagnostics.md`](../../docs/errors-and-diagnostics.md#damaged-archives)
  is the user-facing version, in the "Damaged archives" section.
- The specs own the requirements: `compressed-streams` (the levels and `verify()`),
  `archive-data-model` (the member fields), `archive-reading` (`verify_all()`).
- Each format page owns how its own checks work: what the format stores, where a
  password is confirmed, and its seek points. [`formats/7z.md`](../formats/7z.md),
  [`formats/zip.md`](../formats/zip.md), [`formats/rar.md`](../formats/rar.md),
  [`formats/tar.md`](../formats/tar.md), [`formats/xz.md`](../formats/xz.md) and
  [`formats/zstd-lz4.md`](../formats/zstd-lz4.md) have the parts this page relies on.

The page follows the handbook's page conventions in
[`formats/README.md`](../formats/README.md), so it gives no performance numbers.

The whole feature is **experimental** (`scripts/api_surface.py` lists it so): any release,
a patch release included, may change it. The checks themselves are not experimental. A
read that fails one raises, whatever level the stream reports.

## At a glance

- **Four ordered levels.** `NONE < UNLOCKED < LENGTH < CHECKSUM`.
  - `NONE`: the member is encrypted and nothing reliable has confirmed its password.
  - `UNLOCKED`: the member is not encrypted, or its password passed a check that a
    wrong password cannot pass by chance.
  - `LENGTH`: a read reached the end, and the length and every end-of-data check passed.
  - `CHECKSUM`: every byte of the member passed a check that a wrong byte fails.
- **`CHECKSUM` does not care which layer holds the check.** The member's CRC-32 or
  BLAKE2sp, the WinZip AES authentication code, a gzip, bzip2, lzip or zlib stream's
  checksum, and the per-frame or per-block checks of `.xz`, `.zst` and `.lz4` all count.
  A file of frames counts only when every frame carries a check. Archive headers (7z
  header CRC, RAR header CRCs, TAR header checksums) never count.
- **The level reports checks a caller cannot run.** `hashes` holds only the member
  digests (CRC-32, BLAKE2sp). A codec's checksum, the per-frame checks, the WinZip AES
  code and a 7z folder CRC are not exposed, and some members have no digest of their
  own at all (an AE-2 ZIP member, a `.tar.gz` member, a 7z file covered only by its
  folder CRC). So reading a member and comparing its bytes with `hashes` cannot
  replace `verified`.
- **The level lives on the member.** `verified` is the best any read has proved so far.
  `verifiable` is the most a read from the start to the end can prove. Both are filled
  in place by the reader, like digests. A member stream mirrors its member. An
  `open_stream()` stream has no member and keeps its own.
- **Above `NONE`, `verified == verifiable` means nothing more can be checked.** At
  `NONE` it means nothing was proved, not even that the data is complete.
- **Under-report, never over-report.** A level is never claimed for a check that did not
  run. Every rule below that loses a check (a seek, an unknown frame) lands lower, never
  higher.
- **Two calls.** `stream.verify()` reads one stream until it reaches `verifiable`.
  `reader.verify_all()` does that for every member, does not stop at a failure, and
  returns the members that failed with their errors. There is no `reader.verify(member)`.
- **Checks that span members raise all the members they cover** when they pass: a 7z
  folder CRC, the checksum of a compressed TAR, CPIO or ar stream, and a ZIP streaming
  pass that decodes a member to find the next header.

## 1. Shape

Each check runs in its own stream layer: the member verifier (length and stored
digests), a codec's checksum, a codec's per-frame checks, the WinZip AES stage, and the
password watch over a member whose password only a weak check accepted. The public
`ArchiveStream` asks the layers below it what they have proved and turns the answers into a
level. A spanning check runs outside any one member's stream, in the reader, and raises
members directly.

```text
 member stream (ArchiveStreamImpl)         reader
   │ asks layers below: VerificationProofs   │ spanning checks:
   │   key_in_doubt / ended / content /      │   7z folder CRC
   │   content_possible / per-frame flags    │   compressed TAR/CPIO/ar trailer
   ▼                                         │   ZIP streaming pass
 verifier ─ codec ─ AES stage ─ watch        ▼
   │                                    raise_member_level(member, ...)
   └──────── raise_member_level(member, verified, verifiable) ──► ArchiveMember
                                                                   _verified
                                                                   _verifiable
```

- **The query.** A layer answers through a private, duck-typed `_verification_proofs()`
  and combines its answer with the layer below it (`internal/streams/verification.py`,
  `ask_verification_proofs`). A layer with no such method passes on only the doubt about
  a key. A layer that changes no byte positions sets `forwards_verification` to pass on
  everything. This is why a TAR member's slice of a `.tar.gz` does not claim the gzip
  checksum as its own: the slice passes on only doubt, and the checksum reaches the
  member through the spanning check instead (§2.5).
- **Turning proofs into a level** (`ArchiveStreamImpl._level_now`): a read that ended
  with a whole-content match is `CHECKSUM`, because a wrong key does not decrypt to data
  that matches a checksum. Otherwise a key in doubt is `NONE`, a clean end is `LENGTH`,
  and anything else is `UNLOCKED`.
- **The ceiling** (`_ceiling_now`): `CHECKSUM` when some layer can still match the whole
  content, else `NONE` while the key is in doubt, else `LENGTH`.

### 1.1 How a level moves

- **`verified` only rises.** A read that raises leaves it where it was. A failed check
  can therefore leave a member below its ceiling for good. That is how `verify_all()`
  tells its failures apart.
- **`verifiable` is the level a read can reach if the archive is not damaged.** Damage
  never lowers it: a member that damage keeps below it is a failure of `verify_all()`.
- **`verifiable` starts as the listing's estimate, for every member.** Every backend
  gives one; none leaves it unset until open. It is provisional. `CHECKSUM` when `hashes` holds a
  checksum or the member's codec checks its data (`StreamCodec.checks_content`) or may
  check each frame (`checks_frames`), or a check that spans members covers it
  (`_spanning_checksum`, §2.5), else `LENGTH`. A member with no data of its own (a
  link, a special entry, a directory that declares no data) answers with its `verified`.
- **`verifiable` counts checks that span members.** It is what the member's data can
  reach, not what its own read can reach. A file covered only by a 7z folder CRC, or a
  file of a `.tar.gz`, is `CHECKSUM` from the listing, and no stream of it lowers that
  (`raise_member_level` keeps the ceiling while the flag holds). Its own read, and so
  `stream.verify()`, ends at `LENGTH` below it. `verify_all()` reaches it.
- **It settles once, at the first open of the member's data,** lower or higher. A weak
  password check is found only then, and some members show only then that they carry a
  checksum. A WinZip AES AE-2 member, for example, lists at `LENGTH` (no CRC) and settles
  at `CHECKSUM` when its stream finds the authentication code.
- **After that it falls only for a format fact found late, once each:**
  - A read finds a stream or frame of an `.xz`, `.zst` or `.lz4` file with no check
    (§2.4). It drops to what the other layers can still reach, usually `LENGTH`.
    `ArchiveMember._frame_unchecked` remembers it, so a later stream that sees only
    checked frames does not raise it back.
  - A walk over a compressed TAR, CPIO or ar archive finds a stream or frame of the
    outer codec with no check (§2.5). The covered files drop to `LENGTH`
    (`drop_spanning_ceiling`).
- **It rises when another member's checksum confirms the password** (§2.1), and when a
  spanning check passes.
- **`verified <= verifiable` always.** The public `verifiable` returns
  `max(settled, verified)`.
- **Reading either property reads, decodes and seeks nothing.**

### 1.2 Where the state is kept

- `ArchiveMember._verified`, `_verifiable` and `_frame_unchecked` are private fields,
  excluded from equality like `hashes`, `diagnostics` and `extra`. So a member read later
  still equals a copy taken before.
- `member_state_final` does not cover them, as it does not cover `diagnostics`: they can
  rise after it turns `True`.
- **Copies.** A stream opened from a `replace()` copy raises the reader's own member,
  because the level describes the archive's bytes and not the record passed in. The copy
  keeps the values it was copied with.
- **The level lock.** Every raise is a compare-and-store under one process-wide leaf lock
  (`_LEVEL_LOCK`). It is held for a few attribute reads and writes, never across I/O or a
  callback, and no other lock is taken while it is held, so it adds no edge to the lock
  order. Two threads that raise one member, one through a stream and one through a folder
  CRC, cannot lower it.
- **Streams mirror the member, opened or not.** A lazy `stream_members()` stream of a
  member that `verify_all()` already checked reports `CHECKSUM` before its first read.
  `NONE` means "nothing proved yet", not "not opened".

## 2. What raises a level

### 2.1 Password checks: `NONE` to `UNLOCKED`

An unencrypted member starts at `UNLOCKED`. An encrypted member starts at `NONE` and
reaches `UNLOCKED` when its password passes a check that a wrong password cannot pass by
chance. A check that a wrong password passes by chance (ZipCrypto's one check byte, the
WinZip AES two-byte verifier) accepts the password but leaves the member at `NONE`. The
password watch (`UnverifiedPasswordReadWatch` in `password_confirm.py`) keeps the key in
doubt until the member's own checksum matches.

- **A matching checksum proves the key.** So a weakly accepted member jumps from `NONE`
  to `CHECKSUM` at its end, with no `UNLOCKED` step.
- **In 7z, a matching CRC proves the key for its whole folder, and only that folder.**
  Folders can use different passwords. `_folder_key_proved` raises each member of the
  folder from `NONE`, and its ceiling to `CHECKSUM` or `LENGTH`. A member read before
  that keeps the level it had, and `verify_all()` reads it again.
- **A key nothing can prove stays `NONE`, even after a clean full read.** That is a 7z
  AES member with no CRC of its own and none in its folder. Its `verified` and
  `verifiable` are both `NONE`. `verify()` still reads it to the end each time, so its
  length checks run, and `verify_all()` reads it on every call.
- **Closing or seeking a weakly accepted member before its checksum** reports
  `ENCRYPTED_MEMBER_UNVERIFIED`, since the bytes read may come from a wrong password.
  WinZip AES members do not report it after a seek, because the authentication code
  covers the whole ciphertext and survives seeks.

### 2.2 The end: `LENGTH`

A read reaches `LENGTH` when it ends with the length and every end-of-data check passing.
The member verifier sets this when it concludes without raising. For a stream with no
verifier (a TAR, ISO, CPIO or directory member, an `open_stream()` stream), it is a read
that returns `b""`, or `read(-1)`, with no seek since position 0. A slice that ends short
raises `TruncatedError` before that read returns.

### 2.3 The member digest

The member verifier hashes as it reads and compares the stored CRC-32 or BLAKE2sp at the
end. A match is `CHECKSUM`. RAR5's tweaked-encryption digests are key-derived MACs, not
plaintext checksums. They are kept out of `hashes` and checked by applying the same
transform once a password is known (`formats/rar.md`).

### 2.4 Codec checks

- **A whole-stream checksum** (gzip, bzip2, lzip, zlib: `checks_content`) counts only for
  a read that went from position 0 to the end with no seek between, other than a seek to
  0 or to the current position. A seek through an index skips bytes the decoder never
  saw. That is stricter than the decoders need, and it never over-reports.
- **Per-frame checks** (xz, zstd, LZ4: `checks_frames`). Each frame or stream says in its
  own header whether it carries a check: the xz check type, zstd's
  Content_Checksum_flag, the LZ4 content checksum or block checksums over every block.
  Skippable zstd frames carry no output and do not count. The decoder reports, per
  frame, whether a check was present and passed (`frame_checks`). The stream counts the
  file only when a read from the start reached the end and every frame it saw carried a
  check.
- **Until a frame's header is read, its check is unknown, and it counts as checked.**
  So such a file is `CHECKSUM` from the listing and stays `CHECKSUM` until a read finds a
  frame with no check. Then `verifiable` drops once (§1.1). This keeps `verifiable` at
  what `verify()` can actually reach, so the docs need no exception for these codecs.
- **The AES authentication code** runs below the decoder. The decompressor stream
  forwards only a whole-content match from its source, which is how an AE-2 member's
  code reaches the member stream: a code over the whole ciphertext covers every decoded
  byte.

### 2.5 Checks that span members

A check that covers several members keeps the list of members it covers and raises them
all when it passes, read or not. The members it covers are marked when they are listed
(`mark_spanning_checksum`), so their `verifiable` is `CHECKSUM` from the start (§1.1).
Until it passes, each member's `verified` stays where its own reads left it, usually
`LENGTH`.

- **Compressed TAR, CPIO and ar** (`.tar.gz`, `.cpio.xz`, `.a.bz2`, …). When the walk
  reaches the codec's end and its checksum matched over a decode from the start with no
  gap, every file member reaches `CHECKSUM` (`tar_reader.py`,
  `format_adapter.py` `_raise_members_the_codec_checked`). A sparse TAR member is left
  to its own reads, because its holes are not stored bytes. A file is marked only while
  the codec can still check its content, so an `.xz` whose first stream has no check
  marks nothing. A walk that finds a later frame with no check drops the marked files
  to `LENGTH`. Damage does not: a walk that damage ends before the codec's end, or that
  ends without running a check the codec has, keeps their ceiling and hands them to
  `verify_all()` as failures (`_note_spanning_unreachable`, a `SpanningCheckError`
  whose cause is the damage). An xz or bzip2 check failure looks like damage to
  archivey and goes the same way. A failed gzip, zlib, lzip, zstd or LZ4 checksum
  (`_StreamChecksumError`) returns every listed file (§3.2). A walk the caller cut
  short changes nothing. Listing such an archive on a random-access reader reads it to
  the end, so its members are often at `CHECKSUM` before any read.
- **7z folders.** A folder can store one CRC for its whole unpacked stream and none per
  file.
  - With one file in the folder and no CRC of its own, the folder CRC covers exactly that
    file, so the reader hands it over as the member digest.
  - With several files, each file with no CRC of its own is `CHECKSUM` in `verifiable`
    from the listing, and stops at `LENGTH` when read alone. When a decode of the
    whole folder in order from its start matches the folder CRC, each file with no CRC
    of its own reaches `CHECKSUM` (`_folder_crc_matched`). A file with its own CRC gets
    there through its own read.
  - A `seekable_members=True` read that seeks does not decode the folder in order, so it
    never runs the folder CRC. The reader keeps the folders whose CRC has not matched
    (`_awaiting_spanning_checks`), and `verify_all()` reads their members again whatever
    their levels.
  - A folder CRC that does not match raises `CorruptionError` from the read that reaches
    the folder's end. The internal subclass `SpanningCheckError` carries `covers`: the
    members only that CRC proves. When the last file's own CRC also fails, its read
    raises that more precise error, and the folder error is kept for `verify_all()`
    (`_note_unraised_spanning`). When the last file's own CRC matched, that file reaches
    `CHECKSUM` and is not a failure. No level falls, and the covered files keep their
    `CHECKSUM` ceiling.
  - A decode that fails, or ends before the folder's last byte, means the folder CRC
    can never run. The covered files keep their ceiling, and the reader hands them to
    `verify_all()` as failures (`_folder_crc_unreachable`,
    `_note_spanning_unreachable`).
- **ZIP streaming passes.** A pass that decodes a member to find the next header (a
  bit-3 member with a data descriptor) raises it as a read would: `CHECKSUM` when the CRC
  or the AES code covered every byte, else `LENGTH`, and never past a ceiling that an
  unproved key holds lower (`zip_forward_reader.py`).

### 2.6 What seeks do

Seeks only matter with `seekable_members=True` or an `open_stream(..., seekable=True)`.
`stream_members()` streams never seek.

- **The member digest survives most seeks:** a seek back, a seek to or past the end, and
  a seek forward that the next read decodes its way through. Bytes read again after a
  seek back are not hashed twice.
- **A jump forward that skips bytes without decoding them, and lands before the end,
  stops the digest** once the read goes on from there. That happens in a stored member,
  through the `seekable` accelerator when it has a restart point in between, and in a
  BGZF or Seekable Zstandard file, which list their restart points up front. A seek back
  to a point already read up to brings the digest back.
- **A codec's own checksum, and "reached the end" without a verifier, are dropped by any
  seek other than to 0 or to the current position** (§2.4).
- **The length is still checked after a jump,** and damage the decoder notices still
  raises. Once a read has raised, a later read that reaches the end raises the same
  error, even after a seek.
- After seeks, `verified < verifiable` at the end says a check was skipped. A read from
  the start again runs it, and `verify()` does that by itself (§3.1).

## 3. The calls

### 3.1 `stream.verify(*, password_only=False)`

Reads and discards until the stream reaches its target, then returns `verified`. The
target is `verifiable`, or `UNLOCKED` with `password_only=True` (or `verifiable` when that
is lower). It never reads past its own member, so a spanning check is not reached here.

- **A seekable stream is left as it was:** same position, and a later `read()` returns
  the same bytes. When an earlier seek kept a read from covering every byte, `verify()`
  reads from 0 again. Going back to the middle of a compressed member with no index
  decodes it again up to that point. Its own seeks report no
  `STREAM_REWIND_REDECOMPRESSES`, because the caller did not make them.
- **A stream that cannot seek is read to the end,** unless the target is already
  reached, and any later `read()` raises `ArchiveyUsageError` either way. A second call
  reads nothing: it raises the first call's error again, or returns `verified`.
- **It reads and decodes nothing when `verified` has reached the target and is above
  `NONE`.** A target of `NONE` is never reached this way, so a member whose key nothing
  can prove is still read to the end and its length checks run.
- **`password_only=True` can still cost a full read.** A member whose password passed only
  a weak check is confirmed only at its checksum.
- **A failed check raises what the read raises** (`CorruptionError`, `TruncatedError`,
  `EncryptionError`). A seekable stream is still put back.

### 3.2 `reader.verify_all()`

Returns `tuple[tuple[ArchiveMember, ArchiveyError], ...]`, the failures in listing order.
An empty tuple means everything checked out. It runs one `stream_members()` pass over a
selector that keeps the members with something left to prove:

- a member below its `verifiable`;
- a member whose `verifiable` is `NONE`, so two calls agree on a truncated member that
  nothing else can prove;
- a member of a spanning check that failed last time, or that has not passed yet
  (§2.5). These are read whole, at their ceiling or not, because the check needs their
  bytes and their end again.

Each selected member is read as `stream.verify()` reads one. A failure is recorded and
the pass goes on. Then:

- **A member the password input did not supply** is a failure with its
  `EncryptionError`. A second call reads it again and asks the password input again.
- **A failed spanning check** (7z folder CRC) returns each member it covers, all paired
  with the same error object. That error's `member_name` names the member whose read
  reached the check.
- **A failed checksum over the whole compressed archive** (a `.tar.gz` trailer) ends the
  pass and returns every listed file with that error, read in this pass or not. The
  checksum may cover only some of the files (a concatenated `.tar.gz`, a `.tar.zst` of
  several frames) and nothing says which, so all are returned rather than pass a damaged
  one (DR-1). A member that already failed keeps its own error.
- **Damage that stops the listing ends the call without raising.**
  `members_report().error` holds it.
- **Damage that keeps a spanning check from running** (a 7z folder decode that stops
  early, a `.tar.gz` cut before its trailer) returns each member only that check would
  prove, with a `SpanningCheckError` whose cause is the damage.
- **A per-member limit, such as a decode ratio breach, is a member failure.**
- **What it does raise:** `ArchiveyUsageError` (closed reader, a call during an active
  pass, or any call on a streaming-only reader after its one pass started, its own
  included); `ResourceLimitError` when the listing exceeds `ListingLimits`; an error the
  caller's diagnostic policy escalates; non-archivey errors such as `OSError` and
  `KeyboardInterrupt`.
- **It does not touch streams the caller holds.**
- **On a streaming-only reader it is the one pass,** and `members_report()` afterwards
  returns that pass's report without reading again.
- **A `.zst`, `.lz4` or `.xz` member read only past a jump** is read again, once, so its
  frames can still prove `CHECKSUM`.

Afterwards every listed member has `verified == verifiable`, except the ones returned.

### 3.3 Checking everything about an archive

```python
failures = reader.verify_all()       # each member's data
report = reader.members_report()     # report.error: damage that stopped the listing
findings = reader.diagnostics        # archive-level findings
```

Archive-level damage, such as a missing end-of-archive marker
(`ARCHIVE_EOF_MARKER_MISSING`), is a diagnostic. It raises only when the diagnostic
policy escalates it, and it is never a verification level.

### 3.4 The contract

The design states twelve items, each with a test in `tests/test_verification_contract.py`
or `tests/test_verification_scenarios.py`. In short:

1. `verify_all()` returns per-member failures and raises only the errors listed in §3.2.
2. After `verify_all()`, every member has `verified == verifiable` except the failures.
3. A member stream's levels equal its member's at every moment, opened or not.
4. `stream.verify()` reads nothing once the target is reached above `NONE`.
5. `verified` never falls. `verifiable` never falls after open except when a frame
   with no check is found (§1.1), and never for damage. `verified <= verifiable`.
6. No level is claimed for a check that did not run.
7. A spanning check raises the members it covers when it passes, and not before.
8. Reading a level never reads, decodes or seeks.
9. `stream.verify()` leaves a seekable stream as it was and consumes one that cannot
   seek.
10. `verify_all()` leaves the caller's streams alone, and a second call re-reads exactly
    the members §3.2 selects.
11. On a streaming-only reader, `members_report()` after `verify_all()` reads nothing.
12. "Check everything" is §3.3.

## 4. Per format

What each format carries, the `verifiable` its file members start with, and how they
get there. "Weak" is a password check a wrong password can pass by chance.

| Format | Checks on member data | `verifiable` | Notes |
| --- | --- | --- | --- |
| ZIP | CRC-32 per member; WinZip AES code | `CHECKSUM` | ZipCrypto and WinZip AES accept a password on a weak check: `NONE` until the CRC or the code matches. AE-2 has no CRC and lists at `LENGTH`, then settles at `CHECKSUM` at open. A CRC of 0 on a directory entry is no digest |
| 7z | CRC per file, or one per folder | `CHECKSUM` (a file's own CRC, or its folder's CRC) | No password check value: an AES member is `NONE` until a CRC in its folder matches. AES with no CRC anywhere in the folder stays `NONE` (§2.1). Folder CRC: §2.5 |
| RAR 5 | CRC-32 or BLAKE2sp per member | `CHECKSUM` | The password check value is reliable, so an encrypted member is `UNLOCKED` before its digest. Tweaked digests are checked through the key (§2.3) |
| RAR 3-4 | CRC-32 per member | `CHECKSUM` | An encrypted member has no password check: `NONE` until its CRC matches. An archive with encrypted headers has checked the password already |
| TAR, CPIO, ar | None per member | `LENGTH` | Header checksums do not count |
| Compressed TAR, CPIO, ar | The codec's check over the whole stream | `CHECKSUM` when the codec has one; `LENGTH` once a walk finds a frame without a check | A file's own read stops at `LENGTH`; all files rise together at the codec's end (§2.5). A sparse TAR member is left to its own reads |
| ISO, SquashFS, directory | None | `LENGTH` | |
| gzip, bzip2, lzip, zlib file | The stream's checksum | `CHECKSUM` | Counts only for a read from 0 with no seek between (§2.4) |
| xz, zstd, LZ4 file | Per stream or frame, if the writer added one | `CHECKSUM` until a frame without a check is found, then `LENGTH` | §2.4 |
| Brotli, `.Z`, `.lzma`, LZO file | None counted | `LENGTH` | LZO blocks can carry checksums, which archivey checks but does not count (§6) |

## 5. Sharp edges

**format**: inherent. **archivey**: ours.

| What you see | Where | More |
| --- | --- | --- |
| A ZipCrypto or 7z AES member read halfway reports `NONE`, even with the right password | **format** | Only its checksum proves the key (§2.1) |
| A clean full read of a 7z AES member with no CRC stays `NONE` | **format** | Nothing in the archive can prove the key. `DIGEST_UNVERIFIABLE` (`no_integrity_anchor`) says so too |
| A file of a `.tar.gz`, or a 7z file covered only by its folder CRC, read to its end is `LENGTH` while its `verifiable` is `CHECKSUM` | **format** | The checksum covers several members. `stream.verify()` never reads past its member; `verify_all()` or a pass to the end raises it (§2.5) |
| `verify_all()` on a `.tar.gz` with a bad trailer returns every file | **archivey** | Nothing says which files the failed checksum covers (§3.2, DR-1) |
| A damaged 7z folder or a cut `.tar.gz` makes `verify_all()` return files whose own bytes are intact | **format** | The check that would prove them cannot run, and `verifiable` stays what an undamaged archive reaches (§2.5) |
| A `.zst` file's `verifiable` drops from `CHECKSUM` to `LENGTH` partway through a read | **format** | Each frame says in its own header whether it carries a check (§1.1) |
| After a jump with `seekable_members=True`, a member read to the end is below its `verifiable` | **archivey** | The jump skipped bytes the check needs (§2.6). `verify()` reads from 0 again |
| `verify()` on a non-seekable stream makes later reads raise `ArchiveyUsageError` | **archivey** | It cannot go back. Read the data instead: the read runs the same checks |
| `verify_all()` after seekable reads of a 7z folder decodes the whole folder again | **format** | Only an in-order decode runs the folder CRC (§2.5) |
| A member read before a sibling in its 7z folder confirmed the password keeps `NONE` | **archivey** | Levels rise in place but a read is not replayed; `verify_all()` reads it again |
| A spanning failure's `member_name` is not the member it is paired with | **archivey** | One error object is returned for every member it covers (§3.2) |

## 6. Decisions

Only the rulings that shape behavior. Naming and wording are not listed.

- **`CHECKSUM` means every byte passed a check at some layer** (davi, 2026-11-01/02,
  project thread "Refine the verification design"). Rejected: a separate
  `COMPLETE_NO_CHECKSUM` level for a full read with nothing to check. It is the common
  case (plain TAR, `.Z`, `.br`, `.lzma`), and it proves the same as a full read whose
  checksum a seek skipped, so it would break the ordering. Rejected too: splitting
  "self-verifying" codecs (deflate, LZMA) from stored data. A decoder that did not
  complain proves nothing: a damaged deflate stream can decode cleanly into wrong bytes.
- **Archive headers do not count, and archive-level damage is never a level** (same
  thread). A failing header already raises or reports while the archive is listed.
- **A key nothing can prove stays `NONE`; another member's CRC proves it only within
  the same 7z folder** (same thread). Folders can use different passwords.
- **The level lives on the member, and every stream mirrors it** (same thread).
  Rejected: an archive-wide level on the pass, and no levels on `open_stream()` streams.
  Two stream shapes invite bugs in code that takes both.
- **`verifiable` includes checks that span members** (davi, 2026-11-04, project
  thread "Write the verification topic page"). Rejected: `verifiable` as what the
  member's own read reaches, which left `verified == verifiable == LENGTH` on members
  that `verify_all()` could still raise, so the comparison no longer meant "nothing
  left to check".
- **`verifiable` settles once at the first open; a `replace()` copy's stream raises the
  reader's member** (davi, 2026-11-02, same thread).
- **One call per job: `stream.verify()` and `verify_all()`** (same thread). Rejected:
  `reader.verify(member)` beside `stream.verify()`, and a `verify()` method on
  `ArchiveMember`, which would need a hidden link to the reader. Rejected:
  `verify_all()` stopping at the first failure.
- **`verify()` leaves a seekable stream exactly as it was and consumes one that cannot
  seek, whatever the level** (davi, 2026-11-01, project thread "Plan the 0.3.0
  release"). It does whatever reading the target needs, a re-read from 0 included.
- **A 7z folder CRC that does not match raises like a file CRC failure** (davi,
  2026-11-03, project thread "Sweep the new 0.3.0 code"). `verify_all()` lists the
  members it covers, and no level falls.
- **`verify()` and `verify_all()` read a `.zst`, `.lz4` or `.xz` member again until its
  ceiling is known** (davi, 2026-11-03, same thread).
- **`verifiable` shows `CHECKSUM` for xz, zstd and LZ4 whenever a re-read can reach
  it** (davi, 2026-11-03, same thread, citing DR-22a: fix the code rather than caveat
  the docs). It drops once when a frame without a check is found.
- **`verifiable` is what an undamaged archive reaches; damage never lowers it** (davi,
  2026-11-04, project thread "Write the verification topic page"). It is there to
  answer "could `verify_all()` raise this member, or is this the max?". The members
  damage leaves below it are failures instead. Every member has a provisional value
  from the listing: a value set for some members and unset for others would hide bugs
  until production.

## 7. Open questions

- **The CLI `test` verb does not call `verify_all()`.** It has its own loop over
  `stream_members()` (`cli/test_cmd.py`), counts `ENCRYPTED_MEMBER_UNVERIFIED` and
  `DIGEST_UNVERIFIABLE` as "not verified", and does not read levels. The redesign said
  the verb *can* call `verify_all()`. Nothing is decided.
- **Codec checks across seeks.** A codec's own checksum and "reached the end" without a
  verifier are dropped by any seek other than to 0 or to the current position. Keeping
  them across a seek that decodes through would raise more members. It under-reports
  today and never over-reports.
- **LZO block checksums are not counted.** Each `lzop` block can carry an Adler-32 or
  CRC-32 of its decompressed data, and the decoder checks it (`lzo_decoder.py`), but
  `LzopCodec` sets neither `checks_content` nor `checks_frames`. An `.lzo` file therefore
  stops at `LENGTH` even when every block was checked.
- **Promotion to stable** is planned for 0.4.0, after use.

## 8. Verify

```bash
./scripts/test.sh tests/test_verification_contract.py tests/test_verification_scenarios.py \
    tests/test_verification_level.py tests/test_stream_verify.py tests/test_verify_all.py \
    tests/test_codec_frame_checks.py tests/test_sevenzip_verification_levels.py \
    tests/test_tar_verification_levels.py tests/test_zip_forward_verification_levels.py \
    tests/test_sequential_verification_levels.py
```

## 9. References

- Source: `src/archivey/internal/streams/verification.py` (proofs, the level lock,
  `raise_member_level`, `note_frame_unchecked`, `SpanningCheckError`),
  `internal/streams/archive_stream.py` (`_level_now`, `_ceiling_now`, `_frame_verdict`),
  `reader.py` (`ArchiveStream.verify`), `internal/base_reader.py` (`verify_all`),
  `internal/backends/sevenzip_reader.py` (folder CRC and key proof),
  `internal/backends/tar_reader.py` and `internal/format_adapter.py` (compressed
  container checksums), `internal/backends/zip_forward_reader.py` (streaming pass),
  `internal/password_confirm.py` (the password watch).
- Archived OpenSpec changes: `openspec/changes/archive/2026-11-03-verification-level/`
  and `2026-11-03-verification-level-redesign/` (design Decision 6 holds the full
  contract).
- [`design-rules.md`](../design-rules.md): DR-1 (a wrong answer is the worst failure),
  DR-22a (fix the code before caveating the docs).
