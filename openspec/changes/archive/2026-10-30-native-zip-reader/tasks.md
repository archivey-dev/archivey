# Tasks — native ZIP reader

## 0. Before coding

- [x] 0.1 The three ZIP fix PRs from the October code sweep have merged (trailing bytes
      after a codec's end, malformed Unicode Path field, comment decoding). Rebase on
      main; their tests are acceptance tests from here on. (The Unicode Path one, PR 715,
      closed unmerged; stage 2 carries its tests and docs.)
- [x] 0.2 Questions A, B and C in `design.md` are answered (davi, 2026-10-10) and
      recorded in `dev-docs/formats/zip.md` §6 and `dev-docs/design-rules.md` DR-8.
- [x] 0.3 `openspec validate --strict native-zip-reader`.
- [x] 0.4 Question D is answered (davi, 2026-10-10: a per-member field, working name
      `member_state_final`, settled in the stage 3 PR).

## 1. Parser (PR 1)

- [x] 1.1 `internal/backends/zip_parser.py`: `EndRecord`, `find_end_record`,
      `CentralEntry`, `CentralDirectoryWalk`, `LocalHeader`, `read_local_header`.
- [x] 1.2 ZIP64: extra field `0x0001` resolution order, ZIP64 locator and record, entry
      count past 65 535, offsets past 4 GiB (hand-built records, no large files).
- [x] 1.3 Stub prefix: `base` matches stdlib `concat` for an unadjusted SFX and is 0 for
      an adjusted one.
- [x] 1.4 Disk fields and the archive extra data record raise the existing refusals,
      including under ZIP64.
- [x] 1.5 Differential test: every ZIP in `tests/fixtures/`, every archive
      `tests/create_adversarial.py` builds and the sample corpus give the same entries
      as `zipfile.infolist()` wherever `zipfile` opens it, over the fields and with the
      exceptions `design.md` §"Behaviour that changes" lists; shown to fail against the
      three mutants named there.
- [x] 1.5a `EndRecord.trailing` counts the bytes after the record and its declared
      comment; a comment cut short is not trailing (tests for both).
- [x] 1.6 Walk findings equal what `_end_record_findings` reports today on the existing
      end-record tests.

## 2. Switch the reader (PR 2)

- [x] 2.1 `ZipReader` reads through the parser; `import zipfile` leaves `src/`.
- [x] 2.1a Add the newer-Python row for a comment plus trailing bytes totalling 65 536 to the
  handbook's behaviour notes, as the design's §"Behaviour that changes" table records
  it (the search window stays stdlib's older one).
- [x] 2.2 Reader-owned lock; the source is the handle for path sources too.
- [x] 2.3 Lazy `_iter_members`; `member_count` from a complete walk, `None` when it fails
      or stops at `max_members`.
- [x] 2.4 Offsets and count collected by the listing walk; the index pass only when
      `member_count` comes first; both charge `max_members` (tests:
      a listing then an open walks the directory once, counted reads).
- [x] 2.4a Open refuses a declared entry count over `max_members` when `cd_size` can hold
      it; a count the directory cannot hold stays a finding (tests for both).
- [x] 2.5 Damaged directory lists the entries before the damage, then raises (tests
      first: bad signature mid-directory, directory cut by end of file).
- [x] 2.6 Version needed above 6.3 lists and reads (test first).
- [x] 2.6a Trailing bytes after the end record report `ARCHIVE_TRAILING_DATA` as
      `design.md` §"Trailing bytes" states (1 MiB bound shared with TAR,
      `expected_marker="zeros_to_eof"`, zeros silent, strict refuses; the constant and
      zero-byte loop move to `internal/trailing_scan.py`); tests first,
      (the end record is always within 65 558 bytes of the end, so the 1 MiB bound and a
      pipe cannot arise for ZIP until stage 3).
- [x] 2.6b `member._raw` is a slotted locator, not the `CentralEntry` (design §"`zip_reader.py`");
      a tracemalloc test bounds the per-member listing cost below today's.
- [x] 2.7 Remove every row of `design.md` §"What the parser removes" except the name
      decode; tests that read `ZipInfo` off `member._raw` move to `CentralEntry`.
- [x] 2.8 New ADR superseding 0006; format-zip spec; the `diagnostics` spec row and the
      `ArchiveEofContext` docstring for `"zeros_to_eof"`; `docs/gotchas.md` (trailing
      data, open pipe); `dev-docs/formats/zip.md` §2.2, §5, §6; `dev-docs/IDEAS.md`;
      `docs/formats.md`.
- [x] 2.9 `./scripts/test.sh --all-configs`; benchmark listing against the baseline.
      Every test passes in all three configurations (2026-10-16); the run still
      exited 1, because the all-lowest leg's coverage combine then failed on local
      coverage data ("Can't combine statement coverage data with branch data"), not on
      a test. Against the commit before the switch
      (the stdlib-backed reader), median of nine runs on one machine: listing 20 000
      members takes 430-440 ms against 348-350 ms (`zipfile` alone, 50-58 ms), about
      a quarter slower; a streaming pass over them 680-700 ms against 746 ms; the
      harness's 64-member `zip_open_list` 1.6 ms against 1.4-2.1 ms. Reading and
      extracting the harness's 64 × 256 KiB archive costs 63-69 ms against 57-64 ms;
      the harness counts fewer source seeks for every ZIP case (`zip_read_all` 133
      against 205). Most of the listing time is building each member
      (`ZipReader._to_member`).

## 3. Streaming (PRs 3a, 3b, 3c)

3a is the forward walk alone (3.1, 3.2's parser half, 3.3d); 3b the reader over a
non-seekable source, in three PRs: 3b1 the codec half of 3.2, 3b2 the parts of 3.3e
and 3.3f that need no ZIP pipe reader (3.3e1, 3.3f1), 3b3 the rest; 3c the seekable
cases (3.0, 3.0a, 3.0b).

3b3 is five PRs. `open_archive` keeps refusing a pipe for ZIP until the last one, so
each lands with nothing half-done reachable:

- 3b3a, the pipe reader (`zip_forward_reader.py`): members from local headers, data
  checked against the header or descriptor as it is read, members updated in place
  from the directory at the end of the pass; 3.3h, 3.3e2's reader half, 3.3f2's
  listing half.
- 3b3b, extraction's end of the pass: 3.3's modes, symlinks, `OTHER` removal and
  names, 3.3a, 3.3f2.
- 3b3c, the failures found at the end of the pass, in two PRs: 3b3c1 the reader's
  half (the listing and `stream_members()` for 3.3b, 3.3c and 3.3i), 3b3c2 the
  extraction's half (3.3g, and 3.3i's removal from disk).
- 3b3d, encrypted members from a pipe, in four PRs: 3b3d1 one password, on a member
  whose local header states its size or a bit-3 STORED ZipCrypto one (3.2b's first
  half); 3b3d2 bit-3 encrypted codec members (ZipCrypto through `settle(crc=)`, and
  3.2a for AES) and bit-3 STORED under AES; 3b3d2b the descriptor scan for unread
  encrypted codec members, and descriptors without their signature; 3b3d3 several
  candidates (3.2b's second half).
- 3b3e, every fixture through a pipe (3.4), the gate (`SUPPORTS_STREAMING_NON_SEEKABLE`)
  and the docs (3.3e2's docs half, 3.5, 3.5a), in four PRs. Reading every ZIP the
  test suite opens (1206 archives) from a pipe and from a file turned up differences
  the first three fix: 3b3e1 parses what follows the members with the seekable
  read's code (3.4a); 3b3e2 checks a member's data against its directory entry
  (3.4b); 3b3e3 keeps a Windows reparse buffer longer than the link cap (3.4c). 3b3e4
  opens the gate, adds the fixture test (3.4) and the docs.

- [x] 3.0 A seekable source under `streaming=True` reads the directory first, then
      forward only (question C); a test counts its seeks.
- [x] 3.0a Before the walk: open a real self-extractor fixture through a pipe under the
      `FAST` and default budgets and record what `payload_offset` comes back as.
      Info-ZIP's `unzipsfx` stub (about 75 KiB on Linux, more on macOS) padded with
      zeros, plus `zip -A`: with the ZIP at 128 KiB both budgets report it as
      `payload_offset`, from a pipe and from a file, and the pass reads every member.
      At 1 MiB `FAST` finds no archive behind the executable header (from a file as
      well: detection scans forward only), the default finds it at the right offset,
      and `format=ZIP` from a pipe finds the first local header itself
      (`tests/test_sfx.py`).
- [x] 3.0b A seekable source whose end record is not in the last 65 558 bytes runs the
      local-header walk, per `design.md` §"A seekable source whose end record is not in
      the tail": tests first for a ZIP followed by 1 MiB of non-zero bytes (opens, members
      updated from the directory, `ARCHIVE_TRAILING_DATA`), a ZIP cut before its
      directory (members listed, then `TruncatedError`; `members_report()` carries both),
      a ZIP cut inside a member (`TruncatedError` at it) and junk after a member
      (`CorruptionError` after the members before it); a sized member is seeked over
      (counted reads).
      - [x] 3.0b1 A whole archive behind the trailing bytes: the walk finds where the
            members end and steps over the directory to the end record, from a file
            and from a pipe (which keeps the bytes right after the members as well as
            the last ones).
      - [x] 3.0b2 No end record: the members the walk found are listed from their
            local headers (a bit-3 member's CRC and sizes from its descriptor), then
            the walk's error is raised in the pipe read's words; a member the file
            cuts is listed and its read raises the cut; a test compares sixteen cut
            and junk shapes from a file and from a pipe.
- [x] 3.0c The same walk instead of a refusal for a damaged ZIP64 end record or locator
      (the classic record's fields when none is saturated, with a diagnostic), a bad
      directory offset and an unreadable directory entry, so a file read writes what
      a pipe writes (davi 2026-10-14); `test_zip_pipe_parity.py`'s `_DIFFERS` loses
      those rows.
  - [x] 3.0c1 Damaged ZIP64 end records and a directory offset before the file's
        start: the classic record when none of its fields is saturated, else the walk.
  - [x] 3.0c2 A stored directory offset the members' offsets contradict (a negative
        `base`: both reads already write nothing, and a sliced stub gives the same
        shift, so it stays) and an unreadable directory entry (the walk past it).
- [x] 3.1 Central and local headers parsed by the same code in both walks;
      `LocalHeaderWalk` over a forward reader (`zip_local_walk.py`); data descriptor
      parsing (signature optional, 4- or 8-byte sizes).
- [x] 3.2 Member end per row of `design.md` §"Where a member's data ends", including the
      STORED + bit 3 descriptor scan; tests with stdlib `zipfile` writing to a pipe.
      3a: the walk's half (sized data, the scan, `settle(used)` putting back what a
      codec's layers read past its end), tested in `test_zip_local_walk.py`. 3b1: the
      codec half, `settle(crc=)` finding a codec member's descriptor by its decoded
      CRC, and PPMd8 with `CodecParams.input_runs_on`; tests for DEFLATE, Deflate64,
      bzip2, LZMA with EOS, PPMd and Zstandard, signed and unsigned, in
      `test_zip_walk_codec_end.py`.
- [x] 3.2b Encrypted members from a pipe (3b3a refuses them when read): one password,
      and several candidates, whose bounded confirm reads a prefix the pass keeps
      (`archive-reading`'s "Confirm candidates" requirement); a bit-3 STORED member
      under ZipCrypto or AES ends by the scan without a key, so a skip needs none.
      3b3d1: one password, taken on its cheap check as from a file (the CRC or HMAC
      at the end is the test; a ZipCrypto integrity failure says the password may be
      wrong; `ENCRYPTED_MEMBER_UNVERIFIED` for a stream closed before the read that
      finds the end); a short member nobody read keeps its ciphertext, decrypted
      only once the directory makes it a link (no key derived for a member nobody
      asked for), and an encrypted member's failed read is kept for its target's
      read (`test_zip_pipe_encrypted.py`). Several candidates, or a provider, are
      refused when read until 3b3d3, and the pass must not call a provider for a
      member nobody asked for. 3b3d2: a bit-3 STORED member nobody read keeps its
      ciphertext as a sized one does, its scan's descriptor with it, so its link
      target reads as from a file; a bit-3 codec member the caller reads is
      decrypted and decoded to find its end, and a failure ends the walk there with
      the member's error. 3b3d2b: one nobody read is scanned for like a STORED one
      (signed or unsigned descriptor), so passing it needs no key, and its
      ciphertext is kept the same way. 3b3d3: several candidates or a provider,
      confirmed on the first 1 MiB of the data, kept and replayed to the winner;
      several inconclusive candidates take the first (davi's choice, `design.md`), and
      an unread sized member whose ciphertext is over what the pass keeps is
      decoded only under `read_link_targets`. Left for 3.4 (every fixture through a
      pipe): a bit-3 encrypted link whose ciphertext is over what the pass keeps
      loses its target, reported as damaged and over 4096 bytes when it is
      neither (the kept ciphertext and the rest could be replayed to a decode as
      the pass drains it); a sized member whose data decodes short of its local
      header's size reports the pass's own size-mismatch `CorruptionError` where
      the file read reports the verifier's `TruncatedError`, encrypted or not
      (both `CorruptionError` under DR-4; a ZipCrypto member shows neither, as the
      password-or-damage error). Data past the declared size already gives the
      file read's error.
- [x] 3.2a WinZip AES on a bit-3 codec member: the authentication code follows the
      codec's input, so the AES stage authenticates the ciphertext as it goes, holding
      back the bytes past the codec's end until `settle` says where the data ended
      (test: an AE-1 and an AE-2 deflated member from a pipe, and a wrong code).
      3b3d2: `WinZipAesForwardStream` (also bit-3 STORED under AES, which ends with
      its source and holds back the code alone); `MemberData.passed_over` hands it
      the data the descriptor search read past its last read.
- [x] 3.3 End-of-pass reconciliation: members updated from the directory; extraction
      applies modes, symlinks and `OTHER` removal; unreferenced local entries removed
      and reported; a missing one is handled per 3.3g. 3b3b: extraction keeps what it
      wrote each member of a pass that can still change as
      (`_REVISES_YIELDED_MEMBERS`), and at the end of the pass handles a member whose
      type or name changed again from the start (taking back what was written; a file
      that moved is written again from its bytes on disk) and applies metadata the
      directory added, unless the filter set that field
      (`ExtractionCoordinator._settle_revised_members`, since replaced by
      `_stage_then_place` in `pipe-zip-stage-then-commit`; `test_zip_pipe_extract.py`,
      which also extracts the corpus both ways). 3b3b also selects again at the end:
      `members=` and `filter=` are applied to what each member became, a list matches
      every spelling a member can end with during the pass, a member taken only at
      the end fails with `ExtractionError` when its bytes have gone by, and an entry
      the caller had where the pass wrote is kept aside until the end
      (`design.md`, "The selection is made again"). 3b3c: 3.3i and 3.3g.
- [x] 3.3a A retyped member goes through the filter and the policy checks again before
      its link is made; refused, its file is removed (test: a pipe ZIP whose directory
      types `payload` as a symlink to `../../etc/passwd` is refused from a pipe and from
      a file).
- [x] 3.3b A size or CRC from a data descriptor that differs from the central entry is
      detected; its outcome is 3.3g's (test: a STORED bit-3 member that embeds a
      descriptor for a prefix of itself, read from a pipe and seekably). 3b3c1: the
      reader's half (`ZipForwardReader._failed_at_end`; `stream_members()` raises at
      the end of the pass),
      `test_a_descriptor_the_directory_contradicts_fails_at_the_end_of_the_pass`.
      3b3c2: extraction (`_settle_failures_at_end`, since replaced by
      `_placement_data` in `pipe-zip-stage-then-commit`).
- [x] 3.3c `is_current` from the directory order; same-name members in reverse order are
      detected at the end of the pass, with 3.3g's outcome (fixture with the two orders
      reversed). 3b3c1: `is_current` (`_listed_in_index_order`),
      `test_the_later_copy_in_the_directory_is_current`; ids and listing order stay
      the file's. 3b3c2: extraction; results stay in the order the pass met them.
- [x] 3.3d A stream that starts neither with a local header nor an end record: scan
      within `SFX_MAX` with `validate_zip_local_header`; nothing found is
      `CorruptionError` (tests for both).
- [x] 3.3e1 `ArchiveMember.member_state_final` (question D) in every format: false
      for any member of a forward pass (TAR too) until the walk ends, and for a symlink
      whose target is stored as data until it is read (ZIP, 7z, RAR 4), with a test
      for each; `archive-data-model`, `docs/opening-and-listing.md`, `docs/formats.md`
      and the TAR, 7z, RAR and ZIP handbook pages.
- [x] 3.3e2 Forward-pass `ArchiveInfo` and cost receipt as in `design.md` §"What the
      caller sees in a forward pass"; `member_state_final` false for a pipe ZIP member
      until the directory has been read (test). 3b3a: the pipe reader still charges
      `max_members` as it walks, so a `ListingLimits` discard comes only from another
      limit, and it ends the updates: members after a discard, and the kept prefix,
      are never updated from the directory, so neither needs `_link_target_unread`
      (each is a `FILE` or `DIRECTORY` from its local header, and stays one).
- [x] 3.3e3 The ZIP row of the `docs/formats.md` table gains the directory's fields
      (3b3e, with the gate).
- [x] 3.3f1 A reparse-flagged member whose data is not a reparse buffer is typed when
      `stream_members()` reaches it and yields its whole content, as the 7z pass does
      (a seekable ZIP needs no read-ahead: the pass reads the target, then opens the
      member); tests in both modes, red first.
- [x] 3.3f2 From a pipe such a member stays a file (test). 3b3a: the listing half,
      `test_a_reparse_member_whose_data_is_no_link_stays_a_file`; extraction (3b3b), the
      test of the same name in `test_zip_pipe_extract.py`.
- [x] 3.3g End-of-pass outcomes exactly as `design.md` §"Failures found at the end of
      the pass" states them, under `OnError.CONTINUE` and `STOP`, for 3.3b, 3.3c and a
      directory entry with no local entry. Each test checks every affected result and
      what is at the path afterwards (the reversed pair: `M1` `FAILED`, `M2`
      `SUPERSEDED`, the path empty); `stream_members()` raises for 3.3b and the missing
      entry, not for 3.3c. A member whose local header and directory entry store
      different names (3b3a raises after the pass) gets the same treatment: the file
      written under the local name is taken back and the member fails, as the
      seekable extraction fails it when it reads the local header. 3b3c2:
      `ExtractionCoordinator._settle_failures_at_end` (since replaced by
      `_placement_data`, `pipe-zip-stage-then-commit`), the tests after "Failures
      found at the end of the pass" in `test_zip_pipe_extract.py`; a directory entry
      with no local entry is built from the directory (`_missing_member`) and gets a
      `FAILED` result when selected; a current copy that needs no bytes (an empty
      file, a folder) is written at the end. Recorded divergence: a member whose data
      fails as the pass writes it stops an `on_error="stop"` run, though the
      directory may then not list it.
- [x] 3.3i A local entry no directory entry points to: dropped from the listing and,
      when extracting, from disk, and reported (`ARCHIVE_UNLISTED_DATA`, the
      maintainer's pick 2026-10-13, with `UnlistedDataContext`). 3b3c1: the listing
      half (`_drop_listed`); 3b3c2: extraction takes back what it wrote, as for a
      member the selection drops at the end. Directory entries past the size the end
      record declares are read as the seekable read reads them since 3b3e1 (3.4a),
      which had them listed with a pipe-only `DirectorySizeMismatch` report.
- [x] 3.3h `max_members` charged under `streaming=True`: the directory walk of a
      seekable source and the members a forward pass keeps (tests: a directory over
      the limit refuses in both).
- [x] 3.4 Every fixture read through a pipe and seekably: same members after the pass,
      same files on disk, except the two divergences `design.md` names (3.3b, 3.3c),
      which 3.3g tests instead. `tests/test_zip_pipe_parity.py` runs every ZIP fixture
      under each password case; its `_DIFFERS` holds only the two
      `sevenzip/encrypted_link.zip` rows (no password, wrong password): a link the pass
      wrote as a file keeps its data's `EncryptionError` where the file read reports
      `LinkTargetNotFoundError`, with the same files on disk, as `design.md` accepts.
- [x] 3.4a What follows the members is kept and parsed by `find_end_record` and
      `CentralDirectoryWalk` (`LocalHeaderWalk.read_rest`, `ForwardTail.end_record`),
      bounded by the listing limits: a decoy end record in the comment, an entry
      whose field runs past the directory's declared size, and a wrong declared size
      give what a file read gives. The forward walk's own directory and end-record
      reader, its gap skip and `DirectorySizeMismatch` are gone. A digital signature
      record before the end records is now refused as the file read (and stdlib)
      refuses it (`dev-docs/formats/zip.md` §5).
- [x] 3.4b A member's data checked against its directory entry at the end of the pass:
      the local header's CRC, sizes and encryption flag against the central entry's; a
      short decode is `TruncatedError` in the verifier's words; a mislabelled UTF-8
      local name fails its member instead of the pass; a lone surviving ZipCrypto
      password over a codec leaves later damage to the codec; a short WinZip AES member
      is `TruncatedError` under several passwords
      (`tests/test_zip_pipe_directory_checks.py`).
- [x] 3.4c A Windows reparse buffer longer than the link cap kept as far as it declares,
      read or not (an unread encrypted one excepted), and a folder written for a member
      the directory makes a link taken back with the parents made for it
      (`tests/test_zip_pipe_reparse.py`).
- [x] 3.5 `SUPPORTS_STREAMING_NON_SEEKABLE = True`; the format-zip, `backend-registry`
      and `access-mode-and-cost` specs, `archive-reading` (ZIP applies `max_members` at
      parse) and the `ListingLimits` docstring in `config.py`, `archive-data-model` for
      `member_state_final` (and `safe-extraction` if the filter re-run needs a
      sentence); `docs/access-and-cost.md`, `docs/formats.md`; handbook §1, §2.2, §5,
      §6; `dev-docs/formats/tar.md`, `7z.md` and `rar.md` for which fields
      `member_state_final` covers there. From 3b1: `archive-reading`'s
      "`None` SHALL decode every member in-process" (a bit-3 PPMd member from a pipe
      is refused under `None`), and the same field in `new_docs/security.md`,
      `docs/extracting.md` (limits table and the PPMd paragraph); in
      `dev-docs/threat-model.md`, the residual that junk between a bit-3 codec
      member's end and its descriptor is refused from a file (DR-3) and accepted
      from a pipe (DR-5a, `design.md` §"Where a member's data ends"). From 3b3b: the
      selection made again at the end of the pass (`design.md`, "The selection is
      made again") in `docs/extracting.md` (member selection, and beside the other
      "a filter can see such a member twice" cases), the `MemberSelector`
      requirement in `archive-reading`; the bomb-limit and `abort_on` divergences in
      `docs/extracting.md` (beside the limits table), `new_docs/security.md` and
      `docs/errors-and-diagnostics.md`; and the `members_done` divergence wherever
      `on_progress` is described (`new_docs/extracting.md`). From 3b3c: the failures
      found at the end of the pass (`design.md`, same heading) and the
      `on_error="stop"` divergence in `docs/extracting.md` and the `safe-extraction`
      `OnError` requirement; `ARCHIVE_UNLISTED_DATA` in `docs/formats.md` (ZIP) and
      `new_docs/errors-and-diagnostics.md`; `format-zip` for `is_current` from the
      directory order from a pipe.
- [x] 3.5a The other live statements of the two contracts stage 3 moves (grep
      `"7z, RAR and ISO"` and `"ZIP, 7z, RAR and ISO"` before finishing; the list below
      is the 2026-10-10 result):
      - `max_members` at parse, ZIP joins (done in stage 2, which applies it at open and
        in the walk): `docs/gotchas.md` (§Limits; the
        `documentation` spec requires that residual there),
        `docs/opening-and-listing.md`, `docs/extracting.md` (the limits table and two sentences),
        `dev-docs/threat-model.md` (the recorded residual shrinks; say so),
        `exceptions.py` (`ResourceLimitError` docstring), `config.py` (both docstrings).
      - ZIP no longer has to seek: `docs/reading-members.md` (a member stream handed to
        `open_archive()`), `docs/opening-and-listing.md` (index at the end),
        `tests/test_nested_archives.py` (module docstring),
        `openspec/changes/bounded-source-spooling/proposal.md` if that change is
        still open.

## 4. Names (PR 4)

- [x] 4.1 A flagged name that is not valid UTF-8 decodes as an unflagged name, with
      `MEMBER_NAME_ENCODING_INFERRED` (`declared_encoding="utf-8"`); tests from a real
      writer where one exists (DR-24), else hand-built.
- [x] 4.2 Collisions stay ordinary duplicates (question B: keep); a test pins it.
- [x] 4.3 Spec, handbook §2.2 and §5, `docs/formats.md`; the DR-21 ruling in
      `dev-docs/design-rules.md`.

## 5. Header disagreement (PR 5)

- [x] 5.1 Cases 1 and 2 read, with a new diagnostic (name to the maintainer) and
      strict refusing; case 3 stays refused. Turn the `xfail(strict)` tests in
      `tests/test_audit_backup_scan.py` into the ruled behaviour.
- [x] 5.2 Format-zip spec, `docs/errors-and-diagnostics.md`, handbook §5, the status of
      §3.3-3.4 in `dev-docs/investigations/2026-10-backup-scan.md`.

## 6. ZIPs over 4 GiB without ZIP64 (PR 6)

- [x] 6.1 Offset correction in `CentralDirectoryWalk`, gated on a matching local header
      at the corrected offset; CRC kept; diagnostic.
- [x] 6.2 Test with a small archive whose stored offsets are reduced by 2³².
- [x] 6.3 Format-zip spec, handbook §3 and §5, `docs/formats.md`; close the `IDEAS.md`
      item.
- [x] 6.4 A member over 4 GiB under Archive Utility's fingerprint: compressed size from
      the layout, size from deflate's ratio bound or unknown until a verified read
      (`MEMBER_SIZE_WRAPPED`, `extra["size_mod_2_32"]`); from a file and a pipe.
      The new names go to the maintainer before merging.

## 7. Shrink and Implode (deferred until after 0.2.0, maintainer 2026-10-13)

- [x] 7.1 Pure-Python decoders for methods 1 and 6, registered with the codec layer.
- [x] 7.2 Fixtures from a real writer (Info-ZIP `zip` 1.x / PKZIP 1.x output or the
      scan's archives, if their licence allows), checked against `unzip`.
- [x] 7.3 The new `CompressionAlgorithm` members go to the maintainer before merging.
      `SHRINK` and `IMPLODE`, in a minor release (maintainer, 2026-10-30).
- [x] 7.4 Format-zip spec, `docs/formats.md`, handbook §2.3.
