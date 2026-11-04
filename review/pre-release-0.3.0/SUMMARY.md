# Summary — pre-release bug sweep for 0.3.0

Run 2026-11-04 against `main` @ `f3d1b616`, per [`brief.md`](brief.md). The tests
land in this pull request. The library code does not change.

## Headline

Two crafted archives return another member's bytes. Both are pinned with
`xfail(strict=True)` tests that assert the stored bytes. Two doc sentences do
not match the code. One Windows path shape was not reproduced on this Linux
host. Diagnostic codes match the `DiagnosticCodeStr` list, and every code is
referenced from `src/`.

Baseline, `[all]` only: `./scripts/check.sh --fix` passed.
`./scripts/test.sh` reported 19872 passed, 405 skipped, 2 xfailed.
`./scripts/test.sh --all-configs` was not run. The diff does not reach an
optional library.

## Findings

| # | Severity | Where | What a caller sees | Status |
|---|---|---|---|---|
| F1 | high | `squashfs_reader.py` `fragment_tail` | Two fragment-table entries name one block and disagree on compression. The second read returns the first entry's bytes, or raises `CorruptionError` if the cached block is shorter | Open. `test_two_fragment_entries_at_one_offset_keep_their_own_bytes` |
| F2 | high | `cpio_reader.py` newc/crc link group | Two headers share a device and inode and both store data. A read of the later name returns the earlier bytes. 7-Zip 23.01 extracts both payloads | Open. `test_each_newc_name_in_one_inode_reads_the_bytes_stored_with_it` |
| F3 | low | `docs/formats.md` zstd detection | The page says detection reserves a 2 GiB window with no cap. The probe caps the window at 128 MiB | Open. Existing `test_tar_zst_probe_caps_the_window` pins the code |
| F4 | low | `docs/formats.md` device files | The shared paragraph omits SquashFS. The format lists a device, FIFO, or socket as `OTHER`, and extraction blocks it | Open. Existing `test_lists_and_reads_every_member` pins the types |

### F1. SquashFS fragment cache returns the wrong bytes

**Where:** `src/archivey/internal/backends/squashfs_reader.py:494`
(`fragment_tail`). The cache write is line 505.

**What happens.** The fragment table can hold two entries for one start
offset. One entry says the block is stored. The other says the same bytes are
a zlib stream. `fragment_tail` keeps the decoded block in
`self._fragments[start]` and does not record the stored size or the
compression flag.

Read the stored file first. The compressed file then returns the stored bytes.
`dec` is the first five bytes of the zlib frame, not `b"HELLO"`. Read the
compressed file first. The stored file raises `CorruptionError`: `a file's
tail runs to byte 13 of a 5-byte fragment`.

DR-1 ranks a wrong answer as the worst failure. A real `mksquashfs` image
points every file in a block at one table entry, so this needs a crafted
image. The image in the test is built in the test.

**Test:** `test_two_fragment_entries_at_one_offset_keep_their_own_bytes` in
`tests/test_squashfs.py`. It reads `raw` first, then `dec`, and expects the
zlib frame and `b"HELLO"`.

**Confidence:** high. Reproduced on this host.

### F2. A newc name that stores its own data reads the earlier link

**Where:** `src/archivey/internal/backends/cpio_reader.py:248`.

**What happens.** Two newc headers share a device and inode, with `nlink` above
1, and both have a non-zero file size. The first name becomes the `FILE`. The
later name hits `group.name is not None`, becomes a `HARDLINK` to the first
name, and its payload is skipped. `read("late")` returns the earlier bytes.

7-Zip 23.01 lists both names as files, extracts `EARLY` and `LATE!!`, and
warns `Headers Error`. The handbook
([`dev-docs/formats/cpio.md`](../../dev-docs/formats/cpio.md) §2.2) describes
empty newc links held until the one link that stores the data. It describes
a skipped later payload for binary and odc, not for newc. The crc variant
uses the same branch (`_defers_link_data`).

The test asks for each header's own bytes. A fix that raises
`CorruptionError`, or that keeps only the last payload, still fails that
test. Which of those is the right fix is [`QUESTIONS.md`](QUESTIONS.md) Q1.

**Test:** `test_each_newc_name_in_one_inode_reads_the_bytes_stored_with_it` in
`tests/test_cpio.py`.

**Confidence:** high for the wrong bytes. The choice of fix is Q1.

### F3. User docs say zstd detection reserves a 2 GiB window

**Where:** `docs/formats.md:1332`. Code:
`src/archivey/internal/streams/codecs/zstd_codec.py:105`
(`_PROBE_WINDOW_LOG = 27`).

**What happens.** The page says detection reads a sample with no cap, so a
frame that declares 2 GiB reserves that much address space whatever the cap.
`_probe_window_log_max` caps a detection probe at window log 27 (128 MiB).
The handbook page `dev-docs/formats/zstd-lz4.md` matches the code. The code
is the behaviour to keep. The sentence in `docs/formats.md` is stale.

**Test:** none added. `test_tar_zst_probe_caps_the_window` in
`tests/test_probe_dictionary_clamp.py` already expects a window log of 31 to
stay a bare `.zst`.

**Confidence:** high.

### F4. The shared device-file paragraph omits SquashFS

**Where:** `docs/formats.md:235`. The SquashFS section is line 1110.

**What happens.** The shared paragraph names ZIP, 7z, RAR, ISO, CPIO, and TAR.
SquashFS lists a device, FIFO, or socket as `MemberType.OTHER`. Extraction of
`uncompressed.sqfs` blocks `blk`, `chr`, and `fifo` with `Special file
(device/FIFO/socket) not allowed` and does not create them. The format
section already says they read as `OTHER`. The shared paragraph does not
mention SquashFS.

**Test:** none added. `test_lists_and_reads_every_member` already checks the
three types.

**Confidence:** high.

## Coverage tests

These passed. Each guards a behaviour that was checked and had no test.

| Test | What it guards |
|---|---|
| `test_a_symlink_stays_unlocked_when_the_trailer_raises_the_files` | A symlink in a `.tar.gz` stays at `UNLOCKED` after the gzip trailer raises every file to `CHECKSUM` |
| `test_a_gzip_fname_with_parent_segments_is_not_the_extract_path` | A gzip FNAME of `../outside.txt` stays in `extra`. Extraction writes the archive's own name inside the destination |

## What is actually fine

Checked on this host, and not filed. An existing test is named where one
already pins the behaviour.

- `..` and an absolute member name are refused or re-rooted. An absolute
  symlink target outside the destination is refused. The `l -> a/../secret`
  then `a -> .` case removes `l`.
- A ZIP member with a bad CRC raises `CorruptionError` and extraction leaves
  no file. A bad gzip CRC raises `CorruptionError`. A cut gzip raises
  `TruncatedError`.
- A stored ZIP seek that jumps bytes leaves `verified` at `LENGTH`. A seek
  back to the start and a read to the end reaches `CHECKSUM`. That matches
  DR-4a and `docs/errors-and-diagnostics.md`.
- A CPIO crc file with a bad checksum raises `CorruptionError`.
- `DiagnosticCode` and `DiagnosticCodeStr` list the same codes. Every enum
  member is referenced as `DiagnosticCode.<NAME>` from `src/`.
- 7z and RAR charge key-derivation cost before the hash runs. ZipCrypto AES
  uses a fixed 1000 rounds, which the docs do not put in the KDF budget.
- `ArchiveSource.bytes_reached` does not count a seek until a later read.
- A hard link to a later member fails, and `on_error=continue` still writes
  the later file. `test_a_hardlink_to_a_later_member_still_fails` pins that.
  It matches DR-2.
- Duplicate ZIP names: streaming and random-access extraction both leave the
  last payload on disk.
- A solid RAR reads the later member first and returns that member's bytes.
- Opening and closing ZIP, `.tar.gz`, RAR, and 7z in a loop did not grow the
  process fd count.
- A cut ZIP, gzip, ar, or CPIO raises `TruncatedError` or
  `FormatDetectionError`. None of those probes raised a bare `struct.error`
  or `AssertionError`.

## SUSPECTED

**TRUSTED extraction of a dots-and-spaces segment on Windows.**
`apply_name_policy` returns a `TRUSTED` member unchanged
(`src/archivey/internal/filters.py:837`). `check_universal` refuses a segment
that is exactly `..` (line 469). A segment of only dots and spaces (`.. `,
`...`) is refused for `STRICT` and `STANDARD` (line 875) and kept for
`TRUSTED`. On Windows, Win32 strips trailing spaces and dots, so
`foo/.. /x` can leave the destination. This host is Linux. There `.. ` is a
literal name and the write stays inside the destination. No test. A test
that expects a block would fail here because the write stays inside the
destination. See [`QUESTIONS.md`](QUESTIONS.md) Q3.

## Disagreement with design

**A sized read of a cut member returns short and does not raise.**
`docs/errors-and-diagnostics.md` describes it, and ADR 0014 records it.
`stream.read(member.size)` can return fewer bytes than the member should
hold. The next read raises `TruncatedError`. A caller that reads once and
stops treats a cut member as complete. `read()` with no size already raises.
I would raise from the sized read that cannot fill the declared size. The
docs keep the short return on purpose. No test. See
[`QUESTIONS.md`](QUESTIONS.md) Q2.

## Coverage of the sweep

Read closely enough to file or drop a finding:

- Extraction name and link checks, including the link-watch case above.
- SquashFS fragment cache, special-file extraction, and a pipe refusal
  (existing tests).
- CPIO newc hard-link grouping when both names store data.
- gzip CRC, truncation, FNAME, and a seek that does not move.
- ZIP stored seek, duplicate names, and a bad CRC on extract.
- Verification levels on a `.tar.gz` file, directory, symlink, and sparse
  file (the sparse case is the existing test).
- Diagnostic code enum against `DiagnosticCodeStr` and against
  `DiagnosticCode.` references in `src/`.
- 7z and RAR KDF charging, and `bytes_reached`.

Not read line by line: the ISO multi-extent walk past the cut-extent fix, the
RAR encryption paths, and the 7z folder-CRC path past the tests that already
cover them.
