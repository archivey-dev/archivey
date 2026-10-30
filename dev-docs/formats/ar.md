# ar

Current maintainer truth for Unix ar archives: static libraries (`.a`, Windows `.lib`) and
the outer layer of a `.deb` package. The format is a magic and then one header after
another, with no index, so archivey reads it in one forward pass, from a pipe and inside a
compression stream too. The reader is written against `archivey.formats`, the API a
format added from outside uses, and is registered as a built-in the way ISO is.

## At a glance

| | |
| --- | --- |
| Read | Yes. `internal/backends/ar_reader.py`, an `ArHandler` (`SequentialFormatHandler`) and an `ArReader` (`SequentialReader`), registered with `register_builtin_format` |
| Write | **Not shipped**, for any format ([writing design](../investigations/archive-writing-design.md)) |
| Source | A file, a stream that can seek, or a pipe (`streaming=True`). Inside any single-file compression stream (`.a.gz`, `.ar.xz`, …), as TAR is |
| Listing cost | `REQUIRES_SCANNING`, header by header |
| Access cost | `DIRECT` from a source that can seek; inside a compression stream, solid, as a compressed TAR is |
| Core dependencies | None |
| Encryption | None |
| Name encoding | Bytes. UTF-8 first, then `encoding=`, then escaped, as in every format |
| Refuses | A thin archive (`!<thin>\n`), with `UnsupportedFeatureError` |

## 1. Layout

The magic `!<arch>\n`, then each member as a 60-byte header, its data, and one `\n` pad
byte when the data length is odd. The header is ASCII and space-padded: name (16), mtime
(12, decimal), uid (6), gid (6), mode (8, octal), size (10, decimal), then `` `\n ``. A
numeric field may be blank, which lists as `None`. Every member is a file: ar has no
directories or links.

The two dialects store a name longer than 15 bytes in different places:

- **GNU** (System V, also Windows `.lib`): a short name ends with `/`. A member named
  `//` holds the long names, each ended by `/\n` (or `\0` in Windows libraries), and a
  member named `/123` takes the name at offset 123 of that table. The table comes before
  the members that use it, so the walk keeps it for the rest of the pass.
- **BSD** (and macOS): a short name is stored as it is. A member named `#1/20` has a
  20-byte name at the start of its data area, which the header's size counts.

`ArchiveInfo.extra["ar.dialect"]` is `"gnu"` or `"bsd"`, from the first name or symbol
table spelled in one dialect's own way, and absent for an archive with no members.
`ArchiveInfo.format_version` is `None`, as for TAR, whose dialects are not versions either.

## 2. What archivey does with the oddities

- **Symbol tables** (`/`, `/SYM64/`, `__.SYMDEF` and its `SORTED` and `_64` forms) are the
  linker's index, not files. The walk skips them, and
  `ArchiveInfo.extra["ar.symbol_table"]` says whether one was there. Like `ar.dialect`, it
  says what the walk has seen so far: in a streaming pass over an archive with the table
  after a file, it turns true when the walk reaches the table. GNU ar and llvm-ar write
  it first.
- **macOS padding.** macOS ar pads each member with `\n` so the next header starts on 8
  bytes, and counts that padding in the member's size. The padding is then part of the
  member, as llvm-ar and bsdtar extract it.
- **NUL-padded BSD names.** llvm-ar pads a name stored in the data area with NULs; the
  NULs are not part of the name.
- **A missing last pad byte** is harmless: some writers leave it off.
- **Numbers padded on the left** are read, as GNU ar reads them with `strtol`. A sign is
  refused.
- **A timestamp past `datetime`'s range** (12 decimal digits reach the year 33658) lists
  as `modified=None`.

## 3. Damage and limits

The reader refuses, with `CorruptionError`: a header without its `` `\n `` end, a numeric
field that is not a number in its base (`8` or `9` in the octal mode), a member with no
size or no name, a long-name reference before the table or past its end, a second
long-name table, and a BSD name over 64 KiB or longer than its member. An archive that
ends inside its magic, a header or a member's data raises `TruncatedError`; the members
before the cut stay readable in a pass.

The long-name table is held for the whole walk, so it is charged to
`ListingLimits.max_metadata_bytes`: a larger table raises `ResourceLimitError`. archivey
reads and skips member data itself, and checks each member's length, as for every
format read through `archivey.formats`.

## 4. Tests and fixtures

`tests/test_ar.py`, against `tests/fixtures/ar/`: archives written by GNU ar 2.42, bsdtar
3.7.2 and llvm-ar 18, and a thin archive. `tests/fixtures/ar/make-archives.sh` writes
them again. The same test checks that the reader imports only archivey's public names,
apart from `register_builtin_format`, so it stays an example of a format written against
`archivey.formats`. The Atheris target `ar` fuzzes the walk, plain and inside gzip. The
libarchive and Commons Compress corpus harnesses compare it with those libraries; on
2026-10-28 it matched libarchive and arpy on every archive both read.
