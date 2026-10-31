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
| Listing cost | `REQUIRES_SCANNING`, header by header; inside a compression stream, `REQUIRES_DECOMPRESSION`, as a compressed TAR is |
| Access cost | `DIRECT` from a source that can seek; inside a compression stream, `SOLID`, as a compressed TAR is |
| Core dependencies | None |
| Encryption | None |
| Checksums | None. Damage shows only as a header that does not parse |
| Name encoding | Bytes. UTF-8 first, then `encoding=`, then escaped, as in every format |
| Refuses | A thin archive (`!<thin>\n`), with `UnsupportedFeatureError` |
| Spec | `openspec/specs/format-ar/spec.md` |

Not here, though a reader might look for it: `ArchiveInfo.format_version` is always
`None` (the dialect is in `extra["ar.dialect"]`, §6), the symbol table's contents are not
exposed, and the members of a thin archive are not followed to the files it names.

## 1. Shape

- **A magic, then headers back to back, and nothing at the end.** `!<arch>\n`, then each
  member as a 60-byte header, its data, and one `\n` pad byte when the data length is
  odd. With no index and no trailer, listing is a walk, the walk works on a pipe, and an
  archive cut on a header boundary is indistinguishable from a shorter whole one.
- **The header is ASCII, space-padded, fixed width.** Name (16), mtime (12, decimal), uid
  (6), gid (6), mode (8, octal), size (10, decimal), then `` `\n ``. A numeric field may
  be blank, which lists as `None`. Every member is a file: ar has no directories or
  links, so a member's mode is never trusted to make one.
- **Two dialects, told apart by how a long name is stored.** Names longer than 15 bytes
  do not fit, and the dialects put them in different places:
  - **GNU** (System V, also Windows `.lib`): a short name ends with `/`. A member named
    `//` holds the long names, each ended by `/\n` (or `\0` in Windows libraries), and a
    member named `/123` takes the name at offset 123 of that table. The table comes
    before the members that use it, so the walk keeps it for the rest of the pass.
  - **BSD** (and macOS): a short name is stored as it is. A member named `#1/20` has a
    20-byte name at the start of its data area, which the header's size counts, so its
    data starts after the name.

  Nothing in the magic says which dialect follows, so the dialect is known only once the
  walk reads a name or symbol table spelled in one dialect's own way.

## 2. The pipeline here

### 2.1 Identify

`!<arch>\n` at offset 0 is exact magic, and `!<thin>\n` at 0 is claimed too, so a thin
archive is refused by name rather than with `FormatDetectionError`. Inside a compressor,
the inner-container probe finds `!<arch>\n` in the first decoded bytes as it finds TAR's
`ustar`. The extensions are `.a`, `.ar` and `.lib`. Nothing here is a content probe.

### 2.2 Open and list

The walk (`ArReader.walk`) reads each header, resolves the name, and yields one member
per file:

- **Symbol tables** (`/`, `/SYM64/`, `__.SYMDEF` and its `SORTED` and `_64` forms, as a
  name field or as a BSD `#1/` name) are the linker's index, not files. The walk skips
  them, and `ArchiveInfo.extra["ar.symbol_table"]` says whether one was seen.
- `extra["ar.dialect"]` is `"gnu"` or `"bsd"`, from the first name or symbol table spelled
  in one dialect's own way, and absent for an archive with no members.
- Both keys say what the walk has seen so far: in a streaming pass over an archive with
  the table after a file, `ar.symbol_table` turns true when the walk reaches it. GNU ar
  and llvm-ar write it first.
- mtime, uid, gid and mode map to the member's fields; a blank field is `None`, and a
  timestamp past `datetime`'s range (12 decimal digits reach the year 33658) is
  `modified=None`.

### 2.3 Member data

Nothing here is format-specific: a member's data is the span after its header (after the
name, for a BSD `#1/` member), and archivey reads and skips it itself, checking each
member's length, as for every format read through `archivey.formats`.

### 2.4 Extract

Nothing here is format-specific. Every member is a `FILE`, and names go through the same
extraction rules as every format's.

### 2.5 Write

Not shipped.

## 3. In the wild

- **GNU ar** (binutils) writes the GNU dialect with a `/` symbol table first.
- **llvm-ar** writes either dialect (`--format=gnu|bsd|darwin`), and pads a name stored
  in the data area with NULs; the NULs are not part of the name.
- **macOS ar** pads each member with `\n` so the next header starts on 8 bytes, and
  counts that padding in the member's size. The padding is then part of the member, as
  llvm-ar and bsdtar extract it.
- **Windows `.lib`** is the GNU dialect with `\0`-ended long names.
- **`.deb`** packages are GNU-dialect ar archives holding `debian-binary`,
  `control.tar.*` and `data.tar.*`.
- Some writers leave off the last pad byte, which is harmless. Some pad numbers on the
  left; GNU ar reads them with `strtol`, and so does archivey.
- **Corpus evidence.** On 2026-10-28 the reader matched libarchive and arpy on every
  archive both read.

## 4. Threat surface

ar names are archive-controlled bytes like any format's, and go through the same
extraction rules ([`threat-model.md`](../threat-model.md)). The format-specific surface is
memory a header can ask for:

- The `//` long-name table is held for the whole walk, so it is capped at
  `ListingLimits.max_metadata_bytes` on its own: a larger table raises
  `ResourceLimitError`. The cap is a separate check, not a share of the listing's
  running count: the table is held beside the member names, which the listing
  counts as usual.
- A BSD name is read into memory before the member, so it is bounded: over 64 KiB, or
  longer than its member, is `CorruptionError` before it is read.
- Size fields are parsed but never allocated; member data is streamed by the framework.

## 5. Sharp edges

| What you see | Where | More |
| --- | --- | --- |
| `extra["ar.symbol_table"]` is `False` partway through a streaming pass, then `True` | **format** | The table is a member like any other; it is only conventionally first (§2.2) |
| A thin archive raises `UnsupportedFeatureError` | **archivey** | Its members are paths outside the archive; following them would read files the caller did not hand over (§6) |
| An archive cut exactly between members lists as complete | **format** | There is no trailer or count to compare against (§1) |
| A macOS member is a few bytes longer than the file that went in | **format** | The `\n` padding is counted in the member's size (§3) |
| `format_version` is `None` | **archivey** | The dialect is in `extra["ar.dialect"]` (§6) |

## 6. Decisions

- **Built in, not a separate package.** The maintainer's call (2026-10-28): with
  explicit `register_format()` and no entry-point autoload, a package needs an install
  and a registration call, which breaks one library for every format. The reader still
  imports only public names (apart from `register_builtin_format` and the `override`
  decorator), so it stays an
  example of a format written against `archivey.formats`.
- **The dialect goes in `extra["ar.dialect"]`, not `format_version`.** A dialect is not
  a version, and TAR, whose dialects (v7, ustar, GNU, PAX) are the nearest precedent,
  reports `format_version=None`.
- **Symbol tables are skipped, not listed.** They are the linker's index, rewritten by
  `ranlib`, and every other reader (GNU ar `t`, bsdtar, llvm-ar) hides them.
- **macOS padding stays part of the member.** It is counted in the size, and llvm-ar and
  bsdtar extract it; trimming would need a guess about which trailing `\n` are padding.
- **Thin archives are refused, not followed.** Following a member to a path outside the
  archive would turn a read of one file into reads of others.
- **A 64 KiB cap on a BSD name, as a module constant.** Structural, not policy: no file
  system takes a path that long, and the cap keeps a damaged length from growing one
  buffer to the member's size. It has its spec row (DR-9).

## 7. Open questions

None are open.

## 8. Verify

```bash
./scripts/test.sh tests/test_ar.py
```

The fixtures in `tests/fixtures/ar/` were written by GNU ar 2.42, bsdtar 3.7.2 and
llvm-ar 18 (`--format=darwin`); `tests/fixtures/ar/make-archives.sh` writes them again.
Windows long names, blank fields and damaged headers are built in the tests. The Atheris
target `ar` fuzzes the walk, plain and inside gzip, and the libarchive and Commons
Compress corpus harnesses compare the reader with those libraries.

## 9. References

- The ar format has no standard. FreeBSD
  [`ar(5)`](https://man.freebsd.org/cgi/man.cgi?query=ar&sektion=5) describes both
  dialects; binutils `bfd/archive.c` is GNU's.
- llvm-ar's [`--format`](https://llvm.org/docs/CommandGuide/llvm-ar.html) options and its
  darwin padding.
- `openspec/changes/plugin-api/tasks.md` §3a, the reader's history as a plugin.
