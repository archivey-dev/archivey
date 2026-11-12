# Debian packages

Current maintainer truth for `.deb` (and `.udeb`, `.ddeb`) packages. A package is an ar
archive of three members; archivey lists it as the files it installs, with the control
files under `DEBIAN/`, the tree `dpkg-deb -R` unpacks. The reader is a built-in written
against `archivey.formats`, and the first user of the nested-archive hook
(`ForwardStream.take` and `ReaderContext.open_nested`): it reads both tars with archivey's
own TAR reader, in the one forward pass.

## At a glance

| | |
| --- | --- |
| Read | Yes. `internal/backends/deb_reader.py`, a `DebHandler` (`SequentialFormatHandler`) and a `DebReader` (`SequentialReader`), registered with `register_builtin_format` before ar |
| Write | **Not shipped**, for any format ([writing design](../investigations/archive-writing-design.md)) |
| Source | A file, a stream that can seek, or a pipe (`streaming=True`) |
| Listing cost | `REQUIRES_DECOMPRESSION`: listing reads both tars (`is_solid=True`) |
| Access cost | `SOLID`: a member is reached by walking the package, and its tar, from the start |
| Core dependencies | None for xz, gzip, bzip2 and LZMA tars; a Zstandard tar needs what a `.zst` file needs |
| Encryption | None |
| Checksums | MD5 per installed file, from `DEBIAN/md5sums`, in `member.hashes` and checked on a full read |
| Name encoding | Bytes, as TAR's: UTF-8 first, then `encoding=`, then escaped |
| Refuses | A format version other than 2.x (`UnsupportedFeatureError`); a member other than `_*` before the data tar, a data-tar member in `DEBIAN/`, or a control-tar member outside it (`CorruptionError`) |
| Spec | `openspec/specs/format-deb/spec.md` |

Not here, though a reader might look for it: the old pre-ar format (`0.939000`), signature
checking (a `_gpgorigin` member is skipped, not verified), `conffiles` and the other
control files beyond `control` and `md5sums` (listed, not parsed), and a `.deb` inside a
compression stream (detected as `deb.gz` and so on, as any sequential format is, but no
tool writes one).

## 1. Shape

- **An ar archive, in a fixed order.** `debian-binary` (`"2.0\n"`), then
  `control.tar[.gz|.xz|.zst]`, then `data.tar[.gz|.xz|.zst|.bz2|.lzma]`. `dpkg-deb`
  writes short names with no slash; GNU ar would end them with `/`, and both read.
- **Members starting with `_`** may sit between them: `dpkg-sig` adds `_gpgbuilder`, and
  debsigs `_gpgorigin`. `dpkg-deb` skips them.
- **The control tar comes first**, so `md5sums` is known before any data file: the walk
  can attach each file's digest when it lists it, with no second pass.

## 2. The pipeline here

### 2.1 Identify

The ar magic followed by the first member's name field, `debian-binary` padded with
spaces (or `debian-binary/`), is exact magic at offset 0, 24 bytes long. The deb module is
imported before ar's in `internal/backends/__init__.py`, because the first magic that
matches wins and ar's `!<arch>\n` matches a package too. The extensions are `.deb`,
`.udeb` and `.ddeb`. An explicit `format=ArchiveFormat.AR` still reads the ar layer.

### 2.2 Open and list

`DebReader.walk` checks the ar magic, reads `debian-binary` (its size counted against
`max_metadata_bytes` before the read, since `dpkg-deb` allocates whatever the header
gives; the major version must be 2: `dpkg-deb` reads 2.x and refuses others, and the
digits are compared as bytes, since `int()` refuses more than 4300 of them), skips `_`
members, and hands each tar to `open_nested` through `stream.take(size)`:

- **Control tar.** Each member is renamed under `DEBIAN/`; the tar's `./` root becomes
  `DEBIAN/` itself. `control` and `md5sums` are read whole as they pass (their size first
  charged with `ReaderContext.charge_metadata`, so they count against
  `max_metadata_bytes` with `debian-binary` and the members listed so far, once, on the
  listing walk; a walk started over to reach a member read out of order charges nothing,
  and the charge comes off when the listing ends), and the span is yielded with those
  bytes as its data. `control`'s first paragraph gives `extra["deb.package"]`,
  `["deb.version"]` and `["deb.architecture"]`; `md5sums` gives a name-to-digest map,
  read a line at a time, each entry charged as it is added: its name at the width
  CPython stores it (1, 2 or 4 bytes a character, so one emoji makes a long name four
  times its UTF-8 bytes), its digest and its share of the dict.
  Open takes only the first walk step (the control tar's `./`), so the `deb.*` keys are
  missing on every source until the listing or iteration reaches `control`.
- **Data tar.** Members keep their names (the tar's `./` root lists as `.`, as reading the
  tar alone gives). A `FILE` whose normalized name is in the map gets
  `hashes[HashAlgorithm.MD5]`, which the read path checks as it checks any listed digest.
  A hard link's target is normalized, so it names the member the listing has.
- **The two tars stay apart.** A data member that extracts to `DEBIAN` or under it
  raises `CorruptionError` naming the member (`member_name`), and so does a data hard
  link whose target does (`member_name` and `link_target`). A control member whose
  prefixed name extracts outside `DEBIAN/` (`../usr/x` lists as `DEBIAN/../usr/x`)
  raises the same way, and so does a control hard link whose prefixed target does. The
  listing and iteration raise when they reach the member, after the members before it;
  open does not reach it. Without the refusal, a data `DEBIAN/control` or
  `DEBIAN/postinst` would supersede the control tar's file of that name in the listing
  and in extraction, a control member would land in the data tree under
  `sanitize_names`, and a hard link would read the other tar's bytes.

  `dpkg-deb -R` (checked against 1.22.6, `src/deb/extract.c`) unpacks the data tar into
  the target directory first, then `mkdir`s `DEBIAN` for the control tar with
  `DPKG_TAR_CREATE_DIR` and fails with "unexpected pre-existing pathname" if any path
  exists there: a file, a directory, a symlink. GNU tar refuses a `..` name in either
  tar, and finds no data `DEBIAN/control` for a data hard link to point at.

  The tests share their path handling with extraction. `filters.extracted_top_segment`
  gives the first segment of the path a name can extract to: the root is dropped (a
  drive root too), `..` is resolved as `sanitize_names` resolves it, and both `/` and
  `\` separate segments. The control side compares that segment with `DEBIAN` exactly.
  The data side compares `filters.extracted_top_key`, the same segment folded as the
  extraction collision key folds a name (NFC, case-folded, a trailing dot or space
  trimmed), with the folded `DEBIAN`. The control side is not folded, because folding
  would accept a control `../debian/x`, which is a data path on Linux. Only the first
  segment counts: `usr/DEBIAN/x` and `debianx/x` are ordinary data names. A data
  symlink whose target points into `DEBIAN/` is listed: its target is a path, not a
  member, and `dpkg-deb -R` writes it.

  Some data names are refused that `dpkg-deb -R` unpacks, because GNU tar on Linux
  writes them byte for byte, under a literal directory:
  - `usr\..\DEBIAN/x`: `sanitize_names`, and Windows, read the backslashes as
    separators and put it in `DEBIAN/`.
  - `C:/DEBIAN/x`: extraction drops the drive root on every OS.
  - `DEBIAN./x` and `DEBIAN /x`: `STRICT`, the default policy, trims the dot or space,
    and so does Win32.
  - `debian/x`, and any other case spelling: a case-insensitive filesystem (Windows,
    and macOS by default) makes it one directory with `DEBIAN/`, and extraction's
    collision key already treats it so. **A package whose data tar installs a
    `debian/` directory is refused.**

  Each factor in [`design-rules.md`](../design-rules.md) §"When consistency and the
  official tool disagree" points to refusing these: listing them would break the
  promise that the control files are the control tar's (DR-5: one archive extracts the
  same way on every OS, or is refused everywhere), the lenient reading would weaken
  this check, and only a crafted package holds such a name.
- **After the data tar** the walk stops, as `dpkg-deb` does: trailing members and bytes
  are not read.

Every inner span is yielded, in order, so the inner reader's member numbers match the
outer listing (`open_nested`'s contract), and the outer listing checks every name once.

### 2.3 Member data

Nothing deb-specific: `open_nested` hands each inner member's decoded stream through as
`MemberSpan.data`. Random access walks the package again from the start
(`AccessCost.SOLID`).

## 3. Damage

- A cut package raises `TruncatedError` from the ar layer, or what the TAR reader or
  the decompressor raises inside a tar.
- A wrong MD5 raises `CorruptionError` when a read reaches the member's end.
- A malformed `md5sums` line (not 32 hex digits, a space and a name) is skipped:
  `dpkg --verify` skips it too, and the file it would cover is then listed with no digest.

## 4. Tests

`tests/test_deb.py`: the `dpkg-deb` fixtures (`fixtures/deb/make-archives.sh`, xz, gzip
and zstd) from a file and a pipe, random access and seeking, detection and the raw ar
view, every compression `dpkg-deb` reads (built in the test), the MD5 checks, and each
refusal, among them the data-tar names in `DEBIAN/` that `dpkg-deb -R` refuses and
the `DEBIAN` names it accepts.
