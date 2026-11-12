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
| Refuses | A format version other than 2.x (`UnsupportedFeatureError`); a member other than `_*` before the data tar, or a data-tar member in `DEBIAN/` (`CorruptionError`) |
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
- **`DEBIAN` in the data tar is refused.** A data member at `DEBIAN` or under it raises
  `CorruptionError` naming the member (`member_name`), and so does a data hard link
  whose target is there (`member_name` and `link_target`). The listing and iteration
  raise when they reach the member, after the members before it; open does not reach it.
  Without the refusal, a data `DEBIAN/control` or `DEBIAN/postinst` would supersede the
  control tar's file of that name in the listing and in extraction, and a data hard link
  would read a control file's bytes. `dpkg-deb -R` (checked against 1.22.6,
  `src/deb/extract.c`) unpacks the data tar into the target directory first, then
  `mkdir`s `DEBIAN` for the control tar with `DPKG_TAR_CREATE_DIR` and fails with
  "unexpected pre-existing pathname" if any path exists there: a file, a directory, a
  symlink. The test is on the first segment of the name as it extracts: the root is
  dropped (GNU tar drops it), `.` and empty segments are skipped, and `..` is resolved
  (GNU tar refuses a `..` name, so `dpkg-deb -R` refuses these too). The match is
  case-sensitive: `debian/x` and `usr/DEBIAN/x` are ordinary data names, and
  `dpkg-deb -R` unpacks them. A data symlink whose target points into `DEBIAN/` is
  listed: it is a path, not a member, and `dpkg-deb -R` writes it. A hard link to
  `DEBIAN/control` fails under `dpkg-deb -R` because GNU tar finds no such file when it
  unpacks the data tar.
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
