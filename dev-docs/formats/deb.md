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
  segment counts: `usr/DEBIAN/x` and `debianx/x` are ordinary data names.

  **Data symlinks are followed too** (maintainer's call, 2026-11-17, on a sweep finding
  against #1531: "Refuse those symlinks too"). Extraction writes a member through a
  symlink the archive made, so `foo -> DEBIAN` then `foo/control` overwrote
  `DEBIAN/control` under `overwrite="replace"`, and a read of `x -> DEBIAN/control`
  returned the control file. `deb_reader._DataTree` keeps the data tar's symlinks in a
  trie of folded names and resolves each path one segment at a time: `..` climbs, a
  segment that names a symlink is replaced by its target (from the symlink's directory,
  or from the root when the target is rooted), and at most 40 targets are followed, as
  Linux does. A data symlink whose target lands in `DEBIAN` is refused
  (`member_name` and `link_target`), and so is a member or a hard link target that lands
  there through an earlier symlink (`d -> .`, then `d/DEBIAN/control`).

  A later symlink can move an earlier one's target: `x -> y/DEBIAN/control` names a
  data path until `y -> .` arrives. As extraction's `LinkWatch` does, the tree keeps a
  dependency index (`internal/dependency_index.py`, shared with `LinkWatch`) of the
  paths each target's resolution looked up, and a new symlink resolves again only the
  targets that looked up its path. The new symlink, the one that completes the crossing,
  is refused: re-checking at the end of the data tar would be too late, because
  extraction has already written `x`. Each later symlink can move every earlier one, so
  a crafted tar makes this links x links resolutions; the path steps count against
  `ListingLimits.max_members` and the walk raises `ResourceLimitError` when they cross
  it (maintainer's call on #1607: a re-check with a work cap, following `LinkWatch`,
  which bounds its rechecks by `ExtractionLimits.max_entries`). The unit is a path step,
  not a resolution as in `LinkWatch`: one resolution here can follow 40 symlinks, so
  counting resolutions would allow 40 times the work. Since a symlink may not replace
  another, the hostile shape is N symlinks through `a0/a1/.../aR`, then `a0 -> .`,
  `a1 -> .` and so on. Measured on the tree alone at the default limit (2026-11-17):
  600 x 600 stops in 0.98 s (21.9 s with no limit), 1,000 x 1,000 in 2.9 s. 20,000
  ordinary `usr/lib` symlinks list in 0.26 s with no recheck. No real package comes
  near the limit: a recheck happens only when a later symlink sits on an earlier
  target's path.

  Any resolution, not only a recheck, is charged for the steps it takes inside a target
  it follows (review K5 on #1607). Each of 40 follows pushes the whole target it
  follows, and every symlink routed through it walks it again, so N short symlinks
  through 40 long ones cost N x 40 x K steps from a tar of N + 40 K segments, which xz
  shrinks to almost nothing: an 11 KB package listed for 49 s. The walk over a path's
  own segments stays free, so `libfoo.so -> libfoo.so.1` costs nothing and a symlink
  that follows `lib -> usr/lib` costs 2. Measured (2026-11-17, `reader.members()`,
  default limits): that 11 KB package is refused in 0.25 s; 100,000 symlinks that each
  follow `lib -> usr/lib` list in 11.8 s, most of it tar parsing, using 200,000 of the
  262,144 steps. The index still costs memory per recorded path step, which is linear in
  the stored target text: 50,000 symlinks through a 40-symlink route take 4.9 s and 293
  MiB before the cap stops the rechecks.

  This is stricter than `dpkg-deb -R`, which unpacks the data tar first, so there such a
  symlink points at nothing and `DEBIAN` is made after it only if nothing is there. The
  other option, leaving symlinks alone and narrowing "the two tars stay apart" to names
  and hard links, was rejected: the bypass writes a control file on disk. Reopen if a
  real package ships a data symlink into `DEBIAN`.

  **Every selection, not only the whole tar.** A caller can extract a subset of the
  members, so the tree's verdict has to hold for each subset. Two review findings on
  #1607 showed it did not:
  - K2: `y -> a/b`, then `y/`, then `y/z -> ../DEBIAN`, then `y/z/control` was listed,
    and `y/z/control` overwrote `DEBIAN/control` under `overwrite="replace"`. Which of
    a directory and a symlink at one path extraction keeps depends on the policy:
    `replace` keeps the second, and `skip` and `rename` keep the first (measured
    2026-11-17, file and pipe sources).
  - The same tar without the directory, extracted with `members=` leaving `y` out:
    extraction makes `y` a directory for `y/z`, which then points at `DEBIAN`, and
    `replace` wrote `y/z/control` into `DEBIAN/control`.

  So the reader keeps every path's meaning independent of the selection and the
  policy. It refuses a member under a symlink of the same tar (real packages have
  none: `dpkg-deb` builds the tar from a tree, and tar records a symlinked directory
  as the symlink), and it refuses a symlink at the path of a directory, a member's
  parent or another symlink, and a directory at a symlink's path. A symlink left out
  of a selection then leaves nothing at its path, and the kernel fails a path through
  it rather than sending it elsewhere. A file or hard link at a symlink's path
  replaces the symlink under every policy when both are extracted, but not when the
  file is left out, so the tree keeps the symlink; a path through a file fails on disk
  too. A symlink's target is checked twice: through the tree, as the filesystem
  follows it, and lexically from the symlink's directory, as a read of the symlink
  resolves it (`resolve_link_target_name`). `y -> a/b`, then `x -> y/../DEBIAN/control`
  is refused on the second: the read returned the control file.

  A hard link whose target is a symlink, through any number of hard links, extracts as
  a symlink with the same target text, read from the hard link's own directory
  (`extraction.py` `_as_written`, as GNU tar does). The tree records it as that
  symlink, through the same `add_symlink` and recheck path (review K4 on #1607: `q/h`
  linked to `a/b/x -> ../DEBIAN` left `q/h -> ../DEBIAN`, and `s -> .`, `h` linked to
  `s`, then `h/DEBIAN/postinst` wrote a maintainer script under the default policy).

  The other option was to track each view in its own tree and refuse when any lands
  in `DEBIAN`. A caller's selection is any subset, so the views multiply, and nothing
  real needs them. To see a symlink over a directory that only a member's parent made
  (`y/f`, then `y -> a/b`), the tree keeps a node for every directory and member
  parent, not only for symlinks: on 10,000 directories of 10 files each that costs 1.9
  MiB and 0.49 s against 0.35 s for the walk alone (the tree only, 2026-11-17).

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
- With `open_archive(salvage=True)`, a damaged ar header after `debian-binary` starts
  the ar search (`dev-docs/formats/ar.md` §2.2): a found `control.tar*` or `data.tar*`
  is read, and each of its members is listed with `MEMBER_FOUND_BY_SCAN`. The tars
  themselves are read as they are.

## 4. Tests

`tests/test_deb.py`: the `dpkg-deb` fixtures (`fixtures/deb/make-archives.sh`, xz, gzip
and zstd) from a file and a pipe, random access and seeking, detection and the raw ar
view, every compression `dpkg-deb` reads (built in the test), the MD5 checks, and each
refusal, among them the data-tar names in `DEBIAN/` that `dpkg-deb -R` refuses and
the `DEBIAN` names it accepts.
