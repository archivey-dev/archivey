# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

Entries are written at release time, not by each pull request: new features, public
API changes and security fixes get a line each, and other bug fixes are summarized in
one line. How to write the entry: see
[`dev-docs/release-checklist.md`](dev-docs/release-checklist.md).

## [Unreleased]

## [0.4.0] - 2026-11-14

A minor release: more formats built in, archives read by range from fsspec URLs and
browsed as an `archivey://` file system, self-extracting programs read the way their own
tools read them, limits that hold across nested archives, and the 0.3.0 deprecations
removed.

### Added

- archivey reads RPM packages, Debian packages (`.deb`, listed as the files they
  install), Microsoft cabinets (`.cab`, with a pure-Python LZX decoder), XAR archives
  and macOS `.pkg` files, LHA and LZH archives (`.lzh`, `.lha`), ARJ archives (`.arj`),
  raw CD images (`.bin` with a Mode 1 or Mode 2 Form 1 data track, or a whole disc
  through its `.cue` sheet), makeself installers (`.run`), uuencode and base64 text
  (`.uu`, `.b64`, so a `.tar.uu` lists the tar) and Firefox `.mozlz4` files as built-in
  formats. bzip3 files (`.bz3`, `.tar.bz3`) need the new `[bzip3]` extra.
- ZIP members compressed with Reduce (methods 2 to 5) and PKWARE DCL Implode (method 10)
  are supported, so archivey now reads every compression method that DOS-era ZIP writers
  used.
- `open_archive()`, `open_stream()` and `detect_format()` accept an fsspec `OpenFile`
  (what `fsspec.open(url)` returns) and read it with range requests. A multi-volume set
  is passed as a list of them. `ArchiveyConfig.max_read_through` sets how large a gap a
  read fetches through before it starts a new request. `SourceChangedError` is raised
  when the remote object gets shorter while it is being read. Credentials in a URL never
  appear in names or messages.
- `archivey.fsspec.ArchiveyFileSystem` presents an archive as a read-only fsspec file
  system, under the `archivey://` protocol, so pandas, pyarrow, dask and other fsspec
  users can open its members by path.
- Self-extracting programs: detection looks first for the archive where a Windows, Linux
  or macOS program's own image ends. It finds a ZIP far behind a Windows stub from the
  ZIP's end record, and it stops reading a signed Windows program's archive where the
  signature starts. LHA and ARJ archives behind a DOS or Windows stub are found too.
  `FormatInfo.prefixed` says whether the archive comes after other bytes, and
  `FormatInfo.payload_end` says where a signature starts.
- `open_archive(..., parent=reader)` opens an archive found inside another as part of
  the outer reader's nest. Every level then counts against one member total, one ratio
  against the outermost archive's size, and the new
  `DecoderLimits.max_nest_decoded_bytes` when you set it.
- `ListingLimits.max_decoded_bytes` caps the bytes one listing decodes on its own (a
  `.tar.gz` listing decodes all of it), 4 GiB by default.
- `FormatPolicy.COMMON` is a ready-made policy for files you did not make, such as
  uploads: ZIP, TAR, RAR, 7z and gzip, bzip2, xz and zstd files, without the ZIP methods
  only PKZIP 1.x and earlier wrote. `FormatPolicy(exclude=)` also takes
  `CompressionAlgorithm` values, to refuse members compressed with them.
  `FormatPolicy(only_libraries=)` is the allowlist form of `exclude_libraries=`, and
  `FormatPolicy.allows_library()` answers for both.
- `ArchiveyConfig.unrar_path` and `unar_path` pin the one RAR program archivey runs,
  with no `PATH` lookup. On Windows, archivey finds `UnRAR.exe` in WinRAR's install
  folder when `PATH` has none.
- `ArchiveyConfig.recover_partial_data=False` skips decoding damaged data again to
  recover the bytes before the damage, so a read of a damaged member fails sooner.
- A backward seek in gzip, zlib or raw DEFLATE data, ZIP members included, resumes from
  points archivey records about every MiB, without rapidgzip. mgzip files seek by their
  member sizes, as BGZF files do. A member read from a compressed TAR after the listing
  resumes from the nearest recorded point instead of decoding the archive again from its
  start, xz included even when the file has no usable index.
- `ExtractionReport.ok` and `raise_for_failure()` answer whether every member was
  extracted.
- New diagnostics: `SOLID_OPEN_REDECOMPRESSES` (opening members of a solid 7z or RAR
  archive out of order decodes data again), `DETECTION_DECODER_LIMITED` (detection
  skipped a probe that needed more than `max_decoder_memory`), `MEMBER_LOCAL_OFFSET_SHIFTED`
  and `MEMBER_NAME_DUPLICATE_UNEXPECTED` (both in `ARCHIVE_INTEGRITY_CODES`),
  `SOURCE_CHANGE_UNDETECTABLE` and `MEMBER_PATH_REFUSED`.
- `HashAlgorithm` gains `MD5`, `SHA1`, `SHA256` and `SHA512`, for the digests RPM and
  XAR record.
- `ArchiveyConfig` and `ArchiveFormat` are typed to take the string spellings the docs
  show (`ArchiveyConfig(process_isolation="none")`), through new `Literal` aliases:
  `AcceleratorModeStr`, `ProcessIsolationStr` and `RarDecompressorStr` in
  `archivey.config`, `DetectionBudgetPresetStr` in `archivey.detection_cost`, and
  `ContainerFormatStr` and `StreamFormatStr` in `archivey.types`.

### Experimental

- Plugin interface: `IndexedFormatHandler` (with `non_seekable_reason`) now holds
  `open()`, which `FormatHandler` no longer has, and `register_format()` takes an
  `IndexedFormatHandler` or a `SequentialFormatHandler`. Plugin readers yield names as
  stored and archivey normalizes them, so `stored_name` is gone from `MemberRecord`,
  `MemberSpan` and `ReaderContext.hold()`. New: `ForwardStream.take()`,
  `ReaderContext.open_nested()` (an archive stored inside a member),
  `ReaderContext.charge_metadata()`, `MemberData.ranges` and
  `SequentialReader.data_on_demand`.
- Verification: `verify_all()` returns a `VerifyReport`. Its `failures` are the
  `(member, error)` pairs it returned before, `structure_error` holds damage that stopped
  the walk (a ZIP cut inside its central directory, say), and `ok` and
  `raise_for_failure()` answer for both.
- `reader.backends_used` lists what a reader ran to read its archive: each reader, codec,
  library and external program, with what it was used for.

### Changed

- **Breaking:** `extract_all()` raises `FilterRejectionError` when a safety check
  refused a member. The other members are still extracted first, and the error carries
  the full report in `.report`. Pass `on_blocked="skip"` (the new `OnBlocked` enum) to
  get the report back without raising, as before.
- **Breaking:** a RAR program that cannot start for lack of system resources raises
  `ResourceUnavailableError`, and a command line that is too long raises `ReadError`,
  instead of `PackageNotInstalledError` for both.
- An fsspec source is never searched for its other volumes, whatever `discover_volumes`
  says: pass a remote set as a list. A lone remote part that needs the others says so.
- `ExtractionPolicy.TRUSTED` writes a symlink whose target starts at `/` as stored, as
  GNU tar does for a root filesystem image. `STRICT` and `STANDARD` still refuse it, and
  no policy writes anything through such a link.
- A hard link's `link_target` is normalized in every format, so it equals the listed
  name of the member it links to (TAR's `./b` lists as `b`). A target that ends in `/`
  keeps it, and resolves only to a directory.
- A file in a directory source on procfs or sysfs lists with `size=None` and reads to
  its end. Anywhere else, a file that grew past its listed size, 0 included, is refused.
- RAR: `unrar` reads each member through a small archive that holds only what that
  member needs. No member name reaches `unrar` any more, so names with wildcards,
  backslashes or tens of thousands of characters read without a config switch. A RAR opened
  from a file object copies only the data a member needs instead of the whole archive.
  Passes over many small members read them in batches.
- RPM packages list from their header alone, with no payload byte read. Damage in the
  payload is found when a file's data is read, and the files before it still read.
- ZIP: when bytes are missing from the middle of an archive, the members before the gap
  are read from their stored offsets instead of failing with the rest.
- An ISO image whose directory padding is damaged opens with an `ARCHIVE_TRAILING_DATA`
  warning instead of raising `CorruptionError`. `DiagnosticPolicy.STRICT` still refuses
  it.
- Detection holds its probes to `DecoderLimits.max_decoder_memory`.
- A 7z AES password is confirmed from the padding of the last encrypted block where the
  archive allows it, without decoding the folder.
- A `.zz` file holding several zlib streams under one final checksum that covers all of
  them reads differently under `use_rapidgzip=ON`. This is now a documented difference:
  the 0.3.0 check for it cost about 45% of a decode.
- Reading many small ZIP members takes about half the time it took in 0.3.0, and
  extracting many hard links to one file takes linear time instead of quadratic.
- The `[recommended]` extra asks for `pyppmd` below 2.0 until archivey supports 2.0's
  new decoder.

### Deprecated

- `ArchiveyConfig.rar_allow_glob_member_concatenation` has no effect, and setting it
  `True` warns. Removed in 0.5.0.

### Removed

- The ratio fields of `ExtractionLimits` (`max_ratio`, `ratio_activation_threshold`,
  `live_ratio_activation_threshold`), deprecated in 0.3.0: set them on `DecoderLimits`.
  `ExtractionLimits.UNLIMITED` now lifts only the byte and entry caps, and
  `max_entries` is keyword-only. Add `DecoderLimits(max_ratio=None)` to the reader's
  config to lift the ratio too.
- Building `ArchiveStream` or `MemberPass` yourself, or through a subclass that leaves
  an abstract method unimplemented (deprecated in 0.3.0), now raises `TypeError`. Get
  one from `open()`, `stream_members()` or `open_stream()`.

### Security

- When an archive's path holds `*` or `?`, archivey links it under a fixed name before
  `unrar` reads it, because `unrar` expands wildcards in the archive name. Before this,
  a planted archive beside the real one could mix its members into the output, and a
  matching FIFO could hang the read. The archive's directory no longer reaches `unrar`'s
  command line either.
- A `.deb` whose data tar writes into `DEBIAN/` is refused, as `dpkg-deb` refuses it,
  instead of replacing the control files in the listing and in extraction.
- `open_stream()` is held to `DecoderLimits.max_ratio`, as a member read is, so a bare
  `.gz` or `.bz2` bomb that `open_archive()` refuses no longer decodes in full through
  it.
- Each hard link, symlink or RAR file copy that a read follows counts its bytes against
  the archive-wide ratio limit. Before, links to one file counted its bytes once, so a
  `.tar.gz` of one file and many hard links could be read out far past `max_ratio`.
- PAX records and their entries count against `ListingLimits.max_metadata_bytes` by
  what they keep.
- Errors about a `password=` value of the wrong type no longer print the value.

### Fixed

- For an archive behind a self-extracting stub (ZIP, 7z, LHA, ARJ), every offset in an
  error or diagnostic now counts from the start of the file, stub included, as RAR's
  already did. That includes the `observed_bytes`, `local_offset` and `central_offset`
  fields of a ZIP's diagnostic context.
- About 40 bugs found since 0.3.0, most of them by fuzzing each reader and by comparing
  archivey with each format's official tool on real archives.

## [0.3.0] - 2026-11-04

A minor release: new formats built in, a per-call format policy, the ratio limit on
every read, and stricter defaults for names and for archive shapes no writer produces.

### Added

- archivey reads ar, CPIO (including afio) and SquashFS archives as built-in formats,
  compressed ones too (`.cpio.gz`, `.a.xz` and the like). LZO is a built-in codec, so
  lzop files (`.lzo`, `.tar.lzo`) and the LZO data in SquashFS images are read without
  an extra package.
- ZIP members compressed with XZ (method 95), Shrink (1) and Implode (6) are supported.
- `ArchiveyConfig(formats=FormatPolicy(...))` chooses which formats one open may use
  (`only=`, `exclude=`, `plugins=`) and which optional libraries it may load
  (`exclude_libraries=`, with the new `OptionalLibrary` enum).
  `PackageNotInstalledError.missing` names what is missing.
- `ArchiveMember.accessed_utc()`, `created_utc()` and `ctime_utc()`, beside
  `modified_utc()`. Extraction restores a member's birth time (`created`) on Windows and
  macOS.
- `ArchiveyConfig.discover_volumes` turns off looking for an archive's other volumes.
- `ResourceUnavailableError`, a `ResourceLimitError` for the system running short (a
  killed decoder process, out of file descriptors) rather than a limit you set.
- Detection finds a ZIP, 7z or RAR behind leading bytes of any kind, and a TAR with no
  magic by its header checksum.
- New diagnostics: `MEMBER_HEADER_AMBIGUOUS` (TAR header shapes no known writer
  produces; in `ARCHIVE_INTEGRITY_CODES`, so `DiagnosticPolicy.STRICT` refuses them),
  and `MEMBER_NAME_DUPLICATE` and `MEMBER_READERS_DISAGREE` (shapes other readers take
  differently; reported at INFO, raised only by `PEDANTIC` or `raise_on=`).
  `MEMBER_READERS_DISAGREE` also names a file that only one of an ISO image's trees
  (ISO 9660, Joliet, UDF) holds, and a member name with a NUL byte.
- Python 3.15 is supported and tested on Linux, macOS and Windows, free-threaded 3.15t
  included.

### Experimental

These are outside the stability policy: any release, a patch included, may change or
remove them.

- An interface for formats and codecs from outside archivey: `archivey.formats` with
  `register_format()` and `register_codec()`, and `FormatPolicy(replace=)` to read a
  built-in container with your own reader.
- Verification levels. `verified` and `verifiable`, on `ArchiveMember` and on
  `ArchiveStream`, say how far a member's data has been checked: `Verification.NONE`,
  `UNLOCKED` (the password is confirmed), `LENGTH` (all the data is there) or `CHECKSUM`
  (every byte passed a stored checksum, at whatever layer it sits).
  `ArchiveStream.verify()` runs the checks without keeping the bytes, and
  `password_only=True` stops once the password is confirmed. A stream that can seek is
  left where it was; one that cannot is read to the end. `reader.verify_all()` checks
  every member, checks that cover several members included (a 7z folder CRC, the
  checksum of a `.tar.gz`), and returns each member it could not prove, with its error.

### Changed

- **Breaking:** the decompression ratio limit, now `DecoderLimits.max_ratio`, applies
  to every read, not only extraction, and its default is 800:1, down from 1000:1.
  `read()`, `open()` and `stream_members()` raise `ResourceLimitError` for a member, or
  a whole archive, that expands past it, and it applies to a compressed TAR while
  listing too. Set `DecoderLimits.max_ratio` to raise it or turn it off.
- **Breaking:** `ExtractionPolicy.STRICT`, the default, refuses a member name with a
  backslash, a control character or bytes that are not UTF-8. `STANDARD` still writes
  such names with the portable rewrite.
- **Breaking:** a ZIP member whose attributes say directory is read as a directory even
  without a trailing `/`, as 7-Zip and libarchive do.
- **Breaking:** errors that changed type. A listed volume that is missing raises its
  `OSError` (`FileNotFoundError`) instead of `OpenError`; running out of file
  descriptors raises `ResourceUnavailableError`. A ZIP, 7z or RAR file that is empty or
  holds only the start of its signature raises `TruncatedError` instead of
  `CorruptionError`.
- TAR follows GNU tar where readers disagree: PAX records combine as GNU tar combines
  them, a PAX size on a directory or link no longer frames data, and an mtime field with
  no digit is `None`, not 1970.
- `MEMBER_NAME_NORMALIZED` is no longer reported for a leading `./` alone.
- A seek in a compressed stream no longer decodes anything itself: the next read decodes
  up to the new position. A seek that no read follows, or that another seek replaces,
  costs nothing.
- Under `use_rapidgzip=AUTO`, rapidgzip also decodes large sequential DEFLATE reads on
  Linux and macOS, where it was measured to pay.
- Extracting a ZIP takes about 0.8x the 0.2.1 time, and reading a single `.gz` file
  about 0.7x (same-runner comparison against 0.2.1; the other cases are within about
  15% of it).

### Deprecated

- The ratio fields of `ExtractionLimits` (`max_ratio`, `ratio_activation_threshold`,
  `live_ratio_activation_threshold`): set them on `DecoderLimits`. They still apply, and
  are removed in 0.4.0.
- Constructing or subclassing `ArchiveStream` or `MemberPass` as in 0.2: they are now
  base classes you receive from `open()`, `stream_members()` and `open_stream()`. A 0.2
  subclass still works, with a `DeprecationWarning`. Removed in 0.4.0.

### Security

- The archive-wide ratio limit applies to a ZIP or TAR read from a pipe, as it does to
  one read from a file.
- A discovered sibling volume that is a symlink is refused.
- Extraction never replaces a file that another writer made after archivey checked the
  path was free.
- A raw LZO1X stream is refused once its input exceeds what LZO1X needs for the
  declared size.

### Fixed

- About 30 bugs found since 0.2.1, most of them in TAR, RAR and the decoders. Many came
  from comparing archivey with
  [Apache Commons Compress](https://commons.apache.org/proper/commons-compress/) and its
  test archives, and from the [tar-minefield](https://github.com/haampie/tar-minefield)
  corpus of TAR files that readers take differently.

## [0.2.1] - 2026-10-24

A patch release: no public name was added, renamed or removed.

### Added

- 7z archives that use 7-Zip 24's RISC-V branch filter are now supported. The filter is
  decoded in Python, so it needs no extra package.
- `archivey extract --dry-run` prints a `peak use of the reader limits:` line: the
  largest decoder allocation, the temporary-file peak, the key-derivation rounds and
  the listing size, to compare with the limits before tightening them.
- Reading a member of a solid 7z or RAR archive with `open()` or `read()` logs one INFO
  record per reader when it decodes data an earlier call already decoded, and names
  `stream_members()` as the one-pass alternative.
- The docs state the versioning and stability policy: until 1.0, a removed or renamed
  name warns for one minor release before it goes.

### Changed

- `ExtractionPolicy.STANDARD` refuses a path segment made only of dots or spaces (such
  as `... ` or `.. `), as `STRICT` already did: Windows trims such a segment to `..` or
  merges it away, so the name means something different there. `STANDARD` also treats
  `notes.` and `notes` as the same file, as Windows does, so the second one is a
  collision on every platform instead of silently replacing the first on Windows.
- archivey reads every frame of a ZIP member compressed with Zstandard, as it does for a
  `.zst` file. A second frame used to raise `DataAfterEndError`.
- The `STREAM_REWIND_REDECOMPRESSES` diagnostic is logged at INFO instead of WARNING.
  It is still collected and can still be escalated by a `DiagnosticPolicy`.
- When `rapidgzip` speeds up seeking, the members of one archive share its child process
  on Linux instead of starting one each, and the child reads a ZIP member from the
  archive file directly instead of through the parent process.

### Fixed

- Several bugs: a zstd seek table pointing where the decoder cannot start no longer
  makes a seek fail, a rapidgzip member stream used after `fork()` raises
  `ArchiveyUsageError` instead of disturbing the parent's decoder, and a PPMd member
  refused under `NATIVE_DECODERS` isolation now names the setting that reads it.

## [0.2.0] - 2026-10-22

First public release. This repository is a rewrite: the earlier v1 / alpha line
(previously published from what is now
[`davitf/archivey-old`](https://github.com/davitf/archivey-old)) is a separate codebase
with no compatibility promise.

The public API is not frozen until 1.0: minor releases before then may still change it,
and each change will be listed here. No major changes are expected.

### Added

- **One interface for every format.** `open_archive()` returns a reader that lists,
  reads, streams and extracts members the same way for ZIP, TAR (plain or compressed),
  7z, RAR, ISO 9660, plain directories and single compressed files. The format is
  detected from the content, so a misnamed file still opens.
- **Native readers.** archivey parses ZIP, TAR, 7z and RAR headers itself. The
  compression methods come from three places:
  - the standard library, with no extra package: Deflate, bzip2, LZMA, LZMA2, xz, Delta
    and BCJ, and Zstandard on Python 3.14 and later;
  - archivey's own code: the BCJ2 and ARM64 filters, Unix compress (`.Z`), ZipCrypto
    and the lzip container;
  - third-party packages in `[recommended]`: PPMd, Deflate64, Brotli, LZ4, Zstandard
    before Python 3.14, and AES.

  ISO images also need `[recommended]`, and RAR data needs `unrar`, `rar` or `unar`. The
  [install page](docs/install.md) has the details.
- **Encrypted archives** in ZIP, 7z and RAR, with one password or a list of candidates.
- **Safe extraction by default.** `extract_all()` blocks path traversal, link escapes
  and special files, and caps size, compression ratio and entry count, under three
  policies (`STRICT`, `STANDARD`, `TRUSTED`). It can also report progress, choose what
  happens to existing files, and do a dry run.
- **Resource limits** on listing size, decoder memory, password key-derivation work and
  temporary files.
- **Built for streaming.** `stream_members()` reads every member in one pass, so a solid
  7z or RAR is decoded once. TAR, ZIP and single compressed files can also be read from a pipe,
  and zstd and gzip files can seek instead of decompressing from the start.
- **Crash isolation.** The native decoders known to crash on hostile input run in a
  child process, so a crash costs one member, not your process.
- **Overlapping operations on one reader**, from one thread or several, with
  `concurrent_operations=True`.
- **Verified reads.** A failed checksum or a cut member raises an error, and non-fatal
  oddities are reported as diagnostics that `DiagnosticPolicy.STRICT` turns into errors.
- **The `archivey` command** lists, tests, extracts and prints archives from the shell.
  `uvx archivey-cli` runs it with the recommended extras.
- Tested on Python 3.11 to 3.14 on Linux, macOS and Windows, and on free-threaded 3.13t.
  PyPy 3.11 works and every change has to pass the test suite there, but it can't read
  LZ4, PPMd or Deflate64 data; the install page lists the limits.

### Changed

- **Breaking:** `DecoderLimits.max_ppmd_in_process_input` (0.2.0rc1) is now
  `DecoderLimits.max_ppmd_held_input`, with no alias.

### Removed

- **Breaking:** `crc32_digest`, public in 0.2.0rc1. Use
  `zlib.crc32(data).to_bytes(4, "big")` instead.

### Fixed

- About 30 bugs found since 0.2.0rc1, most in reading damaged or crafted archives.

### Performance

From one benchmark run on 2026-10-21 at commit `de8a6565`, archivey takes 0.9 to 2.7
times as long as the standard library or reference reader to read, and 1.5 to 8.5 times
as long to list. [`benchmarks/RESULTS.md`](benchmarks/RESULTS.md) has the full table.

### Security

- [`SECURITY.md`](SECURITY.md) describes how to report a vulnerability privately.
- Extraction refuses a link whose target can't be looked up. In 0.2.0rc1, a crafted TAR
  (the technique of CPython's CVE-2025-4517) could write outside the destination.
- `[recommended]` now requires brotli 1.2.1 or later, which fixes a buffer overflow in
  brotli's decoder (CVE-2026-111497).
- The test suite replays published vulnerabilities of other archive tools against
  archivey; the [security page](docs/security.md#known-attacks-on-other-archive-tools)
  lists them.

## [0.2.0rc1] - 2026-10-18

Release candidate for 0.2.0, to test the release flow. 0.2.0 adds the `archivey-cli`
companion package and `ArchiveyConfig.process_isolation`, renames one `DecoderLimits`
field and removes `crc32_digest` (see Changed and Removed under 0.2.0), and fixes bugs,
one of them a security fix.

<!--
What goes in this file, from 0.2.0 on:

- One line per new feature and per public API change (Added / Changed / Deprecated /
  Removed). A line that makes callers change their code starts with **Breaking:**.
- A name outside the stability policy (`EXPERIMENTAL` in scripts/checks/api_surface.py)
  gets its line under Experimental, after Added.
- Each security fix gets its own line under Security.
- A Performance section, after Fixed and before Security, gives the peer wall ratios
  for the release with the run's date and commit, and links benchmarks/RESULTS.md for
  the host, method and analysis (dev-docs/release-checklist.md, section 2).
- Other bug fixes share one line under Fixed, e.g. "Fixed N bugs in ZIP and RAR
  reading", unless one changes behavior users rely on.
- Pull requests do not edit this file. The release PR writes the entry from the merged
  PRs (dev-docs/release-checklist.md, section 1).

`scripts/release.py start` writes the compare links below this comment.
-->

[Unreleased]: https://github.com/archivey-dev/archivey/compare/v0.4.0...HEAD
[0.4.0]: https://github.com/archivey-dev/archivey/compare/v0.3.0...v0.4.0
[0.3.0]: https://github.com/archivey-dev/archivey/compare/v0.2.1...v0.3.0
[0.2.1]: https://github.com/archivey-dev/archivey/compare/v0.2.0...v0.2.1
[0.2.0]: https://github.com/archivey-dev/archivey/releases/tag/v0.2.0
[0.2.0rc1]: https://github.com/archivey-dev/archivey/releases/tag/v0.2.0rc1
