# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

Entries are written at release time, not by each pull request: new features, public
API changes and security fixes get a line each, and other bug fixes are summarized in
one line. How to write the entry: see
[`dev-docs/release-checklist.md`](dev-docs/release-checklist.md).

## [Unreleased]

A minor release: new formats built in, a per-call format policy, the ratio limit on
every read, and stricter defaults for names and for archive shapes no writer produces.

### Added

- ar, CPIO (including afio) and SquashFS archives read as built-in formats, and so do
  `.cpio.gz`, `.a.xz` and the like. LZO is a built-in codec: lzop files (`.lzo`,
  `.tar.lzo`), and the LZO data in SquashFS images, read without an extra package.
- ZIP members compressed with XZ (method 95), Shrink (1) and Implode (6) read.
- `ArchiveyConfig(formats=FormatPolicy(...))` chooses which formats one open may use
  (`only=`, `exclude=`, `plugins=`) and which optional libraries it may load
  (`exclude_libraries=`, with the new `OptionalLibrary` enum).
  `PackageNotInstalledError.missing` names what is missing.
- An experimental interface for formats and codecs from outside archivey:
  `archivey.formats` with `register_format()` and `register_codec()`, and
  `FormatPolicy(replace=)` to read a built-in container with your own reader. It is
  outside the stability policy: any release may change it.
- `ArchiveStream.verified` and `.verifiable` say how far a member's data has been
  checked (`Verification.NONE` to `CONTENT`).
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

### Changed

- **Breaking:** the decompression ratio limit, now `DecoderLimits.max_ratio`, holds
  every read, not only extraction, and its default is 800:1, down from 1000:1.
  `read()`, `open()` and `stream_members()` raise `ResourceLimitError` for a member, or
  a whole archive, that expands past it, and a compressed TAR is held to it while
  listing too. Set `DecoderLimits.max_ratio` to raise it or turn it off.
- **Breaking:** `ExtractionPolicy.STRICT`, the default, refuses a member name with a
  backslash, a control character or bytes that are not UTF-8. `STANDARD` still writes
  such names with the portable rewrite.
- **Breaking:** a ZIP member whose attributes say directory is a directory even without
  a trailing `/`, as 7-Zip and libarchive read it.
- **Breaking:** errors that changed type. A listed volume that is missing raises its
  `OSError` (`FileNotFoundError`) instead of `OpenError`; running out of file
  descriptors raises `ResourceUnavailableError`. A ZIP, 7z or RAR file that is empty or
  holds only the start of its signature raises `TruncatedError` instead of
  `CorruptionError`.
- TAR follows GNU tar where readers disagree: PAX records combine as GNU tar combines
  them, a PAX size on a directory or link no longer frames data, and an mtime field with
  no digit is `None`, not 1970.
- `MEMBER_NAME_NORMALIZED` is no longer reported for a leading `./` alone.
- Under `use_rapidgzip=AUTO`, rapidgzip also decodes large sequential DEFLATE reads on
  Linux and macOS, where it was measured to pay.
- Extracting a ZIP takes about 0.8x the 0.2.1 time, and reading a single `.gz` file
  about 0.7x. Reading the members of an uncompressed TAR takes about 1.2x: each read is
  now held to the ratio limit. (Same-runner comparison against 0.2.1; other cases are
  within 15% of it.)

### Deprecated

- The ratio fields of `ExtractionLimits` (`max_ratio`, `ratio_activation_threshold`,
  `live_ratio_activation_threshold`): set them on `DecoderLimits`. They still apply, and
  are removed in 0.4.0.
- Constructing `ArchiveStream` or `MemberPass` directly: they are now base classes you
  receive from `open()`, `stream_members()` and `open_stream()`. Removed in 0.4.0.

### Security

- A ZIP or TAR read from a pipe is held to the archive-wide ratio, as it is from a file.
- A discovered sibling volume that is a symlink is refused.
- Extraction never replaces a file that another writer made after archivey checked the
  path was free.
- A raw LZO1X stream is refused once its input exceeds what LZO1X needs for the
  declared size.

### Fixed

- About 20 bugs found since 0.2.1, most of them in TAR, RAR and the decoders. Many came
  from comparing archivey with
  [Apache Commons Compress](https://commons.apache.org/proper/commons-compress/) and its
  test archives, and from the [tar-minefield](https://github.com/haampie/tar-minefield)
  corpus of TAR files that readers take differently.

## [0.2.1] - 2026-10-24

A patch release: no public name was added, renamed or removed.

### Added

- 7z archives that use 7-Zip 24's RISC-V branch filter now read. The filter is
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
- A ZIP member compressed with Zstandard reads every frame, as a `.zst` file does. A
  second frame used to raise `DataAfterEndError`.
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
  7z or RAR is decoded once. TAR, ZIP and single compressed files also read from a pipe,
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

[Unreleased]: https://github.com/archivey-dev/archivey/compare/v0.2.1...HEAD
[0.2.1]: https://github.com/archivey-dev/archivey/compare/v0.2.0...v0.2.1
[0.2.0]: https://github.com/archivey-dev/archivey/releases/tag/v0.2.0
[0.2.0rc1]: https://github.com/archivey-dev/archivey/releases/tag/v0.2.0rc1
