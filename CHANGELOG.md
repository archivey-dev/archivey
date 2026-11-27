# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

Pull requests may add or edit lines under `[Unreleased]`, and the release does the final
pass: new features, public API changes and security fixes get a line each, and other bug
fixes are summarized in one line that the release writes, so a plain bug fix needs no
line. How to write the entry: see
[`dev-docs/release-checklist.md`](dev-docs/release-checklist.md).

## [Unreleased]

### Added

- `open_archive(salvage=True)` opts into salvage mode, capped by the new `SalvageLimits`
  (`ArchiveyConfig.salvage_limits`). No format has a salvage search yet, so every format
  reads as before and records `SALVAGE_UNAVAILABLE`.
- `ArchiveyConfig(format_options=[...])` holds the settings of single formats, one
  object per format: `archivey.config.RarOptions` for RAR, and a plugin's format can
  have its own. A reader asks for its own with `ReaderContext.options(cls)`.
- `ArchiveyConfig(fallback_encoding=)` names the codec for member names that are not
  valid UTF-8 and whose archive declares no encoding, in every format. Nested archives
  opened with `parent=` inherit it. By default each format keeps its own fallback:
  cp437 for ZIP, the host's code page for RAR 1.5-4, surrogate escapes for the others.
- `ArchiveyConfig.UNTRUSTED`, the settings for files you didn't make, such as uploads:
  `FormatPolicy.COMMON`, `DiagnosticPolicy.STRICT`, `NATIVE_DECODERS`, lower listing,
  decoder and extraction limits, and rapidgzip off. Adjust it with
  `dataclasses.replace()`; the upload recipes start from it.

### Changed

- **Breaking:** a plugin's `probe` (on `FormatHandler` and `CodecHandler`) returns a
  verdict, not a bool: the new `DetectionConfidence.REJECTED` for no,
  `DetectionConfidence.GUESS` for a weak match, `DetectionConfidence.PROBABLE` for a
  match. `detect_format()` reports it as the confidence, raised to `PROBABLE` when the
  extension names the format. A probe that returns a bool, `None` or `CERTAIN` counts as
  no match and logs a warning; replace `True` with `DetectionConfidence.PROBABLE` and
  `False` with `DetectionConfidence.REJECTED`.
- **Breaking:** with `concurrent_operations=True`, `stream_members()`, `extract_all()`
  and `verify_all()` no longer run beside other calls: while a pass runs, `open()`,
  `read()`, `get()`, `members()`, `members_report()`, iteration or another pass raises
  `ArchiveyUsageError`, as without the flag, and a pass started while one of those calls
  runs or a member stream from `open()` is open raises too. `info`, `format`, `cost`
  and `members_report_if_available()` stay readable beside a pass. Without the flag,
  `extract_all()` and `verify_all()` beside an open member stream now raise too, as
  `stream_members()` did. Several open member streams, and `open()`, `read()`, `get()`
  and `members()` from several threads, work as before.
- **Breaking:** `reader.close()` never waits for another thread and never raises
  because of one: it marks the reader closed and returns. A reader call still running
  raises `ArchiveyUsageError` at its next check, and a member stream still open reports
  `closed` at once and raises `ValueError` on its next call, also a read already
  running; an error a call was already raising is kept. The archive is released when
  the last running call returns. `close()` from a callback of the reader's own call
  (`on_progress`, `on_diagnostic`, a password provider) no longer raises: it stops that
  call, which is how to cancel an `extract_all()`. Closing a member stream from such a
  callback raises `ArchiveyUsageError`, and `info` read there gives its last value
  without reading the archive.
- **Breaking:** `extract_all()` takes one setting for problems, `on_problem=`
  (`archivey.OnProblem`): `"stop"`, `"finish"`, `"continue"` or `"keep_partial"`. The
  default, `"finish"`, tries every member and then raises the first problem's error with
  the full report as its `report` attribute. A damaged member no longer stops the run at
  once: pass `on_problem="stop"` for that, which also stops at the first refused member.
  `archivey extract --stop-on-error` now stops at a refused member too.
- **Breaking:** `ArchiveyConfig.use_rapidgzip` decides bzip2 too, so
  `use_rapidgzip="off"` alone now keeps rapidgzip away from bzip2 as well.
- **Breaking:** `DiagnosticCode.MEMBER_NAME_ENCODING_INFERRED` is now
  `MEMBER_NAME_FALLBACK_ENCODING`, and it means something else: the name was not valid
  UTF-8 and its archive declared no encoding, so it went through the fallback and a
  different `fallback_encoding` could change it. Every format emits it, also when no
  codec was given (its context's `fallback_encoding` names the codec used, or
  `"surrogateescape"`); a valid UTF-8 name no longer emits it. The context fields
  `inferred_encoding` and `declared_encoding` became one `fallback_encoding`.
  `DiagnosticPolicy.STRICT` no longer refuses it, also for a ZIP name whose UTF-8 flag
  its bytes refute.
- **Breaking:** the deprecated `ArchiveyConfig` fields `zip_unflagged_fallback_encoding`,
  `rar_decompressor`, `unrar_path` and `unar_path` always read back as `None`: a value
  passed to one moves into `fallback_encoding` or `format_options`, so read it there.
  `use_indexed_bzip2` reads back as `None` unless the caller set it; read
  `use_rapidgzip`.
- A streaming pass over a format with an index (a ZIP, 7z, RAR, ISO, CAB and others)
  reads the whole index before its first member, so `members_report_if_available()`
  gives the same answer inside the loop as before it.

### Deprecated

- The package root keeps 31 names: `open_archive`, `open_stream`, `detect_format`,
  `format_availability`, the reader, member, format, policy and report types, and the
  errors callers catch most. The other 67 come from the submodule that defines them,
  such as `archivey.config.DecoderLimits`, `archivey.types.OverwritePolicy` and
  `archivey.exceptions.ReadError`; the [API page](docs/api.md) heads each entry with
  its full name. `archivey.<name>` still works for 65 of them in 0.6 with a
  `DeprecationWarning` that names the new import, and 0.7.0 removes it. The other two,
  the experimental `PluginContainer` and `PluginStream`, left the root at once and come
  from `archivey.types`. `sanitize_names` moved to `archivey.paths`. `archivey.core`
  keeps only its six functions: `AcceleratorMode`, `ExtractionLimits`, `ListingLimits`,
  `DetectionConfidence`, `FormatAvailability`, `FormatSupport` and `MissingComponent`
  still work from it in 0.6 with the same warning.
- `extract_all(on_error=, on_blocked=, abort_on=)` and their enums `OnError`,
  `OnBlocked` and `AbortOn` keep working in 0.6 with a `DeprecationWarning`; use
  `on_problem=`. The name events have no `on_problem` value: `"stop"` already stops at a
  second member at one path under the default `overwrite="error"`, and
  `ExtractionResult.rewrites` lists every rewritten name. `archivey extract --abort-on`
  is deprecated the same way. 0.7.0 removes them.
- `ArchiveyConfig(rar_decompressor=, unrar_path=, unar_path=)` keep working in 0.6 with
  a `DeprecationWarning`; pass `format_options=[RarOptions(decompressor=...,
  unrar_path=..., unar_path=...)]` from `archivey.config`. 0.7.0 removes them.
- `open_archive(encoding=)`, `ArchiveyFileSystem(encoding=)` and
  `ArchiveyConfig(zip_unflagged_fallback_encoding=)` keep working in 0.6 with a
  `DeprecationWarning`; pass `config=ArchiveyConfig(fallback_encoding=...)`, or
  `dataclasses.replace(config, fallback_encoding=...)` to change only that field. 0.7.0
  removes them.
- `ArchiveyConfig.use_indexed_bzip2` keeps working in 0.6 with a `DeprecationWarning`,
  and decides bzip2 alone while it is set; use `use_rapidgzip`. 0.7.0 removes it.

### Removed

- **Breaking:** `ArchiveyConfig.rar_allow_glob_member_concatenation`, deprecated with no
  effect in 0.4.0. Passing it raises `TypeError`; drop the argument.

## [0.5.1] - 2026-11-20

A patch release with fixes for reading archives from a URL.

### Added

- For a URL, `archivey --track-io` reports how many range requests archivey made and how
  many bytes they fetched, in total and as a share of the archive's size.

### Fixed

- Reading an archive from a URL: a server that answers a range request with the whole
  file no longer costs the whole file in memory, and an occasional such answer is asked
  again; a server that sends each range in several parts is read to the end; a file
  replaced or cut short on the server while it is read raises `SourceChangedError`; and
  a few malformed answers raise an `OSError` instead of another library's error.

### Performance

From a benchmark run on 2026-11-20 at commit `7512aff1`, archivey takes 1.1 to 3.5 times
as long as the standard library or reference reader to read, and 1.5 to 11.0 times as
long to list; the ratios above 4 are archives that list in under 2.5 ms. Against 0.5.0,
timed beside it on the same runner, no case changed by more than 5%, and this release
changes no decoder or format reader. Listing an ISO image from a URL takes fewer
requests: a 488 MB CD image from archive.org went from 18 requests and 5.2 MB fetched to
6 requests and 2.9 MB.

[`benchmarks/RESULTS.md`](benchmarks/RESULTS.md) has the full table.

## [0.5.0] - 2026-11-19

A minor release: the UDF file system of DVD and Blu-ray images, spanned ZIP sets, the
files inside macOS installer packages, Snappy files, URLs as the command's archive
argument, compress-utils in place of python-lzo, and fixes from a sweep of the new code.

### Added

- archivey reads the UDF file system of ISO images, DVD and Blu-ray images included, and
  images that hold only UDF, which are read without `pycdlib`.
- ZIP sets spanned by `zip -s` or WinZip (`name.z01`, `name.z02`, …, `name.zip`) are
  read, opened from any part when all parts are in one folder. Before, they were
  refused.
- macOS installer packages (`.pkg`, `.mpkg`) and Xcode archives (`.xip`) are a new
  format, `ArchiveFormat.PKG`. They list the files inside their payloads, each under a
  folder named after its payload, as `pkgutil --expand-full` unpacks them.
- Snappy framed files (`.sz`, `.tar.sz`) are a built-in format: `StreamFormat.SNAPPY`,
  `ArchiveFormat.SNAPPY` and `CompressionAlgorithm.SNAPPY`. They need no package; with
  `[recommended]`, compress-utils and google-crc32c make them faster.
- The `archivey` command takes a URL as its archive argument (`archivey list
  https://…/data.zip`, `archivey x s3://bucket/a.tar.zst`) and reads it through
  fsspec. The `archivey-cli` package now installs fsspec and aiohttp, so HTTP(S) URLs
  work with nothing else installed.
- A raw CD image (`.bin`) read without its `.cue`, from a stream or from a path with no
  sheet beside it, lists the session an operating system would mount, as it already did
  beside its sheet. When the sector addresses can't place a later session, the first is
  read and the new diagnostic `ARCHIVE_UNREAD_SESSION` reports the one left out.
- ZIP members compressed with method 20, Zstandard's first method number, are read as
  Zstandard.
- XAR file and table-of-contents checksums in SHA-224 and SHA-384 are checked, with the
  new `HashAlgorithm.SHA224` and `HashAlgorithm.SHA384`.
- A ZIP64 extra field whose values differ from the entry's own values, in an entry that
  does not use it, is reported as `MEMBER_HEADER_AMBIGUOUS` with the new ambiguity
  `"zip64_unused"`.
- `DetectionBudget.max_probe_forward_bytes` sets how far detection may read ahead on a
  source that cannot seek to check a Brotli stream's framing.

### Changed

- **Breaking:** compress-utils replaces python-lzo as the optional LZO1X decoder, and
  `OptionalLibrary.LZO` is replaced by `OptionalLibrary.COMPRESS_UTILS`. compress-utils
  and google-crc32c join `[recommended]`, and compress-utils joins `[free-threaded]` on
  Python 3.14 and later. An LZO1X end marker of a length other than 3, which no writer
  produces, is refused.
- A `.pkg` or `.xip` file is detected as `ArchiveFormat.PKG` instead of `XAR`, and lists
  its payloads' files instead of the payloads themselves. `format=ArchiveFormat.XAR`
  gives the earlier view.
- When an ISO image holds several file trees, the names come from Rock Ridge, then UDF,
  then Joliet, then the plain ISO 9660 names, so an image with UDF and Joliet now lists
  its UDF names.
- Joliet file names are listed without their `;1` version suffix, as plain ISO 9660 names
  already were.
- A backward seek in an lzop, legacy LZ4, Snappy or multi-frame LZ4 file resumes at the
  block or frame it lands in, instead of decoding again from the start of the file.

### Security

- A member whose path goes through a symlink that the same extraction created is
  refused, under every policy, `TRUSTED` included, also when the path reaches that link
  through a symlink that was already in the destination.
- When a later copy of a name replaced an earlier directory copy, the directory removed
  was the one the name led to at that time, which a symlink could point at the caller's
  own directory or, under `TRUSTED`, a directory outside the destination. The copy is
  now removed where it was written.
- `ListingLimits.max_decoded_bytes` counts the bytes decoded by every level of a nested
  archive together. Before, each archive opened inside another had its own allowance.

### Fixed

- A few other bugs, among them a hard link that, on a case-insensitive file system, got
  the bytes of a file that replaced its source under another spelling, and data from a
  source of unknown size taken for Brotli without a check of its framing.

### Performance

From a benchmark run on 2026-11-19 at commit `b5c7a01a`, archivey takes 1.1 to 3.4 times
as long as the standard library or reference reader to read, and 1.5 to 10.9 times as
long to list; the ratios above 4 are archives that list in under 2.5 ms. Against 0.4.1,
timed beside it on the same runner:

- Listing a 7z archive with many members measured about 10% less time on the runner,
  but a local check that alternated the two versions found no difference, so it is
  noise.
- Reading a `.Z` file of text takes about 7% less time, from the faster LZW decoder.
- Reading a `.Z` file of highly repetitive data measured 22% slower by the fastest round,
  but its rounds spread from 129 to 199 ms on both sides, and the middle rounds differ
  by 3%, so it is noise. The other cases are within about 5%.

[`benchmarks/RESULTS.md`](benchmarks/RESULTS.md) has the full table.

## [0.4.1] - 2026-11-17

A patch release: RAR archives read from a pipe, bzip2 and xz blocks checked before
their bytes are handed out, makeself installers read in more of their forms, faster
listing and small reads, and fixes from a sweep of the 0.4.0 code.

### Added

- With `streaming=True` and RARLAB `unrar` 7.00 or later, `stream_members()` and
  `extract_all()` read a single-volume RAR archive from a pipe, a socket or any other
  source that cannot seek. Before, RAR was refused there.
- makeself installers written with `--ssl-encrypt` are decrypted with `password=`
  instead of refused.
- A compressed TAR (gzip, bzip2, xz, zstd, LZ4 or lzip) behind a `#!` shell script,
  such as a CPack STGZ installer, is found and read.

### Changed

- RAR reads from a stream source no longer copy a whole member or archive to a
  temporary file, and are no longer refused when that copy would pass
  `SpoolLimits.max_bytes`. With `unrar` 7.00 or later, archivey feeds `unrar` rolling
  16 MiB volumes, so the disk use peaks at one volume.
- bzip2 hands out a block's bytes only after the block's CRC passes, so a damaged block
  gives none of its bytes, where before up to about 900 kB of it came out before the
  error. Each block is also a seek point. A block held back for its check counts
  against `DecoderLimits.max_decoder_memory`.
- A file in a `.tar.bz2`, a `.tar.bz3` or a `.tar.xz` written in several blocks reaches
  `verified == CHECKSUM` once every block its data lies in passes its check, instead of
  when the whole stream ends. A `.tar.bz2` read through the bzip2 accelerator still
  waits for the end.
- A single-file member (`.gz`, `.bz2`, `.xz`, `.lzma`, `.lz`, zlib, zstd, LZ4, Brotli,
  lzop, `.Z`, bzip3) lists its stream's method in `member.compression`, the same method a
  ZIP or 7z member compressed that way lists. The new `CompressionAlgorithm.LZW` and
  `CompressionAlgorithm.BZIP3` name the methods of `.Z` and bzip3, and `exclude=` takes
  them too. uuencode and base64 are encodings and still list `()`.
- `seek(0, SEEK_END)` on a member whose recorded size is small is held to the ratio
  limit, as a read is.
- When no format is detected, the error names every format the leading-bytes scan
  looked for.

### Security

- `FormatPolicy(exclude={CompressionAlgorithm.LZMA2})` also refuses xz, which always
  holds LZMA2 data, and `exclude={BCJ}` or `exclude={DELTA}` stops an xz read at the
  first block that declares that filter. Before, both were decoded.
- A symlink target stored as member data (ZIP, 7z, RAR4) that went over
  `ListingLimits.max_metadata_bytes`, or failed the control-character check, stayed on
  the member uncounted, so a later listing could pass the cap.
- A Debian package whose data symlinks lead into `DEBIAN/` is refused, as a data name
  that extracts there already was.
- A makeself header that sets a variable the reader uses on a line the reader skips, so
  that the shell and the listing would disagree on where the payloads are, is refused.
  A header that lists more payloads than `ListingLimits.max_members` is refused before
  any payload is read.

### Fixed

- A hard link whose source is not extracted is made at its place in archive order as
  an empty file, then filled from the source in a second pass, as GNU tar does. Later
  members meet it on disk as they would meet the link, which fixes the cases where a
  held-back link landed somewhere other than where the link would have been made.
- About fifteen other bugs found by a sweep of the 0.4.0 code, among them cue sheets
  with a `FILE` that holds no `TRACK` refused, and a long uuencode line or a MacLHA
  member no longer costing far more time than its size.

### Performance

From two benchmark runs on 2026-11-18 at commit `2f0db5d8`, archivey takes 1.0 to 3.5
times as long as the standard library or reference reader to read, and 1.6 to 11.4 times
as long to list; the ratios above 4 are archives that list in under 2 ms. Against 0.4.0:

- Reading a `.gz` file takes about 7% less time, and reading a `.Z` file of highly
  repetitive data about 18% less. Listing a 7z archive with many members takes about 11%
  less.
- Reading a `.tar.bz2` file through the optional accelerator takes about 10% longer. The
  other cases are within about 6%, apart from one 7z listing case that measured 11% more
  here and 19% less in a run the day before, which is noise.

Against 0.3.0, timed beside 0.4.1 in the second run, this recovers most of what 0.4.0
lost:

- Reading a `.gz` file takes about 9% longer, where 0.4.0 took about 20% longer. Listing
  a 7z archive takes 3 to 7% longer, against 10 to 15% in 0.4.0. Reading a `.Z` file of
  highly repetitive data takes less time, where 0.4.0 took 40% longer.
- Listing a RAR archive still takes 13 to 19% longer, a slowdown that came with 0.4.0.
  The other cases are within about 9%.

[`benchmarks/RESULTS.md`](benchmarks/RESULTS.md) has the full tables.

## [0.4.0] - 2026-11-15

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
- `ExtractionReport` and `MemberListReport` gain `ok` and `raise_for_failure()`, which
  answer whether every member was extracted or listed.
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
- **Breaking:** the boolean flags of the public functions (`open_archive(streaming=,
  seekable_members=, concurrent_operations=)`, `open_stream(seekable=)`,
  `detect_format(follow_stub_volumes=)`, `extract_all(dry_run=)`,
  `ArchiveStream.verify(password_only=)` and the rest) refuse a value that is not a
  `bool` with a `TypeError`, as `ArchiveyConfig`'s switches already did. Before, a
  string such as `"false"` counted as true.
- **Breaking:** a truth test (`if report:`) on an `ExtractionReport` or a
  `MemberListReport` raises `TypeError`. A report's truth was its length, so a failed
  extraction read as true. Use `report.ok`.
- `ArchiveyConfig`'s accelerator conflicts (`ON` with `process_isolation=NONE`, or with
  rapidgzip excluded by the format policy) raise an `ArchiveyUsageError` that is also a
  `ValueError`.
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

- For a ZIP or 7z archive behind a self-extracting stub, every offset in an error or
  diagnostic now counts from the start of the file, stub included, as RAR's already did.
- About 40 bugs found since 0.3.0, most of them by fuzzing each reader and by comparing
  archivey with each format's official tool on real archives.

### Performance

From one benchmark run on 2026-11-15 at commit `14a36e8a`, archivey takes 1.1 to 3.6
times as long as the standard library or reference reader to read, and 1.2 to 12.6 times
as long to list; the ratios above 4 are archives that list in under 2 ms. Against 0.3.0:

- Reading many small ZIP members takes about half the time (4 000 members, measured on
  2026-11-09), and extracting many hard links to one file takes linear time instead of
  quadratic.
- In the 2026-11-15 run, which timed 0.3.0 beside 0.4.0, listing a RAR archive takes 20
  to 30% longer and listing a 7z archive 10 to 15% longer. Reading a `.Z` file of highly
  repetitive data takes about 40% longer. The other cases are within about 10%.

[`benchmarks/RESULTS.md`](benchmarks/RESULTS.md) has the full table.

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

### Performance

From one benchmark run on 2026-11-15 at the `v0.3.0` tag (`f013eec9`), measured after
the release, archivey takes 1.0 to 3.6 times as long as the standard library or
reference reader to read, and 1.5 to 9.4 times as long to list. Extracting a ZIP takes
about 0.8x the 0.2.1 time, and reading a single `.gz` file about 0.7x (same-runner
comparison against 0.2.1; the other cases are within about 15% of it).
[`benchmarks/RESULTS.md`](benchmarks/RESULTS.md) has the full table.

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

### Performance

From one benchmark run on 2026-11-01 at the `v0.2.1` tag (`5f28bde7`), measured after
the release, archivey takes 1.1 to 2.5 times as long as the standard library or
reference reader to read, and 1.4 to 7.6 times as long to list.
[`benchmarks/RESULTS.md`](benchmarks/RESULTS.md) has the full table.

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
- A Performance section, after Fixed, gives the peer wall ratios
  for the release with the run's date and commit, and links benchmarks/RESULTS.md for
  the host, method and analysis (dev-docs/release-checklist.md, section 2).
- Other bug fixes share one line under Fixed, e.g. "Fixed N bugs in ZIP and RAR
  reading", unless one changes behavior users rely on.
- Pull requests may add or edit lines under [Unreleased], merged into the lines above; a
  plain bug fix needs no line. The release PR does the final pass
  (dev-docs/release-checklist.md, section 1).

`scripts/release/release.py start` writes the compare links below this comment.
-->

[Unreleased]: https://github.com/archivey-dev/archivey/compare/v0.5.1...HEAD
[0.5.1]: https://github.com/archivey-dev/archivey/compare/v0.5.0...v0.5.1
[0.5.0]: https://github.com/archivey-dev/archivey/compare/v0.4.1...v0.5.0
[0.4.1]: https://github.com/archivey-dev/archivey/compare/v0.4.0...v0.4.1
[0.4.0]: https://github.com/archivey-dev/archivey/compare/v0.3.0...v0.4.0
[0.3.0]: https://github.com/archivey-dev/archivey/compare/v0.2.1...v0.3.0
[0.2.1]: https://github.com/archivey-dev/archivey/compare/v0.2.0...v0.2.1
[0.2.0]: https://github.com/archivey-dev/archivey/releases/tag/v0.2.0
[0.2.0rc1]: https://github.com/archivey-dev/archivey/releases/tag/v0.2.0rc1
