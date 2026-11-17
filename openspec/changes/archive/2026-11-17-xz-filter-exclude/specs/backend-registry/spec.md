## MODIFIED Requirements

### Requirement: A method the format policy excludes is not decoded

`FormatPolicy.exclude` SHALL accept `CompressionAlgorithm` members, except `STORED` and
`UNKNOWN`, which SHALL be refused as a usage error; `FormatPolicy.only` SHALL refuse
them as a usage error. Such an entry SHALL refuse a file whose whole-file compression
decodes with that method (gzip and zlib with DEFLATE, bzip2 with BZIP2, xz with XZ,
LZMA Alone and lzip with LZMA, zstd with ZSTD, LZ4 and mozLz4 with LZ4, Brotli with
BROTLI, lzop with LZO), as the stream format's own entry does. A
`ReaderContext.decompress` or `ForwardStream.decompress` call for the method or for
such a stream format, a `ReaderContext.open_nested` call for a format with such a
stream format, and a built-in reader's own decode of its blocks with the method (the
SquashFS LZ4 decoder) SHALL raise `UnsupportedFeatureError` before the codec runs, so a
format that compresses data inside itself without listing the method on its members
(`.deb`, RPM, SquashFS, makeself) is refused when it opens. The filters an xz
block runs ahead of LZMA2 are named in its block header, not in a member's
`compression`: a block whose header declares a filter an entry names (Delta as DELTA;
x86, PowerPC, IA-64, ARM, ARM-Thumb, SPARC, ARM64 and RISC-V as BCJ) SHALL raise
`UnsupportedFeatureError` that names the method before liblzma is given the whole
header, wherever the xz stream is decoded (a file, a member, a nested payload, a
SquashFS block, a resume from the stream's index, the detection probe). The blocks
before it SHALL still decode, and an xz stream none of whose blocks declares such a
filter SHALL NOT be refused. A block header that liblzma refuses on its own (a CRC32
mismatch, reserved flags, a field that does not parse) SHALL raise the error it raises
without the entry. A member
whose `compression` chain lists an excluded method SHALL still be listed; opening,
reading or extracting it SHALL raise `UnsupportedFeatureError` that names the method
and `exclude=`, before the member's decoder is created, on every path that hands out
member data: `open()`, `read()`, a `stream_members()` pass (where the yielded stream
raises on its first read, and a member the caller skips raises nothing), extraction,
and a forward pass over a source that cannot seek, which skips the member's data
without decoding it. A symbolic link whose target is stored as such data SHALL be
listed without a target and reported with `SYMLINK_TARGET_UNAVAILABLE`, reason
`target_data_unsupported`.

`FormatPolicy.COMMON` SHALL be `FormatPolicy(only={ZIP, TAR, RAR, SEVEN_Z, RAW_STREAM,
GZIP, BZIP2, XZ, ZSTD}, exclude={SHRINK, IMPLODE, REDUCE, DCL_IMPLODE})`. A change to
its entries is a user-visible change.

#### Scenario: An imploded ZIP member is refused before it decodes

- **WHEN** a caller opens a ZIP holding an Implode member and a stored member with
  `FormatPolicy(exclude={CompressionAlgorithm.IMPLODE})`
- **THEN** `members()` lists both
- **AND** reading the Implode member raises `UnsupportedFeatureError` and no Implode
  decoder is created
- **AND** the stored member reads

#### Scenario: A method entry refuses a file compressed with it

- **WHEN** a caller opens a `.tar.xz` file with `FormatPolicy(exclude={CompressionAlgorithm.XZ})`
- **THEN** the open raises `UnsupportedFeatureError` that names `CompressionAlgorithm.XZ`

#### Scenario: A BCJ entry refuses an xz block that runs the filter

- **WHEN** a caller reads a `.xz` file whose second block declares the x86 BCJ filter
  with `FormatPolicy(exclude={CompressionAlgorithm.BCJ})`
- **THEN** the first block's bytes read
- **AND** the read then raises `UnsupportedFeatureError` that names
  `CompressionAlgorithm.BCJ`, and no BCJ decoder runs
- **AND** a `.xz` file whose blocks declare no BCJ filter reads in full
