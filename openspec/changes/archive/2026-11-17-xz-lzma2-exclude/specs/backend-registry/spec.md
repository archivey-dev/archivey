## MODIFIED Requirements

### Requirement: A method the format policy excludes is not decoded

`FormatPolicy.exclude` SHALL accept `CompressionAlgorithm` members, except `STORED` and
`UNKNOWN`, which SHALL be refused as a usage error; `FormatPolicy.only` SHALL refuse
them as a usage error. Such an entry SHALL refuse a file whose whole-file compression
decodes with that method (gzip and zlib with DEFLATE, bzip2 with BZIP2, xz with XZ,
LZMA Alone and lzip with LZMA, zstd with ZSTD, LZ4 and mozLz4 with LZ4, Brotli with
BROTLI, lzop with LZO), as the stream format's own entry does. Every xz stream holds
LZMA2 data, so an LZMA2 entry SHALL refuse everything an XZ entry refuses: an xz file,
an xz stream format, and a member whose `compression` chain lists XZ. An XZ entry
SHALL NOT refuse LZMA2 data outside an xz stream, such as a 7z LZMA2 member. A
`ReaderContext.decompress` or `ForwardStream.decompress` call for the method or for
such a stream format, a `ReaderContext.open_nested` call for a format with such a
stream format, and a built-in reader's own decode of its blocks with the method (the
SquashFS LZ4 decoder) SHALL raise `UnsupportedFeatureError` before the codec runs, so a
format that compresses data inside itself without listing the method on its members
(`.deb`, RPM, SquashFS, makeself) is refused when it opens. A member
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

#### Scenario: An LZMA2 entry refuses an xz file

- **WHEN** a caller opens a `.xz` or `.tar.xz` file with
  `FormatPolicy(exclude={CompressionAlgorithm.LZMA2})`
- **THEN** the open raises `UnsupportedFeatureError` that names
  `CompressionAlgorithm.LZMA2`
- **AND** a ZIP member compressed with xz is listed, and reading it raises
  `UnsupportedFeatureError`
