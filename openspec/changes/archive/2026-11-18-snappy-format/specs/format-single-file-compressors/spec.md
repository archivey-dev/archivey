## MODIFIED Requirements

### Requirement: Present each compressor as a one-member archive

The system SHALL present any GZ, BZ2, XZ, ZST, LZ4, LZIP, LZMA Alone, ZLIB, BR,
Z, LZOP, mozlz4, BZ3, SZ (Snappy framed), UU or BASE64 source as an archive containing exactly one `ArchiveMember` of type
`MemberType.FILE`. No directory members SHALL be synthesized.

The member name SHALL be inferred from the source filename:

| Source filename | Member name |
| --- | --- |
| Ends in `.gz`, `.bz2`, `.xz`, `.zst`, `.lz4`, `.lz`, `.lzma`, `.zz`, `.zlib`, `.br`, `.brotli`, `.Z`, `.lzo`, `.mozlz4`, `.bz3`, `.sz`, `.uu`, `.uue`, `.b64` or `.base64` (case-insensitive) | Strip exactly that recognized compression extension |
| Ends in `.tgz`, `.tbz2`, `.tbz`, `.txz`, `.tzst`, `.tlz` or `.tzo` (case-insensitive) | Replace that suffix with `.tar`, as `gzip -d` and `xz -d` do |
| Ends in `.jsonlz4` or `.baklz4` (case-insensitive), Firefox's mozlz4 names | Replace that suffix with `.json` or `.bak` |
| Ends in a recognized extension, but the remaining stem is entirely dots and spaces (`..gz`, `....gz`, ` .gz`) | Append `.uncompressed` instead; `.` and `..` are not member names, and an all-dots segment is refused under `STRICT` and `STANDARD` |
| Has a filename but no recognized compressor extension | Append `.uncompressed`; do not strip arbitrary extensions |
| Anonymous stream | `data` |

Whether `.tar.gz` or `.tgz` opens as a tar is a `format-detection` concern. The naming
rows above apply when such a source opens as a single compressed file, for example with
`format=ArchiveFormat.GZ` or a `.tgz` whose content is not a tar.

Raw Deflate and raw LZMA1/LZMA2 (`FORMAT_RAW`) remain container-only; LZMA Alone
is a framed standalone stream and is in scope here.

#### Scenario: one-member naming matrix

| Case | Expected |
| --- | --- |
| Open `data.txt.gz` | One file member named `data.txt` |
| Open `data.txt.lzma` | One file member named `data.txt` |
| Open `data.tgz` with `format=ArchiveFormat.GZ` | One file member named `data.tar` |
| Open `sessionstore.jsonlz4` | One file member named `sessionstore.json` |
| Open compressed `mystery.bin` detected by content | One file member named `mystery.bin.uncompressed` |
| Open `....gz` | One file member named `....gz.uncompressed`, under every extraction policy |
| Open anonymous non-seekable stream with `streaming=True` | One file member named `data` |
| Iterate any supported single-file compressor | Exactly one file member is yielded |

### Requirement: The member names the stream's compression method

The one member's `compression` SHALL name the method the stream decodes with, as one
`CompressionMethod`, the one a ZIP or 7z member compressed the same way lists: gzip
and zlib `DEFLATE`, bzip2 `BZIP2`, xz `XZ`, LZMA Alone and lzip `LZMA`, zstd `ZSTD`, LZ4
and mozLz4 `LZ4`, Brotli `BROTLI`, lzop `LZO`, `.Z` `LZW`, bzip3 `BZIP3`, Snappy `SNAPPY`. A stream with
no `CompressionAlgorithm` member (uuencode, base64, a plugin codec) SHALL list `()`, not
`UNKNOWN`, which means a method archivey cannot decode. The value SHALL be the same from
a file, a seekable stream and a forward pass. A container inside a compression stream
(`.tar.gz`) SHALL NOT add the stream's method to its members: the stream belongs to the
archive. A single file inside another single file names only its own layer.

#### Scenario: member compression matrix

| Case | Expected |
| --- | --- |
| `.gz` from a path, and from a pipe with `streaming=True` | `compression == (CompressionMethod(DEFLATE),)` both times |
| `.xz` | `(CompressionMethod(XZ),)` |
| `.lz` or `.lzma` | `(CompressionMethod(LZMA),)` |
| `.Z` | `(CompressionMethod(LZW),)` |
| `.bz3` | `(CompressionMethod(BZIP3),)` |
| `.uu` or a plugin codec | `()` |
| `.xz.gz`, and the `.xz` member it holds opened in turn | `(DEFLATE,)`, then `(XZ,)` |
| A member of a `.tar.gz` | `(CompressionMethod(STORED),)` |

## ADDED Requirements

### Requirement: Snappy framed streams decode the same with any installed package

The system SHALL read Snappy's framing format (`.sz`, stream identifier
`ff 06 00 00 73 4e 61 50 70 59`) with no third-party package, and SHALL use `compress-utils`
or `cramjam` for raw blocks and `google-crc32c` or `crc32c` for the CRC-32C when they are
installed, not excluded by the format policy, and `process_isolation` is not
`NATIVE_DECODERS`. Which of them are installed SHALL NOT change which streams are read or
the bytes they read to: a raw block a package refuses, or decodes to a length other than
the one it declares, SHALL be decoded again in Python, whose result SHALL be used.

#### Scenario: A block cramjam refuses is read
- **GIVEN** a `.sz` file whose raw block stores a one-byte literal with a two-byte length
  field, which Google Snappy accepts and cramjam 2.14 refuses
- **WHEN** it is read with only cramjam installed, and with no package installed
- **THEN** both reads return the same byte

### Requirement: Snappy framed streams are checked chunk by chunk

The decoder SHALL refuse with `CorruptionError` a stream that does not start with the stream
identifier, a reserved unskippable chunk (types `0x02` to `0x7f`), a data chunk shorter than
its CRC or longer than a 64 KiB chunk can be, a raw block that declares more than 65,536
decoded bytes (before decoding it), and a chunk whose masked CRC-32C does not match its
decoded data. It SHALL skip reserved skippable chunks and padding (`0x80` to `0xfe`)
without holding them in memory. Input that ends inside a chunk SHALL raise
`TruncatedError`; input that ends between chunks SHALL end the stream.

#### Scenario: A bad CRC is refused
- **GIVEN** a `.sz` file whose chunk CRC does not match its data
- **WHEN** it is read
- **THEN** `CorruptionError` is raised before that chunk's data is returned
