## ADDED Requirements

### Requirement: The member names the stream's compression method

The one member's `compression` SHALL name the method the stream decodes with, as one
`CompressionMethod`, the one a ZIP or 7z member compressed the same way lists: gzip
and zlib `DEFLATE`, bzip2 `BZIP2`, xz `XZ`, LZMA Alone and lzip `LZMA`, zstd `ZSTD`, LZ4
and mozLz4 `LZ4`, Brotli `BROTLI`, lzop `LZO`. A stream with no `CompressionAlgorithm`
member (`.Z`, bzip3, uuencode, base64, a plugin codec) SHALL list `()`, not `UNKNOWN`,
which means a method archivey cannot decode. The value
SHALL be the same from a file, a seekable stream and a forward pass. A container inside
a compression stream (`.tar.gz`) SHALL NOT add the stream's method to its members: the
stream belongs to the archive. A single file inside another single file names only its
own layer.

#### Scenario: member compression matrix

| Case | Expected |
| --- | --- |
| `.gz` from a path, and from a pipe with `streaming=True` | `compression == (CompressionMethod(DEFLATE),)` both times |
| `.xz` | `(CompressionMethod(XZ),)` |
| `.lz` or `.lzma` | `(CompressionMethod(LZMA),)` |
| `.Z`, `.uu` or a plugin codec | `()` |
| `.xz.gz`, and the `.xz` member it holds opened in turn | `(DEFLATE,)`, then `(XZ,)` |
| A member of a `.tar.gz` | `(CompressionMethod(STORED),)` |
