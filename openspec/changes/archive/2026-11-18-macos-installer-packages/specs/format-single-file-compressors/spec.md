## ADDED Requirements

### Requirement: pbzx streams are read as xz chunks

The system SHALL read Apple's pbzx framing (`StreamFormat.PBZX`, `ArchiveFormat.PBZX`,
magic `pbzx` at offset 0): a 64-bit big-endian chunk size, then chunks of a 64-bit
decoded size, a 64-bit stored length and that many bytes. A chunk whose stored length
equals its decoded size SHALL be read as stored; any other chunk SHALL be one xz stream
that decodes to exactly its decoded size, decoded under `max_decoder_memory`. A chunk
shorter than the chunk size SHALL end the stream, and bytes after it SHALL be reported as
`ARCHIVE_TRAILING_DATA`; a stream whose size is a multiple of the chunk size SHALL end
with the input. A chunk size of 0, a chunk that declares 0 decoded bytes or more than
the chunk size, an xz chunk that decodes to another size or holds bytes after its
stream SHALL raise `CorruptionError`, and input that ends inside the header or a chunk
SHALL raise `TruncatedError`. The member's method SHALL be `CompressionAlgorithm.XZ`.
A CPIO inside SHALL be read as `ArchiveFormat(CPIO, PBZX)`.

#### Scenario: pbzx streams

| Case | Expected |
| --- | --- |
| Data of 0, 1 and several chunks, chunks stored, xz or mixed | The data |
| A `.pkg` Payload taken out of its package | Lists as `ArchiveFormat(CPIO, PBZX)` |
| Bytes after the short chunk | The data; `ARCHIVE_TRAILING_DATA` |
| An xz chunk that decodes to fewer bytes than it declares | `CorruptionError` |
| An xz chunk whose dictionary is over `max_decoder_memory` | `ResourceLimitError` |
