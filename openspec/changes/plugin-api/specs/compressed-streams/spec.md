## ADDED Requirements

### Requirement: LZO is a built-in codec

archivey SHALL read the `.lzo` file format `lzop` writes (`StreamFormat.LZOP`) as a
single compressed file and around a TAR (`.tar.lzo`, `.tzo`), and SHALL decode raw
LZO1X (`CompressionAlgorithm.LZO`) through `ReaderContext.decompress` with `size` as the
most it may decode to. LZO1X SHALL decode with liblzo2 through `python-lzo` when it is
installed and not excluded (`OptionalLibrary.LZO`), and otherwise in Python, with the
same results; neither is a requirement, so the formats are available in a core install.
An lzop header's checksum, and each block checksum its flags ask for, SHALL be checked.
An lzop method other than LZO1X (1 to 3), or a filter, SHALL raise
`UnsupportedFeatureError`.

#### Scenario: lzop files

| Case | Expected |
| --- | --- |
| A file `lzop` 1.04 wrote, with or without `python-lzo` | The input bytes; name, mtime and mode from the header |
| Two files `lzop -c a b` wrote | Their contents, one after the other |
| A `.tar.lzo` with no name | `ArchiveFormat(TAR, StreamFormat.LZOP)` by the inner probe |
| The file cut short | `TruncatedError` |
| A changed byte under the header checksum | `CorruptionError` |
| `ReaderContext.decompress(data, CompressionAlgorithm.LZO)` with no `size` | `UnsupportedFeatureError` |
| An lzop block that declares more than 64 MiB | `CorruptionError` |
| An lzop block over `DecoderLimits.max_decoder_memory` | `ResourceLimitError` |
| Detection meeting an lzop block larger than its probe decodes | Not decoded; the probe can't tell |
