# format-detection — compressed streams behind a `#!` script

## ADDED Requirements

### Requirement: A compressed stream behind a `#!` script is found by the SFX scan

When the source starts with `#!` and is not an archive at byte 0 (a makeself archive is,
by its header), the SFX scan SHALL also look for the magic of the single-file codecs
that declare a script-payload header check (`StreamCodec.script_payload_check`): gzip,
bzip2, xz, zstd, LZ4 frame and lzip. A hit SHALL be taken only when its check accepts
the header fields after the magic, so that text passes by chance less often than once
in 2**32: gzip's reserved flags, level and OS bytes; bzip2's block size digit, then its end-of-stream
magic, or its first block magic and the byte after that block's CRC (the block magic is
printable text); xz's stream flags and their CRC32; zstd's reserved
descriptor bit; LZ4's version, reserved bits and block size; lzip's version and
dictionary size. Unix compress (a two-byte magic), the legacy LZ4 format and an
uncompressed TAR (`ustar`) SHALL NOT be claimed there. Only a script cues these needles:
an executable stub carries no bare stream.

The earliest accepted hit among these and the scan's ZIP, 7z and RAR needles SHALL be
the answer, as the scan already chooses. A stream hit SHALL then be probed for an inner
container from its offset, with the decode charged to the budget's `max_decode_input` as
for a stream at byte 0, and reported as that container in the stream (`TAR_GZ`), or as
the bare stream when nothing is recognised inside or the budget allows no decode. The
answer SHALL keep `detected_by="sfx_scan"`, `confidence=PROBABLE`, `prefixed=True` and
`payload_offset` at the stream's first byte, and `open_archive` SHALL read the TAR or
the stream from there, from a path, a seekable stream or a pipe.

A forced `format=TAR_GZ` (or another compressed TAR) on such a script SHALL still fail
at byte 0: the TAR backend declares no SFX magic, so no forced-format locator runs.

#### Scenario: script payloads

| Case | Expected |
| --- | --- |
| CPack STGZ installer (`cpack -G STGZ`) | `TAR_GZ`, `sfx_scan`, `prefixed=True`, `payload_offset` at the gzip header; its files read |
| A script followed by a gzip, bzip2, xz, zstd, LZ4 or lzip TAR | That compressed TAR at the script's end, from a path, a stream and a pipe |
| A script followed by a gzip stream of text | `GZ` at the stream |
| The same with `max_decode_input=0` | `GZ`: the stream is found, its content not probed |
| A script whose text holds a gzip, bzip2 or xz magic with a header that fails its check | `FormatDetectionError` |
| A script followed by an uncompressed TAR | `FormatDetectionError` |
| An `MZ` stub followed by a `.tar.gz` | `FormatDetectionError` |
