## MODIFIED Requirements

### Requirement: Report bytes after the end of a 7z archive

A 7z archive SHALL be taken to end at the later of the end of its next header
(signature header plus `NextHeaderOffset` plus `NextHeaderSize`) and the end of its
last packed stream (signature header plus `PackPos` plus the pack sizes), both counted
from the signature origin and including an encoded header's packed stream. After the
header has parsed, the reader SHALL look at most 1 MiB past that end, and a non-zero
byte there SHALL emit one `ARCHIVE_TRAILING_DATA` with `format="7z"`,
`expected_marker="zeros_to_eof"`, `observed_kind="nonzero"` and `observed_bytes` the
offset of that byte past the end. It is a warning by default and raises under
`DiagnosticPolicy.STRICT` (DR-3). Zero bytes after the end SHALL be silent. A
non-zero byte at 1 MiB or more past the end goes unseen: the bound is an effort limit,
as for the TAR trailer scan. The scan SHALL stop at the payload end (`archive-reading`,
*Honour detection payload_offset at open*): a code-signed self-extractor's certificate
table is identified, not data after the archive, and SHALL raise no diagnostic. Any
other tail of a self-extractor is reported the same way as above, measured from the
archive's own end, not the file's. 7-Zip 23.01 warns "There are data after the end of archive" for any tail, zeros
included; archivey keeps an all-zero tail silent, the DR-3 rule shared with TAR.

#### Scenario: 7z trailing bytes

| Case | Default policy | `STRICT` |
| --- | --- | --- |
| Archive ends at its next header | Nothing | Opens |
| 4 KiB of zeros after the next header | Nothing | Opens |
| `b"JUNK"` after the next header, or after fewer than 1 MiB of zeros | `ARCHIVE_TRAILING_DATA`, `observed_bytes` = zeros skipped | `DiagnosticRaisedError` |
| Two 7z archives concatenated | First listed; `ARCHIVE_TRAILING_DATA` at 0 | `DiagnosticRaisedError` |
| `b"JUNK"` at 1 MiB or more past the end | Nothing (past the scan bound) | Opens |
| Packed stream after the next header, nothing after it | Nothing | Opens |
| Empty archive (`NextHeaderSize` 0) followed by `b"JUNK"` | `ARCHIVE_TRAILING_DATA` at 0 | `DiagnosticRaisedError` |
| Signed PE SFX: 7z, certificate (`payload_end` known) | Nothing | Opens |
| Signed PE SFX: 7z, `b"JUNK"`, certificate | `ARCHIVE_TRAILING_DATA` for `JUNK`; nothing for the certificate | `DiagnosticRaisedError` |
| Unsigned 7z SFX with a tail | `ARCHIVE_TRAILING_DATA` | `DiagnosticRaisedError` |

