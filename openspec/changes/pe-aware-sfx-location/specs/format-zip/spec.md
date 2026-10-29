## MODIFIED Requirements

### Requirement: Report bytes after the end of a ZIP archive

A ZIP archive SHALL be taken to end at the end of its end-of-central-directory record
plus the comment length that record declares. At open, a non-zero byte after that end
SHALL emit one `ARCHIVE_TRAILING_DATA` with `format="zip"`,
`expected_marker="zeros_to_eof"`, `observed_kind="nonzero"` and `observed_bytes` the
offset of that byte past the end. It is a warning by default and raises under
`DiagnosticPolicy.STRICT` (DR-3). Zero bytes after the end SHALL be silent. Bytes inside
the declared comment are the comment, whatever they hold. The end record is searched for
in the last 65 558 bytes before the payload end (`archive-reading`, *Honour detection
payload_offset at open*), which is the end of the file when there is none. Opened at start 0
with no end passed, the seekable reader reads its first bytes to derive one, so a forced
`format=ZIP` searches the same span as auto-detect. Bytes at or past
the payload end are the executable's certificate, not data after the archive, and SHALL
raise no diagnostic; a non-zero byte between the archive's end and the payload end is
reported as above. When a longer tail hides the end record, the reader SHALL walk
the local headers from the start, without decoding any member, to where the members end,
and step over the directory and the ZIP64 end records there to the end record, which is
then read as one the search found. Each local header the walk meets SHALL count toward
`max_members` before its data is passed. A read from a pipe steps over the same records
after its pass. A stub before the archive moves nothing. 7-Zip 23.01 warns on any tail;
Info-ZIP `unzip` says nothing.

#### Scenario: ZIP trailing bytes

| Archive | Expected |
| --- | --- |
| Ends at its end record, with or without a comment | No diagnostic |
| 4096 zero bytes after the end record | No diagnostic; `STRICT` opens it |
| 0, 100 or 60 000 zero bytes then `JUNK` after the end record or its comment | One `ARCHIVE_TRAILING_DATA`, `observed_bytes` 0, 100 or 60 000; members list and read |
| A 1000-byte stub before the archive, 7 zero bytes and `JUNK` after it | `observed_bytes` 7 |
| `JUNK` after the end record under `STRICT` | `DiagnosticRaisedError` |
| 1 MiB of non-zero bytes after the end record, from a file or a pipe | One `ARCHIVE_TRAILING_DATA`, `observed_bytes` 0; members list and read |
| The same with the directory gone | Members listed from their local headers, then `CorruptionError` (see the next requirement) |
| Signed PE SFX: ZIP, zero padding, certificate (`payload_end` known) | No diagnostic; `STRICT` opens it |
| Signed PE SFX: ZIP, `JUNK`, certificate | One `ARCHIVE_TRAILING_DATA` for `JUNK`; nothing for the certificate |
| ZIP whose offsets count from byte 0, followed by a certificate over 64 KiB | The search before the payload end finds the end record; members list and read |

