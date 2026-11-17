## MODIFIED Requirements

### Requirement: uuencode and base64 are read as single files

uuencode (`.uu`, `.uue`) and bare base64 (`.b64`, `.base64`) text SHALL be read as one-member
archives like the compressors, and a TAR inside either SHALL be listed as the TAR.

uuencode SHALL be read from its first `begin MODE NAME` line to its `end` line, or from a
`begin-base64` line to `====`. Detection SHALL accept a `begin` line at offset 0 followed by a
valid encoded line, for any name, as `PROBABLE` from a content test, not as magic. With a `.uu` or `.uue` name, text before the `begin`
line SHALL be skipped, up to 64 KiB; past that the source SHALL be refused with
`CorruptionError`. A uuencode line longer than 4 096 bytes, before the `begin` line or after
it, SHALL raise `CorruptionError`, and detection SHALL NOT look past one for a `begin` line.
Bytes after the end line other than whitespace SHALL be trailing data. The stored name SHALL
be surfaced as `raw_name` and `extra["uu.original_filename"]` and SHALL NOT choose the
member's name; the stored mode SHALL be the member's `mode`.

Base64 SHALL be decoded with line breaks skipped, ending at `=` padding or the end of the
input; any other character, a space included, SHALL raise `CorruptionError`. Without a `.b64` or `.base64`
name, a source SHALL be detected as base64 only when its first four or more lines have one
length of at least 40 characters, all base64 characters, and decode to a known format's magic,
and SHALL then be reported as `PROBABLE`.

#### Scenario: uuencode and base64

| Source | Expected |
| --- | --- |
| `uuencode` output, any name | Detected, `PROBABLE`; reads the original bytes |
| A mail post with a uuencoded file, named `.uu` | Reads the file; the signature after `end` is `ARCHIVE_TRAILING_DATA` |
| The same post with no name | Not detected |
| A `begin` or `begin-base64` line followed by prose | Not detected |
| A uuencoded file with no `end` line | `TruncatedError` |
| A `.uu` post with one 5 000-byte line before `begin` | `CorruptionError` |
| Base64 of a ZIP, no name | Detected as base64, `PROBABLE` |
| Base64 of random bytes, a hex dump or a column of IDs, no name | Not detected |
| Base64 with a character outside the alphabet | `CorruptionError` |
| Unpadded base64 followed by a line of prose | `CorruptionError` |
