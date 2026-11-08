# format-makeself — makeself self-extracting archives

## ADDED Requirements

### Requirement: Detect a makeself archive by its header

Detection SHALL report `ArchiveFormat.MAKESELF` with `detected_by="magic"`,
`payload_offset=0` and `prefixed=False` for a source whose first bytes are
`#!/bin/sh\n# This script was generated using Makeself `. The format SHALL claim no
extension.

#### Scenario: detection

| Case | Expected |
| --- | --- |
| A `.run` from makeself 2.2.0 to 2.7.1, any compressor | `MAKESELF`, `CERTAIN` |
| The same bytes from a stream with no name | `MAKESELF` |
| `#!/bin/sh` followed by anything else | Not `MAKESELF` |

### Requirement: Locate payloads from the parsed header

The backend SHALL read the header without running it: the double-quoted assignments
before the first function definition, and after them the whole lines that state the
payload command and, before makeself 2.4.2, the line count. The header SHALL end after
`skip` lines, and the payloads SHALL follow it back to back with the sizes `filesizes`
lists. It SHALL refuse with `CorruptionError` a header where a variable is assigned twice,
a number is not a number, a digest is not hexadecimal of its length, `totalsize` is not
the sum of `filesizes`, the old offset lines disagree, or the payload command is not
one command. It SHALL refuse with `UnsupportedFeatureError` a payload command or
`decrypt_cmd` it does not read, and a header longer than 2 MiB. The header SHALL count
against `max_metadata_bytes` (`ResourceLimitError`).

#### Scenario: header parsing

| Case | Expected |
| --- | --- |
| A license text holding `skip="3"` and `MS_Printf()` lines | Ignored: inside a quoted value |
| `filesizes` assigned twice | `CorruptionError` |
| The file ends inside the header | `TruncatedError` |
| `max_metadata_bytes` below the header's length | `ResourceLimitError` |

### Requirement: List every payload's TAR

The backend SHALL read each payload as a TAR in the compressor the payload command
names (gzip, bzip2, xz, zstd, lz4, lzop, bzip3, Unix compress, or none), base64-decoded
first when the header says so, and list its members in payload order, a later payload's
after an earlier one's. It SHALL refuse a gpg or openssl payload with
`UnsupportedFeatureError` naming the cipher. Bytes after the last payload that are not
zero SHALL be reported with `ARCHIVE_TRAILING_DATA`. The archive SHALL be solid.

#### Scenario: listings

| Case | Expected |
| --- | --- |
| makeself 2.4.0, `--append` once | Both payloads' files; `makeself.payloads=2` |
| `--base64` (2.4.0 and 2.7.1) | The TAR's files |
| `--ssl-encrypt` | `UnsupportedFeatureError` |
| A pipe, `streaming=True` | The same files |

### Requirement: Check every digest the header states

For each payload the backend SHALL compute every digest the header states for it (the
POSIX `cksum` CRC, MD5, SHA-256) over the stored bytes while reading, and compare them
at the payload's end. Each file of a payload with a stated digest SHALL have
`verifiable=CHECKSUM`; a match SHALL raise each to `verified=CHECKSUM`; a mismatch SHALL
raise `CorruptionError` from the walk and make each a failure of `verify_all()`.

#### Scenario: digests

| Case | Expected |
| --- | --- |
| An unchanged fixture | `verify_all()` empty; every file `CHECKSUM` |
| One byte of an uncompressed payload changed | Listing raises; `verify_all()` returns every file of that payload |

### Requirement: Name makeself when another forced format fails on one

When `open_archive(..., format=)` names a format other than `MAKESELF` and the open
raises `CorruptionError` on a seekable source that starts with the makeself magic, the
message SHALL say the file is a makeself archive and how to open it.

#### Scenario: forced format

| Case | Expected |
| --- | --- |
| `format=TAR_GZ`, `TAR` or `ZIP` on a `.run` | `CorruptionError` naming makeself |
| `format=MAKESELF` | The files detection lists |
