# compressed-streams — verification level redesign delta

## MODIFIED Requirements

### Requirement: A stream reports the verification it has reached and can reach

Every public `ArchiveStream` SHALL expose two read-only properties of type
`archivey.Verification`, an `IntEnum` ordered `NONE < PASSWORD < LENGTH < CHECKSUM`:

- `verified`: the highest level the stream has proved. It SHALL NOT decrease, and a
  read that raises SHALL NOT raise it.
- `verifiable`: the highest level a read from the start to the end can reach.
  `verified` SHALL NOT exceed it. Before a lazy stream opens its member it describes
  what the stream knows without opening it. Once the stream is open it MAY rise (a
  password confirmed by another member) and SHALL NOT fall.

The levels mean:

- `NONE`: nothing is proved yet about the data, or a check that can pass by chance
  accepted its password and nothing has confirmed it since.
- `PASSWORD`: the member is not encrypted, or its password passed a check that cannot pass
  by chance.
- `LENGTH`: `PASSWORD`, and a read reached the end with every length and end-of-data
  check passing.
- `CHECKSUM`: `LENGTH`, and every output byte passed a stored check that a wrong byte
  fails, at any layer: a member digest the verifier computes, the WinZip AES HMAC, a
  codec's whole-stream checksum, or per-frame or per-block checks that cover every frame
  of an `.xz`, `.zst` or `.lz4` file. A codec check counts only over a decode from the
  start with no seek between, other than seeks to 0. The check's value need not be
  exposed. A check that spans several members (a `.tar.gz` trailer, a 7z folder CRC
  over several files) SHALL raise the level of every member it covers only once it
  passes, at the end of the folder or stream; a 7z folder CRC over a single file SHALL
  count as that file's digest when it has none of its own. A member stream's
  `verified` and `verifiable` SHALL equal those of the reader's own member with the
  same identity, at every moment, whether or not the stream has opened its data; a
  stream opened from a `replace()` copy mirrors and raises the reader's member, not the
  copy.

The level SHALL NOT claim a check that did not run. Where a check cannot be traced to
the stream, the level SHALL report less. Reading the properties SHALL NOT read,
decode or seek.

A stream that reaches the end raises any content verdict from that read, as today. The
level adds no new error and no new way to read.

#### Scenario: verification level matrix

| Case | Expected |
| --- | --- |
| ZIP deflate member with CRC-32, read to the end | `verified` is `CHECKSUM`; `verifiable` is `CHECKSUM` |
| Same member, half read | `verified` is `PASSWORD` |
| Same member, `seek(0)` after a full read, then half read | `verified` stays `CHECKSUM` |
| TAR member read to the end | `verified` and `verifiable` are `LENGTH` |
| `.gz` file through `open_stream`, read to the end | `CHECKSUM` |
| `.gz` file, seek forward through an index, then read to the end | `LENGTH`; a `seek(0)` and a read to the end then gives `CHECKSUM` |
| `.xz` file, every block checked, read to the end | `CHECKSUM` |
| `.xz` file with one stream of check type None, read to the end | `LENGTH` |
| `.zst` file, every frame with a content checksum, read to the end | `CHECKSUM` |
| `.lz4` frame with a content checksum, read to the end | `CHECKSUM` |
| `.zst` file with one frame lacking Content_Checksum_flag, read to the end | `LENGTH` |
| `.zst` file with a skippable frame between checked frames, read to the end | `CHECKSUM` |
| `.lz4` frame with block checksums only, read to the end | `CHECKSUM` |
| Legacy-format `.lz4` stream, alone or followed by a checked frame, read to the end | `LENGTH` |
| TAR member of a `.tar.gz`, read to the end | `LENGTH`; `CHECKSUM` once the archive is read to its end and the trailer matches |
| `.tar.gz` listed to its end, trailer matches | every member's `verified` is `CHECKSUM` |
| 7z one-file folder with a folder CRC and no file CRC, read to the end | `CHECKSUM` |
| 7z folder of several files with only a folder CRC, a file read to the end | `LENGTH`; `CHECKSUM` for all once the folder is read and its CRC matches |
| 7z AES folder with no CRC, read to the end | `verified` and `verifiable` are `NONE` |
| 7z: a file's CRC matches in AES folder A; AES folder B has no CRC, read to the end | B stays `NONE`: A's match does not prove B's key |
| ZipCrypto member, password on its check byte, half read | `verified` is `NONE`; `verifiable` is `CHECKSUM` |
| Same member read to the end, CRC matches | `CHECKSUM` |
| Encrypted member with no stored digest, password accepted only on a weak check | `verifiable` is `NONE`; it rises once the password is confirmed |
| WinZip AES AE-2 member read to the end | `CHECKSUM` (the HMAC) |
| Lazy stream from `stream_members()`, before its first read, member not yet proved | `verified` is `NONE` |
| Random-access reader after `verify_all()`; a lazy `stream_members()` stream before its first read | `verified` is the member's level (`CHECKSUM` for a ZIP member with a CRC) |
| Stream opened from a `replace()` copy of a member, read to the end | the reader's own member rises to `CHECKSUM`; the copy keeps the level it was copied with |
| Member whose read raises `CorruptionError` | `verified` stays at the level it had before that read |
| Reading `verified` on a stream that has not opened | Opens nothing; returns the member's level (`NONE` when nothing is proved) |

### Requirement: A stream verifies itself on request

Every public `ArchiveStream` SHALL have a `verify(*, password_only=False)` method that
runs the stream's checks, discarding the bytes, and returns `verified`. Its target is
`verifiable`, or `PASSWORD` when `password_only` is true (`verifiable` when that is
lower). It SHALL raise what its reads raise and nothing else. It SHALL NOT raise when
`verified` ends below the target: it returns `verified`, and the caller compares. Its
own seeks SHALL NOT report `STREAM_REWIND_REDECOMPRESSES`. On a closed stream it SHALL
raise `ValueError`. It SHALL NOT read past its own member.

On a stream that can seek, it SHALL read on until `verified` reaches the target, and
SHALL read and decode nothing when `verified` has already reached the target and is
above `NONE`. A target of `NONE` is never reached this way, so the length and
end-of-data checks still run to the end. When the reads end below the target and the
stream did not start at 0, it SHALL seek to 0 and read on once more. It SHALL then seek
back to the position it started from, also when a read raised, so a later `read()`
returns the same bytes.

On a stream that cannot seek, it SHALL read to the end whatever the target, and every
later `read()`, `readinto()` or `read_ahead()` SHALL raise `ArchiveyUsageError`, also
when a check failed. When `verified` has already reached the target and is above
`NONE`, it SHALL mark the stream consumed without reading. A later `verify()` SHALL
read nothing: it SHALL raise the first call's check failure again if that call failed,
and otherwise return `verified`.

A later release MAY reach a target with less reading (a cheaper password check); the
returned level and the errors SHALL stay those a read to the target gives.

#### Scenario: verify matrix

| Case | Expected |
| --- | --- |
| Fresh ZIP deflate member | returns `CHECKSUM` |
| Same member, 100 bytes read first | returns `CHECKSUM`; position 100 |
| Member already at `CHECKSUM`, positioned mid-way | reads nothing; returns `CHECKSUM`; position unchanged |
| ZIP member whose CRC fails | raises `CorruptionError`; `verified` stays `PASSWORD` |
| TAR member | returns `LENGTH` |
| Seekable `.gz` member after a forward seek | reads again from 0; returns `CHECKSUM`; position restored |
| `stream_members()` stream, either mode | reads to the end; later `read()` raises `ArchiveyUsageError`; a second `verify()` reads nothing |
| `stream_members()` stream whose CRC fails | raises `CorruptionError`; later `read()` raises `ArchiveyUsageError`; a second `verify()` raises `CorruptionError` again |
| Non-seekable stream whose member is already at `CHECKSUM` (proved by `verify_all()`) | reads nothing; returns `CHECKSUM`; later `read()` raises `ArchiveyUsageError` |
| Forward-only `open_stream()` `.gz` | returns `CHECKSUM` |
| Closed stream | raises `ValueError` |
| `password_only=True` on a seekable unencrypted member | reads nothing; returns `PASSWORD` |
| `password_only=True` on a ZipCrypto member (one-byte check only) | reads to the CRC; returns `CHECKSUM` |
| `password_only=True` under a colliding wrong ZipCrypto password | raises `EncryptionError` |
| 7z AES member with no CRC, truncated | raises `TruncatedError`, on a first and on a second call |
| 7z AES member with no CRC, intact | reads to the end; returns `NONE` |

