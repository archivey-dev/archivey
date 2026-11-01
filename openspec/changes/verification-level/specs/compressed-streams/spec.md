# compressed-streams — verification level delta

## ADDED Requirements

### Requirement: A stream reports the verification it has reached and can reach

Every public `ArchiveStream` SHALL expose two read-only properties of type
`archivey.Verification`, an `IntEnum` ordered `NONE < KEY < STRUCTURE < CONTENT`:

- `verified`: the highest level the stream has proved. It SHALL NOT decrease, and a
  read that raises SHALL NOT raise it.
- `verifiable`: the highest level a read from the start to the end can reach.
  `verified` SHALL NOT exceed it. Before a lazy stream opens its member it describes
  what the stream knows without opening it. Once the stream is open it MAY rise (a
  password confirmed by another member) and SHALL NOT fall.

The levels mean:

- `NONE`: the stream has not opened its member, or a check that can pass by chance
  accepted its password and nothing has confirmed it since.
- `KEY`: the member is not encrypted, or its password passed a check that cannot pass
  by chance.
- `STRUCTURE`: `KEY`, and a read reached the end with every length and end-of-data
  check passing.
- `CONTENT`: `STRUCTURE`, and a stored check over every byte matched: a member digest
  the verifier computes, the WinZip AES HMAC, or a codec's own checksum over a decode
  from the start with no seek between, other than seeks to 0.

The level SHALL NOT claim a check that did not run. Where a check cannot be traced to
the stream, the level SHALL report less. Reading the properties SHALL NOT read,
decode or seek.

A stream that reaches the end raises any content verdict from that read, as today. The
level adds no new error.

#### Scenario: verification level matrix

| Case | Expected |
| --- | --- |
| ZIP deflate member with CRC-32, read to the end | `verified` is `CONTENT`; `verifiable` is `CONTENT` |
| Same member, half read | `verified` is `KEY` |
| Same member, `seek(0)` after a full read, then half read | `verified` stays `CONTENT` |
| TAR member read to the end | `verified` and `verifiable` are `STRUCTURE` |
| `.gz` file through `open_stream`, read to the end | `CONTENT` |
| `.gz` file, seek forward through an index, then read to the end | `STRUCTURE`; a `seek(0)` and a read to the end then gives `CONTENT` |
| `.xz` file read to the end | `STRUCTURE` (frame checks not traced yet) |
| ZipCrypto member, password on its check byte, half read | `verified` is `NONE`; `verifiable` is `CONTENT` |
| Same member read to the end, CRC matches | `CONTENT` |
| Encrypted member with no stored digest, password accepted only on a weak check | `verifiable` is `NONE`; it rises once the password is confirmed |
| WinZip AES AE-2 member read to the end | `CONTENT` (the HMAC) |
| Lazy stream from `stream_members()`, before its first read | `verified` is `NONE` |
| Member whose read raises `CorruptionError` | `verified` stays at the level it had before that read |
| Reading `verified` on a stream that has not opened | Opens nothing; returns `NONE` |

### Requirement: A stream verifies itself on request

Every public `ArchiveStream` SHALL have a `verify(level=Verification.CONTENT)` method that
runs the stream's checks, discarding the bytes, and returns `verified`. The goal is `level`,
or `verifiable` when that is lower. It SHALL raise what its reads raise and nothing else.
It SHALL NOT raise when the goal is below `level`, or when `verified` ends below the goal:
it returns `verified`, and the caller compares. Its own seeks SHALL NOT report
`STREAM_REWIND_REDECOMPRESSES`. On a closed stream it SHALL raise
`ValueError`.

On a stream that can seek, it SHALL read on until `verified` reaches the goal, and SHALL
read nothing when the goal is already reached and `verified` is above `NONE`, or when
`level` is `NONE`. When the reads end below the goal and the stream did not start at 0, it
SHALL seek to 0 and read on once more. It SHALL then seek back to the position it started
from, also when a read raised, so a later `read()` returns the same bytes.

On a stream that cannot seek, it SHALL read to the end whatever `level` is, and every later
`read()`, `readinto()` or `read_ahead()` SHALL raise `ArchiveyUsageError`, also when a check
failed. A later `verify()`, at any level, SHALL read nothing: it SHALL raise the first
call's check failure again if that call failed, and otherwise return `verified`.

A later release MAY reach a level with less reading (a cheaper key check); the returned
level and the errors SHALL stay those a read to the goal gives.

#### Scenario: verify matrix

| Case | Expected |
| --- | --- |
| Fresh ZIP deflate member | returns `CONTENT` |
| Same member, 100 bytes read first | returns `CONTENT` |
| Member already at `CONTENT`, positioned mid-way | returns `CONTENT`; position unchanged |
| ZIP member whose CRC fails | raises `CorruptionError`; `verified` stays `KEY` |
| Seekable member whose CRC fails, 100 bytes read first | raises `CorruptionError`; position 100 |
| TAR member | returns `STRUCTURE` |
| Seekable member, 100 bytes read first | returns `CONTENT`; position 100; `read()` gives the rest |
| Seekable `.gz` member after a forward seek | reads again from 0; returns `CONTENT`; position restored |
| Lazy `stream_members()` stream | opens, reads, returns `CONTENT` |
| `stream_members()` stream, `verify(NONE)`, `KEY` or `CONTENT` | reads to the end; returns `CONTENT`; later `read()` raises `ArchiveyUsageError`; a second `verify()` returns `CONTENT` |
| `stream_members()` stream whose CRC fails | raises `CorruptionError`; later `read()` raises `ArchiveyUsageError`; a later `verify(KEY)` raises `CorruptionError` again |
| Forward-only stream, `verify(KEY)` then `verify(CONTENT)`, or the reverse | both return `CONTENT`; the second reads nothing |
| Forward-only `open_stream()` | returns `CONTENT` |
| Closed stream, whatever its level | raises `ValueError` |
| `verify(KEY)` on an open seekable unencrypted member | reads nothing; returns `KEY` |
| `verify(KEY)` on a ZipCrypto member (one-byte check only) | reads to the CRC; returns `CONTENT` |
| `verify(KEY)` under a colliding wrong ZipCrypto password | raises `EncryptionError` |
| `verify(CONTENT)` on a TAR member | returns `STRUCTURE` |
| `verify(NONE)` on a seekable stream | reads nothing |
