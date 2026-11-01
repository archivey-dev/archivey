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

Every public `ArchiveStream` SHALL have a `verify()` method that reads the rest of the
stream, discards the bytes, and returns `verified`. It SHALL read nothing when `verified`
already equals `verifiable` and is above `NONE`. When the read reaches the end with
`verified` below `verifiable` and the stream can seek, it SHALL seek to 0 and read to the end
once more. It SHALL raise what those reads raise and nothing else, and SHALL NOT raise for a
level below `verifiable`. It leaves the stream at its end.

#### Scenario: verify matrix

| Case | Expected |
| --- | --- |
| Fresh ZIP deflate member | returns `CONTENT` |
| Same member, 100 bytes read first | returns `CONTENT` |
| Member already at `CONTENT`, positioned mid-way | returns `CONTENT`; position unchanged |
| ZIP member whose CRC fails | raises `CorruptionError`; `verified` stays `KEY` |
| TAR member | returns `STRUCTURE` |
| Seekable `.gz` member after a forward seek | reads again from 0; returns `CONTENT` |
| Lazy `stream_members()` stream | opens, reads, returns `CONTENT` |
