# compressed-streams — verification level delta

## ADDED Requirements

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

- `NONE`: the stream has not opened its member, or a check that can pass by chance
  accepted its password and nothing has confirmed it since.
- `PASSWORD`: the member is not encrypted, or its password passed a check that cannot pass
  by chance.
- `LENGTH`: `PASSWORD`, and a read reached the end with every length and end-of-data
  check passing.
- `CHECKSUM`: `LENGTH`, and a stored check over every byte matched: a member digest
  the verifier computes, the WinZip AES HMAC, or a codec's own checksum over a decode
  from the start with no seek between, other than seeks to 0.

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
| `.xz` file read to the end | `LENGTH` (frame checks not traced yet) |
| ZipCrypto member, password on its check byte, half read | `verified` is `NONE`; `verifiable` is `CHECKSUM` |
| Same member read to the end, CRC matches | `CHECKSUM` |
| Encrypted member with no stored digest, password accepted only on a weak check | `verifiable` is `NONE`; it rises once the password is confirmed |
| WinZip AES AE-2 member read to the end | `CHECKSUM` (the HMAC) |
| Lazy stream from `stream_members()`, before its first read | `verified` is `NONE` |
| Member whose read raises `CorruptionError` | `verified` stays at the level it had before that read |
| Reading `verified` on a stream that has not opened | Opens nothing; returns `NONE` |
