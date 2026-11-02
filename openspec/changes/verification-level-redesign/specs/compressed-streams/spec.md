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

- `NONE`: the stream has not opened its member, or a check that can pass by chance
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
  over several files) SHALL NOT raise any member's level; a 7z folder CRC over a single
  file SHALL count as that file's digest when it has none of its own.

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
| TAR member of a `.tar.gz`, read to the end | `LENGTH` (the trailer spans members) |
| 7z one-file folder with a folder CRC and no file CRC, read to the end | `CHECKSUM` |
| 7z folder of several files with only a folder CRC, a file read to the end | `LENGTH` |
| 7z AES folder with no CRC, read to the end | `verified` and `verifiable` are `NONE` |
| 7z: a file's CRC matches in AES folder A; AES folder B has no CRC, read to the end | B stays `NONE`: A's match does not prove B's key |
| ZipCrypto member, password on its check byte, half read | `verified` is `NONE`; `verifiable` is `CHECKSUM` |
| Same member read to the end, CRC matches | `CHECKSUM` |
| Encrypted member with no stored digest, password accepted only on a weak check | `verifiable` is `NONE`; it rises once the password is confirmed |
| WinZip AES AE-2 member read to the end | `CHECKSUM` (the HMAC) |
| Lazy stream from `stream_members()`, before its first read | `verified` is `NONE` |
| Member whose read raises `CorruptionError` | `verified` stays at the level it had before that read |
| Reading `verified` on a stream that has not opened | Opens nothing; returns `NONE` |
