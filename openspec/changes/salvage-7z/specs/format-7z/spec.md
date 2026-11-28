# format-7z — salvage step 5 delta

## ADDED Requirements

### Requirement: Open a 7z whose start header is zero, as 7-Zip does

When bytes 8 to 31 of the 7z start header are all zero, the reader SHALL look for the
next header as 7-Zip does, in the default mode: the source's last byte SHALL be zero;
within the last 512 bytes of the source (fewer when less follows the start header, at
least 3), the pair `0x17 0x06` or `0x01 0x04` nearest the end SHALL start the next
header, which SHALL run to the end of the source. That next header SHALL be parsed and,
when encoded, decoded and checked against its folder CRC as any next header is. Only
that one pair SHALL be tried. When no pair is found, or its header does not parse, the
open SHALL raise `CorruptionError` as it does today, and the message SHALL say that the
start header is zero and no end header was found.

An archive opened this way SHALL emit `ARCHIVE_STRUCTURE_INCONSISTENT` once at open
(`diagnostics`, "7z start-header repair is reported"), and its pass SHALL NOT end in an
error. Every other start header that fails its CRC SHALL raise as it does today when
`salvage=False`.

#### Scenario: zeroed start header

| Case | Expected |
| --- | --- |
| 7-Zip archive with bytes 8–31 zeroed, encoded header | Every member lists and reads; one `ARCHIVE_STRUCTURE_INCONSISTENT`; no error at the end |
| The same, plain header of 150 bytes | Every member lists |
| The same, plain header of 594 bytes (starts before the last 512 bytes) | `CorruptionError`, as 7-Zip refuses it |
| Zeroed, one non-zero byte appended | `CorruptionError` |
| Zeroed, 16 zero bytes appended | `CorruptionError` (bytes after `kEnd`), as 7-Zip reports a headers error |
| Zeroed, under `DiagnosticPolicy.STRICT` | `DiagnosticRaisedError` at open |
| Only `StartHeaderCRC` damaged, `salvage=False` | `CorruptionError`, as today and as 7-Zip |

### Requirement: Salvage repairs a damaged 7z start header or end header

With `salvage=True`, when the start header fails its CRC and the default rule above does
not open the archive, the reader SHALL try, in order, and use the first that passes:

| Rule | Candidate | Accepted when |
| --- | --- | --- |
| R1 | the stored offset and size | the next header there passes the stored `NextHeaderCRC` |
| R2 | each change of one byte in bytes 12–31 under which the stored `StartHeaderCRC` passes | the next header that candidate describes passes its `NextHeaderCRC` |
| R3 | a span in the source's tail whose CRC-32 is the stored `NextHeaderCRC`: the stored size kept, then the stored offset kept, over the last 64 MiB; then neither kept, starts with `0x17 0x06`, `0x01 0x02`, `0x01 0x04` or `0x01 0x05`, over the last 1 MiB; each ending at the source's end or in the run of zero bytes before it (at most 64 KiB) or at the stored end | a span passes |
| R4 | only when bytes 8–31 are zero: each `0x17 0x06` or `0x01 0x04` pair in the last 1 MiB, nearest the end first | the header parses to its `kEnd` followed only by zero bytes; an encoded header also passes its folder CRC |

When the start header passes or was repaired and the next header fails its CRC or is
cut, the reader SHALL parse it anyway, and use it when it parses and, if encoded, its
decoded header passes its folder CRC.

Every byte R3 and R4 examine SHALL count against `SalvageLimits.max_search_bytes`. Every
member listed from a repaired or reused header SHALL carry `MEMBER_FOUND_BY_SCAN` with
`method="header_repair"` (R1, R2, a reused next header) or `method="header_search"` (R3,
R4), `offset` the absolute offset of the header used, `confirmed=True` and
`unchecked=()` when a CRC-32 confirmed that header, else `confirmed=False` and
`unchecked=("position",)`. Its data SHALL be read and checked as in any 7z. The pass
SHALL end in the error the default raises at open, and its message SHALL name the rule
that repaired the header.

#### Scenario: start and end header repair

| Case | Expected |
| --- | --- |
| `StartHeaderCRC` byte damaged | R1; every member, flagged `confirmed=True`; `CorruptionError` at the end |
| One byte of `NextHeaderOffset`, `NextHeaderSize` or `NextHeaderCRC` damaged | R2; every member, flagged |
| Two offset bytes damaged | R3 with the stored size |
| A size byte and the CRC byte damaged | R3 with the stored offset |
| Offset and size both damaged | R3 by the marker pair |
| Bytes 8–31 zero, 16 zero bytes appended | R4; every member, flagged |
| Next header fails its CRC, its encoded header decodes and passes its folder CRC | Members from it, `method="header_repair"` |
| Any of these with `salvage=False` | As today |
| `max_search_bytes=0`, two offset bytes damaged | No member; `ARCHIVE_REGION_SKIPPED(reason="search_limit")`; the error names the limit |

### Requirement: Salvage lists a 7z without a usable header as streams

With `salvage=True`, when no next header is usable, the reader SHALL walk the packed
area from offset 32 to the next header's start (when the start header passes or was
repaired and that start is in the source) or to the end of the source:

- At each walk position, a plain `kHeader` that parses there SHALL be taken as a header
  copy. Otherwise an LZMA2 stream SHALL start there when its first chunk resets the
  dictionary (control `0x01` or `0xE0`–`0xFF`). Its extent and unpacked size SHALL come
  from its chunk headers, without decoding. A chain that ends in `0x00` SHALL move the
  walk to the byte after it.
- LZMA1 with `lc=3 lp=0 pb=2` SHALL be tried only at offset 32 and, at a later walk
  position, only for a header copy (the first decoded byte is `0x01`).
- Where nothing starts, where a chain breaks, and after an LZMA1 stream, the reader
  SHALL search forward, one byte at a time, over unclaimed bytes, for an LZMA2 stream
  whose first chunk resets the dictionary, whose chain ends in `0x00` or runs exactly to
  the area's end, and which holds at least one LZMA chunk whose first decodes without
  error. A chain of uncompressed chunks only SHALL NOT be a search candidate. Each range
  stepped over SHALL be one `ARCHIVE_REGION_SKIPPED` (`reason="no_header"`).
- When the walk ends without a header copy, the reader SHALL search the last 1 MiB of
  the area backwards for an LZMA1 stream that decodes to `0x01`.

A header copy SHALL be used when it parses to its `kEnd` and its pack info agrees with
the walk: every LZMA2 stream found starts at one of its pack positions, with the
unpacked size its chain gave. Its members SHALL be listed by name with
`MEMBER_FOUND_BY_SCAN` (`method="header_search"`, `confirmed=True`), and no stream it
names SHALL also be listed as content.

Every other stream SHALL be one member, in archive order: name
`__salvaged__/7z-stream-NNNN.bin`, `NNNN` its place among the streams from `0001`, at
least four digits; type `FILE`; size the chain's unpacked size, or `None` for a cut
stream and for an LZMA1 stream; no times, mode or attributes; `verifiable` `UNLOCKED`;
one `MEMBER_NAME_UNKNOWN` at listing, with `unchecked` holding `"name"` and `"filters"`,
and `"size"` when the size is `None`. Its read SHALL decode the stream as a one-coder
folder whose LZMA2 dictionary is the smallest at least its unpacked size (an LZMA1
stream, whose size is not known: the most bytes its read can give, `max_ratio` times its
packed size and at least `ratio_activation_threshold`, at most `max_decoder_memory` and
4 GiB − 1), under `DecoderLimits` and `ExtractionLimits`. A cut stream's read SHALL
deliver every byte that decodes, then raise `TruncatedError`. A decoder error SHALL
raise `CorruptionError` after the bytes before it. The pass SHALL end in the error the
default raises at open.

#### Scenario: 7z packed-area walk

| Case | Expected |
| --- | --- |
| Non-solid LZMA2, cut at 50 % | One content member per file before the cut, byte-exact; the cut one with `size=None`, its read raising `TruncatedError` after its bytes; `TruncatedError` at the end |
| Solid LZMA2, cut at 50 % | One content member holding the files before the cut, in order |
| Encoded header, cut right before the next header | Every member by name from the header copy; no content member |
| The same with the 36-byte next header damaged (start header intact) | As above, or from the reused next header when it decodes |
| LZMA1 solid, cut right before the next header | Header copy found by the tail search; every member by name |
| AES-encrypted folders, cut | No member; one `ARCHIVE_REGION_SKIPPED` |
| BCJ2 folder, cut | The main stream as a content member; then a search |
| 4 KiB zeroed inside a non-solid archive, then cut | Members before the zeros; the next stream found by the search; one `ARCHIVE_REGION_SKIPPED` |
| Any of these, `salvage=False` | As today |
| Content member under `DiagnosticPolicy.STRICT` | Listed; the pass ends in the default's error |

### Requirement: Salvage opens a 7z whose start is lost

With `salvage=True`, when detection finds no format and `format="7z"` or the source's
extension picks 7z, the reader SHALL search the last 1 MiB as R4 does for an end header.
When one is found, the count of lost bytes SHALL be
`32 + (end of the last packed stream, as the header gives it) − (the header's found offset)`,
and every folder whose packed streams start at or after that count SHALL be listed and
read with stored offsets corrected by it, flagged as for R4. A folder that started in
the lost bytes SHALL NOT be listed, nor its files. Without an end header, the walk SHALL
start with a search from offset 0. `ARCHIVE_REGION_SKIPPED` SHALL cover the bytes before
the first folder or stream found.

#### Scenario: 7z lost start

| Case | Expected |
| --- | --- |
| Non-solid 7z, first 4 KiB deleted, named `.7z` | Members of the folders after the lost bytes, by name; `ARCHIVE_REGION_SKIPPED` from 0 |
| The same named `.bin`, no `format=` | Raises as today |
| Solid 7z, first 4 KiB deleted | No member from the solid folder; the region skipped |
