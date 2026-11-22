# Design — salvage, step 5: 7z

The salvage design is the design-draft PR #1399 (`salvage-design-2026-11-09.md`). Its §0
holds the maintainer's rulings of 2026-11-20 (Q1–Q18), which override its other text.
"Q*n*" below is one of those rulings. Step 3 (`openspec/changes/salvage-mode`) defines
`salvage=`, `SalvageLimits`, `MEMBER_FOUND_BY_SCAN`, `SalvageScanContext`,
`ARCHIVE_REGION_SKIPPED` and the search driver. This change uses them and does not
change them, except where §Diagnostics says so.

## Context

### Rulings this step applies

- **Recall first.** Salvage lists every candidate that passes the format's own check,
  flagged. Confirmation decides the flag, not whether the member is listed.
- **Q2 add-only.** `salvage=True` never changes or drops a member the default lists. It
  only adds members, each flagged.
- **Q4.** Content without a header is listed as members under `__salvaged__/`, named
  per §7.3 and numbered in archive order, flagged `MEMBER_NAME_UNKNOWN`.
- **Q5.** Unknown bytes are never filled. A read stops at the hole and raises.
- **Q7.** `SalvageLimits`, uncapped by default. Each byte is searched at most once per
  layer. Decoding limits apply unchanged.
- **Q9.** Salvage needs a seekable source. 7z needs one in every mode anyway.
- **Q14.** Lost start: `format=` or the file name's extension picks the format.
- **Q15.** 7z start-header repair follows 7-Zip, measured first: if 7-Zip opens such a
  file by default, archivey's default does too, flagged. Otherwise salvage only.
- **Q18.** `verifiable` for a member only salvage reaches is what its own read can
  still check (salvage design §9).

### The 7z layout this depends on

```text
offset 0   magic(6) ver(2) StartHeaderCRC(4) | NextHeaderOffset(8) NextHeaderSize(8) NextHeaderCRC(4)
offset 32  packed streams ...  [packed header stream]  next header
                                 (LZMA1, when the       (kHeader 0x01, or
                                  header is encoded)     kEncodedHeader 0x17, 36 bytes or so)
```

- `StartHeaderCRC` covers bytes 12–31. `NextHeaderCRC` covers the next header.
- 7-Zip writes the next header last and the start header after it: it first writes the
  start header as zeros, then the packed streams, then the header, then seeks back.
- By default (`-mhc=on`) the header is LZMA-compressed into a packed stream of its own,
  and the next header is a short `kEncodedHeader` that describes that stream, with a
  CRC of the decoded header. With `-mhc=off` the next header is the plain `kHeader`.
- An LZMA2 stream is a chain of chunks. Each chunk header holds the chunk's packed and
  unpacked sizes, and the chain ends with a `0x00` byte. So a stream's extent and its
  unpacked size are known from its chunk headers alone, without decoding.
- An LZMA1 stream as 7-Zip writes it has no end marker. Its end is known only from the
  header.

## Measurements

All in the session container, 2026-11-22, on archives 7-Zip 26.05 (`7zz`) wrote from 12
files (430 KB, a quarter of them random bytes): solid LZMA2 (`-ms=on -mmt=1`), non-solid
(`-ms=off`), LZMA1 (`-m0=lzma`), plain header (`-mhc=off`), BCJ (`-mf=BCJ`), Delta
(`-m0=Delta:4 -m1=LZMA2`) and AES (`-pabc`), and a 44 MB set for timing. Scripts in the
session scratchpad, not committed; tasks 1.1 turns them into fixtures and tests.

### Q15: what 7-Zip does with a damaged start header

`7zz l`, `7zz t` and `7zz x` agree in every row (the same exit code and message); 7-Zip
23.01 (`7z`) gives the same exit codes. "Fixed CRC" means the field was changed and
`StartHeaderCRC` recomputed, which only a tool does, not real damage.

| Damage | 7-Zip result | Exit | archivey today |
| --- | --- | --- | --- |
| Intact | 12 files, "Everything is Ok" | 0 | opens |
| `StartHeaderCRC` byte changed | "Is not archive" | 2 | `CorruptionError` (start header CRC) |
| `NextHeaderOffset` +1 | "Is not archive" | 2 | `CorruptionError` |
| `NextHeaderOffset` high byte changed | "Is not archive" | 2 | `CorruptionError` |
| `NextHeaderOffset` +1, fixed CRC | "Unexpected end of archive" | 2 | `CorruptionError` |
| `NextHeaderSize` +1 | "Is not archive" | 2 | `CorruptionError` |
| `NextHeaderSize` high byte changed | "Is not archive" | 2 | `CorruptionError` |
| `NextHeaderSize` +1, fixed CRC | "Unexpected end of archive" | 2 | `CorruptionError` |
| `NextHeaderCRC` byte changed | "Is not archive" | 2 | `CorruptionError` |
| `NextHeaderCRC` byte changed, fixed CRC | "Headers Error" | 2 | `CorruptionError` (next header CRC) |
| Bytes 8–31 all zero (CRC and fields) | **12 files, warning "Headers Error"** | **0** | `CorruptionError` |
| Bytes 12–31 zero, CRC recomputed | 0 files, warning "There are data after the end of archive" | 0 | opens, empty |
| Bytes 12–31 zero, old CRC left | "Is not archive" | 2 | `CorruptionError` |
| Version byte changed | "Is not archive" | 2 | `UnsupportedFeatureError` |
| Magic byte changed | "Is not archive" | 2 | not detected |
| One byte of the next header changed | "Headers Error" | 2 | `CorruptionError` (next header CRC) |
| Cut just before the next header | "Unexpected end of archive" | 2 | `TruncatedError` |
| Cut 100 bytes short | "Unexpected end of archive" | 2 | `TruncatedError` |
| Cut at 50 % | "Unexpected end of archive" | 2 | `TruncatedError` |

The same table holds for the non-solid archive, and for the plain-header archive except
the all-zero row.

The all-zero row is 7-Zip's recovery for an interrupted write. Measured on every kind of
archive, with bytes 8–31 zeroed:

| Archive | Zeroed | Zeroed, one non-zero byte appended | Zeroed, 16 zero bytes appended | Zeroed and cut before the next header |
| --- | --- | --- | --- | --- |
| Solid, non-solid, LZMA1, BCJ, Delta, AES (header 327–356 bytes packed) | 12 files, warning, exit 0 | "Is not archive", 2 | 12 files extracted, "Headers Error" as an error, exit 2 | "Is not archive", 2 |
| Plain header, 150 bytes (2 files) | 2 files, warning, exit 0 | not measured | not measured | not measured |
| Plain header, 594 bytes (12 files) | "Is not archive", 2 | | "Is not archive", 2 | "Is not archive", 2 |

So 7-Zip's rule is: the start header is zero from byte 8 to byte 31; the file's last
byte is zero; within the last 512 bytes, the pair `0x17 0x06` (`kEncodedHeader`,
`kPackInfo`) or `0x01 0x04` (`kHeader`, `kMainStreamsInfo`) nearest the end starts the
next header, which runs to the end of the file. No CRC is checked. The behaviour matches
the `FORMAT_7Z_RECOVERY` path in 7-Zip's `7zIn.cpp`.

**Outcome:** the all-zero start header goes in the default, flagged (decision 1). Every
other start-header damage goes in salvage only (decision 2). The zero-padded case,
which 7-Zip extracts but reports as an error, is open question 4.

### Repair rules R1–R3 on the damaged copies

A prototype of decision 2 on the solid and plain-header archives, damage as in the Q15
table:

| Damage | Repaired by | Candidates that pass the start-header CRC | Time |
| --- | --- | ---: | ---: |
| `StartHeaderCRC` byte | R1 (stored fields; next-header CRC passes) | | <0.1 ms |
| `NextHeaderCRC` byte | R2 (byte 28 restored) | 1 | 0.9–1.6 ms |
| `NextHeaderOffset` +1, high byte | R2 (bytes 12, 17 restored) | 1 | 1.4–1.6 ms |
| `NextHeaderSize` +1, high byte | R2 (bytes 20, 25 restored) | 1 | 1.5–1.6 ms |
| Two offset bytes | R3, size kept | | 0.9 ms |
| Two offset bytes, 300 zero bytes appended | R3, size kept | | 0.8 ms |
| A size byte and the CRC byte | R3, offset kept | | 0.8 ms |
| Offset and size both | R3, by the marker pair | | 0.9–1.0 ms |
| No match (16 MB archive, every field wrong) | none | | 214 ms |

Every R2 search found exactly one candidate in 5 100.

### The cut archive: raw decode from offset 32

The prototype decodes consecutive streams from offset 32 with the stdlib `lzma` module:
LZMA2, and if that gives nothing, LZMA1 with `lc=3 lp=0 pb=2`, both with a 1.5 GiB
dictionary.

| Archive, damage | Streams found | Result |
| --- | ---: | --- |
| Non-solid, cut before the next header | 12 + header copy | 12 of 12 members byte-exact, each its own stream; the 13th stream is the packed header |
| Non-solid, cut at 50 % | 6 | 5 members byte-exact, the 6th partial (4 719 correct bytes) |
| Non-solid, cut 100 bytes short | 12 + partial header | 12 of 12 byte-exact; header copy cut |
| Solid, cut before the next header | 1 + header copy | one stream holding all 12 files in order (409 779 bytes, every byte correct) |
| Solid, cut at 50 % | 1 | 5 files whole inside one partial stream; every decoded byte correct |
| Solid, multi-threaded (`-mmt=4 c=1m`), 44 MB, cut at 50 % | 1 | one stream, 29 files inside, every byte correct |
| LZMA1 solid, cut at 50 % | 1 (LZMA1) | every decoded byte correct |
| LZMA1 solid, cut before the next header | 1 (LZMA1) | the folder's 409 779 bytes correct, then **270 bytes decoded from the packed header**, wrong, with no error |
| LZMA1 solid, 44 MB, cut before the next header | 1 (LZMA1) | decoder error at the end; with 64 KiB pieces, the output of the failing piece is lost |
| BCJ, cut | 1 + header copy | decodes; only the first 9 288 bytes match: the bytes are BCJ output, not the files |
| Delta, cut | 1 + header copy | decodes; only 4 bytes match |
| AES, cut | 0 | nothing decodes at offset 32 |

**The header copy.** When only the next header is lost (the cut is right before it), the
packed header stream is intact. It decoded as LZMA1 to a `kHeader`, and archivey's
`parse_decoded_header` read it in 0.4–1.7 ms: 13 files, `pack_pos` 0, pack sizes equal
to the streams the walk found. For the BCJ archive the copy also names the BCJ filter,
so those members decode right. With the cut 100 bytes short, the copy is cut and does
not parse.

**Speed.** The walk decoded at 22–28 MB/s of packed input (about 60 MB/s of output),
the speed of liblzma, on archives from 160 KB to 16 MB. A 1.5 GiB dictionary costs
nothing until it fills (27 MB RSS for a 1 KB stream).

**Searching for a stream start** (decision 7) in 4 MB of random bytes, pure Python: 4–5
MB/s. 3 452 offsets had a chunk chain that ends in an end marker; 63 of them also
decoded to the end, all chains of uncompressed chunks only. None whose first chunk is an
LZMA chunk.

## Decisions

### 1. Default: the zeroed start header (Q15)

When bytes 8–31 of the start header are all zero, the default does what 7-Zip does:

- the source's last byte is zero;
- in the last 512 bytes (fewer if the file after the start header is shorter, at least
  3), the pair `0x17 0x06` or `0x01 0x04` nearest the end of the file starts the next
  header;
- the next header runs from there to the end of the file and is parsed as any next
  header. For a `kEncodedHeader`, its decode checks the decoded header against its
  folder CRC, as it does today. A plain header has no CRC to check, as in 7-Zip.

Only the pair nearest the end is tried, as 7-Zip does, so the default opens what 7-Zip
opens and nothing more. If it does not parse, the open raises `CorruptionError` as today
("signature header CRC mismatch", plus "the start header is zero and no end header was
found in the last 512 bytes"). Bytes after the header's `kEnd` stay a `CorruptionError`,
as the format-7z spec already says.

The archive emits `ARCHIVE_STRUCTURE_INCONSISTENT` once at open, with
`ArchiveStructureContext(format="7z", structure="start_header", offset=<absolute offset of the next header used>)`.
The message says the start header is zero, as an interrupted 7-Zip write leaves it, and
that the end header was found by its position. It is an integrity code, so `STRICT`
refuses the open. The pass does not end in an error: 7-Zip exits 0, nothing is lost, and
the decoded header has passed its CRC (DR-6). This is the same shape as a DMG whose
primary GPT fails and whose backup is read. The PR is `needs-minor`: an archive that
raised now opens.

Why reuse `ARCHIVE_STRUCTURE_INCONSISTENT`: a caller acts on it the same way, "a
structure was damaged and the read worked around it" (DR-13). Its context already has
`format`, `structure` and `offset`.

### 2. Salvage: start-header repair

With `salvage=True`, when the start header fails its CRC (and decision 1 did not apply
or did not find a header), the reader tries these rules in order and takes the first
that passes. Offsets below are relative to the signature, as every 7z offset is.

| Rule | Candidate | Accepted when | Confirmation |
| --- | --- | --- | --- |
| R1 | the stored `NextHeaderOffset` and `NextHeaderSize` | the bytes there pass the stored `NextHeaderCRC` | 32 bits (the damage was in `StartHeaderCRC`) |
| R2 | each change of one byte of bytes 12–31 (20 × 255 candidates) that makes the stored `StartHeaderCRC` pass | the next header that candidate describes passes the candidate's `NextHeaderCRC` | 64 bits: both CRCs |
| R3 | a search of the file's tail for a span whose CRC is the stored `NextHeaderCRC` (below) | a span passes | 32 bits |
| R4 | only for a start header that is zero from byte 8 to byte 31: every `0x17 0x06` or `0x01 0x04` pair in the last 1 MiB, nearest the end first | the header parses to its `kEnd`, followed only by zero bytes to the end of the file; an encoded header also decodes and passes its folder CRC | 32 bits for an encoded header; none for a plain one |

**R3, the tail search.** The next header ends with `kEnd` (`0x00`), normally at the end
of the file, sometimes before trailing zero bytes. The candidate ends are the end of the
file and every offset in the run of zero bytes at its end, up to 64 KiB of that run,
plus the stored end (`32 + offset + size`) when it is inside the file. In this order:

1. R3a, the stored size is kept: for each candidate end `e`, the span `[e - size, e)`.
2. R3b, the stored offset is kept: for each candidate end, the span from `32 + offset`.
3. R3c, neither is kept: each start in the last 1 MiB whose first two bytes are
   `0x17 0x06`, `0x01 0x02`, `0x01 0x04` or `0x01 0x05` (`kHeader` followed by
   archive properties, main streams or files), with each candidate end.

R3a and R3b are searched over the last `MAX_NEXT_HEADER_SIZE` (64 MiB) bytes, the
parser's limit on a next header. R3c is held to 1 MiB, because each start costs a CRC to
the end of the file: an encoded next header is under 100 bytes, and only a plain header
of a large archive (`-mhc=off`) is longer than 1 MiB. Every byte R3 and R4 examine
counts against `max_search_bytes` once.

**Why R2 is safe:** 5 100 candidates against a 32-bit CRC leave about one false
candidate in 840 000 archives, and the next-header CRC must then pass too. Every
measured single-byte damage had exactly one candidate.

**What a repaired archive lists.** Everything in it, from the repaired end header: the
default listed nothing (it raised at open), so every member is added (Q2). Each member
carries `MEMBER_FOUND_BY_SCAN` with `method="header_repair"` (R1, R2) or
`method="header_search"` (R3, R4), `offset` = the absolute offset of the next header
used, and:

- `confirmed=True`, `unchecked=()` when a 32-bit CRC confirmed the next header (R1, R2,
  R3, R4 with an encoded header);
- `confirmed=False`, `unchecked=("position",)` for R4 with a plain header, which only
  its parse checks.

Members then read as in any 7z: folder and file CRCs check the data, so `verifiable` is
what it would be for the intact archive (salvage design §9: a member with a digest in
its header is `CHECKSUM`). The pass ends in the error the default raised at open, and
that error's message adds which rule repaired the start header and where the end header
was found (S5).

### 3. Salvage: an end header that fails its CRC

When the start header passes (or was repaired) and the next header fails its CRC, or is
cut, the reader parses what is there anyway:

- an encoded header is used when it parses and its decoded header passes its folder CRC
  (32 bits; `confirmed=True`);
- a plain header is used when it parses to its `kEnd` (`confirmed=False`, `unchecked`
  holds `"position"`);
- otherwise, or when the parse raises, the reader goes on to the walk (decision 4).

The members it lists are flagged as in decision 2, with `method="header_repair"`.

### 4. Salvage: the walk of the packed area

When no end header is usable (the archive is cut, the next header is lost or does not
parse, or no repair found one), the reader walks the packed area. The area starts at
offset 32. It ends at the next header's start when the start header passes or was
repaired and that start is inside the file, and otherwise at the end of the file.

```text
p = 32
loop while p < end:
  plain header at p?        bytes parse as a kHeader to kEnd -> header copy (decision 5)
  LZMA2 chain at p?         first chunk resets the dictionary (control 0x01 or 0xE0-0xFF)
                            -> one stream [p, q); unpacked size from the chunk headers
                               chain ends in 0x00   -> p = q, go on
                               chain breaks at x    -> stream ends at the last whole chunk;
                                                       search from x (decision 7)
                               chain runs to end    -> cut stream; the walk ends
  LZMA1 at p?               only at p = 32, or for the header copy (decision 6)
  nothing                   -> search from p (decision 7)
```

- The walk reads chunk headers only (3 to 6 bytes for each chunk of at most 64 KiB
  packed), not the data, so listing does no decoding. The one decode at listing is the
  header copy (decision 5) and, for a searched candidate, its first LZMA chunk.
- Each stream claims its packed range: no search starts inside it.
- A stream found at a walk position (offset 32, or where the last stream ended) is
  accepted on its chain alone, uncompressed chunks included: random data is stored by
  7-Zip as uncompressed chunks, and the position is the evidence.
- 7z packs every folder's streams back to back from offset 32, so in a non-solid
  archive each LZMA2 folder is one stream and the walk finds them in archive order.

### 5. The header copy

A stream that the walk finds and that is the header (a plain `kHeader` at a walk
position, or an LZMA1 stream that decodes to one) is used as the end header when:

- it parses to its `kEnd` (decoded bytes after `kEnd` are ignored: an LZMA1 stream has
  no end marker, so the decoder runs on past the header's end);
- its pack info agrees with the walk: `pack_pos` and the pack sizes put each packed
  stream inside the area, and every LZMA2 stream the walk found starts at a pack
  position the copy gives, with the unpacked size the chunk chain gave.

The decode is held to `MAX_NEXT_HEADER_SIZE` of output and to the listing limits, as an
encoded header is. A copy that passes gives named members, as the intact archive would.
They carry `MEMBER_FOUND_BY_SCAN` with `method="header_search"`, `offset` = the copy's
stream start, `confirmed=True` (the pack layout agrees, and the file CRCs in the copy
check every read), `unchecked=()`. No content member is listed for a stream the copy
names (one member per data location). The copy is what recovers names, and filters, when
a cut loses only the next header, or when the next header alone is damaged.

**When the walk ends before it reaches the copy** (an LZMA1 folder runs into it, or a
BCJ2 folder's streams stop the walk), the copy is searched for over the last 1 MiB of
the area, from the end backwards: at each offset whose byte is `0x00` (an LZMA1 stream's
first byte), one byte is decoded as LZMA1 `lc=3 lp=0 pb=2`, and only a `0x01` goes on to
the full decode and the checks above. Measured: found in 2 ms in the solid and the 44 MB
LZMA1 archives cut before the next header (the LZMA1 one gave all 61 names back); 53 ms
over 1 MiB with nothing to find. The bytes count against `max_search_bytes`.

### 6. LZMA1

7-Zip's LZMA1 streams have no end marker. A raw decode does not stop at the end of the
stream: it decodes whatever follows as more of the same stream, and gives wrong bytes
until the decoder fails, if it fails (measured: 270 wrong bytes, no error). And an LZMA1
property byte other than `lc=3 lp=0 pb=2` decodes to wrong bytes with no error (BCJ2's
call and jump streams use `lc=0 lp=2`).

So LZMA1 is tried at two places only:

- **at offset 32**, when no LZMA2 chain starts there: the first folder of an archive
  that 7-Zip wrote with LZMA (its default before LZMA2). It is listed as one content
  member whose size is `None` at listing; its end is not known, and nothing after it can
  be walked, so the search (decision 7) runs over the rest of the area. The member's
  input ends at the first stream that search finds, or at the area's end. Open question
  1 asks whether this member is listed at all, given its possibly wrong last bytes.
- **at a later walk position, and in the tail search of decision 5, for the header copy
  only:** the first decoded byte is checked. Only when it is `0x01` (`kHeader`) does the
  decode go on, to decision 5. Any other LZMA1 stream at a later position is not listed:
  its bytes cannot be told from wrong ones, and the walk searches on from there.

### 7. Searching for the next stream

Where the walk cannot go on (nothing starts at `p`, a chain breaks, an LZMA1 stream
ends the walk), the shared search driver of step 3 looks for the next LZMA2 stream
start, one byte at a time, over the unclaimed bytes. The format's finder accepts offset
`c` when:

- the first chunk resets the dictionary (control `0x01`, or `0xE0`–`0xFF` with a
  property byte up to 224);
- the chunk chain from `c` ends in `0x00` inside the area, or runs exactly to the area's
  end;
- the chain holds at least one LZMA chunk (control `0x80` or higher), and the first one
  decodes without error.

A chain of uncompressed chunks only is not a candidate: it has no check at all (in 4 MB
of random bytes 63 such chains passed), and its bytes are the file's own bytes copied
out. This departs from recall-first (open question 3).

- A candidate whose chain ends in `0x00` and whose first LZMA chunk decodes is
  `confirmed=True`; one whose chain runs to the area's end is `confirmed=False` and does
  not claim its range, so the search goes on inside it (Q16).
- The bytes between `p` and `c` are one `ARCHIVE_REGION_SKIPPED` (`layer="archive"`,
  `reason="no_header"`). With no candidate, the region runs to the area's end.
  (Step 6 adds `reason="undecodable"` for a codec that fails inside a stream; a 7z range
  where no stream starts is `"no_header"`.)
- The search finds dictionary-reset chunks inside a multi-threaded LZMA2 stream too. A
  stream found there is real content from that reset on, and is listed like any other.
  Finding those parts inside a folder whose header is intact is step 9, not this step.
- What it costs: 4–5 MB/s in Python, counted against `max_search_bytes` (step 3). The
  chunk-header filter is a candidate for a native helper later, as the RAR search is.

### 8. Content members

Each stream the walk or the search finds, and that no header copy names, is one member:

| Field | Value |
| --- | --- |
| `name` | `__salvaged__/7z-stream-NNNN.bin`, `NNNN` the stream's place in archive order, from `0001`, at least four digits (`7z-stream-12345.bin` after 9 999) |
| `type` | `FILE` |
| `size` | the unpacked size from the chunk chain; `None` for a cut stream and for the LZMA1 member |
| `compressed_size` | the stream's packed bytes in the file |
| `compression_method` | LZMA2 (or LZMA) |
| times, mode, attributes | unset |
| `verifiable` | `UNLOCKED` (Q18, §9: content without a header has no length or digest to check) |
| diagnostic | `MEMBER_NAME_UNKNOWN`, once, at listing (§Diagnostics) |

- **Why one member per stream:** a stream is the unit the archive itself delimits. In a
  non-solid archive it is exactly one file (measured, 12 of 12). In a solid archive it
  is the concatenation of a folder's files. Splitting it needs the sizes in the lost
  header, and file-content heuristics are rejected (salvage design §14).
- **Numbering** is per archive, in the order of the streams in the file, so the same
  archive gives the same names (DR-5). A searched stream takes its place in that order.
  `0001` because the names are read by people and nothing else in them is a 7z index.
- **A real member named `__salvaged__/...`** cannot occur together with content members:
  content members exist only when no header is usable. Duplicate names are allowed, as
  in every format; nothing is renamed (add-only).
- **Reading** goes through the normal folder pipeline: a synthetic folder of one LZMA2
  (or LZMA) coder over the packed range, with no CRC. Its dictionary property is the
  smallest LZMA2 value at least the stream's unpacked size: a match cannot reach back
  past the stream's first byte, so this is always enough, and `max_decoder_memory`
  checks it as for any declared dictionary. The LZMA1 member, whose size is unknown,
  uses `max_decoder_memory`, capped at 4 GiB − 1. A cut stream reads every byte that
  decodes, then raises `TruncatedError`. A decoder error raises `CorruptionError` after
  the bytes before it. The decoder is fed so that the bytes decoded before a failing
  input piece are delivered (the prototype lost a 64 KiB piece's output).
- **Filters.** Without the header, nothing says whether a BCJ, BCJ2, ARM64, RISC-V or
  Delta filter followed the LZMA2 coder. The member's bytes are the LZMA2 output, which
  is the file only when no filter followed (measured: BCJ output matched for 9 288
  bytes, Delta for 4). `unchecked` holds `"filters"`, and the docs say what it means.
  Open question 2 asks whether these members should be listed.

### 9. Folders the walk cannot decode

| Folder | Without the header |
| --- | --- |
| LZMA2, any number of streams | listed, one member per stream |
| LZMA2 + BCJ / ARM64 / RISC-V / Delta | listed as the LZMA2 output, `"filters"` unchecked (decision 8) |
| BCJ2 (four packed streams) | the main stream is LZMA2 and listed as its output; the call and jump streams are LZMA1 with `lc=0 lp=2` (measured: `LZMA:20:lc0:lp2`) and are not listed (decision 6); the range-coder stream is not a stream; the search finds the next stream after them. Measured on a cut BCJ2 archive of one ELF file: the main stream decoded (2.5 MB, the first 354 bytes equal to the file), then the walk stopped |
| AES (any coder after it) | nothing: the packed bytes are ciphertext. One `ARCHIVE_REGION_SKIPPED` covers them |
| COPY, BZip2, Deflate, Deflate64, PPMd, Zstd, Brotli, LZ4 | nothing in this step: one `ARCHIVE_REGION_SKIPPED`. The search may find LZMA2 streams inside a COPY folder that holds a 7z (Q12) |
| An encrypted header (`-mhe`) | no header copy: its stream is ciphertext. The content streams are listed if they are not encrypted, which 7-Zip never writes with `-mhe` |

`ARCHIVE_REGION_SKIPPED` messages for 7z say "no LZMA2 or LZMA stream starts here: the
data may be encrypted or use another method".

### 10. Solid and non-solid outcomes

| Archive | Cut before the end header | Cut in the middle |
| --- | --- | --- |
| Non-solid LZMA2, encoded header | header copy: every member named, as intact | one content member per member before the cut, byte-exact; the cut one partial |
| Solid LZMA2, encoded header | header copy: every member named | one content member holding the files before the cut, concatenated |
| Multi-threaded solid LZMA2 | as solid | as solid; after a damaged chunk, the search finds the next dictionary reset |
| Plain header (`-mhc=off`) | the plain header is found at the walk position after the last stream: header copy | as above |
| LZMA1 solid | the walk does not reach the copy (the LZMA1 folder decodes on into it), but the tail search finds it: every member named | one LZMA1 member, every byte correct up to the cut |
| LZMA1 non-solid | the same: the tail search finds the copy | one LZMA1 member for the first folder, its last bytes possibly wrong (open question 1) |

### 11. Lost start (Q14)

With `salvage=True`, when detection finds no format and `format="7z"` or a `.7z`, `.cb7`
or `.7z.NNN` name picks 7z (step 3), there is no start header: the bytes lost from the
start are unknown, and every stored offset is shifted by that count. The reader:

1. runs R4's search over the last 1 MiB of the file for an end header that parses (an
   encoded one also decodes and passes its folder CRC);
2. computes the lost count from that header: 7-Zip writes the last packed stream (the
   packed header, for an encoded one) right before the next header, so
   `lost = 32 + (end of the last packed stream, signature-relative) − (found offset)`;
3. reads every folder whose packed streams start at or after the lost count, as usual,
   flagged as in decision 2 (`method="header_search"`, `confirmed` as for R4). A folder
   that started in the lost bytes is not listed: its start is gone. Its files are named
   in the header, but they have no data; they are not listed either.

Without an end header, the walk of decision 4 runs from offset 0 with a search first,
since the first stream began in the lost bytes. `ARCHIVE_REGION_SKIPPED` covers the
bytes before the first stream found.

### 12. The default listing and add-only (Q2)

For every archive this step reaches in salvage, the default lists nothing: it raises at
open (start header CRC, next header CRC, truncation). So every member salvage lists is
an added member, flagged. An archive the default opens is read by salvage exactly as by
the default, decision 1 included. A folder damaged inside an archive whose headers are
intact is already per-member in the default (the read of its members raises, the others
read); nothing changes for it in this step. With intact headers, `salvage=True` lists
nothing more and records no `SALVAGE_UNAVAILABLE`: 7z declares salvage support from this
step on.

The pass ends in the error the default raised at open, after the last member (S5). For a
repaired start header and a header copy that error is the default's own
(`CorruptionError` or `TruncatedError`); its message adds what salvage did.

## Diagnostics

| Code | Context | When | Default delivery | Integrity code |
| --- | --- | --- | --- | --- |
| `ARCHIVE_STRUCTURE_INCONSISTENT` (exists) | `ArchiveStructureContext(format="7z", structure="start_header", offset)` | default and salvage, once at open, the zeroed start header (decision 1) | warning | yes |
| `MEMBER_FOUND_BY_SCAN` (step 3) | `SalvageScanContext`, `method="header_repair"` or `"header_search"` | salvage, once per member listed from a repaired, found or copied end header | warning | no |
| `MEMBER_NAME_UNKNOWN` (new) | `SalvageScanContext`, `method="content"` | salvage, once per content member, at listing | warning | no |
| `ARCHIVE_REGION_SKIPPED` (step 3) | `RegionSkippedContext`, `layer="archive"`, `reason="no_header"` | salvage, once per range where no stream starts | warning | no |

**`MEMBER_NAME_UNKNOWN`**, designed here for every later step that lists content without
a header (stream segments, XAR heap, SquashFS inodes, CAB folders):

- Value `"member_name_unknown"`. Docstring: "archivey made up this member's name:
  salvage found its content where no header names it. The name is under
  `__salvaged__/`."
- Context: `SalvageScanContext`, shared with `MEMBER_FOUND_BY_SCAN` (salvage design §8).
  `method="content"` here; a later step sets its own (`"stream_segment"`). `offset` is
  where the content starts in its layer (the packed stream's absolute offset).
  `confirmed` is as for the search (decision 7); a stream at a walk position is
  `confirmed=True`. `unchecked` always holds `"name"`; for 7z also `"filters"`, and
  `"size"` when `size` is `None`.
- **One salvage code per member.** A content member carries `MEMBER_NAME_UNKNOWN` and
  not `MEMBER_FOUND_BY_SCAN`. Every content member is a salvage find, so the second code
  would say nothing more, and a caller that wants all salvaged members filters on the
  set of salvage codes. Step 3's add-only requirement already allows "a later step's
  salvage code" in place of `MEMBER_FOUND_BY_SCAN`.
- Not in `ARCHIVE_INTEGRITY_CODES`, as the other listing-time salvage codes (step 3,
  salvage design §8), so `STRICT` does not stop a salvage listing. The damage is still
  the error at the end of the pass.
- Not emitted with `salvage=False`.

Step 6 (stream segments) uses the same shape with `method="stream_segment"` and adds
fields to the contexts; whichever change lands second rebases its delta over the other.

**`SalvageScanContext.method`** gains `"header_repair"` (stored fields corrected under a
CRC), `"header_search"` (an end header found by a search, or a header copy) and
`"content"`. The context's fields do not change.

## Limits and cost

| Work | When | Bound |
| --- | --- | --- |
| R2 | open, salvage, start header fails its CRC | 5 100 CRCs over 20 bytes, about 2 ms; not counted |
| R3, R4 | open, salvage | each byte examined counts against `max_search_bytes`; R3a/R3b over at most 64 MiB, R3c and R4 over at most 1 MiB; 214 ms measured for a failing R3 on 16 MB |
| Default zeroed rule | open | 512 bytes; not a search under step 3's budget |
| Walk | open, salvage | chunk headers only: one small read per 64 KiB of packed data; members counted against `ListingLimits.max_members` |
| Stream search | open, salvage | each byte once, counted against `max_search_bytes`; 4–5 MB/s |
| Header copy decode | open, salvage | at most `MAX_NEXT_HEADER_SIZE` of output; `max_members`, `max_metadata_bytes` as for any header |
| Content read | read | `DecoderLimits` (`max_decoder_memory` for the dictionary, `max_ratio` on the stream's output against its packed bytes, checked at listing from the chain and during the read) and `ExtractionLimits` (`max_extracted_bytes`), unchanged |

A budget that runs out ends the walk as step 3 says: one `ARCHIVE_REGION_SKIPPED` with
`reason="search_limit"`, nothing further listed, the error names the limit.

## Verification (Q18)

| Member | `verifiable` |
| --- | --- |
| From a repaired, found or copied end header | as for the intact archive: `CHECKSUM` with a file or folder CRC, else what the 7z rules give today |
| Content member (LZMA2 or LZMA1) | `UNLOCKED`: nothing checks its bytes or its length |

The LZMA2 decoder still refuses a chunk that does not decode to its declared size, so a
damaged content stream raises `CorruptionError`. That is a decoder failure, not a
check `verifiable` can promise, so the level stays `UNLOCKED`.

## PRs

1. **Default zeroed start header** (`needs-minor`): decision 1, the 7z context values,
   tests against 7-Zip's results (skip without `7zz`/`7z`).
2. **Salvage header repair** (stacked on step 3's switch PR): decisions 2, 3 and 11,
   `supports_salvage` for 7z, `"header_repair"`/`"header_search"`.
3. **Salvage content** (stacked on 2): decisions 4–10, `MEMBER_NAME_UNKNOWN`, CLI mark,
   handbook section.

## Open questions

1. **List the LZMA1 member, whose last bytes may be wrong?** Measured: a solid LZMA1
   archive cut before its end header decodes 270 wrong bytes after the folder's end with
   no error. Recall-first says list it; DR-1 says a wrong value is the worst failure; Q5
   forbids filling unknown bytes, and these are decoded, not filled, but wrong.
   **Recommend: list it**, with `size=None` and `"size"` in `unchecked`, and say in the
   message and the docs that bytes at its end may not be content. In a cut archive, the
   common case, every byte is correct, and LZMA1 archives are the old backups this mode
   is for. Alternative: list it only when its decode runs to the end of the file with no
   error (still not proof).
2. **List LZMA2 output that may still need a filter?** BCJ output is the file except
   near branch instructions; Delta output is not the file at all. Nothing in the archive
   says which, without the header. **Recommend: list it**, with `"filters"` in
   `unchecked` (recall first; the backup indexer at least gets the content of
   non-executable files, which 7-Zip never filters). Alternative: no content members
   unless a header copy gives the coders.
3. **Searched chains of uncompressed chunks only: candidates or not?** Recall-first
   (Q16) lists every candidate that passes the format's check. Such a chain has no
   check: 63 passed in 4 MB of random bytes, and each would be a junk member of copied
   file bytes. **Recommend: not candidates** (decision 7). A stream of random data at a
   walk position is still found; only one after a damaged region is missed.
4. **The zeroed start header with zero bytes after the end header.** 7-Zip lists and
   extracts every file but reports "Headers Error" as an error (exit 2). archivey's spec
   already makes bytes after `kEnd` a `CorruptionError`, matching 7-Zip's error.
   **Recommend: salvage only** (R4 accepts it), so the default opens what 7-Zip opens
   with exit 0. Alternative: open it in the default too, flagged, as 7-Zip does extract
   it.

## Rejected

- **Searching the start header's damage in the default beyond the zeroed case.** 7-Zip
  refuses all of it (Q15). R1 and R2 need no search, but they are not what 7-Zip does.
- **Splitting a solid stream into files by content.** The sizes are in the lost header;
  file-magic carving is rejected (salvage design §14).
- **Trying several LZMA1 property bytes.** Each wrong one decodes wrong bytes without an
  error, so the try cannot tell which one is right.
- **Decoding at listing to find stream ends.** The LZMA2 chunk headers give the extent
  and unpacked size without decoding (DR-15b).
