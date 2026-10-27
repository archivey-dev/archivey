# xz, lzip and LZMA Alone

Current maintainer truth for the three single-file formats built on LZMA: xz (`.xz`), lzip
(`.lz`) and LZMA Alone (`.lzma`), and their TAR forms. All three decode through the
standard library's `lzma` (liblzma). For xz and lzip archivey parses the framing itself,
which is what gives them a size, a seek index and, for lzip, a digest; LZMA Alone goes
through `lzma.LZMAFile`. Raw LZMA and LZMA2 as 7z coders are on [`7z.md`](7z.md). What these
formats share with the other codecs, the one-member reader, the seek table and the
truncation contract, is on [`single-file.md`](single-file.md). Registers keep the status;
this page states the behaviour and links the row.

## At a glance

| | |
| --- | --- |
| Read | xz, lzip and LZMA Alone as one-member archives; `.tar.xz`, `.tar.lz`, `.tar.lzma` |
| Write | **Not shipped** |
| Backends | The standard library's `lzma`, always available. `streams/codecs/xz_decoder.py` and `streams/codecs/lzip_decoder.py` are archivey's own framing parsers over it |
| Seeking | xz: from the nearest block or stream. lzip: from the nearest member. LZMA Alone: a backward seek decodes again from the start |
| Size | xz: from the index. lzip: from the member trailers. LZMA Alone: from the header, unless it holds the "unknown" marker. xz and lzip need a seekable source that is not another archive's member stream |
| Digests | lzip only: the CRC-32 of the whole content, combined from each member's trailer. xz checks (CRC-32, CRC-64, SHA-256) are verified on read, not listed. A check ID liblzma cannot compute (2, 3, 5 to 9, 11 to 15) reads unverified with `DIGEST_UNVERIFIABLE`. LZMA Alone has no check at all (§4), and reports nothing |
| Metadata | None beyond the shared fields |
| Truncation | Always raised, as `TruncatedError` |
| Refuses | A declared dictionary over `DecoderLimits.max_decoder_memory` (`ResourceLimitError`); an xz filter liblzma cannot decode (`UnsupportedFeatureError`) |

**Four things a reader might expect and will not find.** Seeking in a file from default
`xz` or `lzip` re-decodes from the start: each writes one block or one member, so the index
has one entry. Bytes after the last xz stream are ignored rather than refused, although
`xz -t` refuses them, and they cost the index (§3). An xz file's own check value is not in
`member.hashes`. And a seek trusts the file's index: a crafted index that is consistent
with itself can make a seek return the wrong bytes with no error (§4). After a seek back
by such an index, a member digest still passes: it covers the first pass over each byte,
not bytes read again.

## 1. Shape

Four properties generate most of this page.

```
xz stream:    magic(6) flags(2) CRC32(4)            ← header
              block: header, LZMA2 data, padding, check
              block: …
              index: 0x00, count, (unpadded size, uncompressed size) per block, CRC32
              footer: CRC32 backward_size(4) flags(2) "YZ"
              [00 00 00 00 …]                       ← stream padding, multiple of 4
xz stream:    …                                     ← a following stream is legal

lzip member:  "LZIP" version(1) dict_exp(1)  LZMA1 data (lc=3 lp=0 pb=2, end marker)
              CRC32(4) data_size(8) member_size(8)   ← trailer
lzip member:  …
              [trailing data]                        ← allowed by the lzip manual

LZMA Alone:   props(1) dict_size(4) uncompressed_size(8, or all ones)  LZMA1 data
```

**xz and lzip carry their index at the end.** An xz footer gives the size of the index
before it, and the index lists every block's compressed and uncompressed size. An lzip
trailer gives its member's size, so the members can be walked from the end. So on a
seekable source the size and every restart point are known without decoding, by reading
backwards from the last byte. On a pipe they are not reachable until the end.

**Restart points exist only where the writer made them.** An LZMA stream can only be decoded
from its start, but an xz block and an lzip member each start a fresh decoder. How many
there are is the writer's choice: default `xz` 5.4 writes one block, `xz -T` or
`--block-size` many; `lzip` writes one member unless told otherwise (`-b`), and `plzip`
writes one per data block, so a small file is one member unless `-B` sets smaller blocks. The file format decides that
restarting is possible; the producer decides whether it is useful.

**LZMA Alone has no magic and no trailer.** Its 13-byte header is a properties byte, a
dictionary size and an uncompressed size. The properties byte has 225 legal values out of
256, of which liblzma decodes 75 (`lc + lp` at most 4), the dictionary size may be
anything, and liblzma writes all ones for the size. So a large share of random data parses
as a header, and detection must decode to decide (§2.1). There is no integrity check at
all: a corrupt Alone stream decodes to wrong bytes unless the corruption breaks the range
coder.

**Every one declares a dictionary, and the decoder allocates it.** An xz block header
names its LZMA2 dictionary, up to 4 GiB; an lzip header names an exponent from 12 to 29,
up to 512 MiB; an Alone header any 32-bit value, up to 4 GiB. The decoder allocates that
before it decodes a byte, so the number is attacker-chosen memory (§4).

## 2. The pipeline here

### 2.1 Identify

xz is the magic `fd 37 7a 58 5a 00` at offset 0 and lzip `LZIP`, each `CERTAIN`. The
inner-TAR probe then decodes 512 bytes and upgrades a match to `TAR_XZ`, or
to TAR over lzip ([`single-file.md`](single-file.md) §2.1).

LZMA Alone is found by the first of the three content probes. That probe runs only for a
`.lzma`, `.tar.lzma` or `.tlz` name, under `open_stream`, or with
`ArchiveyConfig.always_probe_content` ([`detection.md`](../topics/detection.md) §2.5).
`_alone_header_plausible` checks that the properties byte encodes a legal `(lc, lp, pb)`
and that the declared size is not exactly zero. The dictionary size is not checked: every value is legal, and the
specification rounds one below 4 KiB up. The zero-size rule is there because 18 zero bytes
are a valid, complete, empty Alone stream, so without it a run of zero padding would be
claimed. A source of 13 bytes or fewer is refused, since it has no data after the header.
So is a run of 16 zero bytes starting in the first 32 bytes after the header: a range
coder fed zeros decodes zero literals without error, so a header followed by zeros
decodes, but no measured encoder writes that run (the longest measured is 7 bytes, from 7-Zip;
liblzma's is 3). Then the probe decodes the sample and requires at least one byte of output
([`single-file.md`](single-file.md) §2.1). A match is `PROBABLE`, and an error from a
probe-only match is stamped `format_unconfirmed`.

`.tlz` is an lzip extension, and it also runs the LZMA Alone probe. An LZMA Alone file
named `.tlz` is identified by content as TAR over LZMA Alone, with an extension-conflict
warning.

### 2.2 Open and list

**Size and digest from the end.** On a seekable source the reader reads the xz index or the
lzip trailers backwards from the end at open, whether or not seeking was declared
(`SingleFileReader._probe_lzip_index` and the xz equivalent). For xz that gives the size;
for lzip, the size and the CRC-32 of the whole content, combined from each member's
trailer CRC with `crc32_combine`, in one walk that holds no per-member state. On a pipe,
neither is known before the read ends. Another archive's member stream, passed to
`open_archive(member_stream)`, is not peeked either, seekable or not: availability is
decided by the source's shape, and member streams are excluded as a group
([`single-file.md`](single-file.md) §2.2).

When seeking was declared, the xz scan made at open is kept, and each member stream
uses it (`PrebuiltIndex`) in place of a second scan of every stream's index. A crafted
file of many tiny streams makes that scan cost seconds, so it runs once. A thinned or
unreadable index is then reported by the member stream, on the seek or size query that
needs the index, and not also at open. lzip does not share this: its open-time walk
(`peek_index_summary`) keeps no seek points, so a member stream scans the trailers
itself.

**Through bytes after the end.** The walk has to start at the last stream's end, not at
the file's. Zero bytes are skipped first. For xz, `_data_end()` in
`internal/streams/codecs/xz_decoder.py` then looks back for a footer that checks out: `YZ`
at a 4-aligned end and a valid CRC-32 over its fields. For lzip, `_data_end()` in
`lzip_decoder.py` looks for a trailer whose `member_size` leads back to an `LZIP` header;
a candidate must end in the zero high bytes that any real `member_size` has, which rules
out most offsets without a read. A `member_size` is not zero, so a trailer ends at most 7
bytes past the start of a run of zeros: a run of padding of any length gives a few
candidates, found with one regex match over the reversed window. Both look back at most
`TRAILING_DATA_SEARCH` (1 MiB) and check at most `TRAILING_DATA_CANDIDATES` (4096)
candidate ends there: a tail can be crafted so that every `YZ` is 4-aligned, or as
thousands of short runs of zeros. Past either bound the index is reported unreadable:
`size=None`, and a seek falls back to decoding forward with `SEEK_INDEX_DEGRADED`. The
forward read then reports the bytes as `ARCHIVE_TRAILING_DATA`
([`single-file.md`](single-file.md) §2.3). A footer or trailer followed by a header
magic with a few bytes damaged (`near_stream_magic()`) is not taken for the end: the
search raises `CorruptionError`, as the forward read does there. The two bounds keep the
cost of a file of junk to 1 MiB of reading and 4096 checks at open, a few milliseconds.
Each stream's index is read at most 1 MiB at a time (`_INDEX_READ_CHUNK`), because a
footer that checks out can still claim an index as large as the file; a real index fits
in one read, which the CRC check and both record walks share (threat model,
[Allocations sized by a header field](../threat-model.md#allocations-sized-by-a-header-field)).

**LZMA Alone** gives its size from the header when the header is not the all-ones
"unknown" marker. `xz --format=lzma` always writes the marker; the LZMA SDK writes the real
size.

### 2.3 Member data

**xz.** `XzDecompressorStream` is `DecompressorStream` over `XzDecoder`. It feeds each
stream to a fresh `lzma.LZMADecompressor(FORMAT_XZ)` and handles what liblzma does not:
stream padding in runs of four zero bytes, and the next stream's header. After the first
stream, bytes that are not a stream header end the data silently (§3).

Seek points come from the index. On a seekable source, as each stream finishes, its index
is read backwards and each block with content becomes a seek point; a seek to the end
(`SEEK_END`, `try_get_size`) reads every stream's index at once. To resume at a block,
`_XzBlockResume` decodes from that block to the end of the stream's blocks behind one
synthetic stream header, checks the decoded size against the index, and hands off to the
stream state machine at the next stream. Blocks of zero decoded size are skipped, because
they share an offset with the next block.

The index parser follows liblzma: the index must fill its declared length exactly, its
variable-length integers must be minimally encoded, its CRC-32 must match, and the header
and footer must name the same check. Stream padding is found by scanning backwards in
chunks that grow from 4 bytes to 64 KiB. If a stream's index cannot be read, the read
continues without its seek points and `SEEK_INDEX_DEGRADED` is reported; a stream with more
blocks than the seek table holds keeps a spaced subset and reports the same code
([`single-file.md`](single-file.md) §2.3).

**lzip.** `LzipDecompressorStream` is `DecompressorStream` over `LzipDecoder`. For each
member it checks the version (1) and the dictionary exponent (12 to 29), synthesises an
LZMA Alone header with lzip's fixed properties, and feeds the member to liblzma. At the
trailer it checks the CRC-32, the data size and the member size against what it decoded.
After the first member, bytes that do not start with `LZIP` end the data, as the lzip
manual allows. A version other than 1, version 0 included, raises
`UnsupportedFeatureError` at any member, the first or a later one: a full `LZIP` magic
starts a member, and `lzip` too reports a later version-0 member as unsupported rather
than ignoring it. The trailer walk checks the same byte at each member header it
reaches: each member start, the start of its range, and the bytes after the last
member it finds. It cannot reach a version-0 member strictly between two version-1
members, since a version-0 trailer has no member size; it fails as corrupt there, the
seek index degrades, and a seek falls back to the sequential read, which refuses the
member. So a seek never skips a member the forward read refuses. A header cut short after the
version byte is truncation on both paths, not a version to check. A source of 1 to 5
bytes with no whole header is `TruncatedError` when it is empty or a prefix of the
magic, and `CorruptionError` otherwise.

Seek points are the member starts, from the trailer walk. A backward seek resumes at the
nearest member.

**LZMA Alone.** `FramedDecompressorStream` over `lzma.LZMADecompressor(FORMAT_ALONE)`,
one decompressor per stream ([`single-file.md`](single-file.md) §2.3). Zero bytes are
padding only where they run to the end of the file; a stream after them is trailing data
(§6). A backward seek decodes again from the start.

**Dictionary caps.** Each format's declared dictionary is compared with
`DecoderLimits.max_decoder_memory` before the dictionary is allocated: inside liblzma for
xz and LZMA Alone, before the decoder is built for lzip:

- **xz** and **LZMA Alone**: liblzma reads the declared dictionary (each xz block header
  declares its own, each `.lzma` stream header one), so the decompressor is built with
  `memlimit` set to the cap plus a 128 KiB allowance for liblzma's own overhead
  (`new_capped_decompressor`). liblzma checks it after reading a header and before
  allocating. The allowance is small because it is also slack: liblzma's own overhead,
  about 64 KiB and build-dependent, takes part of it, and a cap set within the rest
  (about 64 KiB) below a size the header declares admits that size. The refusal comes
  from the first `decompress`, so on read, not at open. For `.lzma` that timing
  matters: a probe-only claim's read errors are stamped `format_unconfirmed`, and that
  stamp is attached after open, so a file whose header bytes read as a 2.5 GiB
  dictionary would otherwise tell the caller to raise the cap for a file that is not
  LZMA at all. A second stream of a concatenated `.lzma` is refused the same way, when
  its decoder starts.
- **lzip**: the exponent in the member header, before the decoder is built. The format's
  own ceiling, 512 MiB, is below the default cap.

**Errors by cause.** CPython raises every liblzma failure as `LZMAError` and tells them
apart only by text, the same on 3.10 to 3.14. `lzma_error_to_archivey` maps "Invalid or
unsupported options" and "Unsupported integrity check" to `UnsupportedFeatureError`,
"Memory usage limit" to `ResourceLimitError`, and everything else to `CorruptionError`. A
valid block naming a filter this liblzma lacks is therefore unsupported, not damaged; in a
`.tar.xz` it ends the listing there. Canary tests pin the liblzma wording. lzip maps its
liblzma errors through the same function, but a real lzip member reaches only the
corruption arm: its properties byte is fixed, its decoder has no memory limit, and
`FORMAT_ALONE` has no integrity check.

**A check liblzma cannot compute is a warning, not an error.** liblzma decodes a stream
whose header names such a check ID without verifying it, and reports that only through
`LZMA_TELL_UNSUPPORTED_CHECK`, which CPython never sets; its "Unsupported integrity check"
error is therefore never raised. `streams/codecs/xz_decoder.py` reads the check ID from
each stream header (or, for a block resume after a seek, from the footer the seek point
was read from) and emits `DIGEST_UNVERIFIABLE` (`reason="unknown_algorithm_or_backend"`,
`algorithm="xz check N"`) when `lzma.is_check_supported` says no, then keeps reading, as
`xz -d` does (it warns, decompresses, and exits 2). Once per check ID per decompressor
stream, so re-decoding after a seek does not repeat it; a single-file archive reports it
at open too, from the one-byte probe. Check ID 0 declares no check and is not reported.

### 2.4 Extract

Nothing here is specific to these formats ([`single-file.md`](single-file.md) §2.4).

### 2.5 Write

Not shipped.

## 3. In the wild

Measured with the tools listed on [`single-file.md`](single-file.md) §3.

| Producer | archivey |
| --- | --- |
| `xz` | Reads; `size` from the index; one block, so no seek points but the start |
| `xz -T4 --block-size=…` | Reads; one seek point per block |
| `xz -C none`, `xz -C sha256` | Reads. With `-C none` only a broken LZMA2 stream reveals damage |
| Two `xz` streams with zero padding between them | Reads both: Stream Padding, in multiples of 4 bytes, is part of the xz format. The other codecs stop at zeros between streams (§6) |
| A stream followed by `junk` | Reads the payload, then `ARCHIVE_TRAILING_DATA`; `size` and seeks from the index. `xz -t` refuses the file |
| Two streams, one byte of the second stream's header magic damaged | `CorruptionError` on a read and a seek; the index is unreadable. `xz -t`: "Compressed data is corrupt" |
| `xz --format=lzma` | Detected by the probe, `PROBABLE`; `size=None` (the "unknown" marker) |
| LZMA Alone followed by `junk` | Reads, then `ARCHIVE_TRAILING_DATA`. Junk that passes the next-stream check (about one random tail in 870) fails with `CorruptionError` |
| Two LZMA Alone streams concatenated | Reads both, as `lzma.LZMAFile` does; the second is recognised by its header (§2.3 of [`single-file.md`](single-file.md)) |
| An LZMA Alone stream, 4 zero bytes, a stream (crafted: no known writer emits this) | The first payload, then `ARCHIVE_TRAILING_DATA` at the second stream's first byte; `DiagnosticPolicy.STRICT` raises. `xz --format=lzma -dc` and `lzma -dc` 5.4.5 write the first payload, then "Compressed data is corrupt", exit 1. 7-Zip 16.02 writes it and reports "There are some data after the end of the payload data"; `bsdcat` and Python's `lzma` (`FORMAT_ALONE`) return the first payload |
| An LZMA Alone stream, then 4 zero bytes at the end of the file | Reads, with no diagnostic. `xz --format=lzma -dc` writes the payload and exits 1 on the zeros, and Python's `lzma` raises; archivey keeps them silent, as for every codec ([`single-file.md`](single-file.md) §6) |
| 40 000 zero bytes named `.lzma` | Reads as empty: 18 zero bytes are a complete empty stream (a 13-byte header and 5 bytes of range coder), and the rest is padding |
| `plzip`, `plzip -B` with a small block | Reads; `size` and the combined CRC-32 from the trailers. The 4 MB payload is one member by default and nine with the small block, one seek point per member |
| An lzip member followed by `junk` | Reads the payload, then `ARCHIVE_TRAILING_DATA`; `size` and the CRC-32 from the trailers. The lzip manual allows trailing data |
| Two lzip members, one byte of the second member's `LZIP` damaged | `CorruptionError` on a read and a seek; `size` and the CRC-32 unknown. `lzip` reports a corrupt header, unless `--loose-trailing` |
| COFF object files | Can be claimed by the LZMA Alone probe, `PROBABLE`; the read then fails, stamped `format_unconfirmed` |
| MP3s whose ID3 tag starts with padding, any plausible header followed by zeros | Not claimed: the zero run after the header is refused |
| OLE files (`.msi`, old `.doc`, `Thumbs.db`) | Not probed: the OLE signature stops the content probes ([`detection.md`](../topics/detection.md) §2.5) |

## 4. Threat surface

Specific to these formats; the shared items are [`single-file.md`](single-file.md) §4.

- **A declared dictionary is an allocation.** Capped per format as in §2.3, before any
  allocation; the default cap is 2 GiB.
- **A seek trusts the index (threat-model O17, accepted).** A cold seek goes where the xz
  index or the lzip trailer chain says. A crafted file whose index agrees with itself but
  not with its data can return another block's bytes for the offset asked, with no error.
  A forward read always verifies: xz checks each block against its index record and lzip
  each member against its trailer. Callers who need certainty read forward.
- **An index can declare millions of units.** The seek table is capped and thinned; the
  reader walks the xz index record by record and never reserves it at its declared count,
  and the lzip trailer walk keeps no per-member state. A 16.8 MB lzip file of 645 277
  empty members is listed in bounded memory. The detection probe walks the xz index
  differently: it counts record ends a buffer at a time, each scan no wider than the
  index still to come, so a count no input can hold costs one pass over the bytes the
  probe may read.
- **Padding and the backward scan.** The padding scan reads in growing chunks, so a file of
  megabytes of zeros costs a few reads, not one per four bytes.
- **LZMA Alone has no check.** Corrupt data that the range coder accepts decodes to wrong
  bytes with no error. That is the format.
- **The Alone probe claims foreign files.** COFF headers pass its gate. A header
  followed by zeros, such as an ID3 tag with padding or an OLE header, is refused for
  the zero run, and the OLE signature also stops the probes first.
  The claim is `PROBABLE`, and every error from it is stamped `format_unconfirmed`, so a
  caller can tell a misread file from a damaged one (threat-model O10).

## 5. Sharp edges

*Where it lives*: **format** — inherent, no implementation fixes it · **library** — an
upstream library's behaviour, fixable only there or by replacing it · **archivey** — ours.

| What you see | Where it lives | More |
| --- | --- | --- |
| A backward seek in a default `xz` or `lzip` file re-decodes from the start | **format** | One block or one member (§1). Write with `xz -T` / `--block-size`, or `plzip -B` |
| A file `xz -t` refuses reads, with `ARCHIVE_TRAILING_DATA` | **archivey** | Bytes after the stream are reported, not refused ([`single-file.md`](single-file.md) §6); `DiagnosticPolicy.STRICT` raises |
| More than 1 MiB after the last stream loses `size` and seeks | **archivey** | The index search is bounded (§2.2) |
| `size` is `None` on a pipe | **format** | The index is at the end |
| An `xz` block with a filter this liblzma lacks raises `UnsupportedFeatureError` | **library** | Not damage (§2.3) |
| `ResourceLimitError` naming `max_decoder_memory` | **archivey** | The file declared a dictionary over the cap. Raise it if the file is trusted |
| A `.lzma` file that fails reports `format_unconfirmed` | **format** | No magic; the probe's claim is uncorroborated |
| `size=None` for `xz --format=lzma` output | **format** | liblzma writes the "unknown" marker |
| A crafted xz or lzip file can make a seek return wrong bytes | **format** / **archivey** | O17 (§4) |

## 6. Decisions

| Choice | Why | Rejected |
| --- | --- | --- |
| Parse xz framing natively over stdlib `lzma` (PR #7) | The index gives size and block seeks without decoding; `lzma.open` reports the last stream's size for a multi-stream file | `python-xz`, a dependency that needs a seekable source and scans the whole file up front; removed from every extra |
| Parse lzip natively over stdlib `lzma` (PR #7) | lzip is LZMA1 with a fixed header; its trailers give size, seeks and a CRC | A dependency |
| LZMA Alone: zero bytes end the data unless they run to the end of the file; a stream after them is `ARCHIVE_TRAILING_DATA` (maintainer ruling, 2026-10-10). xz keeps reading past its Stream Padding | Match the official tool (DR-6): `xz --format=lzma` stops at the zeros and fails, as do the gzip, bzip2, zstd and LZ4 tools; xz defines padding between streams and LZMA Alone defines none. Zeros at the end stay silent although `xz` refuses them: one rule for every codec ([`single-file.md`](single-file.md) §6) | Reading a stream after the zeros, as `lzma.LZMAFile` does |
| Combine the lzip trailer CRCs into one whole-content CRC-32 (PR #160) | It is a real digest of the content, known from one backward walk | Listing it only for single-member files |
| Read the xz index and lzip trailers whenever the source is seekable (PR #232); narrowed by PR #732, below | Size must not depend on a flag about member-stream seeking | Gating them on `seekable_members` |
| Do not peek another archive's member stream, stored ZIP entries and TAR members included (PR #732; davitf, 2026-10-10: fix later) | A seek to the end of a deflated member decompresses it twice, and `seek_is_expensive`, the signal detection already uses, covers member streams only as a group. A nested `.xz` or `.lz` loses `size` and the lzip `CRC32`; both are metadata, and the decoder still checks the index and trailers on read. Reopen with a per-stream cheap-seek signal, which would keep both for a stored ZIP entry or a TAR member | Keeping the peek for member streams whose seek is a slice, which needs that signal, shared with detection |
| Keep the xz index scanned at open on the reader for its whole lifetime when seeking was declared, whether or not a stream ever seeks; bounded by `MAX_SEEK_POINTS` (2**18) points | A crafted file of many tiny streams makes the scan cost seconds, and each member stream would repeat it. Peak memory is unchanged; steady-state memory grows by at most the capped table while the reader is open | Freeing the scan after open and rebuilding it on the first seek, which repeats the slow scan per stream |
| Cold seeks trust a self-consistent index (O17) | Verifying a seek means decoding from the start, which removes the reason to have an index; a forward read still verifies | Verifying every seek |
| Check lzip `member_size` on the forward read (PR #407) | An unchecked member size let a seek serve another member's bytes | Trusting it |
| Cap every declared dictionary before allocation (PR #413) | The number is the attacker's | Letting liblzma allocate what the header asks |
| Detection probes decode with the dictionary their read needs, not the declared one | liblzma reserves the declaration, up to 4 GiB, which under `RLIMIT_AS` or Windows' commit limit was a `MemoryError` out of `detect_format`; a match never reaches past output already produced, so the bytes are identical. xz decodes each block raw with its filter chain (rewriting the header would need its CRC recomputed) and walks the index, stream padding and later streams as the reader does | Capping the probe, which changes the format a caller with `UNLIMITED` gets |
| Refuse an over-cap `.lzma` on read, not open | Keeps the `format_unconfirmed` stamp on a probe-only claim | Refusing at open |
| Map liblzma errors by cause (PR #432) | A missing filter or a cap refusal is not damage, and callers act differently on each | Everything as `CorruptionError` |
| The Alone probe accepts any dictionary size and refuses a declared size of zero (PR #270) | Every dictionary size is legal and real streams use zero; zero padding is a valid empty stream | Gating on the dictionary size, which missed real files |
| Report data after the last stream, xz and lzip alike | The rule every codec shares ([`single-file.md`](single-file.md) §6) | Refusing, as `xz -t` does; ignoring, as `lzma.open` does |
| Find the index within 1 MiB of bytes after the end | A signature or padding appended to a file should not cost its size and seeks; a bound keeps a file of junk cheap to open | Searching the whole file; not searching, which lost the index for any appended byte |

## 7. Open questions

- **Distinguishing a multi-point rewind in the warning text.** Tracked internally.

## 8. Verify

```bash
./scripts/test.sh tests/test_seekable_streams.py tests/test_single_file.py \
    tests/test_decoder_limits.py tests/test_lzma_error_causes.py tests/test_detection.py \
    tests/test_probe_provenance_unconfirmed.py -k "xz or lzip or lzma"
```

| Claim |
| --- |
| Size from the index and trailers; not on a pipe or another archive's member stream |
| The open-time xz scan is reused by member streams |
| The combined lzip CRC-32 |
| Block and member seeks read the right bytes |
| Seeks trust a self-consistent index; forward reads verify |
| Index grammar |
| Padding |
| Thinning |
| Truncation and short sources |
| lzip trailing data is allowed |
| An LZMA Alone or lzip stream after zero bytes is trailing data, and strict refuses it; zeros at the end and streams with nothing between them stay silent |
| The index through bytes after the end, and its bound |
| Probes reserve only their read's dictionary |
| Dictionary caps |
| A check liblzma cannot compute warns |
| liblzma errors by cause |
| The Alone probe |
| Alone size from the header; `format_unconfirmed` on a probe-only failure |

**Building fixtures.** The standard library writes single-block xz and LZMA Alone
(`lzma.compress`). `tests/streams_util.py` builds multi-block xz and multi-member lzip.
`xz`, `lzip` and `plzip` install from the distribution.

## 9. References

- The xz file format, version 1.1.0 (tukaani.org/xz/xz-file-format.txt): §2.1 stream
  header and footer, §2.2 stream padding, §3 blocks, §4 index, §1.2 multi-byte integers
- The lzip manual (nongnu.org/lzip/manual/lzip_manual.html), §File format and §Trailing
  data
- The LZMA SDK's `lzma.txt` for the Alone header
- Registers: [`threat-model.md`](../threat-model.md) O10, O17 ·
  [`known-issues.md`](../known-issues.md)
- Decisions: [`library-analysis.md`](../library-analysis.md) §xz, §lzip ·
  [ADR 0014](../decisions/0014-integrity-verdicts-from-reads-not-close.md)
- Code: `internal/streams/codecs/xz_decoder.py` (`XzDecoder`, `_XzState`, `_XzBlockResume`,
  `_read_xz_index_backwards`, `lzma_error_to_archivey`) · `internal/streams/codecs/lzip_decoder.py`
  (`LzipDecoder`, `peek_index_summary`) · `internal/streams/codecs/lzma_codec.py` (`XzCodec`,
  `LzipCodec`, `LzmaAloneCodec`, `_alone_header_plausible`, `_new_alone_decompressor`)
- Handbook: [`single-file.md`](single-file.md) · [`7z.md`](7z.md) (raw LZMA and LZMA2
  coders) · [`tar.md`](tar.md)
