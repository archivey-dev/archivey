# Single-File Compressor Format Behavior

## Purpose

Single-file compressors (GZ, BZ2, XZ, ZST, LZ4, LZIP, ZLIB, BR, Z) are exposed
as one-member pseudo-archives through the unified `ArchiveReader`
interface. Each source contains exactly one file member whose
name is inferred from the source filename.

This capability is the standalone-stream side of `compressed-streams`. Raw
Deflate and raw LZMA1/LZMA2 are not standalone formats because they lack
self-framing; they appear only inside containers such as ZIP or 7z. Unix-compress
(`.Z`, LZW) is decoded natively in core, streams from non-seekable sources under
`streaming=True`, and cannot signal truncation because the format has no length or
checksum trailer.

## Related specs

| Spec | Relationship |
| --- | --- |
| `archive-reading` | One-member reader behavior, random vs streaming access modes |
| `access-mode-and-cost` | Listing/access cost and non-seekable legality |
| `compressed-streams` | Codec descriptors, decoder availability, metadata hooks |
| `format-detection` | Bare stream detection and combined TAR-compressor detection |
| `packaging-and-extras` | Optional codec extras such as Brotli, LZ4, Zstd |

## Requirements

### Requirement: Present each compressor as a one-member archive

The system SHALL present any GZ, BZ2, XZ, ZST, LZ4, LZIP, LZMA Alone, ZLIB, BR,
or Z source as an archive containing exactly one `ArchiveMember` of type
`MemberType.FILE`. No directory members SHALL be synthesized.

The member name SHALL be inferred from the source filename:

| Source filename | Member name |
| --- | --- |
| Ends in `.gz`, `.bz2`, `.xz`, `.zst`, `.lz4`, `.lz`, `.lzma`, `.zz`, `.zlib`, `.br`, `.brotli`, or `.Z` (case-insensitive) | Strip exactly that recognized compression extension |
| Ends in `.tgz`, `.tbz2`, `.tbz`, `.txz`, `.tzst` or `.tlz` (case-insensitive) | Replace that suffix with `.tar`, as `gzip -d` and `xz -d` do |
| Ends in a recognized extension, but the remaining stem is entirely dots and spaces (`..gz`, `....gz`, ` .gz`) | Append `.uncompressed` instead; `.` and `..` are not member names, and an all-dots segment is refused under `STRICT` and `STANDARD` |
| Has a filename but no recognized compressor extension | Append `.uncompressed`; do not strip arbitrary extensions |
| Anonymous stream | `data` |

Whether `.tar.gz` or `.tgz` opens as a tar is a `format-detection` concern. The naming
rows above apply when such a source opens as a single compressed file, for example with
`format=ArchiveFormat.GZ` or a `.tgz` whose content is not a tar.

Raw Deflate and raw LZMA1/LZMA2 (`FORMAT_RAW`) remain container-only; LZMA Alone
is a framed standalone stream and is in scope here.

#### Scenario: one-member naming matrix

| Case | Expected |
| --- | --- |
| Open `data.txt.gz` | One file member named `data.txt` |
| Open `data.txt.lzma` | One file member named `data.txt` |
| Open `data.tgz` with `format=ArchiveFormat.GZ` | One file member named `data.tar` |
| Open compressed `mystery.bin` detected by content | One file member named `mystery.bin.uncompressed` |
| Open `....gz` | One file member named `....gz.uncompressed`, under every extraction policy |
| Open anonymous non-seekable stream with `streaming=True` | One file member named `data` |
| Iterate any supported single-file compressor | Exactly one file member is yielded |

### Requirement: Report single-file compressor properties

The backend SHALL expose these properties for every single-file compressor:

| Property | Value |
| --- | --- |
| Listing cost | `INDEXED`; exactly one member |
| Access cost | `DIRECT`; no inter-member dependency exists |
| Supports write | No — writing is not shipped for any format (`dev-docs/investigations/archive-writing-design.md`) |
| Requires seek | Random access (`streaming=False`) requires seek; forward-only `streaming=True` accepts non-seekable sources for every supported single-file codec including `.Z` |

Random access over a non-seekable source SHALL fail fast at open with
`StreamNotSeekableError`; the backend MUST NOT buffer an unbounded source to
simulate repeatable reads. Under `streaming=True`, every supported single-file
codec including unix-compress `.Z` SHALL stream from non-seekable sources.

Member-stream seekability is a stream-level property from index- or
accelerator-backed decoders (for example xz indexes, CLEAR seek points for
unix-compress, `indexed_bzip2`, `rapidgzip`, seekable zstd), not an archive-level
`CostReceipt` field.

#### Scenario: property matrix

| Case | Expected |
| --- | --- |
| Open any supported single-file compressor | `listing_cost=INDEXED`; `access_cost=DIRECT` |
| Non-seekable source with `streaming=False` | `StreamNotSeekableError` |
| Non-seekable source with `streaming=True` (including `.Z`) | Opens and `stream_members()` yields data |
| Seekable `.Z` with declared member-stream seekability | Member stream is seekable via CLEAR seek points |

### Requirement: Report member size with codec caveats

The system SHALL populate `member.size` according to codec metadata and
format-specific reliability limits:

| Codec | `member.size` behavior |
| --- | --- |
| GZ | `None` until full decompression; stored ISIZE is modulo 2^32 and covers only the last gzip member, so it goes in `extra["gzip.isize"]`, never in `size` |
| BZ2, ZLIB, BR, Z | `None` until full decompression; `.Z` has no size trailer (best-effort truncation via nonzero leftover bits) |
| XZ, ZST | Header size when encoder wrote it; otherwise `None` until full decompression |
| LZ4 | Frame content-size field when present; otherwise `None` until full decompression |
| LZIP | Available from the trailer on a seekable source that is not another archive's member stream; otherwise `None` until full decompression |
| LZMA Alone | 8-byte Alone header size when not the unknown marker (`0xFFFFFFFFFFFFFFFF`); otherwise `None` until full decompression |

Availability of an index/trailer-derived size SHALL be decided by **the source's shape**,
never by the caller's declared member-stream capability. `seekable_members` /
`open_stream(seekable=…)` declare intent to `seek()` inside a member stream; they select
an indexed decompressor backend and resolve accelerator `AUTO` (which for the DEFLATE
family also takes a large sequential read: `seekable-decompressor-streams`), and they
MUST NOT change what metadata a member reports. A seekable source SHALL yield the same
`member.size` with and without the declaration; a non-seekable source SHALL yield `None` for every
index/trailer-derived size, and no probe SHALL force a decompression pass to obtain one.
Another archive's member stream, bare or under a pass-through buffer
(`seek_is_expensive`), counts as a source that cannot reach its end cheaply, so the size
is `None`. The xz index and the lzip trailers sit at the end, and on a member stream
that decompresses (a deflated ZIP entry, a `.gz`'s content) reaching them decompresses
the whole member. Member streams are treated this way as a group: a stored ZIP entry or
a TAR member, whose seek is a slice of its container, also reports `size=None`.

`member.compressed_size` SHALL be the source's length when that is cheap to learn. A
member stream from another archive (`seek_is_expensive`) SHALL report its advertised
`size`, the length its container's header declares, whether or not the member stream is
seekable: the value MUST NOT depend on the outer archive's `seekable_members`. Any other
seekable source SHALL report its cheap size (a path's `stat`, a `BytesIO`'s buffer, a
caller stream's `size` attribute), else one `seek(0, SEEK_END)` when the seek is cheap.
A caller's non-seekable stream SHALL report `None`, also when it has a `size` attribute,
and so SHALL a member stream that advertises no length, rather than seek to the end.

The rule turns on seekability, not on trust: a seekable caller stream's `size` attribute
is reported unchecked, and on a pipe there is no `SEEK_END` to answer instead, so `None`
is the answer it always had. The value is more than metadata. Two extraction ratio
guards divide by a source length: the per-member guard by `compressed_size`, and the
archive-wide guard by `BaseArchiveReader.compressed_source_size`. Both follow this rule
(`safe-extraction`, "Archive-wide decompression ratio for solid containers"), so a
caller's `size` attribute on a pipe reaches neither, and the live ratio applies. A
member stream's declared length is unchecked too: a ZIP member that holds fewer bytes
than it declares is refused with `TruncatedError` only after its payload is decoded,
and a TAR member stream answers `SEEK_END` from the same declared length, so no seek
could learn more. For a nested archive, `max_extracted_bytes` is the bound that holds.

A member whose `size` is `None` after listing SHALL take its size from the first read
that reaches the end of the member having returned every byte from its start in order,
and that the decoder finishes without error: `size` becomes that end position, set in
place on the reader's member object (the one `members()` and `get()` return). This is
the condition under which a member's digest is kept (`dev-docs/design-rules.md`
DR-4a). A seek back keeps the fill, and so does a forward seek whose gap must be
decoded anyway (every codec here with no seek index): the gap is read through the
check. A read that stops early or raises SHALL leave `size` as it is, and so SHALL one
that reaches the end after a seek jumped over bytes nothing decoded (an index jump, an
accelerator, a seek to an end not yet known), until a seek back to where the reads had
reached and a read on to the end. The filled `size` is only as good as the codec's end
check: where that check is best-effort, such as a `.Z` (no end marker or checksum) or
an accelerated `.gz` (see the rapidgzip caveat), a cut the decoder cannot see ends the
read cleanly and fills the length of the cut data, as the data read is. Until the size
is filled in, a `streaming=True` pass ends, or the reader closes, `member_state_final`
SHALL be `False` (`archive-data-model`). A copy made with `replace()` is never filled.
A size the format records SHALL NOT be replaced.

#### Scenario: size matrix

| Case | Expected |
| --- | --- |
| `.gz` opened | Single member size is `None`; `member_state_final` is `False` |
| `.bz2` before full decompression | Size is `None` |
| `.gz` / `.bz2` / `.zz` / `.br` / `.Z` read from the start to EOF with no seek | `size` is the byte count read; `member_state_final` is `True` |
| Same, read that stops short of EOF, or raises (`TruncatedError`) | `size` stays `None` |
| Same, `read(100)`, `seek(5000)`, read to EOF (the seek decodes the gap anyway) | `size` is the byte count |
| Same, `seek(0, SEEK_END)`, then read to EOF | `size` stays `None` |
| Same, then `seek()` back to where the reads had reached, read to EOF | `size` is the byte count |
| Same, `read(100)`, `seek(50)`, read to EOF | `size` is the byte count |
| Same, `streaming=True` pass over a pipe, stream read to EOF | `size` is the byte count read |
| Same, reader closed with the member never read in full | `size` is `None`; `member_state_final` is `True` |
| `.lz` opened from a seekable source, not a member stream | Size is available from the trailer |
| `.xz` / `.lz`, seekable source, with and without `seekable_members=True` | Same `member.size` both ways |
| `.xz` / `.lz` from a pipe | Size is `None` until a full read fills it; no decode pass is forced |
| `.xz` / `.lz` opened from another archive's member stream | Size is `None` until a full read fills it; the member is not seeked to its end |
| `.xz` / `.lz` opened from a stored ZIP entry or a TAR member | Size is `None` until a full read fills it, as for any member stream, though that seek would be a slice |
| `.gz` from a path or `BytesIO` | `compressed_size` is the source's length |
| `.gz` from a caller's pipe with a `size` attribute | `compressed_size` is `None` |
| `.gz` from a member stream that advertises its length, seekable or not | `compressed_size` is that length; no seek to the end |
| `.gz` from a member stream with no advertised length | `compressed_size` is `None`; no seek to the end |
| Alone stream with known header size | `member.size` equals that size |
| Alone stream with unknown-size marker | Size is `None` until a full read fills it |
| Truncated `.Z` with nonzero leftover bits | Available bytes delivered; next `read()` raises `TruncatedError` |

### Requirement: Surface gzip stored metadata without trusting it as the name

The system SHALL surface gzip `FNAME` when present: the decoded value appears in
`member.extra["gzip.original_filename"]` and the undecoded bytes appear in
`member.raw_name`. By default, `member.name` SHALL still come from the source
filename; embedded gzip names are not automatically trusted because they may
disagree with the container filename. A configuration option MAY prefer the
gzip-stored name for `member.name`. Other single-file compressors SHALL not set
these fields from header data because they carry no embedded filename.

The system SHALL surface the gzip trailer's ISIZE field as `member.extra["gzip.isize"]`
(an `int`) when the source's end can be reached cheaply, under the same rule as the
xz index and lzip trailer: a seekable source that is not another archive's member
stream, at least 18 bytes long (the shortest header, 10 bytes, plus the 8-byte
trailer; anything shorter has no trailer to read). The value is the last four bytes of
the file, read little-endian. It is the uncompressed size modulo 2^32 only for a file
of one gzip member with nothing after it; a file of several members (bgzip ends with an
empty one) or with trailing bytes stores something else, and nothing short of reading
the whole file tells these apart. It SHALL therefore never fill `member.size`.

#### Scenario: gzip metadata matrix

| Case | Expected |
| --- | --- |
| `.gz` with `FNAME="report.csv"` opened from `archive.gz` | `extra["gzip.original_filename"] == "report.csv"`; `raw_name` holds undecoded bytes; default `name == "archive"` |
| `.gz` without `FNAME` | No gzip original filename extra; name is derived from source filename |
| `.gz` of one member from a path or `BytesIO` | `extra["gzip.isize"]` is the uncompressed size modulo 2^32; `size` is `None` |
| `.gz` of two members | `extra["gzip.isize"]` is the last member's ISIZE; a full read fills `size` with the whole length |
| `.gz` from a pipe or another archive's member stream | No `gzip.isize` |
| `.xz` / `.zst` / `.lz4` / `.lz` / `.bz2` | No gzip filename fields are set |

### Requirement: Get per-codec metadata from codec descriptors

`SingleFileBackend` SHALL obtain per-codec metadata from each
`compressed-streams` codec descriptor rather than a reader-local dispatch table.
Descriptor hooks SHALL preserve existing surfaced metadata: gzip `FNAME`,
`raw_name`, optional gzip mtime, xz/zst/lz4/lzip size hints, and the
format-specific size-availability rules. A codec with no extra metadata SHALL
register no hook.

#### Scenario: descriptor metadata matrix

| Case | Expected |
| --- | --- |
| `.gz` with stored `FNAME` and mtime | Gzip descriptor hook populates extra filename, `raw_name`, and `modified` |
| `.bz2` source | No hook is needed; default single-file member shell is used |
| Size-aware lzip source | Lzip descriptor hook supplies trailer-derived size |

### Requirement: Use one backend for every standalone codec

The system SHALL implement single-file compressor reading as one
`SingleFileBackend` whose `FORMATS` tuple lists every standalone-stream codec.
The backend SHALL infer the one-member shell, then delegate decompression and
metadata to the stream codec resolved from the member's stream format. Detection
tables and availability SHALL derive from codec descriptors: the backend remains
registered, while a format whose required codec backend is missing reports
support `NONE`. Adding a new standalone codec descriptor SHALL make that format
readable without adding another `ReadBackend` subclass.

#### Scenario: backend matrix

| Case | Expected |
| --- | --- |
| Open `.gz`, `.bz2`, `.xz`, `.lzma` | Same `SingleFileBackend` class serves each format with per-codec metadata |
| Register a new standalone codec descriptor | Existing backend reads it through the descriptor |
| Required codec backend is missing | Format availability reports `NONE`, not a separate backend failure |

### Requirement: Surface stored decompressed digests without decompression

The single-file backend SHALL surface a codec's stored (or cheaply derived-from-stored)
decompressed-content digest(s) on `member.hashes` when readable without decompressing,
and SHALL omit them otherwise. This serves cheap dedupe (`VISION.md` "hashes without
decompression") and never triggers a decompression pass.

Keys and value types follow the public `HashAlgorithm` / `bytes` contract (api-coherence
hashes typing). Surfacing SHALL NOT change read behavior: a full read still verifies via
the existing path; stored/derived values are metadata only.

Whether a digest is cheaply readable SHALL depend only on the codec and **the source's
shape**, never on the caller's declared member-stream capability — the founding dedupe
caller does a plain `open_archive()` and never asks to `seek()`.

- **GZIP:** SHALL NOT carry a digest, before or after a read, and opening SHALL NOT
  read the compressed data to look for a second member. The trailer `CRC32` covers the
  whole member only when the file holds one gzip member, and proving that at open costs
  a pass over the whole file (a scan for the three-byte member magic that also
  false-matches in large compressed data). After a full read it would add nothing: the
  decoder has already checked every member's CRC, and a digest is worth having only
  before a read (to skip one) or to verify one.
- **LZIP:** on a seekable source that is not a member stream, surface `CRC32` of the whole synthetic member from the
  lzip index. For multi-member files, the value SHALL equal
  `crc32(concat(member payloads))` derived by combining per-trailer CRC-32 values with
  each member's exact uncompressed `data_size` (combine algebra). Single-member
  degenerates to the trailer CRC.
- **Non-seekable source, or one whose seek may re-decode** (a member stream): omit
  digests that require a trailer/index peek (no forced decode).
- **BZ2, XZ, ZLIB, BR, `.Z`:** no cheap whole-member stored digest — omit. (Zlib's
  RFC 1950 Adler-32 trailer is verified by the decompressor on read; it is not surfaced
  on `member.hashes` because the wrapper has no size fields for a reliable
  single-stream boundary when concat/trailing junk is possible.)

#### Scenario: stored-digest surfacing by codec

| Case | `member.hashes` |
| --- | --- |
| Any `.gz` (one member or several), listed or after a full read | no digest key |
| Opening any `.gz` | no scan of the compressed data for a second member |
| `.gz` non-seekable | no digest key |
| Single-member `.lz`, seekable source | `CRC32` present (= trailer) |
| Multi-member `.lz`, seekable source | `CRC32` present (= combine of per-member trailers) |
| `.lz` seekable, with and without `seekable_members=True` | Same `hashes` both ways |
| `.lz` from a pipe | no digest key |
| `.lz` opened from another archive's member stream, a stored ZIP entry or a TAR member included | no digest key |
| `.bz2` / `.xz` / `.zlib` / `.br` / `.Z` | no digest key |
| Any of the above, full `read()` | verification unchanged; hashes are metadata only |

### Requirement: A single-file source is validated at open, not at first read

`open_archive` on a single-file compressor SHALL establish that the source is decodable as
the detected codec before returning a reader, and SHALL raise the translated error
(`CorruptionError` / `TruncatedError` / the codec's `PackageNotInstalledError`) from
`open_archive` rather than from a later read.

Validation depth is **one decoded byte, or a proof that one cannot exist**:

- the reader SHALL pull at least one byte from a codec stream over the source, because
  every stdlib codec validates its header on first read and not at construction;
- `read` returning empty is accepted as a valid empty stream only because every codec's
  decoder raises on a source too short to hold its own header (`unix-compress` included:
  its decoder raises `TruncatedError` below the 3-byte header). A codec whose decoder
  reads a zero-byte input as an empty stream SHALL reject a source shorter than its
  minimum header on length before it is admitted.
- the byte SHALL be decoded with the standard library, so the check starts no
  accelerator child process; the accelerator SHALL still be resolved at open, so `ON`
  with the accelerator's package absent or no child process possible raises from
  `open_archive`.

The check SHALL run after `open_archive` has recorded the format's provenance, so an
open-time decode failure is stamped `format_unconfirmed` exactly as a read-time one
would be. The error SHALL NOT name a member, since none was requested.

A genuinely valid empty stream SHALL still open and read as empty.

Non-seekable sources are out of scope: the opened stream is handed to the first
`open_member`, so a probe read there would consume a byte the caller expects. The
obligation applies to seekable sources, and the reader SHALL say so where it is stated.

#### Scenario: open-time validation matrix

| Source, named for each of the ten codecs | Expected |
| --- | --- |
| Valid stream | Opens; member reads its content |
| Valid **empty** stream | Opens; member reads `b""` |
| 40 000 zero bytes | `open_archive` raises `CorruptionError`, except LZMA Alone, whose first 18 zero bytes are a complete empty stream: it opens, reads `b""`, and the rest is padding with no diagnostic |
| Zero-byte source, codec whose decoder rejects it | `open_archive` raises the translated error |
| Zero-byte source, `unix-compress` | `open_archive` raises `TruncatedError` (the decoder rejects a source shorter than its header) |
| Non-seekable source | Validation deferred to the first read |

#### Scenario: the failure carries honest provenance

The open-time raise is stamped with the same provenance a read-time one would carry:
`format_unconfirmed` follows the decode failure whichever call surfaces it. Which evidence
sets that flag is the detection contract's to define, not this one's.

| Case | Expected |
| --- | --- |
| `backup.gz` of zeros, format chosen by extension alone | Raises at `open_archive`, not on a later read |
| Same, `format_unconfirmed` on that exception | Whatever the detection contract assigns to extension-only evidence (today `False`) |
| A probe-only format (no corroborating extension) whose first byte does not decode | Raises at `open_archive` with `format_unconfirmed=True` and emits `PROBE_FORMAT_UNCONFIRMED` |
| `member_name` on the open-time exception | `None` |
| Listing is never reached for an undecodable source | The empty-listing diagnostic channel is not the reporting path for this class |
| A source whose first byte decodes and that fails later | A read-time failure |

### Requirement: Bytes after a compressed stream are read past and reported

For gzip, zlib, bzip2, xz, lzip, LZMA Alone, zstd, LZ4 and Brotli, a
member read SHALL deliver the whole payload of every stream before the end, and SHALL
then stop reading the source. Bytes after the end SHALL be classified this way:

- the start of another stream of the same codec is more data and is read: its magic,
  or for LZMA Alone, which has none, a properties byte liblzma decodes (`lc + lp` at
  most 4) and a zero first byte of range-coder data, as `lzma.LZMAFile` reads a second
  stream. Bytes that pass this check but are not a valid stream fail the read with
  `CorruptionError`;
- for xz, lzip, zstd, LZ4 and bzip2, bytes that match the codec's stream magic in at
  least half of its positions, but not in all of them, are a further stream with a
  damaged header: the read, and a seek that reaches them, SHALL raise `CorruptionError`.
  The positions compared are the first `len(magic)` bytes right after the stream, and
  for xz the first after its stream padding. For zstd, LZ4 and bzip2, a run of zero
  bytes shorter than the magic SHALL also be compared as the first bytes of the magic,
  since a damaged byte can be zero; after a run as long as the magic or longer nothing
  is compared, as no stream is read after zero bytes (next bullet). This is lzip's rule
  for a corrupt header in a multimember file. A tail shorter than the magic is not
  judged by it. gzip, zlib, LZMA Alone and Brotli do not apply it;
- zero bytes are padding and SHALL NOT be reported where they run to the end of the
  source. For every codec but xz, whose format defines Stream Padding between streams,
  they are padding only there: after zero bytes, the first non-zero byte is trailing
  data as the next bullet says, also when it starts another stream, in every
  accelerator mode. Each codec's own tool stops there too (GNU `gzip`, `bzip2`,
  `zstd`, `lz4`, `xz --format=lzma`), and so does 7-Zip for gzip, bzip2 and LZMA Alone;
- anything else is trailing data: the system SHALL emit one `ARCHIVE_TRAILING_DATA`
  per opened member stream, with `expected_marker="end_of_stream"`, the codec name as
  `format`, and the offset of the first non-zero byte after the end as
  `observed_bytes`. A re-read after a seek SHALL NOT report again.

Under the default policy the diagnostic is a warning and the read succeeds. Under
`DiagnosticPolicy.STRICT` it raises `DiagnosticRaisedError` from the read that
reaches it.

The report SHALL come only from a bare single-file read, a compressed TAR's codec,
and `open_stream`. A codec opened inside a ZIP or 7z member, or for detection or a
metadata probe, SHALL stop at the end without reporting.

xz and lzip SHALL find their index when non-zero trailing bytes follow it, by
searching back from the end of the source at most `TRAILING_DATA_SEARCH` (1 MiB) and
checking at most `TRAILING_DATA_CANDIDATES` (4096) candidate ends there. A footer
further out, or behind more candidates, is not found: the index is reported unreadable
(`SEEK_INDEX_DEGRADED` on a seek) and the size is unknown, while a forward read still
delivers the payload and reports the trailing data. A footer (xz) or trailer (lzip)
whose following bytes start another stream, as the first bullet above classifies
them, is not the last one, so the search SHALL NOT stop there: when the last stream's
own footer or trailer is damaged, the index is reported unreadable, the size and CRC
are unknown, and the read or seek that reaches the damage raises `CorruptionError`.
The same holds when the bytes after a footer or trailer are a damaged header magic, as
the second bullet above classifies them.

Brotli's decoder fails on input past the end the same way it fails on damage. The
system SHALL tell them apart by decoding the source again from the start up to the
failure, one byte at a time over the failing region; a stream that ends before the
failure has trailing data, anything else is corruption. On a non-seekable source it
cannot re-read, and the failure SHALL stay `CorruptionError`.

`.Z` (unix-compress) is outside this requirement: it has no end marker, so bytes
after the data decode as more codes.

#### Scenario: trailing data after a single-file stream

| Case | Expected |
| --- | --- |
| Valid stream of any listed codec + `b"appended signature\n"` | Full payload; one `ARCHIVE_TRAILING_DATA`, `observed_bytes` = compressed length |
| Same, `DiagnosticPolicy.STRICT` | The read raises `DiagnosticRaisedError` |
| Valid stream + 4096 zero bytes | Full payload; no diagnostic |
| Valid stream + zeros + junk | One report at the first non-zero byte |
| Two concatenated `.gz` / `.bz2` / `.lzma` / `.zst` / `.lz4` streams + junk | Both payloads; one report after the second |
| `.gz` / `.bz2` / `.zst` / `.lz4` / `.lzma` / `.lz` stream + zero bytes + another stream, accelerator `OFF`, `AUTO` or `ON` | The first payload; one report at the second stream's first byte; under strict the read raises |
| Two `.xz` streams with zero bytes between them | Both payloads; no report (xz Stream Padding) |
| `.bz2` stream + empty streams + zero bytes | Full payload; no diagnostic |
| `.zst` with a skippable frame between two frames | Both payloads; no report |
| `.xz` / `.lz` + junk within 1 MiB | Size known, seek works, full payload, one report |
| Two concatenated `.xz` streams (with or without stream padding) or `.lz` members, last footer or trailer damaged | Size and CRC unknown; data up to the damage, then `CorruptionError` from the read or `SEEK_END` |
| `.lz` member + zero bytes + a damaged member | Size and CRC of the first member; its payload and one report |
| Two `.xz` / `.lz` / `.zst` / `.lz4` / `.bz2` streams, one byte of the second stream's magic damaged | `CorruptionError` from the read and from `SEEK_END`, from a file and from a pipe; no size from the index |
| Two `.zst` / `.lz4` / `.bz2` streams, the second stream's first magic byte set to zero | `CorruptionError` from the read, with the accelerator on and off for `.bz2` |
| Two `.xz` / `.lz` / `.zst` / `.lz4` / `.bz2` streams, the second one's first one or two magic bytes set to zero and the file ending after its magic | `CorruptionError` from the read, from a file and from a pipe; accelerator on and off for `.bz2` |
| A stream + 64 random bytes that match no magic in half of its positions | Full payload; one report |
| A stream + its own first `len(magic) - 1` bytes, at the end of the file | Full payload; one report |
| `.bz2` + `BZh0` and an empty stream's end-of-stream marker | `CorruptionError`, with the accelerator on and off |
| `.xz` / `.lz` + more than 1 MiB of junk | Size unknown; seeking reports `SEEK_INDEX_DEGRADED`; payload and one report |
| `.lz` + 900 000 zero bytes + junk | Size known, seek works, full payload, one report |
| `.xz` + 1 MiB of `00 00 59 5A`, `.lz` + 1 MiB of 8 zero bytes and one byte, repeated | Size unknown; payload and one report, after at most 4096 candidates checked |
| `.tar.xz` with junk after the xz stream | Members read; one report with `format="xz"` |
| Brotli + junk from a pipe | `CorruptionError` |
| Brotli damaged mid-stream | `CorruptionError` |
| `.Z` + junk | Not this requirement |

### Requirement: An lzip member in another version is unsupported

archivey SHALL read lzip version 1 only. A member whose header has the `LZIP` magic and
any other version byte, version 0 (lzip before 1.0) included, SHALL raise
`UnsupportedFeatureError`, not `CorruptionError`, and SHALL NOT be decoded. A full
`LZIP` magic SHALL start a member after a version-1 member as at the start of the file,
so a version-0 member after a version-1 one is refused, not read past as trailing data.
This matches `lzip`, which reports such a member as an unsupported version.

A seek SHALL NOT skip a member the forward read refuses: a seek to or past it raises
`UnsupportedFeatureError` too. The size and CRC-32 that the metadata probe reads at
open are unknown for such a file, and the open-time one-byte read raises
`UnsupportedFeatureError` when the first member is the one refused.

#### Scenario: lzip versions

| Source | Expected |
| --- | --- |
| A member in version 0, 2 or 255, anywhere in the file | A read or a seek that reaches it raises `UnsupportedFeatureError` |
| A version-1 member + `LZIP` and a version byte, with no dictionary byte | `TruncatedError` on a read and on a seek alike |

### Requirement: A stream header its tool calls unsupported is unsupported

A compressed-stream header that the format's own tool refuses as unsupported, rather
than as damaged, SHALL raise `UnsupportedFeatureError`, not `CorruptionError`, and SHALL
NOT be decoded:

- gzip: a member whose compression method is not 8 (deflate) or whose header sets a
  reserved FLG bit (gzip: "unknown method N -- not supported", "has flags 0xN -- not
  supported", "is encrypted -- not supported"), on the first member or a later one;
- lz4: a frame whose version bits are not `01` (`ERROR_headerVersion_wrong`);
- zstd: a frame that names a dictionary (zstd: "Dictionary mismatch"); archivey has no
  way to be given one;
- `.Z`: a maximum code width over 16 bits (gzip and ncompress: "compressed with 17
  bits, can only handle 16 bits").

A header the tool reports as damaged stays `CorruptionError`, such as a gzip header CRC
that does not match. A damaged byte in one of the fields listed above reads the same as
the unsupported value, since nothing tells the two apart; the `UnsupportedFeatureError`
message SHALL say that a damaged header reads the same way (the `error-handling` error
split carries the general rule).

#### Scenario: unsupported stream headers

| Source | Expected |
| --- | --- |
| gzip member with CM 7, or FLG bit 5, 6 or 7 set, first or later member, accelerator on or off | `UnsupportedFeatureError` |
| lz4 frame with version bits `00`, `10` or `11` | `UnsupportedFeatureError` |
| zstd frame compressed with a dictionary | `UnsupportedFeatureError` |
| `.Z` with maximum code width 17 or 31 | `UnsupportedFeatureError` |
| gzip header CRC mismatch | `CorruptionError` |
| zlib stream whose CM is 7 (zlib: "unknown compression method") | `CorruptionError` |
