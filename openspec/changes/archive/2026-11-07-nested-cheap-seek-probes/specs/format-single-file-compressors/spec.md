## MODIFIED Requirements

### Requirement: Report member size with codec caveats

The system SHALL populate `member.size` according to codec metadata and
format-specific reliability limits:

| Codec | `member.size` behavior |
| --- | --- |
| GZ | `None` until full decompression; stored ISIZE is modulo 2^32 and covers only the last gzip member, so it goes in `extra["gzip.isize"]`, never in `size` |
| BZ2, ZLIB, BR, Z | `None` until full decompression; `.Z` has no size trailer (best-effort truncation via nonzero leftover bits) |
| XZ, ZST | Header size when encoder wrote it; otherwise `None` until full decompression |
| LZ4 | Frame content-size field when present; otherwise `None` until full decompression |
| LZIP | Available from the trailer on a seekable source whose end is cheap to reach; otherwise `None` until full decompression |
| LZMA Alone | 8-byte Alone header size when not the unknown marker (`0xFFFFFFFFFFFFFFFF`); otherwise `None` until full decompression |

Availability of an index/trailer-derived size SHALL be decided by **the source's shape**,
never by the caller's declared member-stream capability. `seekable_members` /
`open_stream(seekable=…)` declare intent to `seek()` inside a member stream; they select
an indexed decompressor backend and resolve accelerator `AUTO` (which for the DEFLATE
family also takes a large sequential read: `seekable-decompressor-streams`), and they
MUST NOT change what metadata a member reports. A seekable source SHALL yield the same
`member.size` with and without the declaration; a non-seekable source SHALL yield `None` for every
index/trailer-derived size, and no probe SHALL force a decompression pass to obtain one.
A source whose seek may decode what it skips (`seek_is_expensive`: another archive's
member stream, bare or under a pass-through buffer, or a standard-library `GzipFile`,
`BZ2File`, `LZMAFile` or `ZipExtFile`) is probed only when it says the seeks are cheap:
`ArchiveStream.nearest_resume_offset` SHALL answer, for the last 64 bytes, the middle
and the current position, an offset at most 4 KiB before each. The xz index and the
lzip trailers sit at the end, and on a member stream that decompresses (a deflated ZIP
entry, a `.gz`'s content) reaching them decompresses the whole member, so such a member
answers far earlier and its size is `None`. A stored ZIP entry or a TAR member is a
slice of its container, answers every target itself, and is probed as a file is. A
source that does not answer, or has no cheap length, is not probed. The end itself is
not asked: a decoder may resume there, with nothing left to decode, after decoding all
that comes before it.

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
| `.lz` opened from a seekable source whose end is cheap to reach | Size is available from the trailer |
| `.xz` / `.lz`, seekable source, with and without `seekable_members=True` | Same `member.size` both ways |
| `.xz` / `.lz` from a pipe | Size is `None` until a full read fills it; no decode pass is forced |
| `.xz` / `.lz` opened from a deflated ZIP entry longer than 4 KiB | Size is `None` until a full read fills it; the member is not seeked to its end |
| `.xz` / `.lz` opened from a seekable stored ZIP entry or TAR member | Size is available from the index or trailer |
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
xz index and lzip trailer, at least 18 bytes long (the shortest header, 10 bytes, plus the 8-byte
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
| `.gz` from a pipe or a deflated ZIP entry longer than 4 KiB | No `gzip.isize` |
| `.gz` from a seekable stored ZIP entry or TAR member | `extra["gzip.isize"]` as from a file |
| `.xz` / `.zst` / `.lz4` / `.lz` / `.bz2` | No gzip filename fields are set |

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
- **LZIP:** on a seekable source whose end is cheap to reach (as for the size), surface `CRC32` of the whole synthetic member from the
  lzip index. For multi-member files, the value SHALL equal
  `crc32(concat(member payloads))` derived by combining per-trailer CRC-32 values with
  each member's exact uncompressed `data_size` (combine algebra). Single-member
  degenerates to the trailer CRC.
- **Non-seekable source, or one whose seek may re-decode** (a deflated member stream): omit
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
| `.lz` opened from a deflated ZIP entry longer than 4 KiB | no digest key |
| `.lz` opened from a seekable stored ZIP entry or TAR member | `CRC32` present |
| `.bz2` / `.xz` / `.zlib` / `.br` / `.Z` | no digest key |
| Any of the above, full `read()` | verification unchanged; hashes are metadata only |
