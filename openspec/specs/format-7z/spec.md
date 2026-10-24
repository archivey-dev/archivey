# 7-Zip Archive Support

## Purpose

Archivey reads 7-Zip archives with a native, zero-dependency reader. The reader
parses headers itself and uses shared `compressed-streams` decoders backed by the
standard library for the common methods (`lzma` `FORMAT_RAW`, `bz2`, `zlib`).
`py7zr` is not a read dependency; it is used only for optional 7z writing and as
a test oracle.

The native-first strategy preserves true pull-based streaming and avoids
background thread/queue or per-folder spooling behavior from push-based library
readers. It follows the `archivey-dev` `sevenzip-native-reader` exploration.

## Related specs

| Spec | Relationship |
| --- | --- |
| `archive-reading` | `open_archive`, multi-source input, passwords, bounded storage, `stream_members` |
| `access-mode-and-cost` | Seek requirement, cost receipt, solid access semantics |
| `compressed-streams` | Decoder composition, CRC verification, optional codec backends |
| `packaging-and-extras` | `[recommended]` extra |
| `testing-contract` | Native parser coverage and `py7zr` oracle checks |

## Requirements

### Requirement: Declare 7-Zip format properties

The 7-Zip backend SHALL expose these properties:

| Property | Value |
| --- | --- |
| Read dependency | None; native parser + shared stdlib-backed decoders |
| Write dependency | Not shipped in the current release (writing deferred; no 7z-writing extra) |
| Listing cost | O(1); native header parse, no file-data decompression |
| Access cost | `SOLID` when any folder packs multiple files; `DIRECT` for single-file folders |
| Supports write | No (read-only until the writing phase) |
| Requires seek | Yes |

#### Scenario: format property matrix

| Case | Expected |
| --- | --- |
| Open a seekable 7z for listing | Header is parsed natively; full member list is available; no third-party reader imports |
| Open from a non-seekable source | Open fails because 7z requires seek |

### Requirement: Parse 7-Zip headers natively

The system SHALL parse the signature header, packed-streams info, folders/coder
chains, substreams info, files info, archive comment, and anti-items without any
third-party reader. The parsed header produces every member, each member's folder
mapping, each folder's file count, contiguous file layout inside decompressed
folder output, and `ArchiveInfo.comment` when present. Anti-items SHALL not
corrupt the member list.

A `FILES_INFO` property the reader does not handle SHALL be skipped by its size
prefix, as 7-Zip does, within the header buffer. A member's `raw_name` SHALL be the
stored UTF-16LE name, backslashes included; only the presented `name` treats `\` as a
separator.

A name SHALL decode as UTF-16LE with `surrogatepass`: a surrogate without its partner
stays in `name` as that code unit, every member still lists, and `raw_name` encodes back
to the stored units. Under `STRICT` and `STANDARD` extraction percent-escapes such a
name as a non-portable one; under `TRUSTED` it writes the name as 7-Zip does
(`safe-extraction`, "Lone surrogates in a member name"). A unit in U+DC80–U+DCFF is the
exception under `TRUSTED`: in a Python `str` it cannot be told from a `surrogateescape`
byte, so extraction takes it for one, as it does for every format, and does not write
7-Zip's three-byte form. The archive comment SHALL decode the same way: a lone unit
stays in `ArchiveInfo.comment`, and only a comment with an odd byte count is a
`CorruptionError`.

#### Scenario: native header matrix

| Case | Expected |
| --- | --- |
| Open any supported 7z | Members and folder mapping come from the header without decompressing folders |
| Archive stores a comment | `ArchiveInfo.comment` contains the comment |
| Archive contains anti-items | Member list remains correct |
| `FILES_INFO` holds an unknown property (ID `0x1A` or higher) | Property skipped; members read |
| `ARCHIVE_PROPERTIES` holds a property of any ID | Property skipped by its size; members read |
| `PACK_INFO`, `UNPACK_INFO` or `SUBSTREAMS_INFO` holds a property ID that 7z does not define | Property skipped by its size, as 7-Zip does; members read |
| Bytes follow the header's final `kEnd` | `CorruptionError`, as 7-Zip reports a headers error; never an empty archive |
| Stored name `dir\file.txt` | `name == "dir/file.txt"`; `raw_name` is the stored bytes, backslash included |
| Stored name holds a lone surrogate (`hi` U+D800) | Every member lists; `name == "hi\ud800"`; never `CorruptionError` |
| Comment holds a lone surrogate (`note` U+D800) | Archive opens; `ArchiveInfo.comment == "note\ud800"` |
| Comment payload has an odd byte count | `CorruptionError` |

### Requirement: Accept a non-zero archive start offset (SFX)

The 7z reader SHALL accept an archive whose signature header (`7z\xBC\xAF'\x1C`)
begins at a non-zero byte offset — whether supplied as an explicit start offset
from detection (`payload_offset`) or discovered by a bounded forward scan when
magic is absent at the open position (forced `format=SEVEN_Z` on an SFX stub).

All absolute seeks derived from the signature header SHALL be relative to that
signature origin. The system SHALL read in place and SHALL NOT copy the archive
to a temporary file solely to strip a stub. The forced-format scan bound SHALL be
the shared `SFX_MAX` constant (same binding as the RAR parser and
`detect_format`; today 2 MiB).

The forced-format scan SHALL skip a candidate whose signature header does not
validate and continue, returning the earliest VALID match. If none validate, it
SHALL fall back to the earliest identified candidate so a damaged or empty
payload still reaches the parser. After `MAX_VALIDATED_CANDIDATES` (256)
rejected candidates the scan SHALL stop and raise `CorruptionError` naming the
cap. That bound is structural (a real SFX stub does not carry hundreds of
format magics, and the parser has no `DetectionBudget`) and is not a
`ListingLimits` knob. A miss with no candidate SHALL raise `CorruptionError`
naming that there was no match.

#### Scenario: 7z SFX / start-offset matrix

| Case | Expected |
| --- | --- |
| Magic at open origin (offset 0) | Unchanged success path |
| Explicit start offset N with magic at N | Signature parsed at N; members listed |
| Forced `format=SEVEN_Z`, `MZ` stub, magic at N within `SFX_MAX`, header validates | Scan finds N; open succeeds |
| Forced `format=SEVEN_Z`, `MZ` stub, magic at N, header does not validate, no later VALID hit | Scan falls back to N; the parser reports the damage (truncated or CRC-broken) or opens (empty archive, `NextHeaderSize` 0) |
| Forced `format=SEVEN_Z`, decoy magic then a VALID payload within `SFX_MAX` | Earliest VALID wins |
| Forced `format=SEVEN_Z`, no magic within `SFX_MAX` | `CorruptionError` naming that there was no match |
| Forced `format=SEVEN_Z`, `MAX_VALIDATED_CANDIDATES` (256) candidates rejected, none VALID | `CorruptionError` naming that the candidate cap was reached |
| Packed streams after an SFX signature | Pack/header seeks use signature origin; members readable |

### Requirement: Report bytes after the end of a 7z archive

A 7z archive SHALL be taken to end at the later of the end of its next header
(signature header plus `NextHeaderOffset` plus `NextHeaderSize`) and the end of its
last packed stream (signature header plus `PackPos` plus the pack sizes), both counted
from the signature origin and including an encoded header's packed stream. After the
header has parsed, the reader SHALL look at most 1 MiB past that end, and a non-zero
byte there SHALL emit one `ARCHIVE_TRAILING_DATA` with `format="7z"`,
`expected_marker="zeros_to_eof"`, `observed_kind="nonzero"` and `observed_bytes` the
offset of that byte past the end. It is a warning by default and raises under
`DiagnosticPolicy.STRICT` (DR-3). Zero bytes after the end SHALL be silent. A
non-zero byte at 1 MiB or more past the end goes unseen: the bound is an effort limit,
as for the TAR trailer scan. A self-extractor's tail (the certificate table of a
code-signed one) is reported the same way, measured from the archive's own end, not the
file's. 7-Zip 23.01 warns "There are data after the end of archive" for any tail, zeros
included; archivey keeps an all-zero tail silent, the DR-3 rule shared with TAR.

#### Scenario: 7z trailing bytes

| Case | Default policy | `STRICT` |
| --- | --- | --- |
| Archive ends at its next header | Nothing | Opens |
| 4 KiB of zeros after the next header | Nothing | Opens |
| `b"JUNK"` after the next header, or after fewer than 1 MiB of zeros | `ARCHIVE_TRAILING_DATA`, `observed_bytes` = zeros skipped | `DiagnosticRaisedError` |
| Two 7z archives concatenated | First listed; `ARCHIVE_TRAILING_DATA` at 0 | `DiagnosticRaisedError` |
| `b"JUNK"` at 1 MiB or more past the end | Nothing (past the scan bound) | Opens |
| Packed stream after the next header, nothing after it | Nothing | Opens |
| Empty archive (`NextHeaderSize` 0) followed by `b"JUNK"` | `ARCHIVE_TRAILING_DATA` at 0 | `DiagnosticRaisedError` |

### Requirement: Bound 7z header count fields before allocation

The system SHALL bound count fields read from the 7z header (including
`num_files` and other pre-allocated tables) against the already size-bounded,
CRC-checked header buffer before allocating per-entry structures. A count that
cannot fit in the remaining header semantics SHALL raise `CorruptionError`
(hostile/nonsensical header), independent of `ListingLimits`.

The header buffer is fully resident in memory before parsing, and bounds
enforcement SHALL be independent of how that buffer is walked (byte-cursor or
stream): any field or property read whose length exceeds the bytes remaining in
the header SHALL raise `CorruptionError` at parse, never read past the buffer or
return a short value.

Spine `ListingLimits` (`archive-reading`) still apply. For 7z they are
enforced at header parse — folders, unpack streams, and `num_files` —
because the whole index is resident at `open_archive`. Pack streams are a
coder-graph quantity (a BCJ2 folder has four) and keep the header-size
bound only. A folder, unpack-stream, or file count over
`listing_limits.max_members` (when not `None`) SHALL raise
`ResourceLimitError` at parse, before per-entry allocation. `None`
(`ListingLimits.UNLIMITED`) disables that bound; header-size
`CorruptionError` remains. Parser bounds MUST NOT be implemented by reusing
`ExtractionLimits.max_entries`.

Once the header has parsed (a plain header, or the header an encoded or encrypted
header decodes to), the names it holds (each as `name` and as `raw_name`, two
bytes per character for the stored UTF-16) and the archive comment SHALL be weighed
against `listing_limits.max_metadata_bytes`, by the weights of `archive-reading`;
over it SHALL raise `ResourceLimitError` naming `max_metadata_bytes` at
`open_archive`. The header's own size bound (64 MiB, stored or decoded) is a fixed
parser limit, separate from this budget.

#### Scenario: 7z header bound matrix

| Case | Expected |
| --- | --- |
| `num_files` greater than header buffer size | `CorruptionError` at parse; no giant pre-allocation |
| `NumUnpackStreams` (or the sum across folders) greater than the header buffer size | `CorruptionError` at parse; no giant `* count` allocation |
| Pack-stream, folder, unpack-stream, or file count greater than the header buffer size | `CorruptionError` at parse |
| Legitimate archive whose header is large enough for its file count | Parse succeeds; listing still subject to `ListingLimits` |
| Folder, unpack-stream, or file count over `listing_limits.max_members` | `ResourceLimitError` at parse (`open_archive`), including `stream_members()` |
| `listing_limits.max_members is None` (`UNLIMITED`) | Header-size bound only; a large honest archive opens |
| Plain, encoded or encrypted header, under `max_members`, whose names weigh more than `max_metadata_bytes` | `ResourceLimitError` naming `max_metadata_bytes` at `open_archive`, including `stream_members()` |
| The same archive with `max_metadata_bytes` at exactly what registration weighs | Opens and lists |

#### Scenario: in-header read stays within the buffer

| Case | Expected |
| --- | --- |
| Property payload claims more bytes than remain in the header | `CorruptionError`; no read past the buffer |
| A fixed-width field (uint32 / real-uint64 / byte) read at end-of-buffer | `CorruptionError`; never a short/zero-padded value |
| Well-formed header exactly consumed to its end | Parse succeeds; no residual-bytes error |

### Requirement: Bound encoded-header decode work

The system SHALL decode at most one encoded-header layer (7-Zip writes one). An
encoded header SHALL have exactly one folder, as 7-Zip requires; zero folders or more
than one SHALL raise `CorruptionError`. The folder's unpack size SHALL be checked
against the next-header size cap (`MAX_NEXT_HEADER_SIZE`) before decoding. The
decoded blob SHALL start with `kHeader`: a blob that is itself `kEncodedHeader`, empty,
or a bare `kEnd` SHALL raise `CorruptionError` and SHALL NOT open as an archive with no
members. For a header-encrypted archive these failures count as a rejected password
(`EncryptionError`), because a wrong key cannot be told from damaged bytes.

#### Scenario: encoded-header decode bound matrix

| Case | Expected |
| --- | --- |
| COPY encoded header whose packed bytes are that same header | `CorruptionError` at open; no hang |
| Encoded-header folder claims an unpack size past the next-header cap | `CorruptionError` before decoding |
| Encoded header with zero folders, or with two folders that together hold a valid plain header | `CorruptionError` at open |
| Unencrypted encoded header that decodes to nothing, or to a bare `kEnd` | `CorruptionError` at open; never an empty archive |
| Legitimate single-layer encoded header (including header-encrypted) | Decode once; parse the resulting plain HEADER |

### Requirement: 7z anti-items are MemberType.ANTI

7z `FILES_INFO` ANTI-bit entries SHALL be exposed as `MemberType.ANTI`
(`is_anti`, not `is_file`). `open`/`read` SHALL raise `ArchiveyUsageError`;
`stream_members` SHALL yield `None`. Extraction follows `safe-extraction` anti
rules. This replaces empty-payload `FILE` anti opens.

#### Scenario: 7z anti matrix

| Case | Expected |
| --- | --- |
| ANTI-bit entry in member list | `type == MemberType.ANTI`; `is_anti`; not `is_file` |
| `open`/`read` anti member | `ArchiveyUsageError` |
| `stream_members` anti member | Stream `None` |
| Content then later anti same path | Content `is_current` false; anti `is_anti` and `is_current` true |

### Requirement: Decode folder coder chains through compressed-streams

The system SHALL decode each folder by composing shared `compressed-streams`
backends in decoding order. A coder list such as `AES -> LZMA2` decrypts, then
decompresses. Files in a folder are yielded by reading exactly `member.size`
bytes in archive order from the decompressed folder stream. Per-member CRC32
values SHALL appear in `hashes["crc32"]` and SHALL be verified by the shared
verification stage as data is read.

| 7z codec | Method ID | Backend | Availability |
| --- | --- | --- | --- |
| STORED | `0x00` | pass-through | core |
| LZMA1 / LZMA2 | `0x030101` / `0x21` | `lzma` `FORMAT_RAW` | core |
| Delta | `0x03` | `lzma.FILTER_DELTA` | core |
| BCJ x86/ARM/ARMT/PPC/SPARC/IA64 | `0x04`-`0x09`, `0x03030103`... | `lzma` BCJ filters | core |
| BCJ ARM64 | `0x0A` | archivey's own decoder (pure Python) | core |
| BCJ RISC-V | `0x0B` | archivey's own decoder (pure Python) | core |
| Deflate | `0x040108` | raw `zlib` | core |
| BZip2 | `0x040202` | `bz2` | core |
| Zstd | `0x04f71101` | stdlib `compression.zstd` / `backports.zstd` | core on 3.14+; otherwise `[recommended]` |
| Brotli | `0x04f71102` | `brotli` | `[recommended]` |
| LZ4 | `0x04f71104` | `lz4` frame decoder (same backend as standalone / `.tar.lz4`) | `[recommended]` |
| PPMd (var.H) | `0x030401` | `pyppmd` | `[recommended]` |
| Deflate64 | `0x040109` | `inflate64` | `[recommended]` |
| AES-256 / SHA-256 | `0x06f10701` | crypto backend | `[recommended]` |
| BCJ2 | `0x0303011B` | archivey's own decoder (pure Python) | core |

The `[recommended]` extra SHALL provide PPMd, Deflate64, Zstd on Python versions without
stdlib zstd, Brotli, LZ4, and AES support in one install.

LZMA1+BCJ folders SHALL NOT be decoded via a single combined `lzma` `FORMAT_RAW`
filter chain: liblzma can silently truncate the final BCJ look-ahead bytes when
LZMA1 lacks an end-of-stream marker. The reader MUST stage LZMA1 (and any non-BCJ
`lzma` filters such as Delta) through stdlib `lzma`, then apply each BCJ stage
separately. LZMA2+BCJ remains a single stdlib filter chain.

A folder SHALL be decoded when its coder graph is a **tree**: exactly one coder
output is left unbound (the folder's output), every other output feeds exactly one
input, every input is either bound or a packed stream, and no coder feeds itself.
Each input is decoded as its own branch — a linear chain planned by the rules
above, ending at one packed stream — so a four-input BCJ2 coder over four
branches, each with its own AES coder when the folder is encrypted, is one tree.
Every packed stream SHALL be read through its own view of the archive, with its
own position. A graph that cannot be a valid folder SHALL raise `CorruptionError`:
an input that is neither bound nor packed, an output bound to two inputs, or a
cycle. A valid graph the reader does not run SHALL raise `UnsupportedFeatureError`:
more than one unbound output, or a multi-input coder other than BCJ2. A branch's
coders SHALL be planned with that branch's own sizes, so a coder's input length is
the output length of the coder before it in the same branch.

A folder SHALL hold at most 64 coders and at most 64 coder in-streams and
out-streams, the limits 7-Zip applies (`k_Scan_NumCoders_MAX` and
`k_Scan_NumCodersStreams_in_Folder_MAX` in 7-Zip's `7zIn.cpp`). A larger folder SHALL
raise `UnsupportedFeatureError` at header parse, as 7-Zip reports it unsupported.

An LZMA1 or LZMA2 coder SHALL share a liblzma raw chain only with the Delta and BCJ
filters decoded after it, ARM64 and RISC-V excepted: stdlib `lzma` does not build
those filters, so ARM64 or RISC-V, and every filter decoded after it in its run, SHALL
be decoded as its own stage. An ARM64 coder whose start offset is not a multiple of 4,
or a RISC-V coder whose start offset is not a multiple of 2, SHALL raise
`UnsupportedFeatureError` when the folder is planned, as 7-Zip refuses it. A filter decoded before any LZMA1/LZMA2 coder, and a second LZMA1/LZMA2 coder
in the same run, SHALL be decoded as its own stage, because a liblzma raw chain must
end, in encode order, in its only LZMA1/LZMA2 filter.

Every decoder of a folder runs at once: the stages of a chain are stacked streams, and
a BCJ2 folder's branches run side by side. When a folder has more than one decoder
that declares memory (LZMA dictionary sizes, PPMd memory sizes, and the window of a zstd
frame read directly from a pack stream), their sum SHALL be
checked against `DecoderLimits.max_decoder_memory` before any of them is built, and
exceeding it SHALL raise `ResourceLimitError`.

A coder whose codec ends its own stream (LZMA2, Deflate, Deflate64, BZip2, Zstd, LZ4
and Brotli) that decodes more bytes than its declared unpack size SHALL raise
`CorruptionError`, as 7-Zip reports a data error. In an encrypted folder the password
check can decode the folder before the caller's read does; when it meets the surplus
there, the raised error SHALL be `EncryptionError` ("wrong password or corrupt"), with
the surplus `CorruptionError` in its cause chain, as for any damage the check decodes.
The check SHALL count the coder's decoded output, so AES padding in the coder's input
is not surplus, and the output of concatenated Zstd or LZ4 frames in one coder counts
together. The check SHALL ask the decoder for at most one
byte of output past the declared size, and SHALL NOT decode the folder a second time.
The decoder MAY read the rest of the coder's packed input to produce that byte (a tail
of streams that decode to nothing), so the check's input cost is bounded by the coder's
packed size, the same bound as decoding the folder. A decoder error on that one byte
is not surplus output, except input left after the stream's end (below). LZMA1 and PPMd
coders, which 7-Zip writes without an end marker, SHALL stop at their declared size
and decode nothing past it; the check's read past the size is where they report input
left after that size.

A coder's data SHALL be one stream, as 7-Zip reads it: the decoder SHALL end at the
first stream's end and SHALL NOT decode a further stream after it as output. Any byte
of the coder's input after that end, a zero byte included, and a further stream there,
SHALL raise `CorruptionError` once the output before it is read, whatever the unpack
size and CRC count, as 7-Zip 23.01 reports a data error ("Data Error", or "There are
some data after the end of the payload data"). The exception is Zstd and LZ4, whose
decoders read concatenated frames as one stream: a further frame is output that counts
against the unpack size (below), and only bytes after the last frame that start no
frame SHALL raise. rapidgzip on a Deflate coder is the other exception
(`compressed-streams`): a second Deflate stream long enough to hold a resume point, with
an unpack size and CRC that cover both, reads as both. The coder's input is its declared input
size (its pack size, or the size the coder before it declares), so AES padding past it
is not such a byte. An LZMA1 or PPMd coder ends at its declared size: its input SHALL
end there too, or after an end marker right at that size, and a declared size short of
the data the stream holds SHALL raise `CorruptionError`, not `TruncatedError`, since
the input is too long rather than short. One zero byte after an LZMA1 stream without an
end marker reads: 7-Zip's encoder sometimes flushes it past the decoder's last read.
What cannot be told from a valid stream is a declared size that cuts off only zero
bytes of LZMA1 data, or the last few symbols of PPMd data where pyppmd's end flag has
already risen: there the hidden data is zeros, or a few bits. Under the rapidgzip
accelerator, a Deflate or BZip2 coder SHALL hand over to the standard-library decoder
where a further stream starts, so the verdict is the standard library's.

#### Scenario: coder-chain matrix

| Case | Expected |
| --- | --- |
| BCJ + LZMA2 folder | Shared `lzma` raw filter chain returns original bytes |
| BCJ + LZMA1 folder | Staged LZMA1 then a staged liblzma BCJ returns original bytes |
| ARM64 + LZMA2 folder (7-Zip 23's default for an AArch64 executable), with or without a start offset | LZMA2 chain, then a staged ARM64 filter, returns original bytes |
| RISC-V + LZMA2 folder written by 7-Zip 24+ (`-mf=RISCV`), with or without a start offset | LZMA2 chain, then a staged RISC-V filter, returns original bytes; the member CRC32 verifies |
| RISC-V coder with an odd start offset | `UnsupportedFeatureError` when the folder is planned |
| Member with stored CRC32 | Terminal verification raises `CorruptionError` on mismatch |
| PPMd without `pyppmd` | `PackageNotInstalledError` names `pyppmd` and the `[recommended]` extra |
| AES + LZMA2 folder | Crypto stage decrypts before LZMA2 decompression |
| LZ4 folder (`0x04f71104`) with `lz4` installed | Shared `Codec.LZ4` returns original bytes |
| LZ4 folder without `lz4` | `PackageNotInstalledError` names `lz4` and the `[recommended]` extra |
| 7-Zip `-mx9` folder: `BCJ2` over `LZMA2`, `LZMA`, `LZMA` and one raw pack stream | Four branches over four packed streams return the original bytes |
| Same folder, encrypted: an AES coder on each of the four branches | Each branch decrypts, then decodes; the original bytes return |
| Coder output bound to two inputs, or a coder bound to itself | `CorruptionError`; no output bytes |
| Same malformed graph in an encrypted folder | `CorruptionError` on the first attempt; not reported as a wrong password |
| BCJ2 folder whose `main` branch is `AES` then `BZip2` | The BZip2 stage's input length is the AES coder's output, not a sibling branch's |
| Folder of 64 Delta coders | Decodes; no `RecursionError` |
| Folder of 65 coders, or a coder graph with more than 64 in-streams | `UnsupportedFeatureError` at open |
| Delta, BCJ or LZMA2 decoded before LZMA2 (`7z a -m0=LZMA2 -m1=BCJ`) | Staged separately; the original bytes return |
| LZMA2, Copy, LZMA2 whose dictionaries each fit `max_decoder_memory` but together do not | `ResourceLimitError` before a decoder is built |
| LZMA2 coder decodes past the folder's declared unpack size | `CorruptionError` |
| Deflate, Deflate64, BZip2, Zstd, LZ4 or Brotli coder decodes past its declared unpack size, also before a Delta or BCJ filter or in a BCJ2 branch | `CorruptionError` |
| Same, behind AES, in a folder the password check decodes whole (one inside its 64 KiB prefix) | `EncryptionError`, with the surplus `CorruptionError` in its cause chain |
| Same, behind AES, in a folder the password check does not decode whole | `CorruptionError` |
| LZMA1 or PPMd coder whose data decodes 1000 bytes past its declared unpack size | `CorruptionError`, not `TruncatedError` (`7z t`: Data Error) |
| LZMA1 or PPMd coder with junk, zero bytes or a further stream after its data | `CorruptionError` (`7z t`: Data Error) |
| AES then Deflate, Deflate64, BZip2, Zstd, LZ4 or Brotli, decrypted input ending in AES padding | Original bytes return; the padding is not surplus |
| Two Zstd frames or LZ4 frames in one coder | Original bytes when the unpack size counts both; `CorruptionError` when it stops after the first |
| Two BZip2 or Deflate streams in one coder, whatever the unpack size and CRC count | `CorruptionError` (`7z t`: data after the end of the payload data) |
| BZip2, Deflate or Deflate64 coder with junk or zero bytes after its stream | `CorruptionError` (`7z t`: data after the end of the payload data) |
| Two LZMA (end-marked) or LZMA2 streams in one coder, whatever the unpack size counts | `CorruptionError` (`7z t`: Data Error) |
| LZMA (end-marked) or LZMA2 coder whose input has one more byte after the end marker, a zero too | `CorruptionError` (`7z t`: Data Error) |
| AES then LZMA or LZMA2, decrypted input ending in AES padding | Original bytes; the pad is past the coder's input size |
| LZMA1 coder without an end marker, with input after its data | `CorruptionError` (`7z t`: Data Error), except one zero byte |
| 7-Zip's own LZMA, LZMA:eos, LZMA2, PPMd, `-mhe=on`, solid, `-ms=off` and BCJ2 archives | Read clean |
| Two BZip2 streams under rapidgzip (`use_indexed_bzip2` `ON`), whatever the size and CRC count | `CorruptionError`, as with the accelerator off |
| Two Deflate streams under `use_rapidgzip=ON`, the unpack size covering the first only, or no resume point in the second | `CorruptionError`, as with the accelerator off |
| Two Deflate streams under `use_rapidgzip=ON`, a resume point in the second, the unpack size covering both | Decodes both streams |

### Requirement: Reject unsupported codecs without fallback

The system SHALL raise `UnsupportedFeatureError` naming the codec or method ID
when a folder uses a coder with no available backend. This includes newer
branch filters absent from installed liblzma, and unrecognized method IDs. The
reader MUST NOT return garbage and MUST NOT fall back to `py7zr` or another
third-party reader. PPMd and Deflate64 are optional-supported via
`[recommended]`, and multi-volume 7z is supported by volume joining.

#### Scenario: unsupported-codec matrix

| Case | Expected |
| --- | --- |
| Folder uses BCJ2 | Member is decoded, not rejected |
| Folder uses a multi-input coder other than BCJ2 | `UnsupportedFeatureError` names the method ID |
| Folder uses unknown method ID | `UnsupportedFeatureError` names the method ID |
| Folder uses PPMd with `pyppmd` installed | Member is decoded, not rejected |
| Folder uses LZMA1+BCJ | Member is decoded via a staged BCJ filter, not rejected |

### Requirement: Support multi-volume 7z by ordered concatenation

The system SHALL support split 7z sets (`name.7z.001`, `name.7z.002`, ..., and
SFX numbered parts `name.exe.001`, `name.exe.002`, ...) by
joining volumes in order into one logical byte stream and parsing that stream as
ordinary 7z. The SFX stub `name.exe` (no `.NNN` suffix) is not a volume sibling;
when it has no archive magic, `open_archive` SHALL follow it to the split first
volume beside it (`name.exe.001` or `name.7z.001`).
`open_archive()` SHALL accept either a path inside the set, with
sibling discovery in numeric order, or an explicit ordered source sequence. If a
volume is missing or the stream cannot be reconstructed, the system SHALL raise
`UnsupportedFeatureError` or a truncated/corrupt error, never a partial result.
A lone numbered part (`name.7z.001` / `name.exe.001` with no siblings) SHALL
raise `TruncatedError` naming the missing parts. A named part that is not on
disk itself SHALL raise `FileNotFoundError`, like any other missing path.

#### Scenario: volume matrix

| Case | Expected |
| --- | --- |
| Open `name.7z.001` with complete siblings | Volumes join in numeric order; listing and reads match a single-file archive |
| Open `name.exe.001` with complete `name.exe.00N` siblings | Same join; the stub `name.exe` is not a sibling |
| Open `name.7z.001` or `name.exe.001` with no siblings | `TruncatedError` names the missing parts |
| Open `name.7z.001` when that file does not exist | `FileNotFoundError`, not `TruncatedError` |
| Open stub-only `name.exe` beside `name.exe.001` or `name.7z.001` | Same join as opening the first volume |
| Open stub-only `name.exe` with `format=SEVEN_Z` beside `name.7z.001` | Same join |
| Open stub-only `name.exe` with `format=SEVEN_Z` beside `name.zip.001` | `ArchiveyUsageError` |
| Open an explicit ordered volume list | Sources concatenate and read as one archive |
| Missing or out-of-order volume | Error instead of partial or garbage output |

### Requirement: Decrypt AES-encrypted 7z with archive-reading passwords

The system SHALL read AES-256-encrypted 7z folders and header-encrypted archives
when a valid password and crypto backend are available. Header encryption SHALL
decrypt the end header before listing; without a password the system raises
`EncryptionError`, and with no crypto backend it raises `PackageNotInstalledError`.
Any archive or folder encryption SHALL set `ArchiveInfo.is_encrypted` to `True`.

Passwords SHALL use the `archive-reading` candidate model: known-good successes
for this reader, remaining static candidates, then provider requests. Header
requests use `member is None`; folder/member requests identify the member being
decrypted where possible. Members in different encrypted folders MAY use different
passwords in one open or one `stream_members()` pass. Key derivation SHALL use the
7z SHA-256 scheme (UTF-16LE password, salt, `1 << NumCyclesPower` rounds with the
documented `0x3F` no-hash sentinel) via a 7z-local helper that feeds `AesParams` into
the shared crypto stage — not a generic crypto-surface KDF. `NumCyclesPower` values
other than `0x3F` SHALL be accepted only when `≤ 24`; values 25–62 SHALL raise
`UnsupportedFeatureError` (matching 7-Zip’s decoder clamp), not
`EncryptionError`.

Because 7z AES carries no password check value in the format, wrong-password detection
relies on integrity anchors and codec rejection, applied as the `archive-reading`
confirmation ladder. 7z fills that ladder's cheap-key-check rung in
`sevenzip-aes-tail-key-check`; this requirement starts at the anchor. The reader SHALL
cache derived keys by `(password, salt, cycles)` and try known-good passwords first.

**Integrity anchor.** Confirmation SHALL stop at the earliest sufficient anchor rather
than decoding the folder: per-member CRCs are consulted in substream order, and the plan
terminates once CRC-verified bytes reach 4. A folder digest SHALL be used only when it is
the earliest such anchor — a folder carrying both a digest and per-member CRCs SHALL
anchor on the members. If that anchor sits past `PASSWORD_CONFIRM_PREFIX_BYTES` and the chain
has a rejecting codec, the plan SHALL NOT walk it (codec rejection settles a wrong
key). If the chain has no rejecting codec, the plan SHALL walk it anyway.

**Codec rejection.** A chain rejects iff a decompressor measured to fail on random AES
output decodes the AES output, directly or through other coders. A decompressor that
decodes before the AES coder sees the same bytes whatever the key and does not count. Measured as rejecting: LZMA1, LZMA2, BZip2, Deflate, Deflate64,
Zstandard and LZ4. Measured as non-rejecting: Brotli (about one random input in twenty
decodes a full 64 KiB prefix) and PPMd. Filters (Delta, BCJ) never reject —
`MethodKind.LZMA_FAMILY` includes Delta and is the wrong predicate. A codec not measured
is non-rejecting. A rejecting chain with no reachable anchor decodes a bounded plaintext prefix
and treats a survivor as `INCONCLUSIVE`. A non-rejecting chain follows the
`archive-reading` rule: walk a late CRC; with no CRC at all, do not invent an
unbounded decode.

When an encrypted folder has **no** folder digest and a member has **no** CRC
(format-legal for store/copy), the system SHALL still return decoded bytes (best-effort,
matching 7-Zip) and SHALL emit `DIGEST_UNVERIFIABLE` with
`DigestContext.reason="no_integrity_anchor"` — it MUST NOT imply the decryption was
authenticated. The reader SHALL NOT decode such a folder merely to discover that nothing
can be checked — several candidates do not change that. After decoding a
header-encrypted `kEncodedHeader`, a parsed result with zero file records SHALL raise
`EncryptionError` (legitimate writers never encrypt an empty header) so a wrong password
cannot open as a silent empty listing.

#### Scenario: encryption matrix

| Case | Expected |
| --- | --- |
| Header-encrypted archive, no password/provider result | `EncryptionError` before listing |
| Header-encrypted archive, valid password + crypto | Header is decrypted natively; members list; `is_encrypted` true |
| Encrypted folders with different passwords | Each folder uses its matching candidate in random access or one streaming pass |
| Sole wrong password, integrity anchor present (folder digest and/or member CRC) or compressed codec rejects garbage | `EncryptionError`/`CorruptionError`; no incorrect data handed to the caller as success |
| Header-encrypted archive, wrong password decodes to zero file records | `EncryptionError` (never a silent empty listing) |
| Encrypted store/copy member, no folder digest, no member CRC, any password | Bytes returned; `DIGEST_UNVERIFIABLE` (`reason="no_integrity_anchor"`) emitted |
| `NumCyclesPower` 25–62 | `UnsupportedFeatureError` (not remapped to wrong-password) |
| Repeated salt/cycles/password | Derived key cache avoids repeated key derivation |
| Sole wrong password, LZMA2, CRC at 200 MiB | `EncryptionError` at open (codec rejects in the prefix; no 200 MiB read) |
| Correct password, LZMA2, CRC at 200 MiB, `read(1)` then close | `INCONCLUSIVE`; `ENCRYPTED_MEMBER_UNVERIFIED` |
| Sole wrong password, store/copy, CRC at 200 MiB | Walk to the CRC; `EncryptionError` at open |
| Correct password, store/copy, CRC at 200 MiB, `read(1)` then close | No diagnostic (anchor confirmed) |
| Sole wrong password, store/copy, no CRC at all | Accepted at open; surfaces on the caller's read; `ENCRYPTED_MEMBER_UNVERIFIED` on an abandoned partial read |
| Store/copy, no CRC, two candidates | First candidate; `DIGEST_UNVERIFIABLE`; confirmation ≤ budget |
| Ambiguous candidates, store/copy folder, only CRC at folder end | Unbounded pass; the candidate matching the CRC wins |
| AES → Delta → Copy or AES → BCJ → Copy | Treated as non-rejecting (the filter does not reject random input) |
| Rejecting chain, packed input past 1 MiB before the prefix is decoded | Input capped at `PASSWORD_CONFIRM_MAX_INPUT_BYTES`; running out of it is `INCONCLUSIVE`, not a rejection |
| Solid folder, first member 4 KiB, folder 200 MiB | Confirmation decodes the first member only |
| Folder carrying both a folder digest and per-member CRCs | Anchors on the earliest member CRC, not the folder digest |
| LZMA2 decoded before AES, member CRC past the prefix, candidates `wrong` then `right` | Non-rejecting chain: the CRC is walked, `wrong` is rejected, `right` is used |

### Requirement: Stream solid folders with bounded memory

The system SHALL implement `stream_members()` as a pull stream: each folder is
decoded once, members are yielded in archive order as bytes become available, and
peak memory is bounded by decoder working set plus in-flight output. The reader
MUST NOT buffer an entire solid folder in memory or keep a growing decompressed
cache until close. Random `open()` for a member inside a solid folder MAY
re-decode from the folder start or use explicitly bounded/disk-backed retention.

#### Scenario: streaming and random access matrix

| Case | Expected |
| --- | --- |
| `stream_members()` over a solid 7z | Each folder decodes once; peak memory is not proportional to folder size |
| Random `open()` inside a multi-file folder | Backend decodes from folder start or uses bounded/disk-backed retention |
| Repeated random opens in one folder | Any acceleration obeys `archive-reading` bounded-storage rules |

### Requirement: Report 7z cost and member metadata

The system SHALL populate 7z metadata from the native header. `ArchiveInfo.is_solid`
is `True` when any folder packs more than one file, `CostReceipt.solid_block_count`
is the folder count, and non-solid archives report `AccessCost.DIRECT`. Each
member's parsed coder chain SHALL map to `tuple[CompressionMethod, ...]` in compress
order: pre-filters first, packing codec last. If a POSIX attribute block is absent,
`mode`, `uid`, and `gid` SHALL be `None`, never guessed defaults. The attribute word
holds a Unix mode when its high 16 bits hold a Unix file type (`S_IFMT` bits), as 7-Zip
reads it; a special file type (device, FIFO, socket, unknown) counts only with the
`0x8000` bit (FILE_ATTRIBUTE_UNIX_EXTENSION) set, because the Windows attribute
STRICTLY_SEQUENTIAL reads as `S_IFCHR`. `mode`, the type a mode gives (symlink,
directory, special file), `extra["special_file_type"]`, `create_system` and the slot
"Created" fills SHALL all use that one test.

#### Scenario: metadata matrix

| Case | Expected |
| --- | --- |
| Folder packs multiple files | `ArchiveInfo.is_solid` true; `solid_block_count` equals folder count |
| Every folder packs one file | `ArchiveInfo.is_solid` false; access cost is `DIRECT` |
| BCJ pre-filter followed by LZMA2 | `member.compression` is `(BCJ, LZMA2)`, not the decode order the folder stores |
| No POSIX attribute block | `member.mode`, `member.uid`, and `member.gid` are all `None` |
| "Created" stored, the attribute word holds a Unix mode (below) | `created is None`; `ctime` holds it (7-Zip on Linux and p7zip store `st_ctime`) |
| "Created" stored, no Unix mode (`0x8000` alone, Windows attributes above `0xFFFF`) | `created` holds it; `ctime is None` |
| "Created" out of range | Both `None`; `MEMBER_TIMESTAMP_INVALID` with `field` `ctime` when the word holds a Unix mode, else `created` |
| Unix mode `0x8000 \| 0x20 \| (0o100644 << 16)` | `mode == 0o644`; `create_system` is `UNIX` |
| ARCHIVE \| PINNED (`0x80020`), with or without `0x8000`, or ARCHIVE \| STRICTLY_SEQUENTIAL (`0x20000020`) | `mode is None`; type `FILE`; `create_system` is `WINDOWS_NTFS` |
| `0o120777 << 16` without `0x8000` | `mode == 0o777`; type `SYMLINK`, as 7-Zip lists it |
| `0o010644 << 16` (FIFO) without `0x8000` | `mode is None`; type `FILE`; no `special_file_type` |

### Requirement: Infer presented names for nameless 7z members

When the 7z `FILES_INFO` block omits the `NAME` property (every member's stored
filename is empty), the reader SHALL infer a presented `ArchiveMember.name` from
the archive source filename before `normalize_member_name`. `raw_name` SHALL
remain empty so the missing NAME channel is preserved.

Inference (aligned with single-file compressors via shared
`infer_member_name_from_archive`):

| Archive source | Presented name |
| --- | --- |
| Basename ends with `.7z` (case-insensitive), optionally followed by a numeric volume suffix such as `.001` | Strip `.7z` / `.7z.NNN`; use the remaining stem |
| The remaining stem is entirely dots and spaces (`...7z`) | Append `.uncompressed` instead; `.` and `..` are not member names |
| Other non-empty basename | Append `.uncompressed` (do not strip an arbitrary final suffix) |
| Anonymous stream (no archive filename) | `data` |

Every nameless member in the same archive SHALL receive the same inferred name
(duplicate names are allowed). The reader MUST NOT invent `_1` / `(1)` suffixes
at list time; destination collisions are an extraction/`OverwritePolicy` concern.

#### Scenario: nameless-member naming matrix

| Case | Expected |
| --- | --- |
| Open `github_14.7z` (no NAME property, one file) | One `FILE` member named `github_14`; `raw_name` empty |
| Open `github_14_multi.7z` (no NAME, two files) | Two `FILE` members both named `github_14_multi`; `raw_name` empty |
| Open `archive.7z.001` with no NAME | Stem is `archive` (volume suffix stripped with `.7z`) |
| Open `foo.bin` (no NAME, not a `.7z` name) | Member name `foo.bin.uncompressed` |
| Open `...7z` (no NAME) | Member name `...7z.uncompressed`; the stem `..` is not a name |
| Open nameless 7z from an anonymous stream | Member name `data` |
| Open a 7z that stores NAME normally | Stored names unchanged; no stem synthesis |

### Requirement: Decode BCJ branch filters through liblzma

The system SHALL decode every 7z BCJ branch filter (x86/ARM/ARMT/PPC/SPARC/IA64,
method IDs `0x04`-`0x09` and their long aliases) using liblzma's branch filters, in
core, for every folder shape. No optional package SHALL be required for BCJ.

A BCJ coder that sits inside an LZMA2 filter chain SHALL be folded into that chain.
A BCJ coder staged on its own — after LZMA1, after a non-LZMA codec, or alone —
SHALL run as a raw liblzma chain of that branch filter followed by `FILTER_LZMA2`,
with its input framed as LZMA2 *uncompressed* chunks; liblzma rejects a raw chain
whose only filter is a branch filter, and uncompressed chunks supply the required
trailing compression filter without compressing anything.

The coder's declared unpack size SHALL NOT be passed to the branch filter. It
determines only whether the stream finished, so a member of 2 GiB or more decodes
like any other, and a member whose length is not a whole number of the filter's
blocks SHALL return its trailing partial block.

LZMA1+BCJ folders SHALL still NOT be decoded via a single combined `lzma`
`FORMAT_RAW` filter chain: liblzma can silently truncate the final BCJ look-ahead
bytes when LZMA1 lacks an end-of-stream marker (BPO-21872). The reader MUST stage
LZMA1 (and any non-BCJ `lzma` filters such as Delta) through stdlib `lzma`, then
apply each BCJ stage separately. BCJ2 (`0x0303011B`) is not a branch filter of
this kind and does not go through liblzma; it is decoded by archivey's own
decoder.

#### Scenario: BCJ decode matrix

| Case | Expected |
| --- | --- |
| BCJ + LZMA2 folder | One shared `lzma` raw filter chain returns original bytes |
| 7-Zip CLI `-m0=BCJ -m1=LZMA` fixture | Staged LZMA1 then a staged BCJ returns original bytes; no silent truncation |
| py7zr `FILTER_X86`+`FILTER_LZMA` fixture | Round-trip bytes match |
| BCJ with PPMd, BZip2, Deflate or Copy | Codec stage then a staged BCJ returns original bytes |
| Any BCJ folder with `bcj` unimportable | Decodes normally; no `PackageNotInstalledError` |
| BCJ member of 2 GiB or more | Decodes; no `OverflowError` reaches the caller |
| IA64 member whose length is not a multiple of 16 | Trailing partial block returned; no `TruncatedError` |

### Requirement: A 7z folder is decoded at most once for its link targets

A 7z symlink's target is stored as the member's data, often in the middle of a solid
folder. This refines the folder-decode budget of "Stream solid folders with bounded
memory" for link targets. For its link targets, a 7z folder SHALL be decoded at most once
per reader, and not past the end of its last link member. The one exception is each pass
the caller abandons before the folder's last link, as the abandoned-pass bullet says. The
consumer's own reads are covered by the bullets below.

- Random-access listing (`members()`, `members_report()`) SHALL decode no more of the
  folder for link targets than the end of its last link member.
- A `stream_members()` pass, in either access mode, SHALL read link targets through its
  own folder decode, and a pass that reaches its end SHALL leave every link target it
  read set on the members it yielded. Per folder,
  the pass SHALL decode from the start to the later of the end of the consumer's reads and
  the end of the last link member it reads, and SHALL decode nothing more at EOF. This
  holds when the consumer reads no data, when a link is the last member with data in its
  folder, and when a link is alone in its folder.
- A pass the caller abandons SHALL keep the link bytes it has read and SHALL NOT set
  their targets. A later listing or pass SHALL resolve those links from the kept bytes
  and SHALL decode the folder only for the links the abandoned pass did not reach. A solid
  decode cannot resume, so when such a link exists the folder is decoded again from its
  start to the last of those links. The cost is per pass, not per reader: each abandoned
  pass that reaches a link no earlier pass reached pays that folder's prefix again, so
  the folder can be decoded once per such pass. A pass abandoned after the folder's last
  link costs nothing more.
- Which links a pass reads when the caller's selector excludes them is set by
  `archive-reading`, "Bounded-memory sequential streaming via stream_members".
- With `read_link_targets=False`, listing and a pass advancing SHALL decode nothing for
  link targets. `extract_all` still reads the targets of the links it accepts. It always
  drives a pass, in both access modes, so it SHALL read them through that pass's own
  folder decoder, within the streaming bullet's bound, counting only accepted links.
  `open()` following a link is an ordinary member read, which MAY re-decode from the folder
  start as "Stream solid folders with bounded memory" allows.

#### Scenario: 7z link-target decode matrix

| Case | Expected |
| --- | --- |
| `members()` on a solid 7z with links before, between and after its file members | Decoded bytes equal each folder's last-link end offset, not the sum of every link's end offset |
| Streaming pass over the same 7z, reading every stream | Every link target resolved; decoded bytes equal the folder sizes, each folder decoded once |
| Streaming pass over the same 7z, reading no stream | Every link target resolved; decoded bytes equal each folder's last-link end offset |
| Random-access pass over the same 7z, no `members()` call, reading every stream or none | As the two streaming rows: every link target resolved on the yielded members, same decoded bytes |
| Random-access pass over the same 7z reading no stream, abandoned after the last link, then `members()` | Every link target resolved; decoded bytes equal the folder's last-link end offset, nothing decoded by `members()` |
| Random-access pass over the same 7z, abandoned after the second of three links, then `members()` | Every link target resolved; decoded bytes equal the second link's end offset plus the last link's end offset |
| Non-solid 7z (`-ms=off`) with links | Each link's own folder decoded once, in both modes |
| `read_link_targets=False`, `members()` then a pass reading no stream | No bytes decoded for link targets |
| `read_link_targets=False`, `extract_all()` accepting every member, either mode | Each folder decoded once; accepted links resolved; no second decode for their targets |

### Requirement: Decode BCJ2 folders

The system SHALL decode the BCJ2 coder (`0x0303011B`) on a core install, with no
optional package. The coder's four inputs, in coder order, are `main`, `call`, `jump`
and the range-coder stream `rc`. Each input SHALL be decoded as its own branch of the
folder's coder tree over its own packed stream.

The decoder SHALL produce exactly the coder's declared unpack size. It SHALL copy
`main` up to and including each branch candidate (`E8`, `E9`, or `0F 80`-`0F 8F`),
decode one range-coded bit for it, and on a 1 replace the next four output bytes with
the big-endian absolute target from `call` (for `E8`) or `jump` (otherwise),
converted to the little-endian relative form `target - (position + 4)`. No bit SHALL
be decoded for a candidate that is the last output byte.

A BCJ2 member's `compression` SHALL list the BCJ2 coder, then the coders of its
`main` branch, in the pack direction the `CompressionMethod` contract states. The
coders of the `call`, `jump` and `rc` branches SHALL NOT be listed.

A BCJ2 folder keeps no seek points. A random-access `open()` of a member decodes from
the folder start, and a sequential `stream_members()` pass decodes each folder once.
With `seekable_members=True` a BCJ2 member stream SHALL seek like any other 7z member:
a backward seek SHALL rewind all four inputs and decode again from the folder start.

The decoder SHALL raise `TruncatedError` when any input ends before the declared
output is produced, and `CorruptionError` when `main`, `call` or `jump` still holds
bytes after the last output byte. That check SHALL read at most one byte from each
input and SHALL NOT drain an input. It SHALL NOT allocate from a declared size: output
is produced in bounded blocks, and each input is read in bounded blocks.

The decoders of a BCJ2 folder's branches run at once, so the memory they declare (LZMA
dictionary sizes, PPMd memory sizes and zstd windows) SHALL be checked together against
`DecoderLimits.max_decoder_memory`, before any branch decoder is built, and exceeding it
SHALL raise `ResourceLimitError`. This is one case of the folder-wide sum in "Decode
folder coder chains through compressed-streams".

#### Scenario: BCJ2 decode matrix

| Case | Expected |
| --- | --- |
| 7-Zip `-mx9` archive of an x86-64 executable | Bytes match the original file; `member.compression` is `(BCJ2, LZMA2)`: the root, then its `main` branch in the pack direction, without the `call`, `jump` and `rc` side streams |
| Solid `-mx9` folder of several executables | Every member's bytes match; `stream_members()` decodes the folder once |
| Encrypted `-mx9` BCJ2 folder with the right password | Bytes match; the password check succeeds by folder decode and CRC |
| Encrypted BCJ2 folder with a wrong password | Rejected by the password check; no bytes returned |
| Output whose last byte is `E8`, or whose last byte is `0F` | Bytes match; no range-coder bit is read for the final opcode |
| Forced BCJ2 over non-executable data | Bytes match |
| `call` stream cut short | `TruncatedError` naming the stream |
| `main` longer than the output consumes | `CorruptionError`, after reading one byte past the end, not the rest of `main` |
| `open()` of the second member of a BCJ2 folder | Bytes match; decoded from the folder start |
| BCJ2 member opened with `seekable_members=True`, read, then seeked back | `seekable()` is True; the same bytes are read again |
| BCJ2 folder whose branch dictionaries each fit `max_decoder_memory` but together do not | `ResourceLimitError`; no branch decoder is built |
