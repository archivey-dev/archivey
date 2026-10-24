# Compressed Streams

## Purpose

Compressed streams are the shared pull-stream layer that turns compressed or
encrypted bytes into decompressed bytes. Format parsers compose this layer rather
than calling codec libraries directly, so codecs, AES decryption, exception
translation, dependency checks, digest verification, diagnostics, and compressed
byte accounting are implemented once.

## Related specs

| Spec | Relationship |
| --- | --- |
| `archive-data-model` | `CompressionMethod`, member hashes, and standalone raw-stream formats |
| `seekable-decompressor-streams` | Seekable/indexed behavior when seekability is requested |
| `error-handling` | Typed exception hierarchy and cause preservation |
| `diagnostics` | Digest, rewind, and seek-index diagnostic policy/retention |
| `backend-registry` | Codec availability and install hints for format support |

## Requirements

### Requirement: Format parsers use the shared decompressor-stream layer

The system SHALL expose codec decompression through one pull-based
`open_stream(...)`-style API returning `BinaryIO`/`ArchiveStream`. Single-file
compressors, native 7z, and future native ZIP SHALL compose shared stream
backends and MUST NOT directly import or drive codec libraries such as `pyppmd`,
`inflate64`, raw `lzma` filters, or the crypto backend.

#### Scenario: shared pipeline matrix

| Case | Expected |
| --- | --- |
| Native 7z decodes Delta + LZMA2 | Builds pipeline from shared stream backends |
| 7z and future ZIP need Deflate64 | Both use the same `inflate64`-backed stream backend |

### Requirement: open_stream is forward-only unless seekability is requested

The single-stream API SHALL default to a forward-only stream and accept
`seekable: bool = False`. Without `seekable=True`, the stream reports
`seekable() is False`, `seek()` raises `io.UnsupportedOperation`, `tell()` works,
and no seek index or accelerator is instantiated. With `seekable=True`, the
`seekable-decompressor-streams` contract SHALL apply. Concurrency is not a
parameter because the API returns one stream.

#### Scenario: seekability matrix

| Case | Expected |
| --- | --- |
| Open compressed source without `seekable=True` | Reads forward; `seekable()` false; `seek()` unsupported; no index |
| Open same source with `seekable=True` | Seekable behavior follows `seekable-decompressor-streams` |

### Requirement: open_stream peels the compression layer of a compressed tar

When `open_stream` is given a compressed tar — any `(TAR, <codec>)` pair whose codec is
not `UNCOMPRESSED`, such as `TAR_GZ`, `TAR_XZ` or `(TAR, LZIP)` — it SHALL open that
codec's stream and return the decompressed tar bytes, the same bytes the raw-stream
format of the same codec returns (`format="gz"` for a `.tar.gz`). This SHALL hold
whether auto-detection (`format=None`) found the pair or the caller passed it as
`format=`: how the format was chosen does not change what the file is. The codec SHALL
be the pair's stream half, the one the detector built the pair from, read through one
shared rule rather than a second table. This is what `gzip.open` does for a `.tar.gz`,
and the migration guide offers `open_stream` as its replacement.

Any other container — ZIP, 7z, RAR, ISO, DMG, or an uncompressed tar — has no
compression layer to remove. Detecting one SHALL raise `FormatDetectionError`; passing
one as `format=` SHALL raise `ArchiveyUsageError` (`backend-registry`). A directory path
is refused as `ArchiveyUsageError` before detection runs, and so is
`format=ArchiveFormat.DIRECTORY`.

#### Scenario: compressed tar through open_stream

| Case | Expected |
| --- | --- |
| `open_stream("a.tar.gz")` | Returns the tar bytes; equal to `open_stream("a.tar.gz", format="gz").read()` |
| `open_stream("a.tar.gz", format=ArchiveFormat.TAR_GZ)` or `format="tar.gz"` | The same tar bytes |
| `open_archive(open_stream(p, seekable=True))` for every compressed-tar corpus fixture | Same members (every compared field) and data as `open_archive(p)`; `format` is `TAR` |
| `open_archive(open_stream(p), streaming=True)` | Same `stream_members()` pass as `open_archive(p, streaming=True)` |
| `open_stream("a.tar")`, `open_stream("a.zip")` | `FormatDetectionError` |
| `open_stream(p, format=ArchiveFormat.TAR)`, `format=ArchiveFormat.ZIP` | `ArchiveyUsageError` |

### Requirement: One StreamCodec descriptor describes each codec

The system SHALL register each single-stream codec through one descriptor
containing its open function, exception translator, exact magic signatures,
optional content probe, file extensions, metadata extractor, and optional
dependency requirement (package/extra/tool, install hint, unlocked capability).
A codec SHALL be recognized by exact magic or content probe; there is no separate
weak-magic flag. Descriptor construction MUST NOT eagerly import optional codec
libraries.

A content probe SHALL receive the peeked prefix and MAY additionally receive the
**length of the source** when the caller knows it. The length is an optional input,
not a required one: a probe that does not need it SHALL be unaffected, and a probe that
uses it SHALL behave as before when it is absent — an unknown length means "cannot apply
the check", never "reject".

Two uses follow from those two inputs together, and neither requires a new one:

- **Framing.** A probe MAY test a declared framing length against the bytes the source can
  actually hold (see `format-detection`). Brotli tests a declared meta-block length against
  the source. **LZMA Alone** tests the weaker version of the same invariant: its 13-byte
  header is followed by range-coder payload, so a source no longer than the header cannot
  be an Alone stream — which was the whole of its measured real-world false-positive set,
  4 files in 40 000, each exactly 13 bytes.
- **Completeness.** When `source_length` does not exceed the prefix the probe was handed,
  the probe holds the whole source, and a decode that still wants more input after a
  **declared bounded output drain** SHALL be a rejection (see `format-detection`). This is
  available to every probe without any interface change, and it is why the sentence above
  no longer names zlib as a probe that has no use for the length: completeness applies to
  every probe that decodes.

A probe MUST NOT use the source length to read beyond the prefix it was given, **except**
through a bounded read facility the caller supplies explicitly for that purpose. Where such
a facility exists, it SHALL be optional, absent by default, and bounded in both offset
range (forward-only ceiling today: 1 MiB) and number of links walked; a probe that does not
take it SHALL behave exactly as it does today. This exception exists for the self-describing
block chain in `format-detection`, whose successor offsets frequently sit past a 4 KiB
prefix, and for the decode up to the first compressed block of that chain (within the
same 1 MiB reach). It does not license open-ended reading. A probe that decodes past its
sample SHALL first ask a second optional facility, `charge_decode(n)`, which the detector
backs with its decode allowance; when the answer is no, the probe keeps the verdict it
has.

Registering a standalone codec descriptor SHALL make detection, the single-file
reader, and availability reporting work without edits elsewhere.

#### Scenario: descriptor matrix

| Case | Expected |
| --- | --- |
| New standalone codec descriptor is registered | `detect_format()`, `SingleFileBackend`, and availability reporting pick it up |
| Import `archivey` with no optional codec packages | No third-party codec import and no `ImportError` |
| Probe that ignores the source length | Same verdict with the length supplied or omitted |
| Probe that uses it, length known | May reject a prefix whose declared framing exceeds the source |
| Probe that uses it, length unknown (non-seekable source longer than the peek) | Falls back to the prefix-only verdict; MUST NOT reject on that basis |
| LZMA Alone probe, known length ≤ 13 | Reject — a source that is only the header carries no range-coder payload |
| LZMA Alone probe, length unknown | Today's prefix-only verdict |
| Any probe, `source_length <= len(prefix)`, decode wants more input within the output drain | Reject — the whole source is visible and the stream does not terminate |
| Any probe, `source_length <= len(prefix)`, decode completes within the output drain | Accept |
| Probe offered no bounded read facility | Behaves exactly as today; prefix is its whole world |
| Probe given one, reads past the prefix within its bound | Permitted, for the block-chain walk and the Brotli decode to its first compressed block only |
| Probe given one, attempts an unbounded or unlimited-count read | Not permitted |

### Requirement: Each supported codec has a default backend

The system SHALL decompress supported codecs through these default backends:

| Codec | Default backend | Availability |
| --- | --- | --- |
| gzip | stdlib `gzip` | core |
| bzip2 | stdlib `bz2` | core |
| xz | native xz stream over stdlib `lzma` | core |
| LZMA Alone | stdlib `lzma` `FORMAT_ALONE` | core |
| LZMA1 / LZMA2 raw | stdlib `lzma` `FORMAT_RAW` | core |
| Delta, BCJ x86/ARM/ARMT/PPC/SPARC/IA64 | `lzma` raw filters | core |
| raw Deflate | stdlib `zlib` (`-15`) | core |
| Copy/STORED | pass-through | core |
| zstd | stdlib `compression.zstd` (3.14+) / `backports.zstd` (<3.14) | optional `[recommended]` before 3.14; core on 3.14+ |
| lz4 | `lz4` | optional `[recommended]` |
| Brotli | `brotli` | optional `[recommended]` |
| unix-compress `.Z` | native LZW `DecompressorStream` | core |
| PPMd var.H | `pyppmd` | optional `[recommended]` |
| Deflate64 | `inflate64` | optional `[recommended]` |
| AES-256 decrypt stage | wrapped crypto backend | optional `[recommended]` |

LZMA Alone SHALL be a distinct stream-codec descriptor from raw LZMA1/LZMA2
(`FORMAT_RAW` + properties). Alone is standalone (`StreamFormat.LZMA_ALONE`);
raw LZMA1/LZMA2 remain container-only.

#### Scenario: backend matrix

| Case | Expected |
| --- | --- |
| Default gzip stream | stdlib `gzip` |
| Default zstd on Python 3.14+ | stdlib `compression.zstd` |
| Default zstd on Python 3.11-3.13 with `backports.zstd` | `backports.zstd` using the same API |
| Standalone `.lzma` / Alone stream | `lzma` in `FORMAT_ALONE` mode |
| 7z folder LZMA2 raw stream | `lzma` in `FORMAT_RAW` mode |
| Default unix-compress `.Z` stream | native LZW stream; no `uncompresspy` import |
| Core-only install opens `.Z` | Succeeds without optional extras |

### Requirement: AES decryption is one wrapped pipeline stage

The system SHALL use `cryptography` from `[recommended]` through an internal wrapper
only. AES decryption SHALL be a stream stage composed before decompression, such
as AES then LZMA2 for an encrypted 7z folder. Format parsers MUST use the wrapper
instead of importing `cryptography` directly.

#### Scenario: crypto matrix

| Case | Expected |
| --- | --- |
| AES-encrypted 7z folder over LZMA2 with `cryptography` installed | Pipeline applies AES decrypt stage, then LZMA2 |
| Any format parser needs AES | Uses internal crypto abstraction |

### Requirement: Missing optional backends raise PackageNotInstalledError

The system SHALL raise `PackageNotInstalledError`, naming the missing package,
extra, or tool, when the selected codec/decrypt backend requires an unavailable
optional component.

#### Scenario: missing backend matrix

| Case | Expected |
| --- | --- |
| PPMd stream without `pyppmd` | `PackageNotInstalledError` naming `pyppmd` |
| AES stream without `cryptography` | `PackageNotInstalledError` naming the crypto backend |

### Requirement: Returned streams translate decompression errors

The system SHALL wrap backend streams so decompression failures surface as
Archivey exceptions: corrupt data as `CorruptionError`, unexpected end-of-input
as `TruncatedError`, and source seek requirements as the documented non-seekable
error. No raw backend exception SHALL escape. For zstd specifically,
`compression.zstd.ZstdError` SHALL map to `CorruptionError`, and its truncation
`EOFError` SHALL map to `TruncatedError`, except for a declared window the decoder
refuses: a window over `DecoderLimits.max_decoder_memory` SHALL raise
`ResourceLimitError`, and a window over libzstd's own ceiling, which no cap lifts, SHALL
raise `UnsupportedFeatureError`.

A liblzma failure that is not damage SHALL NOT surface as `CorruptionError`: a filter,
filter option or integrity check liblzma cannot decode SHALL raise
`UnsupportedFeatureError`, and a decoder memory cap refusing a declared dictionary
SHALL raise `ResourceLimitError`. These are not `ReadError`s, so a listing that meets
one fails rather than publishing the members before it as an incomplete report.

A source that ends before its first complete header is end-of-input too. For the
native xz, lzip and unix-compress decoders, a source that is empty, or holds only a
prefix of the format's magic bytes, SHALL raise `TruncatedError`; a short source whose
bytes cannot begin that format SHALL raise `CorruptionError`. Neither SHALL decode as a
valid empty stream.

#### Scenario: decompression error matrix

| Case | Expected |
| --- | --- |
| Corrupt compressed stream is read | `CorruptionError` with backend exception as `__cause__` |
| Compressed stream ends mid-data | `TruncatedError` |
| Zstd stream ends before end-of-frame marker | `TruncatedError`, not a silent short read |
| Zstd checksum frame is corrupted | `CorruptionError` with backend `ZstdError` as `__cause__` |
| Empty source, or only a prefix of the magic, to xz / lzip / unix-compress | `TruncatedError` |
| Source shorter than a header whose bytes are not the format's magic (xz / lzip / unix-compress) | `CorruptionError`, never `b""` |
| xz block header (valid CRC) names a filter liblzma does not know | `UnsupportedFeatureError`, not `CorruptionError` |
| xz / LZMA stream declares a dictionary above `DecoderLimits.max_decoder_memory` | `ResourceLimitError` |
| zstd frame declares a window above `DecoderLimits.max_decoder_memory` | `ResourceLimitError` |
| zstd frame declares a window above libzstd's ceiling (2^31 on a 64-bit build) | `UnsupportedFeatureError`, naming no cap to raise |

### Requirement: Content faults raise from read, never from close

This requirement scopes to the streams this layer owns: `DecompressorStream`
(and every codec `Decoder` behind it) and `VerifyingStream` / the fused
`MemberVerifier`. Other backends (the rapidgzip accelerator and its
`_GzipTruncationCheckStream`, and any third-party wrapper) are **out of scope**
here; they already surface content faults from `read` rather than `close`, and
retargeting them is deferred (see the rapidgzip follow-up). The wording below is
a standing rule for the in-scope streams, not a claim that every stream type in
the library has been audited to it. The one exception is the paragraph on accelerated
decoders and its three `Accelerated decoder` matrix rows, which are deliberately
normative for the rapidgzip decoder process, which decodes the DEFLATE family and bzip2.

Decode and verify streams SHALL raise content `TruncatedError` and
`CorruptionError` from `read` / `readall` (and from size/seek paths that would
otherwise report a false clean completion). `close()` MUST NOT raise those
content faults. `close()` MAY still propagate teardown failures (`OSError`,
translated inner-close errors).

Public bounded `read(n)` for `n ≥ 1` on `ArchiveStream` and
`VerifyingStream` / `MemberVerifier` SHALL be **full-count**: return exactly `n`
bytes unless a terminal boundary is reached (clean EOF, truncation-shaped short,
or a raised content error). Implementations SHALL issue one `inner.read(n)` and
forward a short non-empty return as terminal — they SHALL NOT retry it, which would
pull a decoder's deferred truncation into the call. The `n`-or-terminal guarantee
therefore rests on inners being fill-or-EOF (`DecompressorStream`, `ZipExtFile`,
`BytesIO`); an inner that may short mid-stream SHALL be read through a full-count
reader in front (at the source boundary, the `ArchiveSource`) rather than a gather loop
at the public surface. `read(0)` is a no-op, never EOF.

`VerifyingStream` / fused `MemberVerifier` SHALL verify digests (CRC and other
expected hashes) when a read **reaches the member's end**:

- **Size-declared** (`expected_size` set): the read that consumes the declared
  size is a verifying event (checksum and over-run). On digest mismatch or
  over-run it SHALL raise `CorruptionError` and return **no bytes** for that call
  (withhold the final chunk). When the data past the declared size fails to
  decode, that read SHALL raise the decoder's error as the verdict and return no
  bytes, even when the declared bytes match their checksum; the translator above
  the verifier types it as `CorruptionError`. On truncation-shaped EOF before the
  declared size, the first read that asks past available output returns the
  remaining prefix (short return); the next empty `read` raises `TruncatedError`.
- **Size-unknown**: every data chunk MAY be returned first; `CorruptionError`
  SHALL raise on the read that observes end-of-stream (typically the terminal
  empty `read`) — no mandatory one-chunk delayed-release lookahead.

On `readall` / `read(-1)`, the complete-stream read SHALL include the EOF verdict
and SHALL raise `CorruptionError` on mismatch (and `TruncatedError` on hash-less
short) so `read(); close()` cannot silently accept bad content. `finish_on_close`
SHALL close the inner and MUST NOT introduce a first content `TruncatedError` /
`CorruptionError` solely because the caller is closing.

The digests SHALL cover the bytes from position 0 to the hashing frontier: the end of
the reads that ran contiguously from position 0. A seek SHALL pause them only when a
read then skips bytes the digests have not seen, and SHALL never lose them for good:

- A seek to or behind the frontier SHALL keep the digests; later reads hash only
  the bytes past the frontier.
- A forward seek past the frontier whose inner stream would decode the skipped
  bytes anyway (its `nearest_resume_offset` for the target, asked as for a seek, is
  at or before the frontier) SHALL keep them: the next read SHALL read those bytes
  through the digests before its own. The seek itself SHALL decode nothing, so a
  later seek replaces its target and a stream closed with no read decodes nothing.
  A decode error in those bytes raises from that read, as it would after an inner
  whose own seek is lazy (the unrar pipe).
- A seek to or past the declared size SHALL keep the digests: concluding reads the
  skipped gap through them (below), so the seek itself reads nothing.
- A seek past the frontier that the inner can jump (a seek index, an accelerator, a
  stored or decrypt-only member, or an inner that cannot say) SHALL pause the
  digests once a read starts past the frontier: that read SHALL NOT move the
  frontier, and the length checks still run on it. A seek back to the frontier or
  behind it, then reads on to the end, SHALL complete the digests and check them; the
  read that brings the frontier to the end gives the digest verdict, and on a
  mismatch SHALL raise and withhold its bytes as a first reaching read does. This
  holds whether or not an earlier read already reached the end and gave the length
  verdict. A seek back to the frontier before any skipping read skips nothing.

The digests SHALL cover the first pass over each byte: bytes read again after a seek
back are not hashed again, so a re-decode that returns different bytes there (a crafted
seek index) is not caught by the digest.

A seek to position 0 SHALL re-arm every check: the digests start again and the read
frontier is cleared, so a read from position 0 to the end after any seeks is verified as
a first read is, for every format. Length / truncation / over-run checks SHALL remain
active and SHALL key off bytes actually read (not a seek-updated logical position
alone). When a seek jumps the logical position to/past the declared size without reading
the intervening bytes, concluding SHALL read that skipped gap (bounded by the declared
size, through the digests when the hashing frontier sits at its start) **and probe one
byte past the declared size**, reproducing the same length + over-run verdict a
sequential reaching read runs, rather than returning `b""` blind. So a past-EOF
`seek(declared_size)` on a **truncated** member MUST NOT silence `TruncatedError`, and
on an **over-long** member (one that decodes past its declared size) MUST NOT silence
`CorruptionError`.
Symmetrically, the same jump on a **complete** member MUST NOT fabricate either fault: a
seek to/past the declared size followed by `read` returns `b""` (standard `BinaryIO`
past-EOF semantics), and the `seek(member.size); read(1)` completeness idiom works. A
member already read to its declared size is length-verified, so a later seek past the
end concludes with no extra reads, unless a seek to 0 has re-armed the checks since.

Deliberate partial read then close before clean EOF remains quiet for
digest/length verification (abandon before verdict), modulo the length checks
that only fire when a read reaches EOF / asks past available.

On the complete-stream (`readall` / `read(-1)`) path the verifier SHALL drain
the inner to genuine EOF (`inner.read` returning `b""`) in **bounded** steps.
It MUST NOT assume a single `inner.read` returns the whole body: `inner` is an
arbitrary `BinaryIO` and MAY return fewer bytes than requested without being at
EOF (a short read). A single `inner.read(remaining)` therefore under-returns on
any short-reading inner and skips the EOF verdict — the drain loop fixes both.
When a decompressed size is declared, each step SHALL stay capped by the
remaining declared byte count so a corrupt/adversarial **over-long** stream is
stopped at the declared size (raising `CorruptionError`) and never slurped
unbounded into memory. This is why the sized path MUST NOT delegate to
`inner.read(-1)`; the size cap is a decompression-bomb bound, and the code
carrying it SHALL say so inline. The unsized path (no declared size, no cap)
MAY delegate to `inner.read(-1)` and then run the EOF verdict.

Once the public `ArchiveStream` has raised a content verdict (`CorruptionError` or
`TruncatedError`, or an error raised from one, such as ZipCrypto's password-or-damage
`EncryptionError`), every later `read` / `readinto` SHALL raise the same error object
again until the caller seeks, with the traceback it was first raised with rather than
one that grows per call. A seek SHALL succeed and restart the decode, so the prefix
reads again, as a truncated `DecompressorStream` does; the read that then reaches the
end SHALL raise the verdict again and return no bytes, whether or not a seek forfeited
the digest check (a seek to 0 re-arms it, and the damage found again raises the same
error object). A read reaches the end when it returns short or empty, is `read(-1)`, or
leaves the stream at or past the member's declared size; a full-length
`read(member.size)` after `seek(0)` is one. A caller who catches the verdict and seeks
back SHALL NOT read the damaged member as complete, clean data. `tell()`, `seekable()`
and `close()` are not gated by the verdict, and `close()` still does not raise it.
Opening the member again gives a fresh stream.

An accelerated decoder (the rapidgzip decoder process, for the DEFLATE family and bzip2)
SHALL leave `tell()` at the bytes the caller received after a read that raised,
by moving the decoder back to where that read started. When it cannot, its position
matches no byte the caller received, and the stream SHALL be given up rather than read
on from past a gap. That is the case when the caller's own source raised during a read or
a seek (the decoder took the fault for the end of its input), or when a read raised and
the decoder could not be moved back. The call that met the fault SHALL raise it: the
source's error, or the read's own. From then on, for the life of the stream, every
`read`, `readinto`, `seek` and `tell()` that reaches the decoder SHALL raise `ReadError`
with a message naming the cause. This narrows the paragraph above: after a verdict on a
given-up stream, a seek raises `ReadError` instead of restarting the decode, and
`tell()` raises too. `close()` SHALL still succeed. Opening the member again gives a
fresh stream.

#### Scenario: close vs read matrix

| Case | Expected |
| --- | --- |
| Truncated `DecompressorStream`; catch on empty `read`; then `close()` | `close()` succeeds |
| Truncated gzip stdlib path; error already observed on `read`; then `close()` | `close()` succeeds |
| Size-declared digest/CRC mismatch; `read(expected_size)` or chunk reaching size | Raises `CorruptionError`; that call returns no bytes (withholds) |
| Size-unknown digest/CRC mismatch; chunked `read(n)` | All content bytes delivered; terminal empty `read` raises `CorruptionError`; `close()` quiet |
| Digest/CRC mismatch; `read()` / `read(-1)` | Raises `CorruptionError` (complete-stream verdict); `close()` alone does not raise the digest fault |
| `read(); close()` with bad CRC | `read()` raises — must not succeed quietly |
| Hash-less short member; `read(-1)` | Raises `TruncatedError` |
| Hash-less short; chunked until empty | Available prefix delivered; terminal empty `read` raises `TruncatedError` |
| Exact-available `read(k)` then `close` (k == decompressed length < declared) | Quiet — did not ask past available |
| `read(-1)` over a short-reading inner (returns `< n`, not EOF) | Full body gathered via bounded drain; EOF verdict fires in that call |
| Bounded `read(n)` over a short-reading inner | Full-count: returns `n` or short only at terminal boundary |
| `read(-1)` over an over-long inner with a declared size | Stopped at the declared size; `CorruptionError`; inner not read unbounded past the cap |
| Seek off frontier then short of declared size | `TruncatedError` still raises on completing/empty read |
| Backward seek, then a read to the end over a digest mismatch | Checksum kept (bytes before the frontier not hashed twice); `CorruptionError` |
| Forward seek on a decompressing member (resume point at or before the frontier), then a read to the end over a digest mismatch | Gap read through the digests by the next read, not the seek; `CorruptionError` |
| Forward seek that jumps (stored member, seek index), then a read | Checksum paused by that read; length checks still run |
| Jump, a read past it (even to the end), then a seek back to the frontier and a read to the end over a digest mismatch | Checksum completed by the reads after the seek back; `CorruptionError` from the read that reaches the end, bytes withheld |
| Forward jump undone by a seek back to the frontier before any read | Checksum kept |
| Any seeks, then `seek(0)` and a read to the end over a digest mismatch | Checksum re-armed by the seek to 0; `CorruptionError` |
| Seek to/past declared size on a **complete** member, then `read` (incl. `seek(size); read(1)`) | Returns `b""`; no fabricated `TruncatedError`; the gap read checks the digest |
| Seek to/past declared size over a digest mismatch, then `read` | Concluding hashes the skipped gap; `CorruptionError` |
| Seek to/past declared size on a **truncated** member, then `read` | Concluding reads the skipped gap; `TruncatedError` with the true recoverable length |
| Seek to/past declared size on an **over-long** member, then `read` | Concluding reads the gap and probes past the declared size; `CorruptionError` (over-run), not a silent `b""` |
| Declared size met; the compressed bytes after it are damaged (a ZIP DEFLATE member declared empty, body not DEFLATE) | `CorruptionError` from the probe past the declared size, not a silent end |
| Partial read then `close` before clean EOF (verify) | No digest/length verdict |
| Inner teardown fails on `close` | Teardown error may propagate |
| `ArchiveStream` raised a content verdict; caller catches it, then `read()` | Raises the same error object again; no bytes returned |
| Same, then `seek(0)` and a bounded `read(n)` inside the member | Seek succeeds; the prefix bytes are returned |
| Same, then `seek(0)` and a read that reaches the end | Raises the same error object again; that call returns no bytes |
| Same, retried many times | Traceback stays the first one; it does not grow per call |
| Same, `tell()` or `close()` | Not gated; `close()` does not raise the verdict |
| Accelerated decoder; a read raises and the decoder moves back | `tell()` equals the bytes delivered; the stream stays usable |
| Accelerated decoder; a read raises and the decoder cannot be moved back | That read raises its own error; every later `read` / `readinto` / `seek` / `tell()` raises `ReadError` naming the cause; `close()` succeeds |
| Accelerated decoder; the caller's source raises during a read or a seek | That call raises the source's error; then as the row above, even if the source recovers |

### Requirement: Decompressed output digests are verified at clean EOF

The verification stage SHALL compute available expected digest algorithms
incrementally over decompressed bytes and raise `CorruptionError` for a
computable mismatch at clean EOF. A mismatch SHALL surface from the terminal read
after all data chunks have been delivered; a bytes-returning full read raises and
returns no bytes. Partial/random-access reads SHALL NOT produce a digest verdict.

Supported computable algorithms SHALL include `crc32` (via `zlib.crc32`), the
`hashlib.algorithms_available` set, and `blake2sp` (the 8-way parallel BLAKE2s tree
hash used by RAR5), computed via an internal zero-dependency hasher. A well-formed
member carrying only a `blake2sp` digest SHALL therefore be verified, not skipped. A
zlib stream's Adler-32 trailer is checked by the decompressor, not by a verifying
stream.

When an expected digest cannot be computed because the algorithm is genuinely unknown
or a backend is missing, the system SHALL emit `DIGEST_UNVERIFIABLE` with algorithm,
non-secret reason, and member identity when available. Diagnostic policy controls
collection, logging/callback delivery, member attachment, and escalation. An xz stream
whose header names a check liblzma cannot compute SHALL likewise emit
`DIGEST_UNVERIFIABLE` and keep decoding; a stream declaring no check (ID 0) SHALL NOT.

#### Scenario: digest matrix

| Case | Expected |
| --- | --- |
| Expected `blake2sp` on a well-formed RAR5 member | Computed and verified; mismatch raises `CorruptionError` |
| Expected digest under a genuinely-unknown algorithm name | `DIGEST_UNVERIFIABLE` counted/retained/logged; bytes still returned without that check |
| Full member read reaches EOF with computable digest mismatch | `CorruptionError` naming the algorithm |
| Chunked read reaches EOF with mismatch | All valid chunks delivered; following terminal read raises |
| Caller abandons stream before clean EOF | No digest verdict or mismatch exception |
| xz stream header names check ID 2 (liblzma cannot compute it) | `DIGEST_UNVERIFIABLE`; bytes still returned unverified |
| Unverifiable digest resolves to `RAISE` | `DiagnosticRaisedError` halts open/read |

### Requirement: Public ArchiveStream exposes bounded operation diagnostics

Every public `ArchiveStream` SHALL expose an immutable `diagnostics` snapshot. A
reader-owned stream shows an operation-filtered view over the reader collector; a
standalone codec stream owns a stream-lifetime collector. Serving the view SHALL
not retain another aggregate copy of each occurrence.

#### Scenario: ArchiveStream diagnostics matrix

| Case | Expected |
| --- | --- |
| Standalone codec stream emits index/rewind diagnostic | `stream.diagnostics` exposes exact counts and bounded details without a reader |
| Reader-owned member stream emits diagnostic | Stream view and reader aggregate share one retained occurrence |

### Requirement: Read-only stream wrappers share one internal base

Read-only wrappers in this layer SHALL share an internal base for the read-only
`BinaryIO` surface (`readable`, `writable`, `write`) and canonical `readinto` /
`readall` built from each wrapper's `read`. The public codec-stream path SHALL
return an `ArchiveStream` carrying stream-level presentation metadata; internal
`backend.open()` calls MAY return raw backend streams.

The seekable decompressor path SHALL be a single concrete stream class
(`DecompressorStream`) parameterized by a `Decoder` strategy, not a per-codec
subclass hierarchy. Every codec — forward-only and segmented alike — SHALL plug in
through **one** decoder protocol, which also owns seek-index discovery:

```python
@dataclass
class DecodeOut:
    data: bytes
    points: list[SeekPoint]  # absolute; empty for forward-only codecs

class Decoder(Protocol):
    def recreate(self, point: SeekPoint, inner: BinaryIO) -> Decoder: ...
    def feed(self, chunk: bytes) -> DecodeOut: ...
    def flush(self) -> DecodeOut: ...
    @property
    def finished(self) -> bool: ...
    @property
    def pending_error(self) -> BaseException | None: ...
    def clear_pending_error(self) -> None: ...
    # Default no-op; only index-bearing codecs (xz, lzip, future BGZF) override it.
    def build_index(
        self, inner: BinaryIO, last_known: SeekPoint
    ) -> tuple[list[SeekPoint], int | None]: ...
```

The stream — not the decoder — SHALL own the buffer, position, seek-point table,
and seek algorithm; it SHALL be format-agnostic, storing whatever `SeekPoint`s a
decoder emits. The `Decoder` SHALL choose seek-point placement (member/stream start
vs. post-realignment) and MAY perform progressive index enrichment during `feed`
using the `inner` it retained from `recreate`, restoring `inner`'s position itself.
Forward-only codecs SHALL emit empty `points` and inherit the no-op `build_index`.
Deferred truncation (e.g. unix-compress leftover bits, or a zlib, gzip, raw deflate or
xz stream cut short) SHALL surface through `pending_error`. A chunked `read(n)` SHALL
return the bytes decoded before it and raise it on the next empty read; a whole-stream
`read()` SHALL raise it without returning the prefix. The stream SHALL clear the
decoder's copy via `clear_pending_error` after raising (and on seek reset), and SHALL
record the error it raised. Until a seek, every later read with no buffered bytes
SHALL raise that same error, as SHALL a `seek(0, SEEK_END)` that has no size from an
index, and the decode SHALL publish no size. A seek SHALL restart the decoder from the
nearest seek point, which reaches the same error again at the same place. Adding a
codec SHALL add a `Decoder` and MUST NOT require a new stream subclass or a
`SegmentedDecompressorStream` layer.

#### Scenario: wrapper surface matrix

| Case | Expected |
| --- | --- |
| Any read-only stream wrapper is used | Shared base supplies read-only surface and `readinto` / `readall` |
| Public codec stream is opened | Returned object is an `ArchiveStream` with stream presentation metadata |

#### Scenario: decoder composition matrix

| Case | Expected |
| --- | --- |
| Forward-only codec (zlib, brotli, ppmd, bcj, deflate64) | Implements `recreate`/`feed`/`flush`/`finished`; emits empty `points`; inherits no-op `build_index`; `pending_error` set only when the input ends incompletely |
| Segmented boundary codec (lzip, xz stream start) | `feed` emits a `SeekPoint` at the boundary with the codec's own before/after placement; stream stores it |
| Progressive enrichment (xz block index) | `feed` scans the completed stream's footer via retained `inner` and emits block `SeekPoint`s (carrying resume `state`); restores `inner` position |
| One-shot / forward walk (xz, lzip backward scan; BGZF forward walk) | `build_index` returns points + size; stream drives it demand-driven per `seekable-decompressor-streams`; a size query does not run a scan that reads the payload (the BGZF walk, `index_reads_whole_source`) |
| Deferred truncation (unix-compress leftover bits; a DEFLATE-family or xz stream cut short) | `pending_error` set after `flush`; `read(n)` raises it on the next empty read, `read()` at once |
| Stream that already raised its deferred error | Later reads with no buffered bytes, and `seek(0, SEEK_END)` without an index size, raise the same error; the decode publishes no size; a seek re-decodes from the nearest seek point |
| A new codec is added | One `Decoder` added; no new stream subclass; no `SegmentedDecompressorStream` layer |

### Requirement: Backend dispatch is separable from opening

The system SHALL allow callers to resolve a codec/configuration's open function
and matching exception translator independently of opening a stream, so detection,
TAR, and 7z folder pipelines reuse the same backend selection.

#### Scenario: backend dispatch matrix

| Case | Expected |
| --- | --- |
| Open function is requested for a codec/configuration | Function and matching exception translator are returned |

### Requirement: Decompression streams count compressed bytes consumed

The decompression layer SHALL expose a monotonically increasing count of
compressed bytes consumed from the underlying source, such as
`input_bytes_consumed`. The counter SHALL be cheap, available for non-seekable
pipes, and MUST NOT perturb bytes read or decompressed.

Archive readers SHALL surface the running total for a single outer compressed
source as `compressed_bytes_consumed`, returning `None` when no single compressed
source exists (uncompressed container, directory). When solid/streamed member
streams share that outer source, the count is cumulative across the archive.

#### Scenario: compressed-byte counter matrix

| Case | Expected |
| --- | --- |
| `.gz` read incrementally from non-seekable source | Count increases monotonically and is readable mid-stream |
| Uncompressed container or directory | `compressed_bytes_consumed is None` |
| Count is observed repeatedly during extraction | Decompressed output is byte-for-byte unchanged |

### Requirement: An accelerator preserves the error contract of the path it replaces

When an optional accelerator backend (today rapidgzip, including its bundled bzip2
decoder) replaces a codec's default decoder, the accelerated stream SHALL raise the same
class of translated error, on the same inputs, as the non-accelerated path. An accelerator
SHALL NOT convert a decode failure into a successful empty read.

Specifically, a decoder that ends a stream having produced no output, without consuming its
input and without reaching a valid end-of-stream marker, SHALL raise rather than report
end-of-file. Where the accelerator cannot report enough to tell that apart from a genuine
empty stream (rapidgzip's bundled bzip2 decoder cannot), the first empty read before any
output SHALL be re-decoded by the non-accelerated decoder over a fresh view of the
source, which raises or confirms the empty stream. A seek before that first read does not
bypass the check: on such a stream the accelerator clamps the seek to 0. Accelerator mode
is a performance choice and SHALL NOT be observable as a difference in whether a corrupt
source raises, with one exception. Where every byte of output is covered by checks the
data itself declares, those checks give the verdict, and an accelerator MAY differ from
the standard-library decoder on a stream-boundary malformation they cannot see: for a
standalone multi-member gzip, a wrong ISIZE on a member other than the last, when every
member's CRC-32 is still checked.

A container member's compressed data (a ZIP member's, a 7z coder's declared input) is
one stream of its codec and nothing else. A byte of it the codec leaves after the
stream's end, a zero byte too, and a second stream there SHALL raise `CorruptionError`,
after the output before that end has been delivered, whatever the declared size and CRC
cover, with the accelerator on or off: an accelerator that reads on past the first
stream hands the read to the standard-library decoder there, which refuses it. 7-Zip
23.01 fails such a member ("There are some data after the end of the payload data", or
"Data Error"), and the bytes may hide a second payload. The exception is a ZIP Zstd
member and a 7z Zstd or LZ4 coder, whose concatenated frames are read as one stream, as
RFC 8878 defines Zstd data as one or more frames and the LZ4 frame format lets frames be
appended: a further frame is content that counts against the declared size and CRC, and
only bytes after the last frame that start no frame SHALL raise. A codec that stops at a
declared output size (LZMA1 without an end marker, PPMd) SHALL raise the same way when
its input goes on past that size; such a cut leaves input over, so it is not a
`TruncatedError`. A standalone compressed file keeps reporting the bytes after its
streams as `ARCHIVE_TRAILING_DATA` instead.

A wrong ISIZE on the last member of a one-member gzip is not among them, whatever follows
the member. The accelerator reads the output through a CRC-32 and finds the trailer as the
one place near the end of the file where that CRC-32 occurs: it looks from 72 bytes before
the end of the non-zero data to 12 bytes after it, and takes the file as ending with the
trailer only when the CRC-32 occurs there once, followed by the length and then by nothing
but zero padding. A forged copy of those eight bytes, whether appended after a wrong
trailer, overlapping it or reaching back into the compressed data, leaves the real CRC-32
as a second occurrence, so it does not stand in for the trailer. Not excluded: a copy more
than 56 bytes after the end of the real trailer, which needs rapidgzip to read past that
many bytes that are not a further member without an error; rapidgzip 0.16 raises on ten or
more. In a file of several members the CRC-32 of the whole output is not the last
member's, so it finds no trailer there. A further member that zlib confirms says only that
the file has several members, not that the last one is whole: rapidgzip ends a last member
cut right after its header with no error, at the end of the file. So the accelerator SHALL
also find the last member's trailer, the eight bytes that end the file but for zero
padding, and SHALL accept the file only when they hold the CRC-32 and the length mod 2**32
of the last that-many bytes of the output. A wrong ISIZE or a cut on the last member,
after any number of members before it and whatever its size, then gives the standard
library's error. An empty last member (bgzip's end-of-file member) counts when zlib
decodes it from a header in the 1 KiB before the end of the non-zero data, with only
zeros after it. That CRC-32 SHALL come from the running CRC-32 of the output, saved every
4 MiB of output, as `C(A + B) ^ crc32_combine(C(A), 0, len(B))` for the last `len(B)`
bytes `B`, with `C(A)` carried on from the checkpoint before it by a read-back from the
accelerator: at most four candidates, tried shortest first, each a read-back of at most
4 MiB, whatever the size of the last member or the length a forged trailer states. A
valid file of any size is so decided with no handover to the standard-library decoder.
Not excluded: a crafted cut whose last eight bytes are made the CRC-32 and length of the
end of the output, which takes choosing four bytes of the content. A last member of 4 GiB
or more of output does not match, as its length is wrapped, and is read by the
standard-library decoder, at the cost of a second decode.

When a seek short of the end has skipped output, there is no CRC-32 of the whole output,
and the last four bytes of the file stand in as the ISIZE of a file with no further
member. In a file with a further member, the last member's trailer SHALL still be checked
as above whatever the last four bytes say, and no candidate SHALL be accepted unchecked: a
CRC-32 kept from where reading resumed covers a candidate that starts after that point,
and for one that starts before it the skipped part is read back from the accelerator.
That read-back SHALL be bounded, at most 64 MiB of output in all; a candidate past it
hands the read to the standard-library decoder, which gives the right result at the cost
of a second decode.

#### Scenario: accelerator error parity

| Source | Accelerator `OFF` | Accelerator `AUTO` |
| --- | --- | --- |
| Valid bzip2 stream | Content | Content |
| Valid **empty** bzip2 stream | `b""` | `b""` |
| bzip2 source of 40 000 zero bytes | `CorruptionError` | `CorruptionError` — not `b""` |
| Zero-byte bzip2 source | `TruncatedError` | `TruncatedError` — not `b""` |
| Corrupt gzip source | `CorruptionError` | `CorruptionError` |

#### Scenario: the parity holds through the public reader

| Case | Expected |
| --- | --- |
| `open_archive(corrupt.bz2, seekable_members=True).read(member)` | Raises, matching `seekable_members=False` |
| A capability flag (`seekable_members`) | Never changes whether a corrupt source raises, except through the accelerator on the stream-boundary malformation listed above |

#### Scenario: a container member with input after its stream

| Member | Accelerator `OFF` | Accelerator `ON` |
| --- | --- | --- |
| Two DEFLATE or bzip2 streams; declared size and CRC cover both, or the first only | `CorruptionError` | `CorruptionError` |
| One DEFLATE or bzip2 stream, then junk or zero bytes | `CorruptionError` | `CorruptionError` |
| ZIP Zstd member with two frames; declared size and CRC cover both | Decodes both | — |
| ZIP Zstd member with two frames; declared size and CRC cover the first only, or junk after the last | `CorruptionError` | — |
| ZIP LZMA without an end marker, or 7z LZMA1, whose declared size is 1000 bytes short of its data | `CorruptionError` (not `TruncatedError`) | — |
| ZIP PPMd8 or 7z PPMd, then junk, or a declared size 1000 bytes short of its data | `CorruptionError` (not `TruncatedError`) | — |
| A `.bz2` file with junk after its stream | Content, and `ARCHIVE_TRAILING_DATA` | Content, and `ARCHIVE_TRAILING_DATA` |

### Requirement: Native decoders run where process_isolation puts them

The system SHALL decide where each native decoder runs from
`ArchiveyConfig.process_isolation`:

| Value | Runs in a child process | Runs in the caller's process |
| --- | --- | --- |
| `KNOWN_CRASHES` (default) | rapidgzip (every codec it decodes); `pyppmd` (every PPMd member) | every other decoder |
| `NATIVE_DECODERS` | every native decoder: `zlib`, `bz2`, `lzma` (all formats and filter chains), zstd, `lz4` (frame and block), `brotli`, `inflate64`, `pyppmd`, rapidgzip | nothing that decodes compressed data |
| `NONE` | nothing | every decoder |

The setting SHALL cover every decode of archive data the library runs, not only member
reads: format detection's content probes, password confirmation, the decodes a seek
index is built from and the checks that end a stream. The native code that does not
decode compressed data SHALL stay in the caller's process under every value: checksums
(`zlib.crc32`, `hashlib`) and AES decryption through `cryptography`. The external
programs (`unrar`, `unar`, `7z`) are separate processes under every value.

#### Scenario: where decoding runs

| Case | Expected |
| --- | --- |
| `.tar.xz` read under `NATIVE_DECODERS` | Same bytes as `KNOWN_CRASHES`; `lzma` decodes in a child process |
| `.br` stream under `NATIVE_DECODERS` on a free-threaded build | Same bytes; `brotli` never imported by the caller's process, the GIL stays disabled |
| `detect_format` on a `.zz` stream under `NATIVE_DECODERS` | The zlib content probe decodes in a child process |
| A WinZip AES member under `NATIVE_DECODERS` | AES decrypts in the caller's process; the codec after it decodes in a child |

### Requirement: Each open decoder has a child process of its own

A child process SHALL run one decoder at a time, and an open decoder SHALL have a child
of its own, so a crash is charged to the one decoder whose request was in flight and
threads decode in parallel. A child SHALL import only the standard library and the
library of the codec it is asked for, and MUST NOT import `archivey`; importing
`archivey` SHALL NOT import any codec library the caller's process would not import
without the setting. Under `NATIVE_DECODERS` the caller's process MUST NOT import
`pyppmd`, `inflate64`, `brotli` or `rapidgzip`.

A child MAY be kept and reused for a later decoder only after a clean finish: the
decoder ended with no error from the child and was closed normally, so a run of small
members does not start a process per member. A child MUST NOT be reused after it
reported an error, died, or was interrupted part-way through a request or its reply. A
PPMd child MUST NOT be reused after a member that did not decode to its declared end,
whose check value did not match, or that was refused, nor after the decoder sent the
one-symbol decode that stops a worker waiting on input, since pyppmd can corrupt its
memory there without crashing at once. A child SHALL serve at most a fixed number of
decoders (64) before it is ended.

A crash or an error in a child that served earlier decoders MUST NOT be charged to the
decoder at once, since an earlier member may have left damage that surfaces only now:
the decoder SHALL re-run what it sent in a fresh child, once, and only a crash or error
there SHALL be its verdict. A decoder SHALL keep what it sent while in a reused child up
to 1 MiB of input, and past that SHALL move to a fresh child at once, so a re-run is
always possible. Output already returned to the caller SHALL be checked during the
re-run: when the fresh child's output for those requests differs, the call SHALL raise
`ReadError`, which is not a verdict on the data. A PPMd read abandoned before the
member's end SHALL retire its child, since closing it sends the one-symbol decode. Idle
children SHALL be ended when the interpreter exits, MUST NOT outlive it, and a process
created by `fork` MUST NOT use its parent's children: idle ones are dropped, closing an
inherited decoder leaves the parent's child alone, and a call on one SHALL raise
`ArchiveyUsageError`.

#### Scenario: child per decoder and reuse

| Case | Expected |
| --- | --- |
| Two members of one archive read on two threads under `NATIVE_DECODERS` | Two children, decoding at the same time |
| A ZIP of 1,000 small deflate members read one after another under `NATIVE_DECODERS` | Children reused; far fewer than 1,000 started |
| A two-stream `.xz`, two-member gzip or two-frame zstd or lz4 file read under `NATIVE_DECODERS`, every finished decoder kept referenced | The first stream's child is back in the pool before the next stream's decoder takes one; at most one child is leased at a time |
| 1,000 small valid PPMd members read one after another under `KNOWN_CRASHES` | Each in a child process; children reused |
| A PPMd member that ends early (corrupt or cut) | Child process; that child is not reused |
| Member A leaves its reused child damaged without crashing; member B's decode then crashes in that child | B re-runs in a fresh child and reads correctly; nothing is charged to B |
| A corrupt member decoded in a reused child | Its error comes from the re-run in a fresh child, the same error as in-process |
| A reused child returned wrong bytes for part of a member, then crashed | The re-run's output differs from what was returned: `ReadError`, nothing charged to the data |
| A PPMd member whose read is stopped part-way, then closed | That child is not reused |

### Requirement: A decoder child's end and errors keep the in-process verdicts

A decoder child that ends during a request SHALL be reported by how it ended, and every
later call on that decoder SHALL raise the same error: a fault signal (or its Windows
status) SHALL raise `CorruptionError`; SIGKILL SHALL raise `ResourceUnavailableError`; any other
end SHALL raise `ReadError`, which is not a verdict on the data. An exception the
decoder raises in the child SHALL reach the codec's translator as the same type it
would raise in-process, so a corrupt or truncated stream raises the same archivey
error under every value.

#### Scenario: child ends and errors

| Case | Expected |
| --- | --- |
| The decoder child crashes / is killed by SIGKILL / by SIGTERM during a read | `CorruptionError` / `ResourceUnavailableError` / `ReadError`; every later read raises it again |
| A corrupt deflate stream under `NATIVE_DECODERS` | `CorruptionError`, the same message as `KNOWN_CRASHES`; that child is not reused |

### Requirement: Start failures, NONE and time limits

Under `NATIVE_DECODERS`, and for PPMd and rapidgzip `ON` under `KNOWN_CRASHES`, where no
child process can be started (a frozen application,
an interpreter without `sys.executable`, an archivey imported from a zip with no worker
script on disk, a spawn the operating system refuses), opening a decoder SHALL raise
`ResourceUnavailableError` naming the reason and `process_isolation`; it MUST NOT decode
in-process. A decoder that needs a fresh child part-way through a member (a re-run, or
the move past the replay record's bound) SHALL raise the same error the same failure
raises at open. rapidgzip `AUTO` under `KNOWN_CRASHES` keeps falling back to the standard
library with one warning.

Under `NONE` no child process SHALL be started for decoding. PPMd SHALL decode
in-process at any size, a ZIP member with bit 3 set read from a non-seekable source
included: as in a child, a member up to `max_ppmd_held_input` is held and handed
to pyppmd whole, and a larger one, or one whose size is not known, is fed to it in pieces,
which can crash the process on corrupt input. That risk is the one `NONE` accepts. rapidgzip SHALL NOT be used: `use_rapidgzip=AUTO` and `use_indexed_bzip2=AUTO`
SHALL decode with the standard library without the warning that a child that cannot
start logs, and `ON` is refused at configuration (`archive-reading`, "Explicit
configuration object").

The system SHALL NOT bound the time a decoder takes under any value.

#### Scenario: start failure and NONE

| Case | Expected |
| --- | --- |
| `NATIVE_DECODERS`, no child process can be started | `ResourceUnavailableError` naming `process_isolation`; nothing decoded in-process |
| 7z PPMd member of 1 KB, default config, no child process can be started | `ResourceUnavailableError` naming `process_isolation` on the first read |
| A decoder needs a fresh child part-way through a member, and none can start / the fresh child cannot allocate the PPMd model | `ResourceUnavailableError` naming `process_isolation` / `ResourceUnavailableError` saying the decoder process could not allocate the model |
| 7z PPMd member of 200 KB compressed, `max_ppmd_held_input=1024`, `NONE` | Decoded in-process |
| gzip stream opened seekable, `use_rapidgzip=AUTO`, `NONE` | Standard library decoder; no warning |
