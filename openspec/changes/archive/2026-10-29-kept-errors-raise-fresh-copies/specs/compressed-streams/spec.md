## MODIFIED Requirements

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
`EncryptionError`), every later `read` / `readinto` SHALL raise that verdict again until
the caller seeks: an error of the same type and arguments, whose `__cause__` shows where
it was first raised as text, rather than a traceback that grows per call. The raise
SHALL NOT be the instance the stream keeps, and the stream SHALL NOT keep a traceback:
a kept traceback holds the stream's frames, a cycle that keeps the stream and its
decoder (a leased decoder process among them) alive until the garbage collector runs. A seek SHALL succeed and restart the decode, so the prefix
reads again, as a truncated `DecompressorStream` does; the read that then reaches the
end SHALL raise the verdict again and return no bytes, whether or not a seek forfeited
the digest check (a seek to 0 re-arms it, and the damage found again raises the first
verdict again). A read reaches the end when it returns short or empty, is `read(-1)`, or
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
| `ArchiveStream` raised a content verdict; caller catches it, then `read()` | Raises the verdict again (same type and arguments, first raise as its cause); no bytes returned |
| Same, then `seek(0)` and a bounded `read(n)` inside the member | Seek succeeds; the prefix bytes are returned |
| Same, then `seek(0)` and a read that reaches the end | Raises the verdict again; that call returns no bytes |
| Same, retried many times | Traceback does not grow per call |
| Same, `tell()` or `close()` | Not gated; `close()` does not raise the verdict |
| Accelerated decoder; a read raises and the decoder moves back | `tell()` equals the bytes delivered; the stream stays usable |
| Accelerated decoder; a read raises and the decoder cannot be moved back | That read raises its own error; every later `read` / `readinto` / `seek` / `tell()` raises `ReadError` naming the cause; `close()` succeeds |
| Accelerated decoder; the caller's source raises during a read or a seek | That call raises the source's error; then as the row above, even if the source recovers |
| Same, then the caller drops the stream, with the garbage collector off | The stream is freed at once |
