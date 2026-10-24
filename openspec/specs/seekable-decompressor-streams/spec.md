# Seekable Decompressor Streams

## Purpose

Archivey provides random access inside single-file compressed streams when the
caller declares seekability. The subsystem uses native indexes where formats
provide them and optional rapidgzip accelerators where they do not, while keeping
forward-only streams free of seek machinery.

## Related specs

| Spec | Relationship |
| --- | --- |
| `compressed-streams` | Public `open_stream(..., seekable=...)` and codec backend dispatch |
| `archive-reading` | `seekable_members=True` on archive member streams |
| `access-mode-and-cost` | Declared capabilities vs access modes |
| `diagnostics` | Rewind and seek-index diagnostic policy/retention |
| `error-handling` | Codec exception translation and `DiagnosticRaisedError` |

## Requirements

### Requirement: Seek machinery is demand-driven

The system SHALL construct seek support only when seekability is declared:
`seekable_members=True` on `open_archive()` or `seekable=True` on the
single-stream API. Undeclared streams SHALL NOT parse XZ footers, scan lzip
trailers, instantiate rapidgzip accelerators, retain rewind buffers, or retain
seek-point tables; they are forward-only.

`use_rapidgzip` and `use_indexed_bzip2` SHALL resolve their `AUTO` / `ON` / `OFF`
configuration against declared seek demand, not the `streaming` access-mode
proxy. For declared-seekable streams, native XZ/lzip indexes, rapidgzip-backed
gzip/bzip2 indexes, and stdlib fallback rewinds retain their contracts. The
stdlib O(n)-per-rewind path MAY serve the seek but MUST emit the documented
slow-rewind diagnostic (`STREAM_REWIND_REDECOMPRESSES`).

Under `AUTO`, the system SHALL additionally require the known compressed input size to reach a
documented minimum threshold before selecting rapidgzip for any DEFLATE-family stream (deflate,
zlib, gzip), so per-stream accelerator setup is not paid for members too small to benefit. The
threshold value is fixed by benchmark and recorded in design. When the input size is not known
in advance, `AUTO` SHALL behave as it did before this threshold existed (select the accelerator
when otherwise eligible). `ON` ignores the threshold; `OFF` never selects rapidgzip.
`use_indexed_bzip2` SHALL have its own documented `AUTO` threshold
(`INDEXED_BZIP2_AUTO_MIN_COMPRESSED_SIZE`), fixed by benchmark the same way, with the same
rules for an unknown size, `ON` and `OFF`.

Over a ZipCrypto decrypt stage `AUTO` SHALL resolve to `OFF` for the codec that reads
it, because every backward seek restarts decryption from the member's start.

#### Scenario: demand matrix

| Case | Expected |
| --- | --- |
| gzip/xz/bzip2/lzip opened without seekability under `AUTO` | No index, no accelerator, forward-only |
| Same stream opened with seekability, `AUTO`, accelerator installed, size ≥ threshold | Accelerator or native index provides random access |
| Declared-seekable deflate/zlib/gzip under `AUTO`, known size < threshold | rapidgzip not selected; stdlib backend used |
| Declared-seekable DEFLATE-family stream, `use_rapidgzip=ON`, size below threshold | rapidgzip still selected (threshold ignored) |
| Declared-seekable bzip2 under `AUTO`, known size < `INDEXED_BZIP2_AUTO_MIN_COMPRESSED_SIZE` | rapidgzip not selected; stdlib backend used |
| Declared-seekable bzip2, `use_indexed_bzip2=ON`, size below that threshold | rapidgzip still selected (threshold ignored) |
| Declared-seekable gzip without accelerator, caller seeks backward | Seek re-decompresses from the nearest member or BGZF block start before the target, else from the start; reports `STREAM_REWIND_REDECOMPRESSES`, naming the `[seekable]` accelerator, once the discarded progress reaches `REWIND_REDECODE_WARN_BYTES` |

### Requirement: XZ and lzip use format-native indexes

The system SHALL support random access in XZ and lzip by reading their embedded
index structures. XZ SHALL use the footer and block index to map uncompressed
offsets to compressed block positions. Lzip SHALL scan trailers to locate block
boundaries. A seek SHALL decompress only the block range needed for the requested
uncompressed offset.

#### Scenario: native index matrix

| Case | Expected |
| --- | --- |
| Seekable XZ source opens | Footer/block index maps uncompressed offsets to compressed positions |
| Seek within XZ | Only containing block range is decompressed |
| Seekable lzip source opens | Trailer scan locates block boundaries |
| Seek within lzip | Only required block range is decompressed |

### Requirement: rapidgzip is the only gzip and bzip2 accelerator

The system SHALL use `rapidgzip` as the only optional accelerator library for
both gzip and bzip2: gzip through `rapidgzip.RapidgzipFile`, bzip2 through
`rapidgzip.IndexedBzip2File`. It MUST NOT import the standalone `indexed_bzip2`
package because loading both C++ cores in one process can corrupt the heap on
macOS. `use_indexed_bzip2` remains the bzip2 configuration flag but selects the
rapidgzip-bundled decoder.

When rapidgzip is unavailable or disabled, gzip and bzip2 SHALL use stdlib
decoders; backward seek is serviced by re-decompressing from the start, or for gzip
from the nearest member or BGZF block start it knows (§"gzip member starts are seek
points", §"BGZF members are walked without decoding"), and MUST not degrade silently.

The system MUST NOT run any rapidgzip decoder in the caller's process. The bzip2 decoder
SHALL run in a child process with the same rules as the DEFLATE family's (next
requirement): the child opens a path source itself, a stream source stays in the caller's
process, a child that dies on the data is a verdict the standard library takes over from,
and where no child can be started `AUTO` decodes with the stdlib backend, logging one
warning per process that names `use_indexed_bzip2=OFF`, and `ON` raises
`ResourceUnavailableError`. No crash of that decoder has been seen; it is isolated as a precaution,
because it comes from the same library as the DEFLATE decoder, whose crashes cannot always be
avoided. A maintainer script SHALL run each rapidgzip decoder
in-process on damaged input in a watched process and report every crash by its
signature, so that whether the isolation is still needed stays measurable.

#### Scenario: accelerator matrix

| Case | Expected |
| --- | --- |
| `use_rapidgzip` enabled and package installed | gzip seeks without full re-decompression |
| `use_indexed_bzip2` enabled and rapidgzip installed | bzip2 uses `rapidgzip.IndexedBzip2File` in a child process; the caller's process imports neither rapidgzip nor standalone `indexed_bzip2` |
| `use_indexed_bzip2=AUTO`, no child process can start | stdlib decoder; one warning per process naming `use_indexed_bzip2=OFF` |
| `use_indexed_bzip2=ON`, no child process can start | `ResourceUnavailableError`; never decoded in-process |
| rapidgzip absent or flag `OFF` | stdlib decoder; backward seek re-decompresses from the start, or from a known gzip member start, and warns when it re-decodes past the threshold |

### Requirement: DEFLATE-family random access uses rapidgzip

The system SHALL use `rapidgzip` (the `[seekable]` accelerator, `>=0.16.0`) as the optional
random-access/parallel backend for raw DEFLATE (`deflate` codec) and zlib-wrapped DEFLATE
(`zlib` codec), in addition to gzip. rapidgzip auto-detects `GZIP`/`ZLIB`/`DEFLATE`, so the
codec SHALL pass the stream through unwrapped — no synthetic gzip header/footer. Selection is
gated identically to gzip (`use_rapidgzip` × declared seekability × availability, plus the
`AUTO` minimum-input-size threshold). The default sequential backend is unchanged: when
rapidgzip is unavailable, `OFF`, or below the `AUTO` threshold, deflate/zlib decode through
stdlib `zlib`.

Because rapidgzip auto-detects the format, the codec SHALL decode with the stdlib backend a
source rapidgzip could take for another format: a `deflate` source that starts with `1f 8b`, a
valid zlib header or `BZh` and a digit from 1 to 9, and a `zlib` source that does not start
with a valid zlib header. A `zlib` source whose header sets a preset dictionary SHALL use the
stdlib backend too: rapidgzip does not take that header for zlib. A raw DEFLATE stream that
rapidgzip ends before its first byte of output SHALL be decoded by the stdlib backend, which
gives the verdict. rapidgzip also ends a raw DEFLATE stream cut after a whole block, or inside
its last block, with no error. Where rapidgzip's output of a raw DEFLATE stream ends, the
system SHALL check with zlib that the stream reaches a final block, decoding from the last
DEFLATE block boundary the stream keeps at or before that end (or from the start where it
keeps none). Where it does not, the read SHALL be handed to the stdlib backend, which gives
the verdict, also when a declared size equals the output before the cut. A seek that stops at
the end of rapidgzip's output (a seek to the end, or one rapidgzip clamped short of its
target) SHALL run this check there as a read does; after a handover the stdlib backend SHALL
seek to the caller's target, so the seek raises or returns what it does with the accelerator
off. Once the stdlib
backend has taken over from rapidgzip, its errors SHALL leave as the codec's typed errors, so
the verdict does not depend on whether rapidgzip was engaged: with rapidgzip off, the codec's
own translator types the same error.

rapidgzip 0.16 aborts the process on a DEFLATE-family stream that ends early, so the system
SHALL run the gzip, zlib and deflate decoders in a child process and MUST NOT decode those
codecs with rapidgzip in the caller's process. A path source SHALL be opened by the child. A
stream source SHALL stay in the caller's process, which serves the child's reads, seeks and
tells, so an exception from the caller's source reaches the caller as itself. The child SHALL
be ended and reaped when the stream closes or is collected. bzip2 through
`rapidgzip.IndexedBzip2File` runs in the same kind of child (previous requirement).

Where no child process can be started (a frozen application, an interpreter without
`sys.executable`, an archivey imported from a zip with no worker script on disk, a spawn or
temporary file the operating system refuses, a child that cannot import rapidgzip), `AUTO`
SHALL decode with the stdlib backend, as it does when rapidgzip is absent, and SHALL log one
warning per process on the `archivey.streams` logger naming the reason and
`use_rapidgzip=OFF` (none where rapidgzip is absent). `ON` in that case SHALL raise
`ResourceUnavailableError` naming the reason and `use_rapidgzip=OFF`; it MUST NOT decode
in-process.

rapidgzip keeps decoded chunks in memory, so its memory grows with what the data decodes to,
not with the size of the file. The child's memory SHALL be capped by
`DecoderLimits.max_decoder_memory`, counted from when the child has opened the source: a child
whose peak resident memory grows past the cap SHALL be stopped, and the stdlib backend SHALL
read the rest of the stream, so the bytes delivered and the errors match `OFF`. The check MAY
run at intervals, so the peak MAY pass the cap by what the decoder allocates between two
checks, but it SHALL also run before the child answers each read. `None` sets no cap, and
nothing outside the caller's configuration, such as an environment variable, SHALL set one.
Where the platform does not report the child's peak memory, no cap applies.

rapidgzip over-reads past a DEFLATE end-of-stream looking for a concatenated member, so the
codec SHALL feed it an exactly-bounded input (e.g. the container's `SlicingStream` sized to
the member's compressed length); an unbounded or over-long stream MAY raise a spurious
"Invalid deflate block" error on the trailing bytes.

#### Scenario: deflate/zlib accelerator matrix

| Case | Expected |
| --- | --- |
| Declared-seekable raw deflate, `use_rapidgzip` enabled, size ≥ threshold | rapidgzip decodes/seeks without full re-decompression; input passed unwrapped |
| Declared-seekable zlib stream, accelerator enabled | rapidgzip auto-detects ZLIB and decodes; backward seek without re-decompress from start |
| rapidgzip absent, `OFF`, or size < `AUTO` threshold | stdlib `zlib` (`-15` / `MAX_WBITS`); backward seek re-decompresses from start |
| Accelerator fed an over-long/unbounded slice | May raise a spurious decode error on trailing bytes; callers MUST bound the input |
| No child can be started (frozen interpreter, zip import, refused spawn or temporary file), `AUTO` | stdlib backend |
| No child can be started, `ON` | `ResourceUnavailableError` at open |
| A `deflate` source that starts like gzip, zlib or bzip2, or a `zlib` source with no valid zlib header or with a preset dictionary, `ON` | The bytes and error of `OFF` (`CorruptionError` at the header) |
| A raw DEFLATE stream cut before any output (`03`), `ON`, with or without a declared size | `TruncatedError`, as with `OFF` |
| A raw DEFLATE stream cut after a whole block or inside its last one, `ON`, with or without a declared size equal to the output before the cut | `TruncatedError`, as with `OFF` |
| A `deflate` or `zlib` stream declared empty that does not decode, `ON` | `CorruptionError`, as with `OFF` |
| A gzip, zlib or `deflate` stream whose decode takes the child past `max_decoder_memory`, `ON` | The child is stopped; the stdlib backend delivers the rest, the same bytes as `OFF` |

### Requirement: Accelerator errors translate uniformly

The system SHALL translate corrupt/truncated input from rapidgzip-backed gzip,
bzip2, deflate, and zlib into the same `compressed-streams` errors as stdlib paths:
`CorruptionError` or `TruncatedError`, never raw third-party exceptions. This
translator SHALL account for platform-varying rapidgzip exception types/messages.

For gzip through rapidgzip, the system SHALL backstop truncation by comparing full-read
decompressed length modulo 2^32 with the gzip ISIZE trailer, for **any declared-seekable
source** — a path or a caller-owned `BinaryIO` alike — not only path sources, and also when
a declared decompressed size is set, since that checks only the length (no container
declares a gzip size today, so this is a guard, not a reachable case). The ISIZE trailer
value SHALL be captured up front (when the source is first inspected for backstop
eligibility), so no per-read reopen of a path is required and a non-path source needs no
seek while the accelerator is live. Where the whole output went through the reader, in
order, the trailer SHALL instead be found by the CRC-32 of that output and its length: the
eight bytes that end the file but for zero padding, and only where that CRC-32 occurs once
from 72 bytes before the end of the non-zero data to 12 bytes after it. In a one-member file
a forged copy of the eight bytes, appended after a wrong trailer, overlapping it or reaching
back into the compressed data, SHALL NOT pass for it, since the real CRC-32 is then a second
occurrence; a copy more than 56 bytes after the end of the real trailer is not excluded, and
needs rapidgzip to read past those bytes without an error, which rapidgzip 0.16 does not do
for ten or more. Where rapidgzip reaches EOF having delivered zero bytes, the system SHALL
rewind the seekable source and re-decode through the stdlib gzip engine so recoverable
prefixes stream and truncation still raises from a read (never `close()`). The backstop SHALL
run once, on the first read or seek that meets the end of rapidgzip's output, and is spent
after it; a seek short of that end SHALL leave it armed. The length compared is the position
at that end, which a read that meets the end has whatever seeks came before. A seek that stops
at the end of rapidgzip's output (a seek to the end, or one rapidgzip clamped short of its
target) SHALL run the backstop there, the empty-EOF arm included. It SHALL first read the
output from the end of the CRC-32 to the end of the output, so that the trailer is found by
its CRC-32 as on a read, not by the ISIZE comparison alone. After a handover, at the backstop
or during that read, the stdlib engine SHALL seek to the caller's target. So
`seek(0, SEEK_END)` on a cut file raises as with the accelerator off and never returns a
short size, and a read after a seek past the end never returns bytes from offset 0. On a
mismatch the read SHALL be handed to the standard library decoder, whose verdict it then
gives (`TruncatedError` for a cut, `CorruptionError` for a wrong ISIZE, a trailing-data
report for appended bytes), except where a further gzip member follows the first: then the
trailer records only the last member, and the backstop SHALL stand down when that trailer
holds the CRC-32 and the length of the end of the output (`compressed-streams`, *An
accelerator preserves the error contract*). A further member alone SHALL NOT stand it down,
since rapidgzip ends a last member cut right after its header with no error. Before it compares
the length or stands down, the backstop SHALL check that rapidgzip's decode reached the end
of the source; a decode that stopped short of it SHALL be handed to the standard library
decoder the same way. A `1f 8b 08` in the file SHALL count as a further member only when
zlib's gzip decoder accepts the header there and decodes from it without an error, to the
member's verified end or through a bounded probe; three bytes that turn up by chance in a
compressed body, or a member the source ends inside, SHALL NOT silence the backstop.

A **caller-owned** source driven through the accelerator SHALL NOT be closed by the accelerator
or its truncation wrapper (archivey never closes a source the caller owns); the accelerator's
close-on-finalize guard closes only archivey-owned handles. rapidgzip's `terminate()`-on-raising-
source hazard on Python file objects SHALL be contained so a source-side fault surfaces as a
translated `compressed-streams` error rather than aborting the process.

A DEFLATE-family child process that ends during a request SHALL be reported by how it ended,
and every later call on the child stream SHALL raise the same error: a fault signal (or its
Windows status) is a verdict on the data — `TruncatedError` when rapidgzip's abort names the
truncation, else `CorruptionError`; SIGKILL is `ResourceUnavailableError`; any other end is
`ReadError`.

A fault signal, like a data error rapidgzip reports on a read or a seek, SHALL hand the read
or seek to the standard library decoder, which delivers what it would have delivered with the
accelerator off: the same bytes before the error, and the same error. A seek through a valid
gzip with NUL padding after its last member, which rapidgzip fails on, therefore lands as it
does with the accelerator off. rapidgzip decodes ahead of the reader, so when it
dies the reader can be far short of the fault. The standard library SHALL start at the last
DEFLATE block boundary from rapidgzip's index at or before the position delivered to the
caller, among the boundaries the stream still keeps, with the 32 KiB of output before it as its
window; where it keeps none there, at the start of the stream. A decode started at such a point
that reaches the end of its DEFLATE stream cannot check the CRC-32 or Adler-32 that follows, so
it SHALL start over from the start of the stream. A SIGKILL or other end that is not a fault
signal is not a verdict on the data and SHALL reach the caller as above. A child that ends
after the caller's source raised SHALL be `ReadError`, and the source's exception SHALL be
raised first, unchanged. An exception that rapidgzip raised in the child SHALL reach the
translator as the same built-in type, and any `RuntimeError` rapidgzip raised SHALL translate
to `CorruptionError` when no listed message says truncation.

The same rule SHALL hold for bzip2 through rapidgzip's decoder process: a data error it
raises (on a cut stream an opaque `RuntimeError('std::exception')`), or a crash of the process
on the data, on a read or a seek, SHALL
hand the operation to the standard library decoder, so the bytes delivered and the error match
`use_indexed_bzip2=OFF`. The standard library SHALL start at the newest block from rapidgzip's
index at or before the position delivered to the caller, among a bounded number of the newest
such blocks it keeps as seek points; where there is none, at the start of the stream. A bzip2
block carries no window. A decode started at a block that meets the end of its stream (the
combined CRC, which it cannot check) or a damaged block SHALL start over from the start of the
stream; one that runs out of input first SHALL raise the standard library's `TruncatedError`.

rapidgzip does not validate zlib's Adler-32 and returns a silent short read on some
mid-stream DEFLATE truncations. For a zlib stream the system SHALL check the Adler-32 after
rapidgzip: once the stream has been read to its end (a forward seek reads the skipped bytes, so
a reader that skips is still covered), a mismatch the standard library confirms SHALL raise
`CorruptionError` from the read or seek that reached the end, and the TAR end-of-archive scan
SHALL re-raise it. Where the standard library agrees with every byte rapidgzip delivered and
then has more output, or meets the end of the source inside the stream (a cut stream), the
read SHALL be handed to the standard library at the delivered position, so the bytes and the
`TruncatedError` match `use_rapidgzip=OFF`. Where the standard library's decode ends the first
zlib stream before the bytes rapidgzip delivered (rapidgzip decodes on into a second stream)
and the caller has no byte past that end yet, the read or seek SHALL be handed to the
standard library at that end, so a completing read returns the first stream and the rest is
reported as trailing data, as with `use_rapidgzip=OFF`. A caller that already has bytes past
that end MAY keep the rapidgzip reading, which the decode of the following streams confirms;
that caller then gets the following streams as content, and no `ARCHIVE_TRAILING_DATA` is
reported. One stated exception: with a container-declared
size, the read that reaches it is the verifying stage's verifying event, and when the probe past
the size meets a cut trailer that read's chunk is withheld; the error is still `TruncatedError`.
Raw DEFLATE carries no checksum, so there is no backstop for the deflate accelerator path. A
DEFLATE-family member decoded inside a container (e.g. a ZIP member) SHALL rely on the
container's own checksum (CRC-32 via the shared verifying stage) to catch truncation/corruption.
A standalone deflate stream accelerated by rapidgzip MAY therefore miss a truncation that stdlib
`zlib` would report; this is an accepted limitation of the accelerator path, and corruption
inside a DEFLATE block SHALL still surface as `CorruptionError`.

#### Scenario: accelerator error matrix

| Case | Expected |
| --- | --- |
| Corrupt gzip/bzip2/deflate/zlib through rapidgzip | `CorruptionError`; raw accelerator exception never escapes |
| Truncated gzip through rapidgzip from a seekable **path** | `TruncatedError` via ISIZE backstop / empty→stdlib, or `CorruptionError` from accelerator; never silent short read |
| Truncated gzip through rapidgzip from a seekable **non-path** `BinaryIO` | Same as the path case — backstop active; caller source left open afterward |
| Cut gzip or raw DEFLATE through rapidgzip: `seek(0, SEEK_END)`, or a seek past the end then a read | What the accelerator off gives (`TruncatedError`); never a short size, never bytes from offset 0 at the caller's position |
| Truncated gzip/zlib/deflate that aborts rapidgzip, any source, any access pattern | The process survives; the bytes and the error of the standard library decoder (`TruncatedError`) |
| A fault signal ends the child on a valid stream | The standard library reads on from the delivered position; the caller loses nothing |
| A resumed standard-library decode reaches the end of a DEFLATE stream (a later member, bytes after the data) | It starts over from the start of the stream; the stream's checksum is checked |
| DEFLATE-family child killed by SIGKILL / ended by SIGTERM | `ResourceUnavailableError` / `ReadError`; later calls raise the same |
| Caller-owned source raises while the child reads it | That exception, unchanged; a later child death is `ReadError` |
| Caller-owned source after the archivey stream closes | Still open and readable; accelerator/wrapper closed only its own view |
| Damaged standalone zlib through rapidgzip, read to its end | `CorruptionError`; never a silent wrong read (Adler-32 check) |
| Truncated standalone zlib or bzip2 through the accelerator (`AUTO` / `ON`), cut in the first block, a later block or the end marker | The bytes and the error (`TruncatedError`) of the accelerator `OFF` |
| Damaged `.tar.zz` through rapidgzip, listed or read | `CorruptionError` (the TAR end scan re-raises the Adler-32 mismatch) |
| Truncated standalone deflate through rapidgzip | Corruption in a block → `CorruptionError`; a clean mid-stream cut MAY return a short read undetected (no checksum backstop) |
| Truncated/corrupt container DEFLATE member (e.g. ZIP) | Container CRC mismatch → `CorruptionError`/`TruncatedError` via the verifying stage |
| Valid concatenated multi-member gzip | Decompresses fully without false truncation |
| A gzip member cut short and followed by a complete member, through rapidgzip, with the last trailer right or forged to match the bytes delivered | The error of the accelerator `OFF` |
| Concatenated gzip or BGZF through rapidgzip whose last member is cut anywhere, right after its header included, or has a wrong ISIZE, however many members come before it | The bytes and the error of the accelerator `OFF` |
| Valid concatenated gzip or BGZF through rapidgzip, an empty last member included, whatever the size of the last member | Read by rapidgzip to the end, with no handover to the standard library and a read-back of at most 4 MiB per trailer candidate; an empty last member whose header starts more than 1 KiB before the end of the non-zero data (a long `FNAME`) is handed over, with the same bytes and no error |
| Concatenated gzip through rapidgzip whose last member is cut, with its last four bytes forged to the length, read after a seek that skipped output, the forged length starting before or after the seek target, or after a `SEEK_SET` to exactly the length of the output | `TruncatedError`, as with the accelerator `OFF`; a candidate starting before the seek target reads back the skipped part, up to 64 MiB in all, past which the standard library decides |
| Cut or wrong-ISIZE one-member gzip through rapidgzip, after any seek, or with `1f 8b 08` in its body | The error of the accelerator `OFF`; after a seek short of the end that skipped output, then a read to the end, a wrong ISIZE hidden by four appended bytes equal to the length is the one exception |
| Cut gzip whose last four bytes are forged to the length rapidgzip delivers: `seek(0, SEEK_END)`, or that seek, then `seek(0)` and a read | `TruncatedError`, as with the accelerator `OFF` |
| Valid gzip with NUL padding, seek through rapidgzip | Lands and reads as with the accelerator `OFF` |
| bzip2 through the accelerator with junk, a damaged stream header, or a stream whose block and end-of-stream magics are damaged, before or between streams | The bytes and the error of the accelerator `OFF`; no byte from after the skipped region reaches the caller, also after a seek past it |
| bzip2 through the accelerator with a cut or damaged stream right after the data, or anything after zero bytes | The bytes, the error and the trailing-data report of the accelerator `OFF`; past a bounded stretch (1 MiB) of empty streams between two streams, the standard library takes over and decodes the stretch itself, with the same result |
| gzip through rapidgzip with NUL bytes, then a further member | The first member's bytes and a trailing-data report at the further member, as with the accelerator `OFF` |
| Two zlib streams through rapidgzip, completing read or seek to the end | The first stream, and a trailing-data report, as with the accelerator `OFF` |
| Valid empty gzip through rapidgzip | Succeeds with zero bytes |

### Requirement: Accelerator lifecycle is safe at shutdown

No rapidgzip object SHALL live in the caller's process. The decoder process SHALL close
its rapidgzip stream before it exits and then skip interpreter finalization
(`os._exit`), because `join_threads()` alone does not stop rapidgzip's C++ worker thread
and a worker still running at finalization aborts the process. The caller's process SHALL
reap the decoder process when its stream is closed, collected, or left at interpreter
exit.

The decoder process SHALL use rapidgzip for both gzip and bzip2 and never import
standalone `indexed_bzip2`. With these measures, `AUTO` MAY select rapidgzip for declared
random access on every platform.

#### Scenario: accelerator safety matrix

| Case | Expected |
| --- | --- |
| Accelerator stream is leaked, cyclically collected, or process exits | The decoder process is reaped; the caller's process holds no rapidgzip object and terminates cleanly |
| Decoder process finishes a stream | It closes the rapidgzip stream, then exits with `os._exit` |
| Process accelerates gzip and bzip2 | Both use rapidgzip; standalone `indexed_bzip2` is absent; no cross-library heap double-free |
| Declared random access with `AUTO` and rapidgzip available | rapidgzip may be selected on every platform |

### Requirement: Index-less rewinds emit diagnostic data

The predicate for `STREAM_REWIND_REDECOMPRESSES` SHALL be **the decoded progress the
rewind discards**, not the codec's identity:

```
redecode_distance = position_before_seek − nearest_seek_point_at_or_before(target)
```

That is, the bytes that must be decoded again to return to where the caller was. It is
measured from the **pre-seek position**, not from the target: the seek call itself may
decode almost nothing — `seek(10)` after reading a gigabyte decodes ten bytes — while
throwing away a gigabyte of progress, and it is the discarded gigabyte that makes a seek
loop quadratic.

When a backward seek's `redecode_distance` reaches
`REWIND_REDECODE_WARN_BYTES` (an **absolute** byte threshold), the system SHALL report
`STREAM_REWIND_REDECOMPRESSES` with codec, before/after offsets, the distance, and
accelerator name or `None`. Forward and no-op seeks SHALL report nothing. The message
SHALL say where decoding restarts: the start of the stream, the seek target itself when
the target is a resume point, or the nearest resume point and how far before the target
it is. It SHALL NOT say that the codec has no index, because a multi-block `.xz` or
multi-member `.lz` has one. A message that names an accelerator says this as well.

A `RewindWarning` MAY carry `min_redecode_bytes`. The distance used by the predicate
is `max(redecode_distance, min_redecode_bytes)`, so a carrier that re-decodes bytes
the member stream's `tell()` does not contain (a named `unrar` respawn of a solid
member, which restarts from member zero) is still loud.

The threshold SHALL be absolute rather than relative to the jump distance. A relative
rule goes quietest exactly where the absolute cost is highest: on a 1 GB single-block
`.xz`, seeking from the end back to 900 MB re-decodes 900 MB while jumping only ~100 MB,
a ratio no sane relative threshold would flag.

The distance SHALL be computed against the seek index **as it exists at seek time**, and
obtaining it MUST NOT trigger index construction — a diagnostic that built an index would
change the cost it reports.

**The predicate is uniform across codecs, including accelerated ones.** A format that
*can* carry an index does not always *have* a useful one, and neither does an
accelerator: a single-block `.xz` has one seek point (the origin), and `rapidgzip`'s
`available_block_offsets()` on a `gzip.compress` output is sparse enough that a backward
seek can re-decode megabytes with the accelerator engaged. Both are the same event and
SHALL be reported the same way.

| Stream shape | Nearest resume point | Reported |
| --- | --- | --- |
| No index at all | the origin | yes, once progress passes the threshold |
| Single-block xz / one-member lzip / `.Z` with no CLEAR codes | the origin | yes, same as above |
| Multi-block xz, multi-member lzip | the containing block | only when the progress since that block passes the threshold |
| Multi-frame zstd; multi-member gzip or BGZF on the stdlib engine | the containing frame, member or block | as above |
| One-frame zstd (a ZIP member too), one-member gzip on the stdlib engine | the origin | yes, once progress passes the threshold |
| Accelerated gzip/bzip2, dense index | the containing block | as above |
| Accelerated gzip/bzip2, sparse index | up to a block back | yes, once past the threshold |
| Any codec, less progress discarded than the threshold | — | no |
| `STORED` (no decompression) | — | never; nothing is re-decoded |

A stream that exposes no seek-point table SHALL be treated as resuming from the origin.
For a *decompressing* stream — the only kind this event applies to — that is the truth
rather than a guess, and it is what keeps the index-less codecs (stdlib LZMA Alone,
brotli, lz4) reporting.

The event SHALL live on the stream operation and cumulative owning-reader
aggregate, never on `CostReceipt` or `ArchiveInfo`. Gzip/bzip2/deflate/zlib context names the
`[seekable]` accelerator when a rapidgzip path was eligible; brotli, lz4, and zstd record no
accelerator. A zstd stream SHALL rewind in place: from the nearest frame start it knows
(§"zstd frame starts are seek points"), or from the start when it has one frame. When a
deflate/zlib stream falls back to stdlib `zlib` (accelerator absent, `OFF`, or below the
`AUTO` threshold), its rewind SHALL name the `[seekable]` accelerator, consistent with the
gzip fallback.

**Recording is deduplicated; escalation is not.** The occurrence SHALL be *recorded* at
most once per stream, and the configured `DiagnosticPolicy` SHALL be evaluated on **every**
qualifying seek, so a `RAISE` policy stops the second expensive rewind as well as the
first. See `diagnostics` for the general rule.

#### Scenario: slow rewind matrix

| Case | Expected |
| --- | --- |
| One index-less stream performs many backward seeks | One recorded `STREAM_REWIND_REDECOMPRESSES`; later rewinds add no duplicate record |
| Rewind diagnostic resolves to `RAISE`, first qualifying seek | `DiagnosticRaisedError` raised from that seek |
| Rewind diagnostic resolves to `RAISE`, **second** qualifying seek | `DiagnosticRaisedError` raised again — the guard does not disarm |
| Only forward/no-op seeks occur | No occurrence |
| Full rewind on a **single-block** `.xz` | One occurrence — the format could have carried an index; this file does not |
| Rewind within one block of a multi-block `.xz` | No occurrence |
| Rewind of fewer than `REWIND_REDECODE_WARN_BYTES` on any codec | No occurrence, unless `min_redecode_bytes` meets the threshold |
| Rewind across a sparse gap in an engaged `rapidgzip` index | One occurrence naming the accelerator |
| One-frame zstd stream rewinds | Re-decompresses from start in place; one occurrence when above the threshold |
| Multi-frame zstd stream rewinds within one frame | Resumes at that frame's start; no occurrence unless the progress since that frame passes the threshold |
| Stdlib-fallback zlib/deflate stream rewinds | One occurrence naming the `[seekable]` accelerator |
| Stream with no seek-point table (stdlib LZMA Alone, brotli, lz4) | Resume point is the origin; one occurrence once progress passes the threshold |
| `STORED` member seeks backward | No occurrence, at any distance |

### Requirement: Recoverable seek-index degradation is diagnostic data

When an XZ/lzip backward index or trailer scan fails but sequential
decompression remains safe, the system SHALL emit `SEEK_INDEX_DEGRADED` with
codec, scan kind, and public failure type, then use sequential fallback unless
policy escalates. The occurrence SHALL be aggregate-only on stream/reader
operation summaries, and SHALL reach the collector of the reader or stream that
opened the codec, so the caller's policy and callback apply. An escalated
occurrence SHALL raise only once the stream is consistent: a read raises before
it consumes, keeping the bytes it decoded for the next read, and a seek or size
query raises after it finishes, with the position where it left it. A caller
that catches the `DiagnosticRaisedError` SHALL be able to keep reading and get
the right bytes. Unsafe corruption SHALL remain a typed
`CorruptionError`/`TruncatedError`, not a recoverable diagnostic.

Every seek point SHALL resume on its own, whatever other points the table holds.
An XZ block point SHALL carry its stream's check type, where the stream's blocks
end, and the stream's decompressed and compressed ends; resuming from it SHALL
decode to where the blocks end, SHALL raise `CorruptionError` when the decoded
size disagrees with the stream index, and SHALL then continue sequentially past
the stream.

A stream's seek table SHALL hold at most a fixed number of entries (262 144). Past
it the table SHALL be thinned, not dropped: points kept at least a spacing apart in
decompressed bytes, chosen so the table falls to half the cap, with later points
kept at that spacing. A backward scan SHALL thin as it walks, never holding more
than the cap (nor a whole stream's blocks), and SHALL keep the last unit so the
size it reports stays exact. Thinning SHALL emit `SEEK_INDEX_DEGRADED` (failure
type `SeekTableThinned`). The cap is structural rather than a config field
because passing it costs seek speed, never a readable file.

A point an index scan gave (the xz index, lzip trailers, the zstd seek table, the
BGZF walk), and a point recorded by a decode that resumed at such a point, SHALL be
marked as the index's. When two points name the same compressed offset with the same
resume state but different decompressed offsets, and either is the index's, the index
is wrong; so is it when a decode reaches the end with another total than the index
gave, and when a decoder that resumed at an index point fails before giving any output
there (a zstd seek table whose sizes add up but put a frame start inside a frame). That
last check counts only a verdict on the data, not an `OSError`, a `MemoryError`, a
child decoder ended from outside or one that could not start; a `DecoderLimits`
refusal of a size the bytes there declare is a verdict, and so, on purpose, is an
exception the stream does not know, which costs at most the index. It cannot tell a wrong index from damaged data at an honest
point, so damage there costs a decode of the prefix before its `CorruptionError`.
Only points the seek table holds SHALL be compared, so the check costs no more
memory than the table. The stream SHALL then drop every point that is the index's,
forget a size the index gave (or a decode that resumed at an index point reached), and
emit
`SEEK_INDEX_DEGRADED` (scan `decode_check`, failure type `SeekIndexContradicted`), once
per stream. Later seeks SHALL resume only from points a decode from the origin found,
and a later size query SHALL decode to the end. A decoder that resumed at an index
point SHALL be restarted from such a point before the read, seek or size query that
found the contradiction returns, so that operation returns the right bytes and
position; the file SHALL NOT be refused. An index point and a decoded point at the
same decompressed offset with different compressed offsets SHALL NOT raise: the
decoded point is kept (an empty lzip member makes such a pair in an honest file).

#### Scenario: seek-index degradation matrix

| Case | Expected |
| --- | --- |
| Recoverable XZ index scan failure | `SEEK_INDEX_DEGRADED` collected/logged; stream falls back sequentially |
| Same issue resolves to `RAISE` | `DiagnosticRaisedError`; no fallback |
| That `DiagnosticRaisedError` caught, then reading on | Every byte, in order; a member digest or length check does not report a false fault |
| One stream's table thinned more than once | Recorded once; `RAISE` raises in every read, seek or size query that thins it, once per call |
| Corruption prevents correct sequential decoding | `CorruptionError` / `TruncatedError`, not diagnostic fallback |
| XZ index scan fails after a forward read recorded block points | A later seek from those points reads the right bytes to the end |
| Backward scan finds more units than the cap (lzip members, xz streams or blocks) | Kept units thinned by spacing, last one kept; `SEEK_INDEX_DEGRADED`; seeks read the right bytes |
| A thinned xz index leaves out streams after block points a forward read recorded | A seek from those points reads every stream after them |
| A forward read's per-stream xz scan finds more blocks than the cap | That stream's blocks thinned by spacing; `SEEK_INDEX_DEGRADED`; seeks read the right bytes |
| Forward read records more points than the cap | Table thinned by spacing; `SEEK_INDEX_DEGRADED`; later seeks read the right bytes |
| XZ blocks after a resume point decode to a size other than the stream index declares | `CorruptionError` |
| A forward read finds a frame or member start at another output offset than the zstd seek table or BGZF walk gave it | `SEEK_INDEX_DEGRADED` (scan `decode_check`, `SeekIndexContradicted`); index points and size dropped; later seeks and the size match a read from the start |
| The same, found by a decode that resumed at an index point | That read, seek or size query restarts from a decoded point and returns the right bytes |
| A decode that resumed at a zstd seek-table point fails there before any output (the point is inside a frame) | `SEEK_INDEX_DEGRADED` (`SeekIndexContradicted`); the read or seek restarts from a decoded point and returns the right bytes, no `CorruptionError` |
| The same failure at an honest index point over damaged data (a BGZF block whose deflate data is damaged at its start) | `SEEK_INDEX_DEGRADED` (`SeekIndexContradicted`), then a decode from a decoded point raises `CorruptionError` at the damage |
| An `OSError` from the source in the first decode after a resume at an index point | The `OSError` propagates; no diagnostic, the index stays |
| Lzip file with an empty member; size query before or after a forward read | Every read right; no collision error, no diagnostic |

### Requirement: Unix-compress uses CLEAR seek points

When seekability is declared and the compressed source is seekable, the system
SHALL register `SeekPoint`s at stream start (after the 3-byte `.Z` header) and at
each LZW CLEAR realignment. A seek SHALL resume from the nearest preceding
seek point with an empty dictionary and MUST NOT emit
`STREAM_REWIND_REDECOMPRESSES`.

Forward decode SHALL NOT call `seek` on the compressed source: CLEAR bit-block
realignment MUST use a bounded in-memory buffer. When seekability is not
declared, the system SHALL NOT retain a CLEAR seek-point table. When the source
is not seekable, the decompressor stream SHALL report `seekable() is False` and
`seek` SHALL raise `io.UnsupportedOperation`.

Unix-compress has no length or checksum trailer. At source EOF, after all
decoded bytes have been delivered, the system SHALL best-effort detect
truncation, and the next `read()` SHALL raise `TruncatedError` when any of these
holds: the source ended inside the 3-byte header (see `compressed-streams` for a
short source that is not `.Z` at all); the source ended while a CLEAR's
realignment padding was still owed (compressors write that padding in full); or
leftover bits remain after the last complete LZW code and those bits are nonzero
(finished compressors zero-pad). Zero leftover bits outside CLEAR padding
(including a cut exactly on a code boundary) SHALL end successfully — such
truncation remains undetectable.

Unknown reserved header flag bits (`0x60` in the third header byte) SHALL raise
`UnsupportedFeatureError` when the header is parsed.

#### Scenario: unix-compress seek matrix

| Case | Expected |
| --- | --- |
| Seekable `.Z`, `seekable=True`, seek backward across a CLEAR | Resumes from CLEAR/`SeekPoint`; no rewind diagnostic |
| Seekable `.Z`, `seekable=False` | Forward-only; no CLEAR table retained |
| Non-seekable `.Z` pipe, forward read | Decompresses; `seekable()` false |
| Truncated `.Z` with nonzero leftover bits | Yields available bytes; next `read()` raises `TruncatedError` |
| Truncated `.Z` cut inside the padding after a CLEAR | Yields available bytes; next `read()` raises `TruncatedError` |
| Empty `.Z` source, or one cut inside the header | `TruncatedError`, never a clean empty stream |
| Truncated `.Z` with only zero leftover bits, outside CLEAR padding | Yields fewer bytes; no `TruncatedError` (undetectable) |
| Header flag byte has reserved bits `0x60` set | `UnsupportedFeatureError` |
| Corrupt LZW codes | `CorruptionError` |

### Requirement: zstd frame starts are seek points

On declared seek demand, every regular zstd frame after the first SHALL be a seek
point, recorded when a forward read reaches it. A skippable frame holds no output and
SHALL NOT be one. A stream opened without seek demand SHALL keep no points. A ZIP or 7z
zstd coder keeps them as a `.zst` file does.

#### Scenario: frame point matrix

| Case | Expected |
| --- | --- |
| Multi-frame file, read forward, then seek back | Resumes at the frame start before the target |
| Skippable frame before each frame (pzstd) | Points at the regular frames only |
| Stream opened without seek demand | No points kept, no table read |
| ZIP zstd member of two frames ending in a seek table, seek declared | The table's frame starts are the seek points, as in a `.zst` file |

### Requirement: zstd reads the Seekable Zstandard seek table

A forward seek past the known points, a `SEEK_END`, or a size query SHALL read the
*Seekable Zstandard* seek table when the source ends with one (skippable magic
`0x184D2A5E`, footer magic `0x8F92EAB1`). Its frame sizes SHALL give the seek points and
the total size, with no decoding. The table is trusted like the xz and lzip indexes
(threat-model O17) until a decode contradicts it, which drops it (§"Recoverable
seek-index degradation is diagnostic data"); its per-frame XXH64 checksums SHALL NOT be
checked. A table over the seek-table cap SHALL be thinned and keep the exact total.

#### Scenario: seek table matrix

| Case | Expected |
| --- | --- |
| `seek(0, SEEK_END)` | Total from the table; only the table is read |
| Seek into frame N | Decoding resumes at frame N's start |
| Reserved descriptor bits set, a frame of 0 compressed bytes, or frame sizes that do not reach the table | `SEEK_INDEX_DEGRADED` (scan `zstd_seek_table`); reads decode from the start |
| A frame's decompressed size is wrong; read from the start past the next frame, then seek back into the first | `SEEK_INDEX_DEGRADED` (scan `decode_check`); the seek returns the first frame's bytes; the size is the decoded one |
| Zeros after the table | No table found, no diagnostic; reads decode from the start |

### Requirement: gzip member starts are seek points

Each gzip member starts a fresh DEFLATE stream. On declared seek demand the standard
library engine SHALL record every member after the first that has output as a seek
point when a forward read reaches it. A stream opened without seek demand SHALL keep no
points.

#### Scenario: member point matrix

| Case | Expected |
| --- | --- |
| Multi-member gzip, read forward, then seek back | Resumes at the member start before the target |
| Plain one-member gzip | No points, no diagnostic; seeks decode from the start |
| Stream opened without seek demand | No walk, no points |

### Requirement: BGZF members are walked without decoding

A forward seek past the known points or a `SEEK_END` SHALL walk a BGZF file's members
from the start, reading the file once front to back and inflating nothing: each member's
`BC` extra subfield gives its size and its ISIZE its output. The walk SHALL stop quietly
at the first member without one, keeping the points before it; the size is known only
when it reaches the end of the file. The sizes are trusted like the xz and lzip indexes
(threat-model O17) until a decode contradicts them, which drops the walk's points and
size. A file whose first member is not BGZF SHALL cost one read buffer's worth before the
walk stops. A `.gzi` file is not read.

A size query (`try_get_size()`, `ArchiveStream.size`) SHALL NOT walk the file, because
the walk reads all of it and a size query must be cheap. Before a walk or a read to the
end, the size SHALL be `None`, as for plain gzip. After a walk that reached the end of
the file, or a read to the end, the size query SHALL return the size.

#### Scenario: BGZF walk matrix

| Case | Expected |
| --- | --- |
| `seek(0, SEEK_END)` | Total from the walk; the file read once in large pieces, nothing inflated |
| Size query on a new stream | `None`; no walk, at most one read buffer's worth read |
| Size query after `seek(0, SEEK_END)`, a forward seek that walked, or a read to the end | The total |
| Gzip file that is not BGZF | One read buffer's worth read; no points, no size |
| Seek into block N | Decoding resumes at block N's start |
| BGZF blocks, then a plain member | Points for the blocks; size from decoding to the end |
| Walk over the seek-table cap | `SEEK_INDEX_DEGRADED` (scan `bgzf_blocks`, `SeekTableThinned`); exact total kept |
| A member's `BSIZE` covers the next member too; size query, then a read from the start | Size first the walk's; the read is right; `SEEK_INDEX_DEGRADED` (scan `decode_check`); then size and seeks are the decode's |
| The member hidden that way is the last data member | As above: the size query, then the read to the end, which reports once. A read to the end first: the decoded size, no walk, no report |
