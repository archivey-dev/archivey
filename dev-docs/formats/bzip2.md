# bzip2

Current maintainer truth for bzip2 (`.bz2`) as a single-file format and as a coder inside
TAR, ZIP and 7z. Two backends decode it: the standard library's `bz2`, always available,
and the bzip2 decoder bundled in the optional `rapidgzip` package, which runs in a child
process and gives random access. What bzip2 shares with the other codecs, the one-member
reader, the seek table and the truncation contract, is on [`single-file.md`](single-file.md).
Registers keep the status; this page states the behaviour and links the row.

## At a glance

| | |
| --- | --- |
| Read | bzip2 as a one-member archive, as a ZIP and 7z coder, and inside `.tar.bz2` |
| Write | **Not shipped** |
| Backends | The standard library's `bz2.open`. `rapidgzip.IndexedBzip2File` from `[seekable]`, used when `use_indexed_bzip2` selects it (§2.3) |
| Seeking | Without the accelerator, a backward seek decodes again from the start. With it, from the nearest block of the index it builds while decoding |
| Size | `None`. bzip2 has no size field |
| Digests | None listed. Every block's CRC and the stream's combined CRC are checked on read, the combined one when the read reaches the end of the stream (§2.3) |
| Metadata | None beyond the shared fields |
| Truncation | Always raised: `TruncatedError`, after the same bytes with the accelerator off and on (§2.3) |
| Refuses | Nothing bzip2-specific |

**Two things a reader might expect and will not find.** `member.size` is `None` until the
whole stream has been read: nothing in the file records it. And the accelerator's `AUTO` size
threshold is 1 MiB, not gzip's 16 MiB: the standard library decodes bzip2 slowly, so the
accelerator's child process pays for its start much sooner.

## 1. Shape

Three properties generate most of this page.

```
stream:  "BZh" level('1'..'9')
         block:  pi(48 bits) CRC(32) randomised(1) origPtr(24) Huffman tables … data
         block:  …                                 ← not byte-aligned
         end:    sqrt(pi)(48 bits) combined CRC(32) padding to a byte
stream:  "BZh" …                                   ← a following stream is legal
```

**Blocks are independent, but not byte-aligned.** Each block is a Burrows–Wheeler
transform of up to 900 kB of input (the level digit times 100 kB), with its own Huffman
tables and CRC. A decoder can start at any block without the ones before it. But the
blocks are packed bit by bit: a block starts at a 48-bit magic that can sit at any bit
offset. So finding blocks means a bit-level scan, and a seek table stores a bit offset.
That is what `rapidgzip`'s bundled decoder does, and why the standard library, which does
not, re-decodes from the start on a backward seek.

**The first output needs a whole block.** The Burrows–Wheeler transform is inverted per
block, so no byte of a block comes out until the whole block has been read and sorted
back. The first byte of a stream costs up to 900 kB of decoded output. Open-time
validation (§2.2) and detection's inner-TAR probe (§2.1) both pay that cost.

**A file can be several streams, and nothing counts them.** `pbzip2` and `lbzip2` write one
stream per chunk, and `cat a.bz2 b.bz2` is valid. No stream records the uncompressed size;
the combined CRC covers only its own stream. So neither a size nor a whole-file digest
exists without decoding everything.

## 2. The pipeline here

### 2.1 Identify

bzip2 is the magic `BZh` at offset 0, reported `CERTAIN`. The level digit is not checked.
The inner-TAR probe then decodes 512 bytes to see whether a TAR header follows
([`single-file.md`](single-file.md) §2.1). That probe may read up to 1 MiB of compressed
input for any codec, a bound sized for bzip2's worst case: a single block of level-9 input
can be around 900 kB compressed, and the first byte of output comes only at its end. The
other codecs produce the TAR header from the detection prefix, so in practice only bzip2
reads that far. A `.tar.bz2`
whose first block is that large is still found as `TAR_BZ2`, from a pipe too. `.bz2`,
`.tbz`, `.tbz2` and `.tar.bz2` are the registered extensions.

### 2.2 Open and list

The member has no metadata of its own: `size` is `None`, `modified` is `None`, and
`hashes` is empty. The name comes from the file name ([`single-file.md`](single-file.md)
§2.2).

On a seekable source, the reader decodes one byte at open to prove the source is bzip2
([`single-file.md`](single-file.md) §2.2). For bzip2 that one byte costs the first block.
A file with valid first blocks and damage later opens and lists; the damage raises on
read.

### 2.3 Member data

**The standard library engine.** `FramedDecompressorStream` runs one `bz2.BZ2Decompressor`
per stream, which checks each block's CRC and the stream's combined CRC, and starts
another when the bytes right after a stream are `BZh` and a block size digit. Bytes
there that match those four in two or three places (`BYh9`, `BZh0`) are a stream with a
damaged header and raise `CorruptionError`, although `bzip2 -t` ignores them as trailing
garbage: the rule is the one every codec with a magic follows
([`single-file.md`](single-file.md) §2.3). Anything else after the last stream is
reported as `ARCHIVE_TRAILING_DATA` unless it is zeros that run to the end of the file
(§2.3). After zeros, any byte ends the data, a further stream's header too (§6); the
report names the first non-zero byte. One to three zeros that start a damaged header
with the bytes after them raise as a damaged header does, since the damaged byte can be
a zero. `bz2.open`, which this replaces, ignored trailing bytes without a word. A stream
that ends before its end marker is `TruncatedError`. An `OSError` saying "Invalid data
stream" is `CorruptionError`. It can seek, but a backward seek decodes again from the
start, and the rewind report says so.

**When the accelerator is used.** `use_indexed_bzip2` is an `AcceleratorMode`, `AUTO` by
default:

| Mode | bzip2 |
| --- | --- |
| `OFF` | The standard library, always |
| `ON` | `rapidgzip.IndexedBzip2File` in a child process, or `PackageNotInstalledError` without `rapidgzip`, or `StreamNotSeekableError` on a source that cannot seek (a pipe, or a member stream of an outer archive opened without `seekable_members`), or `ResourceUnavailableError` where no child process can start |
| `AUTO` | The accelerator when seeking was declared (`seekable_members=True`, `open_stream(seekable=True)`), the source is seekable, `rapidgzip` is installed and the compressed input is at least `INDEXED_BZIP2_AUTO_MIN_COMPRESSED_SIZE` (1 MiB) or of unknown size. Otherwise the standard library, silently; where no child process can start, with one warning per process |

The same rules hold for a bzip2 ZIP member or 7z coder, whose data is one stream
(`CodecParams.single_stream`). The standard library stops at the first stream's end, and
the accelerator, which reads on, hands the read over to it where a further stream starts,
so the two agree. A byte of the member after that end, a further stream too, is
`DataAfterEndError` (`StreamConfig.refuse_input_after_end`; [`zip.md`](zip.md) §2.3).

The decoder runs in a child process, as the DEFLATE family's does ([`gzip.md`](gzip.md)
§2.3): `RapidgzipChildStream` with `bzip2=True`, which runs `rapidgzip_worker.py bzip2`. It
has not been seen to abort on a cut or corrupt stream (40 runs of the truncation sweep, the
corpus mutation harness and `scripts/accelerator_crash_search.py` produced Python
exceptions only). It is isolated as a precaution: it comes from the same library as the
DEFLATE decoder, which does abort on input archivey cannot always avoid. Native code alone
is not the reason; the standard library's decoders run in-process. A child that crashes on
the data hands the read to the standard library, like any data error (§2.3 below). The child
costs about 45 ms per stream, which the 1 MiB `AUTO` threshold accounts for: a full read
broke even near 0.6 MiB compressed with 4 cores and near 2 MiB with one
(`scripts/bench_bzip2_child.py`). The guards below sit around the child's stream.

- **A corrupt source must not read as empty.** The bundled decoder returns no output and no
  error for input that is not bzip2 at all: 40 000 zero bytes, a zero-byte file, a bare
  `BZh9`. Its size, compressed position and block offsets for that input are the same as
  for a valid empty stream, so nothing it reports tells them apart.
  `_Bzip2EmptyStreamCheck` therefore hands the first read that comes back empty, before any
  byte was delivered, to the standard library over a fresh view of the source. That engine
  raises for garbage and reads a genuinely empty stream as `b""`. A seek away from 0 before
  the first read disarms the check, but the decoder clamps every seek to 0 on such input, so
  garbage cannot slip past that way.
- **The combined CRC must be checked.** The decoder checks each block's CRC against its
  data, but not the stream's combined CRC, the one check that covers the sequence of
  blocks: a `.bz2` with a whole block cut out read short with no error. At the end of
  data, `_Bzip2EmptyStreamCheck` takes the decoder's index (`block_offsets()`: the bit
  offset of each block and of each end-of-stream marker of a stream with data), reads the
  80 bits of magic and CRC at each from a fresh view of the source, combines the block
  CRCs as bzip2 does (rotate left by one, then XOR) and raises `CorruptionError` where an
  end-of-stream marker disagrees. Nothing is decoded again. A read that stops before the
  end checks nothing, as with the standard library, which checks at the end marker.
- **What the decoder skips between streams must not reach the caller.** The decoder finds
  blocks by their magic, so it passes over junk between a stream header at the start of
  the file and the first block, a stream whose header is damaged, and a stream whose block
  and end-of-stream magics are both damaged, and its output goes on with the next block it
  recognises: three 1000-byte streams with two bytes flipped in the second read as 2000
  bytes with no error. The combined CRC does not see it, since nothing of the skipped
  region is in the index. Before each read returns, `_Bzip2Layout` walks the index built
  so far (`available_block_offsets()`, which forces nothing): the first stream starts at
  byte 0, and each later one where the previous end-of-stream marker ends, rounded up to a
  byte, after nothing but whole empty streams, with its first block right after its 4-byte
  header. A zero byte there does not hold, because the standard library ends the data at
  it (§6). That check is a guard: rapidgzip 0.16 has not been seen to index a block after
  a zero byte. After a stream it stops at the zeros, and a file that starts with zeros
  fails its header check ("Input header is not BZip2 magic string"), which hands the read
  to the standard library. At the first place that does not hold, the read stops at that
  output offset and the standard library takes over there, and raises, reports or reads on
  as it does with the accelerator off. A read that comes back empty is checked too, since
  after a seek to the end it is the only read. More than 1 MiB of empty streams between
  two streams counts as a gap, which only hands the read to the standard library. The walk
  reads 11 bytes per new index entry, and asks for the index only when a read goes past
  the entries already walked and the decoder's compressed position has moved. rapidgzip
  copies its whole index on each such query, so the cost grows with the square of the
  block count: measured on rapidgzip 0.16 with level-1 input (100 kB blocks) read in 64
  KiB pieces, 5% of the read time for 300 MB and 10% for 1 GB. Level 9, bzip2's default,
  has 900 kB blocks, so the same file has a ninth of the blocks. Found by the accelerator
  fuzz targets.
- **Bytes after the last stream must be reported the same way.** The decoder skips them
  and writes a warning to its process's standard error, a temporary file archivey reads
  only to classify a crash, so the warning cannot become a diagnostic. At the end of data,
  `_Bzip2EmptyStreamCheck` asks the decoder for its compressed position
  (`tell_compressed()`, in bits, rounded up to a byte, measured with `parallelization=0`).
  That position is the end of the last stream that produced data, so empty streams after
  it (`bzip2 -c /dev/null` appended to a file) are not counted in it. The check scans a
  fresh view of the source from there. It skips whole empty streams right after that
  position (the `BZh` header, the end-of-stream marker and a zero CRC: 14 bytes), then
  zeros. Zeros that run to the end of the file are padding. Any other byte is reported at
  the offset the standard library engine would: the first non-zero byte. Before the
  empty-stream skip, a trailing empty stream was reported as trailing data under the
  accelerator only. When that byte starts a stream header (`BZh` and a digit 1 to 9) or
  a damaged one with no zero before it, or when one to three zeros before it start a
  damaged one, the decoder stopped short of a stream the standard library decodes or
  rejects (it leaves a cut or damaged stream there alone), so the standard library takes
  over at the end and gives the verdict instead of a trailing-data report. After a zero
  run that does not start a damaged header, a stream header is reported like any other
  byte: both engines stop at the zeros (§6), and rapidgzip 0.16 never reads past them
  (measured with 1 to 70 000 zero bytes before a valid stream).
- **An exception from the caller's source must not abort the process.** `rapidgzip` calls
  `std::terminate` when a Python file object it reads from raises. The child reads the
  caller's stream through this process, and its own source object never raises: a failed
  read is an end of data there, and `RapidgzipChildStream` raises the caller's exception
  when the call ends, unchanged and not translated. The stream is then given up, since the
  decoder took the fault for the end of its input.
- **An unclosed decoder must not abort at shutdown.** `rapidgzip` threads outlive an object
  that was never closed and abort the interpreter at exit. The worker closes its stream
  before it exits and then skips finalization (`os._exit`); this process reaps the child
  when the stream is closed or collected.

The input is also clipped to the coder's packed size (`_bound_rapidgzip_source`), as for
the DEFLATE family. A 7z AES stage decrypts whole blocks, so up to 15 bytes of pad can
follow a coder's data. The 7z reader already cuts each coder's source at its packed size
(measured: an AES and BZip2 folder hands the codec a source that ends at the AES unpack
size), so the clip changes nothing there; it guards a source that is not cut. Without it,
the end check under `refuse_input_after_end` finds the pad and raises `DataAfterEndError`
(`test_bzip2_accelerator_stops_at_the_declared_pack_size`). The standard library engine
has no such clip, so on a source that is not cut it does raise there: see §5.

**Errors through the accelerator.** Its messages carry no exception type archivey can
match on, so `Bzip2Handler._translate_accelerator` matches the text. "Calculated CRC",
"[BZip2 block", "Huffman", "magic", "bit string", "bad optional access", and any
message that contains `std::exception` or "Unknown exception" are `CorruptionError`; each
was seen on a corrupt file. A non-seekable source is `StreamNotSeekableError`.

**The standard library takes over on a data error.** A cut stream is one of those errors:
under the accelerator every cut in the truncation sweep came back as
`RuntimeError("std::exception")`, which says nothing about where the input ended. So any
data error from the accelerator, on a read or a seek, hands the stream to the standard
library (`_StdlibOnAcceleratorError`, as for gzip), which delivers what it delivers with
the accelerator off and raises its error: `TruncatedError` for a cut, `CorruptionError` at
damage. The accelerator decodes ahead of the reader, so on a cut it has usually failed
before the reader got anything, and the takeover starts at the origin. When the reader is
further in, the standard library starts at the newest block at or before it from the
accelerator's index (`available_block_offsets()`, which still answers after the error), and
keeps up to eight such blocks as seek points. A bzip2 block carries nothing from the blocks
before it, so a resume is the compressed bits from the block on, shifted to a byte boundary
behind a made-up `BZh9` header (`bzip2_resume.py`; 9 accepts a block of any level). A
resumed decode that meets its stream's end marker fails the combined CRC, and `bz2`
reports that as it reports a damaged block, so either one starts the decode over from the
origin, which decides. Scanning the source for the block magic instead of reading the index
would find blocks, but not where their output starts, which only decoding everything before
them tells.

### 2.4 Extract

Nothing here is bzip2-specific ([`single-file.md`](single-file.md) §2.4).

### 2.5 Write

Not shipped.

## 3. In the wild

Measured with the tools listed on [`single-file.md`](single-file.md) §3, with the
accelerator `OFF` and `ON`.

| Producer | archivey |
| --- | --- |
| `bzip2` | Reads |
| `pbzip2`, `lbzip2` | Reads, as a run of streams |
| Two `bzip2` files concatenated, nothing between them | Reads both payloads, with the accelerator off and on |
| Two `bzip2` files with zero bytes between them (crafted: no known writer emits this) | Reads the first payload, then `ARCHIVE_TRAILING_DATA` at the second stream's first byte, with the accelerator off, `AUTO` and on; `DiagnosticPolicy.STRICT` raises. The other readers, measured on a stream, 4 zero bytes, a stream: `bzip2`/`bzcat` 1.0.8 and `pbzip2` write the first payload and warn "trailing garbage after EOF ignored"; 7-Zip writes it and reports "There are some data after the end of the payload data"; `lbzip2`, `bsdcat` (libarchive), `unar` and Python's `bz2.decompress` write it and stop silently; rapidgzip's `IndexedBzip2File` writes it and warns "Trailing garbage after EOF ignored!" |
| A stream and empty streams (`bzip2 -c /dev/null`) concatenated, the empty ones before, between or after | Reads, with no diagnostic, with the accelerator off and on. `bzip2 -t` accepts it |
| The same, with zero bytes after the last stream | Reads, with no diagnostic, with the accelerator off and on |
| Zero bytes, then an empty stream | The data ends at the zeros: `ARCHIVE_TRAILING_DATA` at the empty stream, with the accelerator off and on. `bzip2 -t` warns "trailing garbage after EOF ignored" and exits 0: it stops at the first zero byte |
| A stream followed by `junk` | Reads, then `ARCHIVE_TRAILING_DATA` at the same offset with the accelerator off and on. With it on, the decoder process also writes "[Warning] Trailing garbage after EOF ignored!" to its own standard error, a temporary file, so the caller sees nothing. `bzip2 -t` warns and exits 0 |
| A stream cut at any of 20 points | `TruncatedError` after the same bytes with the accelerator off and on. Never a short read with no error |

## 4. Threat surface

bzip2-specific only; the shared items are [`single-file.md`](single-file.md) §4.

- **The accelerator is native code, contained in a child process.** An abort from the bzip2
  decoder costs the stream, and the standard library takes over and gives the verdict
  (§2.3). None has been seen on cut or mutated input. The Atheris `bzip2_accel` target
  fuzzes it through archivey, and `scripts/accelerator_crash_search.py` runs it in-process
  on damaged input to tell whether the isolation is still needed (threat-model O5). A busy
  loop in the child is not bounded by a timeout.
- **A small file costs a whole block.** Each block expands up to 900 kB before the first
  output byte, and detection's inner-TAR probe reads up to 1 MiB of compressed input to
  reach it. Both are bounded by the block size; the detection budget bounds the probe
  (threat-model O11).
- **Garbage must not read as empty.** Covered by `_Bzip2EmptyStreamCheck` (§2.3). Without
  it a corrupt file would pass a read as a valid empty member.

## 5. Sharp edges

*Where it lives*: **format** — inherent, no implementation fixes it · **library** — an
upstream library's behaviour, fixable only there or by replacing it · **archivey** — ours.

| What you see | Where it lives | More |
| --- | --- | --- |
| Each accelerated bzip2 open of a caller's own stream (a file object or `io.BytesIO`) leaks about 1.7 kB of Python objects; every accelerated open, from a path too, leaks a few kB of native memory | **library** | rapidgzip keeps the file object it reads from; archivey frees the caller's stream behind it, so its size does not matter (`known-issues.md` Bug 5) |
| `member.size` is `None` for a `.bz2` | **format** | No size field (§1) |
| Opening a small `.bz2` decodes up to 900 kB | **format** | Open-time validation needs the first block (§1, §2.2) |
| A backward seek re-decodes from the start | **format** | Install `[seekable]` and pass `seekable_members=True` |
| A cold backward seek with the accelerator still re-decodes up to a block, and may log it | **format** | Blocks are the unit of random access |
| A cut or damaged stream right after the data costs a second decode of the file with the accelerator | **archivey** | The accelerator stops before it, and the standard library takes over at the end from the start of the file (§2.3) |
| With `pack_size` declared on a source that is not cut there, the accelerator reads through input after the end that the standard library refuses under `refuse_input_after_end` | **archivey** | Only the accelerator's input is clipped (§2.3). No reader produces that source: the 7z reader cuts each coder's input at its packed size |
| A stream after zero bytes is not read: the first stream's payload, then `ARCHIVE_TRAILING_DATA` | **archivey** | Zeros are padding only at the end of the file (§6), as `bzip2` and 7-Zip read it |
| Reading a large level-1 `.bz2` with the accelerator spends 5 to 10% of the time checking for skipped streams | **archivey** | The check copies the decoder's whole index per batch of blocks (§2.3) |
| Trailing junk after the last stream is a warning | **archivey** | The rule every codec shares ([`single-file.md`](single-file.md) §6); `DiagnosticPolicy.STRICT` raises |

## 6. Decisions

| Choice | Why | Rejected |
| --- | --- | --- |
| The bzip2 accelerator is `rapidgzip`'s bundled decoder (ADR 0008) | `indexed_bzip2` and `rapidgzip` loaded together corrupt the heap on macOS; `rapidgzip` covers both codecs | The separate `indexed_bzip2` package |
| Run the bzip2 accelerator in a child process, like the DEFLATE family (2026-10-10, reversing PR #493) | A precaution: no crash has been seen, but the decoder comes from the same library as the DEFLATE one, whose aborts cannot always be avoided. Isolation is for libraries with observed crashes (rapidgzip, pyppmd), not for native code as such. `scripts/accelerator_crash_search.py` keeps checking whether it is still needed | Keeping it in-process (PR #493); a config option for process isolation, which `use_indexed_bzip2=OFF` already covers |
| Fall back to the standard library on a first empty read (PR #461) | The decoder's own state cannot tell garbage from an empty stream, and an accelerator must not change whether a corrupt source raises | Trusting the empty result; checking the magic by hand, which misses a valid header followed by garbage |
| Serve the caller's source from this process (PR #462 trapped it in-process) | `rapidgzip` terminates the process when a Python source raises; the child's source never raises | Letting the exception cross the native boundary |
| A 1 MiB size threshold for `AUTO` | The child costs a process start; the standard library is slow enough that the child pays for itself from about 1 MiB | No threshold (the in-process decoder cost no start); reusing the 16 MiB DEFLATE gate |
| Let the inner-TAR probe read up to 1 MiB of compressed input, for every codec (PR #32) | bzip2's first output comes only after a whole block; one bound for all codecs needs no per-codec branch | Probing only the detection prefix, which called a `.tar.bz2` with a large first block plain `BZ2` |
| Find the accelerator's end from its compressed position and scan the source | Its warning goes to its process's standard error, a temporary file that cannot become a diagnostic, and the offset must match the standard library engine's | Clipping the source to the end, which is found only by decoding |
| Zero bytes end the data unless they run to the end of the file; what follows them, a valid stream too, is `ARCHIVE_TRAILING_DATA`, in every accelerator mode (maintainer ruling, 2026-10-10) | Match the official tool (DR-6): `bzip2` 1.0.8 stops there, every other reader measured stops there too (§3), and no known writer puts zeros between streams. Nothing hides: what follows is reported, and strict refuses it (DR-3). Zeros at the end stay silent: that is tape and block padding. It also removes a second decode of the file from the start on the accelerated path, which stops at the zeros | Reading on past the zeros, which the standard library engine did and the accelerator matched by handing the end to it (PR #634). The `xz` precedent is weak: the xz format defines padding between streams, bzip2 defines none |
| A stream header right after the data, with no zero before it, hands the end to the standard library | An accelerator changes speed, not behaviour; the 2026-10-03 ruling below applies that to cut and damaged files. The decoder leaves a cut or damaged stream there alone, where the standard library raises | Reporting a damaged stream after the data as trailing data with the accelerator only |
| Check the stream layout from the index before a read returns (`_Bzip2Layout`) | Bytes from after a skipped region must not reach the caller; the index already says where each stream's first block is | Checking at the end of data only, after the wrong bytes were delivered |
| The scan skips whole empty streams right after the data, and zeros only where they run to the end | The compressed position stops before trailing empty streams, and the standard library engine reads them as part of the data | Reading the end from the decoder's block offsets, whose last entry is where an end-of-stream marker starts: undocumented, and it forces the full index |
| On a data error from the accelerator, the standard library takes over and gives the verdict (maintainer ruling, 2026-10-03) | The accelerator must not change what a cut or damaged file delivers or raises; its `std::exception` names no cause | Mapping `std::exception` to `TruncatedError`, which would mislabel damage |
| The takeover resumes at a block from the accelerator's index | A block needs no window; decoding again from the origin costs as much as the bytes already delivered | Scanning the source for the block magic, which gives no decompressed offset |
| Translate the accelerator's errors by message text | They carry no distinct type; each string was seen on a real corrupt file | Treating every `RuntimeError` as corruption, which would hide archivey's own bugs |

## 7. Open questions

- **An upstream report for the garbage-reads-as-empty behaviour.** The workaround is in
  place; no report has been drafted. Tracked internally.

## 8. Verify

```bash
./scripts/test.sh tests/test_single_file.py tests/test_accelerator_corruption.py \
    tests/test_accelerator_truncation_abort.py tests/test_seekable_streams.py \
    tests/test_detection.py tests/test_exception_handlers.py \
    tests/test_stream_trailing_data.py tests/test_accelerator_takeover.py \
    tests/test_bzip2_resume.py -k "bz"
```

| Claim |
| --- |
| Size is `None` before a full read |
| Garbage raises in every accelerator mode; a valid empty stream reads empty |
| A seek before the first read does not bypass the check |
| Empty streams anywhere in the file are data in every accelerator and access mode; bytes after them report at the same offset |
| A stream after zero bytes is trailing data, and strict refuses it, with the accelerator off, `AUTO` and on, for a read and a seek; zeros at the end and streams with nothing between them stay silent; a damaged header after zeros as long as the magic is trailing data too |
| A cut or damaged stream right after the data raises in both modes, a damaged header too, and so do one to three zeros that start a damaged header |
| Junk or a damaged stream before or between streams reads as with the accelerator off |
| A seek gets the verdict a read would, past a skipped stream, into damage, and to the end; at the end of a stream with zero padding after it, what follows the padding is reported, whatever it is |
| A ZIP or 7z coder's single stream reads as with the accelerator off, and bytes after it are `DataAfterEndError` either way |
| Accelerator errors become `CorruptionError`; intact files read clean |
| A cut or damaged stream delivers the same bytes and error with the accelerator off, `AUTO` and `ON`, for a cut in the first block, a later block, the end marker and a second stream; seeks after a takeover |
| A resume from any block reproduces the data and never gives a verdict at the stream's end |
| The caller's source exception reaches the caller unchanged |
| bzip2 runs in a child process; the caller's process never imports rapidgzip |
| A crash of the child on the data hands the read to the standard library |
| `AUTO` uses the accelerator from 1 MiB of compressed input; `ON` uses it at any size; the 1 MiB sits inside the measured break-even |
| The rewind report with the accelerator off; `ON` without the package |
| A `.tar.bz2` with a large first block is found, from a pipe too; a bare one stays `BZ2` |

**Building fixtures.** The standard library writes bzip2 (`bz2.compress`). `pbzip2` and
`lbzip2` install from the distribution.

## 9. References

- The bzip2 format has no formal specification; Joe Tsai's "BZip2 format" notes
  (github.com/dsnet/compress, `doc/bzip2-format.pdf`) describe the block and stream
  layout, and `bzip2` 1.0.8's source is the reference implementation
- [`rapidgzip`](https://github.com/mxmlnkn/rapidgzip), version 0.16, `IndexedBzip2File`
- Registers: [`known-issues.md`](../known-issues.md) (rapidgzip Bug 3) ·
  [`rapidgzip-upstream-report.md`](../investigations/rapidgzip-upstream-report.md) (Bugs 1
  and 2) ·
  [`threat-model.md`](../threat-model.md) O5, O11
- Decisions: [ADR 0008](../decisions/0008-single-accelerator-rapidgzip.md) ·
  [`library-analysis.md`](../library-analysis.md) §bzip2
- Code: `internal/streams/codecs/bzip2_codec.py` (`Bzip2Handler`, `_Bzip2EmptyStreamCheck`),
  `rapidgzip_select.py` (`_bound_rapidgzip_source`, `_open_rapidgzip`),
  `rapidgzip_child.py` (`RapidgzipChildStream`), `rapidgzip_worker.py`
- Handbook: [`single-file.md`](single-file.md) · [`gzip.md`](gzip.md) (the DEFLATE side of
  `rapidgzip`) · [`tar.md`](tar.md) (`.tar.bz2`)
