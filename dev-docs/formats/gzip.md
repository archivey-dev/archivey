# gzip, zlib and raw DEFLATE

Current maintainer truth for the DEFLATE family: gzip (`.gz`) and zlib (`.zz`) as
single-file formats, and raw DEFLATE as the coder inside ZIP and 7z members. All three are
the same compressed format (RFC 1951) in different wrappers, decoded by the same two
backends: the standard library's `zlib`, driven by archivey's own engine, and the optional
`rapidgzip` accelerator, which runs in a child process. What they share with the other
codecs, the one-member reader, the seek table and the truncation contract, is on
[`single-file.md`](single-file.md). Registers keep the status; this page states the
behaviour and links the row.

## At a glance

| | |
| --- | --- |
| Read | gzip and zlib as one-member archives; raw DEFLATE as a ZIP or 7z coder, and inside `.tar.gz` |
| Write | **Not shipped** |
| Backends | The standard library's `zlib` under `DecompressorStream`, always available. `rapidgzip` from `[seekable]`, used when `use_rapidgzip` selects it (§2.3) |
| Seeking | Without `rapidgzip`, a backward seek decodes again from the start, or, on declared seek demand, from the nearest member start: those a forward read has passed, and every member of a BGZF (`bgzip`) file, walked without decoding (§2.3). With `rapidgzip`, from the nearest point of the index it builds while decoding |
| Size | `None`, for both. gzip's ISIZE is the last member's size mod 2³²; zlib has no size field |
| Digests | None listed. Every gzip member's CRC-32 is checked on read, and a zlib stream's Adler-32 too; under `rapidgzip`, archivey checks the Adler-32 when the stream is read to its end (§2.3) |
| Metadata | gzip only: `MTIME` → `modified`, `FNAME` → `raw_name` and `extra["gzip.original_filename"]` |
| Truncation | Always raised by the standard library engine. Through `rapidgzip`, raised by a backstop that runs on the read or seek that meets the end of its output. In a file of several members it stands down only when zlib confirms a further member and the last member's trailer holds the CRC-32 and length of the end of the output (§2.3) |
| Refuses | A member whose method is not 8 (deflate) or whose header sets a reserved FLG bit, as `UnsupportedFeatureError` (gzip: "-- not supported"; `gzip_error`). A zlib stream whose CM is not 8 is `CorruptionError`, not unsupported (`zlib_error`): zlib reports it as damage ("unknown compression method"), RFC 1950 defines no other method, and DR-4 covers only valid features. This changes only if a zlib method other than 8 is ever defined. A zlib stream with a preset dictionary fails to decode, since archivey holds no dictionary |

**Four things a reader might expect and will not find.** The gzip trailer's CRC-32 is not
in `member.hashes`, even for a one-member file: proving there is one member means reading
the whole file (§6). `member.size` is `None` although the trailer holds a size, for the
same reason. With `rapidgzip`, a truncated stream is reported with the same certainty as
without it only for a one-member gzip; a truncated raw DEFLATE stream read alone through
`rapidgzip` under `ON` can come back short with no error (§5). And under `AUTO`,
`rapidgzip` never decodes a stream opened without declared seeking, whatever its size
(§2.3), so a plain open read front to back gets the standard library.

## 1. Shape

Four properties generate most of this page.

```
gzip member:  1f 8b 08 FLG MTIME(4) XFL OS  [FEXTRA][FNAME\0][FCOMMENT\0][FHCRC]
              DEFLATE blocks …  CRC-32(4)  ISIZE(4)          ← repeat for the next member
zlib stream:  CMF FLG [DICTID(4)]  DEFLATE blocks …  Adler-32(4, big-endian)
raw DEFLATE:  DEFLATE blocks …  (the container knows the sizes)
```

**DEFLATE can only be decoded from the start.** Each block may copy from anywhere in the
32 KiB before it, so resuming at a block needs the 32 KiB window that preceded it. Nothing
in the stream records one. So a backward seek decodes again from byte zero unless someone
saved windows on the way; `rapidgzip` does, which is what its index is (§2.3). A new member
starts a fresh window, so a member start is a restart point, and BGZF names every
member's size (§2.3). `pigz -i` resets the window inside one member, which archivey does
not look for (§7).

**A gzip file is a run of members, and nothing counts them.** `cat a.gz b.gz` is a valid
gzip file whose content is both payloads, and bgzip writes every 64 KiB as its own member.
Each trailer covers only its own member: CRC-32 and ISIZE, the size mod 2³². No header says
whether another member follows, and the member magic `1f 8b 08` is three bytes, which a
large compressed body contains by chance about once per 16 MiB. So the file's size and
digest are not in any one place, and are not listed (§6).

**The header carries a name and a time, in the writer's encoding.** `FNAME` is specified as
ISO 8859-1, and GNU gzip writes the filename's bytes as they are, UTF-8 on a modern Linux.
`MTIME` is seconds since 1970, or 0 for none (`gzip -n` writes 0 and no name).

**zlib is DEFLATE with a two-byte header and an Adler-32, and raw DEFLATE is neither.** The
zlib header is not a magic: 66 of the 65 536 two-byte values are legal headers, so detection
decodes to confirm one (§2.1). There is no size field and no defined concatenation. Raw
DEFLATE has no framing at all; its container supplies the compressed and uncompressed sizes
and the CRC, which is what lets `rapidgzip` read it safely (§2.3).

## 2. The pipeline here

### 2.1 Identify

gzip is the magic `1f 8b` at offset 0, reported `CERTAIN`. The inner-TAR probe then decodes
512 bytes and upgrades a match to `TAR_GZ` ([`single-file.md`](single-file.md) §2.1). Both
`.gz` and `.tgz` / `.tar.gz` are registered extensions.

zlib has no magic and is found by a content probe, the second of the three after LZMA Alone.
The probe runs only for a `.zz` or `.zlib` name (or their `.tar.` forms), under
`open_stream`, or with `ArchiveyConfig.always_probe_content`
([`detection.md`](../topics/detection.md) §2.5). It first checks the two header bytes
against the RFC 1950 grammar (`_zlib_header_plausible`): compression method 8, a window of
at most 32 KiB (`CINFO <= 7`), and `(CMF * 256 + FLG) % 31 == 0`. The grammar is stated rather than listed, because a list
of header values is easy to get wrong: the common four leave out six of the seven window
sizes `zlib` will write. The grammar also admits `CINFO = 0`, which `zlib` cannot write.
`FDICT` passes the gate; a stream needing a preset dictionary then fails the decode and falls
through. Only then does the probe decode the sample ([`single-file.md`](single-file.md)
§2.1). A zlib match is `PROBABLE`.

Raw DEFLATE is never detected; it exists only inside a container that names it.

### 2.2 Open and list

`GzipCodec.extract_metadata` reads the first 512 bytes of the source once and takes:

- **`modified`** from `MTIME`, when it is not 0.
- **`raw_name`** as the `FNAME` bytes, and **`extra["gzip.original_filename"]`** as those
  bytes decoded as Latin-1, which is what RFC 1952 specifies. A UTF-8 name therefore reads
  as mojibake there: `café.txt` from GNU gzip is `cafÃ©.txt` (§3). The member's `name` is
  not taken from `FNAME` ([`single-file.md`](single-file.md) §2.4). A name that ends past
  byte 512, behind a large `FEXTRA`, is not reported.

On a non-seekable source those 512 bytes come from `ArchiveSource.peek`, which is
full-count, so a `.gz` under 512 bytes on a held-open pipe waits at `open_archive`
([`topics/detection.md`](../topics/detection.md) §5).

`FCOMMENT`, `XFL`, `OS` and `FEXTRA` subfields (bgzip's `BC` block size among them) are not
reported. `size` is `None` and `hashes` is empty (§6). A zlib stream reports nothing beyond
the shared fields. `compressed_size` is the source's length on a seekable source, and a
member stream's advertised length whether or not that member stream is seekable. It is
`None` on a caller's pipe, also one with a `size` attribute, and on a member stream that
advertises no length (a `.gz` member of another `.gz`, opened with
`open_archive(member_stream)`), since learning it would decompress that member to its end
([`single-file.md`](single-file.md) §2.2).

### 2.3 Member data

**The standard library engine.** `GzipDecompressorStream` is `DecompressorStream` over
`GzipDecoder`: `zlib.decompressobj(16 + MAX_WBITS)`, which parses each member's header and
checks its CRC-32 and ISIZE. It is not `gzip.GzipFile`, because `GzipFile.read()` of a
truncated file discards the prefix it decoded and it validates only on read. After each
member, `1f 8b` right after it starts the next member. NUL bytes are padding when they
run to the end of the file (tape and block padding), as GNU `gzip` reads them. Anything
else ends the stream there, and so does any byte after NULs, a further member too (§6):
every member before it is delivered and the bytes from the first non-NUL one are reported
as `ARCHIVE_TRAILING_DATA` ([`single-file.md`](single-file.md) §2.3). `GzipFile` would
raise on junk, and reads a member after NULs. zlib and raw
DEFLATE use `ZlibDecoder` with `wbits=15` and `-15`. Truncation is certain on this path:
a member that did not reach its trailer arms a `TruncatedError` at the end of input.

**Member starts and BGZF blocks.** On declared seek demand (`seekable_members=True`,
`open_stream(seekable=True)`), `GzipDecoder` records every member after the first as a
seek point once the member has output, so a backward seek after a forward read resumes at
the member before the target. An empty member (BGZF's end marker) shares its offset with
what follows and adds none. A forward seek past the known points or `SEEK_END` walks a
BGZF file (`codecs/bgzf_index.py`): each member's `BC` extra subfield names
its size, and its ISIZE, exact since a member holds at most 64 KiB, its output. The walk
reads the first header (one read buffer's worth) and stops there when the file is not
BGZF; otherwise it reads the file once, front to back in 256 KiB pieces, and inflates
nothing. Jumping from header to header reads fewer bytes only on paper: through the
stream's read buffer (`io.DEFAULT_BUFFER_SIZE`, 8 KiB, 128 KiB from Python 3.14) each
jump refills the buffer, and on a remote source it is one request per member. The walk
stops quietly at the first member without a `BC` subfield (an ordinary gzip member,
trailing data, padding) and keeps the points before it; the size is known only when it
reaches the end of the file, so a BGZF file with NUL padding after it seeks by its
blocks and learns its size by decoding to the end. The sizes are trusted like the xz and lzip
indexes (threat-model O17); a forward read still checks every member's CRC-32 and ISIZE,
and a decode that finds a member at another output offset than the walk gives it, or
reaches the end with another total, drops the walk's points and size
(`SEEK_INDEX_DEGRADED`, scan `decode_check`).
A size query (`try_get_size()`, `ArchiveStream.size`) does not walk, because the walk reads
the whole file and a size query must be cheap (`GzipDecoder.index_reads_whole_source`).
The size is `None`, as for plain gzip, until a seek walks the file or a read reaches the
end. A `.gzi` index is a separate file, which a stream cannot find, so it is not read. Under
`rapidgzip` none of this applies: its own index serves the seeks.

**When `rapidgzip` is used.** `use_rapidgzip` is an `AcceleratorMode`, `AUTO` by default:

| Mode | gzip, zlib, raw DEFLATE |
| --- | --- |
| `OFF` | The standard library engine, always |
| `ON` | `rapidgzip`, whatever the size; `PackageNotInstalledError` without it, `ResourceLimitError` if no child process can start, `StreamNotSeekableError` on a source that cannot seek (a pipe, or a member stream of an outer archive opened without `seekable_members`) |
| `AUTO` | `rapidgzip` only when all hold: seeking was declared (`seekable_members=True`, `open_stream(seekable=True)`), or the read is a large sequential one that pays (below); the source is seekable; `rapidgzip` is installed; the compressed input is not known to be smaller than 16 MiB (`RAPIDGZIP_AUTO_MIN_COMPRESSED_SIZE`; an unknown size counts as large enough, as `AcceleratorMode.AUTO` records); and the decoded length can be checked, either because the container declared it or because a gzip trailer is readable. Otherwise the standard library engine, silently |

The 16 MiB gate is the break-even of the child process: it costs about 45 ms to start and
open (about 25 ms of it starting the child), plus about 70 µs per round trip, which the
parent's read-ahead buffer reduces, and saves about 3.4 ms per MB of compressed input on a
full read, so below about 13 MB the standard library is faster
(`scripts/bench_rapidgzip_child.py`; the numbers are in the design of the archived
`rapidgzip-deflate-child-process` OpenSpec change). The last `AUTO`
condition keeps a bare zlib or raw DEFLATE stream on the standard library: nothing could
catch `rapidgzip` ending a raw DEFLATE stream early, and a zlib stream's Adler-32 is checked
only once the stream is read to its end (below).

**Without declared seeking, `AUTO` uses `rapidgzip` for a large read that pays.**
`rapidgzip` is a member stream's seek machinery here, built on declared seek demand as
xz and lzip build theirs, and also a faster decoder, since it decodes in parallel. So
`AUTO` gives it a read with no declared seeking too (`_sequential_read_pays` in
`codecs/rapidgzip_select.py`), when all of the conditions above hold and also:

- the platform is not Windows;
- the compressed size is known and at least 16 MiB (an unknown size does not count as
  large enough here);
- the data compresses 3:1 or less. The decoded size is the container's (a ZIP or 7z
  member), else the gzip ISIZE trailer, an estimate: it is mod 2**32 and covers only the
  last member, so a file over 4 GiB, or of several members, can be misjudged either way,
  and the cost of that is speed only.

The member stream stays as seekable as it was: an open without `seekable_members=True`
still refuses `seek`. A `streaming=True` open over a file on disk qualifies too, since its
source can seek; one over a pipe does not.

The ratio limit comes from how the child's cost grows: with the bytes it hands back, while
the decoding it saves grows with the bytes it reads. On 4 cores (Linux, 128 MiB decoded,
`ON` against `OFF`, 2026-10-26), a full read under `ON` took 0.32 to 0.52 of the standard
library's time from 1.2:1 to 2.6:1, and the same time at 6.2:1; an earlier run measured a
17:1 log 2.4 times slower. The limit sits below the break-even with a margin, as the
16 MiB gate does.

**Windows.** On a 16-core Windows machine (2026-10-26, rapidgzip 0.16.0, 40 MiB decoded),
`rapidgzip` in process is parallel and fast: from a path or a `BytesIO` alike, its index
has 12 to 29 points, and it reads data compressing 1.5:1 in about 32 ms against zlib's
111 ms. Data compressing 2.9:1 gains nothing (about 100 ms against 110). Through the
child, every full read was slower under `ON` than under `OFF`: a ZIP member 222 against
165 ms (1.5:1) and 240 against 141 ms (2.9:1), a `.gz` 168 against 164 ms and 231 against
137 ms. There the child takes longer to start, always reads its source back through the
parent over a pipe (`OPEN_STREAM`), and is not reused, which costs about 85 to 140 ms per
stream, more than the decode saves at that size. So `AUTO`
keeps sequential reads on the standard library on Windows; a declared seek still gets
`rapidgzip`, whose index is what that open needs. The numbers come from
`scripts/exploration/rapidgzip_platform_probe.py`, which measures the same on any machine.
On the `windows-latest` CI runner a ZIP member's index once had no interior
point at all; that machine's in-process index did, so it is a property of the runner, not
of Windows.

**Why a child process.** `rapidgzip` 0.16 calls `std::terminate` when it decodes a DEFLATE
stream that ends early. The throw comes from a destructor, so it happens for a path, a
file object and a `BytesIO` alike; on an 8 MB gzip, 27 of 30 random cuts aborted the
interpreter, and no `try` can catch it. So gzip, zlib and raw DEFLATE go through
`RapidgzipChildStream` (`internal/streams/codecs/rapidgzip_child.py`), which runs
`rapidgzip_worker.py` in a separate Python (`python -P`, importing nothing from archivey).
The abort then costs the member, not the caller. bzip2 has not been seen to abort, and runs in
the same kind of child anyway ([`bzip2.md`](bzip2.md) §2.3). The child turns off its own core
dumps before it imports `rapidgzip`: an expected abort is no use to anyone as a core, and a crash
handler that `core_pattern` pipes to (apport, systemd-coredump) gets the whole address space,
about 4 GB with every core decoding, whatever `RLIMIT_CORE` says, while the parent waits for it
([`investigations/rapidgzip-worker-deaths.md`](../investigations/rapidgzip-worker-deaths.md)).

What crosses the boundary:

- **Parent to child**: `OPEN` with a path, which the child opens itself, or a request to read
  the parent's stream; then `READ`, `SEEK` and `RESUME` (the nearest index point, for the
  rewind report). Frames are `<BqI>`: tag, argument, payload length.
- **Child to parent**: decoded bytes (at most 1 MiB per round trip, read ahead in 64 KiB
  minimum once reads are sequential), positions, and errors as type name, errno and
  message. When the source is a stream, the child asks the parent for each read, seek and
  tell, and the parent answers from the caller's stream. An exception from that stream
  stays in the parent and is raised to the caller as itself, marked so no translator
  rewrites it.
- **How the child ended**, when it dies: its exit status and its standard error, scanned
  for `rapidgzip`'s abort message. An abort that names the truncation is `TruncatedError`,
  another crash `CorruptionError`, `SIGKILL` `ResourceLimitError` (usually the
  out-of-memory killer), the exit status `MEMORY_LIMIT_EXIT` `ResourceLimitError` (the
  memory cap below), anything else `ReadError`. Every later call raises the same error.

**Memory.** `rapidgzip` keeps decoded chunks in memory, and a chunk is as large as its
output, so its memory follows what the data decodes to: zeros compressed to 255 KB held 285
MB, and a 1 MB file brought in the out-of-memory killer. No `rapidgzip` setting bounds it.
`chunk_size` changed the peak but did not stop it growing with four threads. An
address-space limit (`RLIMIT_AS`, `RLIMIT_DATA`) cannot bound it either: the allocator
reserves about 2 GB of address space before the first byte (1.5 GB with one thread), and a
decode under a smaller limit ends in a segmentation fault. So the child watches its own
peak resident memory once the source is open, from a thread every millisecond and again
before it answers each `READ` or `SEEK`, and exits with `MEMORY_LIMIT_EXIT` when it has
grown by more than `DecoderLimits.max_decoder_memory` (`watch_memory` and `check_memory`
in `rapidgzip_worker.py`). The cap travels at the start of the `OPEN` payload (-1 for
none), so nothing in the caller's environment can set one. The parent marks that death
like a crash on the data, so the standard library takes over from the last index point
and reads the rest in bounded memory. Measured on 64 MiB of zeros, the child's peak was
its start-up memory plus the cap plus about 17 MB, for caps of 8, 16 and 32 MiB; without a
cap it was 87 MB. On a busy machine the watching thread can wait for a processor; the
check before the next `READ` or `SEEK` reply then stops the child, so no reply to a
request that decodes leaves it once its peak is past the cap. Ordinary data on four
threads held about 55 MB over start-up, so the 2 GiB default leaves room for about 140
threads. The peak is read from `VmHWM` in `/proc/self/status` (Linux), `getrusage` (macOS,
the BSDs) or `GetProcessMemoryInfo` (Windows); where none works, no cap applies. Not
`getrusage` on Linux: there a child's `ru_maxrss` starts at its parent's peak, because
`exec` keeps the high-water mark of the memory it replaces. A parent that had once held
more than the child's decode plus the cap left the child never stopped.

Where no child can start — a frozen application, no `sys.executable`, archivey imported
from a zip so the worker is not a file, or a spawn or temporary file the system refuses —
`AUTO` uses the standard library and logs one warning per process on the `archivey.streams`
logger; `ON` raises `ResourceLimitError`.

**Truncation through `rapidgzip`.** Besides aborting, `rapidgzip` often ends a truncated
stream softly, by design: `read()` returns `b""` or a prefix with no error. For a gzip
source that is seekable, two layers back it up. Item 1 is done by
`_StdlibOnAcceleratorError` on a read (its `empty_to_stdlib` switch), and by
`_GzipTruncationCheckStream` above it on a seek that meets the end of an empty output,
which issues no read (`_settle_end`). `_GzipTruncationCheckStream` does the rest:

1. If the stream ends before a single byte came out, the reader switches to the standard
   library engine over a fresh view of the source, which recovers the prefix and raises.
2. If it ends after some bytes, the reader first asks `rapidgzip` how far into the source
   it decoded. A decode that stopped short of the end hands the rest of the read to the
   standard library engine. This is what tells a member cut short and followed by a
   complete one from a multi-member file: there the trailer and the further member are
   both real, but `rapidgzip` stopped at the cut and never decoded the rest. Otherwise the
   trailer is looked for in the file: the CRC-32 of the output, which the reader keeps as
   the output goes by, and its length mod 2³², ending the file but for zero padding. The
   trailer is the one place near the end where that CRC-32 occurs: the reader looks from
   72 bytes before the end of the non-zero data to 12 bytes after it, and finds the
   trailer only when the CRC-32 occurs there once, followed by the length. A forged copy
   of the eight bytes, appended after a wrong trailer (even bytes equal to the length),
   overlapping it, or reaching back into the compressed data (a stored block ends with the
   payload's own bytes), leaves the real CRC-32 as a second occurrence, and is turned
   down. The CRC-32 is no obstacle to a forger, who can set it with four chosen bytes of
   payload, so the rule does not lean on it being unlikely. Not excluded: a copy more than
   56 bytes after the end of the real trailer. `rapidgzip` would have to read past that
   many bytes that are not a further member without an error, and `rapidgzip` 0.16 raises
   on ten or more, which hands the read to the standard library engine. A real trailer
   turned down, when its CRC-32 occurs a second time by chance (about one file in 2²⁵) or
   is zero with padding after it, goes to the standard library engine too, which finds
   nothing wrong. Only when a seek short of the end skipped output and a read then met the
   end, so that there is no CRC-32 of that output, is the ISIZE trailer read at open (the
   file's last four bytes) compared with the length instead, and a match counts only when
   no further member is found; with one, the last member's trailer is checked as below,
   since four bytes equal to the length do not show that the last member is whole. A
   mismatch hands the rest of the read to the standard library engine, which raises the
   truncation, raises the checksum error for a wrong ISIZE, or reports bytes appended to
   the file. The exception is a file with a further member: its trailer is only the last
   member's, so a mismatch is expected, and nothing is raised when that trailer checks out
   against the end of the output (below). `gzip_has_additional_member` decides whether
   there is a further member.
   It looks for `1f 8b 08` after offset 0, and since those three bytes turn up by chance in
   a compressed body about once per 16 MiB, it hands each match to zlib's gzip decoder. The
   match counts only if zlib accepts the header (method, reserved `FLG` bits, `FHCRC`) and
   then reaches the member's end with its CRC-32 and ISIZE right, or decodes 64 KiB of
   input or 1 MiB of output with no error. Random bytes fail within a few hundred DEFLATE
   symbols. A match the file ends inside does not count: a real member cut there is a
   truncation. This scan was chosen over handing every mismatch to the standard library,
   because a multi-member file (bgzip writes one member per 64 KiB) always mismatches, and
   the handover would decode it a second time from the start.

   A further member says nothing about the last one, so the last member's trailer is
   checked too (`_last_member_ends_the_file`). `rapidgzip` ends a last member cut right
   after its header with no error, and its compressed position is then the end of the
   file; with a confirmed member before it, such a file used to read short with no error
   (found by the `gzip_accel` fuzz target, a third member cut after its 10-byte header).
   The trailer's length `n` says where the last member's output starts, `n` bytes before
   the end, and the CRC-32 of the output from there is compared with the trailer's. The
   trailer ends at the end of the non-zero data or up to 3 bytes into the zeros after it:
   its last bytes are the high bytes of ISIZE, which is not zero for a member this checks.
   Each of those four places is a candidate. Candidates are tried shortest first, and the
   first match ends the search. An empty last member, bgzip's end-of-file member, has
   eight zeros for a trailer, which any zeros would match, so it counts only when zlib
   decodes an empty member from a header in the 1 KiB before the end of the non-zero data
   with only zeros after it; one whose header starts further back (a long `FNAME`) goes to
   the standard library engine, which reads it with no error. This needs no member
   boundaries, which `rapidgzip` does not report (§7).

   The candidate's CRC-32 comes from the running CRC-32 of the output, not from a second
   decode of the member. The reader saves that CRC-32 every 4 MiB of output
   (`_CRC_CHECKPOINT_SPACING`, in `_CheckpointedCrc`). With `C(x)` the CRC-32 of `x` and
   the output `A + B`, `B` the candidate's last `n` bytes, `C(B)` is
   `C(A + B) ^ crc32_combine(C(A), 0, len(B))`; `C(A)` is the checkpoint at or before the
   candidate's start carried on to it by reading back less than 4 MiB from `rapidgzip`, or,
   when `B` is shorter than that, `B` itself is read back. So each candidate costs a
   read-back of at most 4 MiB, and at most four candidates are checked, whatever the size
   of the last member or the length a forged trailer states. A valid file of any size is
   decided without the standard library engine, and a file that fails the check costs at
   most four such read-backs before the standard library's decode. A BGZF file pays
   nothing, as its last member is empty. The spacing is our own, not `rapidgzip`'s seek
   points: those are sparse (only the start and the end at `parallelization=0`, §7), built
   ahead of the reader in the child process, a round trip to read, and a point the reader
   has already passed has no CRC-32 saved for it. The read-back itself is a backward seek
   in `rapidgzip`, which decodes from its own index point before the target, so its cost
   still depends on `rapidgzip`'s chunk spacing. A last member of 4 GiB or more does not
   match, as its length wraps, and goes to the standard library engine, which reads it
   right at the cost of a second decode. Not excluded: a crafted cut whose last eight bytes
   are made the CRC-32 and length of the end of the output, which takes choosing four
   bytes of the content.

   After a seek short of the end skipped output, the check still runs, at the cost of
   reading back the skipped part of the last member. The reader starts a second CRC-32,
   with its own checkpoints, where reading resumed (restarted by each later skip), so a
   candidate that starts after that point is checked as above. For one that starts before
   it, the output from the candidate's start to the resume point is read back from
   `rapidgzip`, and its CRC-32 is combined with the one kept since. That read-back has a
   ceiling of 64 MiB in all (`_SKIPPED_READ_BACK`): a candidate past what is left of it
   hands the read to the standard library engine, which gives the right result at the
   cost of a second decode. Nothing is accepted unchecked, so the accelerator gives the
   standard library's verdict after a seek too. A seek to the end (`SEEK_END`), or one
   that `rapidgzip` clamped, reads the output through from the CRC-32 frontier first; a
   `SEEK_SET` to exactly the length of the output is neither, and the read after it runs
   the check with no CRC-32 kept since, reading each candidate back from its start under
   the same ceiling.
3. A source shorter than 18 bytes that still yielded bytes is handed to the standard
   library engine as well, which raises the truncation. A source whose length cannot be
   read is never called truncated.

The check runs once, on the first read or seek that meets the end of `rapidgzip`'s output,
and is spent after it: no later read or seek runs it again. A seek back to the start, or a
forward seek short of the end, leaves it armed. It compares the position at the end, not a
count of the bytes delivered: a read that meets the end is at the output's length whatever
seeks came before (`rapidgzip` clamps a seek past the end to the end, and
`_StdlibSeekContract` keeps the caller's position). A seek that stops at the end of
`rapidgzip`'s output (a seek to the end, or one `rapidgzip` clamped) runs the check there,
so `seek(0, SEEK_END)` on a cut file raises as it does with the accelerator off rather than
return `rapidgzip`'s short length. That seek first reads the output from the CRC-32
frontier to the end, so the check finds the trailer by its CRC-32, as a read does, not by
the four-byte ISIZE comparison that a forged trailer passes. A size query on a gzip not yet
read so moves the whole decompressed output out of the child once. When the standard
library engine takes over, at the check or during that read, it seeks to the caller's
target, so a read after a seek past the end never returns bytes from another offset. The
raw DEFLATE end check (§2.3, *Other `rapidgzip` workarounds*) and bzip2 do the same at the
end, without the read-through: neither checks a checksum of the output, so output a seek
skipped leaves their checks whole. Once the standard library engine has raised, it raises
again at every later end of data. A container member does not need the check: the container
declared the size, and `VerifyingStream` checks length and CRC. A bare zlib or raw DEFLATE
stream has neither, which is why `AUTO` never gives one to `rapidgzip`.

**The zlib Adler-32 check.** `rapidgzip` does not check a zlib stream's Adler-32: a damaged
body or trailer decodes with no error, sometimes short. `_ZlibAdlerCheckStream` keeps an
Adler-32 of the output from offset 0 up to a frontier and compares it with the source's last
four bytes when the frontier reaches the end. A seek back stays behind the frontier, and a
seek forward past it reads the bytes in between, so the check survives the TAR reader, which
skips member data by seeking. The child decodes those bytes to seek past them anyway; the
read-through adds their transfer out of it. For a reader that only skips, that transfer is
the whole cost: listing a `.tar.zz` under `ON` moves the full decompressed archive out of
the child once, where the seeks alone moved nothing. A mismatch is either damage or several zlib
streams one after another (`rapidgzip` reads all of them; the trailer is the last one's), so
the standard library then decodes the source again. It reads the first stream only, as it
does with the accelerator off, where the rest is trailing data. When that stream ends
before the output `rapidgzip` delivered, and the caller has none of the bytes past its
end, the read goes to the standard library at the end of the first stream: a completing
`read()` returns the first stream's bytes, a seek to the end lands there, and the rest is
reported as `ARCHIVE_TRAILING_DATA`, as with `use_rapidgzip=OFF`. A caller that read on in
bounded reads already has bytes of the second stream when the end shows up, and they
cannot be taken back; there the decode goes on stream by stream up to the delivered length,
and that output is accepted (§5). Whichever decode runs must reproduce the delivered
bytes; failing that, the read or seek that reached the end raises `_StreamChecksumError`, a
`CorruptionError`. The TAR end-of-archive scan, which otherwise
ignores a tail that fails to decode, re-raises it, because the checksum covers members it
already handed out. A stream never read to its end is not checked, and the standard library
does not check one either: it verifies the trailer only when it consumes the end.

A cut zlib stream is the third cause of a mismatch: `rapidgzip` reads a stream cut inside
its body as a shorter whole one, with no error, and sometimes stops before output the
standard library still decodes (a cut 200 bytes in gave nothing where the standard library
gave 582 bytes). When the standard library's decode agrees with every byte delivered and
then has more output, or runs out of source inside the stream, the read goes to the
standard library at the delivered position (`switch_to_stdlib`), so the bytes and the
`TruncatedError` are those of `use_rapidgzip=OFF` (maintainer ruling, 2026-10-03). One
exception remains: with a container-declared size, the read that reaches it is the
`VerifyingStream`'s verifying event, and when its probe past the size meets a cut Adler-32
that read's chunk is withheld, as any failed verifying event withholds its chunk.

**What of a cut stream a caller gets back.** The same bytes with `rapidgzip` as without it.
The standard library engine delivers everything up to the last complete block before the
cut. `rapidgzip` decodes ahead in parallel, so it can reach the cut and abort while the
parent is still waiting for earlier bytes: measured on 4 cores, a cut 154 MB gzip gave
nothing before the abort where the standard library gave 20 MB, and the loss grows with the
thread count. So a crash of the child, like a data error it reports, hands the read to the
standard library (`_StdlibOnAcceleratorError`), which starts at the child's `resume_point`
rather than at the start of the stream: a DEFLATE block boundary from `rapidgzip`'s index
at or before what the caller has read, with the 32 KiB of output before it. The child keeps
the last four such points, because the newest can be ahead of the caller: by the read-ahead
buffer, or after a seek back. `deflate_resume.py` makes zlib start there: the window goes
in as a preset dictionary, and the block's bit offset is reached by starting the input with
empty blocks whose length ends that many bits into a byte. The second decode then costs the
distance from that point to the cut, not the file: at most `rapidgzip`'s read-ahead, plus
the spacing of the index queries, plus the spacing of the points. The child queries its
index once the output has passed the point the last query named and run on by 16 KiB per
point it holds (4 MiB at least), which keeps the queries' cost a small share of the decode.
A resumed decode that reaches the end of its DEFLATE stream cannot check the CRC-32 or
Adler-32 after it, so it starts over from the start of the stream, which checks it.

**The first member's header is checked before `rapidgzip`.** `rapidgzip` accepts a header
CRC (`FHCRC`) that does not match and reserved `FLG` bits, which RFC 1952 §2.3.1.2 says a
decoder must refuse. Before starting it, `_gzip_header_refused` feeds the source to a zlib
gzip window until the first byte of output; if zlib refuses, the stream opens on the
standard library engine instead, which raises the same error on the first read as with the
accelerator off. That probe sees only the first member, because `rapidgzip` does not say
where later members start. A later member that zlib would refuse still raises on the read:
`rapidgzip` 0.16 rejects a later header CRC itself, and a later reserved flag is not accepted as
a further member by the scan, so the trailer check hands the read to zlib (§5).

**A wrong ISIZE on a member before the last reads under `rapidgzip`.** It checks every
member's CRC-32 but not the ISIZE of one that another member follows, where zlib raises
"incorrect length check". With each member's output under its CRC, a wrong ISIZE there is
a malformed trailer, not damaged data, and `compressed-streams` lets the accelerator read
it (*An accelerator preserves the error contract*).

**Other `rapidgzip` workarounds.** Its input is clipped to the known compressed length
(`_bound_rapidgzip_source`), because it reads past the end of a raw DEFLATE stream looking
for another member, and a 7z AES stage's padding would look like one. Inside that bound it
still reads on past the stream's final block, where zlib stops, so a raw DEFLATE stream
finishes on the standard library engine (`_StdlibOnAcceleratorError`) when `rapidgzip`
fails on data or its output passes the size the container declared. Its error messages
differ by platform (ISA-L on Linux, a different decoder on macOS, a bare
`RuntimeError("Unknown exception")` for a near-end truncation on Windows), and
`_translate_rapidgzip` maps each; the Windows one becomes `CorruptionError`, not
`TruncatedError`, since the detail is lost.

**`rapidgzip` is told no format.** It looks at the first bytes and tries a gzip member, a
zlib stream, a bzip2 stream and then raw DEFLATE, in that order. So a raw DEFLATE source
that starts with `1f 8b`, a zlib header or `BZh` and a digit, and a zlib source whose
header `rapidgzip` does not take for zlib (none at all, or one with a preset dictionary),
decode with the standard library engine, which raises at the header as it does with the
accelerator off (`_rapidgzip_may_read_as_another_format`, `_rapidgzip_reads_as_zlib`). No
encoder starts raw DEFLATE like zlib: that first byte is a stored block with nonzero
padding bits. `BZh` and a digit is a possible start, so a real raw DEFLATE stream that
has it decodes without the accelerator. `rapidgzip` also ends a raw DEFLATE stream cut
before any output (`03`, a final block with no end code) softly, as if it were empty, so
a raw DEFLATE stream that ends before its first byte goes to the standard library too,
which reads a valid empty stream as empty and raises on a cut one. Where `rapidgzip`'s
output of a raw DEFLATE stream ends, zlib checks that the stream reaches a final block
(`_DeflateEndCheckStream`), on the read or the seek that reaches that end. The standard
library DEFLATE-family decoders raise archivey's typed errors themselves, after a takeover
or with no accelerator at all, so the over-run probe of a declared size raises on a damaged
body past that size and does not take the error for the end of the data. A ZIP member
declared empty with a body that is not DEFLATE raises `CorruptionError`. The accelerator
fuzz targets found all three.

**Every accelerator object is closed, never only joined.** `rapidgzip`'s C++ worker
threads call `std::terminate` if they are still running at interpreter finalization, and
only `close()` stops them. Only the worker process holds rapidgzip objects, and it closes
its stream before it exits, then skips finalization (`os._exit`). The measurements and the canary
that watches for an upstream fix are in
[`rapidgzip-upstream-report.md`](../investigations/rapidgzip-upstream-report.md) §6.

**Bytes after the stream under `rapidgzip`.** `rapidgzip` has no end of stream: it takes
bytes after a gzip member for the start of another and fails on them, or, in the child,
delivers the payload and then takes the file's last four bytes, now junk, for ISIZE. Both
cases switch to the standard library engine at the position already delivered
(`_StdlibOnAcceleratorError` in `internal/streams/codecs/stdlib_takeover.py`): a data error from
`rapidgzip` does it inside the read or a seek, and an ISIZE mismatch with no confirmed
further member does it through the truncation check. A seek meets these errors too:
`rapidgzip`'s seek through a valid file with NUL padding after it fails on the padding,
which `gzip -t` and the standard library accept, so a seek that fails on data switches as
a read does. NULs followed by a further member are the same case: `rapidgzip` raises
"Invalid gzip/zlib wrapper" there, and the standard library ends the data at the NULs and
reports the member as trailing data (§6). The standard library engine then decodes
the rest and finds the junk or the cut, so a file with bytes after it reads in full and
reports once, and a truncated one still raises `TruncatedError`. The switch decodes again
from the start of the stream up to that position; it is paid only by a file that fails
under `rapidgzip`.

### 2.4 Extract

Nothing here is gzip-specific ([`single-file.md`](single-file.md) §2.4).

### 2.5 Write

Not shipped.

## 3. In the wild

Measured with the tools listed on [`single-file.md`](single-file.md) §3.

| Producer | archivey |
| --- | --- |
| `gzip` | Reads; `FNAME` and `MTIME` reported |
| `gzip -n` | Reads; no name, `modified=None` |
| `pigz`, `pigz -i` | Reads. `-i` resets the window at each block, which archivey does not use for seeking |
| `bgzip` (BGZF, the genomics format) | Reads, as a run of 64 KiB members; no `FNAME`. On declared seek demand the block size in `FEXTRA` gives a seek point per member (§2.3) |
| Two `gzip` files concatenated | Reads both payloads |
| A member followed by NUL padding | Reads; the padding is skipped. GNU `gzip -dc` does the same, silently |
| A member, 4 NUL bytes, a member (crafted: no known writer emits this) | Reads the first payload, then `ARCHIVE_TRAILING_DATA` at the second member's first byte, with or without `rapidgzip`; `DiagnosticPolicy.STRICT` raises. GNU `gzip -dc` writes the first payload, warns "decompression OK, trailing garbage ignored" and exits 0. 7-Zip and `bsdcat` stop after the first member; `rapidgzip` raises "Invalid gzip/zlib wrapper". Python's `gzip` reads both members (§6) |
| A member followed by `junk` | Reads the whole payload, then `ARCHIVE_TRAILING_DATA`, with or without `rapidgzip`. `gzip -t` calls it "trailing garbage ignored" and exits 2 |
| GNU gzip of `café.txt` | `extra["gzip.original_filename"] == "cafÃ©.txt"`, `raw_name == b"caf\xc3\xa9.txt"` |
| `zlib.compress` | Detected by the probe, `PROBABLE`; reads |

**Large `.gz` files contain the member magic by chance.** A body of hundreds of MiB almost
always contains `1f 8b 08` somewhere. That is why the rapidgzip backstop's scan has zlib
confirm each match before it takes the file for multi-member (§2.3), and why archivey does
not try to prove a single member at open (§6).

## 4. Threat surface

gzip-specific only; the shared items are [`single-file.md`](single-file.md) §4.

- **`rapidgzip` is native code outside the defended surface.** It aborts on a truncated
  stream (contained by the child process), and the mutation harness found it busy-looping
  on crafted input. A loop in the child is still a loop: there is no timeout. The Atheris
  `gzip_accel`, `zlib_accel` and `deflate_accel` targets fuzz it under libFuzzer's own
  timeout, and `SECURITY.md` tells callers with a latency budget to keep it off for
  untrusted input (threat-model O5).
- **The ISIZE backstop trusts the trailer, but only after a decode to the end.** A crafted
  file whose ISIZE matches the bytes `rapidgzip` delivered before a soft end used to pass;
  the compressed-position check now hands it to the standard library engine. Within a
  decode that did reach the end, a wrong ISIZE on a member before the last still passes
  (§5), with every member's CRC-32 checked. A wrong ISIZE or a cut on the last member does
  not, in a file of one member or of several: there the last member's trailer is checked
  against the CRC-32 of the end of the output, from saved CRC-32 checkpoints (§2.3). A
  crafted cut can still pass, by making the last eight bytes of the cut file the CRC-32
  and length of the end of the output.
- **The trailer lookup folds a CRC-32 over the whole output.** The reader keeps it as the
  output goes by, on the reader's thread while `rapidgzip` decodes on others, and compares
  it at the end with the eight bytes that end the file but for zero padding (§2.3). That is
  the option `gzip-padded-isize-accepted` declined as too costly ("the CRC-32 of the
  output, or a second decode"); it is the cheaper of the two. `zlib.crc32` runs at about
  3.3 GB/s on the machine measured, 0.056 s per 184 MB of output, which was 6% to 15% of
  a full accelerated read of 184 MB from a 33 MB `.gz` with four cores (0.50-0.66 s
  without it; the share is higher on a faster decoder or more cores, and the figures are
  noisy). It is paid once per stream read to its end, and not after a seek that skipped
  output. The end of the file is read in 96 bytes, and further back only over padding.
  Nothing in the benchmark gates holds this number (`targz_read_all_accel_on` is a
  structural case of 131072 bytes).
- **The multi-member scan reads the whole file.** When ISIZE disagrees, the backstop scans
  forward for a member magic in 1 MiB blocks, on an independent view, and has zlib decode
  from each match, at most 64 KiB of input and 1 MiB of output. It runs once per stream,
  at the end. The matches share a decode budget of 1 MiB plus one sixteenth of the bytes
  scanned, so a file built with a header zlib accepts every few bytes costs a bounded share
  of the scan; one that spends it is handed to the standard library engine, which decides.
- **`FNAME` is attacker-chosen bytes.** It is reported, never used as a path.
- **A source of back-to-back gzip headers** gives the SFX scan a candidate at every offset.
  The candidate search is linear in the source, and per-candidate decoding is bounded by
  the detection budget (threat-model O11).

## 5. Sharp edges

*Where it lives*: **format** — inherent, no implementation fixes it · **library** — an
upstream library's behaviour, fixable only there or by replacing it · **archivey** — ours.

| What you see | Where it lives | More |
| --- | --- | --- |
| `member.size` is `None` and `hashes` is empty for a `.gz` whose trailer holds both | **format** / **archivey** | The trailer describes the last member only (§1); decided in PR #441 (§6) |
| `extra["gzip.original_filename"]` is mojibake for a non-ASCII name | **format** | RFC 1952 says Latin-1; GNU gzip writes the bytes it was given. `raw_name` has them |
| A backward seek on a single-member `.gz` re-decodes from the start | **format** | No restart points (§1). Install `[seekable]` and pass `seekable_members=True`; under `AUTO`, only from 16 MiB |
| The same truncated `.gz` raises `TruncatedError` on Linux and `CorruptionError` on Windows under `rapidgzip` | **library** | Windows loses the message detail (§2.3). Catch `ReadError` for both |
| A multi-member `.gz` read through `rapidgzip` reads back up to 4 MiB of output at the end | **archivey** | The backstop checks the last member's trailer (§2.3), as `rapidgzip` ends a cut last member softly. The member's CRC-32 comes from CRC-32 checkpoints saved every 4 MiB, so each of at most four candidates costs a read-back of under 4 MiB, whatever the member's size. A BGZF file pays nothing. After a seek that skipped output, the skipped part of the last member is read back too, up to 64 MiB in all; past that the standard library engine decodes the whole file a second time |
| A member after the first with a header CRC that does not match, or with reserved `FLG` bits, raises the same error with `rapidgzip` as without it | **archivey** | Measured on rapidgzip 0.16.0 (2026-10-18). A later header CRC makes rapidgzip raise, and the read falls back to zlib (`CorruptionError`). A later reserved flag is accepted by rapidgzip, but the further-member scan skips that header, the single-member trailer check fails, and the read falls back to zlib (`UnsupportedFeatureError`). The pre-start probe still sees only the first member (§2.3) |
| A wrong ISIZE on any member but the last reads clean under `rapidgzip` builds that do not compare the size; the standard library raises | **library** / **archivey** | Every member's CRC-32 is still checked, so the data is right; the spec accepts this difference (§2.3). `rapidgzip` 0.16.0 compares it only in its own chunk decoder, for a stream that lies wholly in one chunk; the inflate-wrapper decoder (ISA-L, in the Linux wheels) appends the footer without comparing. The last member's ISIZE is checked by the backstop, which finds the trailer by the CRC-32 of the output, or in a file of several members by the CRC-32 of the end of the output. After a seek that skipped output there is no CRC-32 and the file's last four bytes stand in for the ISIZE in a file of one member; in that case only, four bytes appended after a wrong ISIZE, equal to the length, pass for the trailer. In a file with a further member the last member's trailer is checked whatever the last four bytes say. Found by the `gzip_accel` fuzz target |
| A truncated bare raw DEFLATE stream under `use_rapidgzip=ON` can end short with no error | **library** | No size or checksum to check it against (§2.3). `AUTO` never does this. A stream cut before its first byte of output raises, as with the accelerator off |
| `rapidgzip` does not check a zlib stream's Adler-32 | **library** | archivey checks it after `rapidgzip`, once the stream is read to its end (§2.3) |
| Several zlib streams one after another, read in bounded reads to the end under `use_rapidgzip=ON`, read as one; the standard library reads the first alone and reports the rest as bytes after the stream | **library** | RFC 1950 defines one stream per file. A completing `read()` and a seek to the end stop at the first stream as with the accelerator off; bounded reads have the second stream's bytes before the end shows up, and the Adler-32 check accepts them when the standard library reproduces them stream by stream (§2.3), so they get those bytes as content and no `ARCHIVE_TRAILING_DATA` |
| Trailing junk after a `.gz` is a warning, where `GzipFile` raises | **archivey** | The rule is shared by every codec ([`single-file.md`](single-file.md) §6); `DiagnosticPolicy.STRICT` raises |
| A `.gz` with bytes after it under `rapidgzip` decodes part of the file twice | **archivey** | The switch to the standard library replays up to where `rapidgzip` failed (§2.3); a resumed replay that reaches a member's end starts over to check its CRC-32 |
| One warning on `archivey.streams` that `rapidgzip` cannot run | **archivey** | No child process can start here; `AUTO` used the standard library. `use_rapidgzip=OFF` silences it |
| A zlib stream with a preset dictionary is not detected, and fails when opened by name | **format** | archivey holds no dictionary |
| A large `.gz` opened without `seekable_members=True` is no faster with `[seekable]` installed | **archivey** | Without declared seeking, `AUTO` uses `rapidgzip` only from 16 MiB, at 3:1 or less, and not on Windows (§2.3). Declare seeking, or set `use_rapidgzip=ON` |
| A cold backward seek under `rapidgzip` still re-decodes megabytes, and the log says so | **library** | Its index is sparse: three points over 5 MB of `gzip.compress` output |

## 6. Decisions

| Choice | Why | Rejected |
| --- | --- | --- |
| Never list the gzip trailer CRC-32 (PR #441) | A digest is worth having to skip a decode or to verify one. The trailer covers only the last member, proving there is one member means reading the whole file at every open (a full download for a remote source), the chance magic made large files "multi-member" anyway, and after a read the decoder has already checked every CRC | Scanning for a second member at open; adding the CRC after a full read, which changes `hashes` under a caller who already read it |
| Decode with `zlib`'s gzip window under archivey's engine, not `gzip.GzipFile` (PR #183) | Sized reads recover the prefix of a truncated file, and the engine's seek table and rewind report apply | `GzipFile`, which drops the prefix on `read()` and cannot report rewinds |
| After a member, `1f 8b` starts the next member; NULs are padding only when they run to the end of the file; any other byte, and any byte after NULs, a member too, ends the data and is reported (maintainer ruling, 2026-10-10) | Match the official tool (DR-6): GNU `gzip` stops at NULs before a member with "trailing garbage ignored", and 7-Zip, `bsdcat` and `rapidgzip` stop there too. No known writer emits the shape. Bytes after the data follow the rule every codec shares ([`single-file.md`](single-file.md) §6). Python's `gzip` is the one reader that reads on: `GzipFile._read_eof` skips NULs one byte at a time with no limit, and `gzip.decompress` strips them from `unused_data[8:]`, then both read a further member. Its comment says gzip files "can be padded with zeroes and still have archives" and cites the gzip.org FAQ 8 page, which is no longer reachable. That FAQ was about tape and block padding at the end of a file (`tar` and `dd` pad to a block size), which GNU `gzip` accepts silently and archivey does too; a member after the NULs is beyond what it describes | Raising on junk, as `GzipFile` does; reading a member after NULs, as Python's `gzip` does |
| Switch to the standard library when `rapidgzip` fails on bytes after the stream | `rapidgzip` cannot tell junk from a next member or from damage; the standard library can | Refusing the file under `rapidgzip`, so the result would depend on the accelerator |
| One accelerator library, `rapidgzip`, for gzip, zlib, raw DEFLATE and bzip2 (ADR 0008) | `indexed_gzip` or `indexed_bzip2` next to it corrupt the heap on macOS | Several accelerator packages |
| Run `rapidgzip` in a child process for the DEFLATE family (PR #493) | Its abort on a cut stream is uncatchable in-process | In-process with guards, which cannot catch `std::terminate`; decoding with the standard library first and handing `rapidgzip` only proven input, which decoded the whole member at the first backward seek |
| `AUTO` needs 16 MiB of input and a checkable size | Below that the child costs more than it saves; without a size, a soft end would pass silently | 1 MiB, the in-process threshold; `AUTO` on any declared seek, with no size gate |
| `AUTO` uses `rapidgzip` for declared-seekable streams (the concurrent-member-streams change, PR #59), and for a sequential read from 16 MiB at 3:1 or less, except on Windows (maintainer ruling, 2026-10-26) | Seek machinery is built on declared demand, for every codec; the parallel decode pays on a full read only for data that is not very compressible, and on Windows the child costs more than it saves | `AUTO` keyed on the `streaming` access mode; sequential `AUTO` at any ratio, which is up to 2.4 times slower on very compressible data; sequential `AUTO` on Windows too |
| `AUTO` falls back to the standard library with one log warning where no child can start | The accelerator is an enhancement; a frozen application must still read `.gz` | Raising, which `ON` does |
| Report `FNAME` decoded as Latin-1, keep the bytes in `raw_name` | RFC 1952 says so, and the bytes are there for a caller who knows better | Guessing UTF-8 |
| Member starts as seek points, and a BGZF walk by `BC` subfields, on declared seek demand | A member start is an exact restart point; BGZF names every member's size, so seeking needs no `rapidgzip` for the most common blocked gzip | A `BgzfDecompressorStream` of its own, as first proposed; reading `.gzi` files, which a stream cannot locate |

## 7. Open questions

- **Summing ISIZE per member.** The last member's trailer is checked (§2.3); this would
  add the ISIZE of each member before it, which `rapidgzip` does not compare, but needs
  the member boundaries, which `rapidgzip`'s index does not expose; a byte walk of the
  headers is the only way. Tracked internally.
  Measured on 0.16.0 with 2- and 3-member files of distinct member sizes, read to the end:
  `block_offsets()` and `available_block_offsets()` hold seek points chosen for chunked
  random access, and no member start appears among them at any `parallelization`. With
  `parallelization=0`, archivey's setting, they hold only the start and the end of the
  stream; other settings add mid-member chunk points unrelated to member starts. There is no member or stream count accessor either:
  `add_deflate_stream_crc32` and `set_deflate_stream_crc32s` feed an imported index, they
  do not enumerate streams at decode time. So the backstop's byte scan for a further
  `1f 8b 08` stays, and the per-member sum cannot use the index. A change proposal to
  detect multi-member files through the index was closed on this finding.
- **mgzip and `pigz -i` restart points.** mgzip names each member's size in an `MZ`
  subfield, which the BGZF walk could read too (the `seekable-gzip-and-block-writing`
  proposal). `pigz -i` resets the window inside one member, which only a decode finds.
- **Replaying the standard library engine after a `rapidgzip` abort**, to deliver the rest
  of a cut stream's prefix. Tracked internally.

## 8. Verify

```bash
./scripts/test.sh tests/test_codecs.py tests/test_single_file.py \
    tests/test_rapidgzip_deflate_zlib.py tests/test_accelerator_corruption.py \
    tests/test_accelerator_truncation_abort.py tests/test_accelerator_shutdown.py \
    tests/test_accelerator_bug3_trap.py tests/test_accelerator_takeover.py \
    -k "gzip or zlib or deflate or rapidgzip or accelerat"
```

| Claim |
| --- |
| A cut or wrong-ISIZE last member of a concatenated gzip or BGZF file raises through `rapidgzip`, at every cut point; a valid one reads with no handover |
| Multi-member, NUL padding, trailing junk after the payload |
| Member starts and BGZF blocks are seek points; the walk stops at a plain member; the BGZF sizes are trusted; a size query does not walk |
| A member after the first with a bad header CRC or a reserved flag raises the same error with `rapidgzip` as without it |
| A member after NULs is trailing data, and strict refuses it, with `rapidgzip` off, `AUTO` and on, for a read and a seek; NULs at the end and members with nothing between them stay silent |
| A truncated stream gives its prefix to sized reads and raises |
| `FNAME`, Latin-1, `MTIME` |
| No size, no CRC, no scan at open |
| zlib Adler-32 checked, not listed; under `rapidgzip` too, across seeks and through the TAR end scan |
| `ON` on a source that cannot seek raises `StreamNotSeekableError`; `AUTO` uses the standard library there |
| zlib header grammar and probe |
| `AUTO` on a large `.gz` and ZIP member: declared seeking gets `rapidgzip` at any ratio; without it, only at 3:1 or less, not on Windows, with a known size and a source that can seek. `ON` needs none of that |
| `AUTO` threshold and size condition; `ON` below it |
| The abort happens in-process, and not through archivey |
| A cut stream under `rapidgzip` delivers the standard library's bytes; the takeover resumes at a checkpoint, and starts over at a member's end |
| How the child's death is reported; no child → fallback and one warning |
| The caller's source exception reaches the caller |
| The ISIZE backstop and the empty-end fallback |
| A cut zlib stream delivers the bytes and error of `OFF` under `ON` and `AUTO`, cut in the first block, a later block or the trailer; the declared-size exception |
| A seek to or past the end of a cut gzip or raw DEFLATE stream gives what `OFF` gives under `ON`, whether `rapidgzip` delivered nothing or part of the data |
| Under `rapidgzip`: the gzip check survives seeks; a chance `1f 8b 08` does not silence it; a seek that fails on data is handed over; a second zlib stream is trailing data |
| A raw DEFLATE source that looks like gzip, zlib or bzip2, a zlib source whose header `rapidgzip` does not take for zlib (none at all, or one with a preset dictionary), a raw DEFLATE stream cut before any output, and a declared-empty stream that does not decode give the bytes and error of `OFF` under `ON` |
| A cut bare zlib stream under `ON` without a size raises |
| Close guard on shutdown; one accelerator library |

**Building fixtures.** The standard library writes gzip and zlib (`gzip.compress`,
`zlib.compress`); `tests/streams_util.py::make_bgzf` writes BGZF; `pigz` and `bgzip`
(package `tabix`) install from the distribution. `scripts/setup-dev-env.sh` (`tabix`
on Linux, `htslib` on macOS) and the Linux `all` CI legs install `bgzip`, so the suite
checks the walk against the reference writer there; the macOS CI legs skip that check.
`scripts/bench_rapidgzip_child.py` measures the child's start and round-trip cost.

## 9. References

- RFC 1952 (gzip): §2.3 member format, `FLG` bits, `MTIME`, `ISIZE`, and §2.3.1.2 on
  concatenated members
- RFC 1950 (zlib): §2.2 `CMF`/`FLG` and `FCHECK`, `FDICT`, Adler-32
- RFC 1951 (DEFLATE): §3.2 block format and the 32 KiB window
- SAM/BAM specification §4.1 (BGZF)
- [`rapidgzip`](https://github.com/mxmlnkn/rapidgzip), version 0.16
- Investigation: [`rapidgzip-upstream-report.md`](../investigations/rapidgzip-upstream-report.md)
  (soft end, Bugs 1 and 2, debugging scripts)
- Registers: [`known-issues.md`](../known-issues.md) (rapidgzip Bugs 3 and 4) ·
  [`threat-model.md`](../threat-model.md) O5, O11, O17
- Decisions: [ADR 0008](../decisions/0008-single-accelerator-rapidgzip.md) ·
  [ADR 0014](../decisions/0014-integrity-verdicts-from-reads-not-close.md) ·
  [`library-analysis.md`](../library-analysis.md) §gzip, §raw Deflate / zlib
- Code: `internal/streams/codecs/` (`gzip_codec.py`: `GzipCodec`,
  `_GzipTruncationCheckStream`; `zlib_codec.py`: `ZlibCodec`, `DeflateCodec`;
  `rapidgzip_select.py`: the accelerator selection; `stdlib_takeover.py`;
  `deflate_decoder.py`: `GzipDecoder`, `ZlibDecoder`; `rapidgzip_child.py`,
  `rapidgzip_worker.py`)
- Handbook: [`single-file.md`](single-file.md) · [`zip.md`](zip.md) (DEFLATE members) ·
  [`tar.md`](tar.md) (`.tar.gz`)
