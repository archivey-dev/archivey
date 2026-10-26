# Process isolation

Which native decoders archivey runs in a child process, how those children are started,
reused and ended, and what a caller sees when one dies. The setting is
`ArchiveyConfig.process_isolation`, a `ProcessIsolation`.

Other pages own parts of this, and this page links them rather than repeating them:

- [`formats/gzip.md`](../formats/gzip.md) §2.3 owns the rapidgzip child's protocol, its
  memory cap, and the takeover by the standard library when the child fails.
  [`formats/bzip2.md`](../formats/bzip2.md) §2.3 owns the same for the bzip2 accelerator.
- [ADR 0022](../decisions/0022-ppmd-always-in-a-child-process.md) owns why every PPMd
  member decodes in a child, and [`known-issues.md`](../known-issues.md) owns the
  upstream defects that make the children necessary.
- [`threat-model.md`](../threat-model.md) §"Errors are typed and honest" and §"A native
  decoder crash or MemoryError" own the guarantee and where it stops. The public version
  is [`docs/security.md`](../../docs/security.md#decoders-in-a-child-process).
- The measurements are in
  [`investigations/process-isolation-overhead.md`](../investigations/process-isolation-overhead.md).
  This page gives no performance numbers ([`formats/README.md`](../formats/README.md)).

## At a glance

- **Three settings.** `KNOWN_CRASHES` (the default) isolates the decoders that have been
  seen to crash, rapidgzip's DEFLATE family (`use_rapidgzip`) and pyppmd (every PPMd
  member), and rapidgzip's bzip2 decoder (`use_indexed_bzip2`) as a precaution, because
  it comes from the same library. `NATIVE_DECODERS` also isolates zlib, bz2, lzma, zstd, lz4, brotli and
  inflate64, and the trial decodes that detection runs. `NONE` starts no child: pyppmd
  decodes in this process, and rapidgzip is not used at all (`AUTO` falls back to the
  standard library, and `ON` is refused when the config is built).
- **What a caller sees when a child dies.** A crash signal (or its Windows status) is
  `CorruptionError`: a verdict on the data. SIGKILL is `ResourceLimitError`, usually the
  out-of-memory killer. Any other end is `ReadError`. The last two say the data may be
  valid. A rapidgzip child has more cases (truncation, its memory cap): gzip.md §2.3.
- **The caller's process keeps** checksums, AES and ZipCrypto decryption, the archive
  parsers, and everything the codecs do around the native object. Only the native decoder
  object moves.
- **Where no child can start** (a frozen application, no `sys.executable`, archivey
  imported from a zip, a refused spawn), a decoder that must be isolated raises
  `ResourceLimitError`. The exception is rapidgzip under `AUTO`, which falls back to the
  standard library with one warning per process (§2.6).
- **What you might expect and will not find:**
  - A timeout. A decoder that loops in a child loops for ever, as it would in-process
    (threat model §"Accelerators on by default, and unbounded in time").
  - A sandbox. The child runs with the caller's user, filesystem and network. It is a
    crash boundary, not a privilege boundary.
  - The RAR helper program. `unrar` or `unar` runs as a separate process under every
    setting, `NONE` included; its exits are classified on their own
    ([`formats/rar.md`](../formats/rar.md) §2.3).
  - Isolation chosen per codec. The setting picks a set of decoders; there is no list to
    pass.

## 1. Shape

- **The rule is observed crashes, not native code.** A decoder goes into a child under
  the default because it has crashed the process on some input, and nothing at the
  Python level can avoid that state in every case. Being written in C or C++ is not a
  reason by itself: the standard library's decoders are native and stay in-process.
  The one exception is rapidgzip's bzip2 decoder, which has not been seen to crash: it is
  isolated as a precaution, because it comes from the same library as the DEFLATE decoder
  ([`formats/bzip2.md`](../formats/bzip2.md) §6). `scripts/accelerator_crash_search.py`
  keeps checking both rapidgzip decoders, so the rule can be undone when upstream is
  fixed.
- **Two kinds of child, because the decoders take input in two ways.** A stream decoder
  (zlib, bz2, lzma, zstd, lz4, brotli, inflate64, pyppmd) is pushed input and returns
  output: the generic child (`codecs/decoder_child.py`) runs that object and nothing
  else, and the codec around it stays in the parent. rapidgzip pulls its own input,
  seeks it, and decodes ahead in threads: its child (`codecs/rapidgzip_child.py`) is
  handed a source and serves a seekable decoded stream. The two have different pools,
  different reuse rules and different costs (§2.2, §2.3).
- **A child imports nothing from archivey.** Both run `decoder_worker.py` under
  `python -P`, which imports only the decoder library. So a free-threaded parent never
  imports pyppmd or rapidgzip under the default, and none of the libraries that turn the
  GIL back on under `NATIVE_DECODERS`.
- **The proxy has the library's own surface.** `codecs/isolated.py` gives each library's
  decoder a stand-in with the same methods, picked by `natives_for(process_isolation)`. A
  codec does not know where its decoder runs, so the codec logic has one copy.

## 2. The machinery

### 2.1 Choosing where a decoder runs

`natives_for` returns `ISOLATED` for `NATIVE_DECODERS` and `IN_PROCESS` otherwise. PPMd and
rapidgzip do not go through that choice. They decide for themselves: in a child unless the
setting is `NONE`.

Whether rapidgzip is used at all is a separate decision, made by `AcceleratorMode` in
`codecs/rapidgzip_select.py`. `AUTO` uses it only when all of these are true:

- the caller declared seeking (`seekable_members=True`, `open_stream(seekable=True)`);
- the source is seekable and rapidgzip is installed;
- the compressed input is not known to be smaller than the gate
  (`RAPIDGZIP_AUTO_MIN_COMPRESSED_SIZE`, 16 MiB, for the DEFLATE family;
  `INDEXED_BZIP2_AUTO_MIN_COMPRESSED_SIZE`, 1 MiB, for bzip2);
- for the DEFLATE family, the decoded length can be checked.

The gate exists because of the child: a stream smaller than it does not pay back the
start of the process. gzip.md §2.3 has the full table, and why declared seeking is the
signal.

### 2.2 The generic decoder child

**One decoder per child at a time.** A decoder takes a child from the pool when it is
built and keeps it until it is closed. So a crash is charged to exactly the decoder whose
request was in flight, and threads decode in parallel. The pool is process-wide:
children are reused across archives.

**Reuse, and the bounds on it** (constants at the top of `decoder_child.py`):

- A closed decoder gives its child back when it ended cleanly. A decoder that reported an
  error, died, or was interrupted ends its child instead.
- The pool keeps at most `MAX_IDLE` idle children. More are ended.
- A child is ended after `MAX_DECODERS_PER_CHILD` decoders. A fault that corrupts memory
  without crashing at once could surface on a later decoder; the bound limits how long
  such a state can live.
- Idle children end at interpreter exit. A process made by `fork` forgets its parent's
  pool. A decoder used across a `fork` raises `ArchiveyUsageError`.

**A reused child's crash is not a verdict at once.** The child may carry damage that an
earlier decoder left. So a decoder in a reused child records what it sends, up to
`REPLAY_LIMIT` bytes, and the CRC-32 of each reply. When the reused child crashes or
reports an error, the decoder re-runs the record in a fresh child, and only the fresh
child's result counts. Decoders are deterministic, so the re-run reaches the same state.
When a re-run reply does not match the CRC of output the caller already has,
the call raises `ReadError`: the reused child gave wrong bytes, and they cannot be taken
back. Past `REPLAY_LIMIT` the decoder moves to a fresh child before it sends more, so a
long member never depends on a reused child.

**A digest mismatch retires the child.** When a member's CRC or hash fails above the
decoder, `retire_decoder_children` (`decompressor_stream.py`) walks down the member's
wrappers (`_inner`, and a solid slice's `_stream`) and tells each decoder. Only PPMd acts
on it (`spoil_child`): its child is ended at close instead of being given back, because a
wrong output is the visible sign of pyppmd's known corruption. A PPMd child is also ended
after any member that did not decode cleanly to its end (`PpmdDecoder._ended_cleanly`).

**Releasing early.** CPython gives a child back when the last reference to its proxy
goes. PyPy does that only at a later collection, so a reader that replaces or drops a
decoder calls `release_decoder`, and a reader that closes calls
`release_decoder_children`. Without these, PyPy under `NATIVE_DECODERS` once started one
process for each gzip member, xz stream or zstd frame.

**Interrupts.** A `KeyboardInterrupt` part-way through a request or reply leaves the pipe
out of step. Every later call on that decoder raises `ArchiveyUsageError`, and the child is
ended at close, not inside the interrupt.

### 2.3 The rapidgzip child

**Where its input comes from.** One of three ways, decided when the stream opens:

- **A path.** The child opens the file itself. This is a `.gz` or `.tar.gz` opened from
  a path.
- **A file range** (`OPEN_RANGE`, POSIX only). The source is a byte range of a regular
  file (`streamtools.slice.file_region`): a ZIP member, not encrypted, of an archive on
  disk. The child gets a copy of the archive's descriptor at spawn
  (`pass_fds`) and reads the range with `os.pread`, so no compressed byte crosses a pipe.
  The child's copy outlives the parent's handle, so the parent runs the source's checks
  before each call and raises what the read would have raised.
- **A stream.** Anything else: an encrypted member, a member of a nested archive, a
  `BytesIO`, any wrapper `file_region` does not know, every source on Windows, and every
  source under `enable_measurement` (the measuring wrapper must see each read). The child
  asks the parent for each read and seek, and the parent answers from the caller's
  stream, so the caller's own exception reaches the caller unchanged.

**Reuse within one open archive.** Children that read a file range are kept in a pool
(`RapidgzipChildPool`) that belongs to the archive's `ArchiveSource`. When a member's
stream closes cleanly, its child is `RESET` and the next member takes it. The pool's
children end when the archive closes or is collected, so no child outlives the archive.
That scope follows from the descriptor: a child holds the descriptor of one file from its
start, so it can serve only that file. A child is kept only:

- after a stream that raised nothing;
- for at most `MAX_STREAMS_PER_CHILD` streams, for the reason `MAX_DECODERS_PER_CHILD`
  has;
- where its memory peak can be reset (Linux), and the stream left less than a quarter of
  the memory cap resident, because the cap measures growth from the peak (gzip.md §2.3,
  "Memory"; `RESET` in `rapidgzip_worker.py`).

A path source or a stream source gets a new child each time.

**After `fork`.** The stream records the process that started its child. In any other
process a read, seek, tell or index query raises `ArchiveyUsageError`, and `close()`
drops the child without `RESET`, without returning it to the pool and without ending it.

**When the child fails.** The parent does not raise at once. The standard library takes
over from the child's last resume point and gives the verdict it gives with the
accelerator off. gzip.md §2.3 has the cases.

### 2.4 PPMd

pyppmd segfaults when it is asked to decode after a corrupt stream has ended early, and
from Python that state looks like a valid stream that waits for input (ADR 0022,
`ppmd_child.py`). Two measures work together:

- **Where it runs:** every PPMd member in a child, unless the setting is `NONE`.
- **How it is fed:** a member up to `DecoderLimits.max_ppmd_held_input` compressed bytes is
  held in the parent and handed to pyppmd whole, so pyppmd is asked little after a short
  end. A larger member, or a ZIP member from a non-seekable stream with its sizes after
  its data, is fed in pieces. This holds under every setting. Under `NONE` it is the only
  protection.

A solid 7z folder is one decoder for all its members, so it takes one child.

When the child cannot allocate the member's model (a container memory limit,
`RLIMIT_AS`), the member raises `ResourceLimitError` and does not suggest `NONE`, because
the same allocation in-process would abort the caller.

### 2.5 What crosses the boundary

- **Parent to child, generic:** `OPEN` with the codec name and constructor arguments
  (`marshal`), then `CALL` (method, arguments, input bytes) and `GET` (one attribute).
  Frames are tag, argument, length (`decoder_worker.FRAME`).
- **Child to parent, generic:** the output bytes, plus a small state dictionary with each
  reply (`eof`, `needs_input`, the sizes of `unused_data` and `unconsumed_tail`). The
  parent rebuilds `unused_data` and `unconsumed_tail` from the input it sent, so those
  bytes do not travel back. An error comes back as module, type name and message, and is
  rebuilt as the library's type or a stand-in (`BrotliChildError`, `PpmdChildError`), so
  each codec's `translate` maps it as before.
- **rapidgzip:** gzip.md §2.3, "What crosses the boundary".
- **How the child ended:** `child_process.is_crash` sorts the exit. A native fault signal
  (SIGSEGV, SIGABRT, SIGBUS, SIGILL, SIGFPE), its Windows status, or the C runtime's
  abort status 3 on Windows is a crash: `CorruptionError`. Anything else came from outside
  the decoder (`outside_death`). A child that dies before its first reply did not start,
  which says nothing about the data. An error that is no verdict on the data is marked
  (`mark_no_verdict`), so the seek index is not dropped because of it.

### 2.6 When no child can start

`child_process.unavailable_reason` checks for a frozen application, an empty
`sys.executable` and a worker script that is not a file. A spawn can also fail (a process
cap, no temporary directory, too many open files).

| Decoder | Then |
| --- | --- |
| PPMd under `KNOWN_CRASHES` or `NATIVE_DECODERS` | `ResourceLimitError`, which names `NONE` as the way to decode in-process (PPMd runs in a child under every other setting) |
| Any other decoder under `NATIVE_DECODERS` | `ResourceLimitError`, which names `KNOWN_CRASHES` |
| rapidgzip under `AUTO` | The standard library, with one warning per process on `archivey.streams` |
| rapidgzip under `ON` | `ResourceLimitError` |

A fresh child that is needed part-way through a member (§2.2, the re-run) and cannot start
gives the same error as at open.

## 3. What it costs

The figures are in
[`investigations/process-isolation-overhead.md`](../investigations/process-isolation-overhead.md);
this section says what each cost comes from.

- **The default costs nothing off PPMd and rapidgzip.** `KNOWN_CRASHES` and `NONE` time
  the same on every other path, because nothing there is isolated.
- **A start per child.** A new Python process plus the decoder library import. The pools
  exist to pay it once for many decoders. The rapidgzip gate under `AUTO` exists because a
  rapidgzip child pays it for each stream that is not a file range in an open archive.
- **A copy per byte.** Under `NATIVE_DECODERS` the input goes to the child and the output
  comes back through pipes. That cost grows with the output and dominates for fast codecs
  (zstd) and many small members. The rapidgzip child copies its output back, and its input
  too when the source is a stream.
- **A round trip per request.** Small for large reads; it adds up over many small
  members, and over a non-solid 7z of many small PPMd members, each a decoder of its own.
- **A second decode for a ZIP or 7z DEFLATE member read through rapidgzip.** ZIP and 7z
  set `refuse_input_after_end`. When rapidgzip's output ends, the parent decodes the
  whole member again with zlib from offset 0 (`_hands_over_at_end`, then
  `deflate_resume.stream_end`, in `zlib_codec.py`) to find where the DEFLATE stream ends
  and whether bytes follow it. It cannot start from a resume point, because rapidgzip
  reads on into a second stream, so a point could sit past the first stream's end. This
  is the largest part of a full read of a large ZIP member, and it is why such a read is
  slower with rapidgzip than without. `.gz` and `.tar.gz` do not pay it. A seek short of
  the end does not pay it either, so random reads of a large member are still much
  faster.
- **Memory.** An idle generic child holds a Python interpreter. A rapidgzip child also
  holds decoded chunks, bounded by `DecoderLimits.max_decoder_memory`.

## 4. Sharp edges

**format**: inherent. **library**: upstream's. **archivey**: ours.

| What you see | Where | More |
| --- | --- | --- |
| A full read of a large ZIP DEFLATE member is slower with `seekable_members=True` than without | **archivey** | The end check decodes the member a second time (§3). Random reads of the same member are much faster. A gate on the source kind would not help: the loss and the gain were measured about the same for a path, an open file and a `BytesIO`. §6 |
| A non-solid 7z of many small PPMd members reads more slowly than under `NONE` | **archivey** | One decoder, so one request cycle, per member, and a new child every `MAX_DECODERS_PER_CHILD` (§2.2). A solid folder pays once |
| `NATIVE_DECODERS` makes zstd and gzip reads several times slower | **archivey** | The pipe copy (§3). The setting is for hostile input where a crash must cost only the member |
| A loop on crafted input in a child never ends | **library** | No timeout (§At a glance). Set the accelerators `OFF` for a latency budget |
| A PPMd member raises `ResourceLimitError` in a frozen application or under a spawn limit | **archivey** | By design: it does not decode in-process unless `NONE` is set (§2.6) |
| `use_rapidgzip=ON` with `process_isolation=NONE` raises `ArchiveyUsageError` when the config is built | **archivey** | rapidgzip runs only in a child (§At a glance) |
| A member stream used after `fork` raises `ArchiveyUsageError` | **archivey** | Its child belongs to the parent process, for the generic child (§2.2) and the rapidgzip child (§2.3) alike. Open the member again in the forked process. Closing the inherited stream there leaves the parent's child alone |
| Under PyPy, a reader that is never closed holds its children until a collection | **library** (PyPy) | Close readers; the readers already release replaced decoders (§2.2) |
| A rapidgzip child is not reused on macOS or Windows | **archivey** | Its memory peak cannot be reset there (§2.3). Windows has no file-range path at all |

## 5. Decisions

- **Isolate by observed crash, not by "native".** The bzip2 accelerator is the one
  precaution, for its shared library (§1). Rejected: isolating every native decoder
  by default. The cost is large for the fast codecs, and the standard library's decoders
  have no known crash. `NATIVE_DECODERS` is there for callers who want it.
- **PPMd always in a child, not only above a size** (ADR 0022). Rejected: in-process up to
  16 MiB with a feeding discipline. The discipline held only by measurement, with one
  call between it and a crash.
- **`NONE` refuses `use_rapidgzip=ON`.** Rejected: rapidgzip in-process under `NONE`. Its
  abort on a truncated stream cannot be caught, and the setting would then mean "crash on
  a cut file".
- **A reused child's failure is re-run before it is charged** (§2.2). Rejected: ending
  every child after one decoder. That pays the start for every member.
- **rapidgzip children are reused within one open archive only** (§2.3). Rejected: a
  process-wide pool. The child holds one file's descriptor from its start, and a
  process-wide pool would keep that file open after the archive closes.
- **A file range, not a path, for a ZIP member.** The descriptor is passed at spawn, so a
  rename after the open cannot change what the child reads.

## 6. Open questions

- **Can the end check start from the last resume point?** When rapidgzip's index shows only
  one DEFLATE stream, the check may only need the tail after the last point. That would
  remove the second decode (§3). It needs a careful design, because the check is what
  refuses trailing bytes after a member.
- **Does rapidgzip still crash?** `scripts/accelerator_crash_search.py` answers it. A run
  with no crash over a new release would let the DEFLATE family come back in-process,
  and with it the bzip2 decoder, which is isolated only because the DEFLATE one is.
- **Where should brotli and inflate64 run on a free-threaded build?** Importing them turns
  the GIL back on. Today the default only defers the import until a stream needs them
  (`codecs/deps.py`, `LazyOptional`); `NATIVE_DECODERS` keeps them out of the parent.
  Running them in a child under the default with the GIL off would keep it off, at the
  cost of the copy (§3). It would be the first isolation for a reason other than a crash.
  A proposal exists and is tracked internally; nothing is built.

## 7. Verify

```bash
./scripts/test.sh tests/test_process_isolation.py tests/test_decoder_child.py \
    tests/test_ppmd_crash_isolation.py tests/test_rapidgzip_file_range.py \
    tests/test_accelerator_truncation_abort.py tests/test_accelerator_takeover.py \
    tests/test_accelerator_memory_limit.py tests/test_error_translation.py
./scripts/test.sh --all-configs    # the configs without rapidgzip or pyppmd
```

The costs:

```bash
uv run --no-sync python scripts/bench_process_isolation.py   # NONE / KNOWN_CRASHES / NATIVE_DECODERS
uv run --no-sync python scripts/bench_accelerator_reads.py   # reads through the rapidgzip child
uv run --no-sync python scripts/bench_rapidgzip_child.py     # the rapidgzip child against in-process
uv run --no-sync python scripts/bench_bzip2_child.py         # the same for bzip2
```

Whether the children are still needed: `scripts/accelerator_crash_search.py` (rapidgzip)
and `scripts/pyppmd_crash_repro.py` (pyppmd).

## 8. References

- Decisions: [ADR 0022](../decisions/0022-ppmd-always-in-a-child-process.md) and its
  2026-10-22 amendment (`max_ppmd_held_input`) ·
  [ADR 0008](../decisions/0008-single-accelerator-rapidgzip.md)
- Archived OpenSpec changes, under `openspec/changes/archive/`:
  `2026-10-20-native-decoder-process-isolation` (the setting) ·
  `2026-09-26-rapidgzip-deflate-child-process` (the rapidgzip child) ·
  `2026-10-02-rapidgzip-cut-stream-takeover` · `2026-09-26-ppmd-crash-isolation` ·
  `2026-09-26-ppmd-child-death-verdicts`
- Related pages: [`formats/gzip.md`](../formats/gzip.md) §2.3 ·
  [`formats/bzip2.md`](../formats/bzip2.md) §2.3 · [`formats/7z.md`](../formats/7z.md) ·
  [`formats/zip.md`](../formats/zip.md)
- Registers: [`known-issues.md`](../known-issues.md) §"rapidgzip accelerator: upstream
  defects", §"Intermittent `pyppmd` native aborts on PPMd streams", §"PyPy: rapidgzip,
  python-lz4, pyppmd and inflate64 misbehave" · [`threat-model.md`](../threat-model.md)
- Investigations:
  [`process-isolation-overhead.md`](../investigations/process-isolation-overhead.md) ·
  [`rapidgzip-worker-deaths.md`](../investigations/rapidgzip-worker-deaths.md) ·
  [`ppmd-native-investigation-results.md`](../investigations/ppmd-native-investigation-results.md)
- User docs: [`docs/security.md`](../../docs/security.md#decoders-in-a-child-process) ·
  `docs/recipes.md`
- Code: `config.py` (`ProcessIsolation`, `AcceleratorMode`) ·
  `internal/streams/child_process.py` (spawn, exit classification) ·
  `internal/streams/codecs/isolated.py` (`natives_for`, the proxies) ·
  `codecs/decoder_child.py` and `decoder_worker.py` (the generic child) ·
  `codecs/rapidgzip_child.py`, `rapidgzip_worker.py`, `rapidgzip_select.py` ·
  `codecs/ppmd_child.py`, `ppmd_decoder.py` · `streamtools/slice.py` (`file_region`)
