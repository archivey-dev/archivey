# rapidgzip upstream report — soft EOF and related defects

Status: **documentation only — not filed upstream** (2026-07-20). Soft empty/short
success on truncated gzip is **by design** in rapidgzip’s parallel reader (trial-and-error
mid-stream decode for ratarmount / random access). Filing it as a “bug” would be wrong;
an `is_stream_complete()`-style API would be a **feature request** we are not opening
now. This note records the contract Archivey must work around, plus adjacent abort
defects that *are* bug-class.

Deep dive (code citations, issue table, repros):
`openspec/changes/rapidgzip-truncation-investigation/UPSTREAM_TRUNCATION_REPORT.md`.

Archivey product mitigation (empty→stdlib fallback + single-member ISIZE backstop):
**implemented** in `_GzipTruncationCheckStream` (OpenSpec change
`rapidgzip-truncation-investigation`). The two defects archivey fixed on its side
(closing accelerators at finalization, one accelerator library per process) are §6 and
§7 below. The three live upstream defects (a raising Python source, a truncated DEFLATE
stream, a file object never released) are Bugs 3 to 5 in `dev-docs/known-issues.md`; §9
has a ready-to-file report for the third.

Pinned: **rapidgzip 0.16.0** ≡ librapidarchive `1221a30` (`[version] Bump rapidgzip
version to 0.16.0`). Soft-EOF paths unchanged on inspected HEAD.

---

## Classification

| Topic | Class |
| --- | --- |
| Soft EOF on truncated gzip / empty-short success | **by design** (not a bug) — Archivey limitation; mitigate with empty→stdlib + ISIZE. macOS raises more often than Linux/Windows but still silent at cut=10. |
| `std::terminate` on a truncated DEFLATE stream | **bug-class** — contained by a child process; known-issues Bug 4 + §2 below |
| Worker threads outlive an unclosed object; two libraries in one process | fixed in archivey; §6 and §7 below |
| `IndexedBzip2File` never releases its Python file object | **bug-class** — contained by archivey; known-issues Bug 5 + §9 below |

## 1. Soft EOF on truncated input (by design — Archivey limitation)

### Behaviour

With path sources and `parallelization=0` (**all cores** in upstream’s API — intentional
in Archivey):

- Mid-body truncations of ordinary single-block gzip often make `RapidgzipFile.read()`
  return `b""` **without raising** (**Linux / Windows**; macOS mostly raises after cut=10).
- Multi-block / large streams often return a **correct short prefix** (or full payload if
  only the trailer is missing) **without raising** on Linux/Windows.
- Objects frequently report `block_offsets_complete=True` and `size == len(returned)`, so
  callers cannot tell a valid short member from a truncated stream via those APIs.
- Stdlib `gzip` sized-reads still yield a prefix then raise `EOFError`.

### Why (upstream)

- `ParallelGzipReader::read`: missing chunk → soft EOF, return bytes already written.
- `GzipChunkFetcher::processNextChunk`: `encodedSizeInBits == 0` → finalize block map,
  return empty.
- `GzipChunk::tryToDecode`: **swallows** `std::exception` while guessing block starts
  (expected during speculative decode).

CHANGELOG / empty-gzip handling also prefer not throwing when there is “no more
decodable data.” There is **no** Python docstring that truncated files must raise.
GitHub issues do not treat silent-empty `read()` as a user-facing bug.

### Archivey stance

- Do **not** file this as an upstream bug.
- Do **not** parse stderr (`Unexpected end of file when getting block…` is a **rethrow**
  path near the trailer, not a silent-success channel).
- Do **not** trust `block_offsets_complete` / `size` for completeness.
- Mitigate in Archivey: empty→stdlib fallback + ISIZE for non-empty silent EOF
  (see OpenSpec change).

---

## 2. Abort / `std::terminate` on truncated input (bug-class — contained)

A gzip, zlib or raw DEFLATE stream that ends early makes rapidgzip throw from a destructor
(`GzipChunk::determineUsedWindowSymbolsForLastSubchunk` → `BitReader::tell()`,
`std::logic_error` "The bit buffer should not contain more data than have been read from
the file!"), and `std::terminate` aborts the process. It fires for path, file-object and
`BytesIO` sources alike, from about 380 KB up; on an 8 MB gzip, 27 of 30 random cuts aborted
on Linux. The macOS build raises "Unexpected end of file when getting block ..." instead.
`IndexedBzip2File` never aborted in 110 tries.

A CRC mismatch is a complete stream with the wrong content, not a short one. For the DEFLATE
family it goes through the child like any other input, so an abort on it would be contained
the same way; gzip CRC32 damage raised `CorruptionError` in 8 runs of 8 without one. The
bzip2 decoder still runs in the caller's process: its stream-CRC damage, 12 bit flips and
4 cuts of a 3 MB stream, each read from a path and from a file object, raised
`CorruptionError` or read clean, with no abort in 40 runs. That is testing, not proof; an
input that aborts the bzip2 decoder would still end the caller's process.

Archivey runs the DEFLATE-family decoders in a child process, so the abort costs the member:
the parent reports `TruncatedError` when the abort message names this truncation, else
`CorruptionError` (known-issues Bug 4). The standard library then takes the read over from
the last index point the reader passed (`formats/gzip.md` §2.3), so nothing the abort lost
is lost to the caller.

The abort fires in whichever worker thread decodes the chunk that holds the cut, up to
about threads × 4 MiB (compressed) ahead of the reader. Measured 2026-10-02 on 4 cores, a
154 MB gzip cut at 10 % gave nothing before the abort, where the standard library gave
20 MB; at 16 threads a cut near the end lost about 40 MB of 202. The code path sits behind
`windowSparsity`, which the Python binding does not expose. Wrapping the `seekTo` in the
`Finally` lambda (GzipChunk.hpp:79) in `try`/`catch` and building 0.16.0 from source ended
the aborts: parallel decoding then delivered every chunk before the cut, as one thread
does, and raised `RuntimeError("std::exception")` (the "Unexpected end of file" detail
goes only to stderr, so a report should ask for it in the exception too). This is the
report worth filing upstream: a destructor must not throw, and the input is only short,
not hostile.

| Related Archivey notes | |
| --- | --- |
| Bug 1: must `close()` accelerators | §6 below |
| Bug 2: rapidgzip and indexed_bzip2 in one process | §7 below, ADR 0008 |
| Bug 3: Python source raises → terminate | `known-issues.md` |
| Bug 4: truncated DEFLATE → terminate | `known-issues.md` |
| Bug 5: `IndexedBzip2File` keeps its file object | `known-issues.md`, §9 below |

Soft EOF (§1) is separate from this abort class.

---

## 3. API notes useful to Archivey

| Fact | Implication |
| --- | --- |
| `parallelization=0` → `availableCores()` | Archivey passes `0` **intentionally** (all-cores + benchmarks). Not “sequential.” |
| No `eof()` / `is_complete` / last-error | No first-class incompleteness flag today |
| `verbose=` | Stats/profile only — does not harden EOF |
| CLI maps EOF to exit 1 with a clear message | Python API has no equivalent status |

---

## 4. If we ever request an upstream feature

Only if product needs it later — **feature request**, not a bug report:

> Expose `is_stream_complete()` / similar set when decode stops without a verified
> gzip footer (CRC/ISIZE), without relying on stderr.

Draft body: `UPSTREAM_TRUNCATION_REPORT.md` §7. **Not filing now.**

---

## 5. bzip2 (`IndexedBzip2File`)

Shares soft-EOF shape for very short prefixes; mid-stream more often raises than gzip.
No ISIZE twin; container CRC covers archive members. Document only unless bare `.bz2`
parity is required.

---

## 6. Bug 1: an accelerator object must be closed, not only joined (fixed in archivey)

With the `[seekable]` accelerators installed, a process that used them could abort with
SIGABRT (exit code 134) at interpreter shutdown, after all work had completed, with either
of:

```
Detected Python finalization from running rapidgzip thread.
terminate called without an active exception
```
```
malloc: *** error for object 0x...: pointer being freed was not allocated
```

The first message is this bug; the second is Bug 2 (§7).

`rapidgzip` and `indexed_bzip2` spawn C++ worker threads (`std::thread`s, invisible to
Python's `threading` module). Each installs a guard that calls `std::terminate()` if a
worker thread is still running when the interpreter is finalizing. `join_threads()` does
not stop the worker thread; only `close()` does (the library's own message says to "close
all … objects"). So a stream finalized without being closed aborts, on every platform.
Measured by `tests/test_accelerator_shutdown.py` (rapidgzip, both codecs ×
intact/corrupt/truncated × cleanup, each in its own subprocess). The input variant is
irrelevant; only finalization matters:

| Cleanup strategy | Result |
|---|---|
| **closed**: `read()`, then `join_threads()` + `close()` during the run | clean |
| **raw cycle_gc**: raw object reclaimed by the cyclic GC mid-run, never closed | **abort** |
| **raw unclosed**: raw object finalized at interpreter shutdown, never closed | **abort** |
| **guarded cycle_gc / unclosed**: same two paths, but a `weakref.finalize` guard closes the object on finalization | clean |

A guard that called `join_threads()` only was tried and is not enough.

**What archivey does.** Archivey runs rapidgzip only in its decoder process
(`rapidgzip_worker.py`), so no rapidgzip object lives in the caller's process. The decoder
process closes its stream before it exits and then skips interpreter finalization
(`os._exit`). The in-process wrapper with a `weakref.finalize` guard that archivey used
before is removed.

**The canary.** `tests/test_accelerator_shutdown.py` asserts the contract: the closed case
and the two guarded finalization paths exit cleanly on every platform (if they ever abort,
the close-then-exit the decoder process relies on is broken), while the raw `cycle_gc` and
`unclosed` paths abort. If a later `rapidgzip` release stops aborting on a raw, never-closed
object (for example because it closes or joins in its destructor), the raw-case assertions
fail. That is the signal that the decoder process no longer needs to close before it
exits.

## 7. Bug 2: rapidgzip and indexed_bzip2 cannot share a process (fixed in archivey)

With Bug 1 fixed, macOS still aborted, as a `malloc … pointer being freed was not
allocated` heap corruption, and only when both `rapidgzip` and `indexed_bzip2` were
importable. `scripts/investigations/dual_accelerator_repro.py` isolates it (no archivey, no pytest):
decompressing through both libraries in one process crashes about 100% of the time on
macOS, while using either one alone, even with both imported, never crashes. The two
libraries are by the same author and statically bundle a large overlapping C++ core. On
macOS, dyld coalesces their duplicate weak C++ symbols across the two dynamic libraries, so
one module's allocator can free the other's objects.

**What archivey does.** It uses only `rapidgzip`. Its Python package bundles the
specialized bzip2 decoder as `rapidgzip.IndexedBzip2File`, so archivey routes both gzip and
bzip2 through rapidgzip and never imports the standalone `indexed_bzip2` package. The
`[seekable]` extra depends on `rapidgzip` alone (ADR 0008).
`tests/test_accelerator_shutdown.py::test_archivey_uses_single_accelerator_library`
decompresses both codecs through archivey in a subprocess and asserts `indexed_bzip2` is
never imported.

This matches the library author's own guidance, from
[mxmlnkn/librapidarchive](https://github.com/mxmlnkn/librapidarchive):

> I am not sure how well the rapidgzip and indexed_bzip2 Python modules work when loaded at the
> same time. There may be name collisions resulting in problems. … Currently, I am sidestepping
> this issue in ratarmount by including indexed_bzip2 in the rapidgzip Python package because it
> is trivial and low-overhead to do so. **So, if you need to use both, depend on rapidgzip for
> now.**

rapidgzip can decode bzip2 two ways: `rapidgzip.IndexedBzip2File` (the specialized
indexed_bzip2 code bundled into the rapidgzip package, with full feature and performance
parity) and `rapidgzip.RapidgzipFile` opening a `.bz2` directly (a generic algorithm that,
per the author, "has more memory overhead and might be slightly slower"). Archivey uses
`IndexedBzip2File` for parity with the standalone package.

## 8. Debugging tools

- `scripts/investigations/dual_accelerator_repro.py` confirms the two-library crash (§7) and that routing
  both codecs through rapidgzip alone is safe.
- `scripts/investigations/accelerator_crash_search.py` runs both decoders in-process on damaged input,
  in a process it watches, and reports every crash by its signature, so it shows which
  crashes are still there after a rapidgzip upgrade.
- `scripts/investigations/macos_accelerator_debug.py` characterises the finalization behaviour (§6) across
  raw and guarded objects × cleanup strategies, each in its own subprocess.

## 9. Bug 5: `IndexedBzip2File` keeps its Python file object (bug-class — contained)

Ready to file. `rapidgzip.IndexedBzip2File(f)` holds a reference to `f` that `close()`
does not drop, and the object is still alive after the `IndexedBzip2File` is deleted and
the garbage collector has run. Every open of a Python file object therefore keeps that
object, and an `io.BytesIO` keeps its whole buffer, for the life of the process. Each open
also leaks a few kB of native memory, from a path too. Measured on rapidgzip 0.16.0, Linux,
CPython 3.11:

```python
import bz2, gc, io, weakref
import rapidgzip

class Source(io.BytesIO):  # a plain BytesIO takes no weak reference
    pass

src = Source(bz2.compress(b"payload " * 400))
alive = weakref.ref(src)
f = rapidgzip.IndexedBzip2File(src, parallelization=1)
assert f.read() == b"payload " * 400
f.close()
del f, src
gc.collect()
print("source still alive after close:", alive() is not None)  # True
```

Expected: `False`, as for `bz2.BZ2File`. The leak is per open, whatever the input's size,
so a service that opens many `.bz2` streams from memory grows without bound; archivey's
fuzz run over this decoder ran out of memory after about 36 000 inputs before the
workaround. Archivey now runs this decoder only in its decoder process, which reads the
caller's stream over a pipe, so nothing leaks in the caller's process (known-issues Bug 5,
"What remains").
