# Known issues

This page lists only live archivey defects and live upstream bugs that archivey works
around. Each entry is short: symptom, affected versions, what archivey does, what remains,
upstream status, and a link to the evidence. A fixed archivey defect is deleted in the PR
that fixes it; the regression test and git history keep the record. Measurements, root
causes and rejected fixes live in [`investigations/`](investigations/), the standing rule a
mitigation imposes lives on the format handbook page ([`formats/`](formats/)), and by-design
behaviour lives in the handbook's sharp-edges tables and, when users hit it, in
the user docs ([`docs/formats.md`](../docs/formats.md) for format behaviour).

## MacPaw `unar` / XADMaster: RAR5 solid after an empty entry is silent-wrong (open)

**Symptom.** On a RAR5 solid archive, `unar` fails on a member with data that comes after
an empty file or a directory, on stdout and on extract-to-disk. Selecting only the later
member does not help. Debian's 1.10.1 SIGSEGVs and loses output it had buffered for
earlier members; the XADMaster 1.10.8 lineage (the local build and Homebrew's bottle)
exits 0 with empty output. RAR4 is unaffected.

**What archivey does.** `unar` is the second RAR data program (used when no RARLAB program
is found, under `auto` for a member `unrar` cannot name whose read needs no password,
or with `ArchiveyConfig.rar_decompressor="unar"`). `internal/backends/rar_unar.py`
refuses, from the native listing, every RAR5 solid member with data that follows an empty
file, a directory or a link, and names only the readable members to `unar`, so it never
reaches the crash. The same module handles the six other `unar` failures found on the
fixtures: it refuses RAR 1.5 compression, encrypted RAR 2.x to 4.x data (and compressed
members after it in the same solid stream), non-ASCII passwords, header-encrypted RAR5
volume sets and prefixed volume sets, copies a prefixed
single archive from where the RAR starts, and names stream volumes under the set's own
scheme. Pinned by `tests/test_rar_unar.py`, which CI's macOS leg runs against the
Homebrew bottle.

**What remains.** The gate is built from measured shapes, and ANTI members and
packed-nonzero empty entries are untested, so a shape could slip past it. The per-member size and digest check
is the net.

**Upstream.** Not filed with XADMaster.

**Evidence.** [`alternative-rar-decompressors.md`](investigations/alternative-rar-decompressors.md)
§2026-09-26 measurements. Handbook: [`formats/rar.md`](formats/rar.md) §3.

## Debian/Ubuntu `unar` 1.10.1: some compressed RAR5 members come out empty (open)

**Symptom.** `unar` 1.10.1 (Debian and Ubuntu's package) writes nothing for a compressed
RAR5 member when a Huffman lookup near its end peeks past the last packed byte, solid or
not, and exits 0; under `-o -` stderr is empty too. About 1–6% of `-m3` members measured
do this. In a solid run over several entries, later members are lost as well, or come
out as stale window bytes, so the bytes found where the dropped member should be belong
to something else. Debian's 1.10.8 packages before 1.10.8+ds1-10 do the same (see Cause).

**What archivey does.** `find_unar` runs each `unar` it finds once, after the banner
check, on an 85-byte RAR5 archive embedded in `internal/external/unar.py` (the
`unar_drop__.rar` fixture), and requires the member's exact 14 bytes back. A build that
writes anything else, exits non-zero, or runs out of time is not used, and the answer
is cached per binary like the banner's. Under `"auto"` that `unar` counts as absent;
with `rar_decompressor="unar"` a read raises `PackageNotInstalledError`. For the
patch's signature (exit 0, less than the member) it names the patch and says to install
RARLAB `unrar` or a `unar` without the patch; any other failure says what the run did
(its exit status, a signal, the wrong bytes). A check that cannot run at all, such as a
temporary directory with no space, is reported as that and is not cached.
`unar_rar5_probe_failure(path)` runs the check on any binary. Before the check existed,
and still as a second line for a build that passes it: every member read with `unar` is
checked against its declared size and its stored CRC32 or BLAKE2sp, so a dropped member
is reported as truncated and misplaced bytes in a solid run fail the digest; the solid
pass reads a member that has no digest through a `unar` run of its own, which writes it
exactly or not at all. Pinned by `tests/test_unar_probe.py`, and by
`tests/test_rar_unar.py` on the `unar_drop*` and `unar_stale*` fixtures.

**CI.** The Linux test legs install Ubuntu's `unar`, build upstream XADMaster 1.10.8
from source (`scripts/install-unar-from-source.sh`) and put it first on `PATH`, so the
`unar` tests run against a build archivey uses. A separate step *expects* Ubuntu's
`/usr/bin/unar` to fail the check
(`test_distro_unar_matches_the_ci_expectation`, with `ARCHIVEY_DISTRO_UNAR_EXPECT=patched`).
The `unar-distro-packages` job does the same in containers for `debian:stable`
(expected patched), `debian:unstable` (expected clean) and `fedora:latest` (expected
clean); Alpine does not package `unar`. When one of these fails, the package changed:
flip the row's expectation, and, if Ubuntu's package passes, consider dropping the source
build. The test's failure message and the workflow comments say the same.

**What remains.** With a patched build and no other program, RAR member data cannot be
read with `unar` at all. A local dev box with Ubuntu's package skips the `unar` tests
unless a 1.10.8 build comes first on `PATH`; `scripts/setup-dev-env.sh` reports
`REFUSED unar` when that is the case.

**Cause.** Not upstream: it comes from `CSInputBuffer-bit-string-reading.patch`, which
Debian added in 1.10.1-2 and deleted in 1.10.8+ds1-10 (June 2026, for breaking imploded
ZIP members, Debian bug #1134346). With it, the bit reader raises end of file when fewer
bits remain than a Huffman lookup *peeks*, even when the code it uses is shorter; the
error is swallowed and the member comes out empty. `scripts/find_unar_probe_member.py`
models those reads and found the probe member; its `--validate 300 --check-unar
/usr/bin/unar` agreed with Ubuntu 24.04's package on all 563 compressed cases, 42 of
them solid pairs decided by the first member (2026-10-02). Measured on builds from source
(2026-10-01): upstream 1.10.1, 1.10.7, 1.10.8 (Homebrew's version) and master decode all
300 generated RAR5 archives and the `unar_drop*` / `unar_stale*` fixtures correctly; the
Debian 1.10.1 package build reproduces the drops, the same build without that patch does
not, and upstream 1.10.8 with the patch applied drops the probe member too. The RAR 1.5
refusal (`rar15-comment.rar` missing `FILE1.TXT`) has the same cause.

Which packages carry it (patch series read from the source packages in Ubuntu's archive,
2026-10-01): Ubuntu 22.04 (1.10.1-2build11), 24.04 (1.10.7+ds1+really1.10.1-3build1) and
26.04 (1.10.8+ds1-9build1) do; Debian 1.10.8+ds1-9 does, and is expected to be what
Debian 13 ships (not confirmed: no Debian mirror was reachable); Debian unstable's
1.10.8+ds1-10 does not. So no version string identifies an affected build: Debian's
1.10.8 packages print `unar v1.10.8` with or without the patch, and upstream 1.10.8 and
master still print `v1.10.7`. That is why archivey checks behaviour, not the banner.

**Upstream.** Nothing to file with XADMaster; the patch is Debian's, and Debian has
dropped it. Ubuntu picks that up with its next sync from Debian.

**Evidence.** [`alternative-rar-decompressors.md`](investigations/alternative-rar-decompressors.md)
§Compressed RAR5 member dropped. Handbook: [`formats/rar.md`](formats/rar.md) §3.

## rapidgzip accelerator: upstream defects

Bugs 3, 4 and 5 below are live in rapidgzip 0.16.0, the current and floor version. Bugs 1 and
2 (closing accelerator objects at finalization, one accelerator library per process) are
fixed on archivey's side and written up in
[`rapidgzip-upstream-report.md`](investigations/rapidgzip-upstream-report.md) §6 and §7.

### Bug 3: rapidgzip terminates the process when its Python source raises (open)

**Symptom.** When a rapidgzip object decodes from a Python file object and a callback into
that object raises (for example, the stream was closed underneath it), the C++ layer throws
`std::invalid_argument` ("Cannot convert nullptr Python object to the requested result
type") through a `terminate()` boundary and the process aborts with SIGABRT. It fires on
`read()`, on `close()` and on the GC-time finalize guard, so no Python `try` contains it.
Path sources are unaffected, because rapidgzip owns its own handle.

**What archivey does.** It never closes a source underneath a live accelerator stream: the
single-file reader's `_close_archive` leaves the non-owning `SharedSource` behind member
streams open, so `reader.close()` with a member stream still open cannot trigger it. For a
caller's own stream that fails or is closed mid-read:

- Every codec rapidgzip decodes (gzip, zlib, raw DEFLATE and bzip2) runs in a child
  process (Bug 4). The child's source never raises (a failed read is an end of input);
  this process serves the reads from the caller's stream and raises the caller's
  exception itself, marked as the caller's, so an `EOFError` from a dropped network
  stream stays an `EOFError`. The decoder took the fault for the end of its input, so the
  stream is then given up for good: every later `read`, `seek` and `tell()` raises
  `ReadError`, even after the caller's source recovers (`compressed-streams`, the
  accelerated-decoder paragraph).

Pinned by `tests/test_accelerator_bug3_trap.py`. The stdlib codec fallbacks raise an
ordinary `ValueError`.

**What remains.** The child process is needed until rapidgzip stops terminating.

**Upstream.** Not filed.

**Evidence.** `tests/test_accelerator_bug3_trap.py`; [`formats/bzip2.md`](formats/bzip2.md)
§2.3.

### Bug 4: rapidgzip aborts on a truncated DEFLATE stream (open, contained)

**Symptom.** rapidgzip calls `std::terminate` (SIGABRT) when it decodes a gzip, zlib or raw
DEFLATE stream that ends early:

```
terminate called after throwing an instance of 'std::logic_error'
  what():  The bit buffer should not contain more data than have been read from the file!
```

The throw comes from a destructor (`GzipChunk::determineUsedWindowSymbolsForLastSubchunk`
→ `BitReader::tell()`), so it fires for a path, a file object and a `BytesIO` alike, on
files from about 380 KB up; on an 8 MB gzip, 27 of 30 random cuts aborted. The macOS build
raises `Unexpected end of file when getting block ...` instead. bzip2
(`IndexedBzip2File`) never aborted in 110 tries, nor in the crash search below.

**What archivey does.** gzip, zlib and raw DEFLATE decode through rapidgzip in a child
process (`rapidgzip_child.py` running `rapidgzip_worker.py`). bzip2 does too, as a
precaution: its decoder has not been seen to abort, but it comes from the same library.
The abort ends the child, and
the parent reports it by how the child ended: an abort naming this truncation is
`TruncatedError`, another crash `CorruptionError`, SIGKILL `ResourceLimitError`, anything
else `ReadError`. `tests/test_accelerator_truncation_abort.py` pins the reporting and
keeps a canary that raw rapidgzip still aborts on Linux; when the canary fails, rapidgzip
may be safe in-process again.

A crash hands the read to the standard library, which starts at the last index point the
reader passed, so a cut stream delivers the same bytes as without rapidgzip
([`formats/gzip.md`](formats/gzip.md) §2.3). Before that, rapidgzip's read-ahead lost
everything it had decoded past the reader: up to the whole stream for a cut file of tens
of MB with every core decoding.

**What remains.** Nothing runs rapidgzip in the caller's process. To know whether the
isolation is still needed, `scripts/accelerator_crash_search.py` runs both decoders
in-process on damaged input, in a process it watches, and reports each crash by its
signature; `.github/workflows/accelerator-crash-search.yml` runs it monthly and on a
lockfile change, on Linux, macOS and Windows. A new signature (any bzip2 crash) turns the
run red; a run with cut inputs that no longer finds this abort suggests it is fixed.

**Upstream.** Not filed. It is the one worth filing: a destructor must not throw, and the
input is only short, not hostile. The throw is the `Finally` guard's `bitReader.seekTo()`
in `GzipChunk::determineUsedWindowSymbolsForLastSubchunk`; wrapping that call in
`try`/`catch` and building 0.16.0 from source ended the aborts, and a cut stream then
raised a catchable `RuntimeError` after every chunk before the cut.

**Evidence.** [`rapidgzip-upstream-report.md`](investigations/rapidgzip-upstream-report.md)
§2; the design and costs are in [`formats/gzip.md`](formats/gzip.md) §2.3.

### Bug 5: rapidgzip keeps the Python file object it reads from (open, contained)

**Symptom.** `IndexedBzip2File(f)` never releases `f`: after `close()` and a garbage
collection, a weak reference to `f` is still alive, and so is every bound method of `f` it
took. Each open also leaks a little native memory. Measured on rapidgzip 0.16.0 with an
`io.BytesIO` subclass, through archivey and directly.

**What archivey does.** bzip2 decodes in a child process (Bug 4), one per stream, and the
child's memory goes when it ends. The child reads a caller-owned stream through this
process, which drops it when the stream closes. Before bzip2 moved to the child, an
in-process shim between rapidgzip and the caller's stream did that, and before the shim,
every accelerated bzip2 open of a `BytesIO` leaked a full copy of its buffer: a fuzz run
over the accelerated bzip2 path ran out of memory after about 36 000 inputs.

**What remains.** Nothing in the caller's process.

**Upstream.** Not filed. The report, with a ten-line reproduction, is ready in
[`investigations/rapidgzip-upstream-report.md`](investigations/rapidgzip-upstream-report.md) §9.

**Evidence.**
`tests/test_accelerator_corruption.py::test_indexed_bzip2_frees_a_stream_source_after_close`
pins that the caller's stream is freed. In-process, Python objects measured with `tracemalloc` over
1 000 opens after 200 warm-up opens of a 4 kB `.bz2`: 0 bytes per open from a path, about 1.7 kB
from an `io.BytesIO`. Native memory measured by RSS over 3 000 opens: 2 to 5 kB per open, noisy,
for every source.

## Intermittent `pyppmd` native aborts on PPMd streams (open upstream)

**Symptom.** pyppmd 1.3.x corrupts the heap (SIGSEGV or SIGABRT on Linux,
`STATUS_HEAP_CORRUPTION` 0xC0000374 on Windows) when a decode asks for more output than the
stream holds: `max_length=-1`, a sized request about 64 KiB or more past the true
remaining output, or a `decode` after `eof`. A sized over-request leaves the worker
waiting for input once it runs past what the range coder's tail lookahead can satisfy,
and freeing the decoder in that state is the crash (bare pyppmd, decoder freed without a
quiesce: +64 and +4096 over, 0/20; +65536 over, 13/20). Valgrind pins the first bad write as a
use-after-free of pyppmd's own output buffer at `ThreadDecoder.c:134`. Random input (a
wrong 7z AES key, a hostile archive) reaches a second route: a model that ended early and
is fed more input segfaults in `Ppmd7_DecodeSymbol`, on 1.2.0 as well. PPMd8 behaves the
same way.

**Affected versions.** The overshoot crash is a regression from 1.3.0's `ThreadDecoder.c`
rewrite (upstream PR #126): 1.1.1 and 1.2.0 do not crash on it but return wrong bytes on
chunked decodes, which is why `[recommended]` requires `pyppmd>=1.3.1`. The random-input
crash affects 1.2.0 and 1.3.x.

**What archivey does.** `PpmdDecoder` (`streams/codecs/ppmd_decoder.py`) bounds every request by
the exact remaining `unpack_size` and never passes `-1`; refuses unsized PPMd7 at
construction; decodes unsized PPMd8 in bounded 64 KiB requests; injects at most one capped
NUL at the end; stops at a spent payload; and hands pyppmd the whole member in one
`decode`, so a short return is the end. Two exceptions are fed in pieces: members over
`DecoderLimits.max_ppmd_held_input` (16 MiB by default), and a ZIP member read from
a stream that cannot seek, whose sizes follow its data, so its input runs on into the rest
of the archive. Fed in pieces, pyppmd 1.3.1 resumes a worker that waited for input with
the output budget and count of the call that started it, so a call can return short at a
false `eof` with input unread, which reads as a spent payload; a valid member raised
`TruncatedError` some KiB short. `PpmdDecoder._native_decode` now asks 1 byte of each call
that brings new input after the first, which stops a resumed worker after one symbol, and
the rest of a new worker; a request of 1 byte needs no split. Every PPMd member decodes in
a child process unless `process_isolation` is `NONE` (`ppmd_child.py`), because the
quiesce NUL can crash pyppmd on small members too; a crash becomes `CorruptionError`
(`ResourceLimitError` for SIGKILL or a refused `mem_size`, `ReadError` for other deaths).
A child is reused only after a member that ended cleanly. Pinned by
`tests/test_ppmd_crash_isolation.py` and `tests/test_ppmd_raw_streams.py`; the
non-blocking PPMd native stress workflow watches for regressions, weekly and on pull
requests that touch the PPMd path.

**What remains.** No crash is confirmed on the in-process path; the defect is upstream,
so the path rests on archivey's call discipline, not on a fixed decoder. A header that
overstates `unpack_size` measured clean: crafted 7z (PPMd7) and ZIP (PPMd8, with and
without an end mark) members overstated by 64 KiB, 1 MiB and 15 MiB, read through
`open_archive` with `read()` and with 64 KiB reads, across text, zero-run, mixed and
random payloads, gave 0 crashes in 860 fresh children and 0 valgrind errors on 12 such
shapes. On those members the worker blocked on input a few hundred to a few thousand
symbols past the true end, and the spent-payload stop and quiesce then held. Two
candidates remain:

1. The teardown NUL on a member that ended early. When a sized decode returns short at
   `eof` with all input fed, `_quiesce_worker` still sends `decode(b"\0", 1)`, up to
   `_PPMD_QUIESCE_MAX_CALLS` times, because pyppmd reports the same flags whether its
   worker waits for input (the NUL is needed, K.5) or its model has ended (the NUL is a
   decode after the end, the K.4 route). archivey sends it on 183 of 200 hostile 7z
   members; in isolation it measured 0 crashes in 100 children
   (`--mode spent-quiesce-nul`, K.4).
2. A sized pack declared complete but corrupt can fill toward `unpack_size` through
   empty drains (the exit-after-green entry below, item 2).

The same NULs sent after a `decode` that raised `ValueError` do crash pyppmd (59 of 100
children for PPMd8, 5 of 100 for PPMd7, `--mode nul-after-error`), but archivey never
makes that call: after the error pyppmd reports `eof`, and `_quiesce_worker` returns
without decoding (0 calls after 370 errors, K.4).

**Upstream.** Not filed. The ready-to-file report, its reproduction scripts and the
verification checklist for a fixed release are
[`ppmd-native-investigation-results.md`](investigations/ppmd-native-investigation-results.md)
§J.

**Evidence.** Same file: root cause §D, archivey's options §I, CI fingerprints, version
matrix, crash-shape rates and the stress workflow §K.

## `pyppmd` exit-after-green abort (`test_ppmd_raw_streams` teardown)

**Symptom.** `tests/test_ppmd_raw_streams.py`, run in its own pytest process, can pass
every test and then die in interpreter teardown or GC with SIGSEGV or
`corrupted size vs. prev_size`. Same pyppmd 1.3.x defect as above, reached at teardown:
`Ppmd7T_Free` wakes a worker still blocked on input, and it writes into the freed output
block.

**What archivey does.** `PpmdDecoder._quiesce_worker`, called from `close()` and
`__del__`, drives a parked worker to `finished` with bounded `decode(b"\0", 1)` before the
decoder is freed. `scripts/ppmd_uaf_valgrind.py` reports 0 memcheck errors on archivey's
scenarios with it. Adversarial unfinished-decoder tests run in subprocess children.

**What remains.**

1. The teardown race. Quiescing removes the use-after-free on the shapes valgrind
   reproduces, but it is defence in depth, not proven elimination: the race is timing and
   platform dependent (hotter on 3.12+, free-threaded builds and Windows). Required CI
   keeps `--allow-exit-after-green` for this module until the valgrind gate runs green on
   those platforms.
2. A sized pack declared complete but internally corrupt can still fill toward
   `unpack_size` through empty drains; the container CRC is the backstop.
3. `pack_size` must measure the same bytes `feed()` counts (the invariant in the
   `PpmdDecoder` docstring); the 7z pipeline satisfies it by construction.

**Upstream.** Part of the same unfiled report (§J above).

**Evidence.** [`ppmd-exit-after-green-exploration.md`](investigations/ppmd-exit-after-green-exploration.md);
[`ppmd-native-investigation-results.md`](investigations/ppmd-native-investigation-results.md)
§D, §I and §K.5.

## PyPy: rapidgzip, python-lz4, pyppmd and inflate64 misbehave (open)

**Symptom.** Under PyPy 3.11 (the allowed-to-fail `pypy3.11` CI job). The versions below
are what that job resolved on 2026-10-20, not floors: rapidgzip 0.16.0, lz4 4.4.5, pyppmd
1.3.1, inflate64 1.0.4. The job's install step prints the versions each run resolves, so
check a newer run before assuming a later release still fails.

- rapidgzip refuses valid gzip streams ("Failed to detect a valid file format"), reads a
  bzip2 stream as empty, and aborts the process when it reads a Python file object.
- python-lz4's frame decoder segfaults on an ordinary frame, and the crash surfaces later
  at unrelated places in the suite.
- pyppmd runs its cffi build, which ends a valid PPMd member early: the decoder relies on
  how the C extension reports the end of data (`ppmd_decoder.py`), and the cffi build
  reports it sooner, so the read returns data cut short.
- inflate64 is wrong in both directions once a call handles more than about 32 KiB. With
  PyPy 3.11.17 and inflate64 1.0.4, measured on 300,000 random bytes:
  - `Inflater.inflate` of a valid stream fed in pieces of 40,000 bytes or more returns
    wrong bytes from offset 128, with no error. Pieces of 32,769 bytes or fewer decode
    correctly.
  - An input of 32 KiB that expands to about 64 KiB segfaults the interpreter.
  - `Deflater` output differs from CPython's from byte 129, and CPython's `Inflater`
    refuses it with error -3. That is the `CorruptionError … error code is -3` in
    `tests/test_zip_walk_codec_end.py::test_a_codec_member_ends_where_its_codec_ends[signed-deflate64]`
    and `[unsigned-deflate64]`, whose fixtures the test compresses with `Deflater`.
  - 1,000,000 bytes of one 44-byte line repeated, passed to one `Deflater.deflate`
    call, segfault the interpreter; 900,000 bytes do not. 1,000,000 zero bytes or
    random bytes do not either.

  A decoder child runs the same interpreter, so process isolation does not help.

**What archivey does.** It treats rapidgzip, python-lz4, pyppmd and inflate64 as absent under
PyPy, whether installed or not (`deps.unused_reason` in `internal/streams/codecs/deps.py`;
`rapidgzip_child` refuses to start the child). `MissingComponent.reason` carries why, and
every report of a missing package (the `PackageNotInstalledError` of a read,
`format_availability()`, the registry's refusal and `archivey --version -v`) shows it in
place of the install advice. LZ4, PPMd and Deflate64 data cannot be read there; `AUTO`
decodes gzip, zlib, deflate and bzip2 with the standard library, and `ON` raises. The tests
treat the four as not installed under PyPy (`UNUSED_UNDER_PYPY` in `tests/conftest.py`).

**What remains.** PPMd reads under PyPy need either a pure-Python PPMd decoder or a
workaround for how pyppmd's cffi build reports the end. LZ4 needs a python-lz4 that runs
under PyPy. rapidgzip needs upstream support for PyPy. Deflate64 needs an inflate64 that
handles large buffers under PyPy (its cpyext build), or a pure-Python Deflate64 decoder.

**Upstream.** Not filed with rapidgzip, python-lz4, pyppmd or inflate64.

**Evidence.** The `pypy3.11` job logs in CI; PyPy is not a supported interpreter
([`docs/install.md`](../docs/install.md) §PyPy).

## Intermittent Linux full-suite heap corruption (`[all]` / Hypothesis late crash)

**Symptom.** On GitHub Actions `ubuntu-latest` required legs with `--extra all` or
`all-lowest` (py3.11 to 3.13, sometimes 3.14), the suite process dies with
`Fatal Python error: Segmentation fault` (exit 139) or `Fatal Python error: Aborted` (exit
134). The stack at death is a late symptom of a heap already corrupt, not the corrupting
call:

| Crash site (examples) | What it means |
|-----------------------|---------------|
| `Garbage-collecting` → `hypothesis/internal/charmap.py` during `test_property_safety.py::test_normalize_total_and_idempotent` | Hypothesis touches the allocator after earlier native work poisoned the heap |
| `Garbage-collecting` → `subprocess._close_pipe_fds` / `Popen` in `rar_unrar.open_unrar_p` (e.g. `test_multi_volume_stream_materialization`) | GC plus a new subprocess while the heap is bad |

Fatal logs list `backports.zstd`, `lz4`, `_brotli`, `pyppmd.c._ppmd`, `rapidgzip` and
`_cffi_backend` among the loaded extension modules. `[core-only]` legs and the macOS and
Windows `[all]` legs are typically clean on the same commits. A local
`uv run --no-sync pytest tests/ -q` is often green, so there is no one-shot repro. This is
not the pyppmd defect above: a green PPMd stress run does not clear it, and the fatal
stacks are not in a PPMd decode.

**Suspects (unconfirmed).**

1. The in-process rapidgzip decoder in a long-lived pytest process. Every codec now runs
   rapidgzip in a child process (Bug 4), bzip2 included, so the suite's own process no
   longer loads it. The last recorded red runs predate the move and the rate has not been
   re-measured since.
2. Allocator layout: many natives loaded together, plus coverage and GC, with Hypothesis
   or `subprocess` only the tripwire.
3. Not the gzip/zlib truncation-recovery logic: the crashes do not stack in
   `DecompressorStream` or `verify.py`.

**What archivey does.** CI splits the required `[all]` and `[all-lowest]` jobs into four
steps so a corrupted heap in one cannot take down another. That is CI hygiene, not a
product fix.

**What remains.** The cause. The next step is a soak rate, then an A/B run without
rapidgzip.

**Upstream.** Unknown owner; nothing to file yet.

**Evidence.** [`linux-heap-corruption-soak.md`](investigations/linux-heap-corruption-soak.md):
the CI step split, the soak and A/B recipes, and the recorded red runs.

## PyPy: a C `bool` member reads as an int (open, upstream)

**Symptom.** Under PyPy 3.11.17, a C extension's `bool` struct member (`Py_T_BOOL`) can read
as an int. backports.zstd's `ZstdDecompressor.eof` reads `False` before a frame ends and the
int `1` after it, where CPython gives `True`; `needs_input` read `False` in the same run.
A check that wants `isinstance(value, bool)` drops it, which is how every zstd read in a
decoder child failed with `AttributeError: eof`.

**What archivey does.** The decoder worker takes any int as a flag and sends `bool(value)`
(`_state` in `internal/streams/codecs/decoder_worker.py`). Pinned by
`test_a_flag_read_as_an_int_is_reported_as_a_bool` and
`test_an_int_flag_reaches_the_parent_as_a_bool` in `tests/test_decoder_child.py`.

**What remains.** Any other code that type-checks a flag read from a C extension for `bool`
has the same gap. Truth tests (`if decoder.eof:`) are unaffected.

**Upstream.** Not filed with PyPy.

**Evidence.** A two-line check under PyPy 3.11.17:
`d = ZstdDecompressor(); d.decompress(compress(b"abc")); type(d.eof)` is `int`.

## PyPy: `BufferedRandom.readinto` over-reports its last partial fill (open, upstream)

**Symptom.** Under PyPy 3.11.17, `io.BufferedRandom.readinto` (a file opened `w+b` or
`r+b`, also under `tempfile.NamedTemporaryFile` and a spilled `SpooledTemporaryFile`)
returns more than it filled when fewer bytes are left than the buffer holds. For a
5,000-byte file read into a 128-byte buffer, the last call returns 16 for the 8 bytes
left, so a caller that trusts the count takes 8 stale bytes from the buffer; 300 bytes
read 128 at a time give 344. `read` and a read-only `BufferedReader` are right, and a call
whose buffer is no larger than what is left is right too.

**What archivey does.** Under PyPy, `ArchiveSource`, the one wrapper over a caller's
stream, fills its buffer with `read` instead of the caller's `readinto`
(`_readinto_or_stall` in `internal/source.py`). Pinned by
`test_readinto_over_a_read_write_file_counts_only_what_it_filled` in
`tests/test_archive_source.py`, which fails under PyPy without it, and on CPython by
`test_under_pypy_the_boundary_reads_and_never_trusts_a_readinto_count`, which forces the
PyPy flag over a double that over-reports the same way. The `spooled_tempfile` and
`named_tempfile` cases of `test_readinto_yields_content` in `tests/test_stream_inputs.py`
call the file's own `readinto`, so they skip under PyPy.

**What remains.** Nothing beyond the pins above; the PyPy CI job runs both of them.

**Upstream.** Not filed with PyPy.

**Evidence.** Write 5,000 bytes to `open(path, "w+b")`, `seek(0)`, then call
`readinto(bytearray(128))` until it returns 0: the counts add up to 5,008.

## PyPy: buffer views and non-blocking `readinto` (open, by design upstream)

**Symptom.** Two PyPy 3.11 behaviours that CPython does not share. A `memoryview` that
goes out of scope is released only at a garbage collection, so a caller that resizes the
buffer it handed to `readinto` (`RawIOBase.read` does) gets `BufferError: Existing exports
of data: object cannot be re-sized`. And a non-blocking buffered reader with nothing ready
answers `readinto` with 0, the same as at the end, where CPython answers `None`.

**What archivey does.** Every `readinto` releases its views before it returns, a rule in
`try_readinto`'s docstring and in CONTRIBUTING.md §Coding standards. `ArchiveSource`, the
one wrapper over a caller's stream, asks a 0 again with `read` (`_readinto_or_stall` in
`internal/source.py`), so a stall raises `BlockingIOError` instead of passing for the end.
That is the CPython path. Under PyPy the caller's `readinto` is not called for a
non-empty buffer (see the `BufferedRandom.readinto` entry above): `read` answers a stall
with `None`, which raises the same way, so no 0 arrives to be asked again. The zero-answering doubles in
`tests/test_archive_source.py` pin the 0-confirm on CPython only; under PyPy they reach
`read` directly.

**What remains.** A new `readinto` that keeps a view fails CI only if a test resizes its
buffer under PyPy, and the 0-confirm is still exercised on CPython only.

**Upstream.** Not filed; both are documented PyPy behaviour rather than bugs.

**Evidence.** The PyPy job in `.github/workflows/ci.yml`; the tests named above.

## PyPy: native decoder memory (open, by design upstream)

**Symptom.** Under PyPy 3.11, after the suite has run for a while, every `subprocess` call
in a worker fails with `OSError: [Errno 12] Cannot allocate memory` from `_fork_exec`,
while the worker's RSS is only a few GB. A PyPy decoder from `lzma` (cffi), `bz2`,
`backports.zstd` or `brotli` frees its native buffers only when a major collection takes
it, and their size is invisible to the GC, so that collection comes late. A run that drops
thousands of decoders keeps their dictionaries allocated, glibc grows its heap to hold
them, and `gc.collect()` frees them without shrinking the heap. With heuristic overcommit,
`fork` refuses once the private writable mappings outgrow RAM plus swap.

**What archivey does.** `internal/streams/native_memory.py`. Each decoder `Natives` builds
in-process reports its likely size with `__pypy__.add_memory_pressure`, as PyPy's own
`LZMACompressor` does:

- liblzma: the filter chain's dictionary, else 8 MiB, capped by `memlimit`;
- zstd: 8 MiB, capped by `window_log_max`;
- bzip2: 3.5 MiB;
- brotli: 4 MiB.

A decoder's `close` also ends its liblzma decoders with `ffi.release` and cancels their
pressure, because only the stream declares the real dictionary (up to 4 GiB uncapped).
Pinned by `tests/test_decoder_memory_pressure.py`: each estimate exactly, and 1,600 dropped
xz decoders in a fresh interpreter, where the last 800 must add under 2 GiB through `/proc`.
With the accounting, the growth levels off at whatever pressure PyPy lets build before a
major collection. That level is large and varies: 800 drops reached 3,725 MiB in an xdist
worker (PR #901) and 2,120 MiB in a fresh interpreter (PR #951), and both passed on a
re-run. So the test checks that growth levels off, not how high. Without the accounting,
growth is linear at 8 MiB per drop. The drops run in a child process because the worker
reading was 1.76 times the fresh one, likely because PyPy's threshold scales with the heap
the last collection left (inferred, not reproduced). Each CI run writes the curve to the
job summary.

**What remains.** A zstd frame can reserve up to `window_log_max` (2 GiB under the default
`max_decoder_memory`) and nothing frees it before a collection, nor a brotli window over
4 MiB: neither library can free its state early under PyPy, and reporting the cap would
force a major collection per decoder. A caller who drops streams unclosed relies on the
estimates alone. The PyPy CI job runs the pins above; nothing measures the zstd or brotli
windows, what a caller who leaves streams unclosed really uses, or what the same drops
cost in a long-lived process with a large heap, the shape the ENOMEM failures had.

**Upstream.** Not filed; PyPy documents that native memory needs
`add_memory_pressure` from whoever allocates it.

**Evidence.** PR #927. On main, the PyPy job's extras step had 163 failures and
53 errors, 154 of them ENOMEM, with one worker's `[heap]` mapping at 74 GB. With the fix
it had 35 failures, 12 errors and no ENOMEM. On the runner, 800 dropped default-preset xz
decoders hold 9 MB on CPython and 6.4 GB on PyPy; with 8 MiB of pressure each, the PyPy
heap stays at 82 MB. The xdist worker count and `PYPY_GC_MAX` are not the cause.
