# Snappy packages and compress-utils as archivey backends

**compress-utils 0.12.1: worth a limited accelerator prototype, with LZO1X first.**
Its self-contained, permissively licensed wheels could replace the optional GPL
`python-lzo` kernel without removing archivey's Python fallback. It also exports a C
API with resumable, fixed-size output buffers. A working experimental adapter retained
archivey's framing and matched acceptance and bytes for eight overlapping framed
codecs in this sample. Integration is not ready: its LZO decoder rejects four end
markers archivey accepts, error translation and dictionary limits need work, and its
Python API does not implement resumable `max_length`. Keep existing defaults. Measure
an isolated LZO wrapper with fallback before considering gzip/zlib acceleration.

**aff4-snappy 0.5.1: do not integrate.** It is a 2017 distribution of old
python-snappy with Google Snappy 1.1.3 bundled. Its unmodified extension failed to
build on CPython 3.11, archivey's minimum Python version. It has no wheels and
conflicts with python-snappy's import name. The source has raw and framed Snappy,
but offers no capability that justifies repairing and maintaining this fork.

**py-snappy 0.1.0a1: do not integrate, including as a pure Python fallback.** The
raw decoder accepts an invalid zero-offset copy and produces four zero bytes. It
also rejects valid COPY_4 instructions. Its list-based decoder used about 452 MiB
of additional peak RSS for 16 MiB of output and decoded the 1 MiB benchmark at about
0.2 MB/s. These correctness, memory and performance costs outweigh its small wheel.

**python-snappy 0.7.3: use as an interoperability test dependency if needed, not a new
backend.** Its raw decoder already calls cramjam, so it provides no independent
implementation. Its framed wrapper silently accepts truncated input and synthesizes a
missing stream identifier. A valid Hadoop block with two compressed subblocks returns
only half its data. A new `.sz` plugin should own framing and EOF checks in Python
instead of depending on these wrappers.

**python-snappy-pure 0.2.0: do not integrate in its current form.** It is a small,
readable raw Snappy implementation with COPY_4 support, but accepts a missing length
header and ignores bytes after the declared output. It allocates the complete declared
output before decoding. Its 1 MiB result was about 27 MB/s here. It could inform a new
bounded Python implementation after those defects are repaired. It is not a safe
fallback as released, and PyPy performance was not measured.

**pysnappy 0.8.2: useful as an independent test oracle, especially for Hadoop, but
not a preferred runtime dependency.** Its Google Snappy binding decodes the valid
multi-subblock Hadoop case that python-snappy loses. Its framed decoder checks CRC
and unfinished chunks, but accepts an uncompressed chunk larger than the format's
64 KiB limit. Wheels cover only Linux CPython 3.11–3.13. The compiled Google Snappy
version is not disclosed, and the wheel's license notices need clarification. A
Python-owned `.sz` framer could use its raw kernel, but cramjam and compress-utils
have broader wheel coverage.

## Scope and evidence

**Measured:** 2026-11-16, archivey `main` at
`205bed416e359ab96b3c17eb9b2067b7389f3211`, Linux x86-64, glibc 2.41,
CPython 3.11.18. The host exposes three CPUs with a two-CPU quota. Versions above
are exact PyPI releases. Cramjam 2.14.0 is included as comparison context, using its
normal C-backed wheel. It is not counted as an independent python-snappy backend.
A separate CPython 3.14.10t probe is described below.

**Read:** the exact releases' sdists, tests, PyPI artifact metadata, repository sources
and public issues. The scripts, observations and repro inputs are in
[`scripts/investigations/snappy_compress_utils/`](../../scripts/investigations/snappy_compress_utils/).
`results/packaging.json` records release dates, wheel tags, artifact URLs and SHA-256
hashes. Source claims and measurements are distinguished below. Windows, macOS, PyPy and
sanitizer execution are not measured. A passing sample is not a proof of parity on all
possible inputs.

This extends [the cramjam/unpackio investigation
PR](https://github.com/archivey-dev/archivey/pull/1583). It follows the [libarchive
evaluation](libarchive-accelerator.md): compare damaged input and full bytes before
speed, preserve every difference, and include wrapping costs. It changes no runtime
code, dependency, format registration or changelog.

None of these six packages reads an archive container. Snappy raw blocks, `.sz`
framing and Hadoop blocks have no member names, links, directories, passwords,
volume handling or extraction policy. Those questions are therefore inapplicable
to these candidates. Passing an entire archive to one of their decoders does not
create a container backend. Framed streams can be incremental; raw APIs generally
retain the whole decoded block. Details differ below.

## archivey's current implementations and constraints

**Read:** `StreamCodec` and the registry in `internal/streams/codecs/`,
`FramedDecoder` in `decompressor_stream.py`, the experimental public `CodecHandler`,
`CodecCall`, `register_codec` and format APIs in `formats.py`, `OptionalLibrary`,
`DecoderLimits`, and the accelerator/isolated-decoder machinery.

| Codec / variant | Current backend | Optional component |
| --- | --- | --- |
| gzip, zlib, raw DEFLATE | stdlib zlib plus Python framing | rapidgzip acceleration |
| bzip2, including concatenation | stdlib bz2 plus Python framing | rapidgzip acceleration |
| XZ, LZMA Alone, raw LZMA1/LZMA2, lzip | stdlib lzma plus Python envelopes | none |
| Zstandard frames and skippable frames | stdlib compression.zstd on 3.14+, backport below | backports.zstd below 3.14 |
| LZ4 modern/legacy frames, raw blocks, mozlz4 | lz4.frame/block with Python envelopes | lz4 |
| Brotli | output-bounded brotli process API | brotli >=1.2.1 |
| LZO1X / lzop | Python decoder and framing | detected python-lzo kernel |
| PPMd7 H / PPMd8, Deflate64 | isolated/bounded native adapters | pyppmd >=1.3.1,<2; inflate64 |
| Unix compress .Z | Python LZW | none |
| bzip3 | native bz3, normally isolated | separate bzip3 extra |
| ZIP Shrink, Reduce 1–4, Implode, DCL Implode | Python | none |
| CAB MSZIP / LZX | zlib and Python MSZIP / Python LZX | none |
| LHA LZH/LArc and ARJ methods 1–4 | Python | none |
| Delta, x86/ARM/Thumb/PPC/SPARC/IA64 BCJ | stdlib raw LZMA filter chains | none |
| BCJ2, ARM64, RISC-V filters | Python | none |
| stored, sparse, ZipCrypto, uuencode/base64 | Python / stdlib | none |
| 7z/RAR/ZIP AES | cryptography block operations, stdlib KDF/hash | cryptography |
| Snappy raw, framed .sz, Hadoop | absent | none |

`recommended` installs pyppmd, inflate64, the Zstd backport where needed, Brotli,
LZ4, cryptography, pycdlib and tqdm. `seekable` installs rapidgzip. `all` combines
those extras. `free-threaded` is a measured subset with version markers. `bzip3`
is separate. Python-lzo is detected when present, not installed by an extra.
Zero-dependency core remains the rule, including after any optional integration.

| Container / format | Current format backend and variants | Optional parts |
| --- | --- | --- |
| ZIP / ZIP64 / SFX | Python parser | member codecs / AES above |
| TAR | Python V7/ustar/GNU/pax and sparse parser | outer codecs |
| 7z | Python header/coder graph; solid, SFX, split byte volumes | member codecs / AES |
| RAR3 / RAR5 | Python metadata; unrar or supported unar for data | external decoder, AES headers |
| ISO9660 | pycdlib; Python sector/CUE adapters, Rock Ridge/Joliet/zisofs | pycdlib; no UDF reader |
| CPIO | Python binary both byte orders, odc/newc/crc | outer codecs |
| ar / Debian / RPM / makeself | Python envelopes and nested payload readers | payload codecs |
| SquashFS 4 | Python index; gzip/LZMA/XZ/LZO/LZ4/Zstd blocks | LZ4/Zstd; optional python-lzo |
| CAB | Python cabinet and stored/MSZIP/LZX folder readers | no Quantum or cabinet sets |
| XAR | Python XML/heap; zlib/bzip2/LZMA/XZ members | none |
| LHA | Python header levels 0–3, stored and supported LZH/LArc methods | none |
| ARJ | Python headers and methods 0–4 | no garbled/split members |
| Directory / single compressed file | Python filesystem / registered stream reader | codec-specific |

LHA methods are `-lh0-`, `-lz4-`, `-pm0-`, `-lh1-`, `-lh4-` through `-lh7-`,
`-lhx-`, `-lk7-`, `-lzs-` and `-lz5-`. Sequential formats compose with registered
outer compression streams. DMG is detected and refused, not readable.

[Design rules](../design-rules.md), [code map](../code-map.md) and the
[ADRs](../decisions/index.md) constrain all six candidates equally:

- DR-1/DR-5 require the same complete bytes and error types regardless of installed
  accelerators. No rule authorizes these candidates' silent acceptance or data loss.
  DR-5a's narrow malformed-input exceptions do not permit wrong bytes.
- DR-3 distinguishes trailing data outside an archive from hidden bytes inside a
  member. A candidate's strict whole-buffer API cannot override archivey's framing.
- DR-9/DR-9a require bounded output and preflight checks for attacker-declared
  windows, dictionaries and blocks against `max_decoder_memory`. Slicing a fully
  decoded result does not meet that requirement. Detection probes also need bounds.
- DR-20 keeps parsers in Python and isolates native codecs that can crash. A C
  API or free-threaded wheel does not exempt it from process isolation.
- ADRs 0001/0002/0020/0021 keep container parsers under archivey's policies.
  ADR 0010 forbids hidden spooling to manufacture seeking. ADR 0011 keeps the core
  free of third-party dependencies. ADR 0009 selects stdlib/backports Zstandard.
- ADRs 0003/0007/0013 preserve capabilities, late metadata and name/link policy.
  ADR 0014 makes a completed read the integrity boundary. ADR 0022 covers PPMd
  isolation. None is changed by this investigation.

A format plugin implements `IndexedFormatHandler` / `SequentialFormatHandler` and
returns an indexed reader (`iter_members`, `open_member`) or a sequential reader
(`walk`). `ReaderContext` owns name normalization, metadata charges, diagnostics
and nested decompression. No candidate supplies such a reader. Snappy belongs in
`CodecHandler`, not a replacement container handler. This plugin API is outside
archivey's stability policy and can change in a patch release; pin the archivey
version for a separately distributed plugin.

## Snappy implementations, variants and fit

Fit categories: **a** replace an existing backend; **b** optional accelerator;
**c** add missing capability; **d** does not fit as released. There is no archivey
Snappy baseline, so Snappy safety comparisons use validated system Google Snappy
1.2.2 plus a separate strict `.sz`/Hadoop reference. Snappy speed ratios below
compare with pysnappy's Google kernel through the same dispatch helper, not archivey.
Ratios are 1 MiB results, greater than 1 is faster. Small results appear later.

### aff4-snappy 0.5.1

**Read:** [PyPI](https://pypi.org/project/aff4-snappy/0.5.1/) points to the old
andrix/python-snappy repository, now redirected to
[intake/python-snappy](https://github.com/intake/python-snappy). This distribution
was made for PyAFF4. Its bundled headers identify Google Snappy **1.1.3**.
The wrapper and Snappy code use BSD-3-Clause. The bundled CRC32C source was
produced by pycrc 0.7.11. The published artifact contains no separate functioning
`snappy_cffi.py`, despite its PyPy fallback import and conditional cffi dependency.
Do not infer modern Python/PyPy support from the old classifiers.

| Codec / variant | Current archivey | Candidate | Fit | Safety | Speed ratio |
| --- | --- | --- | --- | --- | --- |
| raw Snappy | absent | bundled Google Snappy 1.1.3 | d | not runnable on CPython 3.11 | unmeasured |
| framed Snappy .sz | absent | Python framer, bundled raw kernel/CRC32C | d | source only; flush checks pending bytes; no 64 KiB decoded-chunk guard | unmeasured |

One-shot `compress`/`decompress` and `StreamDecompressor.decompress`/`flush`
are present. There is no Hadoop API, `max_length`, `eof`, or `unused_data` contract.
Source raises `UncompressError` for invalid framing, CRC mismatch and unfinished
chunks. Full raw blocks allocate their declared output. A custom bounded framer
would still be necessary after repairing the build. The isolated build failed at
`snappymodule.cc:71`, `Py_SIZE(str) = actual_size`, with “lvalue required”. The
failure log is saved. Its tests were read, but cannot be run against this artifact
on the measured interpreter; substituting installed python-snappy would test a
different package.

### py-snappy 0.1.0a1

**Read:** [PyPI](https://pypi.org/project/py-snappy/0.1.0a1/),
[repository](https://github.com/ethereum/py-snappy). This is an independent pure
Python raw codec, inspired by Google's implementation, MIT licensed. It imports
as `py_snappy`. There is no bundled C/Rust library or separately versioned codec.

| Codec / variant | Current archivey | Candidate | Fit | Safety | Speed ratio |
| --- | --- | --- | --- | --- | --- |
| raw Snappy literals/COPY_1/COPY_2 | absent | Python 0.1.0a1 | d | invalid zero-offset copy accepted | about 0.00004x |
| raw Snappy COPY_4 | absent | explicitly unsupported | d | valid input refused | not applicable |

Only one-shot APIs exist. It converts input to a tuple and allocates the declared
output as a list before decoding. Literal copies rebuild that list, which explains
poor scaling on literal-rich inputs. There is no output cap, incremental state,
framing, checksum, or end-of-input API. `BaseSnappyError`, `CorruptError` and
`TooLargeError` are public; unsupported COPY_4 raises `BaseSnappyError`. Standard
truncated/invalid blocks are usually refused, but the zero-offset acceptance is a
counterexample. Trailing input is normally parsed and rejected, not preserved as
`unused_data`. Raw Snappy has no checksum, so some bit flips remain valid changed data.

### python-snappy 0.7.3

**Read:** [PyPI](https://pypi.org/project/python-snappy/0.7.3/),
[repository](https://github.com/intake/python-snappy). It imports as `snappy`.
The BSD-3-Clause Python wrapper delegates raw compression/decompression to
`cramjam.snappy.*_raw`; its dependency is unpinned `cramjam`. Here that is
cramjam 2.14.0, the Rust `snap 1.1.1`-based Snappy implementation evaluated in PR 1583.
The wheel itself is pure Python; the transitive codec is native. Cramjam is MIT,
and snap 1.1.1 is BSD-3-Clause. Its umbrella wheel also brings flate2 1.1.10 /
miniz_oxide 0.9.1 (MIT/Apache-2.0/Zlib alternatives), Rust Brotli 8.0.4 /
brotli-decompressor 5.0.3 (BSD/MIT), libbzip2 1.0.8 (bzip2 license), LZ4 1.10.0
(BSD-2-Clause), liblzma 5.2.5 (public-domain/per-file permissive notices), and
libzstd 1.5.7 (BSD). Rust wrapper crates carry their own permissive notices. This
is the transitive bundle identified in PR 1583, not a new binary-license audit.
Adopting this 9 KiB wrapper still means maintaining that native dependency.

| Codec / variant | Current archivey | Candidate | Fit | Safety | Speed ratio |
| --- | --- | --- | --- | --- | --- |
| raw Snappy, all copy forms | absent | cramjam 2.14.0 raw kernel | c only through a new framer | matched 451-case sample; not independent of cramjam | 1.31x |
| framed Snappy .sz | absent | Python buffering plus cramjam decoder | d | 402 candidate-only accepts in 469 cases | no archivey ratio |
| Hadoop Snappy | absent | Python block wrapper over raw kernel | d | accepts incomplete blocks; valid two-subblock data loses half the bytes | no archivey ratio |

`StreamDecompressor` and `HadoopStreamDecompressor` accept incremental input but
have no resumable output cap or reliable EOF state. `flush()` does not validate
all pending framed input. The framed wrapper adds an identifier when missing.
It handles normal concatenated chunk streams, but arbitrary partial chunks can
produce success at flush. Raw errors become `UncompressError`; framed native CRC
and protocol failures can escape as `OSError`. Hadoop errors include wrapper
exceptions. `copy()` returns the same object, not an independent decoder snapshot.
None of those behaviors meets archivey's decompressor contract without new framing.

### python-snappy-pure 0.2.0

**Read:** [PyPI](https://pypi.org/project/python-snappy-pure/0.2.0/),
[repository](https://github.com/Valmarelox/python-snappy). It imports as
`python_snappy`, distinct from `snappy`. This MIT Python implementation supports
all four raw tag forms. Its codec implementation has the package's version.

| Codec / variant | Current archivey | Candidate | Fit | Safety | Speed ratio |
| --- | --- | --- | --- | --- | --- |
| raw Snappy, including COPY_4 | absent | Python 0.2.0 | d until repaired | 4 candidate-only accepts in 451 cases; ignores trailing data | about 0.002x |

One-shot only; no `.sz`, Hadoop, checksums, output cap or incremental decoder.
It allocates a bytearray from the declared length. Its loop stops when that output
length is filled, accepting concatenated raw blocks or arbitrary trailing bytes.
An empty input returns empty bytes without a length header. Other malformed copies,
including zero offset, are checked. Errors use the confusingly named
`CompressionError` under `SnappyError`, also for decompression. Its own tests compare
with python-snappy, which here means cramjam; the Google C oracle gives an independent
check. A repaired bounded decoder would be new work rather than a wrapper alone.

### pysnappy 0.8.2

**Read:** [PyPI](https://pypi.org/project/pysnappy/0.8.2/),
[repository](https://github.com/aeroevan/pysnappy), found from the distribution and
GitHub search. This is a Cython wrapper around Google Snappy with Cython `.sz`, Hadoop
and CRC32C code. `CMakeLists.txt` uses unversioned `find_package(Snappy REQUIRED)`. The
Linux wheel has no dynamic libsnappy dependency, but does not identify the exact
statically compiled Google Snappy version. That version is **unknown**, not assumed to
equal the separate system oracle's 1.2.2. Wrapper code is MIT; Google Snappy is
BSD-3-Clause.

| Codec / variant | Current archivey | Candidate | Fit | Safety | Speed ratio |
| --- | --- | --- | --- | --- | --- |
| raw Snappy, all copy forms | absent | compiled Google Snappy, version undisclosed | c behind a new Python framer | matched 451-case sample | 1.04x control |
| framed Snappy .sz | absent | Cython framer / CRC32C | d as supplied | oversized decoded chunk accepted; EOF checks stronger than python-snappy | no archivey ratio |
| Hadoop Snappy, multiple subblocks | absent | Cython Hadoop framer | c as an explicit block codec / test oracle | valid two-subblock case correct; no per-call cap | no archivey ratio |

Raw `compress`, `decompress`/`uncompress`, `RawDecompressor`, and framed/Hadoop
`decompress`/`flush` are available. There is no `max_length`, `needs_input`, EOF
or unused-input contract. Full raw output is allocated; framed APIs can emit all
chunks supplied in one call. CRC, truncated chunks, missing identifier and unknown
mandatory chunk errors are generic `Exception`, with messages such as “crc mismatch”
or “Chunk truncated”. Concatenated framed chunks work. Empty framed input is
accepted; our strict reference requires an identifier. That is a framing policy
choice to settle in a new plugin, not evidence of wrong nonempty member bytes.

### A bounded Snappy wrapper

**Proposed, not integrated:** define a `PluginStream` for `.sz`, register a
`CodecHandler` with magic `ff 06 00 00 73 4e 61 50 70 59`, and implement
`decompressor(call)`. The returned object must provide
`decompress(data, max_length)`, `needs_input`, `eof`, `unused_data` and `end_input()`.
Framing has no final marker, so EOF must refuse unfinished headers/payloads and drain
validated output. Validate the mandatory identifier, 24-bit chunk lengths, reserved
chunk rules, masked CRC32C and the **decoded** 64 KiB chunk maximum. Check a compressed
chunk's raw length before native allocation. Feed at most one bounded chunk to the
raw kernel, then deliver at most `max_length` bytes from it. A 64 KiB decoded chunk
buffer is bounded; a whole-file buffer is not. Honor lower caller limits as well.

CRC must validate before a chunk is treated as verified. Raw Snappy has no checksum;
its integrity level cannot promise more than the wrapper/container provides.
Implement CRC32C independently or select an explicit dependency; zlib.crc32 is the
wrong polynomial. Avoid native framed wrappers with the observed EOF/size bugs.
Optional native kernels must be separately excludable and isolated where required.

Hadoop framing lacks a unique file magic. Offer it only with explicit format/codec
selection and declared block limits; do not add broad automatic file detection.
It requires multiple compressed subblocks per uncompressed block and exact totals.
A plain raw Snappy codec also needs an explicit bound, not a guessed file format.

## compress-utils 0.12.1

### Codec inventory, versions and licenses

**Read:** [PyPI](https://pypi.org/project/compress-utils/0.12.1/),
[repository](https://github.com/dupontcyborg/compress-utils), `codec-versions.json`,
`third_party/manifest.json`, algorithm sources and `THIRD_PARTY_NOTICES.md` in the
release. This is a C codec core with a C++/pybind11 Python extension, not a Rust
codec implementation. It has other language bindings, which were not measured.

| Algorithm / variant | Compiled implementation | Version / provenance | License |
| --- | --- | --- | --- |
| Zstandard frame | libzstd | 1.5.7 | BSD-3-Clause selected from dual license |
| Brotli stream | Google Brotli | 1.2.1 | MIT |
| zlib wrapper, gzip, raw DEFLATE | zlib-ng in compatible mode | 2.3.3 | Zlib |
| bzip2 | libbzip2 | 1.0.8 | bzip2-1.0.6 license |
| LZ4 modern frame, raw block without size prefix | liblz4 | 1.11.0 | BSD-2-Clause |
| XZ; `lzma` alias | liblzma | 5.8.4 | 0BSD |
| raw Snappy, all copy forms | first-party C core | compress-utils 0.12.1; Google/Intel snappy-c design provenance | own MIT plus BSD-3-Clause Google/Intel notices |
| raw LZO1X, decoding only | checked C adaptation of lzokay | AxioDL/lzokay `db2df1fcbebc2ed06c10f727f72567d40f06a2be` | MIT, Jack Andersen |

Snappy's documented predecessor is andikleen/snappy-c at
`fef67ac6effb40c83fb5e37eaf243381fa056f9b`. Google Snappy **1.2.2** is included as
an independent **test oracle**, not the runtime codec. Do not list it as the bundled
Snappy implementation. Likewise, LZO decoding here does not bundle GPL liblzo2.

`lzma` is an alias for **XZ**, not LZMA Alone, raw LZMA1 or raw LZMA2. The measured
LZMA Alone input is refused. Modern LZ4 framing is supported; archivey's legacy LZ4
frame envelope and mozlz4 size prefix still need Python parsing around raw blocks.
No `.sz`, Hadoop, lzop envelope, lzip, `.Z`, LZO-RLE/dictionary mode, Deflate64,
PPMd, bzip3, archive format, or archive encryption API is supplied. All listed
codecs compress and decompress except LZO, which only decodes. Raw LZ4 compression
is one-shot; it has no incremental encoder.

Version pins describe the released source build; they are not a separate binary
attestation of each wheel object. The wheel ships the core MIT license and third-party
codec notices listed above. The binding uses pinned pybind11 **3.1.0** (BSD-3-Clause);
its BSD notice was not found in those two wheel license files, so include that in an
upstream notice check before redistribution. The Linux extension also links libc, libm,
libgcc and **libstdc++**. “No system libraries” means no external codec libraries; it
does not mean no C/C++ runtime. The sdist's bundled CPython 3.13 wheel is not used by
these measurements or by the source's intended build.

### API, output bounds and errors

**Measured/read:** `compress(data, algorithm, level=...)` and
`decompress(data, algorithm, expected_size=None)` are one-shot calls.
`expected_size` is an output **upper bound**, not an exact required length.
A process-wide output limit defaults to **1 GiB**; setting it to zero removes it.
The implementation uses atomic access to that setting, but changing a global limit
cannot express different simultaneous archivey callers' limits. Use per-decoder
bounds. An output limit also does not cap a codec dictionary.

`DecompressStream(algorithm, single_stream=False, max_output=None)` accepts
incremental input through `decompress(data)`. `finish()` validates incomplete input.
`max_output` is a **terminal cumulative limit**, not resumable per-call output.
It raises `CompressError` when exceeded. `single_stream=True` exposes `eof` and
`unused_data`; feeding later data can raise `EndOfStreamError`, which also derives
from EOFError. The default handles concatenation for standard streams, subject to
codec differences. A wrapper must use the single-stream mode and let archivey own
concatenation, padding and trailing-data policy.

One-shot checksum/corruption/truncation errors use `CompressError`, often with
“compressed input truncated” or a backend message. Some standard checksums have
no corresponding raw-format checksum. All six explicit integrity-field mutations
were refused by archivey, the Python API and the bounded prototype. One-shot APIs
refuse several tails/concatenations that archivey reads with diagnostics or its
own concatenation policy. Those are parity failures of direct replacement even
though stricter refusal is not silent corruption.

**Measured C API prototype:** the wheel extension exports
`cu_decompress_stream_create_ex`, `write`, `finish`, `eof`, `unused`, `destroy`
and `cu_last_error`. `write` accepts a caller-owned output buffer and length.
Status `CU_ERR_BUF_TOO_SMALL` (3) means it can retain input and resume with empty
input and another output buffer. This is different from the Python binding.
The experimental `c_api.py` supplied 17-byte output buffers, drained all eight
framed codecs, observed EOF and recovered the exact `TAIL` as unused data.
It also kept archivey's `FramedDecoder` around the candidate decoder.

The pinned-header comment and named constants in `c_api.py` identify the C ABI.
C status codes are OK 0, argument 1, level 2, buffer-small 3, unknown-size 4,
unsupported 5, compression 6, decompression 7, truncated 8, size-limit 9,
finished 10, state 11, OOM 12 and internal 13. Error details are thread-local.
The prototype turns status 8 into EOFError and other failures into `CoreError`;
it does **not** claim archivey's final exception taxonomy. Python `CompressError`
messages alone are insufficient for reliable typed error translation.

The adapter proves feasibility, not production readiness. It has no per-call
`max_length=0` input-retention implementation, dictionary preflight, production
error translator, child-process bridge or cross-platform ABI test. Raw Snappy
retains input and decodes the complete block on finish: the C buffer bounds bytes
**returned**, but does not prevent the full output allocation. Raw LZO/LZ4 use
incremental parsing/history; callers still need the container's block size and
working-memory limit. XZ's internal **256 MiB** decoder cap is hardcoded and does
not honor an arbitrary `DecoderLimits` value. Lower limits need preflight; higher
limits need a canonical fallback. Zstd windows and other declared work also need
archivey's existing checks. Keep unrelated global settings out of codec calls.

A production accelerator belongs in the existing internal
`StreamCodec.decompressor(params, config)` selection, with an `OptionalLibrary`
entry and exclusion handling. It must not register a duplicate built-in codec.
The adapter implements the same bounded `decompress`/EOF contract as a
`CodecHandler.decompressor(call)` result. Keep `FramedDecoder` and existing
header-memory checks, and connect native calls to archivey's decoder-child
protocol. Map typed corruption/truncation/resource statuses separately; do not
turn OOM into corruption. A generic `CompressError` alone cannot do that mapping.

For LZO, the smaller route is the existing block-kernel hook: accept `(data,
limit)`, use the candidate under that bound, and retry the retained bounded block
with the Python decoder on candidate refusal. Keep the container's length and
checksum checks. Whole-stream fallback for gzip and other codecs also needs a
bounded replay plan for nonseekable input; it must not add hidden full-input
spooling. No such production fallback is implemented here.

### Fit by codec

Safety “matched” means acceptance and full-byte hashes in the measured sample,
not exact exception classes or equivalence for all inputs. Speed is relative to
archivey's current unaccelerated backend, including its framing where applicable.
The bounded column includes the experimental C adapter and archivey's framing.

| Codec / variant | Current archivey backend | Candidate backend | Fit | Safety result | 1 MiB one-shot / bounded speed ratio |
| --- | --- | --- | --- | --- | --- |
| gzip | zlib + Python framing | zlib-ng 2.3.3 | b, not a default replacement | bounded sample matched; direct one-shot has 1 stricter refusal | 1.87x / 1.22x |
| zlib | zlib + Python framing | zlib-ng 2.3.3 | b | bounded matched; direct has 3 stricter refusals | 1.95x / 1.44x |
| raw DEFLATE | zlib | zlib-ng 2.3.3 | b | both sampled paths matched | 1.55x / 0.89x |
| bzip2 | bz2 + Python framing | libbzip2 1.0.8 | b, weak benefit | bounded matched; direct has 3 stricter refusals | 1.20x / 1.08x |
| XZ | lzma + Python framing | liblzma 5.8.4 | b, weak benefit | bounded matched; direct has 1 stricter refusal; fixed memory cap | 1.06x / 0.92x |
| LZMA Alone/raw LZMA1/raw LZMA2/lzip | lzma / Python framing | absent; `lzma` means XZ | d | LZMA Alone valid control refused | not applicable |
| Zstandard | stdlib/backports.zstd | libzstd 1.5.7 | b, little bounded benefit here | bounded matched; direct has 2 stricter refusals | 2.85x / 0.86x |
| modern LZ4 frame | lz4.frame/block + Python envelope | liblz4 1.11.0 | b | bounded matched; direct has 2 stricter refusals | 1.55x / 1.03x |
| raw LZ4 / mozlz4 / legacy LZ4 payload | lz4.block + Python envelopes | liblz4 1.11.0 raw block | b for block kernel | one-shot primitive sample matched; envelopes not replaced | 1.99x / 0.24x |
| Brotli | bounded brotli API | Brotli 1.2.1 | b, weak benefit | bounded matched; direct has 3 stricter refusals | 0.92x / 0.97x |
| raw LZO1X / lzop payload | Python; optional python-lzo | lzokay-derived C decoder | b with mandatory fallback | 4 valid alternate end markers refused in archivey's corpus | 35.62x / 4.22x |
| raw Snappy | absent | first-party C decoder | c behind bounded Python `.sz` framing | raw sample matched; full raw block buffered internally | 2.20x vs Google / no resumable raw allocation bound |
| framed .sz / Hadoop | absent | absent | c only with new framing code | not implemented by candidate | not applicable |
| every other archivey codec/container | implementations above | absent | d | no candidate API | not applicable |

No row recommends category a today. Retaining Python envelopes means XZ checks,
LZ4 variants, lzop header/block checksums, mozlz4 size rules and archive trailing-data
diagnostics remain archivey's. A native function result must not bypass them.

## Differential safety measurements

Every runnable raw Snappy package received the same 2 KiB payload and **451**
observations: valid input, truncation at every offset when the encoded input was
at most 512 bytes, otherwise 64 sampled offsets plus boundaries, 64 seeded bit
flips, trailing bytes, zero padding and concatenation. Framed Snappy used **469**
cases and Hadoop **134**. Common compress-utils codecs used the same method.
Each differential worker had a 1 GiB address-space ceiling, 45 CPU seconds and a
60-second parent watchdog. No worker termination occurred in that matrix.

The archivey baseline disables accelerators and uses `DecoderLimits.UNLIMITED`
to compare codec acceptance independently of resource policy. Memory probes below
exercise output caps separately. This does not establish equivalence under every
caller-selected dictionary or ratio limit.

“Same bytes” compares each mutated input against the reference, not against the
original unmutated plaintext. Formats without checksums can legitimately decode a
bit-flipped stream to changed bytes. Both refusal counts ignore differences in
exception class; recorded JSON keeps the classes and messages for later translation.

| Candidate / variant | Same bytes | Both refuse | Candidate alone accepts | Reference alone accepts |
| --- | ---: | ---: | ---: | ---: |
| aff4-snappy | not runnable | not runnable | not measured | not measured |
| py-snappy raw | 58 | 393 | 0 | 0 |
| python-snappy raw | 58 | 393 | 0 | 0 |
| python-snappy-pure raw | 58 | 389 | 4 | 0 |
| pysnappy raw | 58 | 393 | 0 | 0 |
| compress-utils raw | 58 | 393 | 0 | 0 |
| cramjam raw, context | 58 | 393 | 0 | 0 |
| python-snappy framed | 3 | 64 | 402 | 0 |
| pysnappy framed | 3 | 465 | 1 | 0 |
| cramjam framed, context | 3 | 465 | 1 | 0 |
| python-snappy Hadoop | 63 | 5 | 66 | 0 |
| pysnappy Hadoop | 62 | 71 | 0 | 1 |

The single extra framed acceptance for pysnappy/cramjam is empty input. The strict
reference requires an identifier. That is a framing/EOF policy decision for a new
plugin, not evidence of wrong output. pysnappy's single Hadoop refusal is also empty
input. These are kept separate from partial headers and incomplete payloads.
The valid two-subblock Hadoop counterexample below is an additional targeted test;
the matrix's normal encoder layout does not expose that loss.

For compress-utils' eight framed codecs, the prototype plus archivey's framing matched
acceptance and bytes on all **2,952** sampled observations. Its one-shot API was
stricter on the cases counted in the fit table. Raw DEFLATE had 59 equal acceptances and
334 joint refusals; raw LZ4 had 66/309. Each of the two independently produced upstream
LZO blocks had 64/70. These positive results are limited by the alternate-end-marker
refusals found when testing archivey's own LZO corpus. There was no candidate-only
acceptance or different-byte result against archivey in the common-codec matrix. Exact
exception-class parity is still unimplemented. The Python streaming paths matched their
corresponding one-shot accept/byte outcomes. Raw LZ4 and LZO comparisons pass the same
container output bound through `max_output` or the C stream limit; omitting that bound
would make the comparison unequal. Raw C/Python Snappy paths also matched the 451-case
sample.

### Repros and disposition of every difference

All matrix differences, including stricter refusals, are saved with their exact input,
options, reference outcome and candidate outcome in
[`results/differences.zip`](../../scripts/investigations/snappy_compress_utils/results/differences.zip).
`replay.py --all` also replays targeted Snappy and archivey LZO cases: **570 saved
observations reproduced without a changed acceptance, byte hash or error class**. Small
individual files live in
[`repros/`](../../scripts/investigations/snappy_compress_utils/repros/).

| Repro / family | Measured behavior | Disposition |
| --- | --- | --- |
| `copy-zero-invalid.bin`, hex `04 01 00` | Google rejects; py-snappy returns four zero bytes | candidate safety defect; never use as fallback |
| `copy4-valid.bin`, hex `05 00 41 0f 01 00 00 00` | Google returns `AAAAA`; py-snappy raises unsupported COPY_4 | candidate missing standard feature |
| `literal-then-junk.bin`, hex `01 00 41 00 42` | Google rejects; python-snappy-pure returns `A` | candidate input-consumption defect |
| `empty-raw-missing-length.bin`, zero bytes | Google rejects; python-snappy-pure returns empty output | candidate missing length validation |
| `zero-length-with-junk.bin` | Google rejects; python-snappy-pure returns empty output | same consumption defect |
| `missing-identifier.sz` | strict reference/pysnappy/cramjam refuse; python-snappy decodes | candidate adds a required header; new plugin must not do this |
| `partial-identifier.sz`, `partial-header.sz` | reference refuses; python-snappy flush succeeds | candidate incomplete-input defect; includes matrix truncation family |
| `oversized-uncompressed-chunk.sz` | 65,537 decoded bytes; Google-style framing reference and cramjam refuse, pysnappy accepts | candidate chunk-size defect; Python wrapper must preflight |
| `hadoop-multi.bin` | valid 4,096 bytes in two subblocks; pysnappy/reference return all, python-snappy returns 2,048 | candidate silent data loss |
| `lzo-0.bin` through `lzo-3.bin` | archivey returns `hello\n`; compress-utils refuses four alternative end markers | preserve archivey's liblzo2-compatible behavior; fallback required |
| matrix `trailing`, `padding`, `concat` and boundary cuts | direct compress-utils differs from archivey's stream policy | retain archivey's `FramedDecoder`, not candidate whole-file policy |
| zero-byte framed/Hadoop input | different empty-stream policies, as above | choose explicit new-plugin behavior; not a corruption finding |

No upstream reports were filed. These are draft findings for the maintainer, in
accordance with AGENTS.md's upstream-report rule. No existing archivey acceptance
rule should be weakened to accommodate a candidate. No archivey byte-decoding defect
was demonstrated here.

## Reading and running the candidates' own tests

**Read and measured:** exact-release tests were inspected for roundtrip-only
assumptions, reference implementation identity, error handling, buffering and
protocol variants. Test success alone did not establish damaged-input safety.

| Package | Upstream tests inspected / run | Cross-read result |
| --- | --- | --- |
| aff4-snappy | raw/framed tests and CFFI test file read; execution blocked by extension build failure | no substituted import or inferred pass |
| py-snappy | repository core, official Google fixtures, Hypothesis compatibility/error tests | 80 completed package/fixture reads agreed; four valid-file runs exceeded the 10-CPU-second worker budget |
| python-snappy | release `test_snappy.py`, `test_formats.py`: 22 passed | raw reference is cramjam; own tests miss framed flush and two-subblock loss |
| python-snappy-pure | release `tests/test_snappy.py`: 41 passed | Google corpus agrees on completed cases; trailing/missing-length probes add missing negative coverage |
| pysnappy | release `tests/test_pysnappy.py`: 18 passed | iris.csv decoded identically by all six runnable raw engines; Hadoop tests explain its useful difference |
| compress-utils | Python smoke/state/threading and canonical interop: 40 passed, 1 skipped, 685 subtests across combined suite | 214 distinct successful encodings cross-read with archivey or Google; all bytes agree |

The combined installed-wheel Python run was **121 passed, 1 skipped, 685 subtests
passed**. The skip requires a free-threaded interpreter. Zstandard's optional
canonical reference was installed before the final run, so its 60 interop subtests
were not silently skipped. py-snappy's separate unmodified repository suite did
not complete within its 160-CPU-second limit. A focused error-parity test fails
because its exception tuple contains `None` when modern python-snappy lacks
`snappy._snappy.CompressedLengthError`; that is a stale test assumption, not a
codec mismatch. The independent corpus script avoids this test-import problem.

The py-snappy clone is pinned at `f91082fa1498ed919ef26bd853a4552675c9665a`. Its eleven
positive Google fixture files and three negative `.snappy` files were tried with all six
runnable engines: **84** attempts. Four py-snappy positive cases (`html_x_4`,
`lcet10.txt`, `plrabn12.txt`, `urls.10K`) hit the worker CPU ceiling. A timeout is not
counted as refusal or byte parity. The other 80 matched the independent reference.
Fixture bytes are not vendored; hashes and results are saved, and the pinned clone
reproduces them.

The compress-utils test capture records one-shot encodings actually produced by its
own tests, including XZ fitted-dictionary cases, empty/single-byte data, random and
repetitive 1 MiB data and raw LZ4. It does not assert coverage of every streaming
encoder output. Raw Snappy uses Google as oracle; existing archivey codecs use
archivey itself. Six additional cross-reads use pysnappy's iris.csv fixture.
The two 32 KiB LZO fixtures were generated by liblzo2 2.10's 1/999 encoders and
verified by upstream's safe decoder; their damaged variants are in the matrix.

**Measured archivey corpus:** spying on the Python LZO decoder while retaining its
original behavior during `tests/test_lzo.py` compared **617** decoder calls with
compress-utils. Four accepted alternate end markers were refused; all other
accept/byte outcomes matched. The baseline tests passed (14 passed, 1 skipped).
The instrumentation deselects the allocation-only tracemalloc assertion because
collecting observations itself allocates. The unchanged test is covered by the
normal repository gate. The skipped liblzo2 comparison needs python-lzo.

**Read, with limited replay:** compress-utils' C tests cover exact output buffers,
stream draining, terminal errors, dictionaries, raw LZO/LZ4 and independent Snappy
interop. Seven saved fuzz payloads concern prior XZ no-progress and bzip2 error-state
memory bugs or empty-input undefined behavior. All seven payloads were refused by
archivey and the bounded adapter without hanging. This replay strips the fuzzer's
two selector bytes and tests the payload; it does not reproduce all mode-selected
C API state sequences. The C test binaries and ASan/UBSan suites were **not run**.
Their past bugs are fixed-regression evidence, not claims of a current vulnerability.

### What archivey should support or fix

Add `.sz` only through a bounded codec plugin and explicit CRC/EOF tests. Include
COPY_4, zero-offset copies, partial identifiers, partial final chunks, skippable and
unknown mandatory chunks, oversized decoded chunks and repeated stream identifiers.
The new feature must work identically with every permitted raw kernel. Hadoop can
be a later explicit codec; pysnappy is a useful producer/oracle for its subblocks.

Keep archivey's existing LZO end-marker semantics. `test_lzo.py` already defends
this behavior; the investigation found a candidate incompatibility, not a missing
archivey fix. Any compress-utils accelerator needs canonical fallback on refusal
and tests for output limits, leftover input, exception types and partial delivery.
No production fix is bundled into this investigation.

## Performance and memory measurements

Payloads are deterministic: repeated archive-like text interspersed with seeded
random bytes. Each codec's candidates decode the exact same encoded bytes.
Sizes are **4 KiB and 1 MiB**. The benchmark validates complete output and takes
the median of five timing batches, three for the slow py-snappy decoder. Batches
aim for 30 ms with at most 2,000 calls; slow decoders use one call. Full samples,
compressed lengths and absolute MB/s are in `results/throughput.json`.

The one-shot common-codec baseline opens archivey's unaccelerated stream and reads
it completely. Its Python API overhead is included. Candidate one-shot calls skip
that envelope. Consequently large small-buffer speedups are not kernel-only gains.
The bounded comparison retains archivey's framing on both sides and is the more
relevant integration estimate. The prototype includes ctypes setup per decoder;
a maintained native bridge might reduce it. Child-process IPC is **not included**.
The two-CPU quota and cache effects produce noise; small differences need another
host and more workloads before selecting a backend.

| compress-utils codec | 4 KiB one-shot / Python stream / bounded ratio | 1 MiB one-shot / Python stream / bounded ratio |
| --- | --- | --- |
| gzip | 35.32 / 24.87 / 0.78 | 1.87 / 1.84 / 1.22 |
| zlib | 26.82 / 16.47 / 0.70 | 1.95 / 1.77 / 1.44 |
| raw DEFLATE | 24.77 / 19.15 / 0.63 | 1.55 / 1.48 / 0.89 |
| bzip2 | 4.28 / 4.67 / 1.04 | 1.20 / 0.95 / 1.08 |
| XZ | 12.90 / 11.75 / 1.07 | 1.06 / 1.05 / 0.92 |
| Zstandard | 5.41 / 4.98 / 0.72 | 2.85 / 1.88 / 0.86 |
| LZ4 frame | 18.94 / 19.06 / 0.70 | 1.55 / 1.20 / 1.03 |
| Brotli | 8.38 / 7.47 / 0.92 | 0.92 / 1.02 / 0.97 |
| raw LZ4 | 0.96 / 0.41 / 0.03 | 1.99 / 0.18 / 0.24 |
| raw LZO1X | 4.15 / 2.73 / 0.13 | 35.62 / 3.32 / 4.22 |

Raw-block baselines are archivey's current LZ4 block primitive and Python LZO
function with a supplied output bound, not a synthetic archive. LZO producers use
external liblzo2 **2.10** solely to generate identical inputs; it is not the
candidate or reference decoder and is not bundled in archivey. Two extra upstream
LZO 32 KiB fixtures also have timings saved, but their mostly literal structure
makes them poor predictors of normal compressed blocks. No existing python-lzo
accelerator was available to time; the LZO ratios compare with core Python.

| Raw Snappy package | 4 KiB MB/s | 1 MiB MB/s | 1 MiB ratio vs Google/pysnappy |
| --- | ---: | ---: | ---: |
| aff4-snappy | unmeasured | unmeasured | unavailable |
| py-snappy | 22.3 | 0.21 | 0.000036x |
| python-snappy | 4,612.6 | 13,912.0 | 1.31x |
| python-snappy-pure | 24.7 | 26.6 | 0.0028x |
| pysnappy | 2,177.2 | 9,782.6 | 1.04x, self-comparison noise |
| compress-utils | 4,548.8 | 22,930.4 | 2.20x |
| cramjam, context | 4,470.5 | 14,466.9 | 1.29x |

The raw-only packages have no incremental decoder to benchmark.
compress-utils offers buffered raw Snappy stream calls: Python stream/C bounded
ratios were 0.79/0.02 at 4 KiB and 0.60/0.50 at 1 MiB. Both retain the raw
block until finish and do not bound its internal decoded allocation.
Framed and Hadoop timings, both all-input and 64 KiB-input calls, are saved for
python-snappy/pysnappy and framed cramjam. They validate full bytes. They are
absolute throughput results, with no archivey ratio because archivey lacks Snappy.
Valid-input speed does not repair EOF or chunk-limit bugs.

### Output caps and peak RSS

**Measured:** fresh children decode 16 MiB of zeros. RSS is Linux `VmHWM` after
imports, including native allocations. Deltas below are peak minus the post-import
high-water mark, rounded, not exact live heap sizes. Python-only tracemalloc would
miss native working buffers. Each package's raw Snappy input is identical.

| Snappy path | Output behavior | Additional peak RSS |
| --- | --- | ---: |
| aff4-snappy | unavailable | not measured |
| py-snappy raw | returns all 16 MiB | 451.8 MiB |
| python-snappy raw | returns all 16 MiB | 32.1 MiB |
| python-snappy-pure raw | returns all 16 MiB | 31.9 MiB |
| pysnappy raw | returns all 16 MiB | 15.8 MiB |
| compress-utils Python stream, total max_output=128 | returns zero on write, fails at finish | 17.3 MiB |
| compress-utils fixed C buffer=128 | returns zero on write, 128 on finish | 17.1 MiB |

The last row demonstrates why a fixed return buffer alone is not proof of bounded
internal production. Its raw Snappy backend still decodes the full block. A `.sz`
wrapper can bound that block to 64 KiB before calling it. Unframed raw input needs
a checked external size/working-memory limit.

For gzip/XZ/Zstd/LZ4/Brotli, archivey and the C adapter returned 128 bytes while
preserving decoder state. Additional RSS for archivey was 0.14/0.16/0.36/0.52/4.30
MiB; for the C adapter it was 0.29/0.48/0.75/0.79/4.19 MiB. The Python binding's
`max_output=128` raised terminal `CompressError`; it cannot resume to return the
next 128 bytes. That error used roughly 0.57/0.75/1.05/0.73/4.57 MiB.
The results file also records zlib, raw DEFLATE, bzip2, raw LZ4 and LZO probes.
These are output-expansion probes, not a comprehensive dictionary-memory audit.

### Import time and wheels

Fresh-interpreter import latency is a seven-run median, excluding interpreter
startup. It includes a module's normal imports: compress-utils **1.82 ms**,
py-snappy **7.65 ms**, python-snappy-pure **0.51 ms**, python-snappy **1.73 ms**,
pysnappy **1.65 ms**. aff4-snappy was unavailable. These are warm-filesystem,
single-host measurements, not cold-start deployment guarantees.

## Packaging, maintenance and security evidence

**Read from exact release artifacts unless marked measured.** Universal wheel
sizes do not include transitive native dependencies.

| Package | CPython / ABI / wheel size | OS and architecture coverage | PyPy / free-threaded | Source build / runtime dependencies |
| --- | --- | --- | --- | --- |
| aff4-snappy 0.5.1 | no wheels; old Python 2/3 classifiers | sdist only | old CFFI path references a missing module; unverified | setuptools, C/C++; bundled Snappy; failed CPython 3.11 build |
| py-snappy 0.1.0a1 | Python >=3.6,<4; py3-none-any; 8,193 bytes | portable Python | plausible PyPy, not measured; 3.14t smoke kept GIL off | setuptools; no runtime dependency |
| python-snappy 0.7.3 | py3-none-any; 9,155 bytes; effective native dependency Python >=3.11 here | wrapper portable; effective matrix is cramjam's | cramjam has PyPy 3.11 wheels; 3.14t smoke kept GIL off | setuptools for wrapper; runtime cramjam; native source build needs Rust/C toolchain |
| python-snappy-pure 0.2.0 | Python >=3.10; py3-none-any; 6,096 bytes | portable Python | PyPy not measured; 3.14t smoke kept GIL off | Python build tooling; no runtime dependency |
| pysnappy 0.8.2 | Python >=3.11; per-version cp311/312/313, no abi3; Linux x86-64 cp311 wheel 136,865 bytes | 12 wheels: glibc/musl x86-64/aarch64; no Windows/macOS | no PyPy/free-threaded wheels; not measured | C/C++, Cython, scikit-build-core/CMake; system Snappy development package, version unpinned |
| compress-utils 0.12.1 | Python >=3.11; per-version cp311–315, no abi3; Linux x86-64 cp311 wheel 1,267,421 bytes | 28 wheels: glibc x86-64/aarch64, macOS ARM64, Windows AMD64; no musl/32-bit/macOS Intel | no PyPy wheels; cp314t/cp315t wheels | C/C++, CMake, scikit-build-core, pinned pybind11/stubgen; bundled codec sources; no Python runtime dependency |

compress-utils' glibc floors are 2.27 for x86-64 and 2.26 for aarch64, with 2.28
compatibility tags. macOS requires 11+ ARM64. Its 3.11–3.13 releases have four
wheels each; 3.14/3.15 have eight each with free-threaded variants. pysnappy's glibc
wheels use 2.24/2.28 tags; musl wheels require 1.2. Do not generalize a platform row
to unsupported interpreter/architecture pairings. Exact filenames are authoritative.

**Measured free-threaded smoke:** CPython 3.14.10t imported compress-utils,
python-snappy, py-snappy and python-snappy-pure without enabling the GIL, and each
roundtripped bytes. The result is saved. It does not establish concurrent-decoder
safety or PyPy speed. pysnappy and aff4-snappy were not tested on that interpreter.
Cramjam's transitive wheels and native maintenance cost remain part of adopting
python-snappy even though the wrapper wheel is only 9 KiB.

pysnappy's source uses `find_package(Snappy REQUIRED)` without a version pin. Its
measured Linux wheel links no external libsnappy and contains a compiled Google
Snappy implementation, but neither source metadata nor wheel exposes its exact
version. **Unknown is the version result**, not an assumed 1.2.2. Its wheel's only
license file is the wrapper's MIT license; a Google BSD-3-Clause notice was not
found. Clarify provenance/notices upstream before redistribution. The wrapper and
CRC implementation are MIT; aff4/python-snappy use BSD-3-Clause; both pure Python
alternatives use MIT. No native library is bundled by the pure implementations.

| Project / named maintainer evidence | Release cadence from PyPI | Public security/maintenance observation |
| --- | --- | --- |
| aff4-snappy / Andres Moreira metadata, AFF4-specific distribution | two releases: 2016, last 2017-11-06 | stale repository pointer; modern build failure; no distinct current security tracker established |
| py-snappy / ethereum repository, Jason Carver metadata | one alpha, 2019-03-13 | open [#3](https://github.com/ethereum/py-snappy/issues/3) exception-path coverage, [#18](https://github.com/ethereum/py-snappy/issues/18) incorrect compressor comparison, [#20](https://github.com/ethereum/py-snappy/issues/20) benchmarks; ancient error-parity test assumption fails today |
| python-snappy / intake repository, Andres Moreira metadata | 19 releases since 2011; last 2024-08-29 | public build failures include [#58](https://github.com/intake/python-snappy/issues/58), [#64](https://github.com/intake/python-snappy/issues/64), [#120](https://github.com/intake/python-snappy/issues/120); no matching open security issue found by this search |
| python-snappy-pure / Valmarelox repository | one release, 2026-01-15 | no matching open security issue found in the public search; single-release maintenance evidence |
| pysnappy / aeroevan repository, Evan McClain metadata | eight releases since 2016; 2026-05-15 release after long gap | open security/crash/corrupt/vulnerability search returned none; sparse platform matrix |
| compress-utils / Nicolas Dupont, CODEOWNERS dupontcyborg | 16 releases since 2025; active late-2026 sequence, last 2026-11-13 | same open-issue search returned none; shipped fuzz regressions document prior native defects |

These are release/metadata observations, not contributor-count or bus-factor audits.
An empty public issue search is not a security audit or proof that no private
advisory exists. Vendored codec updates become the umbrella maintainer's release
responsibility. compress-utils pins codec versions and records provenance, which
helps auditing but does not remove that responsibility. A GPL-free LZO wheel is a
real packaging benefit; replacing stdlib gzip/bzip2/lzma adds a native update path
where none was previously required from PyPI.

## Ranked follow-ups

1. **A bounded `.sz` plugin with Python framing.** Compare cramjam, compress-utils
   and direct Google kernels under the same producer corpus, chunk-limit/CRC/EOF
   tests, caller limits and process isolation. Include a correct fallback only if
   its full raw Snappy validity rules and bounded allocations are tested. Neither
   current pure Python release qualifies. This adds a missing format.
2. **A compress-utils LZO-only accelerator experiment.** Preserve the Python
   decoder and canonical exception behavior. Fall back on valid alternate end
   markers, verify size ceilings/unused input, and run archivey's full LZO/SquashFS/
   lzop corpus plus a stateful differential fuzzer. Measure with process IPC and
   realistic block sizes before choosing it over the existing kernel path.
3. **An upstream C API / binding request.** Draft the four LZO marker repros,
   resumable Python output buffers, per-decoder working-memory limits, typed status
   exposure and Windows/macOS exported-symbol guarantees. Resolve binding/Google
   notice questions. The maintainer files upstream reports.
4. **Optional gzip/zlib acceleration only after that foundation.** Preserve
   `FramedDecoder`, diagnostics, error types and fallback. The bounded gains here
   are modest; do not replace stdlib or add a default dependency based on one-shot
   microbenchmarks. Zstd/LZ4/Brotli/bzip2/XZ are lower priority here.
5. **Explicit Hadoop Snappy if real users need it.** pysnappy is useful as a test
   oracle for subblock handling. Avoid automatic detection without unique magic.
   Do not adopt python-snappy's current Hadoop wrapper.
6. **Keep the other packages as evidence, not runtime dependencies.** Draft the
   pure-codec zero-offset/COPY_4/consumption findings and framed EOF/size findings.
   Repairing those upstream can change a future evaluation; it does not justify
   integrating them today. Future archive writing could use compress-utils'
   compression APIs, but archive writing and compression performance were not
   evaluated here.

## Repository validation

The setup script was rerun. It found the built 7zz 26.05 binary but reported
missing unrar, a `7z` command, unar, xorriso, bgzip and python-lzo in this managed
workspace. The focused codec gate does not require RAR or ISO tools; native
python-lzo tests skip rather than imply coverage.

- `./scripts/test.sh tests/test_codecs.py tests/test_codec_frame_checks.py
  tests/test_codec_api.py tests/test_lzo.py tests/test_lzop.py -n 4 --no-cov`:
  **584 passed, 29 skipped**, with two temporary-directory cleanup warnings.
- `./scripts/check.sh --fix`: Ruff, both type checkers, API surface, documentation
  links/build/roles, line width, tracker check and script tests passed. Script tests:
  **524 passed, 1 skipped**. OpenSpec CLI 1.4.1 alone failed on **21 existing specs**
  that lack SHALL/MUST keywords. The same failures were confirmed on clean `main`
  at the exact base commit; no specs are changed by this PR.
- `review_prep.py` runs the required symbol/width checks before review. No public
  API, runtime dependency, source decoder or changelog changes are included.
- The full suite and `--all-configs` were not repeated for this follow-up. These
  are manually invoked investigation programs and documentation, with no change
  reachable from archivey's runtime imports. The earlier investigation ran the
  full suite on this exact base: 23,307 passed, 2,650 skipped and 11 failed. Ten
  failures reproduced on clean base (filesystem permissions and inaccessible
  `/proc` peak-reset behavior); one PPMd worker death did not reproduce in the
  focused retry. Those observations are context, not a claim of a fresh full run.
