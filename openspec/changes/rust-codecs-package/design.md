# Design: rust-codecs-package

Sources: draft PR #1416 (branch `claude/project-thread-dle5be`, package
`packages/archivey-native`), its report `reports/rust-native-kernels-2026-11-09.md` in
the project files, the 2026-11-17 compress-utils investigation, and the plan
`plans/rust-codecs-package-2026-11-21.md`. The maintainer ruled every open question on
2026-11-21 (§Open questions).

## Context

The prototype has seven line-by-line ports (LZX, the `.Z` LZW state, LZO1X, ZipCrypto
keys, BCJ2, ARM64 and RISC-V filters), a dispatch module `internal/native.py`, a
differential test file and a three-OS workflow. It exports one `ABI_VERSION`, uses
archivey-shaped call signatures, and has no release workflow. It is 11 days behind
main; the twinned decoders changed since (LZO most, with PR 1612).

## Goals and non-goals

Goals: a small native package with its own release cadence; an API that people who know
the standard library can use without archivey; no change to archivey's results; no
install failure anywhere.

Non-goals: parsers (the prototype measured a free parser at 1.2x for ZIP listing and
1.5x for TAR); wrappers of C libraries the standard library already wraps (zlib, bz2,
LZMA); making any format depend on the package; a crates.io release.

## D1. Name and scope

Distribution `archivey-codecs`, import `archivey_codecs` (question 2). The name says
what is inside and keeps the link to archivey's tests and fuzzing, which are why anyone
would trust it. `archivey-native` says how it is built, not what it does. All three
candidate names were free on PyPI on 2026-11-21.

A kernel goes in when all four hold:

1. archivey has a pure-Python version, which stays the reference.
2. It is a codec, filter or checksum: bytes in, bytes or a digest out, with state.
3. It is measurably slow in Python.
4. No maintained package does it at the same speed.

First release: the seven prototype kernels and CRC-16/ARC (LHA, ARJ; question 5). On
2026-11-21 the Python CRC-16 ran at about 16 MB/s, 85x slower than `zlib.crc32`.
BLAKE2sp (RAR5) stays in Python: after PR 1709 it runs on the standard library's C
`blake2s` in linear time, so a port would add a Rust dependency for little gain.

**LZFSE and LZVN, for the DMG reader** (maintainer, 2026-11-21, "Build the DMG reader"
thread: own fast kernel here rather than the `lzfse` PyPI package, which has no output
cap and accepts blocks whose matches use more literals than the block decoded). They
go in the first codecs release after the DMG reader's pure-Python twin
(`streams/codecs/lzfse_decoder.py`) lands, as one-shot functions
(`lzfse.decompress(chunk, out_size=)`, DMG chunks record their sizes). The kernel keeps
every check of the Python decoder: the v2/v1 `n_raw` exact, the literal count a
multiple of 4, no literal overrun, the distance check on every triple, nothing after
`bvx$` or the LZVN end-of-stream, and output never past `out_size`. It must agree with
the Python decoder on every DMG fixture and the DMG fuzz corpus. ADC (DMG's other
codec) follows the same shape if measurement shows it is slow.

Built 2026-11-22 as `lzfse.decompress` and `lzvn.decompress` (raw LZVN, which HFS+
compressed files store), one kernel each in `KERNELS`; the `lzfse` revision also covers
the LZVN decoder inside `bvxn` blocks, so a change to LZVN raises both. Like LZO, each
takes `out_size=` (exact) or `max_size=` (a bound): archivey's callers pass the most a
run may decode to and check the length themselves, with their own message.

Later, by value: LHA/ARJ static-Huffman and LHarc `-lh1-`; PPMd and Deflate64 as
in-process decoders (new decoders, each needs the DR-20 damaged-input evaluation); the
DOS-era ZIP methods and ARJ method 4.

## D2. Hash API

```python
archivey_codecs.crc16_arc(data, value=0) -> int     # function, like zlib.crc32
c = archivey_codecs.Crc16Arc(b"optional initial data")  # type, like hashlib.sha256
c.update(chunk); c.digest(); c.hexdigest(); c.copy()
c.name, c.digest_size, c.block_size                 # "crc16_arc", 2, 1
```

- Every hash is a type, named in CamelCase (`Crc16Arc`), with `update`, `digest`,
  `hexdigest`, `copy`, `name`, `digest_size`, `block_size`, and a constructor taking
  optional initial data. That type is the name to use in annotations.
- A CRC also has a function in snake case (`crc16_arc`), the `zlib.crc32` form. A PyO3
  function cannot carry attributes, so the two are separate names.
- CRC names follow the CRC catalogue (`crc16_arc`), since "CRC-16" names over twenty
  algorithms.
- A CRC's `digest()` is big-endian (question 6), matching the `crc32c` package and
  archivey's `MemberDigest`.
- `update()` releases the GIL above a threshold (64 KiB), as `hashlib` does, but only
  for immutable `bytes` input. A `bytearray` or writable `memoryview` is copied first,
  or hashed with the GIL held, so no other thread can write the buffer while Rust
  reads it. The same rule applies to every `decompress()` and `decrypt()`.

## D3. Decoder API

```python
d = archivey_codecs.lzx.Decompressor(window_bits=21)
out = d.decompress(data, max_length=-1)
d.eof, d.needs_input, d.unused_data

archivey_codecs.lzo1x.decompress(block, out_size=n)
```

The 0.1 names, one per kernel (stubs ship from 0.1, so these are settled here):

| Kernel | `KERNELS` key | Python name | Constructor or call |
| --- | --- | --- | --- |
| LZX | `"lzx"` | `lzx.Decompressor` | `(window_bits, *, output_size=None)`; `set_output_size(n)`; `reset(output_size=None)` at a CAB folder start |
| Unix `compress` | `"lzw"` | `lzw.Decompressor` | `(*, max_width=None, block_mode=None, nine_bit_widens=None)`; `flush(max_length=-1)`, `truncation`; `header_params`, `clear_offsets` |
| LZO1X | `"lzo1x"` | `lzo1x.decompress` | `(block, *, out_size)` or `(block, *, max_size)` |
| ZipCrypto | `"zipcrypto"` | `zipcrypto.Decryptor` | `(password: bytes)`; `decrypt(data) -> bytes` |
| BCJ2 | `"bcj2"` | `bcj2.Decompressor` | `(main, call, jump, rc, *, out_size)`, four readable binary streams |
| ARM64 filter | `"arm64"` | `filters.Arm64Decoder` | `(start_offset=0)`; `decode(data) -> bytes`, `flush()` |
| RISC-V filter | `"riscv"` | `filters.RiscvDecoder` | `(start_offset=0)`; `decode(data) -> bytes`, `flush()` |
| CRC-16/ARC | `"crc16_arc"` | `crc16_arc`, `Crc16Arc` | `(data, value=0) -> int`; `Crc16Arc(data=b"")` |
| LZFSE | `"lzfse"` | `lzfse.decompress` | `(data, *, out_size)` or `(data, *, max_size)` |
| LZVN (raw, decmpfs) | `"lzvn"` | `lzvn.decompress` | `(data, *, out_size)` or `(data, *, max_size)` |

- ZipCrypto is a cipher, so its object is a `Decryptor` with `decrypt()`, not a
  decompressor. It has `copy()`, `getstate()` and `from_state()` (the header and 12
  bytes of keys) like the streaming decoders, and `total_in` (bytes decrypted).
- LZX output comes in frames of 32 KiB, and only the last frame is shorter. The frame
  length sets where the input realigns and where the Intel E8 scan stops, so the kernel
  must know it whatever `max_length` the caller asks for. The caller gives the folder's
  declared output size with `output_size=` or, when the CAB reader learns it later,
  with `set_output_size(n)` before the last frame starts. The kernel decodes one whole
  frame into an internal buffer of at most 32 KiB and returns it in `max_length`
  slices. `eof` turns true when `total_out`, the bytes returned so far, reaches the
  output size. Without an output size, every frame is 32 KiB, and `eof` turns true at
  `flush()` once the last frame has used all the input.
  This is how `cab_reader.py` calls `decode_frame(frame)` today.
- LZX also needs to know when the compressed input has ended, which an output size
  does not say: the CAB reader's `_lzx_more()` returns `None` after the last data
  block, and only then does the Python twin read zero padding past the end (at most
  `_MAX_PADDING` bytes) for its last lookahead. Before that, a frame is tried only
  once the queued input is about twice what the last frame used, so that a frame fed
  block by block is decoded once, not retried at every block; output lags the input
  by up to two frames, and `needs_input` is true while it waits. LZX therefore has
  `flush(max_length=-1)`, like LZW: it marks the end of input, finishes the frame with
  the twin's zero padding, and returns the rest. A frame that still cannot finish then
  raises `TruncatedDataError`, as the twin's `TruncatedError`. This also covers a
  folder whose output size is unknown (an incomplete block table).
- Unix `compress` has no end marker: the stream ends where its source ends. An empty
  `decompress(b"")` only drains buffered output, as for `LZMADecompressor`, so LZW has
  `flush(max_length=-1)` to say that the input has ended. `flush()` returns the
  remaining output (called again while it returns bytes, if capped), then sets `eof`
  and `truncation`: `None`, or the message of the Python twin's `truncation` (padding
  owed, nonzero leftover bits). Truncation is reported, not raised, so the bytes before
  it are kept; archivey decides what to raise, as it does with the twin today.
  `max_length` bounds what every call decodes, `flush()` included: the final pass runs
  only once less than one code of input is left. `nine_bit_widens` is the switch the
  Python twin already has for the old `compress` variant whose 9-bit codes widen at a
  different point (`None` guesses from the data). `clear_offsets` lists the CLEAR codes
  the last `decompress()` or `flush()` call passed, as `(input, output)` offsets counted
  like `total_in` and `total_out`, where a decoder made with the stream's
  `header_params` can start afresh; each call reports only its own, so a caller that
  wants them all collects them.
- BCJ2 reads four input streams, so it cannot take one `data` argument. It pulls from
  four objects with `read(n)` and gives output through `read(max_length)` with `eof`.
  `out_size` is the declared output size (`unpack_size` in the 7z pipeline) and is
  required: `eof` turns true after exactly `out_size` bytes. An input that ends before
  that raises `TruncatedDataError` naming the stream, and bytes left in `main`, `call`
  or `jump` after the last output byte raise `CorruptDataError`, as
  `Bcj2DecoderStream` does. Nothing is allocated from `out_size`. Its state holds
  `total_in` for each of the four streams and none of their buffered bytes. BCJ2 has no
  `copy()`, because two copies would share the four read cursors. It is restored with
  `bcj2.Decompressor.from_state(state, main, call, jump, rc)`, each new stream placed
  at its saved `total_in`.
- The branch filters are streaming objects, not functions: an instruction can span two
  calls, so each keeps the cut-off bytes until the next `decode()` or `flush()`.

Two kinds of decoder (question 4):

- **Streaming objects** for codecs whose state carries over: LZX, LZW, BCJ2, the ARM64
  and RISC-V filters, and (as a cipher) ZipCrypto.
- **One-shot functions** for codecs whose blocks stand alone: LZO, later DMG's ADC and
  LZFSE chunks. `out_size` is exact; output that ends short or would run past it is
  `CorruptDataError`. There is no state, and a seek point is the block's offset.
  lzop records each block's decoded size, but SquashFS records only the most a block
  may decode to, and most fragment blocks decode to less. So LZO also takes
  `max_size=` instead: output up to that many bytes, and `CorruptDataError` past it.
  Without it every short SquashFS block was decoded twice, about twice as slow as
  compress-utils on an image of small files (review of the LZO hook, round 1).

Seeking (question 4b). Every streaming object has (BCJ2 without `copy()`, as above):

```python
snap = d.copy()                         # in-memory copy, like zlib's
point = (d.getstate(), d.total_in, d.total_out)
d2 = lzx.Decompressor.from_state(point[0])
f.seek(stream_start + point[1])         # feed input from total_in; output resumes
                                        # at total_out
```

- `total_in` counts input bytes consumed, `total_out` output bytes returned to the caller.
- `getstate()` returns bytes holding what the decoder consumed, including the bits of a
  partly read byte and any decoded output not yet returned (at most one LZX frame, 32
  KiB), and never the input it holds but has not used. `total_out` counts the bytes
  returned to the caller, not the bytes decoded into a buffer, as BCJ2's Python twin
  counts its position today (`_produced - len(_pending)`).
- The state starts with the kernel's name and revision; `from_state` refuses any other
  with `UnsupportedDataError`, so a stale seek index cannot decode wrong bytes.
- `from_state` checks a state's contents as it checks input: a window size over the
  kernel's maximum, a table entry out of range or a cut-off state is
  `CorruptDataError`, and it allocates no more than the kernel's largest window.
- A decoder made by `from_state` starts with `total_in` and `total_out` at the saved
  values, so its counters keep counting from the stream's start.
- Sizes: LZX up to its 2 MiB window (cheap to copy, too big to keep at every point;
  archivey's `MAX_SNAPSHOT_BYTES` cap applies), LZW a few hundred KB at most,
  ZipCrypto the header and 12 bytes of keys, filters tens of bytes.

- Streaming decoders follow `bz2.BZ2Decompressor` and `lzma.LZMADecompressor`
  (question 4): the `max_length` and `needs_input` contract is the one that bounds
  output. `zlib.decompressobj`'s `unconsumed_tail` is the older shape.
- Block codecs with a known output size get a one-shot `decompress(data, *, out_size)`
  that never allocates more than `out_size`.
- Format details stay as attributes or keyword arguments (LZX frame reset, LZW
  `header_params` and seek points), not extra classes.
- Errors: `CodecError(ValueError)`, with `CorruptDataError`, `TruncatedDataError` and
  `UnsupportedDataError`. Messages are not public API for outside users; archivey's
  parity tests compare them, and its wrappers re-raise archivey's own exceptions with
  the same message.
- Panics: a missed check in a kernel panics, and PyO3 raises
  `pyo3_runtime.PanicException`, a `BaseException` that gets past `except Exception`.
  `internal/native.py` catches it around every kernel call and raises archivey's
  `CorruptionError` with the panic as `__cause__`, so the caller sees a typed error as
  with the Python twin. The decoder object is then unusable (its state may be half
  updated): every later call raises the same error. Fuzzing and parity treat any panic
  as a bug to fix.
- Memory: every allocation is bounded by a constructor argument or by `max_length` /
  `out_size`; input data alone cannot make a kernel allocate much.
- Threads: one thread at a time per object. A concurrent call into the same object
  raises `RuntimeError` (PyO3's borrow check), never corrupts state. Different objects
  run in parallel with the GIL released, and on free-threaded builds.
- Kernel modules have `#![forbid(unsafe_code)]`; bindings are only in `lib.rs`, so the
  kernels could become a Rust crate later.
- Ships `__init__.pyi` and `py.typed`. Semantic versioning, 0.x until the API settles.

## D4. Compatibility: per-kernel revisions

`archivey_codecs.KERNELS` maps each kernel name to a revision, raised whenever the
kernel's observable behaviour changes (output, error kind or message, seek points).
archivey's `internal/native.py` holds the minimum revision it needs per kernel and uses
a kernel only at that revision or newer; otherwise it uses the Python decoder and logs
once at DEBUG. The dependency range is `archivey-codecs>=0.1,<1` (question 7).

So adding a kernel never breaks an older archivey, an old package with a new archivey
loses only the kernels that changed, and neither package's release waits for the
other. The prototype's single `ABI_VERSION` would turn every kernel off when any one
changed.

What "same results" means across versions. archivey's parity guarantee holds at the
revisions it was released with. A newer revision is a fixed kernel, so an older
archivey that meets it can see different bytes or messages from its own Python twin:
the fixed ones, as the newer archivey's Python twin gives. That is the point of "or
newer"; the alternative, exact pinning, would keep old bugs in the native path.

What a raised revision may not change: the call signature, the attribute names and the
error classes. A change to any of those is not a new revision of the same kernel. It
gets a new `KERNELS` key (for example `"lzx2"`) next to the old one, or waits for 1.0.
Before 1.0, and within a major version after it, a release removes no kernel and lowers
no revision.

The "change it twice" rule stays: a fix to a twinned Python decoder is made in Rust in
the same PR, and the kernel's revision goes up. Users get the fixed Python version
until the next codecs release turns the kernel back on.

## D5. How archivey installs and turns it off

- Extra `archivey[codecs]` with platform markers, so pip never falls back to the sdist:

  ```toml
  codecs = [
    "archivey-codecs>=0.1,<1; platform_python_implementation == 'CPython' and (sys_platform == 'linux' or sys_platform == 'darwin' or sys_platform == 'win32') and (platform_machine == 'x86_64' or platform_machine == 'AMD64' or platform_machine == 'aarch64' or platform_machine == 'arm64' or platform_machine == 'ARM64')",
  ]
  ```

  Every term is `==`: PEP 508 `in` on strings tests for a substring, so
  `platform_machine in '...x86_64...'` would also match 32-bit Windows (`x86`). The
  allowlist is exactly D7's platforms, so armv7l, i686, ppc64le, s390x and 32-bit
  Windows never ask for the package. No marker tells a free-threaded build apart, so
  D7 builds free-threaded wheels for every free-threaded CPython from 3.13t on. The
  implementation PR checks the marker with pip and uv on each excluded platform.
- `archivey-cli` depends on `archivey[codecs]` from the first archivey release that
  knows the package; `[recommended]` gains it one archivey release later (question 9).
- `OptionalLibrary.ARCHIVEY_CODECS` (question 8), passed through every call site (the
  prototype reached only LZO). It is the only switch: tests that need the Python path
  pass `exclude_libraries`, or use a fixture that patches `internal/native.py`. No
  environment variable turns the kernels off.
- `[free-threaded]` includes the package (the module declares `gil_used = false`, and
  CI's GIL assertion over that extra covers it). `[all]` gets it through
  `[recommended]`.
- Isolation: under `ProcessIsolation.KNOWN_CRASHES` (the default) and `NONE` the kernels
  run in the caller's process. Under `NATIVE_DECODERS`, which promises that no native
  decoder runs in the caller's process, the decoding kernels (LZX, LZW, LZO, BCJ2,
  ARM64, RISC-V, later LZFSE) run in archivey's decoder child, like zlib, lzma and
  compress-utils today (question 13). CRC-16/ARC and ZipCrypto run in the caller's
  process under every setting, as checksums and AES decryption do now. Each decoder in
  the child costs about 0.6 to 1 ms (the `NATIVE_DECODERS` docstring in
  `src/archivey/config.py`, measured with
  `scripts/investigations/bench_process_isolation.py`), plus copying the bytes across
  the pipe twice; at 8x to 38x the Python speed the kernels still win on anything but
  tiny members. A panic in the child reaches the caller as `CorruptionError`, as
  in-process. The streaming kernels push input as the child protocol already expects;
  BCJ2's four input streams need the protocol to carry four inputs (task 2.7). If no
  child can start, archivey uses the Python twin in the caller's process, as if
  `ARCHIVEY_CODECS` were excluded: a Python decoder is not native, so the promise holds,
  and the read gives the same bytes as without the package. LZO then goes to
  compress-utils, which raises `ResourceUnavailableError` as today, and to Python only
  when compress-utils is absent.
- LZO order: archivey-codecs, then compress-utils, then Python (question 11), because
  ours is tested against our Python twin message for message.

## D6. Repository layout

`packages/archivey-codecs/` in this repo (question 3), next to `archivey-cli`:

```
Cargo.toml          single source of the version (pyproject: dynamic version)
pyproject.toml      maturin backend, abi3-py311
CHANGELOG.md, README.md
src/lib.rs          bindings only
src/kernels/*.rs    one module per kernel
python/archivey_codecs/__init__.pyi, py.typed
tests/test_api.py      the API alone, no archivey import
tests/test_parity.py   each kernel against archivey's Python twin
```

The parity tests need both sides at one commit, and the "change it twice" rule is
enforced by one PR's CI and one review loop. A separate repo pays off only with outside
contributors; it can be split out later with its history.

## D7. Wheels

One workflow on `PyO3/maturin-action`. abi3 (cp311) wheels, one per platform, each
built on a native runner: manylinux_2_28 and musllinux_1_2 x86_64 and aarch64, macOS
arm64 and x86_64, Windows x86_64 and arm64. About 300 KB each.

- Free-threaded (3.13t, 3.14t, later 3.15t): per-version wheels on the same platforms
  (question 10). The module already declares `gil_used = false`.
- PyPy: none for now (question 10). cpyext call overhead is high and PyPy's JIT already
  runs the Python decoders well; measure once before adding.
- sdist published; Pyodide skipped.
- A job per platform installs each built wheel in a clean venv and runs
  `test_api.py` and `test_parity.py`. The parity job runs on PRs that touch a kernel or
  a twin; the full suite with kernels on runs post-merge and nightly (PR 1514 rule).
- `cargo clippy -D warnings`, `cargo fmt --check`, `cargo deny`, and the atheris
  targets pointed at the kernels in the nightly fuzz job, every crash kept as a replayed
  regression input.

## D8. Release

1. A session opens the release PR: version in `Cargo.toml`, the package changelog,
   raised kernel revisions; it gives davi the merge commit and paste-ready notes.
2. davi creates the release in the GitHub web UI with tag `codecs-vX.Y.Z` and unticks
   "Set as latest release", so the repo's latest release stays archivey's.
3. `codecs-publish.yml` runs on `codecs-v*` (archivey's `publish.yml` runs on `v*`,
   which `codecs-v…` does not match), checks the tag against `Cargo.toml`, builds and
   tests the matrix, and uploads through Trusted Publishing.
4. One-time: PyPI and TestPyPI pending publishers for `archivey-codecs`, and a TestPyPI
   dry run through `workflow_dispatch`.
5. `scripts/release.py` support only if releases become frequent.

Release when a kernel is added or its revision changes, or for a security fix.

## Risks

- Bus factor and review load: Rust review is new to the loop. Kept small by
  line-by-line ports and the parity tests.
- A missed check panics instead of corrupting memory; archivey turns the panic into
  `CorruptionError` (D3). The parity and fuzz jobs treat any panic as a failure.
- Allocation failure aborts the process; bounded by D3's memory rule.

## Open questions

All ruled by the maintainer (davi, project thread, 2026-11-21, cards unless noted).

1. Go ahead with a separately versioned package, starting from #1416? RULED yes.
2. D1: name `archivey-codecs`? RULED yes.
3. D6: same repo, `packages/archivey-codecs/`? RULED yes.
4. D3: streaming decoders in the `LZMADecompressor` shape, and one-shot
   `decompress(block, out_size=)` functions for codecs whose blocks stand alone (LZO,
   later ADC and LZFSE)? RULED yes (the split confirmed in the thread).
4b. D3: `copy()`, `getstate()` / `from_state()` and `total_in` / `total_out` on every
   streaming decoder, the state leaving out held input and `from_state` refusing another
   revision's state? RULED yes (added during the questions, at davi's ask).
5. D1/D2: hashes in 0.1? RULED CRC-16/ARC only (davi in words, correcting a card tap);
   BLAKE2sp stays in Python, which PR 1709 made linear in the update size.
6. D2: CRC `digest()` big-endian? RULED yes.
7. D4: per-kernel revisions with a minimum per kernel in archivey, range `>=0.1,<1`?
   RULED yes.
8. D5: public `OptionalLibrary.ARCHIVEY_CODECS`? RULED yes.
9. D5: `[recommended]` gains the package one archivey release after codecs 0.1? RULED
   yes, and `archivey-cli` depends on `archivey[codecs]` from the first archivey
   release that knows the package (davi in words).
10. D7: free-threaded wheels in 0.1, no PyPy wheels until measured? RULED yes.
11. D5: LZO order archivey-codecs, then compress-utils, then Python? RULED yes.
12. Name of the extra: `[codecs]`? RULED yes.
13. D5: under `ProcessIsolation.NATIVE_DECODERS`, where do the kernels run? RULED: in
    archivey's decoder child, like the other native decoders, so the setting keeps its
    promise and keeps the speed-up (card, after an earlier card had chosen Python
    in-process; raised by review round 1).
14. D3: keep LZX, LZW and BCJ2 in 0.1 with the framing and end-of-input API (LZX
    `output_size`, LZW `flush()`, BCJ2 `out_size` and restore without `copy()`)?
    RULED: yes, all three in 0.1 (card; raised by review round 4). Review round 5 added
    LZX `flush()` for the end of input, within the same ruling.
