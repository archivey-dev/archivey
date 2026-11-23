# Codec kernels: archivey-codecs and the Python twins

**In one minute.** archivey has its own Python decoders for a few old or rare formats:
CAB's LZX, Unix `compress` (`.Z`), LZO, 7z's BCJ2 and its ARM64 and RISC-V branch
filters, ZIP's traditional encryption (ZipCrypto), LHA's CRC-16, and Apple's LZFSE and
LZVN (DMG images and HFS+ compressed files). The optional `archivey-codecs` package has
Rust versions of the same ten kernels. Each Python
decoder has a *twin* with the package's exact API, and a switch picks the Rust kernel or
the twin: one switch per package module, so the two branch filters share one. A call
site builds its decoder through the switch and does not know which one it got: both give
the same bytes and raise the same errors, so the package changes speed only. This page
covers the switch, the two sides, what happens under `NATIVE_DECODERS`, and the rules
for changing a kernel. The guide's [streams and
codecs](../guide/06-streams-and-codecs.md) page sets the codec layer in context.

The code is in `src/archivey/internal/kernels/` (archivey's side) and
`packages/archivey-codecs/` (the package). Other pages own parts of this, and this page
links them rather than repeating them:

- The design and its rulings are openspec change `rust-codecs-package`
  (`openspec/changes/rust-codecs-package/design.md`): D3 the decoder API, D4 the
  revisions, D4a the switch, D5 installing and isolation, D7 and D8 wheels and release.
- What each format does with its kernel is on the format's page:
  [`cab.md`](../formats/cab.md) (LZX), [`7z.md`](../formats/7z.md) (BCJ2 and the branch
  filters), [`unix-compress.md`](../formats/unix-compress.md) (LZW),
  [`squashfs.md`](../formats/squashfs.md) (LZO blocks), [`lha.md`](../formats/lha.md)
  (CRC-16), [`zip.md`](../formats/zip.md) (ZipCrypto) and [`dmg.md`](../formats/dmg.md)
  (LZFSE and LZVN).
- The decoder child that runs the kernels under `NATIVE_DECODERS` is
  [`process-isolation.md`](process-isolation.md)'s.
- The package's own README (`packages/archivey-codecs/README.md`) has the table of
  kernels, their package names and their twins, and the developer commands.

## At a glance

- **Ten kernels, nine switches.** `kernels.crc16_arc`, `kernels.zipcrypto`,
  `kernels.filters` (ARM64 and RISC-V, two kernels), `kernels.lzo1x`, `kernels.lzw`,
  `kernels.lzx`, `kernels.bcj2`, `kernels.lzfse` and `kernels.lzvn`. Each takes the
  call's excluded libraries (and, for a decoding kernel, whether the call is isolated)
  and returns a namespace with the package module's names:
  `kernels.lzx(...).Decompressor`, and so on.
- **Same bytes, same errors.** The package raises its own `CorruptDataError`,
  `TruncatedDataError` and `UnsupportedDataError`. archivey's wrappers raise them as
  `CorruptionError`, `TruncatedError` and `UnsupportedFeatureError` with the same
  message, and the twins raise those directly. A message differs only where the Rust
  kernel refuses something only a caller can reach (two LZX frame-size cases, in the
  package README).
- **One switch for the caller.** `OptionalLibrary.ARCHIVEY_CODECS` in the call's
  `FormatPolicy` (`exclude_libraries` or `only_libraries`) turns the package off. No
  environment variable does.
- **Isolation.** Under `KNOWN_CRASHES` (the default) and `NONE` the kernels run in the
  caller's process. Under `NATIVE_DECODERS` the decoding kernels (LZX, LZW, LZO1X,
  ARM64, RISC-V) run in the decoder child. BCJ2, LZFSE and LZVN decode as their twins
  there, and CRC-16 and ZipCrypto stay in the caller's process under every setting
  (§2.4).
- **A Rust panic is `CorruptionError`.** The panic is its cause, and the kernel object
  that panicked refuses every later call (§2.3).
- **What you might expect and will not find:**
  - A kernel for every decoder archivey has. Only these ten have one. The DMG reader's
    ADC decoder, PPMd, LHA's and ARJ's decompressors and the rest are Python or another
    library only.
  - The package's whole API on the twins. A twin has only what archivey's call sites
    use: no `Crc16Arc` class, no state methods (`getstate`, `from_state`, and `copy`
    except ZipCrypto's), and no LZX `reset()`, `window_bits`, `unused_data` or
    `total_in`. The package's stubs (`python/archivey_codecs/`) have the whole API.
  - A way to tell, from outside, which side decoded a member. Nothing in the result
    changes. LZO is the one kernel whose backend a reader records (§2.1).
  - Rust parsers. The package holds decoding kernels only; archive parsing stays in
    Python.

## 1. Shape

- **The package is a speed-up, never a behaviour change.** This is DR-5
  ([`design-rules.md`](../design-rules.md#dr-5-same-input-same-outcome)) applied to a
  whole package: an accelerator changes speed, never the result or the error type. So
  every kernel is a line-by-line port of archivey's Python decoder, down to its error
  messages, and the Python decoder stays the reference. The consequences run through the
  rest of the page: the twins need the same API (§2.2), a kernel too old to match its
  twin is skipped (§2.5), and a fix is made on both sides at once (§3).
- **One API, so call sites have one code path.** Each twin has the package module's
  names, arguments and attributes, so a call site builds what the switch returns and
  uses it the same way whichever it is. The switch is the only code that knows the
  package exists. The parity tests and the kernel benchmark use the same property from
  the other side: one driver runs over a `PYTHON` namespace and the `RUST` module.
- **The decoders have the standard library's shapes.** A stream decoder is shaped like
  `lzma.LZMADecompressor` (`decompress(data, max_length)`, `eof`, `needs_input`,
  `unused_data`), plus `flush()` where the format has no end marker (LZW, LZX). The
  CRC is shaped like a `hashlib`/`zlib.crc32` function. A call site that already drives
  a standard-library decoder drives these the same way, and the decoder child can carry
  them with the protocol it has.
- **archivey imports the package, never the reverse.** The package's tests import
  archivey (for the twins), but the package itself has no Python dependency. Its
  releases are separate (`codecs-vX.Y.Z` tags), so archivey has to cope with an older
  or newer package (§2.5).

## 2. The machinery

### 2.1 The switch (`kernels/__init__.py`)

One function per package module. Each asks `_select` whether the kernel may be used for
this call (§2.5). When it may, the function returns the package's classes and
functions wrapped by `kernels/rust.py` (§2.3); otherwise it returns the twin's from
`kernels/python/` (§2.2). The protocols at the top of the module (`LzxDecompressor`,
`BranchDecoder` and the rest) are the API both sides meet, for the type checker.

Each namespace also has `library`: `OptionalLibrary.ARCHIVEY_CODECS` when the package
decodes, else `None`. `filters` has `arm64_library` and `riscv_library` instead,
because the two filters are separate kernels with separate revisions.

The call sites:

| Kernel | Call site |
| --- | --- |
| `crc16_arc` | `backends/lha_reader.py` |
| `zipcrypto` | `backends/zipcrypto.py` |
| `filters` | `streams/codecs/lzma_filter_decoder.py` (7z ARM64 and RISC-V) |
| `lzo1x` | `streams/codecs/lzo_decoder.py` |
| `lzw` | `streams/codecs/unix_compress_decoder.py` |
| `lzx` | `backends/cab_reader.py` (its folder stream's frame loop) |
| `bcj2` | `streams/codecs/bcj2_filter.py` |
| `lzfse`, `lzvn` | `streams/codecs/lzfse_decoder.py` (DMG runs, HFS+ compressed files) |

LZO is the exception to "one code path". Its order is archivey-codecs, then
compress-utils, then Python (design question 11), so its call site takes only the
package from the switch, falls back to compress-utils itself, and calls the Python
decoder last. It is also the one call site that records `library` as the backend
that decoded the block. The LZFSE and LZVN call site reads `library` too, but only to
call its Python decoder directly when the switch gives the twin.

### 2.2 The Python twins (`kernels/python/`)

One module per package module, except the CRC: `crc16_arc` is a function in
`python/__init__.py`. Most are thin adapters: the decoder itself stays where it
was, and the twin gives it the package's API.

| Twin | Wraps |
| --- | --- |
| `python.crc16_arc` (in `python/__init__.py`) | its own table-driven loop |
| `python.zipcrypto` | its own cipher (the key schedule) |
| `python.filters` | `streams/codecs/arm64_filter.py`, `riscv_filter.py` |
| `python.lzo1x` | `streams/codecs/lzo_decoder.py` |
| `python.lzw` | `streams/codecs/unix_compress_decoder.py` |
| `python.lzx` | `streams/codecs/lzx_decoder.py` (`LzxDecoder` in push mode) |
| `python.bcj2` | its own decoder (the core moved into the twin) |
| `python.lzfse`, `python.lzvn` | `streams/codecs/lzfse_decoder.py` |

A twin raises archivey's errors directly. It reads any buffer (`bytes`, `bytearray`,
`memoryview`) as its bytes, as the package does.

### 2.3 The Rust side (`kernels/rust.py`)

Each class wraps one package object and keeps its API. Every method goes through two
guards from `kernels/_select.py`:

- `codec_errors` turns the package's errors into archivey's with the same message.
- `panic_to_corruption` turns a Rust panic into `CorruptionError`, the panic its cause.
  PyO3 raises a panic as `pyo3_runtime.PanicException`, a `BaseException` that passes
  `except Exception`, so it has to be caught here. A panic is a missed check in the
  kernel, never something the data or a password causes; `caused_by_panic` tells the two
  apart for code that needs to.

A stateful object also holds a `Latch`. After a panic its state may be half updated, so
the latch makes every later method call raise the same error again. Its counters
(`total_in`, `eof` and the like) still read, so a caller can report where it stopped.

The package releases the GIL while it decodes `bytes` input (the CRC only above 64 KiB,
where the release pays off) and copies other buffers first. BCJ2 holds the GIL, because
it reads its four input streams by calling their `read()` methods. The module declares
`gil_used = false`, so it does not turn the GIL back on in a free-threaded build.

### 2.4 Under `NATIVE_DECODERS` (`kernels/child.py`)

`NATIVE_DECODERS` promises that no native decoder runs in the caller's process, and
the Rust kernels are native. So under it, a decoding kernel runs in archivey's generic
decoder child, as zlib and lzma do ([`process-isolation.md`](process-isolation.md)
§2.2). `child.open_kernels` returns a stand-in for the `archivey_codecs` module whose
objects each live in a child, and the wrappers in `rust.py` use it as they use the real
module. So the bytes, the errors and the panic handling are the same as in-process: a
panic in the child comes back as `ChildPanic`, which `is_panic` counts as a panic.

- **No child, no package.** When no child can start, or the child cannot import the
  package, the call site gets the Python twin in the caller's process. A Python decoder
  is not native, so the promise holds, and the read gives the same bytes as without the
  package. The failure is remembered for the rest of the process, so a CAB with many
  folders does not try a child per folder.
- **BCJ2 decodes as its twin.** The child protocol carries one input stream, and BCJ2
  reads four. Until the protocol carries four (task 2.7 of the change), the switch gives
  the twin under `isolated`.
- **LZFSE and LZVN decode as their twins.** The child cannot run them yet, so under
  `isolated` their switches give the twins.
- **CRC-16 and ZipCrypto stay in the caller's process** under every setting, as
  checksums and AES decryption do. They take no part in decoding a compressed stream.
- **LZO takes a child for each block.** LZO1X is a one-shot call, so each SquashFS or
  `.lzo` block takes a child from the pool, decodes, and gives it back.
- **LZO without a child** goes on down its own order: compress-utils (which raises
  `ResourceUnavailableError` when it cannot be isolated either), then Python (design
  D5).

### 2.5 Which kernels are used (`kernels/_select.py`)

A kernel is used when all of these hold:

- the call's `FormatPolicy` leaves `OptionalLibrary.ARCHIVEY_CODECS` on;
- the package is installed and imports (`streams/codecs/deps.py` loads it once);
- `archivey_codecs.KERNELS[name]` is at least `MIN_REVISIONS[name]`;
- under `NATIVE_DECODERS`, for a decoding kernel, a child can run it (§2.4).

`KERNELS` maps each kernel to a revision, raised whenever the kernel's observable
behaviour changes: its output, an error's kind or message, or where it raises. archivey
needs a revision at least as new as the one its twin matches. An older kernel may differ
from the twin, so it is skipped, and the skip is logged once per process at DEBUG. A
newer one is a fixed kernel: it gives what the next archivey's twin gives, which is
the point of "or newer" over an exact pin. A change to a signature, an attribute name or
an error class is not a new revision; it is a new `KERNELS` key (design D4).

## 3. Changing a kernel

- **Change it twice.** A fix to a twinned Python decoder is made in Rust in the same
  PR, and the reverse. The kernel's revision goes up, and so does archivey's
  `MIN_REVISIONS` entry. Until the next package release, users get the fixed Python
  decoder, because the installed kernel is too old.
- **Revisions count from the first release.** Until a version is on PyPI, no build has a
  revision to keep, so a change made before it stays at revision 1.
- **A new kernel** needs, in one PR: the Rust module under `src/kernels/` and its
  bindings in `src/lib.rs`, the stubs, a twin under `kernels/python/` with the call
  sites' subset of the API, a switch function and protocol in `kernels/__init__.py`, a
  wrapper in `kernels/rust.py`, its `KERNELS` and `MIN_REVISIONS` entries, parity tests,
  a benchmark row, and the twin's files in `codecs-publish.yml`'s path filter. If it
  decodes a compressed stream, it also needs the decoder child to carry it (§2.4).
- **The kernel modules forbid `unsafe` code** (`#![forbid(unsafe_code)]` in
  `src/kernels/mod.rs`). The PyO3 bindings are in `src/lib.rs`.

## 4. Sharp edges

| Symptom | Where it lives |
| --- | --- |
| `CorruptionError` whose cause is a `PanicException`. | **archivey.** A missed check in a kernel. The object refuses every later call. Fix it in Rust, and add the input to the parity tests. |
| Under `NATIVE_DECODERS`, a 7z with BCJ2, or a DMG with LZFSE, decodes no faster with the package. | **archivey.** BCJ2, LZFSE and LZVN decode as their twins there (§2.4). |

## 5. Decisions

- **Rust, in a separate optional package, in this repository.** The package keeps
  archivey pure Python, and one repository lets one PR change both sides, with the
  parity tests running in its CI. A separate repository was rejected until there are
  outside contributors (design D6).
- **Python stays the reference.** Each kernel is a port of the Python decoder and
  matches it message for message: the Python is what users get without the package.
- **One API and one switch, rather than an `if native` at each call site.** The
  maintainer asked for it (2026-11-22). Before it, each call site had a path for the
  package and a path for Python, with different API shapes.
- **Per-kernel revisions, not one ABI number.** One number would turn every kernel off
  when any one changed (design D4).
- **The caller's switch is `OptionalLibrary.ARCHIVEY_CODECS`, and nothing else.** The
  prototype's environment variable is gone; tests that need the Python side exclude the
  library or patch the switch (design D5).
- **LZO tries compress-utils between the package and Python,** because ours is tested
  against the Python twin message for message (design question 11).
- **Under `NATIVE_DECODERS`, no child means the twin,** not `ResourceUnavailableError`:
  the twin keeps the promise and gives the same bytes (design D5).

## 6. Open questions

- **BCJ2 in the decoder child.** It needs the child protocol to carry four input
  streams (task 2.7). Until then, `NATIVE_DECODERS` gets the Python speed for BCJ2.
- **LZFSE and LZVN in the decoder child.** They are one-shot calls like LZO1X, so the
  child can carry them; it does not yet. Until then, `NATIVE_DECODERS` gets the Python
  speed for them.

## 7. Verify

With the package built into the environment:

```sh
uv pip install ./packages/archivey-codecs
CODECS_PARITY_CASES=1000 uv run --no-sync pytest --no-cov packages/archivey-codecs/tests
uv run --no-sync pytest tests/test_kernels.py
uv run --no-sync python packages/archivey-codecs/bench/bench_kernels.py
cargo test --manifest-path packages/archivey-codecs/Cargo.toml
```

Without the package, archivey's tests run with the twins only; the package's tests
skip. `codecs-publish.yml` runs the package's tests on every wheel it builds, for a pull
request that touches the package, a twin or a decoder a twin wraps.

## 8. References

- openspec change `rust-codecs-package`: `design.md` (D1 to D8, the questions) and
  `tasks.md`.
- `packages/archivey-codecs/README.md` and `CHANGELOG.md`.
- [`process-isolation.md`](process-isolation.md) §2.2, the decoder child.
- [`design-rules.md`](../design-rules.md#dr-5-same-input-same-outcome), DR-5.
