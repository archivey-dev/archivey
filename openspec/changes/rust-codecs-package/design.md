# Design: rust-codecs-package

Sources: draft PR #1416 (branch `claude/project-thread-dle5be`, package
`packages/archivey-native`), its report `reports/rust-native-kernels-2026-11-09.md` in
the project files, the 2026-11-17 compress-utils investigation, and the plan
`plans/rust-codecs-package-2026-11-21.md`. Nothing below is ruled until §Open questions
says so.

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

First release: the seven prototype kernels. Hashes (question 5): BLAKE2sp (RAR5) and
CRC-16/ARC (LHA, ARJ), if measurement justifies them. On 2026-11-21 the Python CRC-16
ran at about 16 MB/s, 85x slower than `zlib.crc32`; BLAKE2sp has a quadratic `update()`
in Python today (16 MiB in one call took 22 s), which is a separate Python fix to make
first, then measure again.

Later, by value: LHA/ARJ static-Huffman and LHarc `-lh1-`; PPMd and Deflate64 as
in-process decoders (new decoders, each needs the DR-20 damaged-input evaluation); the
DOS-era ZIP methods and ARJ method 4; DMG's ADC and LZFSE if DMG resumes.

## D2. Hash API

```python
h = archivey_codecs.blake2sp(b"optional initial data")
h.update(chunk); h.digest(); h.hexdigest(); h.copy()
h.name, h.digest_size, h.block_size

archivey_codecs.crc16_arc(data, value=0) -> int   # like zlib.crc32
c = archivey_codecs.crc16_arc.new()                # hashlib-shaped object
```

- Every hash is a type with `update`, `digest`, `hexdigest`, `copy`, `name`,
  `digest_size`, `block_size`, and a constructor taking optional initial data.
- CRCs also have the `zlib.crc32` function form.
- CRC names follow the CRC catalogue (`crc16_arc`), since "CRC-16" names over twenty
  algorithms.
- A CRC's `digest()` is big-endian (question 6), matching the `crc32c` package and
  archivey's `MemberDigest`.
- `update()` releases the GIL above a threshold (64 KiB), as `hashlib` does.

## D3. Decoder API

```python
d = archivey_codecs.lzx.Decompressor(window_bits=21)
out = d.decompress(data, max_length=-1)
d.eof, d.needs_input, d.unused_data

archivey_codecs.lzo1x.decompress(block, out_size=n)
archivey_codecs.filters.arm64_decode(buf, start_offset)
```

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

The "change it twice" rule stays: a fix to a twinned Python decoder is made in Rust in
the same PR, and the kernel's revision goes up. Users get the fixed Python version
until the next codecs release turns the kernel back on.

## D5. How archivey installs and turns it off

- Extra `archivey[codecs]` with platform markers, so pip never falls back to the sdist:

  ```toml
  codecs = [
    "archivey-codecs>=0.1,<1; platform_python_implementation == 'CPython'"
    " and sys_platform in 'linux darwin win32'",
  ]
  ```

  (the final marker form is checked against pip and uv in the implementation PR).
- In `[recommended]` one archivey release after the first codecs release (question 9).
- `OptionalLibrary.ARCHIVEY_CODECS` (question 8), passed through every call site (the
  prototype reached only LZO), and `ARCHIVEY_CODECS=0` in the environment for tests.
- Kernels run in-process whatever `ProcessIsolation` says.
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

One workflow on `PyO3/maturin-action`. abi3 (cp311) wheels, one per platform:
manylinux x86_64 and aarch64 (native arm runner), musllinux x86_64 and aarch64, macOS
arm64 and x86_64 (cross-compiled), Windows x86_64 and arm64. About 300 KB each.

- Free-threaded (3.14t, later 3.15t): per-version wheels on the same platforms
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
- A missed check panics instead of corrupting memory; panics reach Python as
  `PanicException` (a `BaseException`). The parity and fuzz jobs treat that as failure.
- Allocation failure aborts the process; bounded by D3's memory rule.

## Open questions

Recommendation first. None ruled yet.

1. Go ahead with a separately versioned package, starting from #1416? Recommended: yes.
   Alternative: keep #1416 parked.
2. D1: name `archivey-codecs`? Recommended: yes. Alternatives: `archivey-native`, a
   brand-free name.
3. D6: same repo, `packages/archivey-codecs/`? Recommended: yes. Alternative: a separate
   repo.
4. D3: decoders in the `LZMADecompressor` shape, plus one-shot `decompress(data,
   out_size=)` for block codecs? Recommended: yes. Alternative: `zlib.decompressobj`
   shape.
5. D1/D2: BLAKE2sp and CRC-16/ARC in 0.1? Recommended: yes if a measurement after the
   Python BLAKE2sp fix still shows a real gain; otherwise in a later release. The
   `hashlib` interface is the design either way.
6. D2: CRC `digest()` big-endian? Recommended: yes. Alternative: little-endian, as most
   archive formats store CRCs.
7. D4: per-kernel revisions with a minimum per kernel in archivey, and a loose range
   `>=0.1,<1`? Recommended: yes. Alternative: one package-wide ABI number.
8. D5: public `OptionalLibrary.ARCHIVEY_CODECS`? Recommended: yes.
9. D5: add the package to `[recommended]` (with markers) one archivey release after the
   first codecs release? Recommended: yes. Alternative: `[codecs]` only.
10. D7: free-threaded wheels in 0.1, no PyPy wheels? Recommended: yes to both.
11. D5: LZO order archivey-codecs, then compress-utils, then Python? Recommended: yes.
12. Name of the extra: `[codecs]`? Recommended: yes. Alternative: `[native]`.
