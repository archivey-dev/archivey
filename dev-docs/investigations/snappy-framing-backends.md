# Snappy framing with cramjam or compress-utils raw blocks

**Both backends work under archivey's own framing, and neither is clearly better.**
Measured 2026-11-17: they agree with an independent reference on every valid file and
every damaged input tried, neither crashed in 20.7 million fuzz runs, both stay within
about 6 MiB of extra memory on a 64 MiB file, and their speed differs by less than the
noise of this host. The one difference found: cramjam 2.14.0 refuses three valid but
unusual raw encodings that Google Snappy and compress-utils accept. No standard encoder
writes them. The real speed question is CRC-32C, not the backend: with the Python CRC a
read runs at about 20 MB/s, with `google-crc32c` at 480 to 930 MB/s.

**Ruling (maintainer, 2026-11-17): keep both, selectable.** `snappy_handler()` defaults
to `"auto"`: compress-utils when it is installed, since it matched Google Snappy on
every input, else cramjam, which has wheels for more interpreters. A caller can still
name one. Consequence: a cramjam-only install refuses the three unusual encodings below
that a compress-utils install reads. The facts behind the choice are under
[Choosing](#choosing).

## What was built

- `src/archivey/internal/streams/codecs/snappy_framed.py`: the framing format
  (`framing_format.txt` in google/snappy) in Python. It checks the stream identifier,
  chunk types and lengths, the raw block's decoded-length varint (at most 64 KiB,
  checked before a backend allocates), the decoded length after the call and the masked
  CRC-32C. It refuses unknown unskippable chunks and skips skippable ones as they
  arrive, without holding them. The stream ends only between chunks. A backend is one
  function, `decode(block, size) -> bytes`; everything else is shared.
- `src/archivey/internal/snappy_plugin.py`: `snappy_handler(backend, crc)` returns a
  `CodecHandler` for `register_codec`. Nothing registers it by default, so no public
  enum, format list or dependency changes. `.sz` and `.tar.sz` then read through the
  ordinary plugin-codec path.
- `tests/test_snappy_framed.py`: 86 tests, run for both backends: round trips, feeding
  patterns, every damage kind, the earlier study's repro files. They skip when a
  backend is not installed; CI installs neither, so CI does not run them.
- `scripts/investigations/snappy_framing/`: the comparison and the fuzzer
  ([README](../../scripts/investigations/snappy_framing/README.md)); results in
  `results/`.

This follows the bounded-wrapper design in [the Snappy package
study](codec-libraries-snappy-compress-utils.md) §"A bounded Snappy wrapper" and the
`.sz` sketch in [the cramjam study](codec-libraries-cramjam-unpackio.md).

## Measurements

Linux x86-64, CPython 3.11.18, 4 CPUs, cramjam 2.14.0, compress-utils 0.12.1,
google-crc32c 1.9.0. Oracles: system Google Snappy 1.2.2 through ctypes, and a strict
Python raw decoder written from `format_description.txt`. The framing reference shares
no code with `snappy_framed`.

### Correctness

| Check | Inputs | Result |
| --- | --- | --- |
| Valid files: 4 producers (cramjam framed; Google, compress-utils and small-chunk cramjam raw blocks in a test framer) x 4 payloads x 1 KiB / 300 KiB / 4 MiB, read with `open_stream` | 48 | all exact, both backends |
| Damaged files: cuts, bit flips, byte changes, trailing data, zeros, concatenation; each backend fed whole and in 4,099-byte pieces with 777-byte reads | 6,288 | no disagreement with the reference (719 read, 1,089 truncated, 4,480 refused) |
| Earlier study's repros (`bad-crc`, `missing-identifier`, `oversized-uncompressed-chunk`, `partial-*`, `unknown-mandatory`, `skippable`, five raw blocks) | 12 | as Google Snappy and the strict reference, both backends |

### Fuzzing

Atheris, 25 minutes per target. The native backends are not instrumented, so coverage
guidance comes from the Python framing and the Python oracle only.

| Target | Runs | Native crashes | Disagreements |
| --- | ---: | ---: | --- |
| `raw`: one raw block, both backends vs Google and the strict decoder | 19.1 M | 0 | 1 signature (below) |
| `framed`: one stream, both backends fed two ways vs the reference | 1.6 M | 0 | 0 |

The raw finding is
[`cramjam-refuses-long-literal-tag-at-end.bin`](../../scripts/investigations/snappy_framing/results/repros/cramjam-refuses-long-literal-tag-at-end.bin),
hex `01 f4 00 00 00`: one byte stored as a literal with a 2-byte length field. A probe
of literal tags 60 to 63 found three refused shapes, all a literal of one or two bytes
at the very end of the block, with a 1- or 2-byte length field. Google Snappy,
compress-utils and the strict decoder accept them; cramjam says
`expected literal read of length 4`. Encoders write tags 60 to 63 only for literals over
60 bytes, so real files are unlikely to hit this. It is a stricter refusal, not wrong
bytes. An upstream report for the Rust `snap` crate is possible; the maintainer files
those.

### Speed

16 MiB, median of 5 runs (3 for the framed reads). MB/s of decoded output. Another
process on the host was idle but the numbers move by about 20 % between runs.

| Payload | raw 64 KiB blocks: cramjam / compress-utils / Google | `.sz` read, google-crc32c: cramjam / compress-utils | `.sz` read, Python CRC | cramjam's own framed decoder |
| --- | --- | --- | --- | ---: |
| text | 1,178 / 925 / 838 | 639 / 531 | 18 to 20 | 838 |
| random | 10,055 / 10,704 / 7,319 | 482 / 597 | 19 | 2,178 |
| zeros | 1,730 / 1,918 / 1,328 | 856 / 935 | 23 | 1,227 |
| mixed | 1,621 / 1,238 / 1,142 | 704 / 648 | 19 to 20 | 1,116 |

The kernels are within 30 % of each other and each leads on some payloads. Once the
framing and CRC are in Python, the ranking flips between runs. cramjam's own framed
decoder is faster still (one call per stream instead of per 64 KiB chunk), but using it
would give up the checks this module owns.

### Memory and stability

| Check | cramjam | compress-utils |
| --- | ---: | ---: |
| Extra peak RSS reading 64 MiB of zeros in 1 MiB reads | 5.2 MiB | 6.2 MiB |
| RSS growth over 200,000 refused raw blocks and 200 refused streams | 0 KiB | 20 KiB |
| Mismatches, 4 threads x 30 decodes of a 300 KiB stream | 0 | 0 |

### CRC-32C implementations

Measured 2026-11-17 on the same host, 16 MiB of random data.

| Implementation | License | 64 KiB calls | Wheels |
| --- | --- | ---: | --- |
| `crc32c` 2.9.post0 (ICRAR) | LGPL-2.1-or-later | 19,279 MB/s | 113: CPython 3.9 to 3.15 incl. 3.14t/3.15t, PyPy 3.11, glibc and musl x86-64/aarch64/riscv64, macOS x86-64/ARM64, Windows x86/AMD64/ARM64 |
| `google-crc32c` 1.9.0 | Apache-2.0 | 7,878 MB/s | 30: CPython 3.10 to 3.15, no free-threaded, no PyPy, no musl; glibc x86-64/aarch64, macOS, Windows AMD64 |
| Python, four 16-bit tables (built lazily, 1 MiB, ~25 ms) | in archivey | 21 to 22 MB/s | none needed |
| Python, slicing by 8 with byte tables (first version) | in archivey | 14 to 16 MB/s | none needed |

Both packages agree with each other and with the Python CRC. Either is far faster than
the raw Snappy decode (about 1 GB/s), so the read speed barely depends on which one.
`crc32c` reaches every interpreter archivey tests on; its LGPL license is the cost.
The 16-bit-table Python CRC (proposed by Codex on the PR, checked here on CPython 3.11,
3.12 and 3.13) replaced the first version.

## Pure-Python fallback backend

`decode_raw_python` in `snappy_framed.py` is a third backend, `"python"`, last in
`AUTO_ORDER`, so `"auto"` always finds one and reading `.sz` needs no package. It
refuses what Google Snappy refuses (cut elements, copy offset 0 or before the output
start, output past the declared length) and accepts the long-tag short literal that
cramjam refuses. All the per-backend tests above run on it too.

Differential check (60 s, 464,228 mutated raw blocks from Google-compressed payloads of
0 to 64 KiB): Google Snappy, compress-utils and the Python decoder agreed on every
accept or refuse and every output byte.

Whole `.sz` read of 8 MiB (MB/s, CPython 3.11, same machine as above):

| Payload | Python decode, google-crc32c | Python decode, Python CRC | compress-utils, google-crc32c |
|---|---|---|---|
| text | 29 | 14 | 289 to 429 |
| random (stored chunks) | 1207 | 26 | 926 |
| zeros | 164 | 25 | 958 |
| zlib-ish | 36 | 15 | 624 |

So on compressible data the Python decoder, not the CRC, is the bottleneck: about
30 to 35 MB/s, roughly 10 to 20 times slower than a native backend. A 256-entry tag
table and `struct` offset reads (Codex's experiment on PR 1629) gave 15 to 50% over
the first version; a second 60 s differential run (519,786 cases) again found no
difference from Google Snappy.

## Choosing

The facts the choice was made on:

- **Correctness.** Equal on everything measured except cramjam's three refusals above.
- **Speed.** Equal within noise. A CRC-32C accelerator is what matters. Options:
  `google-crc32c` (Apache-2.0; a C extension with a Python fallback) as an optional
  extra, or the Python CRC at about 20 MB/s. The standard library has none.
- **Reach.** From the earlier study's packaging data: cramjam has PyPy 3.11 wheels;
  compress-utils has 28 CPython wheels (glibc x86-64/aarch64, macOS ARM64, Windows
  AMD64, free-threaded 3.14t/3.15t) but no PyPy, musl, 32-bit or macOS Intel wheels, and
  links libstdc++. Neither was run here on PyPy, free-threaded CPython, Windows or
  macOS.
- **What else it brings.** compress-utils also has the LZO1X decoder the earlier study
  ranked as its next experiment. cramjam's Snappy is the Rust `snap` 1.1.1 crate.
- **Process isolation.** Both run in this process. DR-20 isolates native codecs that
  can crash; neither crashed here, but a built-in codec would need the same decision as
  lz4 and brotli.

## Before this could ship

- Make it a built-in codec (a `StreamFormat`, an `OptionalLibrary`, an extra, docs,
  format lists, detection tests) instead of an opt-in plugin, or keep it a plugin.
- Decide the CRC-32C dependency.
- Add a native backend to a CI leg so its tests run there (the Python backend's tests
  already run everywhere).
- Hadoop Snappy and bare raw Snappy stay out: neither has a magic to detect.
