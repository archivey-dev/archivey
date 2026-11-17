# LZO1X kernel: compress-utils vs python-lzo

Measured 2026-11-17 on Linux x86-64, CPython 3.11, 4 cores. compress-utils 0.12.1,
python-lzo 1.15 (liblzo2 2.10). Script:
[`scripts/investigations/lzo_compress_utils/compare.py`](../../scripts/investigations/lzo_compress_utils/compare.py).
Follows the broader study in
[`codec-libraries-snappy-compress-utils.md`](codec-libraries-snappy-compress-utils.md).

## Result

compress-utils can replace python-lzo as archivey's optional LZO1X kernel, with
archivey's Python decoder as a retry when compress-utils refuses a block. It is
**1.2 to 1.4 times faster** than python-lzo on compressible data, ships wheels for
every supported CPython platform including free-threaded builds, and is MIT. Its only
disagreement with archivey in 700,000 fuzz cases is that it refuses LZO1X end markers
other than the canonical `11 00 00`, which liblzo2 and archivey accept. No crash and no
output over the limit was seen in either library.

## Where both plug in

LZO decoding already goes through one block hook, `lzo1x_decompressor()` in
`internal/streams/codecs/lzo_decoder.py`: a `(block, limit) -> bytes` function used by
both lzop blocks (at most 64 MiB, checked against `max_decoder_memory` first) and
SquashFS blocks (at most 1 MiB). `compress_utils.decompress(block, "lzo",
expected_size=limit)` has exactly that shape: `expected_size` is an upper bound, and the
result is what was decoded. Framing, checksums and limits stay archivey's. The
streaming `DecompressStream` API, whose `max_output` is not resumable, is not needed.

## Correctness

Differential fuzz of the three decoders on raw blocks: seeds are LZO1X-1 and LZO1X-999
output of nine inputs (empty, tiny, text, Python source, random, mixed, zeros, a
repeated pair), mutated by bit flips, byte overwrites, truncation, trailing bytes,
splices and short random blocks; the limit is the true size, a bit more, a bit less, or
4096.

| Outcome over 700,000 cases | Count |
| --- | ---: |
| all three refuse | 632,558 |
| all three return the same bytes | 66,858 |
| python-lzo and archivey accept, compress-utils refuses | 584 |
| any other disagreement | 0 |

All 584 compress-utils-only refusals are the alternate end marker: replacing the final
three bytes with `11 00 00` makes compress-utils return the same bytes (checked on the
last 200,000 cases; the earlier 500,000 showed only the same family). This is the same
case as `lzo-0.bin` to `lzo-3.bin` in the earlier study. python-lzo agreed with archivey
on every case, accepting and refusing.

Neither library returned more bytes than the limit. Edge cases: both refuse empty input;
both accept `11 00 00` with a limit of 0. python-lzo raises `OverflowError` for a limit
of 2 GiB or more; archivey never asks for one (lzop blocks are capped at 64 MiB).

Error types: compress-utils raises `CompressError` for every refusal seen, python-lzo
`lzo.error`. Both map to archivey's `LzoError` in one place.

## Speed

One-shot decode of LZO1X-1 blocks, in-process, MB/s of output (one run each,
20 repetitions for the native decoders):

| data | block | python-lzo | compress-utils | archivey Python |
| --- | ---: | ---: | ---: | ---: |
| Python source | 4 KiB | 413 | 519 | 22.6 |
| Python source | 128 KiB | 357 | 496 | 15.5 |
| Python source | 256 KiB | 361 | 444 | 19.5 |
| binary (python executable) | 4 KiB | 601 | 697 | 29.1 |
| binary (python executable) | 128 KiB | 448 | 541 | 21.3 |
| binary (python executable) | 256 KiB | 460 | 578 | 21.8 |
| random (stored as literals) | 4 KiB | 10,217 | 8,924 | 2,809 |
| random (stored as literals) | 128 KiB | 19,603 | 32,948 | 5,829 |
| random (stored as literals) | 256 KiB | 24,029 | 36,521 | 5,806 |

Both native decoders are about 20 times faster than the Python one on real data. The
difference between the two native ones (1.2 to 1.4 times) matters less than the
difference in who can install them.

## Packaging and license

| | python-lzo 1.15 | compress-utils 0.12.1 |
| --- | --- | --- |
| License | GPL-2.0 (liblzo2 GPL-2.0+) | MIT; bundled codecs BSD/0BSD/MIT; lzokay MIT |
| Wheels | for archivey's Pythons (3.11+), only CPython 3.11 on Windows x86-64; the others are 3.7 to 3.10 or macOS x86-64 for 3.7/3.8; none for Linux, macOS arm64 or PyPy | CPython 3.11 to 3.15, Linux x86-64/aarch64 (glibc 2.28+), macOS arm64, Windows x86-64; 3.14t and 3.15t |
| Without a wheel | builds from source, needs liblzo2 headers | sdist |
| Free-threaded | re-enables the GIL on import (measured 2026-10-30, 3.14t) | free-threaded wheels; GIL behaviour not measured here |
| Not covered | | PyPy, musl, macOS x86-64 |
| Maturity | liblzo2 is 2017 and widely used | young (0.x); lzokay-derived decoder adapted by the project |

In practice python-lzo installs without a compiler and liblzo2 headers only on Windows
with CPython 3.11, so almost every user decodes LZO in Python today. archivey never
depends on python-lzo (it is only detected), so GPL is a cost to users who install it,
not to archivey.

compress-utils is also what the parked Snappy experiment uses, so one optional
package would serve both codecs.

## What a replacement needs

1. A new `OptionalLibrary` member for compress-utils (shared with Snappy if that lands),
   and `lzo1x_decompressor()` choosing it, with `excluded_libraries` and `usage`
   recording as today.
2. On `CompressError`, decode the same block with `lzo1x_decompress_python` and use its
   result or its error. This covers the alternate end markers and keeps the error
   message archivey's. The retry costs a Python decode of one block only on refusal,
   which is damaged data in every case seen except the end markers.
3. A decision on python-lzo: remove it (one kernel, less code, no GPL path) or keep it
   as a second choice where compress-utils has no wheel (PyPy, musl, macOS x86-64);
   python-lzo has no wheel there either, so it would only help users who build it.
4. Isolation: python-lzo runs in-process by default and only in a child under
   `NATIVE_DECODERS`. compress-utils would follow the same rule; this needs the child
   bridge entry that `Natives.lzo_decompress` has for python-lzo.
5. Tests: the existing LZO tests under each kernel (`--all-configs`), plus the four
   end-marker repros.

An upstream report to compress-utils about the alternate end markers would let a later
version drop the retry for that case.
