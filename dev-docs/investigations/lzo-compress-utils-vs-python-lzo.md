# LZO1X kernel: compress-utils vs python-lzo

Measured 2026-11-17 on Linux x86-64, CPython 3.11, 4 cores. compress-utils 0.12.1,
python-lzo 1.15 (liblzo2 2.10). Scripts: block fuzz and kernel speed in
[`compare.py`](../../scripts/investigations/lzo_compress_utils/compare.py), whole reads
in [`pipeline.py`](../../scripts/investigations/lzo_compress_utils/pipeline.py)
(`scripts/investigations/lzo_compress_utils/`). Follows the broader study in
[`codec-libraries-snappy-compress-utils.md`](codec-libraries-snappy-compress-utils.md).

## Result

compress-utils replaces python-lzo as archivey's optional LZO1X kernel (maintainer's
choice, 2026-11-17). It is **1.16 to 1.4 times faster** than python-lzo on compressible
data, is MIT, and ships wheels for CPython 3.11 to 3.15 on the main platforms,
free-threaded builds included. Its only disagreement with archivey's decoder in 700,000
fuzz cases was that it refuses LZO1X end markers of a length other than 3, which
liblzo2 and archivey then accepted. archivey now refuses them too (§End markers), so the
two agree and no fallback is needed. No crash and no output over the limit was seen in
either library.

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

Before archivey refused the other end markers (first run, 700,000 cases):

| Outcome | Count |
| --- | ---: |
| all three refuse | 632,558 |
| all three return the same bytes | 66,858 |
| python-lzo and archivey accept, compress-utils refuses | 584 |
| any other disagreement | 0 |

After (rerun with 32 fixed shards, 700,000 cases, so a different sample):

| Outcome | Count |
| --- | ---: |
| all three refuse | 632,717 |
| all three return the same bytes | 66,673 |
| python-lzo accepts, archivey and compress-utils refuse | 610 |
| archivey and compress-utils disagree | 0 |

All 584 compress-utils-only refusals of the first run are an end marker whose length is
not 3 (first byte `0x12` to `0x17`, or `0x10` with an extended length); compress-utils
accepts one with only the low 2 bits set, such as `11 03 00`. Replacing the final three
bytes with `11 00 00` makes compress-utils return the same bytes (checked on the last
200,000 cases; the earlier 500,000 showed only the same family). This is the same case
as `lzo-0.bin` to `lzo-3.bin` in the earlier study. python-lzo agreed with archivey on
every case, accepting and refusing.

Neither library returned more bytes than the limit. Edge cases: both refuse empty input;
both accept `11 00 00` with a limit of 0. python-lzo raises `OverflowError` for a limit
of 2 GiB or more; archivey never asks for one (lzop blocks are capped at 64 MiB).

Error types: compress-utils raises `CompressError` for every refusal seen, python-lzo
`lzo.error`. Both map to archivey's `LzoError` in one place.

## End markers

LZO1X has no formal specification: liblzo2's code is the reference, and the only
written description of the bitstream is the kernel's `Documentation/staging/lzo.rst`.
It says a stream ends at "a block copy of distance 0", that only the `0001HLLL`
instruction encodes it, and that it takes 3 bytes. Every encoder (liblzo2, so lzop, the
kernel, lzokay) writes `11 00 00`, a length of 3.

| Decoder | Length other than 3 | Low 2 bits (literal count) |
| --- | --- | --- |
| kernel `lzo1x_decompress_safe` (reads SquashFS) | refused (`t != 3`) | ignored |
| compress-utils 0.12.1 | refused | ignored |
| liblzo2 2.10 (lzop, python-lzo) | accepted | ignored |
| upstream lzokay | accepted | ignored |
| archivey before this change | accepted, for parity with python-lzo | ignored |
| archivey now | refused | ignored |

Another length only comes from damaged or hand-made data. The pre-0.3.0 sweep accepted
it only so that the result would not depend on python-lzo being installed; with
python-lzo gone that reason is gone, and refusing follows the rule for an official tool
that lacks a check for clear damage. After the change the fuzz below found no
disagreement between the two decoders archivey uses.

## Speed through archivey

A whole `.lzo` read of 16 MiB of Python source (`pipeline.py`, best of 3, LZO1X-1
blocks), so with lzop framing, Adler-32 checks and, under `NATIVE_DECODERS`, the copy
of each block to and from a child process:

| block size | Python decoder | compress-utils in-process | compress-utils, `NATIVE_DECODERS` |
| ---: | ---: | ---: | ---: |
| 128 KiB (SquashFS default) | 20 MB/s | 265 MB/s | 97 MB/s |
| 256 KiB (lzop's) | 18 MB/s | 256 MB/s | 132 MB/s |

Isolated, compress-utils is 5 to 7 times faster than the Python decoder, which is what
an isolated read used before when python-lzo was absent.

## Kernel speed

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

Both native decoders are 18 to 32 times faster than the Python one on real data. The
difference between the two native ones (1.16 to 1.4 times) matters less than the
difference in who can install them.

## Packaging and license

| | python-lzo 1.15 | compress-utils 0.12.1 |
| --- | --- | --- |
| License | GPL-2.0 (liblzo2 GPL-2.0+) | MIT; bundled codecs BSD/0BSD/MIT; lzokay MIT |
| Wheels | for archivey's Pythons (3.11+), only CPython 3.11 on Windows x86-64; the others are 3.7 to 3.10 or macOS x86-64 for 3.7/3.8; none for Linux, macOS arm64 or PyPy | CPython 3.11 to 3.15, Linux x86-64/aarch64 (glibc 2.28+), macOS arm64, Windows x86-64; 3.14t and 3.15t |
| Without a wheel | builds from source, needs liblzo2 headers | sdist |
| Free-threaded | re-enables the GIL on import (measured 2026-10-30, 3.14t) | keeps the GIL disabled (measured 2026-11-17, 3.14t) |
| Not covered | | PyPy, musl, macOS x86-64 |
| Maturity | liblzo2 is 2017 and widely used | young (0.x); lzokay-derived decoder adapted by the project |

In practice python-lzo installs without a compiler and liblzo2 headers only on Windows
with CPython 3.11, so almost every user decodes LZO in Python today. archivey never
depends on python-lzo (it is only detected), so GPL is a cost to users who install it,
not to archivey.

compress-utils is also what the parked Snappy experiment uses, so one optional
package would serve both codecs.

## Not covered

- The fuzz is stateless over single raw blocks. lzop and SquashFS framing go through
  the existing tests, which read every LZO fixture (`tests/test_lzop.py`,
  `tests/test_squashfs.py`) with each decoder; there is no separate corpus sweep.
- No speed measured on Windows, macOS or aarch64, and no fuzz there.
- No sanitizer build of compress-utils; only its release wheels were fuzzed.

## What the replacement does

1. `OptionalLibrary.LZO` (python-lzo) is replaced by `OptionalLibrary.COMPRESS_UTILS`,
   and `lzo1x_decompressor()` picks compress-utils when it is installed and not
   excluded, recording it in `usage`.
2. A `CompressError` becomes `LzoError`, so `CorruptionError` to callers; there is no
   Python retry, since the two decoders agree. The message is the decoder's own.
3. compress-utils is in `[recommended]` on CPython except Intel macOS (no wheel), and
   in `[free-threaded]` from 3.14 (no 3.13t wheel).
4. It runs in-process by default and in a child under `NATIVE_DECODERS`, as python-lzo
   did.
5. python-lzo stays a test oracle: `tests/test_lzo.py` compares archivey's decoder with
   liblzo2 on what python-lzo compresses, in the CI benchmark job.
