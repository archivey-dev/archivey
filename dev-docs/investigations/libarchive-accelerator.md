# libarchive as an accelerator for archivey's Python decoders

**Status:** finished evidence, 2026-11-09 (re-measured 2026-11-10 on `main` after PR
1480). Not pursued: the recommendation is no.
**Measured on:** the system libarchive 3.7.2 (Ubuntu 24.04 build: zlib, liblzma, bz2,
lz4, zstd; no liblzo2), CPython 3.11.18, 4 cores, archivey at merge `1a440968` plus this
PR's scripts. Oracle for LZX: `cabextract` 1.11.
**Code:** [`scripts/investigations/libarchive_accelerator/`](../../scripts/investigations/libarchive_accelerator/)
(`bindings.py`, `wrappers.py`, `bench.py`, `differential.py`). Not wired into archivey.

## Question

archivey decodes several codecs in pure Python (DR-20: no native library behaves well
enough on damaged input, or none exists). Could the system libarchive decode those
streams faster, as an optional accelerator? An accelerator changes speed, never the
result or the error type (DR-5); the only accepted exception is the rapidgzip shape in
DR-5a.

## Result

**No.** libarchive is as fast as a native port (13x to 26x over the Python decoders),
but it fails the accelerator rule, and it cannot be made to pass it:

1. **It accepts damaged streams that archivey refuses, and archivey cannot change
   that.** In 1,000 streams each, 188 cut `.Z` streams (78% of the cut ones) decode
   with no error in libarchive where archivey raises `TruncatedError`, and 43 damaged
   LZX folders decode with no error where archivey and `cabextract` refuse them. A
   fallback to Python on a libarchive error repairs only the other direction.
2. **It needs a child process.** libarchive is C with a long CVE list in exactly these
   readers. DR-20 puts a native codec that can crash in a child process. That costs a
   process start per stream, which is what makes PPMd slow on small members today.
3. **What a machine gets depends on its libarchive.** The system library differs by
   distribution and version (RHEL 8 has 3.3, Debian 12 has 3.6, Ubuntu 24.04 has 3.7.2
   without liblzo2), and Windows ships no copy that programs are meant to load. So the
   same archive could read differently on two machines (DR-5), and a bundled copy would need the same wheel matrix as the
   Rust package, for C code archivey does not control.

The parked Rust package (draft PR 1416) gives the same speed, in-process, with byte-
and message-exact parity enforced by differential tests, for more codecs. If these
decoders need to be faster, resume that.

## There is no codec API

libarchive's decoders sit behind its format readers. `archive_read_support_format_raw`
plus a filter reaches only the stream formats (`.Z`, lzop, and codecs archivey already
runs in C). Every other codec needs a **synthetic one-entry container** around the coded
bytes, as archivey already does for RAR and `unrar`:

| archivey decodes in Python | libarchive 3.7.2 | How to reach it |
| --- | --- | --- |
| LZW (`.Z`) | yes | `raw` format + `compress` filter |
| LZX (CAB) | yes | synthetic CAB: one folder, the CFDATA blocks as stored |
| ZipCrypto | yes | synthetic stored ZIP entry, `zip:ignorecrc32` |
| LZH `-lh5-`/`-lh6-`/`-lh7-` (LHA, PR 1405) | yes | synthetic LHA header |
| LZH `-lh1-`, `-lzs-`, `-lz5-` | no | |
| BCJ2, ARM64 (7z) | yes | synthetic 7z header (not built: see below) |
| RISC-V (7z) | **no** ("Unexpected codec ID") | |
| LZO1X | only with liblzo2 or an external `lzop`; Debian and Ubuntu link neither | |
| Shrink, Reduce, Implode, DCL Implode (ZIP) | no | |
| ARJ methods 1-4, bzip3, Quantum | no | |
| Deflate64 (ZIP 9; inflate64 today) | no | |
| PPMd7 / PPMd8 (pyppmd today) | yes | synthetic 7z / ZIP entry |

The wrappers are small (a CAB header is 64 bytes, a ZIP local header 31, an LHA
level-0 header 24), and the coded bytes pass through unchanged, pulled through
libarchive's read callback in chunks, so nothing reads the whole member first. archivey
keeps the checks the container carries (CFDATA checksums, CRCs), because the wrapper
writes zero or ignored check values. The LHA wrapper also checks the output size
itself: read as a whole archive, libarchive returned 4,993 bytes for a 5,000-byte
member and 30,037 for a 30,000-byte one, with no error.

## Speed

`bench.py`: the same coded bytes fed in 64 KiB chunks to archivey's decoder and to
libarchive behind the wrapper, best of three on each side, outputs equal. The
libarchive column includes the wrapper, the callback and the copy out. The text is the
interpreter's standard library source, so absolute times depend on the Python build.

| Kernel | Python | libarchive | Speed-up | Rust (PR 1416) |
| --- | ---: | ---: | ---: | ---: |
| `.Z`, 11 MB text | 819 ms | 62 ms | **13.3x** | 14x end to end |
| ZipCrypto decrypt, 11 MB | 2,731 ms | 118 ms | **23.2x** | 32x (131 MB/s) |
| LZX 16-bit window, 4 MB text | 375 ms | 15 ms | **24.6x** | 32x |
| LZX 21-bit window, 4 MB text | 397 ms | 15 ms | **26.4x** | 32x |
| LZH `-lh5-`, 1 MiB text | 69 ms | 4 ms | **16.2x** | not ported |
| LZH `-lh7-`, 1 MiB text | 60 ms | 4 ms | **16.0x** | not ported |

The same script's second part reads whole archives with libarchive (from memory: 7z
needs a seekable source) against archivey reading them end to end. The codecs already
in C dominate, so these gain little. The filter rows compress the interpreter's own
binary (here the 6.6 MB x86-64 `python3.11`), repeated to 16 MiB:

| Archive | archivey | libarchive | Speed-up |
| --- | ---: | ---: | ---: |
| 7z ARM64 + LZMA2, 16 MB | 346 ms | 313 ms | 1.1x |
| 7z BCJ2 + LZMA, 16 MB | 612 ms | 280 ms | 2.2x |
| 7z PPMd, 11 MB text (pyppmd in a child) | 696 ms | 471 ms | 1.5x |
| ZIP PPMd8, 11 MB text (pyppmd in a child) | 691 ms | 465 ms | 1.5x |

The 7z filter and PPMd rows are not worth a wrapper: 1.1x to 2.2x, the Rust BCJ2
kernel gives 1.75x in-process, and PPMd would need the child process in either
library.

## Parity on damaged input

`differential.py 1000 1`: each stream decoded by archivey's decoder and by libarchive
behind the wrapper; a tenth clean, the rest with 1 to 3 bit flips, 1 to 8 replaced
bytes, or a cut. The text comes from a fixed seed, so the counts repeat on any machine
with the same archivey, libarchive and `cabextract`.

| Codec | Same result | Both refuse | archivey accepts, libarchive refuses | **libarchive accepts, archivey refuses** |
| --- | ---: | ---: | ---: | ---: |
| `.Z` | 612 | 200 | 0 | **188** (all cuts: 78% of cut streams) |
| LZX, no CFDATA checksums | 327 | 629 | 1 | **43** |
| LZH `-lh5-` to `-lh7-`, codec only, wrapper size check on | 291 | 500 | 209 | 0 |
| ZipCrypto decrypt (200 random) | 195 | - | - | 0 (5 passwords with a NUL byte cannot reach libarchive) |

- **`.Z`.** A `.Z` stream has no length and no check value. archivey refuses a cut
  stream when bits are left after the last whole code; libarchive returns what it
  decoded. Nothing outside the decoder can tell, so an accelerator would turn
  `TruncatedError` into a short read with no error (DR-1).
- **LZX.** libarchive accepts trees that do not fill their code space, matches that
  reach before the stream start, and invalid block types. `cabextract` refuses all 43,
  like archivey. The CFDATA checksums catch most damage, but they are optional, and a
  crafted cabinet carries valid ones.
- **LZH.** With the wrapper's size check, libarchive accepted nothing archivey refused.
  It refused 209 streams archivey decodes ("Bad lzh data"); the LHA reader's CRC-16,
  which this codec-level test leaves out on both sides, refuses those members in
  archivey. So LZH parity is reachable, with a Python re-decode for each refusal.
- **ZipCrypto.** Decryption cannot fail, so the output is the same by construction.
  The one gap is a password with a NUL byte: libarchive takes a C string.

The other direction is repairable: when libarchive refuses, decode again in Python and
raise archivey's error, as `stdlib_takeover.py` does for rapidgzip. The lenient
direction is not: archivey cannot add libarchive's missing checks to libarchive.

## Safety and limits

- **Memory.** For these codecs libarchive allocates little and archivey can bound it
  before the call: a 2 MiB LZX window, a 64 KiB LZH window, the LZW table. PPMd is the
  exception (it allocates what the header asks); archivey reads that field first and
  could check it against `DecoderLimits.max_decoder_memory`.
- **Crashes.** The wrapper headers are archivey's, so libarchive's header-parsing CVEs
  (most of its CAB and LHA list) are out of reach; only the decoders see attacker
  bytes. They are C. Over 2,700 damaged streams (900 each for `.Z`, LZX and LZH) nothing
  crashed, but DR-20 asks for a child process unless a codec's behaviour on damage is
  measured, and the measured behaviour above is not archivey's.
- **GIL.** ctypes releases the GIL during `archive_read_data_block`, but each read callback
  takes it back, once per input chunk.
- **Passwords.** A NUL byte ends a libarchive passphrase, so those members would need
  the Python path.

## Side finding, now fixed: LZX read past the folder's end

The first run (on `main` before PR 1480) used `cabextract` as a third opinion and found
15 of 1,000 damaged LZX folders that archivey decoded to wrong bytes with no error,
while `cabextract` ("error in CAB data format") and libarchive refused them. Every case
read into the zero padding past the folder's last block. PR 1480 made archivey refuse
those streams as `cabextract` does. On the re-run, one folder remains where archivey
returns wrong bytes and libarchive refuses, and `cabextract` accepts that one, so
archivey again matches the tool it follows. The other 225 folders that decode to wrong
bytes are accepted by all three: with no checksums, nothing can tell.

## Reproduce

```sh
uv run python scripts/investigations/libarchive_accelerator/bench.py
uv run python scripts/investigations/libarchive_accelerator/differential.py 1000 1
```

Both need the system libarchive (`libarchive.so.13`) and `ncompress`. The LZX third
opinion needs `cabextract`, and the whole-archive rows need `7zz`; each part is skipped
without its tool. Every number on this page comes from these two commands.
