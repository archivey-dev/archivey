# libarchive as an accelerator for archivey's Python decoders

**Status:** finished evidence, 2026-11-09. Not pursued: the recommendation is no.
**Measured on:** the system libarchive 3.7.2 (Ubuntu 24.04 build: zlib, liblzma, bz2,
lz4, zstd; no liblzo2), CPython 3.11, 4 cores. Oracle for LZX: `cabextract` 1.11.
**Code:** [`scripts/investigations/libarchive_accelerator/`](../../scripts/investigations/libarchive_accelerator/)
(`bindings.py`, `wrappers.py`, `bench.py`, `differential.py`). Not wired into archivey.

## Question

archivey decodes several codecs in pure Python (DR-20: no native library behaves well
enough on damaged input, or none exists). Could the system libarchive decode those
streams faster, as an optional accelerator? An accelerator changes speed, never the
result or the error type (DR-5); the only accepted exception is the rapidgzip shape in
DR-5a.

## Result

**No.** libarchive is as fast as a native port (13x to 28x over the Python decoders),
but it fails the accelerator rule, and it cannot be made to pass it:

1. **It accepts damaged streams that archivey refuses, and archivey cannot change
   that.** In 1,000 streams each, 174 cut `.Z` streams (77% of the cut ones) decode
   with no error in libarchive where archivey raises `TruncatedError`, and 29 damaged
   LZX folders decode with no error where archivey and `cabextract` refuse them. A fallback to Python on a libarchive
   error repairs only the other direction.
2. **It needs a child process.** libarchive is C with a long CVE list in exactly these
   readers. DR-20 puts a native codec that can crash in a child process. That costs a
   process start per stream, which is what makes PPMd slow on small members today.
3. **What a machine gets depends on its libarchive.** The system library differs by
   distribution and version (RHEL 8 has 3.3, Debian 12 has 3.6, Ubuntu 24.04 has 3.7.2
   without liblzo2), and Windows ships no copy that programs are meant to load. So the same archive could read differently
   on two machines (DR-5), and a bundled copy would need the same wheel matrix as the
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

The wrappers are small (a CAB header is 64 bytes, a ZIP local header 31), and the coded
bytes pass through unchanged, pulled through libarchive's read callback in chunks, so
nothing reads the whole member first. archivey keeps the checks the container carries
(CFDATA checksums, CRCs), because the wrapper writes zero or ignored check values.

## Speed

`bench.py`: the same coded bytes fed in 64 KiB chunks to archivey's decoder and to
libarchive behind the wrapper, best of three, outputs equal. The libarchive column
includes the wrapper, the callback and the copy out.

| Kernel | Python | libarchive | Speed-up | Rust (PR 1416) |
| --- | ---: | ---: | ---: | ---: |
| `.Z`, 11 MB text | 930 ms | 68 ms | **13.8x** | 14x end to end |
| ZipCrypto decrypt, 11 MB | 2,770 ms | 117 ms | **23.6x** | 32x (131 MB/s) |
| LZX 16-bit window, 4 MB text | 380 ms | 15 ms | **25.5x** | 32x |
| LZX 21-bit window, 4 MB text | 422 ms | 15 ms | **28.2x** | 32x |
| LZH `-lh5-`, 1 MiB (PR 1405's decoder) | 114 ms | 5 ms | **~25x** | not ported |
| LZH `-lh7-`, 1 MiB | 102 ms | 4 ms | **~27x** | not ported |

Whole archives read by libarchive, against archivey reading them end to end (the
codecs already in C dominate, so these gain little):

| Archive | archivey | libarchive | Speed-up |
| --- | ---: | ---: | ---: |
| 7z ARM64 + LZMA2, 16 MB | 155 ms | 139 ms | 1.1x |
| 7z BCJ2 + LZMA, 16 MB | 233 ms | 154 ms | 1.5x |
| 7z PPMd, 11 MB (pyppmd in a child) | 993 ms | 621 ms | 1.6x |
| ZIP PPMd8, 11 MB (pyppmd in a child) | 1,091 ms | 723 ms | 1.5x |

The 7z filter and PPMd rows are not worth a wrapper: 1.1x to 1.6x, and PPMd would need
the child process in either library.

## Parity on damaged input

`differential.py 1000 1`: each stream decoded by archivey's decoder and by libarchive
behind the wrapper; a tenth clean, the rest with 1 to 3 bit flips, 1 to 8 replaced
bytes, or a cut.

| Codec | Same result | Both refuse | archivey accepts, libarchive refuses | **libarchive accepts, archivey refuses** |
| --- | ---: | ---: | ---: | ---: |
| `.Z` | 618 | 208 | 0 | **174** (all cuts: 77% of cut streams) |
| LZX, no CFDATA checksums | 234 | 722 | 15 | **29** |
| LZH, CRC-16 set to match libarchive's output (500, PR 1405) | 49 | 404 | 0 | **47**, all of a wrong size |
| ZipCrypto decrypt (200 random) | 193 | - | - | 0 (7 passwords with a NUL byte cannot reach libarchive) |

- **`.Z`.** A `.Z` stream has no length and no check value. archivey refuses a cut
  stream when bits are left after the last whole code; libarchive returns what it
  decoded. Nothing outside the decoder can tell, so an accelerator would turn
  `TruncatedError` into a short read with no error (DR-1).
- **LZX.** libarchive accepts trees that do not fill their code space, matches that
  reach before the stream start, and block types 0 and 4 to 7. `cabextract` refuses
  all 29, like archivey. The CFDATA checksums catch most damage, but they are optional,
  and a crafted cabinet carries valid ones.
- **LZH.** Every lenient case returns more or fewer bytes than the header's size, so a
  wrapper that compares the size would refuse them all. In this sample that gives
  parity; the size check is archivey's, not libarchive's.
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
  bytes. They are C. Over about 3,000 damaged streams nothing crashed, but DR-20 asks
  for a child process unless a codec's behaviour on damage is measured, and the
  measured behaviour above is not archivey's.
- **GIL.** ctypes releases the GIL during `archive_read_data`, but each read callback
  takes it back, once per input chunk.
- **Passwords.** A NUL byte ends a libarchive passphrase, so those members would need
  the Python path.

## Side finding: LZX decodes some damaged folders that `cabextract` refuses

With `cabextract` as a third opinion, **15 of 1,000** damaged LZX folders without
checksums decode in archivey with no error to wrong bytes, while both `cabextract`
("error in CAB data format") and libarchive refuse them. In a CAB-level run, all 31 such
cases used the zero padding past the folder's last block. archivey's LZX decoder says it
follows libmspack's `lzxd.c`, so this is a difference from the tool it matches. Tracked
internally as a separate fix.

## Reproduce

```sh
uv run python scripts/investigations/libarchive_accelerator/bench.py
uv run python scripts/investigations/libarchive_accelerator/differential.py 1000 1
```

Both need the system libarchive (`libarchive.so.13`) and `ncompress`; the LZX third
opinion needs `cabextract`. The LZH rows used PR 1405's branch with a variant of the
differential script.
