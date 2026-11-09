# bzip3

Current maintainer truth for bzip3 (`.bz3`) as a single-file format and inside `.tar.bz3`.
bzip3 is a young format (2022) with one implementation, libbzip3, so most of this page is
about what archivey checks before that library sees a byte. What bzip3 shares with the other
codecs, the one-member reader, the seek table and the truncation contract, is on
[`single-file.md`](single-file.md).

## At a glance

| | |
| --- | --- |
| Read | `.bz3` as a one-member archive and inside `.tar.bz3` |
| Write | **Not shipped** |
| Backends | The `bzip3` package (imported as `bz3`, libbzip3 bundled), from `[bzip3]` only: not in `[recommended]` or `[all]` |
| Process | libbzip3 runs in a child process unless `process_isolation` is `NONE` |
| Seeking | With seek demand, a seek resumes at its block's start and decodes one block (§2.1) |
| Size | With seek demand on a source that can seek, from a walk of the block headers (§2.1); else `None` until a full read |
| Digests | None listed. Each block's CRC-32 is checked as it decodes |
| Metadata | None beyond the shared fields |
| Truncation | `TruncatedError` for a cut inside the header or a block; a cut between blocks reads short with no error |
| Refuses | A block size outside 65 KiB to 511 MiB, block sizes out of range, a forged literal block, a block shorter than its own header (§2), as `CorruptionError`; a block size whose decoder is over `DecoderLimits.max_decoder_memory`, as `ResourceLimitError` |

**Three things a reader might expect and will not find.** The extra does not install on macOS,
PyPy or Python 3.15 (§3). A `.bz3` cut exactly between two blocks is a valid shorter file:
the format has no end mark and no whole-file checksum. And bytes appended after the last block
are not reported as trailing data: they are read as one more block and fail.

## 1. Shape

```
file:     "BZ3v1"  block_size (s32 LE, 65 KiB to 511 MiB)
          block:   compressed (s32 LE)  decoded (s32 LE)  data[compressed]
          block:   …                                              ← to the end of the file
data:     CRC-32 (u32)  BWT index (s32; -1 = literal)  model byte  [LZP size] [RLE size]  …
literal:  CRC-32  -1  up to 64 raw bytes
```

- No end mark, no stream count, no whole-file checksum. The tool writes blocks until its input
  ends.
- The model byte's flag `0x02` adds a 4-byte LZP size and flag `0x04` a 4-byte RLE size to
  the block header.
- `bzip3 -d` (1.4.0) refuses a second file appended to the first ("Inconsistent headers")
  and bytes appended after the last block ("Corrupt file"); so does archivey.
- A block compresses to at most `n + n/50 + 32` bytes (`bz3_bound`).

## 2. The pipeline here

`codecs/bzip3_codec.py` frames the file itself and hands libbzip3 one whole block at a time;
the binding's own framing (`bz3.backends.BZ3Decompressor`) is fed the header once and then
blocks it has already been checked against.

1. **Header.** Magic, then the block size range, then `_block_size_check`: the decoder memory
   for that block size (`decoder_memory`, about 10 times the block size, from libbzip3's
   allocations) against `max_decoder_memory`. Only then is the decoder built, lazily.
2. **Each block, before decoding.** The compressed size is in `0..bz3_bound(block_size)`, the
   decoded size in `0..block_size`. A literal block holds at most 64 bytes and decodes to its
   own length. Any other block is at least 9 bytes plus 4 for each size its model byte names.
3. **After decoding.** The output length must match the block header's decoded size. The
   0.1.10 binding always returns exactly that size, so what refuses a forged decoded size
   today is libbzip3's CRC-32, which covers that many bytes; the length check holds if a
   later binding stops slicing to it.
4. **End of input.** Inside the header or a block is `TruncatedError` (the decompressor's
   `end_input` raises `EOFError`, which the stream layer turns into it).

Why archivey frames it rather than the binding: `bzip3` 0.1.10's `BZ3Decompressor` copies a
negative compressed size to `memcpy` as a huge length, and for a literal block returns as many
bytes of its buffer as the header declares, whatever the block held (stale data from the
previous block). Both are refused at step 2 before the binding sees them.

`ValueError` from libbzip3 (a CRC mismatch, a damaged block) becomes `CorruptionError`.
`MemoryError` propagates unchanged, as everywhere in archivey: running out of memory is
never a damaged archive.

### 2.1 Seeking

Every block decodes on its own: libbzip3 keeps nothing from one block to the next but the
block size. So under declared seek demand (`seekable_members=True`), each block with
output is a seek point, resumed by a new decoder told the block size
(`Bzip3Decompressor.resume`, through `framed_decoder.BlockResumable`). A forward read
records each block it reaches. On a source that can seek, a `SEEK_END`, a size query or a
seek past the known points walks the block headers from the start
(`build_bzip3_index`): one 8-byte read per block, nothing decoded. The walk stops quietly
at a header the decoder would refuse or at a block that runs past the end of the file,
keeping the points before it, and gives the size only when the last block ends at the end
of the file.

A seek then decodes at most one block: up to the block size, 16 MiB with the tool's
default. The walk trusts the block sizes, as the xz and lzip indexes are trusted
(threat-model O17): a lying decoded size in a block the seek skips moves the offsets after
it, with no error. A block that is decoded is still checked against its header and its
CRC-32. Each resume builds a new native decoder (in the child, unless `NONE`), about ten
times the block size, as the first one did.

**Detection.** `BZ3v1` is an exact magic, so a `.bz3` is found by content, whatever its name.
The inner-TAR probe does not build a decoder for blocks over 16 MiB (the tool's default) and
does not wait for a first block over 1 MiB compressed: past either it records
`CAPABILITY_UNAVAILABLE` for the inner TAR test, and the file opens as a bare `.bz3`, as an
xz with an ARM64 filter does. `format=ArchiveFormat(TAR, BZIP3)` reads such a file as a TAR.

## 3. Packaging

`[bzip3]` installs `bzip3>=0.1.10`. That release publishes wheels for CPython 3.11 to 3.14 on
Linux and Windows only, with no source distribution, so the extra cannot install on macOS, on
PyPy or on 3.15. That is why it is not in `[recommended]` (which must install everywhere) or
`[all]`. The dev group pins it with the same markers, so the macOS and PyPy jobs run the
suite without it and the tests that need it skip.

## 4. Threat surface

libbzip3 had several memory-safety fixes in its 2023 releases (out-of-bounds reads and writes
on crafted blocks). archivey's answer, ruled by davi when the format was added:

- libbzip3 runs in a child process under `KNOWN_CRASHES` and `NATIVE_DECODERS`, as pyppmd does;
  the parent imports `bz3` only under `NONE`.
- Every size libbzip3 would trust is range-checked first (§2).
- The block size is checked against the decoder memory cap before allocation.

## 5. Sharp edges

- A cut at a block boundary is undetectable; nothing in the format distinguishes it.
- The first byte of a `.tar.bz3` from a pipe waits for the first whole block (16 MiB of
  output by default).

## 6. Verify

- `tests/test_bzip3.py`: tool-written fixtures under every isolation mode, forged block
  headers, truncation, memory cap, detection limits, the package missing or excluded.
- `tests/test_bzip3_seek.py`: block seek points, the header walk and where it stops, one
  block decoded per seek under every isolation mode.
- Fixtures: `tests/fixtures/external/bzip3/`, written by the `bzip3` 1.4.0 tool.

## 7. References

- bzip3: <https://github.com/kspalaiologos/bzip3> (format in `src/libbz3.c`, the CLI framing
  in `src/main.c`).
- Python binding: <https://pypi.org/project/bzip3/>.
