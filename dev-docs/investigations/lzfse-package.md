# LZFSE: the `lzfse` package against archivey's own decoder

This is Part A0 of the DMG reader plan (`openspec/changes/dmg-reader/`, design §11). It
checks whether the `lzfse` package from PyPI can be the optional fast LZFSE decoder of
Part H, next to the pure-Python decoder that Part A ports from the prototype.

Measured on 2026-11-21 with `lzfse` 0.4.2.post1 on Linux x86-64 (a 4-core Xeon at
2.1 GHz). The interpreters were CPython 3.13.18, CPython 3.14.6 free-threaded and PyPy
3.11.15. The scripts are in
[`scripts/investigations/lzfse_package/`](../../scripts/investigations/lzfse_package/),
and their output is in `results/` next to them.

## Result

**Recommendation: do not use the package as it is.** Part A should ship the Python
decoder alone. Part H should wait for an upstream fix of the binding; a draft upstream
report of the problems below is ready for the maintainer to file.

The package is fast, correct on real data, and has wheels for every CPython archivey
supports. Its C decoder did not crash or hang in 200,000 fuzz cases. Two problems
remain, and archivey cannot work around either one from the outside:

- **The output has no limit.** `lzfse.decompress(buffer)` takes no size argument. The
  first buffer it allocates comes from a 32-bit field in the input. When that buffer
  fills, the binding doubles it and decodes again from the start, with no upper bound.
  The block headers do not bound the output either: in 1,078 fuzz cases the call
  returned more bytes than the limit, which is at least the total the headers declare.
  An in-process call can therefore use as much memory as the input asks for. A call in
  a child process with a memory limit is safe, but it costs a copy through a pipe.
- **It accepts some damaged streams that the Python decoder refuses.** The worst case
  is a block whose matches use more literals than the block decoded. Apple's code then
  copies bytes that were never decoded, so the output is zeros or literals left over
  from an earlier block. archivey's rule is that an accelerator never changes a result
  or an error type, and archivey refuses clear damage that the official tool merely
  fails to check (the maintainer, 2026-11-10). Neither rule holds with this package:
  0.3% of the fuzz cases still decode to bytes when the Python decoder raises, even
  after archivey's own header checks.

The other way to make the package usable is to ask for a ruling. It would make an
exception to "accelerators never change the result" for LZFSE blocks whose literal
counts are inconsistent. With that ruling, Part H can use the package now: in a child
process, behind the header walk and the length check (§Using it safely).

A third way is the Rust speedups package (`archivey-speedups`, planned separately). It
could hold its own LZFSE kernel with archivey's checks. That is more work, and decision
D3 in the design prefers an established package as an extra.

## The package

| | |
| --- | --- |
| Release | 0.4.2.post1, uploaded 2026-10-16. The previous release, 0.4.2, was 2024-04-19. |
| Licence | The binding is MIT (Yogesh Khatri and Dima Krasner). The vendored decoder is Apple's BSD-3 reference implementation (`lzfse/lzfse`). |
| Repository | github.com/m1stadev/lzfse. This session could not read its issue tracker, so duplicates were not checked. |
| Wheels | CPython 3.9 to 3.15, including free-threaded 3.14t and 3.15t. Platforms: manylinux and musllinux (x86-64, aarch64, i686), macOS (x86-64, arm64) and Windows (win32, amd64). |
| Not covered | PyPy (no wheel; the sdist built here with a C compiler), Windows arm64, Linux ppc64le, s390x and armv7. |
| Free-threaded | The module does not declare `Py_mod_gil`. Importing it re-enables the GIL with a `RuntimeWarning`, as brotli, inflate64 and pyppmd do, so archivey would import it only in a child process. |
| API | `compress(buffer)`, `decompress(buffer)` and `lzfse.error`. Nothing else. |

## What `decompress()` does

Read from `pylzfse.c` and checked by running it
([`probes.py`](../../scripts/investigations/lzfse_package/probes.py),
`results/probes-*.json`):

- **The first allocation comes from the input.** The binding reads the eight bytes at
  offset 4 as a `size_t` and keeps the low 32 bits. That is the first block's raw size,
  up to 4 GiB. Nothing checks the input's length first, so an input shorter than 12
  bytes is read past its end. Inside a Python `bytes` object this did not crash, and
  every such input raised `lzfse.error`.
- **A buffer that fills is doubled, and the stream is decoded again.** Apple's
  `lzfse_decode_buffer` returns the buffer size both when the output fits exactly and
  when the buffer is too small. The binding cannot tell these apart, so it doubles the
  buffer either way. As a result:
  - **A correct single-block stream is decoded twice.** One example is a 16 MB stream
    whose first block declares the true size. The binding took 58 ms on CPython 3.13.
    One call into the same C function with a buffer one byte larger took 32 ms.
  - **A stream that always reports a full buffer doubles until allocation fails.** One
    32-byte `bvxn` block raises `MemoryError` at once, with any memory limit or none. The
    pages are reserved and never touched.
  - **Nothing caps the output.** A stream of 256 copies of one `bvx2` block that holds
    16 MiB of zeros is 2.5 MB long and asks for 4 GiB. Under a 1 GiB address-space limit
    it raises `MemoryError`. Sixteen copies (160 KB of input) return 256 MiB.
- **An empty stream raises `lzfse.error`.** `compress(b"")` writes a correct empty
  stream (`bvx-` with size 0, then `bvx$`), and `decompress()` refuses it.
- **Raw LZVN works.** decmpfs types 7 and 8 store raw LZVN with no block header. Put in a
  `bvxn` block (magic, raw size, payload size) and closed with `bvx$`, it decodes the
  same as the prototype's `lzvn_decode`. `common.wrap_lzvn` does this.
- **The ctypes route is not portable.** On Linux and macOS the extension exports Apple's
  `lzfse_decode_buffer`, so ctypes could call it once with archivey's own capped
  buffer. The Windows `.pyd` exports only `PyInit_lzfse`.
- **The GIL is released during the decode.** That matters only to threads in the child.

## Agreement on real data

[`agreement.py`](../../scripts/investigations/lzfse_package/agreement.py),
`results/agreement.json`. The prototype read every file of the ten unencrypted
`hdiutil` fixtures. Each LZFSE run and each LZVN decmpfs chunk it decoded was recorded
and decoded again with the package. The test image was VSCodium 1.92.2 for arm64,
LZFSE image `VSCodium.arm64.1.92.2.24228.dmg` from the corpus URL list. Each of its runs
was decoded with both decoders.

| Source | Records | Decoded | Mismatches |
| --- | ---: | ---: | ---: |
| Fixtures, LZFSE runs (`ULFO` images) | 5 | 2.1 MB | 0 |
| Fixtures, LZVN decmpfs chunks (`compressed.txt`, every HFS+ and APFS image) | 60 | 3.6 MB | 0 |
| VSCodium image, LZFSE runs | 342 | 337 MiB | 0 |

## Speed

[`bench.py`](../../scripts/investigations/lzfse_package/bench.py),
`results/bench.json`. The test was the VSCodium image's 342 LZFSE runs (1009 KiB each
on average) on CPython 3.13. Each figure is the fastest of three passes.

| Decoder | MB/s | ms per run |
| --- | ---: | ---: |
| Package, in process | 249 | 4.2 |
| Package, in a long-lived child, through a pipe | 208 | 5.0 |
| Prototype (pure Python), first 20 runs | 4.7 | about 210 |

The child takes about 10 ms to start (interpreter plus `import lzfse`), and archivey
reuses one child per archive. The header walk that a capped call needs costs 0.007 ms
per run. Reading the whole VSCodium image is about 1.7 s through a child and about 75 s
in pure Python.

## Fuzz

[`fuzz.py`](../../scripts/investigations/lzfse_package/fuzz.py),
`results/fuzz.json`; causes from
[`classify.py`](../../scripts/investigations/lzfse_package/classify.py),
`results/classify.txt`.

The seeds were the package's own encoder output for 45 inputs: text, random bytes, mixed
data and zeros, from 0 to 64 KiB, plus one stream of two blocks. They cover `bvx-`,
`bvxn` and `bvx2` blocks. Each case mutated a seed: bit flips, byte overwrites,
truncation, trailing bytes, splices, header size fields and packed `bvx2` fields. Most
cases used the seed's true size as the limit; one in ten used that size ±1 or +4096.

The run had 200,000 cases in four shard processes, each under a 1 GiB address-space
limit, and took 175 s. The parent restarts a shard that dies, or that makes no progress
for 30 s, and records the case.

- **No crash and no hang.**
- The package, called directly on every case, returned bytes 61,505 times, raised
  `lzfse.error` 104,020 times and `MemoryError` 34,475 times. In 3,140 cases it returned
  more than the expected size.
- **The reader's verdict differed in 2,546 cases (1.3%).** The reader's verdict is either
  the exact bytes of the expected size or a refusal. The package was called after the
  header walk, as `common.binding_capped` does.

| Cause | Cases | Python decoder | Package | Can archivey check it outside the package? |
| --- | ---: | --- | --- | --- |
| The literal count in a `bvx2` header is not a multiple of 4 | 989 | refuses | decodes the count rounded up | yes, the header walk can read it |
| A `bvx2` block decodes to a size other than its declared raw size | 915 | refuses | accepts; Apple uses that field only for `bvx-` and `bvxn` blocks | yes, by comparing the output length with the declared total |
| The matches use more literals than the block decoded | 639 | refuses | copies bytes that were never decoded (zeros or older literals) | **no** |
| A triple with no match carries a distance out of range | 3 | accepts | refuses | Python decoder bug: Part A adds Apple's check |

`common.binding_checked` adds the strict header walk and the length check. With it, 642
differences remain: the 639 literal overruns and the 3 distance cases. Fixing the
Python decoder removes the 3. The 639 remain, because only the decoder itself can see
them.

### Python decoder fixes for Part A

The fuzz also found faults in the prototype that Part A must fix when it ports the code:

- **Truncated block headers raise the wrong error.** A header cut short raised
  `struct.error` instead of `LzfseError` in 2,389 cases. Part A checks each header's
  length before unpacking it.
- **One check of Apple's is missing.** Apple checks every literal, match and distance
  triple's distance against the output so far (`lzfse_decode_lmd`). It does this even
  when the match length is 0, and the distance before the first match starts at -1. The
  prototype checks the distance only when there is a match. Part A checks it as Apple
  does, so the 3 cases are refused as Apple refuses them. The cause was found by running
  Apple's code with each error return instrumented.

## Using it safely

If the package is fixed upstream, or the maintainer makes the exception, Part H should
call it like this:

1. **Run the package only in archivey's decoder child**, as PPMd runs (ADR 0022), whatever
   `process_isolation` says. The reasons are the GIL re-enable on free-threaded builds,
   the memory use with no cap, and `MemoryError` as a refusal.
2. **Walk the block headers first** (`common.walk_blocks(strict=True)`). Refuse an
   unknown magic, a block past the input, a `bvx2` header outside the block limits, and
   a declared total other than the run's decoded size.
3. **Check the output length afterwards.** It must equal the declared total. Treat
   `lzfse.error` and `MemoryError` as damage. A correct stream needs up to about three
   times the run's size: the doubled buffer, then the copy into a `bytes` object. With
   16 MiB per run (design §4.4) the child's memory limit can stay small, but it needs
   headroom above that peak. When the copy fails, the binding replaces the `MemoryError`
   with `lzfse.error`, so a limit that is too tight makes a correct run look damaged.
4. **Wrap raw LZVN** in a `bvxn` block before calling, and **handle an empty stream**
   before the call.

## Reproduce

```sh
python3 -m venv /tmp/lzfse-venv && /tmp/lzfse-venv/bin/pip install lzfse==0.4.2.post1
cd scripts/investigations/lzfse_package
/tmp/lzfse-venv/bin/python probes.py
/tmp/lzfse-venv/bin/python agreement.py VSCodium.arm64.1.92.2.24228.dmg
/tmp/lzfse-venv/bin/python bench.py VSCodium.arm64.1.92.2.24228.dmg
/tmp/lzfse-venv/bin/python fuzz.py 200000 4 results/fuzz.json
/tmp/lzfse-venv/bin/python classify.py
```

Set `PROBE_LIMIT_GIB=3` for a free-threaded interpreter. It reserves more address space
at start, and every probe fails under 1 GiB.
