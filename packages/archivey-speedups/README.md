# archivey-speedups

Rust versions of the decoders that [archivey](https://github.com/archivey-dev/archivey)
otherwise runs in Python. When archivey finds this package, those decoders get faster,
and nothing else changes: the output bytes are the same, and a damaged archive raises
the same exception type with the same message (two caller-only exceptions are listed
below). Without it, archivey uses its Python decoders.

This is a pre-release. Every kernel has its final, standard-library-shaped API
(`zlib.crc32`-style checksums, `lzma.LZMADecompressor`-style decoders). The API holds
what archivey calls, plus the saved-state methods its seek points will use.

| Name | Used for | archivey's Python twin |
| --- | --- | --- |
| `crc16_arc` | LHA data and header checks | `kernels.python.crc16_arc` |
| `lzo1x.decompress` | `.lzo` files, LZO SquashFS images | `kernels.python.lzo1x` |
| `lzw.Decompressor` | Unix `compress` (`.Z`, `.tar.Z`) | `kernels.python.lzw` |
| `zipcrypto.Decryptor` | ZIP members with traditional encryption | `kernels.python.zipcrypto` |
| `filters.Arm64Decoder`, `filters.RiscvDecoder` | 7z ARM64 and RISC-V branch filters | `kernels.python.filters` |
| `lzx.Decompressor` | LZX folders in Microsoft cabinets | `kernels.python.lzx` |
| `bcj2.Decompressor` | 7z BCJ2 (four-stream x86 filter) | `kernels.python.bcj2` |
| `lzfse.decompress`, `lzvn.decompress` | LZFSE runs in DMG images, LZFSE and LZVN compressed files on HFS+ | `kernels.python.lzfse`, `kernels.python.lzvn` |

Each twin (in `archivey.internal.kernels.python`) has the subset of the package's API
that archivey's call sites use, with the same names, arguments and behaviour. It
leaves out the state methods (`getstate`, `from_state`, `copy` other than ZipCrypto's)
and LZX's `unused_data` and `total_in`. The stubs in `python/archivey_speedups/` give
the package's whole API. archivey's call sites cannot tell which one runs, except
LZO's, which tries compress-utils between the two.

```python
import archivey_speedups
from archivey_speedups import lzw

archivey_speedups.crc16_arc(b"123456789")  # 0xBB3D
d = lzw.Decompressor()
data = d.decompress(z_bytes)
# flush() returns the output before a bad code, and the next call raises it:
# call it until eof.
while not d.eof:
    data += d.flush()
# A .Z stream has no end marker, so a cut can pass unseen. Some cuts leave
# evidence, which flush() reports here instead of raising:
if d.truncation is not None:
    raise ValueError(f"the .Z stream was cut short: {d.truncation}")
```

Errors are `CorruptDataError`, `TruncatedDataError` and `UnsupportedDataError`, all
subclasses of `CodecError`, which is a `ValueError`. `KERNELS` maps each kernel name to
its revision; a decoder's `getstate()` names that revision, and `from_state()` refuses
a state from another one. Decoders release the GIL while they read `bytes` input (the
CRC only above 64 KiB, where the release pays off); other buffers are copied first.
The BCJ2 decoder holds the GIL, because it reads its four input streams by calling
their `read()` methods. Use each decoder or decryptor object from one thread at a time,
or give each thread its own `copy()`: unlike `zlib` and `lzma` objects, which make a
second thread wait, a call made while another thread's call on the same object runs
raises `RuntimeError`. The running call is not affected. Two LZX refusals that only a caller can reach (a frame size
off the 32 KiB grid) raise `CorruptDataError` where Python raises `IndexError` or grows
its window; see `src/kernels/lzx.rs`. The kernel modules (`src/kernels/`) forbid `unsafe` code.

## Develop

From the archivey checkout:

```sh
uv pip install ./packages/archivey-speedups   # then use `uv run --no-sync`
SPEEDUPS_PARITY_CASES=1000 uv run --no-sync pytest --no-cov packages/archivey-speedups/tests
uv run --no-sync python packages/archivey-speedups/bench/bench_kernels.py
```

A change to a Python decoder in the table needs the same change here, in the same pull
request. The differential tests in `tests/test_parity.py` compare the two on clean,
damaged and random input.

The version lives in `Cargo.toml` only. Releases are tagged `speedups-vX.Y.Z`.
