# archivey-codecs

Rust versions of the decoders that [archivey](https://github.com/archivey-dev/archivey)
otherwise runs in Python. When archivey finds this package, those decoders get faster,
and nothing else changes: the output bytes are the same, and a damaged archive raises
the same exception type with the same message (two caller-only exceptions are listed
below). Without it, archivey uses its Python decoders.

This is a pre-release. Every kernel has its final, standard-library-shaped API
(`hashlib`-style hashes, `lzma.LZMADecompressor`-style decoders).

| Name | Used for | archivey's Python twin |
| --- | --- | --- |
| `crc16_arc`, `Crc16Arc` | LHA data and header checks | `kernels.python.crc16_arc` |
| `lzo1x.decompress` | `.lzo` files, LZO SquashFS images | `kernels.python.lzo1x` |
| `lzw.Decompressor` | Unix `compress` (`.Z`, `.tar.Z`) | `kernels.python.lzw` |
| `zipcrypto.Decryptor` | ZIP members with traditional encryption | `kernels.python.zipcrypto` |
| `filters.Arm64Decoder`, `filters.RiscvDecoder` | 7z ARM64 and RISC-V branch filters | `kernels.python.filters` |
| `lzx.Decompressor` | LZX folders in Microsoft cabinets | `kernels.python.lzx` |
| `bcj2.Decompressor` | 7z BCJ2 (four-stream x86 filter) | `kernels.python.bcj2` |

Each twin (in `archivey.internal.kernels.python`) has the subset of the package's API
that archivey's call sites use, with the same names, arguments and behaviour. It
leaves out `Crc16Arc` (the twin has the `crc16_arc` function only), the state methods
(`getstate`, `from_state`, `copy` other than ZipCrypto's), and LZX's `unused_data`,
`total_in`, `reset()` and `window_bits`. The stubs in `python/archivey_codecs/` give
the package's whole API. archivey's call sites cannot tell which one runs, except
LZO's, which tries compress-utils between the two.

```python
import archivey_codecs
from archivey_codecs import lzw

archivey_codecs.crc16_arc(b"123456789")  # 0xBB3D
d = lzw.Decompressor()
data = d.decompress(z_bytes) + d.flush()
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
their `read()` methods. Two LZX refusals that only a caller can reach (a frame size
off the 32 KiB grid) raise `CorruptDataError` where Python raises `IndexError` or grows
its window; see `src/kernels/lzx.rs`. The kernel modules (`src/kernels/`) forbid `unsafe` code.

## Develop

From the archivey checkout:

```sh
uv pip install ./packages/archivey-codecs   # then use `uv run --no-sync`
CODECS_PARITY_CASES=1000 uv run --no-sync pytest --no-cov packages/archivey-codecs/tests
uv run --no-sync python packages/archivey-codecs/bench/bench_kernels.py
```

A change to a Python decoder in the table needs the same change here, in the same pull
request. The differential tests in `tests/test_parity.py` compare the two on clean,
damaged and random input.

The version lives in `Cargo.toml` only. Releases are tagged `codecs-vX.Y.Z`.
