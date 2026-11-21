# archivey-codecs

Rust versions of the decoders that [archivey](https://github.com/archivey-dev/archivey)
otherwise runs in Python. When archivey finds this package, those decoders get faster,
and nothing else changes: the output bytes are the same, and a damaged archive raises
the same exception type with the same message (two caller-only exceptions are listed
below). Without it, archivey uses its Python decoders.

This is a pre-release. The API below is the prototype's. Before 0.1, it is reshaped to
the standard-library shape in archivey's design
(`openspec/changes/archive/*-rust-codecs-package/design.md` once that change is
archived): `hashlib`-style hashes, `lzma.LZMADecompressor`-style decoders and a
`KERNELS` revision table.

| Kernel | Used for | Python decoder it mirrors |
| --- | --- | --- |
| `LzxDecoder` | LZX folders in Microsoft cabinets | `lzx_decoder.LzxDecoder` |
| `LzwState` | Unix `compress` (`.Z`, `.tar.Z`) | `unix_compress_decoder.LzwState` |
| `lzo1x_decompress` | `.lzo` files, LZO SquashFS images | `lzo_decoder.lzo1x_decompress_python` |
| `ZipCryptoKeys` | ZIP members with traditional encryption | `zipcrypto.ZipCryptoKeys` |
| `Bcj2Core` | 7z BCJ2 (four-stream x86 filter) | the loop of `bcj2_filter.Bcj2DecoderStream` |
| `arm64_decode`, `riscv_decode` | 7z ARM64 and RISC-V branch filters | `arm64_filter`, `riscv_filter` |

The kernels raise `CorruptData`, `TruncatedData` and `UnsupportedData`, all
subclasses of `ValueError`. LZO, the branch filters and `LzwState.feed` release the GIL
while they decode; the others hold it (LZX and BCJ2 call back into Python for input).
Two LZX refusals that only a caller can reach (a frame size off the 32 KiB grid) raise
`CorruptData` where Python raises `IndexError` or grows its window; see
`src/kernels/lzx.rs`. The kernel modules (`src/kernels/`) forbid `unsafe` code.

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
