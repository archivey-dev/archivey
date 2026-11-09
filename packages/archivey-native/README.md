# archivey-native (prototype)

Optional Rust versions of the decoders [archivey](https://github.com/archivey-dev/archivey)
otherwise runs in Python. Installing it makes those decoders faster and changes nothing
else: the same bytes come out, and damage raises the same exception type with the same
message. Without it, archivey uses its Python decoders.

| Kernel | Used for | Python decoder it mirrors |
| --- | --- | --- |
| `LzxDecoder` | LZX folders in Microsoft cabinets | `lzx_decoder.LzxDecoder` |
| `LzwState` | Unix `compress` (`.Z`, `.tar.Z`) | `unix_compress_decoder.LzwState` |
| `lzo1x_decompress` | `.lzo` files, LZO SquashFS images | `lzo_decoder.lzo1x_decompress_python` |
| `ZipCryptoKeys` | ZIP members with traditional encryption | `zipcrypto.ZipCryptoKeys` |
| `arm64_decode`, `riscv_decode` | 7z ARM64 and RISC-V branch filters | `arm64_filter`, `riscv_filter` |

## How archivey uses it

`archivey.internal.native` is the only module that imports this package. It uses a
kernel when the package imports, its `ABI_VERSION` is one archivey knows, the caller has
not excluded `OptionalLibrary.ARCHIVEY_NATIVE`, and `ARCHIVEY_NATIVE=0` is not set. The
kernels raise `CorruptData`, `TruncatedData` and `UnsupportedData`; archivey turns
these into its own exceptions. Every kernel that loops over caller data releases the GIL.

## Develop

```sh
uv pip install ./packages/archivey-native   # then use `uv run --no-sync`
NATIVE_PARITY_CASES=1000 uv run pytest --no-cov packages/archivey-native/tests
uv run python packages/archivey-native/bench/bench_kernels.py
```

A change to a Python decoder in the table needs the same change here. The differential
tests in `tests/test_parity.py` compare the two on clean, damaged and random input, and
`.github/workflows/native.yml` runs them whenever either side changes.
