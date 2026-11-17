## MODIFIED Requirements

### Requirement: Compression methods model codec chains

The system SHALL define `CompressionAlgorithm`, frozen `CompressionMethod`, and
`tuple[CompressionMethod, ...]` for filter chains:

```python
class CompressionAlgorithm(Enum):
    STORED = "stored"
    DEFLATE = "deflate"
    DEFLATE64 = "deflate64"
    BZIP2 = "bzip2"
    LZMA = "lzma"
    LZMA2 = "lzma2"
    ZSTD = "zstd"
    LZ4 = "lz4"
    BROTLI = "brotli"
    PPMD = "ppmd"
    BCJ = "bcj"
    BCJ2 = "bcj2"
    DELTA = "delta"
    RAR = "rar"
    UNKNOWN = "unknown"

@dataclass(frozen=True)
class CompressionMethod:
    algo: CompressionAlgorithm
    level: int | None = None
    properties: bytes | None = None
```

The enum SHALL be open-ended by appending new members over time. Unrecognized
codec IDs SHALL map to `UNKNOWN` rather than raising. Ordinary RAR M1–M5 SHALL
map to `RAR`, not `UNKNOWN`.

#### Scenario: compression matrix

| Case | Expected |
| --- | --- |
| ZIP member stored with DEFLATE | `(CompressionMethod(algo=CompressionAlgorithm.DEFLATE),)` |
| 7z member uses BCJ2 + LZMA2 | `(CompressionMethod(BCJ2), CompressionMethod(LZMA2))` |
| Compressed RAR member (M1–M5) | `(CompressionMethod(algo=CompressionAlgorithm.RAR, level=<1-5>),)`; `extra["rar.extract_version"]` is the RAR3 `UNP_VER` byte as stored (unvalidated), or `50` for RAR5 |
| Archive contains an unknown codec ID | `CompressionAlgorithm.UNKNOWN`; no exception |
| Single-file `.gz` or `.xz` member | `(CompressionMethod(DEFLATE),)` or `(CompressionMethod(XZ),)`, as a ZIP member compressed the same way (`format-single-file-compressors`) |
