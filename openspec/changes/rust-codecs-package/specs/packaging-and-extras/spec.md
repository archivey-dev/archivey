## ADDED Requirements

### Requirement: archivey-codecs is an optional accelerator with a Python fallback

archivey SHALL NOT require `archivey-codecs`. The `[codecs]` extra SHALL depend on it
only where it publishes wheels (CPython on Linux, macOS and Windows), so that no install
builds it from source. archivey SHALL use a kernel only when the installed package
reports it in `KERNELS` at a revision at or above the one archivey needs, and SHALL
otherwise use its Python decoder, logging the fallback once at DEBUG. Results, error
types and messages SHALL be the same with and without the package.
`OptionalLibrary.ARCHIVEY_CODECS` in `FormatPolicy.exclude_libraries` SHALL turn every
kernel off for that call, and the environment variable `ARCHIVEY_CODECS=0` SHALL turn
them off for the process. Kernels SHALL run in-process whatever `ProcessIsolation` says.
The `archivey-cli` distribution SHALL depend on `archivey[codecs]`.

#### Scenario: accelerator selection

| Case | Expected |
| --- | --- |
| Package absent | Python decoders; nothing reported |
| Package present, `KERNELS["lzx"]` at or above the needed revision | Rust LZX |
| Package present, `KERNELS["lzw"]` below the needed revision | Python LZW; other kernels still Rust |
| Package present, kernel missing from `KERNELS` | Python decoder for that kernel |
| `exclude_libraries={OptionalLibrary.ARCHIVEY_CODECS}` | Python decoders for that call only |
| `pip install archivey[codecs]` on PyPy | archivey installs; `archivey-codecs` is not requested |
| `pip install archivey-cli` on CPython for Linux | `archivey-codecs` installed from a wheel |
| A damaged CAB read with and without the package | Same bytes before the error; same error type and message |
