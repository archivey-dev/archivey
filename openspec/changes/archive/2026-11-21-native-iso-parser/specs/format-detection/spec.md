## MODIFIED Requirements

### Requirement: Detection never consumes or discards bytes

Bytes inspected during detection MUST remain available to the backend. Wrapping
non-seekable sources is the **opener's** job so one wrapper is shared:

| Source | Behavior |
| --- | --- |
| Path / seekable stream | Peek/read then restore entry `tell()`. Archive begins where the caller positioned. `open_archive` may wrap a mid-file seekable stream in a zero-origin view (`SlicingStream`) so absolute-offset backends (e.g. ISO) see origin 0. |
| Non-seekable | The `ArchiveSource` `open_archive` builds holds a replay prefix; detection and backend receive that **same** object. Detection uses `peek(n)` only, and the backend's reads drain the prefix before reaching the source. |

Standalone `detect_format` is non-consuming for paths/seekable streams. For a raw
non-seekable stream the peeked prefix is lost to the caller unless the caller buffers
it; `open_archive` and `open_stream` keep it in the `ArchiveSource`.

The replay prefix: buffers what detection peeks, `DETECTION_LIMIT` bytes by default
(32774 when ISO triggered, up to 1 MiB for the inner-TAR probe and chain walks, up to
`SFX_MAX` for the self-extracting scan); `.peek(n)` without consume; reads drain the
prefix, then the underlying source.

Every tier that reads from the front SHALL do so through **one detection-owned prefix
workspace** that grows monotonically: extending the window reads only the delta, and
bytes already in the prefix buffer SHALL NOT be fetched again. The trailer read is
outside that buffer. It seeks to its block and restores the handle, and a later tier
that grows the prefix over those bytes fetches them again. A path keeps one detection
handle; a seekable caller stream records its entry position, reads forward, and restores
it in an exception-safe exit; a non-seekable source uses the same replay buffer the
backend will consume.

#### Scenario: non-consuming matrix

| Case | Expected |
| --- | --- |
| Seekable `BinaryIO` at position N | After detect, position is N again; backend can read full archive |
| `open_archive` on non-seekable | One `ArchiveSource` for detect + backend; peeked bytes replay then fall through |
| Standalone detect on raw non-seekable the caller will reread | Caller must buffer the stream itself |

#### Scenario: the workspace reads each byte once

| Case | Expected |
| --- | --- |
| Near magic then far magic on a seekable stream | 32 774 bytes fetched once, not 4 096 then 32 774 from zero |
| Five tiers peeking the same 30-byte head | One fetch, four buffer reads |
| Cued scan growing 64 KiB → 256 KiB → 1 MiB → 2 MiB | 2 MiB of unique source I/O, not 3.31 MiB of overlapping reads |
