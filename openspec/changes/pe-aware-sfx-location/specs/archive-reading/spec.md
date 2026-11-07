## MODIFIED Requirements

### Requirement: Honour detection payload_offset at open

When `detect_format` returns `payload_offset > 0`, `open_archive` (auto-detect
path) SHALL open the archive at that byte offset by either (a) passing an
explicit start-offset argument into `backend.open_read`, or (b) handing the
backend a bounded offset view / slice whose byte 0 *is* the payload. A bare
`seek` on a shared handle is **not** sufficient: backends that perform absolute
seeks (notably 7z’s `read_signature_and_next_header`, which `seek(0)`s then
seeks to `_SIGNATURE_HEADER_SIZE + next_header_offset`) discard caller
positioning. The system SHALL NOT copy the remainder of the source to a
temporary file solely to strip an SFX stub.

When detection also reports `payload_end` (`format-detection`: the start of a PE's
Authenticode certificate table), `open_archive` SHALL pass it the same way, and the
backend SHALL behave as if handed a view of `[payload_offset, payload_end)`: it reads
nothing at or past the end and treats the bytes there as identified, not as part of the
archive or data after it. A backend SHALL NOT read before its start offset to find an end
for itself. A backend that hands the file to an external program (`unrar`) applies the end
to its own checks only.

An explicit `format=` that bypasses detection retains each backend’s own
start-offset / SFX rules (`format-rar`, `format-7z`). For a backend whose format can carry
a stub (RAR, 7z, ZIP), on a seekable single-file source, `open_archive` SHALL read the
source's first 4096 bytes and, when they are a PE whose layout parses, SHALL pass the
payload end derived from them with the PE layout helper detection uses. Detection reads
the layout from the same 4096 bytes whatever `max_prefix_bytes` says. So a forced
`format=` and auto-detect open the same region and list the same members: what an archive
holds SHALL NOT depend on whether its format was named. No backend derives an end itself.
A non-seekable source gets no end either way, since its size is unknown and the table
cannot be placed.

#### Scenario: payload_offset hand-off

| Case | Expected |
| --- | --- |
| Auto-detect SFX RAR/7z/ZIP with `payload_offset == N` | Backend opens via start-offset arg or offset view; real members listed |
| `payload_offset == 0` | Unchanged open-at-current-position behaviour |
| Explicit `format=` | Detection skipped; backend SFX/start-offset rules apply |
| Bare seek only (no start-offset / no offset view) | Insufficient for 7z; MUST NOT be the sole hand-off mechanism |
| Auto-detect, signed PE SFX, `payload_end == E` | Backend reads nothing at or past `E`; the certificate raises no `ARCHIVE_TRAILING_DATA` |
| Forced `format=` on the same signed SFX (RAR, 7z, or ZIP from a seekable source) | `open_archive` passes the same `E`, read from the same headers; same listing, same diagnostics |
| Auto-detect with `max_prefix_bytes` below 4096 | Detection still reads the layout from the first 4096 bytes and reports the same `E` |
| The same SFX from a non-seekable stream, auto-detect or forced | No `E`: the certificate is reported as trailing data, the same both ways |
| Forced `format=ZIP` on the IRPF installer under `DiagnosticPolicy.STRICT` | Opens, as auto-detect does: the certificate is past `E` |
| Forced `format=ZIP` on a signed SFX whose certificate holds a second whole ZIP, its offsets counted from its own start or from the start of the file | The archive before `E` is listed, as auto-detect lists it; the ZIP inside the certificate is not |
| No `payload_end` (unsigned, non-PE, or total size unknown) | Unchanged: the archive is read to the end of the source |
