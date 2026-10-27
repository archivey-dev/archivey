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
start-offset / SFX rules (`format-rar`, `format-7z`). A backend that scans the start of the
source for its payload under those rules SHALL derive the payload end from the same bytes
with the PE layout helper detection uses, so forced `format=` and auto-detect see the same
end.

#### Scenario: payload_offset hand-off

| Case | Expected |
| --- | --- |
| Auto-detect SFX RAR/7z/ZIP with `payload_offset == N` | Backend opens via start-offset arg or offset view; real members listed |
| `payload_offset == 0` | Unchanged open-at-current-position behaviour |
| Explicit `format=` | Detection skipped; backend SFX/start-offset rules apply |
| Bare seek only (no start-offset / no offset view) | Insufficient for 7z; MUST NOT be the sole hand-off mechanism |
| Auto-detect, signed PE SFX, `payload_end == E` | Backend reads nothing at or past `E`; the certificate raises no `ARCHIVE_TRAILING_DATA` |
| Forced `format=` on the same signed SFX | The backend's own scan derives the same `E`; same listing, same diagnostics |
| No `payload_end` (unsigned, non-PE, non-seekable) | Unchanged: the archive is read to the end of the source |
