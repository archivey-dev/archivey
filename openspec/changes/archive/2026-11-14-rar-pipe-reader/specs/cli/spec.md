## MODIFIED Requirements

### Requirement: read-once paths open in streaming mode

When the archive path is a pipe (FIFO), a character device or a socket, which can be
read only once, every verb that opens the archive (`list`, `test`, `extract`, `info`)
SHALL open it in streaming mode, because the user has no option to choose the mode.
`list` SHALL list the members in one pass, `test` SHALL verify them in one pass and
`extract` SHALL extract them in one pass; TAR, ZIP, the single-file formats, and RAR
with RARLAB `unrar` 7.00 or later read so. When the format cannot be read in one
forward pass (7z, ISO), the verb SHALL exit `1` with a message that names the format by
its file extension (`7z`, `iso`) and tells the user to copy the input to a regular file
first. So SHALL a RAR when no RARLAB `unrar` 7.00 or later is found. The message MUST
NOT suggest `streaming=True` or a `BytesIO`, which a CLI user cannot pass. A block
device rereads the same bytes and opens as a regular file does.

A read-once path includes `/dev/stdin` and `/proc/self/fd/N` when that descriptor is a
pipe, so an archive piped on stdin is read through this requirement. The `-` token is
separate: `cat` reads it from stdin, and every other verb refuses it (below).

#### Scenario: read-once paths

| Case | Expected |
| --- | --- |
| `archivey list <tar-fifo>` (also `<zip-fifo>`) | Lists every member; exit `0` |
| `archivey test <tar-fifo>` (also `<zip-fifo>`) | Verifies every file member in one pass; exit `0` |
| `archivey extract <tar-fifo> -d out` (also `<zip-fifo>`) | Extracts every member into `out`; exit `0` |
| `archivey info <tar-fifo>` | Prints the identity and an `access:` line that says the source is forward-only; exit `0` |
| `archivey list <7z-fifo>` (also `test`, `extract`, `info`; also ISO) | Exit `1`; message names the format as `7z` (`iso`) and says to copy the input to a regular file first |
| `archivey list <rar-fifo>` with RARLAB `unrar` 7.00 or later | Lists every member; exit `0` |
| `archivey list <rar-fifo>` without it | Exit `1`; message names the format as `rar` and says to copy the input to a regular file first |
| `cat a.tar \| archivey list /dev/stdin` | Lists every member; exit `0` |
