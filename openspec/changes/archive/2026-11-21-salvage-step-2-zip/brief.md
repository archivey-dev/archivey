# salvage-step-2-zip — a ZIP pipe goes past a damaged local signature

**Status:** Implemented (2026-11-21). Ruled by the maintainer on 2026-11-07 (ZIP from a
pipe follows a damaged header's size, confirmed by the next ZIP signature and the
central directory at the end) and 2026-11-21 (the 4 MiB pipe limit, shared with RAR and
TAR). Target: 0.6.0 (`needs-minor`). Effort: small.

**What it does:** a ZIP read from a pipe walks its local headers. When the four bytes
where the next one should start are not a ZIP signature but the other 26 bytes are a
valid local header that names its sizes (bit 3 clear), the walk follows those sizes. It
goes on when the bytes where the member's data ends are a ZIP signature that may follow
a member, no more than 4 MiB ahead. The member is listed, and its read fails with
`Bad magic number for file header`, exactly as a read from a file fails on the same
header (`unzip`: "bad zipfile offset (local header sig)"; 7-Zip: "Headers Error"). The
members after it are walked as usual, and the central directory at the end checks
every one.

**What was there before:** the walk stopped, kept the rest of the stream (up to the
listing limits' bound, about 76 MiB by default), and read the members after the damage
from it at the directory's offsets; the damaged member then ended the pass in
`CorruptionError` ("the stream held no local header"), where a file read only fails
that member. So the change makes the pipe list and fail exactly as the file does, and
removes the bound on how much of the stream after the damage a pipe can reach.

**No `MEMBER_HEADER_DAMAGED`:** the member's read fails, as from a file, so there is
nothing to flag. Only the signature is followed: a local header has no checksum, so any
other damage is not detectable there and was already handled by the directory
(`MEMBER_LOCAL_NAME_DIFFERS` and the other local/directory checks).

**Not followed:** a bit-3 member (its sizes are in the descriptor after its data), a
header whose other fields fail the detector's local-header checks, a damaged header
right at the start of the stream (the stub scan handles that), or one whose data is
longer than 4 MiB.
