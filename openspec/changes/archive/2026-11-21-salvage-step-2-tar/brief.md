# salvage-step-2-tar — list every TAR member past a damaged header

**Status:** Implemented (2026-11-21). Ruled by the maintainer on 2026-11-07 ("for
consistency with the rar behavior": TAR and ZIP follow the damaged header's size,
confirmed), on 2026-11-20 (salvage plan, step 2 in the default mode) and on 2026-11-21
(the pipe limit, shared with RAR). Target: 0.6.0 (`needs-minor`). Effort: small.

**Why it matters:** one TAR header that fails its checksum ends the listing today, and
every member after it is lost. A flipped byte in the name of the third of five members
lists two.

**What it does:**

- **The walk follows the damaged header's size.** A header that fails its checksum, and
  whose other fields parse and that has the `ustar` magic, is read from those fields.
  The walk goes on from where its size points when the block there confirms it: a
  header that passes its checksum and has the `ustar` magic, or the end-of-archive
  marker with only zeros after it to the end of the archive. Up to 8 damaged headers in
  a row are followed, the last confirmed by the block after it. Otherwise the walk stops
  at the damaged header, as today. Nothing searches the bytes.
- **The damaged member is listed, flagged**, with `MEMBER_HEADER_DAMAGED` on every read,
  as for RAR. A TAR member has no checksum of its own: the header its size points at is
  what vouches for its size, and nothing checks its name, type, mode, owner or times.
- **The pass still ends in `CorruptionError`**, after every member.
- **From a pipe:** the same, while the damaged member's data fits in the 4 MiB a pipe
  holds (the RAR limit); past that, the walk stops at the damage and the error says to
  save the archive to a file.

**A deliberate DR-6 departure:** GNU tar scans block by block for the next header that
passes its checksum ("Skipping to next header"), and does not list the damaged member.
That scan is salvage mode's (0.7.0), not the default's (maintainer, 2026-11-07).

**Found while implementing:** a block of member data where a header was expected (a
directory that declares a size, say) fails its checksum too, and its empty numeric
fields parse as zeros. Requiring the `ustar` magic on the damaged header keeps the walk
from listing such a block. So a v7 archive, which has no magic, is never followed.
