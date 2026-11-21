# Design — salvage step 2 (TAR)

## Decisions

1. **Follow, then confirm** (maintainer, 2026-11-07). The damaged header is parsed with
   its checksum field set to the sum its bytes hold, so every other check runs as for an
   intact header. The walk takes the member's chain as usual (PAX `size` included) and
   checks the block where the next header starts.
2. **What confirms.** A header that passes its checksum and has the `ustar` magic. A
   checksum alone is a byte sum that a random block passes about once in 2¹⁷; the magic
   adds 48 bits. The end-of-archive marker confirms only when the archive holds nothing
   but zeros from there to its end, read no further than 1 MiB (the RAR trailing scan),
   because zero blocks are common inside member data.
3. **The damaged header needs the magic too.** Found while implementing: member data
   where a header was expected (after a directory that declares a size) fails its
   checksum, and its NUL numeric fields parse as zeros. A v7 archive is therefore never
   followed. A damaged magic byte stops the walk as today.
4. **Runs.** Up to 8 damaged headers in a row, as RAR. Looking ahead past a damaged
   member header that is followed by another damaged header uses that header alone (a
   regular file's size, or no data for a directory or link with no size); its chain is
   followed again when the walk reaches it.
5. **Any failure inside a damaged chain** (an error, a block that does not confirm, an
   end) stops the walk at the chain's first damaged header with today's reason: nothing
   the unconfirmed size framed is trusted.
6. **Pipes** (maintainer, 2026-11-21, shared with RAR): the walk reads the damaged
   member's data and the block after it ahead, at most 4 MiB before that block, and
   replays them, so the member's data stays readable in the pass. A random-access walk
   seeks.
7. **No member checksum.** TAR has none, so the read of the damaged member checks
   nothing more; the message says the size was confirmed by the next header.

## Not done

- GNU tar's block scan (salvage mode, 0.7.0). The DR-6 departure is the maintainer's
  ruling.
