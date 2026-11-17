# link-extraction-redesign: remove the link corner-case classes instead of closing cases one by one

**Status:** Design draft, never merged. Three maintainer decisions in `design.md` §6.
Effort: medium (placeholders), small (leaves), small (fuzzer as a test).

**Why it matters:** Each review round on held-back hard links (#1371, #1598, #1616)
closed the cases it named and the next round found more. A random-archive fuzzer still
finds held-versus-made mismatches on #1616's head after four rounds, and every streaming
mismatch has one cause.

**What it does:** A held-back hard link becomes an empty file at its place in archive
order, filled after the pass, so the filesystem answers every later member as it would
for a made link. A member under a symlink that the run created is refused, as bsdtar and
the deb reader do. The fuzzer becomes a standing test.

**Decided:** Nothing yet.

**Your call:** D1 placeholders instead of #1616 and the supersede follow-up. D2 refuse
writes through the run's own symlinks (next minor; differs from GNU tar). D3 streaming
keeps failing a hard link whose source has no written copy.

**Bottom line:** A 40-line prototype of D1 takes held mismatches from 110 in 1,200 runs
on `main` to 1 in 6,400, and lets about 500 lines of simulation go.
