# pipe-zip-stage-then-commit — stage a pipe ZIP's members, then place them once the directory is read

**Status:** Implemented. The maintainer ratified both open questions as the design recommends. It depends on nothing and blocks nothing. It is breaking for ZIP extraction from a pipe only. Effort: medium.

**Why it matters:** A ZIP read from a pipe learns which members are links, their modes, and which copy of a name is current only at the very end. Today extraction writes every member into the destination as it arrives, then revises it: it turns files into links, takes back members, and moves the caller's own files aside and puts them back. That takes about six hundred lines, and it keeps producing review findings.

**What it does:** During the pass, each selected member's data goes into one private staging folder inside the destination. Once the directory is read, the members are placed by the same code every other extraction uses, each staged file landing by a rename.

**Decided:** The name safety checks still run during the pass, so a hostile or damaged archive is refused early, without decoding the rest of it. The filter runs once per member, at placement, so a filter that selects by a folder name only the directory gives now works from a pipe as from a file. A run that stops before the directory leaves nothing in the destination. Bomb limits count staged files when they are written, and give back those of members that are not placed.

**Decided by the maintainer:** Staged data is ordinary extraction output, bounded by the extraction limits, with no separate budget under the spool limits. Progress reports each member while it is staged, and the counts of extracted and blocked members once, at the end.

**Bottom line:** A simplification that keeps today's early refusals, shipped in 0.2.0.
