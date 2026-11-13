# nest-scoped-limits — an archive opened inside another counts toward its upload's totals

**Status:** Design revised after review round 1; waiting on the maintainer's go. Depends
on nothing; supersedes the budget-argument commits on the same pull request. Breaking:
yes, but only for Budget, which was never released. Effort: medium.

**Why it matters:** Today an archive that a caller finds inside an upload and opens on
its own gets a fresh set of limits, so the ratio cap multiplies by eight hundred at
every level. Budget tried to fix that with a second, separately scoped pool, and that
scope turned out to be a trap when a config was reused. It also did nothing for the
ratio.

**What it does:** The caller opens the inner archive with parent set to the outer
reader, open or already closed. The inner reader keeps every limit it would have on its
own. On top, the whole nest is held to three totals from the outermost config: members,
the ratio against the upload's size, and an optional cap on decoded bytes. Budget goes
away.

**Decided:** Linking never weakens a limit. Memory limits stay per reader for
caller-opened archives; format-level nesting keeps its sharing because its levels run
at once. Extraction limits stay per call, and the listing decode cap per pass. Unrelated
archives in one request get no shared total; the caller bounds that.

**Your call later:** The name and default of the decoded-byte cap (recommended: a name
that says "nest", no cap by default), and whether to infer the parent from a member
stream later.

**Bottom line:** A medium refactor that leaves one concept instead of two and closes the
ratio compounding, best done before 0.4.0 ships Budget.
