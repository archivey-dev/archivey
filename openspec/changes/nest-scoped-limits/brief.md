# nest-scoped-limits — an archive opened inside another shares its limits

**Status:** Ready to implement. Depends on nothing; supersedes the unmerged
budget-argument pull request. Breaking: yes, but only for Budget, which was never
released. Effort: medium.

**Why it matters:** Today an archive that a caller finds inside an upload and opens on
its own gets a fresh set of limits, so the ratio cap multiplies by eight hundred at
every level. Budget tried to fix that with a second, separately scoped pool, and that
scope turned out to be a trap when a config was reused.

**What it does:** The caller opens the inner archive with parent set to the outer
reader. The inner reader then shares the outer one's limits, exactly as the format-level
nesting already does. The config's limits come to mean "per nest" everywhere, and Budget
goes away.

**Decided:** Memory limits, decoder memory and metadata, are shared by the levels open
at the same time. The ratio is measured against the outermost archive, so n levels give
n times the ratio instead of the ratio to the n-th power. Members, key derivation
rounds, spool bytes and a new total of decoded bytes are summed over the whole nest, in
an account the outermost reader owns. Extraction limits stay per extraction call, and
the listing decode cap stays per pass. The link is explicit, so it survives the recipe's
copy to a temporary file and works from any thread. Unrelated archives in one request
get no shared total; the caller bounds that.

**Your call later:** The default for the new total of decoded bytes. The recommendation
is no cap for now, and to measure real uploads before picking one.

**Bottom line:** A medium refactor that leaves one concept instead of two, best done
before 0.4.0 ships Budget.
