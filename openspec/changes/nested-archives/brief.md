# nested-archives: read an archive stored inside another one, as members of the outer one

**Status:** Implemented in the pull request that adds it. Depends on nothing. Not breaking: two new names in `archivey.formats`. Effort: small.

**Why it matters:** A `.deb` is an `ar` archive whose real content sits in `data.tar.xz` and `control.tar.xz`. ipk packages and XAR payloads have the same shape. A format reader needs a way to hand those inner archives to archivey's own TAR reader and list their files as its own, with the caller's limits and diagnostics.

**What it does:** `ForwardStream.take(n)` gives a walk the next `n` bytes as a stream, read forward. `ReaderContext.open_nested(stream, format)` reads that stream with archivey's reader for the inner format and yields its members as spans the walk can rename and yield. The inner reader shares the outer one's diagnostics, numbers its reports as the outer listing numbers members, and leaves the name checks to the outer listing.

**Decided:** A public hook in the format API, not internal plumbing for deb alone (maintainer, 2026-11-07, decision card Q9). Inner formats are read in one forward pass; one that needs a seekable source is refused.

**Your call later:** Whether a later version lets an indexed inner format (ZIP with random access, 7z) be read from a seekable outer source.

**Bottom line:** A small hook that deb uses first, and other package formats later.
