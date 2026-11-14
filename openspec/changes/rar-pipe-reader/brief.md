# rar-pipe-reader — read a RAR archive from a pipe in a streaming pass

**Status:** Ready to implement. Depends on the rolling-volume pull request, 1552. Blocks
nothing. Not breaking. Effort: large.

**Why it matters:** RAR is refused from a pipe or socket today, in both access modes,
while ZIP and TAR read one. Archivey is meant to be one library for every format, and a
pipe is the common case for uploads and downloads.

**What it does:** With RARLAB unrar 7.00 or later, a streaming pass reads a
single-volume RAR front to back. Each member is listed as its header arrives, and one
unrar run decodes everything, fed the archive as rolling volumes with only one volume on
disk at a time.

**Decided:** The forward reader is a subclass picked for a source that cannot seek, as
ZIP does it. The existing header walks become generators, so the seekable path keeps the
same code. Stored members go through unrar too, so there is one data path. unrar gets
one password per pass. For RAR five, the password check values pick from several
candidates. For RAR one-five to four, an encrypted member needs the one password, since
its data has no check value. A member whose output does not line up ends the pass,
because a pipe cannot go back. A RAR five file copy is refused, because its source bytes
were not kept. Volume sets, random access, and reading without unrar 7 stay refused,
each with its own message.

**Your call later:** Whether a stored-only archive should later be read from a pipe
without unrar.

**Bottom line:** A large, self-contained step that goes in after 0.4.0, together with
the rolling-volume pull request.
