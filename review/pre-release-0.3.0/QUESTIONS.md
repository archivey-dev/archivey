# QUESTIONS — pre-release bug sweep for 0.3.0

Maintainer decisions from [`SUMMARY.md`](SUMMARY.md). One question per item.
The library code is unchanged. F1 and F2 have xfail tests on this branch.

## Q1 — Two newc payloads for one inode (F2)

**Context.** Two newc headers share a device and inode and both store data.
Archivey returns the earlier bytes for both names. 7-Zip 23.01 extracts both
payloads and warns `Headers Error`. The handbook describes one payload, stored
with the last link. The xfail test asks for each header's own bytes.

**Question.** Which result should a read return?

1. Each name returns the bytes stored with that header. This is what the test
   asserts, and what 7-Zip extracts.
2. Raise `CorruptionError`. Neither name returns the other name's bytes.
3. The last payload wins. The earlier name is a hard link, and its own bytes
   are reported as skipped.

Option 1 and option 2 both avoid returning the wrong bytes. Option 3 still
returns the later bytes for the earlier name.

## Q2 — A sized read of a cut member (disagreement)

**Context.** ADR 0014 and `docs/errors-and-diagnostics.md` say
`stream.read(member.size)` may return a short result. The next read raises
`TruncatedError`. `read()` with no size raises on that same cut.

**Question.** Keep the short return, or raise `TruncatedError` from the sized
read that cannot fill the declared size?

I would raise. The docs keep the short return on purpose, so this stays a
question and not a test.

## Q3 — A TRUSTED name made of dots and spaces (suspected)

**Context.** `STRICT` and `STANDARD` refuse a segment of only dots and spaces.
`TRUSTED` keeps it. `check_universal` refuses a segment that is exactly `..`.
On Windows, Win32 strips trailing spaces and dots, so `foo/.. /x` can leave
the destination. On Linux the same name is a literal directory and stays
inside the destination. This host is Linux, so the escape was not reproduced.

**Question.** Should `TRUSTED` refuse a segment of only dots and spaces on
every OS, the way a Windows drive or UNC symlink target is refused on every
OS?
