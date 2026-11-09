# 12. Non-obvious choices

**In one minute.** A list of things that look wrong, over-built or inconsistent until you
know the reason. Each answer is short and links to where the reason is recorded. If you
are about to "simplify" one of these, read the link first: most of them were the simple
version once.

## Reading

**Why does random access refuse a pipe instead of buffering it?**
Buffering a pipe means holding the whole archive in memory or on disk without the caller
asking. archivey fails at open and the caller picks `streaming=True` or a seekable source
(ADR [0010](../decisions/0010-no-silent-buffer-nonseekable.md),
[page 7](07-pipes-and-files.md)).

**Why does `streaming=True` refuse an out-of-order read on ZIP, which could serve it?**
So the mistake shows on the first archive tested. A program written against ZIP would
otherwise fail later on TAR or 7z, where an out-of-order read is impossible
([DR-5](../design-rules.md#dr-5-same-input-same-outcome), ruling of 2026-09-29).

**Why are member streams not seekable by default?**
Seeking is cheap in some formats and means re-decoding from the start in others. An
always-seekable API lets a developer test on ZIP and ship a slow or failing path on TAR
(ADR [0003](../decisions/0003-member-streams-opt-in.md)). `seekable_members=True` asks for
it, and then it works on every format.

**Why does `stream_members()` never seek, even on a seekable file?**
The integrity guarantee is for a read from start to end with no seek
([DR-4a](../design-rules.md#dr-4a-the-integrity-guarantee-is-for-a-start-to-end-read)). A
pass that seeks would trust the index for where data is, and a crafted index can lie
([page 7](07-pipes-and-files.md)).

**Why is there no `len(reader)` and no `reader[name]`?**
The number of members in a TAR is unknown until it has been read to the end, and a pipe
can only be read once. `get(name)` exists instead and returns the **last** member with
that name, which is what extraction leaves on disk when names repeat
([page 4](04-readers-and-members.md)).

**Why does `get()` find a member before a damaged point and only then raise?**
A listing cut short by damage still holds the members before the cut. `get()` returns one
of those if it matches, and raises the listing error only when the name is not among
them ([DR-2](../design-rules.md#dr-2-deliver-everything-recoverable-then-raise)).

**Why are `ArchiveMember` objects mutable?**
Some facts arrive after the member is yielded: a size and CRC from a data descriptor
after the data, a symlink target stored as data, and, for a ZIP from a pipe, modes and
link types from the central directory at the end. A streaming pass cannot hand back a new
object, so the member is updated in place, and `member_state_final` says whether more can
change
(ADR [0007](../decisions/0007-mutable-archive-member.md),
[page 4](04-readers-and-members.md#mutable-members-filled-in-place)).

**Why does a symlink in a ZIP or 7z get its target read even if I never asked for it?**
`read_link_targets=True` is the default because a field filled on some formats and empty
on others "is a recipe for bugs" (maintainer, 2026-09-23,
[DR-8](../design-rules.md#dr-8-defaults-are-complete-and-consistent-laziness-is-an-explicit-opt-in)).
Turning it off is an explicit opt-in.

**Why does opening a `.gz` decode a byte?**
To fail at open on a stream that is not really gzip, rather than on the first read in
some later function. It is the cheap check that
[DR-15b](../design-rules.md#dr-15b-fail-at-open-but-do-no-expensive-work-there) allows
([page 3](03-life-of-an-open.md)).

**Why does the read that finds a bad CRC hold back the last chunk?**
So a caller that reads in a loop never receives the final bytes of a member that failed
its check without also getting the error. The error comes from that read, never first
from `close()`
(ADR [0014](../decisions/0014-integrity-verdicts-from-reads-not-close.md),
[page 9](09-errors-and-diagnostics.md#when-an-error-is-raised-adr-0014)).

**Why does a read sometimes ask for one byte past the member's end?**
To catch a stream that has more data than the header said, which could hide content
([DR-3](../design-rules.md#dr-3-hidden-bytes-are-errors-inside-a-member-warnings-outside-it)).
A format reader that promises `bounded=True` lets archivey skip it
([page 5](05-formats-and-plugins.md#what-archivey-does-with-a-member-the-promises-in-memberdata)).

**Why does a refused second `open()` run the garbage collector?**
A stream the caller dropped but the collector has not freed would otherwise block the next
call, depending on the interpreter and on timing. The collect makes the outcome the same
everywhere (maintainer, 2026-10-20, PR 915,
[DR-5](../design-rules.md#dr-5-same-input-same-outcome)).

## Names and types

**Why are `..` and a leading `/` kept in `member.name`?**
The name says what the archive says, cleaned of separators and other spellings, but not
made safe. Safety is extraction's job: an absolute name is re-rooted inside the
destination and `..` is refused there
([page 1](01-vocabulary.md), [page 8](08-security.md)). A listing that hid them would
misreport the archive.

**Why does a valid UTF-8 name ignore `encoding=`?**
Self-validating data beats a caller hint: `encoding=` fills only the gap the archive
leaves ([DR-7](../design-rules.md#dr-7-trust-self-validating-data-over-caller-hints)). A
wrong `encoding=` cannot then break names that were fine.

**Why is a FIFO or device entry `OTHER`, when `unzip` writes an empty file?**
An empty file in place of a device is useless to a caller, so consistency across formats
won over the tools (2026-10-06,
[§When consistency and the official tool disagree](../design-rules.md#when-consistency-and-the-official-tool-disagree)).
An entry marked FIFO that carries data is a `FILE`, because its bytes are the content.

**Why is `created` sometimes `None` when the archive has a ctime?**
`created` is birth time only. A Unix ctime is the time of the last metadata change, so it
goes to `ArchiveMember.ctime` instead (PR 470,
[DR-5](../design-rules.md#dr-5-same-input-same-outcome)).

**Why do hard links resolve only to earlier members?**
That is what `unrar` and GNU `tar` do, and it settled a crafted quadratic shape with a
simpler rule than more bookkeeping (PR 532,
[DR-6](../design-rules.md#dr-6-when-the-semantics-are-open-match-the-formats-official-tool)).

**Why is a file of zeros an empty TAR instead of "not an archive"?**
`tar -b 64` writes exactly that. archivey reads it as an empty archive and reports what it
saw (ADR [0015](../decisions/0015-zero-filled-files-are-valid-empty-tars.md)).

## Errors and limits

**Why is `ArchiveyUsageError` not an `ArchiveyError`?**
So `except ArchiveyError:` around untrusted input never hides a bug in the calling program
(ADR [0012](../decisions/0012-usage-errors-outside-archiveyerror.md)).

**Why doesn't archivey wrap unknown exceptions in `CorruptionError`?**
Calling an unknown bug "your archive is corrupt" is a wrong answer. Each backend and codec
translates the exceptions it understands, and anything else propagates unchanged
([DR-15a](../design-rules.md#dr-15a-translate-archive-problems-let-io-problems-through)).

**Why is `max_ratio` 800 and not a round 1000?**
A gzip of zeros compresses at about 1003 to 1032:1. At 1000 it was refused only by chance;
at 800 it is refused every time, like zeros in every other codec (2026-10-30,
[page 10](10-decisions.md#every-cost-has-a-public-limit)).

**Why does the ratio check behave differently on a pipe?**
On a pipe the total size is unknown, so the check waits for 256 MiB of output before it
judges the archive as a whole; otherwise an honest archive that starts with a long blank
run is refused (PR 775,
[page 11](11-bugs-and-lessons.md#a-ratio-check-that-judged-a-pipe-too-early)).

**Why are diagnostics data instead of warnings?**
A log line cannot be acted on and a warning filter is process-wide. A `Diagnostic` has a
stable code a caller can test, count, ignore or raise on per call with `DiagnosticPolicy`
([page 9](09-errors-and-diagnostics.md#diagnostics)).

## Speed and processes

**Why does every PPMd member start a child process, even a 1 KB one?**
pyppmd can crash the interpreter, and the call order that avoided it was safe only by
measurement. The child costs about 75 ms and keeps the process alive
(ADR [0022](../decisions/0022-ppmd-always-in-a-child-process.md)).

**Why does rapidgzip only kick in from 16 MiB under `AUTO`?**
It runs in a child process that costs about 45 ms to start and saves about 3.4 ms per MB
of compressed input, so it breaks even near 13 MB. Below that the standard library is
faster (`RAPIDGZIP_AUTO_MIN_COMPRESSED_SIZE` in `config.py`).

**Why doesn't archivey use `multiprocessing` for its children?**
Its spawn mode re-imports the caller's `__main__` and reports neither stderr nor the exit
status. Each child is a plain subprocess running a small worker script (ADR 0022).

**Why does reading one RAR member from a stream build a small fake RAR archive?**
`unrar` reads only files. Before synthetic archives, the first read from a stream copied
the whole archive to disk: 1,350 ms for a 1.2 KB member of a 200 MiB archive, against
7 ms from a path. Now archivey writes a temp file holding only that member's header (its
name replaced by `m0`), its packed bytes and an end header; a solid member also needs
the members before it in its solid stream. `unrar` never sees the real names
([page 7](07-pipes-and-files.md)).

**Why does detection from a pipe hold up to 2 MiB?**
A self-extracting archive has a program stub before the archive, and finding the archive
behind it means scanning ahead. The scanned bytes are replayed to the reader, so nothing
is lost ([page 7](07-pipes-and-files.md)).

## Plugins

**Why can a plugin not claim `.zip` or win over a built-in magic number?**
Registering a plugin must never change the answer for a file a built-in format already
reads. Plugin magic counts only when no built-in signature matched
([page 5](05-formats-and-plugins.md#plugins-from-outside)).

**Why do ISO, CPIO and ar use the "plugin" interface though they are built in?**
To keep that interface honest: if something is missing from it, a built-in format notices
first ([page 5](05-formats-and-plugins.md#why-some-built-in-formats-use-the-public-interface)).
