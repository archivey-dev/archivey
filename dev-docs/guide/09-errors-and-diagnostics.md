# 9. Errors, diagnostics and verification

**In one minute.** Archivey reports trouble in three ways. An **exception** stops the
operation: the archive is damaged, encrypted with the wrong password, needs a missing
package, or hit a limit. Every archive problem is an `ArchiveyError`, reached by
*translating* the library's own exception; an I/O failure stays an `OSError`; a caller's
mistake is `ArchiveyUsageError`, which is deliberately *not* an `ArchiveyError`. A
**diagnostic** is something unusual that did not stop anything ("data after the end of the
archive", "this name was renamed"), recorded as data with a stable code; the caller's
`DiagnosticPolicy` can turn any code into an exception. A **verification level** on each
member says how much has been proved intact so far. All three are designed around one
fear: handing the caller a wrong answer without saying so.

## Exceptions

### The tree (`exceptions.py`)

```
Exception
├── ArchiveyError                       archive, environment and format problems
│   ├── OpenError                       reading never started
│   │   ├── FormatDetectionError
│   │   └── StreamNotSeekableError
│   ├── ReadError                       the archive's data is bad or unreadable
│   │   ├── CorruptionError
│   │   │   └── TruncatedError
│   │   ├── EncryptionError
│   │   ├── LinkTargetNotFoundError
│   │   └── SourceChangedError
│   ├── ExtractionError                 writing a member to disk failed
│   │   ├── FilterRejectionError
│   │   ├── NameCollisionError
│   │   └── NameRewrittenError
│   ├── ResourceLimitError              a limit was reached
│   │   └── ResourceUnavailableError    the machine ran out (memory, descriptors, no child)
│   ├── UnsupportedFeatureError         valid, but archivey cannot read it
│   ├── PackageNotInstalledError
│   └── DiagnosticRaisedError           a diagnostic the policy raises on
└── ArchiveyUsageError                  the caller used the API wrongly (outside the tree)
    ├── _UsageTypeError    (also a TypeError)
    └── _UsageValueError   (also a ValueError)
```

The groups follow the *cause*, not the call that hit it. A type exists only when a
caller would act on it differently from its parent
([DR-13](../design-rules.md#dr-13-a-public-name-earns-its-place)); finer detail goes in
the message and in attributes (`archive_name`, `member_name`, `source_format`).

### Why `ArchiveyUsageError` is outside the tree (ADR 0012)

A program that processes untrusted archives writes `except ArchiveyError:` around the
work, to skip bad archives. If a bug in that program, such as passing an `int` where a
member is expected, also raised an `ArchiveyError`, the `except` would hide the bug as "bad
archive". So misuse has its own root (ADR
[0012](../decisions/0012-usage-errors-outside-archiveyerror.md)). A wrong argument raises a
private subclass that is also a `TypeError` or `ValueError`, so code that already catches
those keeps working ([DR-15](../design-rules.md#dr-15-usage-errors-are-for-what-the-types-cannot-rule-out)).

### Translation, not catch-alls

Code inside archivey calls libraries (zlib, lzma, pyppmd, pycdlib, the `cryptography`
package) whose exceptions mean different things: `zlib.error`, `lzma.LZMAError`,
`EOFError`, `ValueError` with a message. Each backend and each codec has a
**translator**: a function that gets the raw exception and returns the right
`ArchiveyError`, or `None` to let it propagate unchanged. The public stream
(`ArchiveStreamImpl`) and the reader route everything through the translator and then
*stamp* the result with the format, archive and member names.

There is no "catch everything and raise `CorruptionError`". An exception nobody
recognized propagates as it is, because turning an unknown bug into "your archive is
corrupt" is a wrong answer. `OSError`, `KeyboardInterrupt` and `MemoryError` pass through
([DR-15a](../design-rules.md#dr-15a-translate-archive-problems-let-io-problems-through)).
Where a blind `except Exception` is really needed (cleanup, combining two errors, a
finalizer), it takes one of seven shapes listed on the
[exception handlers](../topics/exception-handlers.md) topic page.

Two small rules worth knowing:

- **Errors survive `pickle`.** An error raised in a child process reaches the parent whole.
- **A stored error is raised as a copy.** Raising the same exception instance twice
  attaches a new traceback to it each time and can keep large objects alive through a
  reference cycle ([page 11](11-bugs-and-lessons.md#a-stored-exception-kept-a-child-process-alive)).

### When an error is raised (ADR 0014)

- **At open**, for problems that are cheap to find: the format, a missing package, a
  damaged header at the front, an encrypted index with no working password. Nothing
  proportional to the archive's size runs at open
  ([DR-15b](../design-rules.md#dr-15b-fail-at-open-but-do-no-expensive-work-there)).
- **On the read that finds the problem**, for content: a checksum mismatch raises on the
  read that reaches the end, and the last chunk is withheld; a cut member returns what
  exists, and the next read raises `TruncatedError`. This lets `read(n)` loops salvage the
  intact prefix of a damaged member.
- **Never first in `close()`.** A program that does `data = f.read(); f.close()` must have
  seen the verdict already, and a `with` block must not turn a clean exit into an
  exception (ADR [0014](../decisions/0014-integrity-verdicts-from-reads-not-close.md)).

On damage in the middle of an archive, every intact member is delivered first and the
error is raised at the point of damage
([DR-2](../design-rules.md#dr-2-deliver-everything-recoverable-then-raise)). A listing cut
short keeps the members before the cut (`members_report()` returns them with the error).

## Diagnostics

### What they are for

Many things in real archives are odd but not fatal: zero padding after the end, a name
stored with Windows separators, a timestamp out of range, a password passed for a format
with no encryption, a member listed twice. A library can raise (too strict: real archives
fail), log (too weak: nobody can act on a log line), or record it as data. Archivey records
it: a `Diagnostic` with a `DiagnosticCode`, a message, and a typed `context` dataclass with
the details (`diagnostics.py`). There are about 40 codes.

A caller can:

- read them after the fact: `reader.diagnostics`, `stream.diagnostics`, the extraction
  report, and the diagnostics attached to each member;
- get a callback as they happen (`ArchiveyConfig.on_diagnostic`);
- choose per code with `DiagnosticPolicy(ignore=..., raise_on=...)`. `DiagnosticPolicy.STRICT`
  raises on the codes about the archive's own bytes (`ARCHIVE_INTEGRITY_CODES`, about 20).
  `PEDANTIC` raises on every code.

The policy is how "is this damage or just unusual?" stops being archivey's decision alone.
Archivey's default reads the archive and reports. A caller who wants to refuse anything
unusual says so in one line.

### Where to put a new check

[DR-3](../design-rules.md#dr-3-hidden-bytes-are-errors-inside-a-member-warnings-outside-it)
settles the most common case: leftover bytes *inside* a member's data are corruption
(they could hide content); bytes *outside* any member are a diagnostic. Unsupported
features are not corruption ([DR-4](../design-rules.md#dr-4-unsupported-is-not-corrupt)).
Data nobody can check (no checksum in the format) is not a breach: it gets
`DIGEST_UNVERIFIABLE` where a check would be expected, and formats that never carry one
are documented once rather than flagged on every member.

### How they are kept bounded (`internal/diagnostics_collector.py`)

A hostile archive can produce a diagnostic per member, and there can be 262,144 members.
The collector keeps **exact counts** per code in a small counter, but **retains** only a
bounded number of `Diagnostic` objects (`max_retained_diagnostic_references`). A snapshot
for one operation, such as one member stream or one extraction, comes from a scope that
operation holds, not from copying the global list. So memory does not grow with the
number of diagnostics, and counts stay exact.

Deduplication is a quieter problem. A member can be seen more than once (by a peek, by a
listing, by a pass), and its diagnostic must be attached once. The rule that worked:
emit where the question is settled (when the member is typed) and dedupe on the member's
position in the listing ([page 11](11-bugs-and-lessons.md#diagnostics-attached-to-the-wrong-member-objects)).

### Logging

Each diagnostic is also logged, at WARNING by default, on the `archivey.*` logger tree
(`internal/logs.py` names every logger). An ignored code is counted but not logged. Some
access-pattern codes log at INFO because the caller may have chosen the pattern on
purpose: `SOLID_OPEN_REDECOMPRESSES`, `STREAM_REWIND_REDECOMPRESSES`.

## Verification levels

Every member has two fields (`types.py`, `Verification`):

- `verified`: the most any read has proved so far;
- `verifiable`: the most a read from the start to the end *can* prove.

The levels, from weakest: `NONE` (encrypted, password not confirmed), `UNLOCKED` (not
encrypted, or the password passed a check a wrong one cannot pass by chance), `LENGTH`
(a read reached the end and every length and end check passed), `CHECKSUM` (every byte
passed a check that a wrong byte fails). A checksum counts whichever layer holds it: the
member's CRC-32, a codec's own check (gzip, xz, zstd frames), the WinZip AES authentication
code, a 7z folder CRC covering several members. Header checksums never count.

`stream.verify()` reads one stream until it reaches `verifiable`; `reader.verify_all()`
does that for every member and returns the failures without stopping at the first. The
rule is "under-report, never over-report": a level is never claimed for a check that did
not run. The levels are experimental API. The [verification](../topics/verification.md)
topic page has every rule, including what seeks and multi-member checks do.

## A worked example: one damaged ZIP

A ZIP member whose CRC-32 does not match:

1. `open_archive` succeeds: the central directory is intact.
2. `reader.open(member)` succeeds: the member's local header is intact.
3. `f.read(4096)` in a loop returns bytes normally.
4. The read that reaches the member's end: the verifier compares CRCs, they differ, and
   it raises a `CorruptionError` stamped with the archive and member names, withholding
   that last chunk.
5. `member.verified` stays below `CHECKSUM`.
6. `extract_all()` on the same archive writes the member to a temporary name, the same
   error is raised during the write, and the temporary file is discarded, so nothing
   half-written appears under the real name. Under the default `OnError.STOP` the error
   propagates and extraction stops there, after every earlier member was written. Under
   `OnError.CONTINUE` the member's result is `FAILED` and extraction goes on.
