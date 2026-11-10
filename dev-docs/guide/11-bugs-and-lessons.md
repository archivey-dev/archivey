# 11. Bugs that taught us something

**In one minute.** Most bugs are fixed and forgotten. These are the ones that changed how
archivey is built, or left a rule that later code follows. Each entry says what went
wrong, why, what fixed it, and the lesson. Live defects are not here: they are in
[`known-issues.md`](../known-issues.md). Format-specific bugs usually live in §6 of that
format's handbook page; this page keeps the ones whose lesson crosses formats.

The lessons repeat. Three show up again and again:

- **A claim nobody re-runs drifts.** A doc, a comment or a test that says "this cannot
  happen" is worth running.
- **Every path must reach the step.** Random access, streaming, a pipe, an abandoned pass,
  a child process: a check placed where only some of them pass is a check that some
  callers never get.
- **Test with data that exercises the case.** Compressible test data, a test that runs
  alone, a session that runs as root: each hid a real bug.

## Stream ownership and wrappers

### A doc claimed something could not happen

`dev-docs/topics/stream-ownership.md` once argued that a class of owning wrappers was
safe because "`open_archive` wraps a caller `BinaryIO` before any backend sees it". That
sentence was the reason nobody worried about the case. It was false on the day it was
written: two narrow mechanisms (a replay wrapper only for non-seekable streams, and a
non-closing buffer in three places) had been generalized into a front door that did not
exist. A real spec violation sat under it, described in the next entry.

**Lesson.** When a doc's claim is the reason not to worry about something, run the thing
it says cannot happen. Then check whether the claim was wrong when written or regressed
later; the two need different fixes. This is why the guide's README says "check before
you trust", and part of why
[DR-22a](../design-rules.md#dr-22a-a-caveat-in-the-docs-is-a-question-for-the-code)
treats a caveat in the docs as a question for the code.

### A caller stream got closed

**What happened.** The spec says archivey never closes a caller's stream. But with
performance measurement on, opening a ZIP or most compressed TARs from a `BytesIO` closed
it when the reader closed. The caller's object reached the backend unwrapped, and the
measuring wrapper (`SeekCountingStream`, a `DelegatingStream`) owns its inner stream and
closes it. Measurement is the benchmark harness's switch, so no ordinary caller hit it,
but the same shape was one wrapper away on every backend.

**Fix, in two steps.** PR 400 wrapped every caller stream in a borrowing wrapper at the one
boundary every source crosses. That still left a stack of single-purpose wrappers
(borrowing, full-count reads, detection replay, ISO's bounded reads), each present or
absent depending on the source, the backend and whether detection ran. The
`single-archive-source` change, implemented in PR 419, replaced them all with one
`ArchiveSource`
([page 3](03-life-of-an-open.md)). The reader owns the source and closes only what
archivey opened. `tests/test_source_ownership.py` runs every format with two stream
shapes, with measurement on and off, and **reads from the stream afterwards** rather than
only checking `.closed`.

**Lesson.** An ownership rule that governs wrappers says nothing about the object under
the first wrapper. Put the rule at one boundary that every input crosses, not in a
convention each backend follows.

A small follow-on bug from PR 400 is worth knowing: the new wrapper first refused a wrong
inner type in `__init__`, which left a half-built object whose `IOBase` finalizer ran
`close()` on attributes that were never set. CPython hides that outside `-X dev`; CI's
free-threaded legs caught it. Refuse in `__new__`.

## Where a step runs

### A fact that arrived too late in streaming mode

PR 386 taught ZIP and 7z to read Windows reparse points (symlinks and junctions stored as
a Win32 buffer instead of a path). Its review found that the natural place to report a
link with no target, the step that settles link targets after the listing, does not run in
every path:

- a streaming pass that the caller abandons early never reaches its end-of-pass step;
- a 7z streaming pass does not run member registration at all, because it streams from
  the cached member list.

So the report moved to the one moment every path shares: when the member is typed.
Facts in the header are settled there. Only facts that need the member's bytes wait, and
for those the docs say where streaming and random access differ.

ZIP from a pipe has the same shape on a larger scale: a symlink is a `FILE` until the pass
reaches the central directory at the end, which is why `member_state_final` exists and why
extraction places a pipe ZIP's members only once the directory is read
([page 7](07-pipes-and-files.md)).

**Lesson.** Before putting a check "after the listing", list every path that produces
members and confirm each one reaches it.

### Diagnostics attached to the wrong member objects

The same PR hit a second problem with where a report lands. `extract_all` listed an
indexed archive twice, once for its progress totals and once to drive the pass. ZIP built
a fresh `ArchiveMember` each time, while 7z handed back the same object. A diagnostic
attached during the first listing was on an object the caller never saw, and a naive fix
would attach it twice.

The fix that held: report where the question is settled (typing time), and dedupe on the
member's position in the listing, the id registration stamps. A repeat sighting re-attaches
the first report instead of making a second. The larger cure came next: PR 423 gave every
reader **one** member list filled by one walk
([page 4](04-readers-and-members.md#one-member-list-per-reader)), so there is only one object per
member to attach to.

**Lesson.** If the same thing can be built twice, anything attached to it needs a stable
identity that is not the object.

### A single-member extract skipped the checks

Versions before 0.2.0 had `ArchiveReader.extract()` for one member next to
`extractall()`. The single-member path did not run the filters `extractall()` ran, so a
member named `../x` or with an absolute name was written outside the destination, for TAR
and ZIP with the default configuration. It was reported privately in October 2026 and
published as advisory
[GHSA-vc39-qg2q-c3jg](https://github.com/archivey-dev/archivey/security/advisories/GHSA-vc39-qg2q-c3jg);
0.2.0 is not affected, because it has no single-member extract.

0.2.0 had also removed the top-level `archivey.extract()`
(ADR [0019](../decisions/0019-no-top-level-extract.md)), for usability reasons rather than
this one. Together they leave one extraction path, `extract_all()`, so every safety check
has one place to live ([page 8](08-security.md#layer-4-extraction-stays-in-the-destination)).

**Lesson.** Two entry points to the same dangerous operation drift apart. Keep one, and
let other conveniences call it.

## Native code and child processes

### PPMd could kill the process

pyppmd segfaulted when asked to decode again after a corrupt stream ended early, and a
wrong password on a 7z PPMd folder is enough to get there. In a hostile-input stress run,
10 of 10 runs crashed. PR 481 kept small members in the process under a careful call order
and moved large ones to a child process (0 crashes in 1,200 hostile members). On
2026-10-20 the in-process path went too: the call order was safe only because tests had
not found a crash, not by a rule anyone could check
(ADR [0022](../decisions/0022-ppmd-always-in-a-child-process.md)).

**Lesson.** "We measured and it didn't crash" is weaker than "it cannot reach the crash".
When a library hides the state that would make a call safe, isolate it.

### rapidgzip killed the process, then lost bytes

rapidgzip 0.16 called `std::terminate` on a truncated gzip, zlib or raw DEFLATE stream, so
a cut `.gz` read with the accelerator killed the interpreter. PR 493 moved gzip decoding
through rapidgzip into a child process; the crash then ends the child and the read raises
`TruncatedError`.

That exposed a second problem (PR 545). rapidgzip decodes ahead in threads, and the child
died as soon as any thread reached the cut, taking everything decoded past the reader with
it. On a 154 MB gzip cut at 10 %, the accelerator delivered 0 bytes where the standard
library delivered 20.3 MB. The bytes were correct, but fewer of them breaks
[DR-2](../design-rules.md#dr-2-deliver-everything-recoverable-then-raise) (deliver
everything recoverable, then raise) and DR-5 (an accelerator never changes the result).
Now, when the child crashes, the standard library takes over from the last DEFLATE block
boundary the reader passed (`deflate_resume.py`), so a cut stream delivers exactly the
standard library's bytes.

**Lesson.** Isolating a crash is half the fix. Check what the caller receives up to the
crash, and compare it with the path without the accelerator.

### A stored exception kept a child process alive

`DecoderChild` kept the error its child died with and raised it again on every later
call. Raising the same instance attaches a new traceback each time; the traceback's frames
held the decoder, and the decoder held the exception. That cycle kept a dead decoder alive
until the garbage collector ran. When the collector then finalized it in the middle of
other code, the finalizer raised the death again from the collector's frames, which kept
the interrupted code's frames alive, including a new decoder and its leased child. The
leak oracle failed a test only when it ran after certain other tests (PR 1058).

The fix keeps an instance that is never raised and raises a copy each time. Every "store
the error, raise it later" pattern in archivey now does the same
([page 4](04-readers-and-members.md), [page 9](09-errors-and-diagnostics.md)).

**Lesson.** Never raise a stored exception instance twice. And an order-dependent failure
in a leak test is a real cycle, not flakiness.

## Hostile input in our own code

### unrar's own mask matcher backtracked

Opening a member of a 271-byte, two-member RAR archive took 32.9 seconds. A member named
`a*a*a*a*a*a*a*a*ab.txt` becomes a glob when handed to `unrar -n`, and two matchers
backtracked exponentially on it: archivey's (which compiled `*` to `.*`) and RARLAB's own.
`unrar` alone took 15.6 s on that mask. The time was spent before the subprocess started,
so no subprocess timeout applied.

PR 371 replaced every `*` with `?` in the mask. `?` matches exactly one character, so the
mask keeps the name's length, still matches the member itself, and matches a subset of what
the `*` mask matched. The subprocess dropped to 0.009 s. Today a name holding `*` or `?`
is never sent as a mask at all: that member is read through a synthetic RAR archive
([page 7](07-pipes-and-files.md)).

**Lesson.** Any string from the archive that reaches a pattern matcher, ours or another
program's, is an attack surface. Prefer a form that cannot backtrack over a timeout.

### The xz seek bug the test could not see

Seeking in a multi-block `.xz` file (what `xz -T0` writes) and reading across a block
boundary could return wrong bytes with no error (PR 407). A multi-block test existed and
passed, because its whole compressed stream fit in one read, so the code path that
crossed a feed chunk never ran. The new test uses incompressible content.

The same PR recorded the gap it did not close: a seek trusts the file's own index, so a
crafted index that is consistent with itself can still misplace data on a seek past the
lie. The maintainer kept index-based seeking (2026-09-23), and the gap is threat-model O17
([page 6](06-streams-and-codecs.md)).

**Lesson.** Test data must exercise the boundary, not only the feature. Compressible data
is a common way to make a "large" test small without noticing.

### A ratio check that judged a pipe too early

A `.tar.gz` whose member starts with 64 MiB of zeros was refused from a pipe ("Live
decompression ratio 1008:1 exceeds limit") and extracted fine from a file. On a file the
archive-wide ratio divides by the whole file size; from a pipe the size is unknown, so it
divides by the bytes read so far, and a blank start reads far above any limit until the
data after it arrives. No mid-stream check can tell that from a bomb. PR 775 makes the
check wait for its own floor (`live_ratio_activation_threshold`, 256 MiB) on a source of
unknown size. The trade-off, stated in the PR: a bomb from a pipe can now write up to
256 MiB before the ratio stops it, with `max_extracted_bytes` as the absolute bound.

**Lesson.** A check whose input differs between a file and a pipe gives different answers.
Either make the inputs the same or say how far the answers can differ.

## How we test

### Sessions run as root, CI does not

Development sessions run tests as root; GitHub's runners do not. A worker that sets
`PR_SET_DUMPABLE 0` makes its `/proc/self` files root-owned, so opening one worked locally
and failed with `EACCES` only in CI (found on PR 1027). Permission-sensitive code is tested
as an unprivileged user before it is pushed.

### Tests that pass alone

Several bugs on this page (the stored exception, the half-built wrapper) appeared only in
a particular test order or on a particular interpreter build. The suite has a leak oracle
(`tests/leak_oracle.py`) that fails a test which leaves a child process or an owning
stream behind, and CI runs free-threaded builds (3.13t) beside the usual ones. When one of
those fails and a rerun passes, the first failure is the one to believe.
