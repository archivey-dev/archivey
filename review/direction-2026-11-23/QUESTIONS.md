# Questions

The reasoning is in [`SUMMARY.md`](SUMMARY.md). Each question here is meant to be
answered on its own. The unknowns at the end are not decisions. They are risks this
repository's tests will not close.

## Decisions

### Q1. Cut the everyday vocabulary before "no large changes are expected"?

The README says the API is not frozen until 1.0 and that no large changes are expected.
DR-12a turns a removal into a migration. The root package exports 97 names,
`open_archive` takes ten keyword arguments, and there are 49 diagnostic codes.

If you cut first: the cheat sheet becomes the contract for what a first-day caller sees.
New names stay off it unless that caller would branch on them. The "no large changes"
sentence comes back after the cut.

If you mean the sentence now: treat the current vocabulary as what 1.0 will keep, and
spend the effort on the plugin ceiling and the pitch instead of on a slimmer API. Say
that, so later reviews stop proposing removals you will not do.

### Q2. What is the plugin ceiling, and is it stable before 1.0?

`archivey.formats` is experimental. A patch release may remove it. Three built-in
readers (ar, cpio, rpm) are held to public imports. The others that subclass the plugin
readers still import `archivey.internal`. The vision leaves "which of this becomes
stable" as a pre-1.0 decision.

One ceiling: a plugin may do what ar, cpio, and rpm do, and may decode through
`ReaderContext.decompress`. Passwords, self-extracting stubs, multi-volume sets, and new
diagnostic codes stay internal. TAR stays internal, and the guide says so.

A wider ceiling: passwords, stubs, and volumes become context methods, the readers that
need them pass the import test, and TAR moves onto the interface as the proof. ZIP, 7z,
and RAR stay internal because a solid compression graph is a different program.

Either way, a published plugin needs a stability promise and a conformance check that
runs outside this repository. Until both exist, the vision's ecosystem sentence is ahead
of the product, and the honest description is "a way we write the simple built-in
formats."

### Q3. When scenario 3 and scenario 6 disagree, who owns the first screen?

Scenario 3 is an agent, or a person, unpacking an archive from the README in one try.
Scenario 6 is a forensics caller who needs raw names, evidence, and diagnostics. The
code can serve both. The cheat sheet, the README, and `llms-full.txt` cannot lead with
both.

If scenario 3 owns the first screen: the long-form docs point back to the cheat sheet,
and forensics stays one page away, on `members_report`, diagnostics, and `raw_name`.
Agents are told to start at the cheat sheet, with the full file as a reference.

If scenario 6 owns the first screen: accept that agents will copy caveats into scripts
that did not need them, and invest in error text that names the one flag to set. The
newcomer review's dropped `extract_all` report is the shape of that failure.

### Q4. Are you building the default reader, or the library that also writes?

There is no writer. The deferred design is marked as not current truth. Writing is not a
1.0 requirement. The vision's pitch is the default library for dealing with archives.
The philosophy page says the library does not write.

If you are the default reader: change the pitch in `VISION.md` and the README now. Put
two sentences on the first screen. The library does not create archives. Compressed RAR
members need an external program. `zipfile` and `tarfile` remain the way to create a ZIP
or a TAR, and that is a finished answer.

If you are the library that also writes: start only after Q1, mirror the cheat-sheet
contract, and limit the first writer to ZIP and TAR. A writer designed against today's
full surface copies it.

### Q5. Is an external program a permanent part of reading RAR?

ADR 0002 keeps RAR metadata in Python and RAR bytes in `unrar`, `rar`, or `unar`. A
native decompressor is out of scope. `pip install archivey` lists a RAR and does not
return its compressed bytes.

If that is permanent: the first screen says it beside the zero-dependency claim, in the
same breath, so "zero dependencies" is not read as "reads every format in the list."

If it is not permanent: decoding common RAR without the external program is an adoption
project. It needs a correctness bar you would trust against `unrar` before it is a
feature. A research note in the ideas list does not close the adoption gap.

### Q6. Which `open_archive` flags are you willing to explain forever?

The flags are `streaming`, `pipe`, `seekable_members`, `concurrent_operations`, and
`salvage`, plus `parent` for a nest. ADR 0004 already refused to collapse the read modes
into an intent enum, because `AUTO` did not choose. This question does not reopen that.

`streaming`, `pipe`, and `seekable_members` are the format differences. They stay on the
signature. `concurrent_operations` and `salvage` are specialist. Overlap is specified as
correct and not always cheaper. Salvage is specified as something you must not use to
decide what an archive holds.

If a specialist flag stays on `open_archive`: its machinery in the base reader is a 1.0
cost, and every new rule for it is base-reader law.

If it moves to `ArchiveyConfig`: callers who need it still have it, and the signature
stops being the list of every mode. That is a break, so it wants a deprecation under
DR-12a, or it waits for a minor release on purpose.

### Q7. What number means this is working?

PyPI downloads count installs, including CI. A better pair: how many other packages
depend on archivey, and a repeated trial where an agent is asked to unpack a ZIP and a
7z, scored on whether the script is short and correct, against `zipfile` and py7zr.

If you pick a number and look at it: the review loop keeps ownership of correctness, and
the number keeps ownership of "would a stranger switch."

If you do not: the next year of work will be whatever the review loop rewards, which is
a precise behavior, a new code, and a new test. That can make the library better and
leave it unadopted.

### Q8. Is the format list inside this repository allowed to stop?

The README's format list is already the breadth the pitch asked for. Each further format
is a reader, a handbook page, a corpus, and a fuzz or oracle story. The maintenance
reality in the vision is one person plus agents.

If the list can stop: the next format is a plugin under the ceiling from Q2, or it
waits. The core grows only when a format cannot fit that ceiling.

If every format stays in tree: the plugin contract has to take the next simple ones, or
the core grows past what a review can honestly reread. `base_reader.py` is 5,937 lines
and `format_adapter.py` is 4,170. Those files are the shared path. They get worse when a
new format copies `zip_reader.py` (5,201 lines) instead of going through the adapter.

## Unknowns the suite will not close

### U1. "Safe" will be read as "bounded time."

The threat model accepts no CPU or wall-clock bound, and it lists slow cases: a crafted
7z BCJ2 stream, LZX and LZH streams made of headers, and many tiny compressed members
when native decoders run in a child process. Memory stays bounded. The README says a
hostile archive fails with `ResourceLimitError` instead of exhausting the machine. A
CPU-only input exhausts the machine in the way an operator notices, and that error does
not fire. This is written down. The risk is that the first public incident is one of
these cases, and that the first screen has no sentence that says "bounded memory, not
bounded time" in words a caller will see.

### U2. The memory-safety claim stops at a plugin.

VISION's second claim is that header parsers are pure Python and archivey's own, so a
hostile archive cannot corrupt memory through the parser. A plugin is ordinary Python in
the process. `FormatPolicy(plugins=False)` can keep plugins out of one call. The risk is
a caller who installs a plugin and still believes the claim. Write the sentence before
anyone publishes a plugin: a plugin is trusted code, the way any dependency is. After
someone has published one, that sentence is an argument.

### U3. A faster product can copy the safety policy and skip the parsers.

VISION already says libarchive is faster on nearly every path, and a measured attempt to
use it as an accelerator was parked because it accepts damaged streams archivey refuses.
A different product is still open: someone else's library runs libarchive in a child
process and copies your extraction checks. Sandboxing gives them the crash isolation. It
leaves them without honest metadata, without a damaged archive that yields its intact
prefix, and without header parsers free of native memory-safety bugs. If those three are
why a caller would prefer archivey, they belong in the pitch, in two sentences. If they
do not fit in two sentences, the pure-Python work is larger than the reason a stranger
switches.

### U4. The complete docs may make an agent write a worse script.

The repository is built so an agent can change it. Scenario 3 is an agent using it,
once, from the README and the docstrings. `llms-full.txt` is the whole guide, and the
README offers it. The risk is that the complete file makes the agent copy a caveat the
task did not need. The README's `abort_on` is the kind of line that spreads that way.
The check is small and has not been run: the same task, once with the cheat sheet and
once with the full file, scored on whether the script is correct and short.

### U5. A real archive will trip a default and teach the caller to trust everything.

The defaults I read are ordinary-sized: extraction stops at 2 GiB and at 262,144
entries, and the ratio check starts after 5 MiB at 800:1. Listing stops at 262,144
members. The corpus is built by other tools to pin behavior, and it will not look like a
mail spool, a scientific dataset, or a twenty-year backup drive. Scenario 4 already
names the failure: refusing an ordinary archive pushes the caller to the trusted policy,
and the trusted policy turns the safety checks off. There is a backup-drive
scan in the investigations. I did not re-read it. The risk is that its surprises never
met the defaults.

### U6. Free-threaded Python against the reader state machine.

CI runs a free-threaded 3.13 job. `reader_state.py` is about a thousand lines of leases,
passes, and live-stream reservations, built so a dropped stream does not depend on when
CPython's garbage collector runs. The risk is that this design, written around that
collector, misbehaves when threads run without the GIL. I did not look for a race.
Before `concurrent_operations` is part of what you support on free-threaded builds,
decide whether that flag is in the support matrix or only in the job list.

### U7. "Cannot be corrupted" will be read as "cannot be wrong."

VISION says a pure-Python parser can be wrong and cannot be corrupted. That sentence is
easy to over-read. Wrong bytes, a hang that stays inside the accepted CPU limit, or a
path check that lets a name out: none of those are memory corruption, and any of them is
what a user would call a security bug. Fuzzing covers the ZIP, TAR, 7z, RAR, and ISO
parsers, detection, and the stream codecs. OSS-Fuzz is still not on, which VISION
already says. The long tail of pure-Python codecs under `internal/streams/codecs` is the
part of the claim the current targets may not reach. The risk is an incident in a codec
the fuzz shards do not exercise, described by a reporter with the word you used in the
pitch.
