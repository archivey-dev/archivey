# Cursor (cloud agent): direction review

Written by Cursor (cloud agent) for [PR #1822](https://github.com/archivey-dev/archivey/pull/1822) (branch `cursor/direction-review-2402`, originally at `review/direction-2026-11-23/`). Moved here unchanged except for heading levels and links between its own parts. See [README.md](README.md) for the set and [assessment.md](assessment.md) for what was taken from it.

## Brief

A direction note for the maintainer. It is not a defect review.
[`review/README.md`](../README.md) asks a commissioned review for a green baseline, a
findings table, theme files, and file-and-line evidence. Those do not fit this ask, and
this brief does not pretend they were done. The test suite was not run. Nothing under
`src/` or `tests/` changes. `./scripts/check.sh` was run on the prose.

### The ask

Look at the library with fresh eyes, as a candidate for the default way to deal with
archives: easy to use, safe, broadly compatible, and easier to extend with a plugin than
by writing another library. Say what is missing, what is too complicated in the API and
in the internal architecture, whether the project has gone too far, what else to ask,
and which unknowns the current work will not surface. Stay at the level that shapes
direction. Do not search for bugs. Write the analysis under `review/` and open a pull
request. Ignore other open pull requests.

### What was read

`VISION.md`, `docs/philosophy.md`, `docs/cheat-sheet.md` (the opening), `README.md`,
`dev-docs/scenarios.md`, the index and principles of `dev-docs/design-rules.md`,
`dev-docs/guide/README.md` and pages 2, 5, and 12, `docs/adding-a-format.md` (the
opening and "What is not supported yet"), `dev-docs/IDEAS.md` (formats and detection;
salvage status was checked against `open_archive` and the ideas page was not used for
it), `openspec/project.md` on deferred work,
`dev-docs/investigations/archive-writing-design.md` (status only),
`dev-docs/threat-model.md` section 4's opening, ADRs 0001, 0002, 0004, 0007, 0010, 0011,
and 0019, `review/outside-newcomer-2026-11-08/SUMMARY.md`, and the public signatures in
`src/archivey/__init__.py`, `core.py`, `reader.py`, `formats.py`, and `config.py`.

Counts (modules, lines, `__all__`, diagnostic codes, which readers import
`archivey.internal`) were taken at `183e3911`.

### What was not done

No bug hunt, no handbook pass, no benchmark, no comparison with other open pull
requests, and no measurement of downloads, dependents, or agent behavior. Where the note
says an agent trial or a backup corpus was not run, that is the gap.

### Deliverable

- [`SUMMARY.md`](#summary) is the analysis, including what to leave alone and an order
  of work.
- [`QUESTIONS.md`](#questions) is the decision list and the unknowns.

There is no findings table and no theme file. Nothing here is a live TODO for the code.
A decision that comes out of it belongs in `VISION.md`, `dev-docs/design-rules.md`, or
the plugin guide, in the change that carries it.

## Summary

Archivey can already be the library a careful program reaches for when it has to read an
archive it does not trust. The reading engine, the safety contract, and the shared
extraction path are strong enough to build on. Becoming the library someone opens
without thinking still takes three changes: less for a caller to hold in their head, a
plugin boundary the hard formats actually live behind, and a pitch that says "reading"
until the library also writes.

Shrink the everyday vocabulary before 1.0, make the plugin contract either stable or
honestly small, and say "default reader" until a writer exists. Do that before adding
another format or another public concept. The machinery gets more expensive to remove
every release, and the README already says no large changes are expected.

### How to read this

This is a direction note. It names no defects and proposes no patches. Counts below are
from `main` at `183e3911` on 23 November 2026. The counts will go stale. The shape they
describe stays until you change it on purpose.

I read the vision, the philosophy page, the usage scenarios, the design-rule index and
principles, the README, the start of the cheat sheet, the plugin guide, the internals
guide's map and its pages on formats and on choices that look oversized, the writing
investigation's status, the deferred list in the project spec, a few ADRs, the threat
model's accepted limits, and the public signatures of `open_archive` and the reader. I
counted the tree. I did not read the format handbooks for bugs, and I did not run the
suite.

An outside newcomer review on 8 November 2026 already named the strongest design
objection: there is no single answer to "is this archive acceptable?" That objection
still stands. This note is about the shape around it.

### What is already the right shape

Keep these. Several are decisions you already took against a more complicated
alternative.

- One opener, then methods on the reader. Deleting the top-level `extract()` was right
  (ADR 0019). A second entry point had drifted from `open_archive` plus `extract_all`,
  and it gave one report type two meanings.
- `streaming` as a boolean (ADR 0004). An `AUTO` intent was tried and did not choose a
  mode. The mode flags are real differences between formats. Folding them back into one
  enum would hide the difference.
- The annotation split between `ArchiveReader` and `ForwardArchiveReader`. At run time
  every reader is an `ArchiveReader`. The split makes a program typed against a
  streaming open fail in the checker on `get()` or `open()`, instead of failing later on
  a TAR. That is DR-5 doing its job.
- Safe by default, and parsers in Python, with native codecs isolated when they can
  crash. Those two claims are why the library is worth existing. The threat model, the
  corpus built by other tools, the fuzz targets, and the three-configuration CI are how
  one person can keep the claims. That size is the product.
- A zero-dependency core (ADR 0011), and reading 7z and RAR without taking py7zr or
  rarfile on as the read path (ADR 0001, ADR 0002). Their quirks would have become the
  unified contract.
- The five-box picture in the internals guide: source, detection, reader, member,
  stream. Shared code owns names, limits, links, extraction, and checksums. Format code
  owns the bytes. That is the architecture, and it is the right one.
- `ReaderContext` as the only door a format reader is supposed to have. The ar, cpio,
  and rpm readers are written that way, and tests check that they import public names
  only, apart from the call that registers a built-in format.
- Diagnostics as data with a stable code, rather than a log line the caller never sees.
  The forensics caller and the "no silent success" rule need this. The problem further
  down is how many doors report one event.
- The cheat sheet. It is already the first page: open, iterate, `get`, `read`, `open`,
  `stream_members`, `extract_all`, `open_stream`, `detect_format`.

### The first call is simple. The model is not.

`open_archive` takes ten keyword arguments: `format`, `streaming`, `pipe`,
`seekable_members`, `concurrent_operations`, `password`, `encoding`, `config`, `parent`,
and `salvage`. The root package exports 97 names. The exceptions module has twenty
exception types and one reason enum. There are 49 diagnostic codes. A caller who wants
to know what happened can look at an exception, a `Diagnostic`, a `MemberListReport`,
an `ExtractionReport`, a `VerifyReport`, a `Verification` level, or a `CostReceipt`.

Each of those earned a ruling. A warning that is not also data is a surprise postponed.
A costly or risky capability stays off until the caller asks, and then it is guaranteed.
The same archive should behave the same way in every format, so a seek that is cheap on
ZIP stays off until asked, because on TAR it re-decodes. Those rules stay.

Nothing in the rules limits how many of these a caller meets at once. A newcomer, and an
agent writing a script from the docs in one try (scenario 3), meets the whole set and
misses the ruling behind each flag. The cheat sheet hides the total.
The docstring of `open_archive`, `ArchiveyConfig`, and the long-form docs show it.
`llms-full.txt` is the long form in
one file, and the README sends agents there.

The practical failure is already visible, and it was visible to the newcomer review.
`extract_all` returns a report and, with the defaults, does not raise when it refuses a
member. The README example had to grow `abort_on` because a dropped report looks like
success. Success is spread across a return value, a report, and sometimes an exception.
One method on the reader, defined as a summary of the reports you already build, would
tell the upload scanner and the agent whether the archive met their bar. Leave the
top-level `extract()` deleted. ADR 0019's reasons still hold. A new entry point would
grow a second meaning for the same report, which is the bug that deletion fixed.

The process pushes the same direction. A new code, limit, or flag is easy to defend one
case at a time, because each one closes a hole the upload server might hit. DR-12a makes
a removal a migration. The README says no large changes are expected, while the API may
still change before 1.0. If you mean that sentence now, the vocabulary you have is close
to the vocabulary you will keep. Cut first, and then mean the sentence.

### The plugin seam is the right idea, and it leaks

A format as two classes, with archivey doing names, limits, links, and extraction, is
how this stays one library. For a sequential format shaped like ar, a plugin is already
easier than a separate library. The ar reader is the proof, and the plugin guide says
so.

That fact is narrower than the vision. The vision says a public plugin interface turns
format coverage "from a solo treadmill into an ecosystem," and that the pre-1.0 decision
is which of that interface becomes stable. Today the interface is experimental. A patch
release may remove it with no deprecation period. A plugin is told to pin
`archivey==X.Y.Z`. The guide also lists what a plugin cannot do: an indexed format
inside an outer compressor, self-extracting stubs, multi-volume sets, new diagnostic
codes, and writing.

The public-import test is the real boundary. Three readers pass it: ar, cpio, and rpm.
Other readers subclass `IndexedReader` or `SequentialReader` and still import
`archivey.internal`. How far they reach varies. xar imports a listing-limit helper.
SquashFS imports the internal lz4 codec, which the guide already says a plugin cannot
do. LHA and ARJ import internal decoders, plus stub and timestamp helpers. ISO is an
`IndexedReader` and also imports shared internal helpers for listing limits, streams,
and timestamps, along with its own parser modules. Subclassing the plugin class is a
different claim from "a third party could have written this file."

ZIP, TAR, 7z, RAR, the single-file compressors, and directories subclass the internal
base reader. The guide gives the reasons: passwords, volumes, stubs, solid compression
graphs, a listing fast path. It also says TAR is planned for the plugin interface. TAR
has not moved.

The adapter that turns a plugin reader into a full reader is 4,170 lines. The shared
base reader is 5,937. `formats.py` is 1,612. That size matches the shared behavior. The
trap is a contract that keeps moving while the other side of it is unpublished and
unstable. A third party cannot tell which of those lines they may depend on.

Decisions, rather than a rewrite:

1. Write the ceiling on one page, and make the guide match the imports. A plugin may do
   what ar, cpio, and rpm do, plus indexed formats whose codecs go through
   `ReaderContext.decompress`. Otherwise the ceiling also includes passwords, stubs, and
   volumes, and those become methods on the context. A reader that still imports
   `archivey.internal` is an internal format. Say that at the top of the plugin guide.
2. Extend the public-import test from ar, cpio, and rpm to every reader you still want
   to call a plugin. A reader that fails is internal until it passes. That test is the
   contract. The prose will drift.
3. Hold off any invitation to publish plugins while a patch release may delete the API.
   An ecosystem needs a stability promise. Until you can make one, this interface is a
   way to write built-in formats, and the vision's ecosystem sentence can wait.
4. Move TAR onto that ceiling, or write down that TAR stays internal. TAR is the proof
   that matters: pipes, a compression wrapper around the archive, sparse files, a format
   every caller has. If TAR cannot be expressed through the context, the ceiling is
   "simple formats." ZIP, 7z, and RAR staying internal is then a permanent fact. Say so.
   A solid compression graph is a different program from an ar reader. Forcing both
   through the same two methods will weaken the interface, or make it as large as the
   base reader.
5. Give a plugin a conformance check it can run without this repository. The corpus
   sweep is why the built-in formats stay honest, and it lives here. A plugin that
   cannot run a slice of it will drift, and the drift will come back as a bug report
   against archivey.

Two changes would make this worse. Plugins subclassing `BaseArchiveReader` would remove
the boundary. Splitting `format_adapter.py` and `base_reader.py` as a project of its own
would too. Split one of them when a change is already in the file and the new
boundary is one a caller could name.

### Listing pays for a forensics record

VISION records the listing gap itself. ZIP listing is past the 3× `zipfile` band. 7z and
RAR listing is slower than py7zr and rarfile. The cost is per member. On ZIP and 7z it
is mostly building `ArchiveMember`. Lazy derivation is the follow-up VISION already
names.

Treat that as an API decision. `ArchiveMember` is a forensics record: the raw name,
several timestamps, hashes, extras, and link targets filled in by default, because a
field that is present on one format and empty on another causes bugs (DR-8). It is also
the object every listing allocates, so a listing pays for the forensics record on every
member. Members are already mutable because some facts arrive after the member is
yielded (ADR 0007). Lazy fields are that
rule applied to cost. A listing fills the identity of the member. A field that costs
work waits until the caller reads it. `member_state_final` still says whether more can
change.

Keep one member type. A cheap listing type beside a full type is a second API, and
scenario 3 will guess wrong about which object it holds.

The same choice explains internal size that looks excessive and is the cost of the
format. `zip_reader.py` is 5,201 lines, `rar_reader.py` is 7,099, and `extraction.py` is
5,621. A ZIP reader of that size is affordable while the next format goes through the
adapter. It is unaffordable if the next format copies the ZIP reader. The plugin ceiling
is what decides which of those you get.

### Where the size is earned, and where it has gone past the caller

The safety scaffolding is the right size. So are the per-format parsers, the corpus, and
the refusal to buffer a pipe in secret (ADR 0010). The internals guide's page of choices
that look oversized is worth trusting: most of those were the simple version once. Leave
them closed.

The public vocabulary is past the size a default library can carry. So is the part of
the lifecycle that exists for flags the common path never sets.

`reader_state.py` is 1,036 lines of passes, leases, and live-stream reservations. Some
of that serves ordinary use: one stream at a time, and a stream the caller dropped must
not depend on when the garbage collector runs. Some of it serves
`concurrent_operations=True`. The docstring says overlap is correct, and that it is not
always cheaper. The flag sits on `open_archive`, so every new overlap rule becomes a
rule in the base reader. Keep the flag if a real caller needs overlapping reads. Keep it
off
the cheat sheet, and add overlap rules slowly.

`ArchiveyConfig` is the right home for accelerator modes, process isolation, the RAR
decompressor choice, the limit objects, the detection budget, the diagnostic policy, and
salvage limits. The package docstring treats the 97 root names as the documented API,
and keeps a handful of payloads and thresholds in their own modules. DR-13 is stricter:
a public name exists only when a caller would use it differently. Several of the 97 are
real, and a first-day caller never branches on them.

The tree around the code has the same shape. About 169,000 lines of library Python in
250 modules, about 264,000 lines of tests, 20 published doc pages, 133 maintainer docs,
36 specs, and 22 ADRs. The tests and the specs are why the safety claims are believable.
The maintainer docs are why an agent can change the code. A person who came to add a
format will not read them. The plugin guide has to stand on its own for that person. It
is long, it is experimental, and it describes a boundary the import test does not
enforce.

### What is still missing

Another format is not the gap. The README already lists ZIP, TAR, 7z, RAR, ISO,
SquashFS, CPIO, ar, deb, RPM, makeself, CAB, XAR, pkg, LHA, ARJ, directories, and a long
list of single-file codecs.

- A cheat-sheet contract that the long docs defer to. The sheet is the draft. The
  missing piece on it is one verdict, defined as a summary of the existing reports, and
  a habit that a new flag, code, or exception has to say whether a first-day caller
  branches on it.
- A plugin contract with a ceiling, a test, and a stability promise. Until those exist,
  "easier than a separate library" is true for an ar-shaped format and false for a
  format someone would otherwise start a library for.
- RAR bytes with no extra install. Listing a RAR needs nothing. Reading a compressed RAR
  member needs RARLAB `unrar` or `rar`, or `unar` (ADR 0002). A native RAR decompressor
  is out of scope there, for a real reason. The adoption cost is still that installing
  the package on its own does not return the bytes of a `.rar`. That sentence belongs
  on the first screen next to "zero dependencies," or common RAR has to decode without
  the external
  program, under a correctness bar you would trust against `unrar`.
- Writing, or a pitch that stops implying it. There is no writer. The deferred design is
  marked as not current truth, and writing is not a 1.0 requirement. The vision's
  one-sentence pitch is the default Python library for dealing with archives. The
  philosophy page does say the library reads and does not write. `zipfile` and `tarfile`
  remain mandatory for the other half of the work. "Default reader" is a finished
  product. It is a different product from that pitch. Say which one you are building. If
  it is the library that also writes, start the writer only after the cheat-sheet
  contract is what the writer would mirror, and start with ZIP and TAR, which is the
  scope the deferred design already sketched. A writer designed against the full current
  surface copies every concept in it.
- A number that means someone switched. I do not have download counts or a list of
  dependents, and I did not go looking. With no number, the next year follows the review
  loop. That loop is good at correctness. It will not notice that a stranger still
  starts with `zipfile`.

The fsspec filesystem, the CLI, the migration guide, and `llms.txt` are the right
adoption tools. They do not fill the gaps above.

The safety comparison with the standard library gets weaker on a calendar the vision
already describes. `tarfile` took years to grow extraction filters, and
`shutil.unpack_archive` is unsafe by default only before Python 3.14. After that,
"safer than the standard library" is a weak reason for a program that only sees ZIP and
TAR to switch. The newcomer review reached the same place. The reasons that survive
are the ones the standard library will not grow: one API across formats, a
solid archive decoded once per pass, limits on listing and decoding as well as on
extraction, header parsers that are not C, and a damaged archive that yields the intact
prefix and then raises. Lead with those.

### What to do, in order

1. Write the cheat-sheet contract down as a rule. Name the calls, the exceptions a
   caller catches, and the one report they have to read. A new public name stays off
   that sheet unless a first-day caller branches on it. Retire the README sentence "no
   large changes are expected" until this cut is done, or accept that the cut will not
   happen.
2. Add the verdict on the reader, as a summary of the reports that already exist. No new
   extraction behavior.
3. Freeze the plugin story or postpone the ecosystem sentence. Publish the ceiling,
   extend the import test, and either move TAR or declare it internal for good.
4. Decide which `ArchiveMember` fields a listing computes. Do the lazy derivation VISION
   already names, and keep a single member type.
5. Then pick the pitch. Default reader, with the RAR sentence and the writing sentence
   on the first screen. Or the library that also writes, scoped to the cheat-sheet
   contract.

Leave these unopened: a simplification rewrite of the base reader, a new intent enum, a
second member type, and a public subclass of `BaseArchiveReader`.

### Questions and unknowns

`QUESTIONS.md` holds the decisions and the risks the suite will not show you. The
decisions that change the next year are the cheat-sheet cut, the plugin ceiling, the
pitch, and what you count as success.

### What this review did not do

No defect pass, no failing input, no benchmark run, no reread of the format handbooks,
and no look at other open pull requests. A number in this note is a count or a signature
from `183e3911`. It is not a claim that a particular function is wrong.

Written 23 November 2026 by a Cursor cloud agent (Grok 4.7).

## Questions

The reasoning is in [`SUMMARY.md`](#summary). Each question here is meant to be
answered on its own. The unknowns at the end are not decisions. They are risks this
repository's tests will not close.

### Decisions

#### Q1. Cut the everyday vocabulary before "no large changes are expected"?

The README says the API is not frozen until 1.0 and that no large changes are expected.
DR-12a turns a removal into a migration. The root package exports 97 names,
`open_archive` takes ten keyword arguments, and there are 49 diagnostic codes.

If you cut first: the cheat sheet becomes the contract for what a first-day caller sees.
New names stay off it unless that caller would branch on them. The "no large changes"
sentence comes back after the cut.

If you mean the sentence now: treat the current vocabulary as what 1.0 will keep, and
spend the effort on the plugin ceiling and the pitch instead of on a slimmer API. Say
that, so later reviews stop proposing removals you will not do.

#### Q2. What is the plugin ceiling, and is it stable before 1.0?

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

#### Q3. When scenario 3 and scenario 6 disagree, who owns the first screen?

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

#### Q4. Are you building the default reader, or the library that also writes?

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

#### Q5. Is an external program a permanent part of reading RAR?

ADR 0002 keeps RAR metadata in Python and RAR bytes in `unrar`, `rar`, or `unar`. A
native decompressor is out of scope. `pip install archivey` lists a RAR and does not
return its compressed bytes.

If that is permanent: the first screen says it beside the zero-dependency claim, in the
same breath, so "zero dependencies" is not read as "reads every format in the list."

If it is not permanent: decoding common RAR without the external program is an adoption
project. It needs a correctness bar you would trust against `unrar` before it is a
feature. A research note in the ideas list does not close the adoption gap.

#### Q6. Which `open_archive` flags are you willing to explain forever?

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

#### Q7. What number means this is working?

PyPI downloads count installs, including CI. A better pair: how many other packages
depend on archivey, and a repeated trial where an agent is asked to unpack a ZIP and a
7z, scored on whether the script is short and correct, against `zipfile` and py7zr.

If you pick a number and look at it: the review loop keeps ownership of correctness, and
the number keeps ownership of "would a stranger switch."

If you do not: the next year of work will be whatever the review loop rewards, which is
a precise behavior, a new code, and a new test. That can make the library better and
leave it unadopted.

#### Q8. Is the format list inside this repository allowed to stop?

The README's format list is already the breadth the pitch asked for. Each further format
is a reader, a handbook page, a corpus, and a fuzz or oracle story. The maintenance
reality in the vision is one person plus agents.

If the list can stop: the next format is a plugin under the ceiling from Q2, or it
waits. The core grows only when a format cannot fit that ceiling.

If every format stays in tree: the plugin contract has to take the next simple ones, or
the core grows past what a review can honestly reread. `base_reader.py` is 5,937 lines
and `format_adapter.py` is 4,170. Those files are the shared path. They get worse when a
new format copies `zip_reader.py` (5,201 lines) instead of going through the adapter.

### Unknowns the suite will not close

#### U1. "Safe" will be read as "bounded time."

The threat model accepts no CPU or wall-clock bound, and it lists slow cases: a crafted
7z BCJ2 stream, LZX and LZH streams made of headers, and many tiny compressed members
when native decoders run in a child process. Memory stays bounded. The README says a
hostile archive fails with `ResourceLimitError` instead of exhausting the machine. A
CPU-only input exhausts the machine in the way an operator notices, and that error does
not fire. This is written down. The risk is that the first public incident is one of
these cases, and that the first screen has no sentence that says "bounded memory, not
bounded time" in words a caller will see.

#### U2. The memory-safety claim stops at a plugin.

VISION's second claim is that header parsers are pure Python and archivey's own, so a
hostile archive cannot corrupt memory through the parser. A plugin is ordinary Python in
the process. `FormatPolicy(plugins=False)` can keep plugins out of one call. The risk is
a caller who installs a plugin and still believes the claim. Write the sentence before
anyone publishes a plugin: a plugin is trusted code, the way any dependency is. After
someone has published one, that sentence is an argument.

#### U3. A faster product can copy the safety policy and skip the parsers.

VISION already says libarchive is faster on nearly every path, and a measured attempt to
use it as an accelerator was parked because it accepts damaged streams archivey refuses.
A different product is still open: someone else's library runs libarchive in a child
process and copies your extraction checks. Sandboxing gives them the crash isolation. It
leaves them without honest metadata, without a damaged archive that yields its intact
prefix, and without header parsers free of native memory-safety bugs. If those three are
why a caller would prefer archivey, they belong in the pitch, in two sentences. If they
do not fit in two sentences, the pure-Python work is larger than the reason a stranger
switches.

#### U4. The complete docs may make an agent write a worse script.

The repository is built so an agent can change it. Scenario 3 is an agent using it,
once, from the README and the docstrings. `llms-full.txt` is the whole guide, and the
README offers it. The risk is that the complete file makes the agent copy a caveat the
task did not need. The README's `abort_on` is the kind of line that spreads that way.
The check is small and has not been run: the same task, once with the cheat sheet and
once with the full file, scored on whether the script is correct and short.

#### U5. A real archive will trip a default and teach the caller to trust everything.

The defaults I read are ordinary-sized: extraction stops at 2 GiB and at 262,144
entries, and the ratio check starts after 5 MiB at 800:1. Listing stops at 262,144
members. The corpus is built by other tools to pin behavior, and it will not look like a
mail spool, a scientific dataset, or a twenty-year backup drive. Scenario 4 already
names the failure: refusing an ordinary archive pushes the caller to the trusted policy,
and the trusted policy turns the safety checks off. There is a backup-drive
scan in the investigations. I did not re-read it. The risk is that its surprises never
met the defaults.

#### U6. Free-threaded Python against the reader state machine.

CI runs a free-threaded 3.13 job. `reader_state.py` is about a thousand lines of leases,
passes, and live-stream reservations, built so a dropped stream does not depend on when
CPython's garbage collector runs. The risk is that this design, written around that
collector, misbehaves when threads run without the GIL. I did not look for a race.
Before `concurrent_operations` is part of what you support on free-threaded builds,
decide whether that flag is in the support matrix or only in the job list.

#### U7. "Cannot be corrupted" will be read as "cannot be wrong."

VISION says a pure-Python parser can be wrong and cannot be corrupted. That sentence is
easy to over-read. Wrong bytes, a hang that stays inside the accepted CPU limit, or a
path check that lets a name out: none of those are memory corruption, and any of them is
what a user would call a security bug. Fuzzing covers the ZIP, TAR, 7z, RAR, and ISO
parsers, detection, and the stream codecs. OSS-Fuzz is still not on, which VISION
already says. The long tail of pure-Python codecs under `internal/streams/codecs` is the
part of the claim the current targets may not reach. The risk is an incident in a codec
the fuzz shards do not exercise, described by a reporter with the word you used in the
pitch.
