# Making Archivey the default Python archive reader

Reviewed `main` at `183e3911c72feea225e8173f3afe5479d5e7cb65` on 2026-11-23. This is a
product and architecture review. The evidence comes from the public docs, specs,
reader and plugin paths, and earlier reviews linked below. The adoption proposals
are hypotheses for outside users to test.

## Direction

Make Archivey the default for **reading and extracting archives from unfamiliar
sources**. The promise is that a caller can use the same few calls, understand the
result, and get a useful remedy when their environment or the archive gets in the way.
Prioritize two jobs before 1.0. Let a developer unpack a download safely and know
whether to publish the output. Let a developer index or hash a mixed collection in
one pass and know what was read, recovered, or left unverified. Those jobs exercise
the strengths already described in [the vision](../../VISION.md).

| Priority | Decision | Evidence that it worked |
| --- | --- | --- |
| 1 | Specify what a completed job means. | A newcomer can handle a refusal, damaged input, and missing dependencies from one recipe. |
| 2 | Define support by operation and deployment. | Users can predict what a clean install can do with their corpus. |
| 3 | Prove a small extension API outside the repo. | Two plugin authors ship packages using public imports and survive a host minor upgrade. |
| 4 | Give shared reader behavior clear owners. | A change to a shared rule needs one implementation and runs against both reader shapes. |

## The everyday API

**Keep `open_archive()` as the front door.** An open reader, iteration, `open(member)`,
`stream_members()` and `extract_all()` already cover the main work. `open_stream()`
has a distinct use. On `data.tar.gz` it returns the TAR bytes, while `open_archive()`
gives access to the files in the TAR. Keep that distinction and teach it with this
example. A source that cannot seek, a one-pass reader, a seekable member stream and
simultaneous operations are four distinct concerns. At the call site they look like
four neighboring switches. Teach three tasks first: open and inspect, read one
member, and process all members in archive order. Teach `pipe=True` with stdin.
Introduce member seeking and concurrency where the task needs them. Keep the current
types and opt-ins while testing whether the task-based examples suffice.
[Cheat sheet](../../docs/cheat-sheet.md) · [Opening and access](../../src/archivey/core.py#L391)

**Make extraction outcomes easy to act on.** With defaults, a blocked path is skipped
and extraction can write other files before raising `FilterRejectionError`. A corrupt
member can stop the pass earlier. `abort_on=["blocked_member"]` stops at the refusal
and earlier writes can remain. These are useful semantics for recovery, and a caller
publishing an upload needs a different workflow. Put two examples in front of users.
One extracts to a fresh private staging directory and publishes it only after success.
The other keeps what it can and reads the report. Use the existing API to test both
examples. Consider a named policy or helper only if users keep implementing the same
workflow incorrectly. A library helper that publishes a directory would need an
explicit contract for destination ownership, cleanup and filesystem boundaries.
[Extraction options](../../docs/extracting.md#options) · [Security assumptions](../../docs/security.md#what-archivey-relies-on)

**Stabilize one way to answer whether a read job finished.** The experimental
`verify_all()` and its report already offer a place to do this. Test whether users can
use that report to distinguish incomplete listing, failed data, and data read to the
limit of the evidence available. Some formats store no checksum, and a shared
checksum may only settle at the end of a pass. Keep these facts visible. A plain
boolean would lose the information that determines whether a dataset may be accepted.
Require a full pass only when the caller asks for it. The reader's diagnostics and
cost receipt should support those decisions when needed, with detailed codes and
counters available for operations teams. Avoid adding a parallel `validate()` API
while the verification report can serve the job.
[Verification](../../docs/errors-and-diagnostics.md) · [Prior newcomer review](../outside-newcomer-2026-11-08/SUMMARY.md)

## What broad compatibility should buy

A format name in the support table is a poor proxy for a successful task. A core
install can list RAR and read stored members, yet compressed RAR data needs an
outside program. ZIP can list members whose methods the install cannot decode. A
forward-only source, a missing volume and an unsupported encryption method can all
change the answer for an archive in a familiar format. The project already has
`format_availability()`, install hints and format-specific docs. Use them to put an
operation-led support table near install and in release checks. Show recognition,
listing, full reads and extraction for representative producer variants. Check a
clean core install and a recommended install on the supported systems. Explain when
the answer depends on an individual member. Let real install failures decide whether
a CLI capability check earns a place, and build it on the existing availability data.
[Formats and extras](../../docs/formats.md) · [Installation](../../docs/install.md)

Treat compressed RAR as an adoption experiment. Can a new user get from `pip install`
to extracting their RAR on Windows and Linux, including a container with no package
manager? Record where that fails, then compare better install guidance, an opt-in
additional decoder route, and narrowing the advertised out-of-box promise. Include
licensing, wheel coverage, malformed-data behavior and who supports each route in the
cost. Use the same test for optional codecs. Prioritize gaps that block a user job.
A new extension in the format table has less value than getting the common producers
and codecs for a widely used format to work on a fresh installation.
[Known support boundaries](../../docs/formats.md#rar) · [RAR roadmap](../../dev-docs/IDEAS.md)

Wide support earns its maintenance cost when it brings a corpus, a reference producer
or reader, and a way to test the promised features. Ask for these before committing to
new disk image families or rare codecs. Make room for third-party readers whose scope
and support are clear. Keep write support deferred through the reader milestone. If
real users need creation for adoption, test a small reproducible ZIP and TAR writer
as a separate API. Decide metadata loss, ownership, and cleanup after failed output
before promising conversion or round-tripping. The previous writing design already
identifies these decisions.
[Writing investigation](../../dev-docs/investigations/archive-writing-design.md#before-re-specifying)

## What a plugin should get for free

The extension model is already viable in outline. Indexed readers describe members
and open their bytes. Sequential readers advance through headers and data together.
Archivey provides the member model, extraction, and shared checks around the records
and streams it receives. Built-in ISO, CPIO and ar exercise the adapter. The tutorial
also covers passwords, nesting, budgets, codecs, diagnostic context and replacement.
That breadth pays for formats in this repo and creates a large compatibility promise
if it all becomes stable. The experimental API currently asks external plugins to pin
an exact Archivey version.
[Adding a format](../../docs/adding-a-format.md) · [Adapter](../../src/archivey/internal/format_adapter.py)

Start the stability experiment with the declarations needed to identify a format,
bounded source access, records and byte streams for the two reader shapes, and an
error and cleanup contract. Support plain, indexed and forward-only fixtures. Define
who owns a stream, when it expires, how parser allocations are charged, and what
Archivey can verify. Keep advanced hooks provisional until an independent plugin
needs them. Give authors two installable examples and reuse the corpus tests to give
outside packages a conformance suite. It should exercise detection, truncated input,
name handling, limits, partial reads and resource cleanup through public imports.
Have one author wrap an existing parser and another write one directly. Measure time
to first usable plugin, how much glue it took, and how many private imports it needed.
Re-run the unchanged packages against the next host minor before promising stability.
[Plugin spec](../../openspec/specs/format-plugins/spec.md) · [Corpus contract](../../openspec/specs/testing-contract/spec.md)

Keep explicit opt-in. Installed packages contain executable code, and a plugin's probe
and parser can run on untrusted input. Host checks can constrain member records and
bytes after the plugin hands them over. The plugin controls its own allocations,
external calls and native code. Make that boundary visible on any plugin listing.
Global registration is convenient for a standalone application. Two dependencies in
one process may want different handlers or an application may want the base policy for
uploads and a chosen plugin for its collection. Have the outside pilots exercise this.
If that conflict occurs in practice, try explicit per-call plugin selection through the
existing format policy before committing to a new public registry. Protect built-in
detection precedence and measure plugin detection request counts for remote sources.
[Registration and trust](../../docs/adding-a-format.md#registration-and-trust) · [Detection](../../docs/adding-a-format.md#detection)

## Where the internals carry too much

`BaseArchiveReader` owns member presentation and name indexing, link resolution,
stream construction, verification, extraction dispatch and reader shutdown. The
format adapter extends it for both plugin reader shapes and also handles nested opens,
passwords, span-based streams and sequential walk state. A new concern can touch the
backend, adapter and base class because state and policy cross all three. Moving
methods to more files leaves that problem in place. `ReaderState` shows a better
kind of split. It owns call admission and leases, with no archive data or I/O.
[Base reader](../../src/archivey/internal/base_reader.py#L843) · [Format adapter](../../src/archivey/internal/format_adapter.py) · [Reader state](../../src/archivey/internal/reader_state.py)

Prove one boundary with existing behavior first. Give listing state one owner for
registering members, resolving names and links, and settling a partial listing.
Backends and adapters report what they observed, including which metadata can still
change. Exercise the same contract through an indexed reader and a forward reader
before migrating more formats. Include duplicate names, late ZIP metadata, hardlinks,
truncation and early close in the comparison. A follow-up can move verification and
byte accounting to the point where decoded member streams become public streams.
Measure duplicate rule implementations and the modules touched for the next policy
change. Retain a fast path if the shared version costs a second decode or breaks a
remote I/O budget. Use the existing cost and corpus checks for that decision.
[Reader contract](../../openspec/specs/archive-reading/spec.md) · [Cost contract](../../openspec/specs/access-mode-and-cost/spec.md) · [Engineering rules](../../dev-docs/design-rules.md)

The physical distinctions are worth keeping. A ZIP central directory, a forward TAR
walk and a solid 7z block imply different costs. Link policy and destination writes
should agree across them. Pure Python parsing for supported built-ins, bounded reads,
verification on read, cost signals, and read-once paths are investments to protect.
Keep native acceleration behind the existing kernel and decoder boundaries. Promote a
new fast path when its parity tests and measured workload justify carrying it. Avoid
rewriting every backend to prove that the extension API can handle everything.
[Codec kernels](../../dev-docs/topics/codec-kernels.md) · [Threat model](../../dev-docs/threat-model.md)

## What to learn before freezing the API

- **Who would switch today, and from what?** Watch developers migrate a stdlib
  extraction job, a mixed-format workflow using a native tool, and a backup indexer.
  Record setup steps, errors they understood and places they returned to the old tool.
  Python 3.14 changed `tarfile`'s default extraction filter to `data`. Test the
  advantage on current Python and against a tool with broad format support.
  [Python extraction filters](https://docs.python.org/3/library/tarfile.html#extraction-filters) · [Libarchive](https://github.com/libarchive/libarchive/wiki/)
- **Can an upload service set an operational budget it can explain?** Run inputs in a
  small worker with capped memory, disk and elapsed time. Include nested reads linked
  with `parent=` and several unrelated readers. Check cancellation and cleanup. Decide
  what Archivey should enforce and what the process supervisor should own. The threat
  model already describes linked archive budgets and per-decoder limits. The experiment
  tests how those controls compose for an entire job.
  [Threat model](../../dev-docs/threat-model.md)
- **Does the support promise hold on the user's storage?** Try a case-insensitive disk,
  a network destination and a remote object store. Track name collisions, temporary
  bytes, requests and source changes. Record which filesystem and deployment features
  the desired guarantee depends on.
  [Remote reads](../../docs/remote.md) · [Security assumptions](../../docs/security.md)
- **What could make a plugin ecosystem fragment?** Install two outside plugins
  together, upgrade the host, and hand a plugin to a second maintainer. See whether a
  user can tell which package owns a failure, how to disable it, and which versions
  it supports. Decide who fields security reports for the archive parser and its
  native dependencies before labeling a plugin as supported.
  [Registration and trust](../../docs/adding-a-format.md#registration-and-trust)
- **Do the benchmarks predict when a user gives up?** Try a folder of tiny ZIPs, a
  large solid backup and a remote dataset. Measure end-to-end time, memory, decoded
  bytes, temporary bytes and remote requests. Establish which cost would make each
  user switch back. Pair early results with the existing performance measurements.
  [Performance results](../../benchmarks/RESULTS.md)
- **Is “all kinds” about unpacking, inspection or round trips?** Ask users to bring
  files they cannot handle today. Record the workarounds they use and their cost.
  Reopen writing or a new first-party format when a repeated job depends on it.

Start with the upload and inventory recipes, the clean-install matrix, and the two
external plugins. Delay a stable plugin contract until an outside author upgrades the
host successfully. Delay new workflow APIs until the recipes show what users still
need from the library. Use the first shared-reader change to test the architecture
boundary before committing to a larger refactor.
