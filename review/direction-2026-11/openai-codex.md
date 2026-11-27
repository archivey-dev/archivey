# OpenAI Codex: direction review

Written by OpenAI Codex for [PR #1821](https://github.com/archivey-dev/archivey/pull/1821) (branch `codex/archivey-direction-review`, originally at `review/archivey-direction-2026-11-23/`). Moved here unchanged except for heading levels and links between its own parts. See [README.md](README.md) for the set and [assessment.md](assessment.md) for what was taken from it.

## Summary

Reviewed `main` at `183e3911c72feea225e8173f3afe5479d5e7cb65` on 2026-11-23. This is a
product and architecture review. The evidence comes from the public docs, specs,
reader and plugin paths, and earlier reviews linked below. The adoption proposals
are hypotheses for outside users to test.

### Direction

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

### The everyday API

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

### What broad compatibility should buy

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

### What a plugin should get for free

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

### Where the internals carry too much

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

### What to learn before freezing the API

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

## Ten specific changes

The first five fit the current contracts. The last five are choices I would make
with a clean slate. The changes in each section are in priority order. Proposed API
names show what the call site would look like. The changes are independent where
possible. For example, a staged extraction recipe pays off under either reader API.
[Direction review](#summary)

### Five changes that fit the current design

#### 1. Give eager member reads an explicit byte cap

Add `archive.read(member, max_bytes=8 << 20)`. Count decoded bytes delivered by the
member stream, even when the header has no size. If the member exceeds the cap, raise
`ResourceLimitError` and return no `bytes` object. Read through the normal verified
path and preserve its integrity checks, including at the exact limit. Omitting the
argument preserves today's behavior. Keep the normal file-object contract on
`stream.read()`. This gives callers reading small manifests or configuration files a
one-call way to bound memory used for the result. Test zero bytes, exactly the cap,
one byte over, and a member whose size is unknown before reading.
[Read API](../../src/archivey/reader.py#L957) · [Current limits](../../docs/security.md#where-the-guarantees-stop)

#### 2. Make the upload extraction recipe publish only on success

Replace the current upload example, which leaves its `mkdtemp()` output behind on
failure, with a context-managed staging directory under a private destination parent.
Use a fresh child for the extraction. Publish that child to a new output name after
`extract_all()` succeeds, with publishers serialized by the application. Use one
filesystem for staging and publication. Show cleanup on refusal or corruption, and
show the existing best-effort extraction recipe alongside it. Start in docs and run
the example in a test. A failing extraction should leave neither a published output
nor a staging directory, and a successful one should leave the published tree. This
solves the publication problem without adding another extraction policy.
[Current recipe](../../docs/recipes.md#extract-an-upload) · [Extraction options](../../docs/extracting.md#options)

#### 3. Lead installation docs with the support cases that change the outcome

Put four rows near `pip install archivey` for core ZIP/TAR, AES ZIP, Zstandard TAR,
and compressed RAR. Give each row the install requirement and whether listing alone
works. Generate the evidence from one real archive per case in clean core and
recommended installs. Run listing and a complete data read in the same smoke check.
Include an installation without `unrar` or `unar` so that RAR's list/read distinction
stays explicit. Use the existing `format_availability()` and `MissingComponent` output
for programmatic inspection. That API already reports the minimum source capability.
Keep its answer about the installation distinct from whether a particular file can
be read. The latter may require inspecting member methods or encryption.
[Installation](../../docs/install.md) · [Format availability](../../src/archivey/types.py#L700)

#### 4. Publish two plugin examples with the same reusable tests

Make two small installable example packages that import only `archivey` and
`archivey.formats`. Use a fixed-offset indexed format in one package and a
header-then-body sequential format in the other. Add a public conformance test
recipe that both can run with their own samples. Cover explicit registration,
listing, reading to EOF, extraction, short input and close after an early exit.
Give the sequential example a pipe test. Keep tests for detection, link policy and
resource limits in one shared harness so plugin authors do not have to learn
Archivey's test internals. A clean virtual environment should be able to install
an example wheel and run its tests without an Archivey checkout.
[Format guide](../../docs/adding-a-format.md) · [Corpus contract](../../openspec/specs/testing-contract/spec.md)

#### 5. Cut the cost of listing small ZIP members

Use the existing many-small-members benchmark to profile a names-only ZIP listing.
Prototype delaying the construction of format-specific metadata objects, such as
`MemberExtra` wrappers, until the caller asks for them. Keep required header checks,
diagnostic decisions and metadata budget charges at listing time. Retain the parsed
information needed to build the same public value later without another source read.
Measure both names-only and full-metadata listings before adopting the change.
Require the same reports, metadata limits and source read counts, and a repeatable
improvement on the names-only workload. Stop if the wrapper turns out to be cheap
or storing deferred values erases the improvement. Start with ZIP so the experiment
can identify the cost before the same representation spreads across formats.
[Many small members](../../benchmarks/RESULTS.md#many-small-members-1) · [Member model](../../src/archivey/types.py#L1452)

### Five choices I would make in a rewrite

#### 1. Delete `streaming=` and `pipe=` from `open_archive()`

Give random access and a single pass separate entry points. `open_archive(source)`
opens a seekable source for listing and named reads. `scan_archive(source)` returns a
one-pass handle for iteration, hashing, verification and extraction. Passing a pipe
to `scan_archive` explicitly authorizes consuming it. That call can also use a
seekable source, so a ZIP scan can consult its index when one is reachable. Both
entry points retain shared format detection and policy. A scan of input that needs
seeks fails with the existing kind of actionable error. `open_stream()` still handles
single-file compression. Callers would change `open_archive(..., streaming=True)`
and `open_archive(..., pipe=True)` to `scan_archive(...)`. The cost is two entry
points and a migration for typed callers. The benefit is that the operation determines
the return type and lifetime, without flag combinations.
[Opening signatures](../../src/archivey/core.py#L391) · [Reading from a pipe](../../docs/reading.md#reading-from-a-pipe)

#### 2. Delete `concurrent_operations=` and make each reader single-owner

An operation holds the reader until its stream or pass closes. Applications that
need parallel random reads open one reader per worker. A solid archive still gets
one ordered decode per pass. For independent ZIP members, try one internal extraction
scheduler only after throughput measurements justify it. Remove the public ability
to share one reader for concurrent listing, open, extraction and close. This can
remove much of the coordination between user callbacks, live streams, passes and
shutdown. It also makes multiple workers pay for extra listings, remote requests and
handles. Measure ZIP and remote workloads with independent readers before taking
this option. If they need shared metadata, share a read-only index keyed to a stable
source identity and keep each reader's I/O and lifetime separate.
[Concurrency contract](../../openspec/specs/reader-concurrency/spec.md) · [Current state machinery](../../src/archivey/internal/reader_state.py)

#### 3. Make member metadata immutable once it crosses the public API

A random-access reader returns immutable member snapshots with a stable ID within
that reader. A scan yields an observed entry with an ID and a stream for the current
record. At the end, its report carries final metadata or an explicit incomplete
outcome. In a ZIP scan from a pipe, a caller can hash bytes immediately and use the
final report to decide which hashes to publish. Remove in-place updates of retained
members and the public `member_state_final` flag. Use the same distinction internally
between observed records and a settled listing, including in the format adapter.
The cost is extra work for callers who used to keep a member object and get updates
for free. The terminal report also needs an explicit memory budget. Prototype it on
a pipe ZIP and TAR before choosing the report representation.
[Duplicate names](../../docs/opening.md#members-with-the-same-name) · [Reading from a pipe](../../docs/reading.md#reading-from-a-pipe)

#### 4. Replace process-global registration with explicit plugin sets

Bind chosen handlers and codecs to an immutable configuration passed to detection,
opening and availability. The default configuration contains built-ins. An app that
reads an unsupported format opts in with a call such as
`open_archive(path, config=ArchiveyConfig(plugins=(FooHandler,)))`. Remove the
side effects of `register_format()` and `register_codec()`. Make an override of a
built-in an explicit setting on that same configuration and propagate it to nested
opens. Keep one internal lookup for built-ins and extensions, with two supported
reader shapes at the public boundary. Add a CLI mechanism for explicit activation
when there is an outside package to use it with. The cost is application plumbing
and a migration for packages that register at import. The benefit is reproducible
behavior when two libraries in a process need different handlers or trust policies.
[Registration and trust](../../docs/adding-a-format.md#registration-and-trust) · [Replacement readers](../../docs/adding-a-format.md#replacing-a-built-in-reader)

#### 5. Move legacy format parsers into a first-party plugin pack

Start with ARJ and LHA. Keep ZIP, TAR, 7z, RAR and common compression streams in the
core. Build the legacy pack against the same adapter contract and conformance suite
that an outside author gets. Let users explicitly enable it as one unit. Publish a
compatibility table and keep the existing corpus running against the pack. Remove
those backends from core dispatch once the pack can handle its supported operations.
If the pack requires a private helper, move that helper into the pack, replace it
with a generally useful host service, or keep the backend in core until one of those
choices works. This makes an actual built-in consumer exercise the plugin boundary
across package releases. It also breaks the current one-install promise for those
formats and adds release coordination. I would accept that trade for legacy formats
only after measuring how often users rely on opening them without setup.
[Format support](../../docs/formats.md#older-and-unix-formats) · [Format adapter](../../src/archivey/internal/format_adapter.py)

### Where I would start

Ship the read cap and staged extraction recipe first. Prototype the two entry points
and immutable scan records together on ZIP and TAR. Use the same fixtures to compare
error reporting, memory, source reads and how much code a caller writes. The external
plugin examples can then test whether a second package can implement the chosen
reader contract and survive a host upgrade.
