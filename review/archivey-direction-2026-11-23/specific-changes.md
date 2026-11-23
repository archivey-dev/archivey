# Ten changes I would make to Archivey

The first five fit the current contracts. The last five are choices I would make
with a clean slate. The changes in each section are in priority order. Proposed API
names show what the call site would look like. The changes are independent where
possible. For example, a staged extraction recipe pays off under either reader API.
[Direction review](SUMMARY.md)

## Five changes that fit the current design

### 1. Give eager member reads an explicit byte cap

Add `archive.read(member, max_bytes=8 << 20)`. Count decoded bytes delivered by the
member stream, even when the header has no size. If the member exceeds the cap, raise
`ResourceLimitError` and return no `bytes` object. Read through the normal verified
path and preserve its integrity checks, including at the exact limit. Omitting the
argument preserves today's behavior. Keep the normal file-object contract on
`stream.read()`. This gives callers reading small manifests or configuration files a
one-call way to bound memory used for the result. Test zero bytes, exactly the cap,
one byte over, and a member whose size is unknown before reading.
[Read API](../../src/archivey/reader.py#L957) · [Current limits](../../docs/security.md#where-the-guarantees-stop)

### 2. Make the upload extraction recipe publish only on success

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

### 3. Lead installation docs with the support cases that change the outcome

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

### 4. Publish two plugin examples with the same reusable tests

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

### 5. Cut the cost of listing small ZIP members

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

## Five choices I would make in a rewrite

### 1. Delete `streaming=` and `pipe=` from `open_archive()`

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

### 2. Delete `concurrent_operations=` and make each reader single-owner

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

### 3. Make member metadata immutable once it crosses the public API

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

### 4. Replace process-global registration with explicit plugin sets

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

### 5. Move legacy format parsers into a first-party plugin pack

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

## Where I would start

Ship the read cap and staged extraction recipe first. Prototype the two entry points
and immutable scan records together on ZIP and TAR. Use the same fixtures to compare
error reporting, memory, source reads and how much code a caller writes. The external
plugin examples can then test whether a second package can implement the chosen
reader contract and survive a host upgrade.
