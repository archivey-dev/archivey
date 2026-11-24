# Direction review, 2026-11-24

A fresh, high-level read of archivey against the goal "the default library for every kind
of archive, the one you reach for without thinking". Scope and method are in
[`brief.md`](brief.md). This is about direction, not bugs.

## Headline

The foundations are right, and rarer than they look: a specified safety contract,
container parsing in pure Python, errors and warnings as data, and honest handling of
damaged input. I know of no other Python archive library that has all four. What
stands between archivey and "the default" is mostly not missing capability. It is the
cost of using what is there:

1. **The defaults are tuned for the worst format.** Out of the box a ZIP member cannot
   seek, two members cannot be open at once, and a ZIP inside a ZIP does not open. The
   stdlib `zipfile` allows all three. The restriction exists because these operations
   are expensive on a solid 7z or a `.tar.gz`, but the gate applies to every format.
   Gate on the cost, which the reader already knows, not on the feature.
2. **The surface is large, and every piece of it is justified on its own.** There are 97
   names at the package root, 25 fields on `ArchiveyConfig` plus seven policy and limit
   objects, 49 diagnostic codes, five mode flags on `open_archive` that interact, and
   three overlapping error knobs on `extract_all`. DR-13 checks each name on its own,
   and nothing caps the total. Pre-1.0 is the cheapest time to tier and merge.
3. **There are two ways to write a reader, and the public one has not been proven on the
   hard formats.** About fifteen formats run on `archivey.formats`, which is good
   dogfooding. ZIP, 7z, RAR and TAR run on a 5,900-line internal base class. The
   features the public API lacks (solid blocks, volumes, self-extracting prefixes, an
   indexed format inside a compressor) are the ones those four need. Until they run on
   it, the plugin API is the second-class path and the core keeps two contracts.
4. **Scope has spread into file systems while writing is missing.** archivey reads DMG
   with HFS+ and APFS, UDF, raw CD sectors with cue sheets, and installer packages, but
   it cannot write a ZIP. As long as people need `zipfile`, `tarfile` or
   `shutil.make_archive` to write, archivey can be the default *reader* at most. That is
   a fine goal, but it should be chosen on purpose.
5. **The process is heavier than the product.** There are 209,000 lines of Markdown
   against 169,000 lines of source, 26 workflows, and about 45 design rules. Agents
   make complexity cheap to write. Its cost falls on the one person who has to hold
   the design, and nothing in the process measures that cost.

## The picture in numbers

Measured in this container on 2026-11-24 (Linux, CPython 3.11, `[all]` installed).

| What | Size |
|---|---|
| Source, `src/archivey` | 169k lines in 250 modules: public modules 14k, CLI 6k, internal core 40k, backends 65k, streams and codecs 40k |
| Tests | 264k lines, about 9,700 test functions in 422 files |
| Markdown | 209k lines: `openspec/` 122k (most of it archived changes), `dev-docs/` 42k, `review/` 38k, user `docs/` 6.5k |
| CI workflows | 26 |
| Public names at the root (`__all__`) | 97, plus 28 in `archivey.formats` |
| `ArchiveyConfig` | 25 fields, plus `ExtractionLimits`, `ListingLimits`, `DecoderLimits`, `SpoolLimits`, `SalvageLimits`, `FormatPolicy`, `DiagnosticPolicy` |
| Diagnostic codes / exception classes | 49 / 22 |
| `open_archive` keywords | 11, five of them access modes: `streaming`, `pipe`, `seekable_members`, `concurrent_operations`, `salvage` |
| `extract_all` keywords | 11: `members`, `filter`, `policy`, `overwrite`, `on_error`, `on_blocked`, `abort_on`, `on_progress`, `limits`, `dry_run` |
| Lines per format | RAR 17.5k (member data goes to an external `unrar`), ZIP 13k, 7z 5.8k, TAR 5.1k. For scale: stdlib `zipfile` is 2.6k, `tarfile` 3.1k |
| Shared reader machinery | `base_reader.py` 5.9k (about 195 methods), `extraction.py` 5.6k, `format_adapter.py` 4.2k, `reader_state.py` 1.0k |
| `import archivey` | 0.28 to 0.44 s, loads 210 archivey modules |
| ZIP, 5,000 members of 100 bytes | listing 3.7× `zipfile`; reading every member 8.9× `zipfile`; open and read one member 156 ms |
| Release pace | 0.2.0 on 2026-10-22 to 0.5.1 on 2026-11-20: four minor releases in a month, 11 **Breaking:** lines in the changelog |

None of these numbers is a defect by itself. Together they describe a library that is
deep, careful and expensive to approach, both as a user and as a maintainer.

## What is strong: keep it

- **Safety is a contract, not a flag.** A threat model, specs with scenarios, a
  conformance sweep, and fuzzing at three levels. When I extracted a ZIP that holds
  `../evil.txt`, the other members were written, the bad one was refused, and the error
  carried a full per-member report. That is the right behaviour, and few libraries have
  it.
- **Container parsing in pure Python.** This is a real differentiator against libarchive,
  and isolating the native decoders that are known to crash is a disciplined answer to
  "but decompression is native".
- **Problems as data.** The error tree is small and readable (the cheat sheet shows it in
  20 lines). `ArchiveyUsageError` sits outside it and is also a `TypeError` or
  `ValueError`. Diagnostics have stable codes and a policy. This is what lets an
  application make decisions instead of parsing log messages.
- **Damaged input.** "Deliver everything recoverable, then raise" is the right rule for
  the founding use case, and it is applied across formats.
- **The plugin API exists and is used.** CPIO, ar, ISO, SquashFS, CAB, XAR, LHA, ARJ,
  RPM, makeself and the DMG stack all run on `archivey.formats`. The adapter runs the
  name checks, limits and digest checks, and a plugin cannot skip them. That is the
  right shape for an ecosystem.
- **Honest docs.** VISION says which performance bands are not met. The security page
  says what is not limited. Keep that habit through every change below.
- **Zero-dependency core.** It makes "just install it" true.

## 1. The defaults are tuned for the worst format

What a newcomer meets on an ordinary ZIP, with no options:

```python
with archivey.open_archive("a.zip") as r:
    a = r.open("one.txt")
    b = r.open("two.txt")      # ArchiveyUsageError: a member stream is already open
    a.seek(0)                  # io.UnsupportedOperation, even for a stored member
    with r.open("inner.zip") as s:
        archivey.open_archive(s, parent=r)   # StreamNotSeekableError: "pass pipe=True
                                             #  ... or copy the archive to a BytesIO"
    for m, s in r.stream_members():
        r.read("one.txt")      # ArchiveyUsageError: 'stream_members' is active
```

`zipfile` does all of these. So on the most common format, archivey is stricter than the
library it wants to replace. Each refusal has a good reason somewhere: a backward seek in
a `.tar.gz` can mean decompressing from the start, and a second stream on a solid 7z means
a second decoder. But the reader already knows which case it is in: `reader.cost`
reports `AccessCost.DIRECT` for this ZIP before anything is read.

The philosophy page gives the reason for strict defaults: "A strict default can be
relaxed later without breaking anyone's code, but a permissive one can't be tightened."
That is true, and it is also the way out. Relaxing these defaults where they cost nothing
is non-breaking by the project's own rule.

**Proposal: gate by cost, not by feature.**

- Where access is direct (ZIP, ISO, SquashFS, directory, any stored member), allow seek
  and several open streams by default.
- Where it is solid, keep today's behaviour, or allow it and record a diagnostic, as
  `SOLID_OPEN_REDECOMPRESSES` already does for out-of-order opens, with `raise_on` for
  callers who want the hard stop. The diagnostic machinery already exists for this.
- DR-5 ("same input, same outcome") is the argument against this, because the same code
  would then work on a ZIP and fail on a 7z. I think that trade is worth it: the user who
  writes "open two members" on a ZIP is the common case, and a clear error on a 7z, which
  names the flag, is a fine teacher. If DR-5 must win, the alternative is to make the
  capabilities work everywhere and let the diagnostic carry the cost.
- **Nested archives need one obvious call.** Today the caller has to know to pass
  `seekable_members=True` on the *outer* open and `parent=` on the inner one. A reader
  method, `reader.open_archive(member, **kw)`, would set the parent, carry the limits and
  pick the best source (seekable if the outer access is direct, spooled within
  `SpoolLimits` if not). DR-14 forbids convenience wrappers "for a short chain of public
  calls". This chain is not short, because it needs a flag decided before the inner
  member is known, so DR-14 should not block it. Nested archives (a JAR in a ZIP, a
  `.tar.gz` in a ZIP, `.deb` payloads, wheels, Office files) are common enough to count
  as the main path.
- Small things in the same spirit: `open_archive(b"...")` raises "unsupported source type:
  bytes"; accept `bytes` and `memoryview`. A `stream_members()` member whose fields may
  still change (`member_state_final`) is a trap for the user who does not read the
  warning box; consider yielding only final members by default, and offering the early,
  provisional ones as the opt-in for pipe users who need them.

## 2. The API surface: tier it, and merge the knobs that overlap

Each public name passed DR-13 ("a caller would use it differently"). The problem is the
total, and the fact that the beginner and the expert see the same list. Concrete moves,
cheapest before 1.0:

**Tier the root namespace.** About 20 names cover almost all code: `open_archive`,
`open_stream`, `detect_format`, `ArchiveReader`, `ArchiveMember`, `MemberType`,
`ArchiveFormat`, `ExtractionReport`, `ArchiveyConfig`, and the error tree. The rest
(`BackendKindStr`, `BackendUse`, `MissingComponent`, `PartialDataRecovery`,
`ProcessIsolation`, `RarDecompressor`, `SourceProgress`, `ARCHIVE_INTEGRITY_CODES`,
`AcceleratorMode`, `StreamCapability`, `CostReceipt` and so on) can live in
`archivey.config`, `archivey.diagnostics`, `archivey.types` and `archivey.cost` without
loss. The docs index and the IDE completion list then show the 20 names first.

**Turn the access-mode booleans into one choice.** `streaming`, `pipe`, `seekable_members`,
`concurrent_operations` and `salvage` are not independent: `pipe` implies `streaming`,
`streaming` has no effect with `pipe`, `salvage` needs a seekable file, and the return
type depends on two of them through overloads. ADR 0004 chose a bool over an intent enum.
The interactions are new evidence. Something like `access="random" | "once" | "pipe"`
covers the first two, and with cost-gated defaults (§1) the next two mostly drop out of
everyday code.

**Merge the extraction error knobs.** `on_error`, `on_blocked` and `abort_on` all answer
"what happens when something goes wrong", in three vocabularies. `policy` and
`overwrite` answer "what is allowed". One `errors=` setting with a few named values
(`"raise"`, `"report"`, `"raise_at_once"`), plus `policy` and `overwrite`, would cover the
cases I can see. Check the less common combinations against real callers before you merge.

**Give `ArchiveyConfig` profiles, and split its fields by kind.** Its 25 fields mix four
things: safety limits, per-format quirks (`zip_unflagged_fallback_encoding`,
`rar_allow_glob_member_concatenation`, which exists only because of `unrar` name masks),
performance tuning (`use_rapidgzip`, `max_read_through`, `source_read_step`) and hooks
(`on_diagnostic`, `on_source_read`). `IDEAS.md` has predefined configs as "not to be
built yet". I would build them: `ArchiveyConfig.UNTRUSTED` and `ArchiveyConfig.TRUSTED`
(and maybe `REPRODUCIBLE`, with accelerators off) are the "don't think about it" answer
to limits, and they let the many fields become expert detail. Per-format options could
move to a `format_options={ContainerFormat.ZIP: ZipOptions(...)}` mapping, which is also
how a plugin would add its own.

**Rethink `ArchiveMember` before writing lands.** It has 25 fields and 15 properties, and
it is mutable and filled in place (ADR 0007), so a member a pass yielded can change
later. A writer will want to build members, and users will hash them, store them and
share them across threads. A frozen member plus a reader-side "updates" channel, or a
frozen member with a lazily computed part, is easier to reason about. This decision
constrains the writer API, so make it before 1.0 even if writing comes later.

## 3. The common path is slow, and import is heavy

- `import archivey` takes about 0.3 to 0.4 s and loads 210 modules, because every
  backend is imported to register itself. That matters for CLIs, serverless functions,
  test suites and anything that imports archivey "just in case". The registry needs only
  each format's magic, extensions and probe to detect, so the parsers can load on first
  use. That needs one small metadata table per backend.
- Per-member cost dominates the founding use case (many members, hash each). Reading
  5,000 small ZIP members is about 9× `zipfile`, and listing is 3.7×. VISION names lazy
  `ArchiveMember` derivation as the follow-up and says it is not a release blocker. For
  "the default library" I would make it a 1.0 blocker. A user's first benchmark is
  usually "open a big ZIP and loop over it", and it decides whether they stay.
- Opening one member of a 5,000-member ZIP costs a full listing (156 ms here). That
  follows DR-8 (complete defaults) and is probably right, but the name-lookup path
  (`get`, `open(name)`) on an indexed format could skip the per-member checks for members
  it does not return. Measure it before you decide.

## 4. Architecture: one reader contract, and a register of mode axes

**Two routes are one too many.** `archivey.formats` serves about fifteen formats. The
internal `BaseArchiveReader` serves ZIP, 7z, RAR, TAR, directories and single files. The
plugin-api brief gave the reason: a 4,000-line base class with about 150 hooks cannot be a
public contract. That is right. The conclusion I draw is the reverse of keeping both: make
the public contract the only one, and let the base class become the adapter's
implementation.

- The page "What is not supported yet" for plugins lists exactly what the big four need:
  an indexed format inside a compressor, self-extracting prefixes, multi-volume sets, and
  (until plugin-passwords lands) encryption. Each item, once added for 7z or ZIP,
  becomes available to every plugin.
- Order: TAR (already planned), then 7z (solid folders, volumes, header encryption),
  then ZIP (forward and random walks, SFX, split volumes). RAR may reasonably stay
  internal, because of its external-program data path.
- Each port either shrinks the base class or shows a gap in the public API. Both
  outcomes are worth having. If ZIP cannot be expressed on the public API without a
  measured cost, that is the evidence the API needs a lower layer, and plugin authors
  will hit the same wall later.

**The shared core holds the product of many modes.** The base reader and extraction are
both near 6,000 lines because each operation has to be right for every combination of:
access mode (random, once, pipe) × seekable members × concurrent operations × partial
recovery × salvage × verification level × diagnostic policy × password provider ×
process isolation × accelerators × library policy. Each axis is defensible. Together they
are why every change touches many paths and needs many reviews.

- Keep a **register of mode axes**: one table listing every axis, who it serves, which
  tests cover its combinations with the others, and what it costs in code. A new axis
  should name one it merges or removes, or argue in the register why it can't.
- Candidates to merge or drop, from the outside: `concurrent_operations` (with
  cost-gated defaults, much of its value goes away), `recover_partial_data` (does any
  caller choose a value other than the default?), the accelerators (`rapidgzip`, `indexed_bzip2`), which bring a child
  process module of 1,355 lines and four stress and soak workflows of their own. Is the
  speedup used by anyone yet?

**Per-format size is a signal.** RAR is 17,500 lines, and its member data is decoded by
an external program. About a thousand of those lines port `unrar`'s name and mask rules
so archivey can predict what a mask selects. The `rar-synthetic-archives` change would
delete that code and the config flag that exists only for it; I would put it ahead of
new formats. More generally, when a reader is several times the size of the reference
implementation, ask what the extra code is for. Sometimes the answer will be
"hostile-input checks the reference does not have", and that is a good answer to write
down.

**Decoding has several execution strategies.** In-process native, a child process for
codecs that are known to crash, a Rust kernel or its Python twin, and accelerators. Each
one is justified. Together they make "which code decoded this byte" a hard question to
answer. The kernel switch design (one switch, the same bytes and the same errors either
way) is the right model, so hold the accelerators to the same rule.

## 5. Scope: what is over, what is missing

### Probably overboard, or at least in the wrong place

- **File-system images.** DMG (UDIF, HFS+, APFS, encrypted images), UDF, raw CD sectors
  with cue sheets, `.pkg` and `.xip`. These are file-system readers, each with a deep
  spec and a long tail of real-world quirks, maintained by one person. If users ask for
  them, fine. If not, they are the ideal first **out-of-tree plugins**: they already use
  `archivey.formats`, and moving them out would prove the plugin story, cut import time
  and shrink the review load.
- A possible shape: a **core tier** with the full guarantee and the full test matrix
  (ZIP, TAR with its compressors, 7z, RAR, ISO, the single-file formats, directories), and
  an **extras distribution** (`archivey-formats` or similar) for the rest, built only on
  the public plugin API. Users of `[recommended]` see no change, because it pulls both in.
- Deep features for narrow needs: resume indices for seeking inside gzip, bzip2 and zstd,
  salvage mode, base64 and uuencode as archive formats. Each is good work. Each also adds
  to the axes in §4. Make sure each has a user, or at least a user scenario, in
  `dev-docs/scenarios.md`.

### Missing, for "the default library"

- **Writing.** This is the largest gap. VISION puts writing last, possibly after 1.0.
  That is consistent with a "content-first reader" pitch, and inconsistent with the
  pitch at the top of VISION ("the default Python library for dealing with archives",
  "the way `requests` became the default for HTTP"). Either build a minimal writer
  before 1.0 (ZIP, and TAR with gz, xz or zst; reproducible by default), or change the
  pitch to "the default way to read archives". Writing also shapes `ArchiveMember`
  (§2), so even a post-1.0 writer needs its member model decided now.
- **A time limit.** The security page says it plainly: "Nothing limits how long an
  operation takes", and it recommends running archivey in a subprocess. DR-9a's upload
  server needs a time bound as much as a byte bound, and pure-Python decoders on crafted
  input are where the slow cases are. A `deadline=` (or a cancel token) checked at chunk
  boundaries and inside parser loops, with child-process decoders killed on expiry,
  would close the last open line of the upload-server test.
- **Async callers.** Sync-only (ADR 0005) is fine, but the upload-server audience mostly
  runs FastAPI, Starlette or aiohttp. A documented `asyncio.to_thread` / `anyio` recipe,
  and a stated guarantee about which objects are safe to hand to a worker thread, would
  cover most of them.
- **Path-style navigation** (`zipfile.Path`): `IDEAS.md` has it as an open idea. Users of
  `zipfile.Path` and of `importlib.resources`-style code will look for it.
- **Machine-readable CLI output** (`--json`). It is waiting for a member schema. That
  schema is also what a persisted index, a dedupe database and a future writer need,
  which gives a fourth reason to design it.

## 6. The plugin ecosystem: what it needs besides the API

The API itself is small and well shaped. What an ecosystem also needs:

- **A versioned contract, early.** The docs tell a plugin to pin `archivey==X.Y.Z`.
  Two plugins pinned to different exact versions cannot be installed together, so the
  ecosystem stops at the second plugin. Even while the API is experimental, give it its
  own version number (`archivey.formats.API_VERSION`, with a plugin declaring the range
  it supports), and make breaking changes to it in steps.
- **Opt-in discovery.** Explicit `register_format()` is the right trust default. But the
  CLI, and any application that wants "whatever formats are installed", needs a way to
  ask for them: `archivey.formats.load_installed(allow=[...])`, or an entry-point group
  the CLI reads when given a flag.
- **Export the test scaffolding.** archivey's real strength is its corpus sweep, its
  mutation fuzzing and its conformance checks. A plugin author gets none of them today.
  An `archivey.formats.testing` module (or a pytest plugin) that runs the conformance
  sweep, truncation and bit-flip fuzzing, and the extraction safety checks against a
  plugin and its fixtures would make "write a plugin" clearly better than "write a
  library". I think this is the strongest single lever for the extensibility goal.
- **A template.** The "Adding a format" page is 1,134 lines. A plugin template with a
  working reader, a fixture, tests already wired to the kit above and a `pyproject.toml`
  would be a better first read for most authors, with the long page as reference.
- **Proof.** No plugin exists outside this repo yet, so "easier than a separate library"
  is untested. Write one, outside the repo and against the released wheel only: WIM,
  MSI/CFB or one of the DMG pieces. Record the friction and the line count. A fresh agent
  given only the public docs is a cheap stand-in for a stranger.
- Smaller gaps that the docs already list: plugins cannot add diagnostic codes, and
  cannot be multi-volume or self-extracting. A plugin namespace for codes
  (`plugin.<name>.<code>`) would cover the first.

## 7. Process and docs: is the weight paying for itself?

The process is built to catch the errors agents make, and it does: the safety record and
the specs show it. Two costs are easy to miss, because nobody is charged for them as they
build up:

- **Complexity is now cheap to produce and still expensive to own.** An agent will
  write the 40th config field, the 50th diagnostic code and the fourth RAR fallback path
  as readily as the first, with a spec, tests and a review. Every rule in the process
  checks that a change is *correct*. No rule checks that the system as a whole stays
  *small*. Signals that point that way: four minor releases in a month with 11
  **Breaking:** lines, readers four to six times the size of the stdlib equivalents,
  and an `AGENTS.md` that has to warn that specs, handbook and docs can disagree.
- **The user docs are precise to the point of being hard to read.** `reading.md` and
  `security.md` put contract-level detail on the main path: which bytes are lost from a
  pipe, under PyPy, for which codec. For the user who "doesn't want to think about it",
  the answer is buried under the caveats. DR-22a ("a caveat in the docs is a question for
  the code") is the right rule. Apply it as a measure: count the caveats on each task
  page, and treat a rising count as a design smell, not a docs task.

Suggestions:

- **A recurring deletion review.** Commission it the way the other deep reviews are
  commissioned, with one question: what can be removed, merged or moved out of the
  core? Measure the result in lines, public names, config fields, mode axes and
  workflows.
- **Budgets that CI tracks.** The API surface file already fails on drift. Add counts
  next to it (root names, config fields, diagnostic codes, mode axes) so that growth is
  a visible decision in the PR, not a side effect.
- **A two-layer user doc.** Short task pages ("extract an upload safely", "hash every
  member", "read a nested archive") that say what to write and nothing else, and
  reference pages that hold every caveat. The cheat sheet is already close to the first
  layer.

## Questions to ask

1. **Default reader or default archive library?** That decides whether writing is a 1.0
   requirement.
2. **Who are the first hundred users, and what do they open?** Format coverage is
   currently driven by what 7-Zip reads and by the maintainer's corpus. Download counts
   for `py7zr`, `rarfile`, `libarchive-c` and `patool`, and the formats asked about on
   their issue trackers, are a cheap proxy.
3. **Which formats carry the full guarantee, and which are best effort?** One tier for
   everything means every format costs the same review and CI effort.
4. **Is uniformity of restrictions worth more than convenience on the common format?**
   (§1.) That is the DR-5 question in its sharpest form.
5. **What is the stable contract for *output*, not only for the API?** The founding use
   case builds indexes keyed on member names, sizes and digests. If a release changes
   name normalization, member order or a diagnostic code, an index built with an earlier
   release is quietly wrong. Write down which outputs are stable, and test them across
   versions.
6. **What does the plugin API promise at 1.0, and how does it evolve after?**
7. **What is the complexity budget, and who enforces it?** (§7.)
8. **What is the bus-factor plan?** What happens to plugins, and to users of the safety
   contract, if the maintainer steps away for six months?
9. **Is "AI-written" plus "safe" credible without an independent human audit?** Users
   in security-sensitive places will ask. One external audit of the extraction path and
   the ZIP, TAR and 7z parsers, published, would answer more doubts than any amount of
   process documentation.
10. **Where must archivey run?** Pyodide, AWS Lambda, sandboxes that forbid
    `subprocess`, containers without `/dev/shm`, free-threaded builds. Pure Python is an
    advantage in Pyodide, where child-process isolation and `unrar` do not exist. Decide
    which of these are supported and test them.

## Unknown unknowns

Areas where I expect surprises, because nothing I read covers them fully:

- **Supply chain, once it is the default extractor.** A library that every pipeline
  uses to unpack untrusted data is a high-value target. Trusted publishing, build
  attestations, signed tags, OSS-Fuzz onboarding (VISION says it is not done yet), and a
  policy for the CVE pins on optional dependencies (`pyppmd`, `brotli` and others).
- **Upstream fragility.** Several optional dependencies are capped or floored for
  correctness or CVEs. Each cap is a future conflict in a user's environment. Know which
  ones would break an install, and have a plan for each.
- **RAR in practice.** Linux distributions often ship `unrar-free` or `unar` rather than
  RARLAB `unrar`, Windows users rarely have either on `PATH`, and the RARLAB licence
  limits redistribution. Find out what share of users can actually read RAR data in their
  real environment.
- **Behaviour against producers over time.** New 7-Zip, WinRAR and macOS releases
  change what they write. The corpus is a snapshot. A scheduled job that builds fixtures
  with the current tool versions would show drift before users do.
- **Child processes in strange hosts.** `fork` after threads, `spawn` start-up cost on
  macOS and Windows, signal handling, process limits in containers, and frameworks that
  forbid child processes. Process isolation is a safety feature, so its failure modes are
  part of the safety story.
- **Mutable members across threads.** With `concurrent_operations=True` and members
  that are updated in place, which reads are safe? (§2.)
- **What users do with the reports.** `ExtractionReport`, `MemberListReport`,
  `VerifyReport` and `DiagnosticSummary` are rich. Most callers will ignore them. Check
  that ignoring them is still safe, and that the default printout is useful (the
  `repr` of one `ExtractionResult` is about 700 characters).

## Suggested order

1. **Before the API freezes (cheap now, impossible later):** cost-gated defaults and a
   nested-archive method (§1); fewer access-mode flags, merged extraction error knobs,
   root namespace tiers, config profiles (§2); the `ArchiveMember` mutability decision
   (§2, §5).
2. **Architecture:** port TAR, then 7z, then ZIP onto `archivey.formats`; bring
   `rar-synthetic-archives` forward; start the register of mode axes (§4).
3. **Ecosystem:** a versioned plugin contract, the exported test kit, a template, one
   plugin outside the repo, and a decision on moving the file-system images to an extras
   distribution (§5, §6).
4. **Performance:** lazy backend imports and per-member cost as 1.0 blockers (§3).
5. **Scope decision:** writing, and the time limit (§5).
6. **Process:** the deletion review and the CI budgets (§7).

## What this review did not do

- No bug hunt. The flows run by hand were chosen to show the experience, and nothing
  here claims a defect.
- The earlier reviews in `review/` were not read, by request. Some points (the
  access-mode flags, the extraction error knobs, writing) may have recorded decisions.
  Where they do, read this as "this is how the decision looks from outside", not as a
  new finding.
- The numbers come from one Linux container and a synthetic 5,000-member ZIP. They show
  the order of magnitude, not a benchmark.
