# 10. Decisions and why

**In one minute.** archivey's shape comes from a short list of principles and a few large
decisions. The two firm principles are: never hand back wrong or incomplete data without
raising on a plain full read, and never let an archive cause unbounded memory or a crash.
Most large decisions follow from them: archivey parses every container format itself
instead of wrapping `zipfile`, `tarfile`, `py7zr` or `rarfile`; native codecs that can
crash run in a child process; every cost has a public limit; costly abilities (seeking,
concurrency) are off until asked for. This page tells the story behind each one and points
to where it is recorded. It does not restate the rules: those live in
[`design-rules.md`](../design-rules.md) and the [ADRs](../decisions/index.md), and they win
if this page disagrees.

## The principles

The maintainer summarized what he weighs most on 2026-10-09; the
[principles section](../design-rules.md#the-principles) of `design-rules.md` has his
words. In short:

| | Principle | What it rules out |
| --- | --- | --- |
| Firm | 1. No wrong or incomplete data without raising on a straightforward full read | A "best effort" read that quietly returns bad bytes. The one exception is data nothing can check (no checksum anywhere); then archivey says so with `DIGEST_UNVERIFIABLE` |
| Firm | 2. No unbounded memory, no crash | "Only a crafted archive hits it" as an excuse. The test is a server that lets anyone upload an archive to be scanned ([DR-9a](../design-rules.md#dr-9a-the-upload-server-test)) |
| Default | 3. No surprises for users | A default that works on ZIP and fails on TAR |
| Default | 4. Easy to use and to explain, for people and agents | Options that need a paragraph to use right |
| Default | 5. The same behaviour across formats and libraries | A field that means one thing in ZIP and another in 7z |
| Default | 6. Follow the format's official tool | Inventing semantics where `unrar` or GNU `tar` already decided |
| Default | 7. Generalise a fix to every format | Fixing a bug in one backend when four have it |

"Firm" means nothing outranks them. The others are strong defaults, and whether one wins
depends on the case. Principles 5 and 6 conflict often enough that `design-rules.md` has a
section on weighing them
([When consistency and the official tool disagree](../design-rules.md#when-consistency-and-the-official-tool-disagree)).

The numbered rules (DR-0 to DR-25) are these principles applied to recurring kinds of
question. When you are about to ask "should this raise or warn?" or "should this be a
config field?", the answer is usually already a DR with rulings under it.

## Native parsers for every format

The biggest decision, made four times: archivey reads the structure of ZIP, TAR, 7z and
RAR with its own pure-Python parsers. The standard library and the popular packages stay
in the test suite as **oracles** (a second opinion the tests compare against), never in
`src/`.

Each time the reason was the same: a wrapped library decides things archivey has to
control, and a wrapper can only react after the library has already lost the fact it
needed.

| Format | Library dropped | What it could not do | Record |
| --- | --- | --- | --- |
| 7z | `py7zr` | Reading a solid folder member by member led to caching and re-decoding per member, so "hash every member" became intractable; its quirks leaked into the shared contract | ADR [0001](../decisions/0001-native-7z-not-py7zr.md) |
| RAR | `rarfile` | It tied listing to its decompressor stack and did not fit the streaming and cost model. RAR decompression is proprietary, so member data still comes from RARLAB's `unrar` program | ADR [0002](../decisions/0002-native-rar-metadata-unrar-data.md) |
| ZIP | `zipfile` | It parsed the whole central directory at open, before `ListingLimits` saw one member; one bad entry made the archive unlistable; some malformed shapes gave different results on different Python versions; archivey had to reach into private names and match exception text | ADR [0020](../decisions/0020-native-zip-reader.md) (supersedes [0006](../decisions/0006-stdlib-zipfile.md)) |
| TAR | `tarfile` | About 650 of the backend's 1,810 lines were workarounds, 7 of them on private API. It could serve sparse padding as data (DR-1), read extended headers whole and recurse on header chains (DR-9), and one 2.5 KiB archive listed three members on Python 3.12.13 and two on 3.12.3 (DR-5) | ADR [0021](../decisions/0021-native-tar-reader.md) |

The TAR case is the clearest lesson. The wrapper grew one hook at a time, each one
reasonable, until most of the backend existed to fight the library, and the hooks were on
private functions that distributions backport changes to. So the version number alone did
not tell you which answer a caller would get.

Writing parsers in Python also matters for security: a crafted header can make a Python
parser compute a wrong value, but not overwrite memory
([DR-20](../design-rules.md#dr-20-parse-in-python-isolate-native-code-that-can-crash),
[page 8](08-security.md)). The cost is speed, which the codec layer (native `zlib`,
`lzma`, `bz2`) and the accelerators mostly recover, since headers are a small share of the
work.

## Native code that can crash goes in a child process

A codec library written in C or C++ can kill the interpreter on bad input. archivey's
rule is to measure each library on damaged input and either design around a known crash or
run the library in a child process
([DR-20](../design-rules.md#dr-20-parse-in-python-isolate-native-code-that-can-crash)).

- **PPMd** (pyppmd) could segfault when asked to decode again after a corrupt stream
  ended early. The first fix (PR 481) kept small members in the process under a careful
  call order and sent members over 16 MiB to a child. On 2026-10-20 that was reversed:
  every PPMd member now decodes in a child, because the safe call order held only by
  measurement, not by a rule anyone could check
  (ADR [0022](../decisions/0022-ppmd-always-in-a-child-process.md)). The cost is about
  75 ms of start-up per child, which dominates small members.
- **rapidgzip** called `std::terminate` on a truncated gzip, so it moved to a child
  process (PR 493); see [page 11](11-bugs-and-lessons.md#rapidgzip-killed-the-process-then-lost-bytes)
  for what came after.
- **`multiprocessing` is not used.** Its spawn mode re-imports the caller's `__main__` and
  reports neither stderr nor the exit status, so each child is a plain subprocess running
  a small standalone worker script (ADR 0022).

## Zero dependencies, one accelerator, sync only

- **Zero-dependency core** (ADR [0011](../decisions/0011-zero-dependency-core.md)).
  `pip install archivey` installs nothing else. Every optional library comes through a
  named extra (`[recommended]`, `[seekable]`, …), and `unrar` is a system program needed
  only for RAR member data. This is why the registry tracks availability separately from
  registration ([page 5](05-formats-and-plugins.md#the-registry-which-code-reads-which-format)).
- **One accelerator library** (ADR [0008](../decisions/0008-single-accelerator-rapidgzip.md)).
  `rapidgzip` and `indexed_bzip2` ship overlapping C++ cores, and loading both in one
  process corrupted the heap on macOS. archivey uses only `rapidgzip`, for gzip and bzip2
  alike.
- **zstd from the standard library** (ADR [0009](../decisions/0009-zstd-stdlib-backports.md)):
  `compression.zstd` on Python 3.14+, `backports.zstd` before that, not `zstandard`.
- **Synchronous API** (ADR [0005](../decisions/0005-sync-only-v1.md)). Every decoder pulls
  bytes synchronously, and an async wrapper over blocking calls would mislead. Code on an
  event loop uses `asyncio.to_thread`.

## Defaults: complete, consistent, and costly things opt-in

Two rules pull against each other and together give archivey's defaults their shape.

- **Defaults are complete** ([DR-8](../design-rules.md#dr-8-defaults-are-complete-and-consistent-laziness-is-an-explicit-opt-in)).
  The maintainer's wording (2026-09-23): a default should be "as lazy as possible while
  providing full info and consistency". A field filled on some formats and empty on
  others "is a recipe for bugs". This is why `read_link_targets` defaults to `True`, and
  why a seekable ZIP read with `streaming=True` still reads the central directory first.
- **Costly or risky abilities are declared**
  ([DR-10](../design-rules.md#dr-10-costly-or-risky-capability-is-declared-and-a-declaration-is-a-guarantee)).
  Seekable member streams, several open streams at once, accelerators and external
  programs are off until named, and once named they are a guarantee on every format, not
  "where the backend can". ADR [0003](../decisions/0003-member-streams-opt-in.md) gives the
  reason: an always-seekable API lets a developer test on ZIP and ship a failure on TAR.

The second rule extends to cheap cases on purpose: `streaming=True` refuses an
out-of-order read on ZIP too, although ZIP could serve it, so the mistake shows on the
first archive tested (2026-09-29, [DR-5](../design-rules.md#dr-5-same-input-same-outcome)).
[Page 7](07-pipes-and-files.md) follows these switches through every format.

## The same archive gives the same result

[DR-5](../design-rules.md#dr-5-same-input-same-outcome) lists the axes that must not
change the outcome: the format, the access mode, the operating system, accelerators, the
entry point, and when or where a call is made. Two rulings show how far it goes:

- **Streaming and random access end up the same on disk** "unless there's a strong reason
  that makes it impossible" (2026-09-25). This drove the ZIP-from-a-pipe design, where
  extraction waits for the central directory before it places members
  ([page 7](07-pipes-and-files.md)).
- **Auto-detection and a forced format must list the same contents** (maintainer,
  2026-11-07, on PR 1303). Accelerators are the only accepted exception, for one crafted
  shape ([DR-5a](../design-rules.md#dr-5a-malformed-corner-cases-may-differ-a-little)).

DR-5a is the release valve: for a malformed shape that only a crafted archive produces, a
format may keep its own behaviour if matching would need real plumbing. It never relaxes
the two firm principles.

## Every cost has a public limit

[DR-9](../design-rules.md#dr-9-every-cost-is-bounded-by-a-public-raisable-limit) says
every bound is a field on a public limits object, with an escape hatch, so a user with a
legitimately huge archive can always raise it. Default values are the maintainer's call;
implementation constants (a cache size) are the implementer's. Some of the numbers and
their reasons:

- **Decoder memory 2 GiB.** First "1GB so that real files always decode fine"
  (2026-09-19), later 2 GiB.
- **`max_members` 262,144, key derivation 2^25 rounds** (2026-10-07), after measuring
  per-member listing cost. They replaced 1,048,576 and 2^27.
- **`max_ratio` 800** (2026-10-30). Deflate's ceiling is about 1032:1, so a gzip of zeros
  lands between about 1003 and 1032:1. A limit of 1000 refused it only sometimes; 800
  refuses it every time, as zeros are refused in every other codec. On the same day the
  ratio moved from `ExtractionLimits` to `DecoderLimits`, because it now holds every
  decode (listing a `.tar.gz`, reading a member), not only extraction. The bzip2 bomb that
  prompted this was blocked in one spelling (`.tar.bz2`) and open in three others (ZIP,
  7z, bare `.bz2`).

## The official tool, and when it loses

[DR-6](../design-rules.md#dr-6-when-the-semantics-are-open-match-the-formats-official-tool)
makes the format's reference tool the tie-breaker: `unrar` for RAR, GNU `tar` for TAR,
7-Zip for 7z, `bzip2`/`xz`/`zstd` for their streams. Hard links resolve to earlier members
only, as `unrar` and `tar` do; absolute names re-root inside the destination, as every
mainstream extractor does. ZIP and ISO have no single official tool, an open question
since 2026-10-02.

The tool loses when its answer is useless or unsafe. Device and FIFO entries with no data
are `OTHER` in every format, although `unzip` and 7-Zip write empty files: "they're useless
as files" (2026-10-06). Leftover compressed bytes inside a ZIP member raise, as 7-Zip does,
although `unzip` accepts some of them, because the lenient answer could hide bytes.

## Fewer entry points

- **No top-level `archivey.extract()`** (ADR [0019](../decisions/0019-no-top-level-extract.md),
  2026-10-06). The one-call function could not behave exactly like `open_archive()` then
  `extract_all()`: no `members=` or `filter=`, a different diagnostics scope, and it opened
  a pipe in streaming mode by itself where `open_archive()` refuses. Two lines instead of
  one was judged cheaper than explaining every difference.
- **Usage errors outside `ArchiveyError`** (ADR [0012](../decisions/0012-usage-errors-outside-archiveyerror.md)),
  so `except ArchiveyError:` around untrusted input never hides a bug in the caller
  ([page 9](09-errors-and-diagnostics.md#why-archiveyusageerror-is-outside-the-tree-adr-0012)).
- **Verdicts from reads, never from `close()`** (ADR [0014](../decisions/0014-integrity-verdicts-from-reads-not-close.md)).
- **`streaming: bool`, not an intent enum** (ADR [0004](../decisions/0004-streaming-bool-not-intent-enum.md)).
  An `Intent` with an `AUTO` value was dropped in favour of a plain switch whose effect a
  caller can predict.

## Extraction: sanitize, refuse only what is unsafe

- **Names that cannot be written on this OS are renamed, not refused**, under STRICT and
  STANDARD (ADR [0013](../decisions/0013-cross-platform-name-safety-policies.md)).
  Refusing would force a Linux user to switch to TRUSTED, a permissions decision, just to
  extract a backup with an odd name.
- **Bidi override characters are refused by policy, not always**
  (ADR [0017](../decisions/0017-bidi-override-rejection-is-policy-keyed.md)): TRUSTED
  writes the name as stored.
- **A zero-filled file is a valid empty TAR**, reported and never refused
  (ADR [0015](../decisions/0015-zero-filled-files-are-valid-empty-tars.md)), because
  `tar -b 64` writes one.

[DR-17](../design-rules.md#dr-17-extracting-beats-refusing-refuse-only-what-is-unsafe) and
[DR-18](../design-rules.md#dr-18-extraction-never-damages-what-it-did-not-create) are the
rules behind these.

## Where rulings are recorded

| Kind of decision | Where to look |
| --- | --- |
| A principle or a rule that applies across formats | [`design-rules.md`](../design-rules.md), with rulings dated under each rule |
| A large, lasting architectural choice | [`decisions/`](../decisions/index.md) (ADRs) |
| A choice specific to one format | §6 of that format's handbook page in [`formats/`](../formats/) |
| A residual security risk accepted on purpose | [`threat-model.md`](../threat-model.md) §4 |
| The design of a feature, with alternatives weighed | `openspec/changes/archive/` |
| What still goes to the maintainer | [`design-rules.md` §What still goes to the maintainer](../design-rules.md#what-still-goes-to-the-maintainer) |

A ruling keeps its decider, its date and its reason, and says what would reopen it
([DR-22](../design-rules.md#dr-22-docs-say-what-is-true-now-with-reasons)). Reversing one
needs a new argument, not a restatement of the old one.
