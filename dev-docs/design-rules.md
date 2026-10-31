# Design rules

These are the rules the maintainer has applied, again and again, when settling a design
question. They exist so that most questions get settled by a rule instead of by a new
question to the maintainer. Each rule says what it is and the rulings it was derived
from. Most also say why it holds and what would reopen it; a rule without a "Reopen if"
has no known reason to reopen yet, so bring new arguments if you want to.

Use this page before you ask. If a rule here settles the question, do what it says and
name the rule in the pull request ("settled by DR-7"), so the maintainer can still object.
If the question is a
[clash between consistency and the official tool](#when-consistency-and-the-official-tool-disagree)
that the factors do not settle, or is on the
[escalation list](#what-still-goes-to-the-maintainer), ask.

Where these rules come from: maintainer rulings in pull requests, ADRs, handbook pages
and the project's decision threads, collected in October 2026. VISION.md stays the
product tie-breaker; these rules are how its priorities have been applied in practice.
Format-specific rulings stay on their handbook pages (`dev-docs/formats/`); this page
holds only what has generalised across formats.

To test a question against concrete callers, use [`scenarios.md`](scenarios.md): who we
imagine using archivey and what would hurt each of them.

## Index

One line per rule, to find the one that applies. The rule text below is what
binds.

- [DR-0](#dr-0-fix-the-class-not-the-instance). **Fix the class, not the instance.** A bug
  in one format is a question about every format and shared path.
- [DR-1](#dr-1-a-wrong-answer-is-the-worst-failure). **A wrong answer is the worst
  failure.** Reported absence beats a refusal, a refusal beats silent loss, and a wrong
  value is worst.
- [DR-2](#dr-2-deliver-everything-recoverable-then-raise). **Deliver everything
  recoverable, then raise.** On damage, deliver every intact member, then raise at the
  point of damage.
- [DR-3](#dr-3-hidden-bytes-are-errors-inside-a-member-warnings-outside-it). **Hidden
  bytes are errors inside a member, warnings outside it.** Leftover bytes inside a
  member's data are corruption; outside it, a warning.
- [DR-4](#dr-4-unsupported-is-not-corrupt). **Unsupported is not corrupt.** A valid
  feature archivey cannot decode is `UnsupportedFeatureError`, not corruption.
- [DR-4a](#dr-4a-the-integrity-guarantee-is-for-a-start-to-end-read). **The integrity
  guarantee is for a start-to-end read.** Integrity checks are promised for a start-to-end
  read with no skipped bytes; a read after a seek that jumps gives the digest up.
- [DR-5](#dr-5-same-input-same-outcome). **Same input, same outcome.** One archive gives
  one result across formats, access modes, sources and OSes, and a call that works once
  works every time.
- [DR-5a](#dr-5a-malformed-corner-cases-may-differ-a-little). **Malformed corner cases may
  differ a little.** A malformed, crafted-only shape may keep per-format behaviour when
  matching costs code.
- [DR-6](#dr-6-when-the-semantics-are-open-match-the-formats-official-tool). **When the
  semantics are open, match the format's official tool.** For an open format-specific
  question, test the reference tool and match it.
- [DR-7](#dr-7-trust-self-validating-data-over-caller-hints). **Trust self-validating data
  over caller hints.** Use what the archive can verify; a caller hint fills only the gap.
- [DR-8](#dr-8-defaults-are-complete-and-consistent-laziness-is-an-explicit-opt-in).
  **Defaults are complete and consistent; laziness is an explicit opt-in.** Defaults give
  full, consistent information; a cheaper partial behaviour is an opt-in.
- [DR-9](#dr-9-every-cost-is-bounded-by-a-public-raisable-limit). **Every cost is bounded
  by a public, raisable limit.** Every resource bound is a public, raisable limit, checked
  before the cost is paid.
- [DR-9a](#dr-9a-the-upload-server-test). **The upload-server test.** No archive may cause
  unbounded memory or disk, an unbounded hang, or a crash.
- [DR-10](#dr-10-costly-or-risky-capability-is-declared-and-a-declaration-is-a-guarantee).
  **Costly or risky capability is declared, and a declaration is a guarantee.** A costly
  or risky capability is off until asked for, and then guaranteed.
- [DR-10a](#dr-10a-read-sequentially-seek-only-when-the-format-needs-it). **Read
  sequentially; seek only when the format needs it.** Read forward in few large reads;
  seek only where the format needs it.
- [DR-11](#dr-11-environment-trouble-falls-back-explicit-requests-fail-loudly).
  **Environment trouble falls back; explicit requests fail loudly.** An `AUTO` choice
  falls back on environment trouble; an explicit request fails loudly.
- [DR-12](#dr-12-before-the-first-release-remove-rather-than-keep). **Before the first
  release, remove rather than keep.** Applied until 0.2.0; DR-12a replaced it.
- [DR-12a](#dr-12a-after-the-first-release-deprecate-before-removing). **After the first
  release, deprecate before removing.** A removal or rename warns for one minor release;
  a break that can't be phased in gets a **Breaking:** changelog line.
- [DR-13](#dr-13-a-public-name-earns-its-place). **A public name earns its place.** A
  public name or exception type exists only if a caller would use it differently.
- [DR-14](#dr-14-one-obvious-way-and-one-mechanism-per-job). **One obvious way, and one
  mechanism per job.** No convenience wrapper for a short chain of public calls; one
  mechanism per job.
- [DR-14a](#dr-14a-easy-to-explain-easy-to-use-right-the-first-time). **Easy to explain,
  easy to use right the first time.** Between designs that meet principles 1 and 2, pick
  the easier to explain and use.
- [DR-15](#dr-15-usage-errors-are-for-what-the-types-cannot-rule-out). **Usage errors are
  for what the types cannot rule out.** A wrong argument raises an `ArchiveyUsageError`
  that is also a `TypeError` or `ValueError`; a plain `ArchiveyUsageError` is for misuse
  the signature cannot express.
- [DR-15a](#dr-15a-translate-archive-problems-let-io-problems-through). **Translate
  archive problems; let I/O problems through.** Archive-content errors become archivey
  errors; I/O failures pass through.
- [DR-15b](#dr-15b-fail-at-open-but-do-no-expensive-work-there). **Fail at open, but do no
  expensive work there.** Raise a cheap-to-detect problem at open, but do no work
  proportional to the archive there.
- [DR-16](#dr-16-a-feature-must-deliver-its-promise). **A feature must deliver its
  promise.** An advertised capability works in every format that claims it, or the format
  says it does not.
- [DR-17](#dr-17-extracting-beats-refusing-refuse-only-what-is-unsafe). **Extracting beats
  refusing; refuse only what is unsafe.** Refuse a member only when writing it is unsafe
  or the outcome differs by OS.
- [DR-18](#dr-18-extraction-never-damages-what-it-did-not-create). **Extraction never
  damages what it did not create.** Extraction never changes or removes what it did not
  create.
- [DR-19](#dr-19-prefer-one-structural-invariant-over-many-string-checks). **Prefer one
  structural invariant over many string checks.** Replace several ad-hoc checks for one
  hazard with one structural invariant.
- [DR-20](#dr-20-parse-in-python-isolate-native-code-that-can-crash). **Parse in Python;
  isolate native code that can crash.** Parsers are pure Python; a native codec that can
  crash runs in a child process.
- [DR-21](#dr-21-defer-a-fix-that-a-planned-rewrite-absorbs-and-document-it). **Defer a
  fix that a planned rewrite absorbs, and document it.** A fix that a planned rewrite
  absorbs waits for it, documented meanwhile.
- [DR-21a](#dr-21a-dont-ship-what-cant-be-tested). **Don't ship what can't be tested.**
  Refuse and document a case no tool can produce and archivey cannot test.
- [DR-22](#dr-22-docs-say-what-is-true-now-with-reasons). **Docs say what is true now,
  with reasons.** Docs say what is true now, with reasons.
- [DR-22a](#dr-22a-a-caveat-in-the-docs-is-a-question-for-the-code). **A caveat in the
  docs is a question for the code.** Before writing a caveat, ask whether the code can
  change instead.
- [DR-23](#dr-23-zero-debt-in-the-code-you-touch). **Zero debt in the code you touch.**
  Leave no debt in the code you touch; existing code is no justification.
- [DR-23a](#dr-23a-share-what-must-agree-copy-what-agrees-by-coincidence). **Share what
  must agree; copy what agrees by coincidence.** If one copy changes, must the other? If
  yes, share it.
- [DR-24](#dr-24-tests-pin-behaviour-against-real-producers). **Tests pin behaviour
  against real producers.** A bug fix starts red; tests check behaviour against fixtures
  from real tools.
- [DR-25](#dr-25-type-comes-from-structure-data-decides-when-structure-is-silent)
  (in §Consistency). **Type comes from structure; data decides when structure is
  silent.** A mode attribute never
  overrides a format's directory marker or typeflag; an entry with a data stream and no
  structural type is `FILE`; bytes extraction does not deliver are reported and stay
  readable.

## The principles

The maintainer's own summary of what he focuses on consistently (2026-10-09, in his
words). He then asked for the two he weighs most to go first, and proposed principle 4 as
a further test ("useful or redundant?"), which this page adopts. The split into "firm"
and "strong defaults", and the order within the strong defaults, are this page's reading,
not his ranking. Every numbered rule below is one of these applied to a kind of
question.

**Firm.** No other principle outranks these, and "only crafted archives hit it" is no
excuse.

1. **Never output incorrect or incomplete data without raising on a straightforward full
   read** (DR-1, DR-2, DR-4a). The one exception is data that is unknowable: the format
   carries no checksum or check value and the stream does not validate itself, so
   nothing can tell good bytes from bad. Then archivey says so with a diagnostic
   (`DIGEST_UNVERIFIABLE`) instead of implying the bytes were checked (maintainer,
   2026-10-09).
2. **Unbounded memory or crashes are never acceptable.** An attacker crafts archives at
   will and will choose the loopholes. The test: if a server lets anyone upload an
   archive to be tested, scanned or have its members hashed, could an upload bring the
   server down? (DR-9a).

**Strong defaults.** Whether these win depends on the case.

3. **No surprises or gotchas for users** (DR-8, DR-10).
4. **Easy to use and to explain, for people and for agents.** Archivey aims to be the
   default library for archives in human- and agent-written code. Using it should take
   little work, few tokens and no detours during development. The test is "don't make me
   think": which option is easiest to explain and to use correctly the first time?
   (DR-14a).
5. **Consistent behaviour between formats and libraries** (DR-5). This can be relaxed a
   little for malformed data, particularly for a corner case so specific that only
   crafted archives hit it (DR-5a).
6. **Follow the official tool's behaviour** (DR-6). When this and principle 5 conflict,
   that needs a real decision. The factors below settle the clear cases; the rest go to
   the maintainer.
7. **Generalise fixes and approaches across all formats** (DR-0).

The numbered rules below work the same way as the strong defaults: a rule settles a
question when the case looks like the rulings it came from, and a case that differs in
an important way goes back to the maintainer.

## Generalise

### DR-0. Fix the class, not the instance

**Rule.** A bug found in one format is a question about every format and every shared
path. Before fixing it, check whether the other formats have the same problem, and put
the fix in the shared path when there is one. A ruling on one case is a prompt to sweep
for the rest of its class.

**Why.** Every time the maintainer asked "does this affect other formats?", the answer
was yes. A cross-format check of recent format-specific bugs found 20 more
(2026-10-06), and a cross-OS check found 13 gaps.

**Rulings.** RAR password lists moved into the shared `password_confirm` logic so every
format benefits (2026-10-06, PR 627). The Windows drive-letter link refusal covers ZIP,
7z and RAR alike (PR 620). Junk after the archive end is reported in every container,
not only TAR (2026-10-07).

---

## When consistency and the official tool disagree

Neither wins by default; it depends on the case. Weigh these factors. When they all
point the same way, follow them and say so in the pull request. When they split, ask the
maintainer, with what each format's tool does, what the other formats do, and how each
factor came out.

- **Is the tool's result useful?** If it is useless to a caller, consistency wins. Device,
  FIFO and socket entries with no data are `OTHER` in every format, although unzip and
  7-Zip write them as empty files: "they're useless as files" (2026-10-06, PR 610). An
  entry whose mode says FIFO but which carries data is a `FILE`, because its bytes are
  the content and unzip, 7-Zip, bsdtar and `zipfile` all write them out (2026-10-10,
  DR-25; applied by PR 730).
- **Would the tool's result break a promise archivey makes?** Principles 1 and 2, and the
  policy levels' promises, come first. A 7z name holding a lone UTF-16 surrogate lists
  the way 7-Zip does, but is refused under STRICT and percent-escaped under STANDARD, which
  both promise the same result on every OS (ADR 0013 amendment, 2026-10-31). TRUSTED, the
  faithful level, writes 7-Zip's bytes (PRs 564 and 577).
- **Could the lenient behaviour hide bytes or weaken a check?** Then the stricter side
  wins. Leftover compressed input inside a ZIP or 7z member raises, as 7-Zip does, though
  unzip accepts some of it (2026-10-07).
- **Does only a crafted archive reach the case?** Then prefer the answer that needs the
  least code (DR-5a), within principles 1 and 2.
- **Would matching need plumbing across layers?** For a rare case, that weighs against
  matching. U+DC80 to U+DCFF surrogates keep archivey's one-byte meaning instead of
  7-Zip's bytes (2026-10-03, PR 564).
- **Would users compare the two results directly?** Extraction output on disk is compared
  with the tool's far more often than a diagnostic's wording. Where the comparison is
  likely, the tool's behaviour weighs more.

---

## Correctness and damaged input

### DR-1. A wrong answer is the worst failure

**Rule.** Rank outcomes: reported absence (a field is `None`, a diagnostic says why) is
better than a refusal, a refusal is better than silent loss, and silent loss is better
than wrong data. Never truncate, clamp or guess to produce a value. Verify before
serving bytes whenever a stored digest makes that possible.

**Why.** A caller can act on an error or a `None`. A caller cannot detect a wrong value.

**Unknowable data.** When the format gives nothing to check against (no stored digest,
no check value, a codec that does not validate its own stream), a wrong value cannot be
detected by anyone, so it is not a breach of this rule. What would be a breach is
staying silent where a check normally exists and was skipped. Emit
`DIGEST_UNVERIFIABLE`, with a `reason`, whenever a member's bytes reach the caller
unchecked although the caller would expect them checked. Example: 7z AES with stored
data and no CRC, where a wrong password yields garbage
(`reason="no_integrity_anchor"`). A format or codec that never carries a checksum
(plain TAR, legacy LZ4) says so once in the user docs (`docs/formats.md`) rather
than with a diagnostic on every member.

**Rulings.**
- An over-long symlink target is left unset with `SYMLINK_TARGET_UNAVAILABLE`, never
  truncated (2026-09-23, PR 412).
- A cut-short RAR5 extra area: the member still lists, but its stored bytes are checked
  against a surviving digest before any are returned (2026-09-22, PR 401).
- The RAR5 encryption record stays fatal: a member shown as plaintext would be a wrong
  answer (PR 371, `formats/rar.md` §6).
- `created` never holds a change time in any format (DR-5).
- Streams raise rather than clamp an over-long read (CONTRIBUTING §Coding standards).
- A ZIP central entry whose name, extra or comment runs past the directory, swallows
  the entries after it or is shortened is damage: members list from their local
  headers, then `CorruptionError`, from a file as from a pipe. This supersedes the
  cut-and-warn rule (2026-10-17, davi, PR 860, `formats/zip.md` §6).

**Reopen if** a case appears where the only alternative to a guess is refusing data that
real tools read correctly; then the guess must be reported as a diagnostic, not silent.

### DR-2. Deliver everything recoverable, then raise

**Rule.** On damage, list and read every member that is intact, then raise a typed error
at the point of damage. Never fail the whole open for a defect that only affects later
members. `extract_all` writes the members before the damage, then raises.

**Why.** The founding use case is decades of messy backups (VISION). Every official tool
recovers what it can and reports the rest.

**Rulings.**
- A RAR set whose last volume is missing lists every member in the present parts; a
  member that runs into the gap raises `TruncatedError` (2026-10-06, PR 611). A missing
  middle volume: "read past the gap. list everything in all available parts, then raise
  at the end". A set opens from any present part, including when part 1 is missing
  (2026-10-06).
- A listing that ends in damage: every format writes the prefix, then raises
  (2026-10-03, PR 562).
- A cut plain RAR header lists the members before the cut, then raises (PR 541).

**Reopen if** recovering past a defect would require trusting data that cannot be
verified (DR-1 wins).

### DR-3. Hidden bytes are errors inside a member, warnings outside it

**Rule.**
- Leftover compressed input inside a member's declared data is a `CorruptionError` by
  default. rapidgzip on a DEFLATE member is the one exception, for a long second stream
  (DR-5a).
- Bytes after the end of an archive or stream are reported as `ARCHIVE_TRAILING_DATA`: a
  warning by default, refused under strict.
- Zero padding is silent.
- Data declared by an entry that has no content of its own (a directory) is not member
  data that was misread, so it takes the outside weight: a diagnostic in
  `ARCHIVE_INTEGRITY_CODES`, a warning by default, refused under strict, with the bytes
  still readable through `open()` (DR-25).
- Damage to trailing structure that does not affect member data (an end block, an
  optional header record) becomes a diagnostic in `ARCHIVE_INTEGRITY_CODES`, so the
  default lists everything and strict refuses.

**Why.** Extra bytes are where a polyglot hides a second file, and inside a member they
could act as a side channel ("raising by default and refusing for strict seems
correct", 2026-10-07). Outside the member data nothing is misread, so 7-Zip's warning is
the right weight.

**Rulings.**
- ZIP and 7z members whose decoder finishes before the declared compressed size raise,
  matching 7-Zip, fixed before 0.2.0 (2026-10-07).
- Junk after ZIP, 7z, RAR and ISO archives is reported like TAR's (2026-10-07).
- A RAR end block with a bad CRC keeps the listing (2026-10-03, PR 561); a damaged second
  TAR end block keeps it too, with `ARCHIVE_EOF_MARKER_MISSING` (2026-10-06, PR 614).
- A malformed optional RAR header record is dropped with `MEMBER_HEADER_RECORD_SKIPPED`
  (PR 371).
- A zero-filled file is a valid empty TAR (ADR 0015).
- A directory entry that declares data keeps the directory on disk, reports
  `MEMBER_DIRECTORY_DATA_IGNORED` (a warning; strict refuses) and keeps the bytes
  readable through `open()` (2026-10-10, DR-25): nothing is misread, so this is the
  "outside a member" weight, and the ZIP spec forbids the shape (APPNOTE 4.3.8).
  Applied by PR 731 for ZIP and RAR and by PR 763 for TAR (an old-style `d/` file
  entry with data). `stream_members()` yields a stream of the same bytes for such a
  directory in every format, so a forward-only reader reaches them too (2026-10-17),
  except a bit-3 ZIP directory read from a pipe, whose size comes after its data.
- A TAR symlink or hard link header that declares data lists as a link, its declared
  blocks are skipped so the members after them stay listed, and
  `MEMBER_LINK_DATA_IGNORED` reports it (a warning; strict refuses), with the weight
  of the directory case (2026-10-17, "skip and report"). A member header right after
  the link header means the size names no data: nothing is skipped, as for a `DIRTYPE`
  header with a size (PR 763), and both are reported with `MEMBER_HEADER_AMBIGUOUS`
  (`size_on_no_data`; 2026-10-30, as no real writer puts a size there).

**Reopen if** a real producer writes the extra bytes routinely (then check DR-6).

### DR-4. Unsupported is not corrupt

**Rule.** A valid file using a feature archivey cannot decode raises
`UnsupportedFeatureError`. `CorruptionError` is only for data that is actually damaged.
The truncated/corrupt split is best-effort: `TruncatedError` is a `CorruptionError`
subclass, and the docs present it as a hint that the source was most likely cut short,
so fetching it again or resuming a download may help.

**Why.** Exception types are control flow. A caller sorting a backup corpus treats
"corrupt" files differently from "needs a newer tool".

**Rulings.** lzip version 0 is unsupported, not corrupt (2026-10-03, PR 567). LZMA with
`lc + lp > 4` stays unsupported because liblzma cannot decode it, and the handbook names
the one library that could (2026-10-08, PR 621). `TruncatedError` became a
`CorruptionError` subclass before 0.2.0 (2026-09-27, PR 508). `TruncatedError` is a
resume hint, kept best effort, instead of a label not to branch on: an aborted download
is the common cause, and a caller can act on that (davi, 2026-10-30, PR 1140); reopen if
a common cut raises plain `CorruptionError`.

### DR-4a. The integrity guarantee is for a start-to-end read

**Rule.** Archivey promises integrity checks for a member read from start to end with no
skipped bytes. A seek keeps the member's digest unless a read then skips bytes nothing
decoded: a seek back keeps it, a forward seek whose gap must be decoded anyway keeps it
(the seek decodes nothing; the next read decodes the gap through the verifier), and a
seek to the end keeps it (the concluding read hashes the gap). A seek that jumps by an
index, an accelerator or random access, then a read past it, gives the digest up; such
seeks trust the format's own index and are best-effort. The digest covers the first pass
over each byte: bytes read again after a seek back are not checked again. A read that
skips bytes pauses the check where the reads had reached; a seek back to that point or
before it, then a read on to the end, completes it. A seek back to 0 re-arms the check.

**Why.** A seek that jumps skips the bytes that a check would cover, and the format's
own tools trust their indexes the same way. When the gap must be decoded anyway, the
next read has those bytes in hand at no extra cost, so dropping the check there gave up
integrity for nothing. Reopen if a decoder appears whose forward seek is cheap but
cannot hand the skipped bytes up (the cost claim would break).

**Rulings.** 2026-09-23 (index trust, PR 407); 2026-09-28 (PR 509); seek to 0,
2026-10-01; keep the digest across seeks that decode anyway, maintainer 2026-10-10
("we'd only lose the check for indexed or accelerated seeks", PR 743); a seek back to
where the reads had reached completes a paused digest, maintainer 2026-10-13.

---

## Consistency

### DR-5. Same input, same outcome

**Rule.** One archive gives one result, whichever of these changes:
- **Format.** A field means the same thing in every format. A value that does not fit
  goes to a format-prefixed `extra` key, or to a dedicated cross-format field.
- **Access mode.** Streaming and random access end up the same on disk "unless there's a
  strong reason that makes it impossible" (2026-09-25).
- **Operating system.** The same archive extracts the same way on Linux, macOS and
  Windows, or is refused everywhere, but for the same crafted shape under rapidgzip
  (DR-5a).
- **Accelerators and extras.** An accelerator changes speed, never the result or the
  error type, but for one crafted shape (DR-5a).
- **Entry point.** Public functions agree with each other (`detect_format` recognises
  what `open_archive` opens).
- **When and where a call is made.** A call that works on one archive, or at one point in
  a reader's life, works on every archive and at every point, or raises on all of them.
  That holds across threads too: a reader opened with `concurrent_operations=True` can be
  handed to several threads that each do what they need, whatever the others are doing.
  A call that raised only sometimes would ship bugs that never showed during development
  (2026-10-13).

**Why.** "Consistency between formats is a core promise of the library" (PR 290).
"Consistent behavior unless we have a good reason not to" (2026-10-07). A field
that is right on one format and wrong on another breaks callers silently.

**Rulings.**
- `created` is birth time only, never `st_ctime`, in any format; the change time goes to
  `ArchiveMember.ctime` (2026-09-25, PR 470).
- Device, FIFO and socket entries with no data are `OTHER` everywhere (2026-10-06, PR 610);
  with data they are `FILE` everywhere, and `extra["special_file_type"]` says what the
  archive called them (2026-10-10, DR-25; applied by PR 730).
- Timestamp diagnostics name the member attribute (`modified`, not `mtime` or
  `date_time`) in every format (2026-10-07, PR 608).
- A valid UTF-8 name wins over `encoding=` in every format; `encoding=` only replaces the
  fallback guess (2026-10-07).
- Plain TAR names decode as UTF-8 everywhere, not by the process locale (2026-09-26).
- `stream_members()` never seeks, on any format (ADR 0003 amendment, 2026-09-26).
- Hard links resolve backward-only in both access modes (2026-10-02, PR 532).
- A link target with a drive letter or UNC root is refused on every OS
  (2026-10-06, PR 620, ADR 0017).
- A truncated `.bz2` raises the same error with the accelerator on as off (2026-10-03).
  zlib under the accelerator checks Adler-32 like the standard library (2026-09-27).
- `streaming=True` refuses out-of-order reads on every format, ZIP included, although a
  ZIP could serve them cheaply, so the mistake shows on the first archive tested
  (2026-09-29, `docs/reading.md` §"Why these aren't on by default").
- Under `concurrent_operations=True`, `open`, `read`, `get` and `members()` work during a
  `stream_members` pass, on every format and from any thread, because they share one lazy
  walk of the archive with the pass (2026-10-13; applied by PR 786). `extract_all` joined
  them on 2026-10-17: under the flag every operation works as if it ran on a reader of its
  own.
- A pass or member stream that nothing can reach any more never blocks the next call, on
  any interpreter: a call refused for an overlap runs `gc.collect()` and tries once more
  (`reader_state._retry_after_collecting`). Without it, the refusal depended on when the
  collector happened to run: on PyPy for every dropped object, on CPython for one caught
  in a reference cycle. A pass or stream still referenced is refused either way. davi
  kept the retry and asked for it on every interpreter (2026-10-20, PR 915). Reopen if
  the collection on the refusal path has a measured cost that matters.

**Reopen if** matching would require an OS feature that one platform lacks; then refuse
on every platform rather than diverge.

### DR-5a. Malformed corner cases may differ a little

**Rule.** Consistency can be relaxed for malformed input, particularly a shape so specific
that only a crafted archive produces it. There, a format may keep its own behaviour if
making it match would add real code or plumbing. This never relaxes DR-1 or DR-9a: no
wrong or incomplete data on a full read without raising, no unbounded resources, no
crash.

**Why.** Cross-format plumbing for a shape nobody writes costs more than the difference
it removes.

**Rulings.** Lone surrogates in U+DC80 to U+DCFF in 7z names keep archivey's one-byte
meaning instead of 7-Zip's three bytes, because matching would mean carrying each name's
origin through the filters "for a name nobody writes on purpose" (2026-10-03, PR 564).
The quadratic crafted hard-link shape was settled by the simpler backward-only rule
rather than more memo state (2026-10-02, PR 532).
rapidgzip on a ZIP or 7z DEFLATE member checks only the tail after the last point of its
index, so a second stream that holds that point, with a size and CRC that cover both
streams, reads as both; with the accelerator off it raises. Finding the first stream's
end takes a decode from the start, which "negates the whole point of accelerators", so
the limitation is accepted and documented (2026-10-24). Whether the second stream holds
the point depends on the data, rapidgzip's thread count and the platform, so the same
member may read on one machine and be refused on another; that is accepted as well, and
the docs say "may" (2026-10-25). It does not relax DR-1: the output is what the member's
own size and CRC describe.

**Reopen if** a real producer writes the shape.

### DR-6. When the semantics are open, match the format's official tool

**Rule.** For a format-specific behaviour question, test what the format's reference tool
does and match it: `unrar` for RAR (over `unar`), GNU `tar` for TAR, 7-Zip for 7z,
`bzip2`, `xz`, `lzip` and `zstd` for their streams. Before refusing an input as junk,
check whether a real tool produces it.

**Why.** It is a tie-breaker that avoids relitigating each case, and it is what users
already expect from their tools (2026-10-02, extraction re-audit).

**Rulings.** Hard links resolve to earlier members only, like unrar and tar
(2026-10-02, PR 532). The RAR end-block CRC keeps listing like `unrar t` (PR 561).
Absolute member names re-root inside the destination like every mainstream extractor
(2026-09-30, PR 524). A zero-filled TAR is valid because `tar -b 64` writes one
(ADR 0015). A bare `.bz2` or `.gz` stops at zero bytes between streams or members, as
`bzip2` 1.0.8 and GNU `gzip` do: what follows them is trailing data, and only zeros that
end the file are silent padding. Every reader measured but Python's `gzip` stops there,
and no writer produces the shape (2026-10-10; `formats/bzip2.md` and `formats/gzip.md`
§6). The same day the rule was extended to zstd, LZ4 and LZMA Alone, whose tools stop
there too; xz keeps reading past the Stream Padding its format defines. Zeros at the end
stay silent for every codec, although `zstd`, `lz4` and `xz --format=lzma` refuse them:
one cross-codec rule, after the tape and block padding GNU `gzip` and `bzip2` accept
(`formats/single-file.md` §6).

**Limits.** When this rule and DR-5 disagree, that is a
[real decision](#when-consistency-and-the-official-tool-disagree): weigh the factors,
and ask when they split.
ZIP and ISO have no single official tool; see [Open gaps](#open-gaps).

### DR-7. Trust self-validating data over caller hints

**Rule.** When the archive says something verifiable (a UTF-8 flag, a valid UTF-8
sequence, a stored digest), use it. A caller hint such as `encoding=` fills only the gap
the archive leaves. An explicit caller assertion that conflicts with the source, such as
`format=` on a directory, is refused loudly, never silently overruled.

**Rulings.** Valid UTF-8 names win over `encoding=` (2026-10-07). `format=` on a
directory path raises `ArchiveyUsageError` (#225). An empty listing under an explicit
`format=` is reported, not refused, because an override is obeyed (diagnostics design,
2026-08).

### DR-25. Type comes from structure; data decides when structure is silent

**Rule.** A member's `type` follows the format's structural marker: the trailing separator
in the name (ZIP, and the V7 spelling in TAR), the typeflag (TAR), the directory flag
(RAR), stream presence (7z: a record with a stream is never a directory), the directory
record (ISO). A mode attribute, the Unix `st_mode` bits a ZIP, 7z, RAR or Rock Ridge
writer stored, never overrides that marker. Where the structure says nothing about what
the entry is, the data decides: an entry with a data stream is `FILE`; a special-mode entry
(device, FIFO, socket, unknown) with no stream is `OTHER`. What the archive said is always
visible: `extra["special_file_type"]` is set on every member whose stored type is special,
`FILE` and `OTHER` alike, and a special-mode entry typed `FILE` for its data also gets
`MEMBER_SPECIAL_FILE_HAS_DATA` (advisory). Bytes that extraction does not deliver, a
directory entry that declares data, are reported with `MEMBER_DIRECTORY_DATA_IGNORED` (a
warning; strict refuses) and stay readable: `open()` refuses a member that has no data (an
anti item, a stream-less `OTHER`, a directory with none), not a member by its type, and
`stream_members()` yields a stream for exactly the directories `open()` reads.

Ruled 2026-10-10. Applied by PR 730 (special-mode entries, every format), PR 731
(directory data in ZIP and RAR, and `open()` by data) and PR 763 (directory data in TAR;
a `DIRTYPE` header with a size that the walk ends right after is reported the same
way, since its blocks cannot be told from the trailer). Extended 2026-10-17 (maintainer
decision): `stream_members()` yields a data stream for a directory that declares data, in
every format, with the bytes and checks `open()` gives, where it had yielded `None` for
every directory and left the bytes out of a forward-only reader's reach. The one shape
left out is a ZIP directory written with a data descriptor (bit 3) and read from a pipe:
the pass meets it before its size, and its message says so.

**Why.** Info-ZIP's `zip -FI` stores a named pipe's content under the pipe's own FIFO
mode, and libarchive carries a workaround for exactly that shape; unzip, 7-Zip, bsdtar
and `zipfile` all write the file, so `OTHER` was the one reader that hid the bytes. The
2026-10-06 "useless as files" reason only ever described the stream-less case. For
directories every official tool creates the directory and drops the bytes without a word,
Go's `archive/zip` refuses to open such an entry, and APPNOTE 4.3.8 forbids it; DR-1 ranks
a reported loss above a silent one, and a readable `open()` is better than either. The
report fires only on a declared uncompressed size above zero, because a deflated empty
directory body (compressed size 2, uncompressed 0) is a shape real writers produce: Go's
`archive/zip` tolerates it on the strength of "the Java jar tool" (its source comment),
Debian bug 654899 shows it in a repackaged jar, and `zipfile` writes it for a deflated
empty entry; `jar` 21.0.12, measured for this rule, stores directories with both sizes
0. Evidence:
[`investigations/device-flag-and-directory-data.md`](investigations/device-flag-and-directory-data.md).

**Rulings.**
- Both halves accepted by the maintainer on that report (2026-10-10).
- A 7z record with a stream is a file whatever its attribute word says, as in 7-Zip (PR
  698).
- A TAR device or directory typeflag followed by data is damage, not a file: GNU tar and
  libarchive ignore the size field for those typeflags and resync, so archivey's
  `CorruptionError` stands. A TAR regular-file typeflag (NUL, `0` or contiguous `7`)
  named `d/` with data is a directory, as GNU tar reads it; 7-Zip agrees for NUL and `0`
  and lists a contiguous `d/` as a file (2026-10-10; `7` added 2026-10-16).
- A TAR typeflag archivey does not know (`9`, say) that declares data is a `FILE` of that
  size, readable, as GNU tar 1.35 extracts it and 7-Zip 23.01 lists and extracts it; with
  no data it stays `OTHER`. Both report `MEMBER_TYPE_UNKNOWN` (advisory), and
  `extra["tar.type"]` keeps the byte (2026-10-17).
- `archivey test` reads a directory's declared data and fails it on a bad checksum, while
  `archivey cat` skips it (maintainer, 2026-10-17, TAR/ZIP sweep questions). `unzip -t`
  tests the bytes and fails a bad CRC; `7z t` reports the same archive as OK. archivey
  takes the stricter reading because a lenient one would hide bytes from the integrity
  command. Reopen if a real writer routinely stores directory data that `7z t` users
  rely on passing.
- Agent decision in PR 879's review (2026-10-17), not a maintainer ruling: a directory
  body archivey cannot decode (an unsupported method, a missing codec, RAR's compressed
  directory data) is not tested rather than failed, per DR-4 and `unzip -t`, which skips
  it. A directory body that needs a password stays a failure, as an encrypted file does
  with no password (`unzip -t` splits here: it skips AES and errors on ZipCrypto).
  Reopen if the maintainer wants the password case skipped too.

**Reopen if** a real producer writes a directory entry whose data users need on disk, or a
special-mode entry whose bytes are not the content; then that format needs a named
exception here, not a silent one.

---

## Defaults, limits and opt-ins

### DR-8. Defaults are complete and consistent; laziness is an explicit opt-in

**Rule.** A default should be "as lazy as possible while providing full info and
consistency" (2026-09-23). If a cheaper behaviour fills a field only sometimes, it is an
opt-in config field, and its users accept the gap. When the opt-in removes information,
give the caller a way to see the gap before any cost is paid.

**Why.** "Having link targets filled sometimes but not always is a recipe for bugs."

**Rulings.** `read_link_targets` defaults to `True`; with `False`, `extract_all`'s
filter runs before a link target is read (PR 404). The same field decides whether solid
7z link targets are read at listing (2026-10-06). Checksum checks run on possibly
encrypted stored members before any byte is served. A seekable ZIP opened with
`streaming=True` reads the central directory first, so every member is complete when
yielded; only a non-seekable source walks local headers and completes members at the end
of the pass (davi, 2026-10-10, native ZIP reader design). The reasons given with the
question: the tail read costs one seek, and a member that is complete when yielded needs
no fixing later. Reopen if a seekable source where the tail read is expensive (a remote
object) turns out to matter more than complete members. A member that archivey will
still update in place says so on the member itself, with a field (working name
`member_state_final`), not on the cost receipt, which describes cost; it covers
data-stored link targets not yet read, `is_current` in any forward-only pass, and a ZIP
read from a pipe (davi, 2026-10-10). Reopen if callers need to know which fields are
still provisional rather than only that some are, or if a format turns up where the
field would be false for most members of an ordinary read.

**Do not** recommend "lazy by default, complete on request".

### DR-9. Every cost is bounded by a public, raisable limit

**Rule.**
- Every resource bound is a field on a public limits object (`ListingLimits`,
  `ExtractionLimits`, `DecoderLimits`, `SpoolLimits`), with `None`/`UNLIMITED` as the
  escape hatch. Not a module constant, unless the bound is structural rather than
  policy; then the reason goes in a comment at the constant and the bound gets a spec
  row (CONTRIBUTING §Coding standards).
- Defaults admit the real archives real tools write. Tighter numbers belong in a preset,
  not the default.
- Work the archive chooses counts against the limits. Work the destination causes counts
  only against absolute caps.
- Reuse an existing limit before inventing a new one.
- Implementation constants (a cache size, a candidate cap) are the implementer's to pick
  and move on evidence. Default *limit* values are the maintainer's.

**Why.** A user with a legitimately huge archive must be able to raise any cap
(CONTRIBUTING). The caller's own configuration is trusted (threat model §1).

**Rulings.**
- Decoder memory: a new public `DecoderLimits`, not a field on `ExtractionLimits`,
  "with 1GB so that real files always decode fine", later 2 GiB (2026-09-19 and
  2026-09-23, PR 398).
- RAR stream spool: "let's add a cap, it would be a config field" (2026-09-26, PR 485).
- PPMd in-process threshold is a config field, not a constant (2026-09-26, PR 481).
- ISO path-table entries count against `max_members` (2026-10-06, PR 612).
- Hard-link copies at the link-count limit count toward `max_ratio`; cross-device copies
  count only toward bytes (2026-10-07, PR 623).
- A container inside a compression stream (a `.tar.gz`, a handler's `.cpio.xz`) holds
  its whole decode to the archive-wide `max_ratio` in every use, listing included
  (`DecodeRatioGuard`): listing one decodes everything, and extraction would refuse the
  same archive anyway (davi, 2026-10-29, PR 1138). Cost: an honest archive over 1000:1
  past the first 5 MiB no longer lists by default (800:1 since 2026-10-30). Reopen if a real archive class
  (not a test of zeros) is refused there.
- `max_ratio` holds every member read (`open()`, `read()`, `stream_members()`), by the
  per-member and archive-wide rules extraction applies (`MemberRatioGuard`): scanning
  or hashing members pays for the decode as extracting does, and holding only the
  compressed-tar spelling of a bzip2 bomb left the ZIP, 7z and bare `.bz2` spellings
  open (davi, 2026-10-30, after PR 1138). Cost: an honest member over 1000:1 past
  5 MiB no longer reads by default. Extraction's passes keep their own tracker.
- The ratio fields move from `ExtractionLimits` to `DecoderLimits`, since they now hold
  every decode; the `ExtractionLimits` fields stay one minor, deprecated, and override
  when set (davi, 2026-10-30). Default `max_ratio` 800, below Deflate's ceiling of about
  1032:1, so a gzip of zeros (about 1003 to 1032:1) is refused every time rather than
  by chance, as zeros are in every other codec (davi, 2026-10-30). Raising it so gzip
  of zeros passes was weighed: bzip2, xz and zstd of zeros would still be refused.
- Default numbers (decided 2026-10-07): `max_members` and `max_entries` 262,144;
  `max_key_derivation_rounds` 2**25. These replace the 2026-10-01 decision to keep
  1,048,576 and 2**27, after measuring per-member listing cost.

**Reopen if** a measured real archive class hits a default.

### DR-9a. The upload-server test

**Rule.** No archive may cause unbounded memory, unbounded disk, a hang without a
bound, or a crash of the process. Picture a server that lets anyone upload an archive to
be tested, scanned or have its members hashed, with default limits. If some upload could
bring it down, that is a bug, however unlikely the archive is to occur naturally.
Native code that can crash runs in a child process (DR-20). Every allocation an archive
can steer is checked against a limit before it is made (DR-9).

**Why.** An attacker crafts archives at will and picks whichever loophole is left
(2026-10-09). "Only crafted archives hit it" can relax consistency (DR-5a), never this
rule.

**Rulings.**
- PPMd decoding past the end could corrupt memory, so it runs in a child process
  (2026-09-26, PR 481).
- rapidgzip killed the process on a truncated gzip, so it moved into a child process
  (2026-09-26, PR 493).
- `detect_format` must not allocate an LZMA dictionary at whatever size a crafted header
  declares (2026-10-07).
- ISO path-table entries count against `max_members` (2026-10-06, PR 612).
- Decoder memory is capped before allocation (PR 398).

**Known limits.** Limits cap bytes, entries and key-derivation rounds, not time; the
accepted non-guarantees are in `threat-model.md` §4. Each of them must still pass this
test at default limits, or be listed there with its reasons.

### DR-10. Costly or risky capability is declared, and a declaration is a guarantee

**Rule.** Seekable streams, concurrent streams, accelerators, external programs and
anything else that costs resources or changes guarantees is off until the caller asks
for it by name. Once asked, it is a guarantee, not "where the backend can". A
non-seekable source in random-access mode fails at open instead of being buffered.

**Why.** "An unconditional 'always seekable' API lets developers test on ZIP and ship a
footgun on TAR/7z" (ADR 0003). Blocking a cheap read too catches the mistake during
development, not in production on a different archive (2026-09-29).

**Rulings.** ADR 0003, 0004, 0010. `stream_members()` is never seekable (2026-09-26).
The gzip AUTO accelerator stays seek-only for 0.2.0 (2026-09-27); after it, AUTO also
takes a large sequential DEFLATE-family read at 3:1 or less, on Linux and macOS, and the
stream stays forward-only (2026-10-26). `ListingCost` names
how the member list is read through the source the archive was opened on (index, header
walk or decompression), not the work of finding the index or when it is paid: RAR
reports `REQUIRES_SCANNING` although it walks its headers inside `open_archive`
(2026-10-15). A caller reading the receipt learns what a lazy backend would pay, and the
value does not change when a backend moves the walk; it may differ by source, as a piped
ZIP's does. Reopen if callers need "already paid" as its own signal, or if the RAR5
quick-open case (`formats/rar.md` open questions) is ruled `INDEXED`.

### DR-10a. Read sequentially; seek only when the format needs it

**Rule.** Prefer forward reads over seeks, and few large reads over many small ones.
Read only the parts the operation needs: the index to list, the member's bytes to read
it. Count seeks and bytes read as costs, the same as bytes decompressed.

**Why.** Sources are often remote file objects, such as an HTTP range reader or a
storage-bucket client, where each seek can be a network request (2026-10-09,
[scenario 9](scenarios.md#9-loading-from-a-remote-file-object)). Pipes cannot seek at all.

**Rulings.** Performance claims cite bytes decompressed and seeks, not wall time
(CONTRIBUTING). Solid blocks are decoded once per pass (VISION).

### DR-11. Environment trouble falls back; explicit requests fail loudly

**Rule.** When an automatic choice (an `AUTO` setting) cannot run because of the
environment (a package not installed, a child process that cannot start), fall back to
the slower correct path, with a log warning when the cause is the host rather than the
archive. When the caller asked for that path explicitly (`ON`), raise.

**Rulings.** rapidgzip under AUTO falls back to the standard library when its child
process cannot start: "a log warning may be warranted. it's not an archive related
issue, but an environment issue" (2026-09-26, PR 493). A refused `unar` is never used,
whatever the setting (ADR 0002 amendment, 2026-10-01).

---

## Public API

### DR-12. Before the first release, remove rather than keep

**Rule.** Before 0.2.0, any breaking cleanup went in at once: deleting a name, renaming
a field, changing an exception's base class. If a public name has a single value, no
caller, or an obvious two-line alternative, delete it. Offer "remove it" as an option on
every API question. The maintainer still reviewed every removal or rename of a public
name: he was for the cleanup and wanted to check it and know it happened (2026-10-09).

**Why.** Removing a public name after the release breaks callers. Adding it back later
breaks no one ("no need to delay until after release", 2026-09-27).

**Rulings.**
- `DiagnosticSeverity` removed: "let's simplify the API" (2026-09-26, PR 479).
- `WriteError` deleted outright (PR 479).
- Exception tree pruned from 27 to 18 classes (2026-09-27, PR 506).
- Top-level `archivey.extract()` removed (ADR 0019).
- `extract_all(config=)` dropped because the reader already has a config.
- The seven string enums became `StrEnum` (PR 639).
- Leftover compressed input raises before 0.2.0 rather than after (DR-3).
- `crc32_digest` made private: callers only read `member.hashes`, and comparing their
  own CRC is `zlib.crc32(data).to_bytes(4, "big")` (2026-10-20, PR 896).

In several of these the maintainer went further than the recommendation, toward
removal.

**Reopen if** a removed name is needed by a real caller; add it back then.

0.2.0 shipped on 2026-10-23, and DR-12a replaced this rule. It stays as the record of
the rulings above.

### DR-12a. After the first release, deprecate before removing

**Rule.** From 0.2.0 until 1.0:
- A patch release adds, removes and changes no public function, class, parameter or
  attribute. It may read input it used to refuse, add a `DiagnosticCode`, or add a value
  to an enum documented as open-ended (`CompressionAlgorithm`); the maintainer allowed
  new codes and enum values in a patch on 2026-10-23. It adds to
  `ARCHIVE_INTEGRITY_CODES`, which `DiagnosticPolicy.STRICT` raises, only a code for
  damage archivey should already have caught; any other addition to that set waits for
  a minor release. It may add a line to the command's human-readable output, but changes
  or removes none; the maintainer allowed that on 2026-10-24 (PR 1033).
- A minor release may remove or rename a public name, but the old spelling keeps working
  for one minor release first and emits a `DeprecationWarning` naming the replacement,
  with `stacklevel=2` so Python attributes it to the caller's line; at the default level
  it is attributed to archivey and hidden from every caller. The release after that
  removes it. This warning is about the caller's code, not about
  an archive, so the diagnostics-as-data rule (VISION, "queryable as data") does not
  govern it: there is no `Diagnostic` for a deprecated call.
- A break that can't be phased in that way (the same call gives a different result, an
  exception changes type) goes in a minor release, and its changelog line starts with
  **Breaking:**. The GitHub release mirrors the changelog.
- The `archivey` command's verbs, options and exit codes are public names under the
  same rule (maintainer, 2026-10-22). The command prints its own deprecation notice
  for an old spelling: a command-line user has no Python call site to attribute a
  `DeprecationWarning` to. The text it prints for people may change in a
  minor release. A minor release may add a verb, which then wins over a file of that
  name; `archivey list <path>` and `./<path>` always reach the file (`cli` spec).
- `archivey.internal` is not public and changes freely.
- The plugin interface is experimental and outside this rule: `archivey.formats` and the
  names that exist only for it (`PluginContainer`, `PluginStream`,
  `FormatPolicy.replace`, `FormatInfo.from_plugin`) may change or go in any release,
  with no deprecation release (maintainer, 2026-10-31: it should not freeze before he
  has reviewed it closely). `scripts/api_surface.py` `EXPERIMENTAL` lists them, and
  `release.py notes` does not ask for a minor for a line whose own name is one of them.
  A stable signature that only mentions one (`FormatPolicy`'s constructor with
  `replace=`, `ArchiveFormat`'s `container` field typed `ContainerFormat |
  PluginContainer`) still shows as a minor; the maintainer judges that change.
  `FormatPolicy.plugins` stays stable (maintainer, 2026-10-31): a switch that refuses
  plugin formats keeps working whatever happens to the interface it refuses. Declaring the interface stable
  is the maintainer's call.

Public docs: `docs/how-it-is-built.md` §Versioning and stability.

**Why.** 1.0 waits until early users have run archivey for a while (maintainer,
2026-10-21), so those users are who the 0.x line serves. A warning release keeps their
code running while they update, and a shim costs a few lines that the next minor release
deletes. Chosen over breaking in any minor with only a changelog note, and over freezing
the API until 1.0 (2026-10-21).

**Reopen if** keeping a shim would mean keeping wrong behaviour (DR-1 wins), or when 1.0
ships and the rule becomes semver's major-version rule.

### DR-13. A public name earns its place

**Rule.**
- A public exception type exists only if a caller would handle it differently from its
  parent (ADR 0012).
- Niche names live in a public submodule, not at the package root (`archivey.terminal`,
  `archivey.detection_cost`).
- `__all__` grows one export at a time, with the reason in the PR.
- The CLI uses only public API, apart from what `tests/test_cli_uses_public_api.py`
  allowlists with a stated reason. What the CLI needs becomes public, which is how `dry_run=`
  and `archivey.terminal` were made public.

**Rulings.** `detection_cost` stays in its module: "minimizes root exports, these are
too niche for root" (2026-09-25). The CLI escaping helpers became a public submodule not
re-exported at the root (2026-09-24). `dry_run=` is public (2026-10-01, PR 531).
`MemberStreams` was demoted (PR 479).

### DR-14. One obvious way, and one mechanism per job

**Rule.**
- Do not add a convenience wrapper that duplicates a short chain of public calls.
- When two mechanisms disagree, delete one rather than choose between them.
- When a new need appears, look for an existing option or class first. Extend it and
  document it before adding a new one.
- Collapse layered wrappers into one owned abstraction at the boundary.

**Why.** The two rulings in the September sweep both removed surface instead of choosing
between two behaviours. Later questions were often answered with "don't we already have
an option for this?".

**Rulings.**
- `strict_archive_eof` was removed rather than reconciled with `IGNORE`.
- The solid 7z link-target cost: "don't we already have an option…", so the card closed
  as "Leave it", with a doc fix (2026-10-06).
- Password lists for RAR were folded into the shared `password_confirm` logic, which
  helps every format (2026-10-06, PR 627).
- The bzip2 resume reused the gzip bit-shift approach (2026-10-03).
- One `ArchiveSource` wraps every caller stream or path (2026-09-22, PR 419).
- Exception refusal reasons: "I was only considering reusing if something already
  existed" (2026-09-27).

### DR-14a. Easy to explain, easy to use right the first time

**Rule.** Between two designs that both meet principles 1 and 2, pick the one that is
easier to explain in a sentence and easier to use correctly on the first try, by a person
reading the docs or an agent reading a docstring. Concretely:
- The common path needs no options. `open_archive(path)` then iterate, read or
  `extract_all`.
- When a declared opt-in is required (DR-10), the error that asks for it names the
  option to set, so the fix costs one step during development rather than a search.
- Names say what they govern (`detection_budget`, `DecoderLimits`), so a reader does not
  need the docs to guess.
- Docs lead with what a caller chooses, then the consequences, and frame options by use
  case.
- A mechanism its own author cannot explain in one page gets simplified before it is
  frozen.

**Why.** Archivey aims to be the default library for archives, in code written by
people and by agents. Every extra concept costs each caller time and tokens, and a
library that makes callers stop and think becomes a bottleneck (2026-10-09).

**Rulings.**
- Top-level `extract()` was removed because a near-identical second way "causes more
  confusion than it saves" (ADR 0019).
- The `open_archive` options got a use-case table after the maintainer asked whether
  the docs made them look "more annoying than they actually are" (PR 513).
- Diagnostics were re-explained after "I still don't fully understand how it works and
  how it should be used" (2026-09-25).
- `budget=` became `detection_budget` on the config: "it's unclear otherwise … most
  users won't care … let's think about what makes more sense from the user's POV"
  (PR 275).

**Tension.** Declared opt-ins (DR-10) add a thing to know. They stay, because they turn a
production surprise on another format into an error during development (DR-5, "When and
where a call is made"). This rule asks that the error make the fix obvious.

### DR-15. Usage errors are for what the types cannot rule out

**Rule.** A wrong argument type raises a `TypeError`. An argument of a usable type whose
value the call refuses raises a `ValueError`; that includes a value refused only after
looking at what it names, such as a `format=` that conflicts with what the source is, a
directory passed to `open_stream()`, or a volume sequence that is not the parts of one
set. Both are also `ArchiveyUsageError`s: the boundary helpers
(`internal/arg_checks.py`, `enum_args.py`, `format_args.py`, the `*Limits` field checks)
raise the private `_UsageTypeError` or `_UsageValueError` from `archivey/exceptions.py`,
so `except TypeError`, `except ValueError` and `except ArchiveyUsageError` all catch a
bad argument. A plain `ArchiveyUsageError` is for misuse the signature cannot express,
such as calling a method in the wrong mode or using a closed reader. Translate only
known third-party exceptions; never add a catch-all.

The source and destination paths follow the same rule: `open_archive(0)` is a type
error, and an empty string, which `Path("")` would read as the current directory, is a
value error.

**Rulings.**
- 2026-09-25, recorded in the ADR 0012 amendment: wrong argument types keep
  `TypeError` and `ValueError`.
- 2026-10-10: the two private subclasses above, rather than making `ArchiveyUsageError`
  itself a `TypeError`, because mode misuse and closed readers also raise it and are not
  type errors. The subclasses are not exported; callers catch the builtin or
  `ArchiveyUsageError`.

### DR-15a. Translate archive problems; let I/O problems through

**Rule.** Errors about the archive's content become archivey errors. Runtime failures not
about decoding, such as a disk read error or a dropped network connection, raise the
original exception. A known library exception is mapped; an unknown one propagates. An
error message states the fact, with no advice the reader cannot act on.

**Rulings.** "Actual runtime unpredictable filesystem-level errors … should still raise
the original exception, as they're not directly related to archive decoding" (PR 3,
reaffirmed in PR 18). `MemoryError` is not translated, so running out of memory is never
mistaken for damage (threat model §4).

### DR-15b. Fail at open, but do no expensive work there

**Rule.** A problem that open can detect cheaply (contradictory options, a missing
package, an unreadable header) raises at open, not at the first read. Work proportional
to the archive's data (a full CRC scan, decoding members) waits until a read asks for it.

**Rulings.** Single-file readers open their stream eagerly so init errors surface at open
(PR 13). The gzip trailer CRC is decided at read and never scanned at open (2026-09-24).

### DR-16. A feature must deliver its promise

**Rule.** If archivey advertises a capability, it works in every format that claims it,
or the format says it does not. A heuristic that silently degrades the capability is a
bug.

**Rulings.** RAR3/4 password lists tried only the first candidate. Taking the first
candidate "would defeat the whole purpose of supporting multiple passwords", so every
candidate is probed (2026-10-06; shipped in PR 627). Anything on by default is fuzzed:
"if they're the default, we should fuzz them", so the accelerator fuzzing gap was closed
instead of keeping the "accelerators are not fuzzed" caveat in the docs (2026-10-06, PR
638). Closing a gap rather than documenting it is DR-22a.

---

## Extraction

### DR-17. Extracting beats refusing; refuse only what is unsafe

**Rule.**
- Refuse a member only when writing it is unsafe, or when the outcome would differ by OS.
- Rewrite what is merely non-portable (percent-escape, re-root).
- Policy decides everything else, with TRUSTED as the faithful escape hatch.
- Prefer a composable hook to a new policy value.

**Why.** Refusing an odd but harmless name forces the user into TRUSTED, which couples a
naming question to a permissions decision (ADR 0013).

**Rulings.** Absolute names re-root under STANDARD and TRUSTED, and STRICT refuses. The
caller filter runs first, so `sanitize_names` can fix them; it was picked over a fourth
policy (2026-09-30, PR 524). Bidi overrides are policy-keyed (ADR 0017). A segment of
only dots or spaces (`a/.../b`) is refused under STANDARD as under STRICT, because Win32
merges it into its parent (2026-10-21, PR 955, ADR 0013 decision 4).

### DR-18. Extraction never damages what it did not create

**Rule.** Do not change the mode of a pre-existing directory, the destination root
included. `REPLACE` never removes a non-empty directory. Directory modes and times are
applied in a final pass, like GNU tar.

**Rulings.** 2026-09-30 extraction re-audit (PR 532). Directory modes in a final pass
(2026-10-08).

### DR-19. Prefer one structural invariant over many string checks

**Rule.** When several ad-hoc checks guard one hazard, look for the invariant that makes
them unnecessary. For hard links, the invariant is that a target must name an earlier,
non-refused member.

**Rulings.**
- Hard-link targets: one rule replaced the drive, backslash and re-root path checks
  (2026-10-07, PR 632).
- The CLI hoist check walks each link's real path, replacing the earlier
  "any `..` blocks" rule, which over-blocked (2026-09-30).

---

## Dependencies and formats

### DR-20. Parse in Python; isolate native code that can crash

**Rule.** Container and header parsers are pure Python. Native code is for codecs only.
A codec with known crashes runs in a child process or is designed around. Choose a
library by how it behaves on damaged input, measured. A tool that is known to decode
wrongly is refused, not used.

**Rulings.** ADR 0001, 0002, 0009. PPMd (PR 481) and rapidgzip (PR 493) run in child
processes rather than reading the whole file first, which "defeats much of the
accelerator usefulness". Only a `unar` that passes the RAR5 probe is used
(2026-10-01). Zero-dependency core (ADR 0011).

### DR-21. Defer a fix that a planned rewrite absorbs, and document it

**Rule.** If a fix would mean replacing a component that is already planned for
replacement, record the limitation where users will find it and fix it in the rewrite.

**Rulings.** A ZIP name with the UTF-8 flag but invalid UTF-8 kept refusing the archive
until the zipfile replacement (2026-10-06). The replacement, the native ZIP reader, moved
into 0.2.0 on 2026-10-10 (davi); its names stage ended the refusal: such a name decodes
as an unflagged one, with a diagnostic.

### DR-21a. Don't ship what can't be tested

**Rule.** If no available tool can produce a case and archivey cannot test it, refuse it
up front with a clear error and document it as a known limitation, rather than ship an
untested path.

**Rulings.** Encrypted comments in old RAR archives: "skip up front. note in docs as a
known limitation due to being untestable" (2026-09-24).

---

## Documentation

### DR-22. Docs say what is true now, with reasons

**Rule.**
- VISION describes what the project wants to provide, not a claim that it is done.
- `dev-docs/` is a clean set of developer docs, not task tracking.
- The threat model is a model, not a list of known security issues.
- Handbook and topic pages explain how things work today and why ("we do Y because X
  would cause…"), not a history.
- A recorded decision keeps its decider and date, and adds its reasons and what would
  reopen it: "just citing doesn't help us reevaluate or accept later" (2026-10-02).
- User-facing numbers are ballparks: higher precision gives a false sense of exactness.

**Rulings.** Top-level docs review (2026-09-28). Detection topic page (2026-09-26).
Ballpark numbers (2026-10-07). User-doc voice: see the `write-user-docs` skill.

### DR-22a. A caveat in the docs is a question for the code

**Rule.** When a behaviour needs a caveat, a gotcha or a "be aware that" in the docs,
first ask whether the code can change so the caveat is no longer needed. If it can, fix
the code and drop the caveat. Keep the caveat only when the fix is impossible (the
format gives nothing to work with, as in DR-21a, or the data is unknowable, principle 1)
or costs more than it buys; then the caveat says why. When the fix changes public
behaviour, put it to the maintainer as a choice between "fix it" and "document it",
with the fix recommended unless something argues against it.

**Why.** A caveat is work for every reader, and most readers never see it (principles
3 and 4). Writing the docs keeps turning up inconsistencies: questions the maintainer
raised while rewriting the user docs repeatedly turned out to be behaviour to fix, not
to explain (2026-10-09).

**Rulings.**
- Accelerators were not fuzzed, and the docs said so. The gap was closed instead of
  keeping the caveat (DR-16, 2026-10-06).
- `MEMBER_TIMESTAMP_INVALID` named its field differently in ZIP and TAR. "Keep the split
  and list both vocabularies in the docs" was offered and turned down in favour of one
  vocabulary (2026-10-07, PR 608).
- The `encoding=` rule came out of writing the opening page: valid UTF-8 names are to
  win over `encoding=` in every format, rather than the page explaining a per-format
  difference (ruled 2026-10-07).

**Reopen if** a fix would break the upload-server test or hide data (principles 1 and
2); then the caveat stays.

---

## Code and tests

### DR-23. Zero debt in the code you touch

**Rule.**
- "Previously existing code is not a good justification, we're striving for zero debt."
  Remove dead code and unused fields; prefer the cleaner structure over the smallest
  diff.
- A simple bug in code the PR already touches is fixed in that PR. A sweep across files
  the PR does not touch is its own PR.
- Review nits are fixed, not deferred. Something too big to fix in place is split into
  its own PR, not parked.
- Before adding a class or mechanism, check whether the standard library or an existing
  helper does it. "Do we really need a custom class for this cache?" (PR 418).
- Comments and maintainer docs describe the code as it is and why: "Don't talk about the
  past. Code maintainers need to understand the current state and the reasons behind
  it" (PR 400). History belongs in PRs and ADRs.
- Names are spelled out and carry their context (`detection_budget`, not `budget`).
  No logic in `__init__.py` beyond the export surface's own machinery (registration,
  module pinning, `__getattr__`). Code is grouped by format, not by pipeline phase (PR 443).
- Raise naming questions at proposal review. A rename after implementation needs a
  reason beyond taste.

**Reopen if** a cleanup would change public behaviour; then it is its own PR with its own
review, not part of the PR that found it.

### DR-23a. Share what must agree; copy what agrees by coincidence

**Rule.** Before sharing or copying code in `src/`, `tests/` or `scripts/`, ask: if one
copy changes, must the other change too?
- If yes, share it. Copies that must agree for correctness drift apart, and the drift is
  a bug: limits and resource checks, error translation, integrity checks, diagnostics
  wiring, and the workarounds for one library that several codecs use.
- If no, keep the copies. Code that happens to look alike today (two formats' header
  parsers, two tests' setup) may diverge for good reasons. Keeping copies does not
  narrow DR-0: a bug found in one copy is still a question for the others.
- A shared helper that needs a flag, mode or callback per caller to cover their
  differences is worse than plain copies. Share the part that must agree and leave the
  rest in each caller.
- If you can't tell, keep the copies and add a comment at each one naming the other, so
  a fix to one reaches the other.

**Why.** The maintainer, 2026-10-09: some duplication makes sense; "nothing is black and
white". The same day's duplication check of the codec modules (on the layout PRs 647 and
649 introduce) found copies that had drifted into different behaviour, and one bug where
a copy missed the diagnostics collector the others pass (tracked internally). DR-14
covers duplicated public mechanisms; this rule covers internal code.

### DR-24. Tests pin behaviour against real producers

**Rule.** A bug fix starts with a failing test (red, then green). Tests check behaviour,
not internals. Fixtures come from the real tools users run (the gzip command line,
RARLAB `rar`, 7-Zip), pinned by hash where they are committed, and a matrix row says
when no available tool writes that case. A refactor that breaks a test means the fix or
the test is wrong: find out which and report it, never quietly edit the test.

**Reopen if** a real producer cannot make a case that users do hit; then a crafted
fixture is acceptable, with a comment saying why.

**Rulings.** gzip `FNAME` is Latin-1 per RFC 1952, fixed red/green with a
command-line fixture (PR 13). Committed RAR fixtures (ADR 0016). The corner-case
cleanup's rule for refactors (2026-10-02).

---

## Questions to ask yourself first

The maintainer's questions have repeatedly turned up the real answer, often a better one
than any option offered. Ask them yourself, and put the answers in the question before it
reaches him.

- **Does this affect other formats? Is there a shared path?** A cross-format check of
  recent format-specific bugs found 20 more (2026-10-06).
- **What does the official tool do?** Run it (DR-6).
- **Do streaming and random access agree? Does each OS agree? Does the call work on
  every archive and at every point, or raise on all?** (DR-5)
- **Is this a limit of the library we use, or are we refusing by spec?** (the lc=8
  question, 2026-10-08)
- **Don't we already have an option or class for this?** (DR-14)
- **How hard is it to do it properly instead of exempting it?** The exemption on hard-link
  copies did not survive "how hard is it to count?" (2026-10-07).
- **Did a later change make this code redundant?** The gzip size-check fallback "was
  useful at first but became redundant" (2026-10-06).
- **Does it break callers?** Then it waits for a minor release, behind a deprecation
  warning where one can phase it in (DR-12a).
- **Could these bytes hide something?** (DR-3)
- **Can the user still get what they need through a filter or an opt-in?**
- **Is it actually simpler?** For a large design, ask for a fresh review before building
  it. The detection evidence ledger was dropped after one said the small fixes were
  enough (2026-09-25).
- **Does this need a caveat in the docs?** If so, can the code change so it doesn't?
  (DR-22a)
- **Is the premise right?** Check the finding against current `main` and measure before
  asking. Several questions were withdrawn because the finding was stale.

## What still goes to the maintainer

- A **default limit value** or any number users will see as a default.
- A **new public name**, or **removing or renaming** one, an `archivey` verb or option
  included (DR-12a). Expect a yes; the point is that he checks and knows.
- Accepting a **residual risk** in the threat model.
- **Reversing** an earlier ruling. This needs a new argument, not a restatement (ADR 0019).
- A **clash between consistency and the official tool** where the factors split.
- Anything **outside the repo**: upstream bug reports (agents draft them, the maintainer
  files them), repository settings, publishing.
- Merging a **tricky** pull request: one that makes a decision of the maintainer's, such
  as a behaviour trade-off, a design reversal, removing or renaming a public name
  (DR-12a), or anything an open decision touches (the list is in `AGENTS.md`, and
  `scripts/review_prep.py tier` finds most of it). Size alone is not one of them. Any
  other one an agent may merge once its review approves and CI is green; on standard and
  deep that approval includes the Opus pass, and on deep Cursor's too (maintainer,
  2026-10-31).

How to ask is in `AGENTS.md` §Working with the maintainer.

## Open gaps

Questions no rule here settles yet.

- **The official tool for ZIP and ISO.** DR-6 names none. Asked on 2026-10-02 and not
  answered.
- **The stricter `DecoderLimits` preset.** The numbers are chosen (256 MiB, 2**24); the
  name, and whether it should be a mode rather than numbers, are open.
- **`size` of a stream-less `OTHER` member.** TAR reports `None`; ZIP, 7z and RAR keep
  the header's value. `None` fits TAR, where GNU tar and libarchive ignore a device
  header's size, and the stored value fits where the field is read as data. Whether to
  unify, and which way, is open (investigation `device-flag-and-directory-data.md`,
  item 3, 2026-10-10).
- **TAR symlink and hard-link headers with trailing data.** libarchive zeroes the size
  for typeflags `1` and `2` as it does for devices and directories, so the same
  `CorruptionError` is the consistent answer, but the case was not measured and DR-25
  rules only on the device and directory typeflags (same investigation, item 6).

## Recording a new ruling

When the maintainer rules on something:
- If it is format-specific, add a bullet to that format's handbook page.
- If it generalises, add it here as an example under the rule it applies, or as a new
  rule.
- If it contradicts a rule here, update the rule and keep the old ruling as history in
  the example list.
- Either way, write the date, the reasons and what would reopen it.
