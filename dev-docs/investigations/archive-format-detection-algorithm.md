# Archive format detection: independent design analysis

**Date:** 2026-08-23; revised 2026-08-26 after review.

**Status:** complete analysis, **not a normative specification**. Accepted as redesign
input for PR #257 — meaning #257's selection and stopping rules should be revised against
it before implementation. It becomes binding only through #257's revised delta, not by
sitting here (§14).

**Inputs:** the original analysis was written against `main` at `bee7735`, PR
[#257](https://github.com/archivey-dev/archivey/pull/257), PR
[#262](https://github.com/archivey-dev/archivey/pull/262), the measured Brotli investigation,
the current detector, and the format specifications linked in §15. Measurements added in
the 2026-08-26 revision were taken against `main` at `a3dc408` (which carries #267/#268);
each states its tree explicitly.

> **On the measurements.** Every corpus number in this document was taken on **one
> Debian-family Linux container** — one distribution, one toolchain, largely one set of
> compression defaults. That is a genuine limit, not a formality: a homogeneous build
> environment understates how much producers vary. A count of zero here means "this
> distribution's tools do not do it", never "nothing in the wild does it" — the gzip
> `FHCRC` result in §5 is exactly that trap. Read every measurement as *"measured on X"*,
> and treat any rule that would reject inputs on the strength of a zero count as needing a
> heterogeneous corpus first.

## Executive recommendation

Keep an **ordered acquisition plan**, but do not keep **first match wins**.

The detector should collect typed evidence for candidates, compare totally ranked evidence
classes with ordered tie-breakers, and stop only when no unrun detector can change the winner.
This is not an additive score: adding a filename to a weak decode must never outweigh a
checksum-validated header, and two correlated weak signals must never be promoted above
one stronger signal.

The full acquisition order should be:

1. read the name, source capabilities, cheap size, and up to 4096 prefix bytes;
2. evaluate every near signature and its format-declared structural validator;
3. evaluate fixed-offset far signatures, currently 32,775 bytes for a structurally
   checked ISO descriptor;
4. for seekable sources, locate ZIP's EOCD in at most 65,557 tail bytes, then charge
   central-directory/local-header validation separately;
5. when a prefix cue fires, scan at most 2 MiB forward and validate every candidate,
   resuming after decoys;
6. run an exhaustive embedded-payload scan only under a separate, explicit
   try-hard/discovery policy;
7. run **all** applicable magic-less content probes and retain all hits;
8. use the filename as corroboration and, only now, as a last-resort candidate;
9. select a unique maximal candidate; raise a dedicated `AmbiguousFormatError` carrying
   tied maximal candidates when there is no unique winner, or `FormatDetectionError` when
   there is no candidate.

This is an evidence order, not a claim that every tier is enabled by the default budget.
In particular, #257's proposed always-on ZIP tail tier is held out of `BALANCED` until its
aggregate cost is measured on the founding backup workload (§10 and §13).

PR #257 is substantially right about putting far magic and validated prefix searches
ahead of content probes. I disagree with four load-bearing parts:

- raw near magic is not uniformly `CERTAIN`: two bytes of gzip or `.Z` are not the same
  evidence as an XZ flags CRC, a 7z StartHeader CRC, or a TAR checksum;
- a registry-order first hit is not a sound decision rule, especially when multiple
  magic-less probes can accept the same bytes and polyglots can be genuinely plural;
- "format-bounded" does not imply "cheap enough to run unconditionally": on 71,983
  sufficiently large files, the tail locator alone has a 4.39 GiB worst-case aggregate,
  before central-directory reads;
- an unbounded scan is embedded-archive discovery, not ordinary format detection, and
  the current prefix-only peek primitive makes it `O(source size)` in both retained bytes
  and copying for a non-seekable source.

Confidence and provenance must be separate. In particular, every probe-only failure
should carry `format_unconfirmed`, regardless of whether the probe result was labelled
`GUESS` or `PROBABLE`.

The winning candidate's evidence ledger is a public outcome, exposed as an always-present
field on `ArchiveReader` and `ArchiveStream` as well as from standalone detection, with
`confidence` and `detected_by` **derived** from it rather than stored beside it. See
*The public surface* in §1 for the measured gap this closes, the declared-evidence kinds
that keep the field non-optional, and why the derivation is the library's judgement to
make on the caller's behalf.

## 1. The result should be an evidence ledger, not one winning string

The backend registry should continue to own detection data, but a declaration needs more
than `(offset, magic, format)`:

```python
@dataclass(frozen=True)
class DetectionDeclaration:
    name: str
    max_evidence: EvidenceStrength
    required_capabilities: frozenset[DetectionCapability]
    estimated_cost: DetectionCostEstimate
    evaluate: DetectionEvaluator


@dataclass(frozen=True)
class DetectionEvidence:
    kind: EvidenceKind
    strength: EvidenceStrength
    anchor: EvidenceAnchor
    offset: int
    bytes_examined: int
    validation: ValidationState
    estimated_random_bits: float | None = None
    detail: str | None = None


@dataclass(frozen=True)
class FormatCandidate:
    format: ArchiveFormat
    payload_offset: int | None
    evidence: tuple[DetectionEvidence, ...]
    prefix_kind: PrefixKind
```

`DetectionDeclaration` is scheduler input: `max_evidence` is the strongest result that
detector can possibly produce, capabilities say when it can run, and `estimated_cost`
orders declarations whose ceilings are equal. `DetectionEvidence` is achieved output.
The branch-and-bound check compares every unrun declaration's ceiling with the current
winner; it does not infer ceilings from result objects or run every detector to discover
them.

#### The supporting types

The listing above names five types it does not define. They are small, but two of them
(`DetectionCapability` and `PrefixKind`) carry rules stated elsewhere in this document, so
they are pinned here rather than left to the implementation.

**`DetectionCapability`** — what a declaration needs *from the source*, checked as
`d.required_capabilities <= source.capabilities(budget)` in the scheduler. It is the
mechanism behind the "unavailable" arm of the stopping rule and behind §11's degradation on
pipes:

| capability | supplied when |
| --- | --- |
| `PREFIX` | always — a bounded head read through the prefix workspace |
| `SIZE_KNOWN` | a cheap total size is available (§2 step 0) |
| `REMAINING_KNOWN` | bytes from the caller's current position are *provable*, not merely estimated |
| `TAIL` | the source can be read near its end — seekable, or spooled by explicit policy |
| `SEEK` | arbitrary range reads: the exhaustive tier, central-directory walks |
| `REREAD` | the source can be consumed and still presented to a backend afterwards |

The set is source-**and-budget** derived, not source-alone: an explicit spool policy makes a
pipe `TAIL`-capable, and `max_seeks = 0` withdraws `SEEK` from an ordinary file. That is why
the scheduler calls `source.capabilities(budget)` rather than reading a field off the
source.

**`DetectionCostEstimate`** — the *a priori* half of §10's cost model, expressed in the same
units as the receipt it will be measured against: prefix bytes, tail bytes, seeks, scanned
bytes, decode input, decode output, index bytes. Estimates order declarations whose ceilings
are equal and feed `affordable()`; the receipt records what actually happened. Two objects,
one vocabulary. A declaration that cannot estimate a field states an upper bound and never
zero, because `affordable()` reads the estimate as a promise.

**`DetectionEvaluator`** — the callable a declaration carries:

```python
DetectionEvaluator = Callable[
    [PrefixWorkspace, DetectionSource, int, DetectionBudget, DetectionCostReceipt],
    Iterable[FormatCandidate],
]
```

Returning an *iterable of candidates* rather than one optional record is required by the
tiers that find several: one scan pass over a 2 MiB window can yield several `ustar` hits at
different offsets, and each is a separate `(format, payload_offset)` candidate. An evaluator
that finds nothing yields nothing; absence is not signalled with `None`. The evaluator
charges the receipt for the bytes it requests, which is what lets `affordable()` be checked
once per declaration instead of once per read. The receipt is detection's own, not the
archive-open `CostReceipt` — §10's "do not overload an archive-open receipt with detection
I/O that happened before a reader existed", made structural.

**`EvidenceAnchor`** — what an evidence record's `offset` is measured *relative to*, which is
the metadata §"Anchoring and bits of constraint" needs and a bare integer cannot carry:

| anchor | meaning |
| --- | --- |
| `ORIGIN` | a fixed offset from the detection origin — gzip magic at 0, ISO at 32,769 |
| `CANDIDATE` | a fixed offset from *this candidate's* `payload_offset` — a TAR checksum at +257 inside an SFX payload |
| `END` | measured back from source end — the ZIP EOCD |
| `FLOATING` | located by scanning; no fixed relationship to either end |
| `NONE` | not positional at all — `NAME` and `ASSERTED` evidence |

`ORIGIN` and `CANDIDATE` coincide whenever `payload_offset == 0`, which is the common case.
Keeping them distinct is what lets a prefixed archive's internal evidence stay *anchored*
instead of degrading to `FLOATING` merely because the payload did not begin at zero — the
distinction that answers "is a checksum-valid TAR header at +257 of a scan hit anchored
evidence?" with yes.

**`PrefixKind`** — what precedes `payload_offset`, reported and never acted on: `NONE`
(payload at the detection origin), `ELF`, `PE`, `MACHO`, `SCRIPT` (a shebang or other text
stub), `OTHER` (bytes matching none of these). This is the field the `SFX_SCAN` rename
paragraph above leans on: the tier reports *what the prefix is* and stops asserting *why* it
is there. Classifying the prefix beyond these values is out of scope — archivey is not a
general file-type detector (§12) — and no rule in this document branches on the value.

**Where `estimated_random_bits` belongs: the evidence record, not the declaration.** The
same declaration produces different constraint on different sources — an anchored hit and a
floating scan hit of the same magic are not equally surprising — so a static per-declaration
number would be wrong exactly where the field is interesting. The declaration already
carries the only quantity the scheduler reads, `max_evidence`; neither the stopping rule nor
the priority keys consult bits, and §"The public surface" marks the field advisory and
unstable. It exists to explain a decision after the fact, not to make one.

#### The ceiling rule: one declaration, or two?

Several detectors can reach more than one class depending on what the source turns out to
be, which makes "the strongest result it can possibly produce" ambiguous unless the rule is
stated:

> **`max_evidence` is a ceiling, not a prediction.** The achieved class may be lower. Split
> a detector into **two declarations** only when reaching the higher class costs
> *materially more*, so the scheduler can price and exclude the expensive half separately.

Both cases occur, and getting this wrong breaks the stopping rule outright:

- **Magic-less content probes → split.** A bounded prefix decode reaches `BOUNDED_PROBE`;
  an exact whole-source decode to EOS reaches `COMPLETE`, the top of the lattice. Declaring
  a single ceiling of `COMPLETE` would mean *no detector can ever stop while probes are
  unrun* — every gzip, ZIP and 7z would pay for three probe decodes, contradicting §7's own
  "validated XZ header + `.xz` may stop" example. Declaring `BOUNDED_PROBE` would let §9's
  completeness rule produce evidence *above* the declared ceiling, breaking the invariant
  branch-and-bound depends on. So: a cheap prefix-probe declaration with ceiling
  `BOUNDED_PROBE`, and a separate **whole-source completion** declaration with ceiling
  `COMPLETE`, its own cost, and a capability requirement that the remaining size is known
  and within budget. The completion declaration should be able to reuse the prefix work
  rather than redo it.

  This composes with the stopping rule already stated rather than needing an exception:
  under `BALANCED` the completion declaration is **excluded by budget**, which is the stop
  predicate's own third arm, so a `SELF_VALIDATING` winner stops legitimately and the result
  records the search as incomplete in that respect. The consequence is explainable to a
  user: a small genuine `.br` is `GUESS` under `BALANCED` and `CERTAIN` under `THOROUGH`.

- **gzip → do not split.** Verifying `FHCRC` is free once the header has been read, so gzip
  is one declaration whose ceiling is `SELF_VALIDATING` and whose achieved class is
  `SIGNATURE_ONLY` whenever `FHCRC` is absent (§5).

The important fields omitted by today's `FormatInfo` are:

- **all provenance**, not one `detected_by` string;
- **validation state** (`VALID`, `INVALID`, `INCOMPLETE`, `NOT_APPLICABLE`);
- **search completeness**: which tiers were unavailable or skipped by budget;
- **retained candidates**, when more than one interpretation survives.

The winning candidate's evidence ledger is a required public outcome of this redesign,
not merely an internal implementation detail or a polyglot convenience:

- standalone detection must return the winning `DetectionEvidence` records;
- `open_archive()` / `open_stream()` must retain the same detection result for callers;
- a read error marked `format_unconfirmed` must carry that evidence (or a stable reference
  to the retained result), so the exception explains *why* the Boolean is true without
  requiring the caller to repeat detection and correlate two independent operations.

This requirement is narrower than an API that enumerates every non-winning candidate.
The all-candidates API's name and shape may stay open; exposure of the winner's evidence
cannot, because error-provenance semantics depend on it.

`payload_offset` is **already public** — a field on `FormatInfo`, which is in
`archivey.__all__` — and this design keeps it that way rather than withdrawing it.
`payload_offset=None` exists only on the proposed internal/extended `FormatCandidate` and
means "not computed within the index budget". Public `FormatInfo.payload_offset` remains
an `int`: zero means "confirmed at the detection origin" and a positive value marks SFX,
exactly as the shipped spec requires. The compatibility `detect_format()` view must either
pay to compute the offset or raise a budget/incomplete-detection error; it must never turn
unknown into zero. Exposing optional offsets publicly would require an explicit OpenSpec
API change and migration, not an incidental type widening in this design.

> **This is not settled — see §13.** Both stated options have a cost: charging a caller who
> wanted the *format* for a full central-directory walk, or turning a successful
> identification into a failure over one derived field. A third exists — separate
> identification from offset resolution, and let the ledger's search-completeness record say
> "identified; exact offset not computed". The paragraph above states the conservative
> default (never turn unknown into zero), which holds whichever way the question resolves. The related question of whether `payload_offset > 0` should keep
> meaning "self-extracting archive" is a naming one and is taken up under *The public
> surface* below; whether a caller should care what is *inside* a given archive is a
> separate post-1.0 idea, in [`dev-docs/IDEAS.md`](../IDEAS.md).

### The public surface: who sees the ledger, and in what form

Measured on shipped `main` (`a3dc408`), a caller who opens an archive sees essentially
none of this — and the result object is not merely unexposed, it is **discarded**:

| surface | what the caller gets |
| --- | --- |
| `reader.format` | the answer, ungraded |
| `reader.info` (`ArchiveInfo`) | `format`, `format_version`, `is_solid`, `member_count`, `comment`, `is_encrypted`, `is_multivolume`, `cost`, `extra` — nothing about detection |
| the reader itself | no public detection attribute; `_format_provenance` is private |
| the raised error | `format_unconfirmed: bool` and `source_format` — no *why* |
| `reader.diagnostics` | the one partial channel: detection emits into the reader's collector |
| `open_stream()` | worst case — the helper returns `detected.format.stream` and nothing else survives; the caller gets a stream and not even the container |

`open_archive()` reads four things off the `FormatInfo` (`format`, `encoding_hint`,
`payload_offset`, and `chosen_by`/`probe_only` via `_format_provenance`) and drops the
object at `core.py:386`. (`encoding_hint` was removed before 0.2.0, so the count is now
three.) Confidence, `detected_by` and corroboration are lost at open time.

Two consequences worth stating plainly, because both are evidence rather than opinion:

- **The diagnostics channel is asymmetric.** A caller *can* observe
  `FORMAT_EXTENSION_CONFLICT` and `PROBE_FORMAT_UNCONFIRMED`, because those are emitted
  into the reader's collector. So the **negative** signals are public and the **positive**
  ones are not: you can learn that the name contradicted the bytes, never that it agreed,
  nor how strong the evidence was.
- **Archivey's own CLI already pays for the gap.** `cli/info_cmd.py:run_info` calls
  `detect_format(archive)` and then `open_archive(archive)` — detecting twice, because the
  reader will not tell it. `VISION.md` calls the CLI "a wedge and second consumer …
  useful evidence of API gaps"; this is that evidence, and on a non-seekable source the
  workaround is not even available.

#### Requirement: the detection result is a field on the reader and the stream

`ArchiveReader` and `ArchiveStream` SHALL each expose the detection result as a field.
It SHALL always be present — never `None` — on the same reasoning that makes
`prefix_kind` always present: a caller should read it without first testing whether
detection happened to run.

Where detection did not run, the ledger SHALL say so as **declared evidence**, which is
truthful provenance rather than absent provenance. Two distinct kinds, and conflating them
would be a real loss:

| kind | source | strength |
| --- | --- | --- |
| `DECLARED_BY_CALLER` | the `format=` argument, which skipped detection | class `ASSERTED` — not content evidence; nothing verified it |
| `DECLARED_BY_CONTAINER` | a member stream's format read from the archive's own metadata (ZIP's compression method, 7z's coder chain) | **inherits the container's class** — a `SELF_VALIDATING` container declaring its member's codec is a far stronger claim than a caller's assertion |

`DECLARED_BY_CALLER` projects to `GUESS`, and under this document's reframing that is
exactly right rather than insulting: `GUESS` means *"the bytes did not confirm this
identity"*, and when the caller supplied the format the bytes were never consulted. The
existing `EXPLICIT_FORMAT_LISTED_EMPTY` diagnostic already encodes the same judgement —
`format=` is an override that gets reported, not trusted.

`DECLARED_BY_CONTAINER` is the case that makes a single `DECLARED` value insufficient.
A member stream inside a CRC-validated 7z is not a guess; the container structurally
declares its codec and the container itself was validated. Ranking it with the caller's
assertion would understate it as badly as ranking it with a bounded probe would overstate
a probe.

#### `confidence` and `detected_by` are both derived, from different fields

Both stay in the public API, and neither is stored:

- `confidence` — a property over the winning record's **class** (`COMPLETE` …
  `BOUNDED_PROBE`, `NAME`), projected onto the existing three-value enum.
- `detected_by` — a property over the winning record's **kind** (`MAGIC`,
  `ZIP_TAIL_PROBE`, `SFX_SCAN`, `EXHAUSTIVE_SCAN`, `CONTENT_PROBE`, `NAME`,
  `DECLARED_BY_CALLER`, `DECLARED_BY_CONTAINER`).

  Today's four values — `"magic"`, `"extension"`, `"content_probe"`, `"sfx_scan"` — keep
  their spelling and meaning, mapping to `MAGIC`, `NAME`, `CONTENT_PROBE` and `SFX_SCAN`.
  The rest are **new**: `ZIP_TAIL_PROBE` and `EXHAUSTIVE_SCAN` describe tiers that do not
  exist yet, and `DECLARED_BY_CALLER` / `DECLARED_BY_CONTAINER` describe results that are
  currently discarded before any caller sees them. So this is a widening of the value set,
  not a pure re-spelling, and it belongs in the migration list (§14).

That `DetectionEvidence` carries **both** `kind` and `strength` is what lets these two
coexist without being a second ranking: they summarize different columns of the same
record. `detected_by` names *which detector answered*; `confidence` names *how strong the
answer is*. Neither is rich enough to drive exception semantics — that keys on the class
directly, per §6 and §9.

> **Rename `SFX_SCAN` while these values are still changeable.** Shipped code defines
> self-extraction as an offset — `detection.py:115` reads
> `# nonzero only for SFX archives (is-SFX == payload_offset > 0)` — and the same tier that
> finds a real 7z installer also finds a JPEG with a ZIP appended, a `zipapp` (where the
> archive *is* the program and is meant to be run, not extracted), and junk prepended to a
> tar. `detected_by="sfx_scan"` is simply wrong for three of those four. Nothing here needs
> to classify the stub — `PrefixKind` already reports what the prefix *is*, and whether a
> caller should care about the payload is a separate post-1.0 question in
> [`dev-docs/IDEAS.md`](../IDEAS.md) — but the *name* should stop asserting intent.
> `prefixed_scan` or `embedded_scan` costs nothing now and is a public-value migration once
> this redesign ships.
>
> Two measurements bear on the tier itself, from 3,320 ELF/PE files under `/usr/bin`,
> `/usr/lib`, `/usr/local` and `/opt`: **zero** carry a real appended ZIP, and all **six**
> `PK\x05\x06` tail matches are false positives — `zip`, `zipnote`, `zipsplit`,
> `zipcloak`, `libzip.so`, `librevenge-stream.so`, carrying the signature as a string
> constant, every one parsing to nonsense (entry counts 19,280–55,381, central-directory
> offsets past EOF). A concrete instance of this document's own requirement that the tail
> tier *validate* rather than locate, on a directory every developer machine has.

Making them properties rather than fields is the point, not an implementation detail. Most
callers who care at all want one honest number and not the mechanism, so translating
evidence into trust is the **library's** judgement to make and publish. A stored scalar
can be constructed inconsistent with the ledger it claims to summarize; a derived one
cannot. It also stops equality and golden-value tests from pinning a redundant field.

The full ledger belongs in `__str__` / `__repr__`, where "bounded probe **and** a matching
name" can be rendered for a human, a log line, or `archivey info` — the composition that a
single scalar deliberately does not carry.

Per-record detail (`bytes_examined`, `estimated_random_bits`, anchors) SHOULD be treated as
advisory and unstable. The stable public commitments are the **kinds**, the **classes**,
and their ordering — the same conservatism that keeps public `payload_offset` an `int`.

#### Detecting once: the `detection=` handoff

Exposing the result as a field fixes the CLI's specific complaint — `run_info` can drop its
`detect_format(archive)` call and read the field off the reader instead — but it does not
cover the shape the CLI stands in for: **a caller who must decide on the detection result
before deciding whether, or how, to open.** That caller cannot use the field, because the
field only exists after the open it was trying to inform.

Today the only way to have both is to detect twice, and this document makes the second
detection *more* expensive rather than cheaper: an always-on ZIP tail tier, a
central-directory walk for an exact offset, whole-source completion under `THOROUGH`.
Doubling that is not a rounding error. So `open_archive()` and `open_stream()` SHOULD accept
a previously produced detection result and skip detection when given one:

```python
result = detect_format(source)
if result.confidence is not DetectionConfidence.CERTAIN:
    ...                                  # the caller's own policy
reader = open_archive(source, detection=result)
```

Three properties this needs, each a constraint rather than a convenience:

- **It is not `format=`.** `format=` is an override: it records `ASSERTED`, skips detection,
  and suppresses `format_unconfirmed` because the caller took responsibility (§6).
  `detection=` replays evidence *archivey itself* produced, so the reader's ledger, its
  `confidence`, and its `format_unconfirmed` behaviour are exactly what they would have been
  had the open detected for itself. Routing a detection result through `format=` — the only
  option available today — silently launders a `GUESS` into a trusted assertion, which is
  the opposite of what a caller inspecting the result wanted.
- **The result must name the source it came from.** A result handed to a *different* source
  is a caller bug the library should catch rather than honour: the result records an opaque
  source token (the path, or the stream object's identity plus its entry position) and a
  mismatch raises rather than opening the wrong bytes as the wrong format. This is a
  typo-catcher, not a security boundary — a path can change on disk between the two calls,
  and `detection=` inherits exactly the TOCTOU window that today's detect-then-open pattern
  already has. Worth stating so nobody later reads the token as an integrity check.
- **On non-seekable sources it is not an optimisation but the only way.** Detect-then-open
  works today only because a *path* can be reopened. On a caller-supplied pipe, detection has
  already consumed the prefix and a second detection cannot re-read it, so "look before you
  open" is currently inexpressible there. The handoff is what makes it expressible —
  provided the replay buffer travels with the result, which couples this parameter's design
  to §2's prefix workspace and §11's spool policy. The consequence is worth spelling out: on
  a non-seekable source the detection result **cannot be a pure value object**; it must carry
  or reference the buffered bytes, and its lifetime is therefore tied to the source's.

Scope: nothing else in this document depends on the parameter, and it can ship after the
field. It is stated here so the field's design does not foreclose it — in particular the
result must stay constructible and inspectable without a reader, which it already is. Being
a new keyword argument with no change to existing behaviour, it needs no migration row.

### Evidence classes

Evidence classes are totally ranked, strongest first:

| class | examples | what it establishes |
| --- | --- | --- |
| `COMPLETE` | a decoder reached stream end on the entire source; a complete container parse succeeded | the bytes form a complete instance under the parser's contract |
| `SELF_VALIDATING` | ZIP EOCD + central directory; 7z StartHeader CRC and bounds; XZ flags CRC; TAR checksum; LZ4 header checksum | a format-specific identifier and an independent consistency check agree |
| `DISCRIMINATING_HEADER` | RAR marker; ISO descriptor tuple; bzip2 header + block marker; zstd magic + legal descriptor | enough mandatory structure to make accidental identity remote |
| `SIGNATURE_ONLY` | a strong fixed-position signature whose validator is unavailable, or a damaged header after a strong signature | identity evidence without structural confirmation |
| `BOUNDED_PROBE` | a prefix decoder accepted Brotli, zlib, or LZMA Alone but did not reach source end | the prefix is compatible with the format; it does not establish a complete stream |
| `NAME` | `.zip`, `.tar.gz`, `.br` | a prior supplied by the caller's namespace, not content evidence |
| `ASSERTED` | the `format=` argument, which skipped detection entirely | an instruction, not an observation — nothing was consulted |

`ASSERTED` is bottom of the ranking for the same reason `NAME` is near it: neither is
evidence about the bytes. It is not "no evidence" — recording it is what lets the result
say *why* nothing was measured, and what makes the reader's detection field always
present (see *The public surface* above). The other non-detection kind,
`DECLARED_BY_CONTAINER`, is **not** a class of its own: a member stream whose codec the
archive's own metadata declares inherits the class the container itself achieved, so a
member of a `SELF_VALIDATING` 7z is `SELF_VALIDATING`, not a guess.

**A decode only counts as evidence when it decoded something.** A bounded probe that
succeeds having produced *only stored/uncompressed output* has learned nothing the header
did not already say — the decoder copied bytes. Such a candidate SHALL be graded on its
header alone and SHALL NOT reach `BOUNDED_PROBE` on the strength of the decode.

This already exists for one format and needs generalizing to the others. Brotli's
first-block framing gate (§9) is exactly this rule: an uncompressed or metadata first
meta-block is the class every false positive came from, and the gate exists because
"it decoded" was not evidence there. Of the three magic-less formats:

| format | has a stored mode? | status |
| --- | --- | --- |
| Brotli | yes — uncompressed / metadata meta-blocks | **handled** by the first-block gate |
| zlib / deflate | yes — `BTYPE=00` stored blocks | **gap**, see §5 |
| LZMA Alone | no — LZMA1 is always range-coded (uncompressed chunks are an LZMA2 feature) | not applicable |

Measured on `a3dc408`: `zlib.compress(payload, 0)` emits stored deflate blocks, 200,000
bytes in and 200,026 out; `detect_format` reports `ZLIB` / `PROBABLE` / `content_probe`;
64 KiB decodes cleanly and is byte-identical to the input. The only real evidence there is
the two-byte header, which admits **66 of 65,536 `(CMF, FLG)` pairs — about 2⁻¹⁰** — and
that weakness is precisely why zlib needs a probe rather than a magic entry. Reporting
`PROBABLE` for it overstates what was established.

Note this is about *identification*, not resource use: stored blocks are 1:1, so they are
the tool for a false identity, not for amplification. The separate question of bounding
decode work is in §13.

Do not assign points and add them. Evidence is correlated: a `.br` suffix and a Brotli
probe are not two random independent observations, and the base rate differs radically
between `/usr`, a browser cache, and a backup corpus.

### Anchoring and "bits of constraint"

Whether evidence is anchored to a fixed string/offset is useful metadata. It explains why
a decode behind a validated gzip or 7z header is categorically safer than an unconstrained
Brotli decode, and a declaration may carry a conservative random-data constraint estimate
for review and scheduling.

It is **not** the top-level ordering rule, and constraint bits are not a score:

- a short anchored gzip header can still be weaker than unrun far ISO evidence;
- zlib has mandatory header grammar but no single fixed byte string;
- v7 TAR has no `ustar` anchor but can have a checksum-valid 512-byte header;
- CRC bits and grammar fields are not automatically independent, and real corpora are not
  IID random bytes.

Therefore "all anchored evidence first; cost within that class; stop on a hit" recreates
the original defect in a different form: a weak near anchor can stop before stronger far
evidence. Anchor kind and estimated bits may refine evidence classes and schedule equal
classes, but the stopping rule remains "no unrun detector can tie or dominate".

Resolve equal-class candidates with ordered priority keys:

1. strongest content-evidence class;
2. semantic position: a format beginning at the detection origin outranks an unrelated
   embedded payload at a later offset;
3. end anchoring (`declared_end == source_end` before merely `<=`) within the same format
   and evidence class;
4. a matching **filename**, and only here: it may separate two candidates that are equal
   under keys 1–3, and may do nothing else. This is the tie-break role §6 grants it, and
   it does not conflict with `NAME` never raising a class — ordering among equals is not
   promotion. Both candidates keep the same `confidence` and the same `format_unconfirmed`
   behaviour whichever wins;
5. if incompatible candidates remain tied, report ambiguity rather than using registry
   order.

These are priority keys, not an additive score vector. The class decides first, each
subsequent key is consulted only on a tie, and candidates still equal after the last
settled key remain ambiguous. "Undominated" below means maximal under this class-plus-
priority relation, not a separate mathematical partial order.

**Refinement is not tie-breaking, and the distinction decides which key applies.**
Content-derived corroboration that *changes the class or the format* is refinement: it is
consumed by key 1 and never reaches key 4. The `(container, stream)` pair is the clearest
case — a gzip candidate whose decoded prefix contains a checksum-valid TAR header becomes
`TAR_GZ`; it does not leave independent `GZ` and `TAR_GZ` candidates tied. An earlier
revision offered that same inner-TAR checksum as key 4's example, which cannot happen: by
the time keys are consulted the refinement has already decided. Key 4 is for evidence that
distinguishes equals *without* being strong enough to promote either, which is exactly the
filename.

How often this key is reached: running all three magic-less probes independently over
33,947 real files gave 25 single-probe hits and **0 multi-probe hits**, so same-class probe
ties do not arise naturally on that corpus. They are reachable by construction — bytes can
satisfy zlib's header and Brotli's framing at once — and polyglots are in scope (§12), so
the rule has to be right; it is not a hot path.

### Confidence mapping

Keep the current enum for compatibility, but define it as **a projection of the winning
candidate's strongest content-evidence class** — not as a second, parallel score:

| confidence | meaning |
| --- | --- |
| `CERTAIN` | `COMPLETE` or `SELF_VALIDATING` |
| `PROBABLE` | `DISCRIMINATING_HEADER` or `SIGNATURE_ONLY` |
| `GUESS` | `BOUNDED_PROBE`, `NAME` or `ASSERTED` — **whether or not a matching `NAME` item is present** |

The rows are the evidence classes, one-for-one and with no overlap. That is the point: an
earlier revision described `PROBABLE` as "signature-only or a **well-calibrated** bounded
structural/decode probe" while the surrounding text said `BOUNDED_PROBE` projects to
`GUESS` unconditionally — the two rows then both matched every bounded probe, on the exact
case this document is about, with "well-calibrated" left undefined. Likewise `CERTAIN`
carried a third arm, "a format-specific header whose declared false-match risk is accepted
as decisive", which quietly reintroduced per-format judgement into what is claimed to be a
mechanical projection: accepted by whom, recorded where? Both are gone. If a bounded probe
should ever count as more than `GUESS`, that is a change to its **class** (with the
measurement in §13 to justify it), not a second opinion applied at projection time.

**A `NAME` item never raises confidence**, for the same reason it never suppresses
`format_unconfirmed`: it is not content evidence, and `NAME` ranks below `BOUNDED_PROBE`.
Letting it move the scalar would create exactly the second ranking this design exists to
remove — two candidates in the same evidence class reporting different confidences, with
no way to tell from the scalar which signal did it. The ledger carries the `NAME` item, so
a caller who wants to weigh it can, without the class pretending the bytes said more than
they did.

`GUESS` therefore means **"the bytes did not confirm this identity"**, not "this is
probably the wrong format" — the same reframing this document applies to
`format_unconfirmed`. A genuine `asset.js.br` that a bounded probe accepted is `GUESS`:
the answer is very likely right, and the bytes did not establish it. If that reads wrong
for a public enum, the fix is the enum's labels or the exposed ledger, not re-admitting
the filename to the scalar.

This is a deliberate change to shipped behaviour, and it is **not confined to Brotli**.
`_brotli_probe_confidence` currently returns `PROBABLE` when the name ends in `.br`
(shipped in #261), and the zlib and LZMA Alone probes return `PROBABLE`
*unconditionally*. All three are `BOUNDED_PROBE`, so all three become `GUESS` under this
mapping. The Alone and zlib move is the larger one and is easy to miss, because those
probes never had a name-based branch to notice.

`CERTAIN` does **not** mean the whole archive is uncorrupted. A 7z signature can identify
a damaged 7z archive even when its StartHeader CRC fails. Validation failure should often
lower confidence and attach a corruption diagnostic, not erase a highly specific format
identity and turn a useful `CorruptionError` into "unknown format".

The exact failure disposition is format-declared:

- for a short signature such as gzip's two bytes, a failed mandatory header check should
  normally reject the candidate;
- for a six- to eight-byte format identifier such as 7z or RAR, a failed checksum usually
  means "identified but damaged";
- absence of enough bytes is `INCOMPLETE`, never the same as a proved mismatch.

No error path should branch on `confidence`. Error provenance should ask whether the
winner was probe-only, name-only, structurally validated, or explicit.

#### Degenerate and truncated sources: what `INCOMPLETE` costs

"Absence of enough bytes is `INCOMPLETE`" is stated just above, and again in §5's bzip2 row,
but neither says what *class* an `INCOMPLETE` validation yields — so the rule currently has
no consequence. It needs one, because shipped behaviour is worse than the rule implies.

Measured on `main` (`a3dc408`): feeding each of the 15 registered magic entries a source
consisting of **nothing but that magic** returns `CERTAIN` in all 15 cases.

| source | bytes | shipped result |
| --- | --- | --- |
| `\x1f\x8b` | 2 | `GZ` / `CERTAIN` / `magic` |
| `BZh` | 3 | `BZ2` / `CERTAIN` / `magic` |
| `PK\x03\x04` | 4 | `ZIP` / `CERTAIN` / `magic` |
| the other 12 entries | 4–32,774 | `CERTAIN`, without exception |

A gzip header is at minimum 10 bytes and a bzip2 stream header is 4 plus a 6-byte block
marker, so none of these sources can contain a valid header of the format they were just
declared to be with certainty. Nothing here is malformed — the validator simply never ran.

> **An `INCOMPLETE` validation caps the candidate at `SIGNATURE_ONLY`**, whatever the
> declaration's `max_evidence` says. The signature matched; nothing corroborated it.

This is the case the ceiling rule already anticipates rather than a new mechanism:
`max_evidence` is what a detector could reach on a complete source, and a truncated source
is exactly where the achieved class falls below it. It costs nothing — a validator that runs
out of bytes already knows it did — and it composes with the rest: `SIGNATURE_ONLY` projects
to `PROBABLE`, and being *above* `BOUNDED_PROBE` it does **not** set `format_unconfirmed`.
That is the right reading. Two bytes of gzip magic are weak evidence, but they are evidence
*about the bytes*, which a filename is not.

Deliberately **not** proposed: rejecting a candidate whose source is shorter than the
format's minimum header. It is cleaner in the abstract and it discards the more useful
answer — a truncated `.gz` pulled off a damaged backup should report "GZ, truncated", not
"unknown format". Identification and completeness are different questions, and this document
keeps them apart everywhere else.

Two adjacent behaviours, both real, neither needing a rule of its own:

- **A zero-byte source with a name** is already covered by §6's filename rule, and it is
  worth checking that it comes out right. A zero-byte `empty.gz` on `main`: detection returns
  `GZ`/`GUESS`/`extension`, `open_archive` **succeeds**, the listing shows one fabricated
  member, and the read raises `TruncatedError` with `format_unconfirmed=False`. Under §6 the
  flag becomes true, which is correct — only the filename ever claimed gzip.

  That the open succeeds at all was a separate confirmed bug (since fixed by
  `2026-09-25-single-file-open-time-validation`): `SingleFileReader`'s eager probe opens and
  closes a codec stream without reading, and every stdlib codec validates on first read.
  Verified causally here: a zero-byte file opens cleanly under **all ten** single-file
  codecs today (gz, bz2, xz, zst, lz4, zlib, brotli, lzma-alone, lzip, Z), and patching the
  probe to `read(1)` turns **nine** of them into open-time errors. The tenth, `.Z`, still
  opens — its decoder treats an empty input as an empty stream rather than a truncated one,
  so the probe fix does not reach it and P15 needs a per-codec answer for that case rather
  than one read. This matters to this document because the deferred failure is the mechanism
  that keeps the empty-listing diagnostic from ever firing.

  **Since fixed** (`single-file-open-time-validation`): a seekable single-file source now
  raises at `open_archive` under all ten codecs, `.Z` included (its decoder now rejects a
  source shorter than the 3-byte header). The failure moved to open; the
  `format_unconfirmed` rekeying above is still this document's to make.

- **A zero-byte source with no name** raises `FormatDetectionError: no magic-byte match and
  no usable file extension`, which is misleading — there were no bytes to match. The
  incomplete-search record §1 already requires is the natural place to fix this: an empty or
  sub-minimum source is a **capability shortfall**, not an exhausted search, and the error
  should say which of the two happened. This is a message-and-record change, not a
  behavioural one; the raised type stays `FormatDetectionError`.

### Proposed evidence map for current formats

This map prevents a cheap validator from being promoted ad hoc into an early-stop class:

| detector after cheap validation | achieved class on success |
| --- | --- |
| gzip (`CM` + reserved `FLG`) — `SELF_VALIDATING` instead when `FHCRC` is present and verifies (§5) · compress `.Z` header | `SIGNATURE_ONLY` |
| bzip2 header + first marker · zstd/lzip header · ISO descriptor · validated ZIP local header | `DISCRIMINATING_HEADER` |
| XZ flags CRC · LZ4 header checksum · TAR checksum · 7z StartHeader CRC · RAR main-header CRC · validated ZIP tail/CD linkage | `SELF_VALIDATING` |
| zlib/LZMA Alone/Brotli bounded decode without exact EOS | `BOUNDED_PROBE` |
| exact whole-source decode/complete container validation | `COMPLETE` |
| filename only | `NAME` |

**Far fixed-offset evidence runs before the content probes — and that needs no special
rule.** `DISCRIMINATING_HEADER` dominates `BOUNDED_PROBE`, so a probe result can never let
the scheduler stop while a reachable far declaration is unrun. The measured defect this
closes is exactly a probe one: a bootable ISO's system area is claimed by the Brotli probe
when far magic was available at a known offset the whole time. The ordering falls out of
the ranking rather than being stipulated on top of it.

An earlier revision went further and required far declarations to run *even when the near
candidate is `SELF_VALIDATING`*, on the grounds that "far ISO can tie it and reveal an
intentional polyglot". That was wrong by this document's own table: the ISO descriptor
check is `DISCRIMINATING_HEADER`, which cannot tie `SELF_VALIDATING`, so running it would
change no selection outcome — it would only add a losing candidate to the retained list.
Under the default profile a `SELF_VALIDATING` near winner may therefore stop before far
declarations, and a far declaration is skipped when remaining size proves it impossible or
the caller excluded it and the result records an incomplete search.

**Recording losing candidates is what `THOROUGH` is for.** Stated generally, because it
applies well beyond ISO:

> Under `THOROUGH`, **every bounded declaration runs to completion even when its ceiling
> cannot beat the current winner**, so the ledger records everything the source could be
> said to be. `BALANCED` runs only what can change the answer.

Unbounded discovery is *not* part of that: `exhaustive_prefix_scan` is a separate opt-in
axis (§2 step 6, §10), not a budget level, precisely because its cost is not bounded by the
format.

Two placements in the table above are worth justifying rather than asserting, since they
are the rows most likely to be challenged:

- **TAR at `SELF_VALIDATING`** — `ustar` is the format-specific identifier and the header
  checksum is an independent consistency check, which is the class definition exactly. The
  obvious objection is that a 512-byte sum carries far fewer constraint bits than the CRC32s
  beside it. Measured, that objection does not survive: **0 hits in 2,000,000 random
  512-byte blocks**, and across **80,378 real files** the gate accepted 175 blocks of which
  167 are genuine tars and the other 8 are deliberately-malformed tar fixtures — i.e. zero
  genuine false positives. The constraint is not the numeric match but that eight bytes at
  offset 148 must *parse as octal ASCII* **and** equal the sum, which alone is worth roughly
  2⁻³⁰ on random data. Scan mode was measured separately and behaves the same way, because
  candidates are generated needle-first: searching 2 MiB windows across those 80,378 files
  produced **884 `ustar` candidates in the entire corpus** — about 0.011 per file, not one
  per offset — and the checksum is only ever tested at a position the 6-byte needle already
  selected.
- **v7 TAR (no `ustar`) is an anchored-only candidate, never a scan needle.** It has no
  identifier to generate candidates from, so in a scan it would have to be tried at every
  offset — the one case where the per-offset multiplication is real. §5's requirement of
  plausible numeric/type/name fields applies there and is not optional.

## 2. Precise acquisition and stopping algorithm

### Step 0 — establish the detection origin and budget

Collect, without consuming:

- the longest matching filename suffix, if any;
- whether the source can seek;
- a cheap total size and, where provable, bytes remaining from the caller's current
  position;
- the configured byte, seek, decode-input, decode-output, and spool budgets.

The distinction between total size and remaining size matters for a caller-positioned
stream. An overestimated size is safe for Brotli's current overrun rejection but is not a
proof that a later offset is reachable. A size gate may skip a detector only when the
remaining source is provably too short.

The extension is now available as metadata, but it cannot answer yet.

### Bounded prefix workspace

Use one detection-owned, monotonically growing prefix workspace for steps 1, 2, 4, and 6:

- a path keeps one detection handle open;
- a seekable caller stream records its entry position, reads forward once, and restores
  once in an exception-safe exit path;
- a non-seekable source uses the same replay buffer the backend will consume.

Consumers request candidate-relative ranges from that workspace. Extending from 256 KiB to
1 MiB reads only the delta, so the 2 MiB SFX window costs 2 MiB of unique source I/O rather
than 3.31 MiB of overlapping path/stream reads. This is the bounded implementation of the
`peek_range` contract needed by makeself, TAR SFX, and the Brotli chain walk.

The workspace does not make exhaustive scan, tail access, or arbitrary range reads free.
Its retained-byte ceiling and copied bytes remain part of the budget.

### The I/O shape detection is allowed

The workspace bounds *how many* bytes detection reads. It does not bound the **shape** of
the access, and on a source where seeking is cheap to permit and expensive to perform — an
HTTP range reader, a member stream from a solid block — the shape is what costs.

> **Detection SHALL perform at most: one forward-only pass from the detection origin; then
> at most one seek towards the end; then one read to end.** No backward seek, and no
> re-reading of bytes already retrieved.

This is a good shape for every source. A network source pays at most two range requests. A
solid member stream decodes forward once and, if the tail is reached at all, never rewinds
into a block it has already left behind. A local file loses nothing.

**The non-seekable path already obeys it; the seekable path actively violates it.**
`PeekableStream.peek` grows a forward buffer and never seeks, which is exactly the rule.
`detection._peek_prefix` on a seekable stream does `tell()` → read → `seek(start)`, and
`_read_at` repeats that around every far read, so every peek rewinds to the origin. There
is also no caching between peeks. Instrumenting a seekable stream through `detect_format`
on `a3dc408`:

| source | reads | forward seeks | backward seeks |
| --- | --- | --- | --- |
| gzip | 5 | 0 | **5** — the same 30 bytes fetched five times |
| ISO | 2 | 0 | **2** — 4,096 bytes, rewind, then 32,774 re-read *from zero* |
| ZIP, TAR | 1 | 0 | **1** |
| unrecognised, 40 KB | 2 | 0 | **2** |

So the discipline exists for the source type that cannot seek, and is missing for the one
where seeking is most expensive. Routing every source through the same monotonically growing
workspace is what closes it — the workspace's "extending from 256 KiB to 1 MiB reads only the
delta" property is the same property, stated for bytes rather than for seeks.

**What fits the shape.** Near magic, the 32,775-byte ISO descriptor, the cue-gated 2 MiB
scan and the magic-less prefix probes are all forward reads from the origin: one pass,
growing. The ZIP tail tier is one seek towards the end and a read to end. Nothing in the
acquisition order needs to interleave them.

**What does not fit, and it is exactly one thing.** Resolving an exact `payload_offset`
requires walking the central directory, which the EOCD points *backwards* to, and which
points backwards again to the earliest local header. That cannot be monotone. It is an
independent argument for the third option in §13's open question — separate identification
from offset resolution, and let the search-completeness record say "identified; exact offset
not computed" — because on a network or solid source the offset is not merely expensive, it
breaks the access discipline that makes the rest affordable.

#### When the tail read happens

It cannot be cued by finding ZIP magic at the front, because a ZIP with `PK\x03\x04` at
offset 0 is already identified by near evidence. The tier has two uses and only one of them
can be cued:

- **Discovery** — an appended or concatenated ZIP behind a prefix that produces no near
  magic (§4 cases a2 and g). Uncued by construction: cueing it on a front hit would make it
  find only ZIPs that were already found. This is the use that costs, because it means one
  tail read on *every* source, and most sources are not ZIPs. It is exactly what §10's
  cost gate is about, and why the tier stays out of `BALANCED` until that gate passes.
- **Upgrade** — a ZIP already found at offset 0, where EOCD geometry raises the class to
  `SELF_VALIDATING` and yields the exact offset. Cued by the near hit, and under
  `open_archive` it is not additional work at all: the ZIP backend reads the EOCD on open
  regardless, so detection is bringing it forward rather than adding it. Under a bare
  `detect_format()` it is additional, which is the asymmetry the budget should price.

**Nested archives are already gated, by the caller.** `open_archive`'s `seekable_members`
defaults to `False`, so a member stream is `FORWARD_ONLY` unless the caller opted in. The
tail tier's `TAIL` capability is therefore absent by default on exactly the sources where a
rewind would re-decode a solid block, and the caller who sets `seekable_members=True` has
declared they will pay for positioning. No new gate is needed for that case; the existing
capability check does it, provided the tier is written to require the capability rather than
to test `seekable()` directly.

### Step 1 — near evidence

Call `peek_more(4096)` once. Run every matching near declaration, not only the first table
entry. Each declaration returns zero or one candidate plus validation details.

Stopping condition:

- do not stop until every enabled fixed-offset declaration whose ceiling can tie or
  dominate the winner has run; in `BALANCED`, reachable ISO far evidence is mandatory;
- a short or unvalidated signature may **not** stop while an unrun far/tail/scan detector
  can produce stronger evidence;
- when collecting non-maximal/polyglot candidates, do not stop.

This keeps cheap common archives cheap without allowing two-byte gzip magic in an ISO
system area to hide the ISO descriptor.

### Step 2 — far fixed-offset evidence

For every far declaration whose end offset is not proved beyond EOF, request the maximum
required prefix. Today that is `peek_more(32775)` for the seven-byte ISO descriptor tuple:
descriptor type, `CD001`, and version.

Cost under the current primitive:

- at most 32,775 retained prefix bytes;
- if `_peek_prefix` does not cache across calls, 4,096 + 32,775 = 36,871 requested bytes;
- no seek for a non-seekable source, but its replay wrapper must retain the prefix.

A strong direct-format result may stop in single-result mode. A miss falls through.

### Step 3 — ZIP tail evidence (explicit opt-in until the default-cost gate is met)

When the source is seekable and the remaining size is at least 22 bytes:

1. inspect at most `min(remaining_size, 65535 + 22)` bytes at EOF;
2. search backwards for every EOCD candidate;
3. require the comment length to end exactly at EOF;
4. follow ZIP64 when sentinel fields require it;
5. validate disk/count fields according to supported split-archive policy;
6. derive and bounds-check the central directory, inspect referenced signatures, and
   reconcile local-header offsets;
7. on failure, resume the backward search rather than accepting a decoy.

The **EOCD locator** costs one tail-positioning operation plus restoration and at most
65,557 bytes. Strong validation additionally reads the referenced ZIP64 record (when
present), central-directory data, and at least one local header. Computing the exact
earliest local-header offset may require walking the entire central directory, whose size
is not bounded by 65,557 bytes. Therefore:

- a cheap candidate may be `DISCRIMINATING_HEADER` after bounded geometry plus a few referenced
  records, with `payload_offset=None`;
- a `SELF_VALIDATING` result with exact `payload_offset` charges all central-directory
  bytes against an index budget;
- size discovery, each range read, and restoration count as actual seeks/requests rather
  than being hidden behind the phrase "one seek".

Exact comment-to-EOF is the standards path and preserves the 65,557-byte completeness
bound. A separate compatibility policy may accept trailing bytes only after CD/local
validation, prefer an exact-EOF candidate, record the trailer, and charge a configured
`max_trailing_bytes`. Once arbitrary trailers are accepted, 65,557 bytes is no longer a
complete search bound relative to physical EOF; the result must say that.

A validated tail hit is `SELF_VALIDATING`. If the prefix carries an executable/script cue,
continue the bounded scan before deciding: an executable can contain both a ZIP payload
and a different SFX payload, and stage order must not silently choose intent. It may stop
only after every enabled declaration capable of tying/dominating it has run; explicit
non-maximal-candidate collection suppresses that early stop.

### Step 4 — cue-gated bounded forward scan

Grade cues using mandatory structure:

- bare `MZ`, `\x7fELF`, or `#!` is weak and only authorizes the scan;
- validated PE, ELF, or Mach-O is strong and additionally prevents a raw stream probe
  from becoming the selected answer;
- `ca fe ba be` produces no Mach-O cue unless the fat header and arch table parse, so Java
  class files do not pay for a scan.

Search the backend-declared needles in 64 KiB, 256 KiB, 1 MiB, and 2 MiB prefixes. A miss
currently requests:

```text
64 + 256 + 1024 + 2048 KiB = 3,473,408 bytes
```

to cover a 2,097,152-byte window: 1.65625× for paths/seekable streams, 1× underlying I/O
plus repeated copying for `PeekableStream`.

The bounded prefix workspace above should reduce the recommended implementation to 1×
unique I/O for every source kind. The 1.65625× figure remains the cost of today's
`peek_more(first_n_bytes)` implementation, not a desirable permanent contract.

Every hit must pass its format-declared validator. Resume one byte past a rejected
candidate; do not let an early decoy terminate the scan. Prefer an exact declared EOF as a
tiebreak but allow `declared_end < source_end` where the format/tool permits trailers.

Needles need a declared **anchor offset**, and every validator/probe must receive a view
relative to the candidate origin. TAR's `ustar` occurs at candidate offset 257, so a hit at
absolute `H` means candidate origin `H - 257`, not `H`. A gzip needle begins at candidate
offset zero. The current `peek_more(length)` always starts at source origin; makeself and
TAR SFX support therefore require a bounded `peek_range(candidate_origin, length)` (or an
equivalent candidate-relative view) before they are implementable correctly.

Compressor needles belong only under the `#!` cue and must include every cheap mandatory
discriminator available. For gzip that is at least `1f 8b 08` plus legal flags, followed
by a bounded decode and inner-TAR check.

### Step 5 — exhaustive discovery is a separate mode

Do not describe this as just another ordinary detection tier. Without a cue, a valid
archive found in arbitrary bytes may be:

- the file's intended payload;
- an embedded resource;
- an archive nested inside another format;
- one member of a polyglot.

The result therefore needs `prefix_kind=UNKNOWN`, retained candidates, and an explicit
embedded/discovery provenance. A validated hit is not evidence of producer intent.

The current `peek_more(n) -> first n bytes` interface also makes a whole-source scan
retain the whole source for non-seekable input and repeatedly re-request prefixes for
seekable input. A serious exhaustive mode needs one of:

- a reopenable independent handle and a streaming scanner;
- a seek-preserving `read_at(offset, n)`/range-peek primitive;
- an explicit bounded spool shared with the backend.

Until then, `exhaustive_prefix_scan=True` is an opt-in `O(size)` memory/copy operation,
not merely an opt-in CPU scan.

### Step 6 — magic-less content probes

Run all available content probes over the same bounded input. Do not return from the first
one that accepts. If zlib, LZMA Alone, and Brotli produce competing maximal hits, compare
their declared evidence and raise `AmbiguousFormatError` when no candidate dominates.

Before selecting a probe result:

- all affordable stronger tiers must have run;
- a skipped stronger tier must set `search_complete=False`;
- a strong executable cue prevents a raw-stream probe from winning;
- an inner-TAR hit refines the stream candidate;
- a matching extension corroborates but does not promote the candidate above a stronger
  evidence class.

If the probe holds the entire source, "decoder needs more input" is a rejection. If it
does not hold the entire source, that outcome remains inconclusive/positive according to
the per-format probe.

### Step 7 — filename fallback and final selection

Add the longest-suffix filename candidate only after content acquisition. Use it in three
ways:

1. corroborate the same content candidate;
2. break a tie between otherwise equal weak candidates;
3. provide a last-resort `GUESS` when no content detector accepted.

Never use it to restrict near/far magic, ZIP tail detection, or container SFX needles.
Wrong extensions are a founding use case. It may authorize extra expensive work under a
caller-selected budget, but it must not suppress other formats.

Select the unique maximal candidate. If two incompatible candidates remain tied after all
settled priority keys, raise `AmbiguousFormatError`, a dedicated `FormatDetectionError`
subclass carrying the tied candidates. This preserves existing broad
`except FormatDetectionError` handling while making the wrong-format choice loud.
`open_archive()` and `open_stream()` propagate the ambiguity by default; an explicit
`format=` continues to bypass detection.

| detection state | `detect_format()` | `open_archive()` / `open_stream()` |
| --- | --- | --- |
| unique winner, search complete for primary | return `FormatInfo` | open it |
| unique winner, explicit budget skipped a detector that could tie/dominate | return only through a result shape that reports `search_complete=False`; otherwise raise an incomplete-detection error | refuse automatic open unless policy explicitly accepts incomplete detection |
| tied maximal candidates | raise `AmbiguousFormatError(candidates=…)` | propagate; do not try registry order |
| no candidate | raise `FormatDetectionError` | propagate |

A future candidate-reporting API can return all interpretations without raising; its name
is deliberately left open. Default exhaustive try-open behavior is also deferred because
it must define validation depth, replay/cost limits, and aggregate failure semantics
(`dev-docs/IDEAS.md`).

For `open_archive`, a tentative raw-stream result must not silently expose a synthetic
member as though the format were confirmed. Either:

- require a caller policy that accepts tentative detection;
- validate the stream to an agreed bound before exposing the member; or
- raise a detection error carrying the candidate and evidence.

Container guesses are less dangerous because opening normally parses a real container
header immediately. The policy still belongs in the caller, not in confidence labels.

### The scheduler in one place

The rules above are stated per tier, which is how three contradictions survived review:
the probe ceiling (§1), the mandatory-far-ISO claim (§1), and priority key 4 (below) were
all interactions between paragraphs that never appear together. One listing is where such
interactions are visible. This is the normative shape; the prose above is its justification.

```text
detect(source, budget) -> Result:

    # ---- setup ------------------------------------------------------------
    origin   = detection origin (0, or the stream's current position)
    name     = filename, read once; recorded as NAME evidence, never as a gate
    prefix   = prefix workspace, grown on demand to budget.max_prefix_bytes
    receipt  = new cost receipt          # bytes, seeks, decode in/out
    incomplete = []                      # why the search is not exhaustive

    # Ceilings are resolved per source, not read from a static table alone:
    # a declaration whose capabilities are unmet cannot run, and one whose
    # higher class needs a capability it lacks is capped at the lower class.
    decls = [d for d in registry.declarations()
             if d.required_capabilities <= source.capabilities(budget)]
    for d in registry.declarations():
        if d not in decls: incomplete.append(("unavailable", d))

    candidates = []
    winner     = None

    # ---- acquisition, in evidence order ------------------------------------
    # Ordered by what each tier can establish, not by what it costs.
    #   1 near magic + validators          -> SIGNATURE_ONLY .. SELF_VALIDATING
    #   2 far fixed-offset (ISO)           -> DISCRIMINATING_HEADER
    #   3 ZIP tail (seekable)              -> SELF_VALIDATING
    #   4 cued bounded scan                -> validated hit's own class
    #   5 exhaustive scan (opt-in only)    -> validated hit's own class
    #   6 magic-less prefix probes         -> BOUNDED_PROBE
    #   7 whole-source completion          -> COMPLETE        (separate decl)
    #   8 filename                         -> NAME
    for tier in ACQUISITION_ORDER:
        for d in decls_in(tier):

            if not affordable(d, budget, receipt):
                incomplete.append(("budget", d)); continue

            # Branch and bound. THOROUGH suppresses this: it runs every bounded
            # declaration even when it cannot win, so the ledger records
            # everything the source could be said to be.
            if winner and not budget.collect_nonmaximal_candidates:
                if not can_dominate(d.max_evidence, winner):
                    continue

            for cand in d.evaluate(prefix, source, origin, budget, receipt):
                # A decode is evidence only if it decoded something: output that
                # is purely stored/uncompressed is graded on the header alone.
                if cand.evidence_is_stored_only():
                    cand = cand.regrade_to_header_class()

                # Refinement, not competition: corroboration that changes the
                # class or the format replaces the candidate rather than
                # competing with it (gz + inner TAR -> TAR_GZ, one candidate).
                candidates = merge_or_refine(candidates, cand)

            winner = select(candidates)          # see priority keys below

            if stop_now(winner, decls, budget):
                break

    # ---- selection ---------------------------------------------------------
    # Ordered priority keys, consulted only on a tie, never summed:
    #   1 strongest content-evidence class
    #   2 semantic position (origin outranks a later embedded payload)
    #   3 end anchoring (declared_end == source_end before <=)
    #   4 matching filename — separates equals only, promotes nothing
    #   5 still tied -> ambiguous
    maximal = undominated(candidates)
    if not maximal:            raise FormatDetectionError(receipt, incomplete)
    if len(maximal) > 1:       raise AmbiguousFormatError(maximal, receipt, incomplete)

    return Result(winner       = maximal[0],
                  evidence     = maximal[0].evidence,   # the public ledger
                  search_complete = not incomplete,
                  incomplete   = incomplete,
                  receipt      = receipt)


stop_now(winner, decls, budget) -> bool:
    # The stated rule, unchanged: stop when the winner is unique and every unrun
    # declaration is incapable of dominating it, unavailable by capability, or
    # excluded by an explicit budget recorded in the result.
    return (winner is unique
            and all(not can_dominate(d.max_evidence, winner)
                    or unavailable(d) or excluded_by_budget(d)
                    for d in unrun(decls)))
```

**What this makes visible that the prose did not.**

- **Probe ceilings.** `can_dominate` reads `d.max_evidence`, so a single probe declaration
  ceilinged at `COMPLETE` would make `stop_now` permanently false and every archive pay for probes.
  Splitting tiers 6 and 7 is what keeps the cheap half at `BOUNDED_PROBE` and lets the
  expensive half be excluded by budget under `BALANCED` — the third arm of `stop_now`,
  not a special case.
- **Mandatory far ISO.** There is no exception arm for it. Far evidence precedes probes
  because `DISCRIMINATING_HEADER` dominates `BOUNDED_PROBE`, so `can_dominate` keeps ISO
  unrun-and-blocking until it has run. Nothing else is needed.
- **`THOROUGH`.** One flag, `collect_nonmaximal_candidates`, suppresses the branch-and-bound
  skip. Unbounded discovery is *not* on this axis — the exhaustive scan is tier 5 and gated
  by its own opt-in, because its cost is not bounded by any format.
- **Refinement vs tie-breaking.** `merge_or_refine` runs before `select`, so class-changing
  corroboration never reaches the priority keys. That is why key 4 is the filename and not
  the inner-TAR checksum.

**Still open, and it shows here.** `affordable()` and `excluded_by_budget()` both depend on
whether budgets are per-detection aggregates or per-candidate — the question recorded in
§13. Written as an aggregate above (`receipt` accumulates across candidates); with
per-candidate budgets the scan tiers become unbounded in total work.

## 3. Where this disagrees with PR #257

1. **Ordered acquisition: agree. First match wins: disagree.** Acquisition should be
   cost-aware; selection should compare typed evidence after every relevant stronger tier
   and after all same-class probes.
2. **PR #257 still contains two orders: disagree.** Its canonical list puts far magic
   before tail/scan/probes, while the modified SFX requirement says a scan miss falls
   through to probes and then far magic. One requirement must own the complete order.
3. **Far magic before content probes: agree.** The bootable ISO is a decisive
   reproduction.
4. **Near magic always `CERTAIN`: disagree.** Two-byte magic without mandatory header
   fields is not comparable to self-validating structure.
5. **Validated ZIP tail: agree on the mechanism, not its stated bound or unconditional
   cost rationale.** EOCD location is bounded to 65,557 bytes; exact offset/strong
   validation can require the whole central directory.
6. **Cued scan and validated resume: agree.** The cue is a cost gate; validation is the
   correctness gate.
7. **Tail hit always skips scan: disagree when the prefix itself is a cue or non-maximal
   candidates were requested.** That is exactly where multiple SFX payloads are plausible.
8. **Exhaustive scan as a normal next tier: disagree.** It is embedded discovery with a
   different result and resource contract.
9. **Extension as up-front corroborator and last answer: mostly agree.** It must not
   promote a bounded probe above stronger evidence or restrict the candidate set.
10. **Brotli compressed-first `PROBABLE`: disagree for an uncorroborated hit.** The
   real-file measurement does not support that public label. Keep the class as telemetry.
11. **Strong executable cue suppresses content probes: agree as a selection rule.** It
    should not prevent probes from being run for diagnostics if a caller explicitly asks
    for non-maximal candidates.
12. **Confidence driving `format_unconfirmed`: disagree.** The provenance-based follow-up
    (#262, implemented in #267) is the correct direction. Its *mechanism* is not: keying
    the stamp on a `corroborated` Boolean that a matching filename can set is a second
    predicate over the same question. The stamp should key on the winning content-evidence
    class — see §6 and §9.
13. **Per-probe `dict_size != 0` guard: disagree and remove.** Zero is legal LZMA Alone;
    the guard is a false-negative compatibility bug introduced to compensate for ISO's
    ordering.
14. **Candidate-relative probing is underspecified.** Makeself and TAR needles occur after
    a prefix, but today's probe/inner-TAR API reads only from source offset zero.

## 4. Required cases

**"Required" means the algorithm must produce this result under a named policy**, not that
every case passes at the default budget. Two do not, and the policy column says so rather
than leaving it to be discovered during implementation — §10 holds the ZIP tail tier out of
`BALANCED` until the corpus-cost gate passes, and two cases below reach ZIP only through
that tier.

| Required case | policy | result under this algorithm |
| --- | --- | --- |
| (a1) `zipapp` (`#!` prefix + ZIP) | `BALANCED` | The `#!` weak cue authorizes the bounded scan (§2 step 4), which finds ZIP's declared `PK\x03\x04` needle and validates it. Reached **without** the tail tier — this is why the gap below is easy to miss. |
| (a2) concatenated ZIP behind a non-cueing prefix | `THOROUGH` | No cue fires, so no scan; the tail tier is what finds it. Seekable: bounded EOCD/geometry validation yields ZIP; walking the central directory yields `CERTAIN` and exact `payload_offset` at the earliest local header (EOCD-derived base for empty ZIP), with the two offset conventions handled explicitly. If the index budget is exhausted the **internal** `FormatCandidate` retains ZIP with `payload_offset=None`; what the public `detect_format()` view reports in that state is the open question in §1/§13, and is *not* `None`. Non-seekable: only a cue scan can identify it, and automatic open still needs explicit spooling. |
| (b) PE/ELF + 7z/RAR | `BALANCED` | Cue-gated scan; reject decoys; validate 7z StartHeader CRC/bounds or RAR main header; return the container and payload offset. |
| (c) makeself `.run` | `BALANCED` | `#!` authorizes `1f 8b 08` and other sufficiently discriminating stream needles; bounded decode plus checksum-valid inner TAR returns `TAR_GZ` at the gzip offset. |
| (d) `ca fe ba be` | `BALANCED` | Parse the fat Mach-O header/arch table. A real Mach-O cues the scan; an ordinary Java class produces no cue and pays no 2 MiB scan. |
| (e) Mach-O stub claimed by a probe | `BALANCED` | A parsed Mach-O is a strong cue. The scan finds and validates 7z; raw-stream probes cannot win on the stub. |
| (f) bootable ISO | `BALANCED` | The descriptor tuple at 32,768–32,774 is checked before content probes; return ISO. No per-probe ISO workaround is needed. |
| (g) JPEG + ZIP | `THOROUGH` | `\xff\xd8\xff` is not a cue, so nothing authorizes a scan and only the tail tier finds the payload. Under `THOROUGH`, tail validation returns ZIP with a nonzero payload offset and a non-archive/other prefix; JPEG identity remains out of scope. Under `BALANCED` this is a `FormatDetectionError` — an accepted consequence of the cost gate, not an oversight. |
| (h) extension/content agreement | `BALANCED` | Near evidence already answers the 98.9%. For the residual, agreement is recorded but cannot skip stronger unrun tiers. |
| (i) conflict diagnostic | `BALANCED` | Describe the actual evidence: e.g. "extension suggests ISO; bounded Brotli probe suggests Brotli; using ISO descriptor evidence." Never hardcode "magic bytes" for a content probe. |

Splitting (a) matters because its two halves resolve by different routes: a `zipapp` is
found at the default budget via the cue, a bare concatenation is not found at all. An
earlier revision described both through the tail route, which the default disables — so the
row documented a mechanism that does not run for a case that half the time does not need it.

**Accepted consequence:** archivey does not find a JPEG+ZIP polyglot at the default budget.
That is deliberate. The founding backup-corpus workload does not need polyglot discovery,
and paying an extra seek per file across a whole sweep to get it would invert the cost
argument §10 makes at length.

## 5. Cheap structural validators

"Magic" should mean a signature declaration **plus an optional structural validator**.
The validator strengthens or diagnoses the match; it is not always a hard gate.

| format | recommended check | disposition and compatibility caveat |
| --- | --- | --- |
| gzip | `CM == 8`; FLG reserved bits 5–7 are zero; parse optional-field bounds; verify `FHCRC` when present and fully available | Safe mandatory checks. Do **not** require `XFL in {0,2,4}` or `OS in 0..13,255` — see the note below. |
| bzip2 | `BZh`, block size ASCII `1`–`9`, then block magic `314159265359` or the empty-stream EOS marker | Strong and cheap at stream start. Treat a short source as incomplete. Later blocks are bit-aligned, but the first marker after the byte-aligned stream header is suitable here. |
| compress `.Z` | `1f 9d`; max-code width at least 9 and supported up to 16; inspect block-mode and reserved bits | Width is structural. Historical decoders warn and continue when reserved bits are set, so reserved bits should downrank/warn rather than erase identity unless archivey intentionally rejects that compatibility. |
| XZ | six-byte magic; two Stream Flags; CRC32 over flags; first flag byte zero; reserved high nibble zero | CRC is mandatory and ideal. A CRC-valid but unsupported check ID is "XZ with unsupported feature", not "not XZ". |
| zstd | regular-frame magic or one of the 16 skippable-frame magics; reserved frame-header bit zero; parse the descriptor and present fields within bounds | Safe for the current frame version. A local check confirmed the installed decoder accepts a legal skippable frame before a regular frame while `detect_format` raises `FormatDetectionError`, so skippable-first detection is a current correctness gap. |
| LZ4 frame | four-byte magic; FLG version `01`; reserved bits/BD legal; parse optional fields; verify the one-byte xxHash header checksum | The checksum is the strongest cheap check. Failure identifies a damaged header; it need not erase the four-byte format identity. |
| lzip | `LZIP`; version 1; coded dictionary size resolves to 4 KiB–512 MiB | Mandatory for the current format. A future version is "lzip version unsupported", not arbitrary data. |
| TAR | parse the full 512-byte header and accept the stored checksum against both unsigned POSIX and historical signed sums | This should replace bare `ustar`. It also permits a conservative v7-TAR candidate without `ustar`; require plausible numeric/type/name fields because checksum-only detection has a different collision surface. All-zero "empty TAR" remains fundamentally indistinguishable from padding. |
| ZIP at origin | parse the local/empty header fields; for seekable sources prefer EOCD geometry plus referenced CD/local records | `PK\x03\x04` is useful; `PK\x05\x06` is an empty ZIP only with a valid EOCD; `PK\x07\x08` alone is too contextual to call `CERTAIN`. Exact earliest-local-header offset can require the whole CD. |
| 7z | six-byte signature; version support; StartHeader CRC over the next 20 bytes; NextHeader offset/size within known source | Use this at offset zero as well as for SFX hits. CRC failure after the six-byte identifier should normally mean damaged 7z, not unknown bytes. |
| RAR | RAR4/RAR5 marker plus parseable/CRC-valid main header | The long marker already identifies strongly; main-header validation makes scan hits safe and distinguishes corruption. |
| ISO 9660 | at offset 32,768 require type 0–3, `CD001`, version 1; optionally inspect consecutive descriptors for a PVD and terminator under a higher budget | Seven constrained bytes need a 32,775-byte prefix and are better than five. Type 255 at sector 16 cannot start a valid set because it terminates before the mandatory PVD; invalid surrounding fields should lower confidence or indicate damage. |
| zlib | any RFC 1950 header with `CM=8`, `CINFO<=7`, and `(CMF*256+FLG) % 31 == 0`; account for `FDICT`; **require at least one entropy-coded deflate block before the decode counts as evidence** | The current four-header allow-list accepts only common 32 KiB-window, no-dictionary encodings. Valid streams with smaller windows begin `18`, `28`, … `68` and are currently missed. The stored-block clause is the zlib counterpart of Brotli's first-block gate: a `BTYPE=00`-only stream decodes perfectly while proving nothing beyond a 2⁻¹⁰ header (§1). A stored-block stream is still *valid* zlib — the clause changes its grade, not whether it can be identified. |
| LZMA Alone | legal properties byte; any 32-bit dictionary field; size field; then bounded decode/completeness | Do **not** reject dictionary size zero. The LZMA specification allows every 32-bit value and requires decoders to round values below 4 KiB up to 4 KiB. |
| Brotli | RFC-valid WBITS/meta-block framing; source-length overrun; whole-source completeness; bounded chain walk where permitted | No prefix check can manufacture a signature the format does not have. Keep this in the bounded-probe class unless a complete decode reaches EOS. |

**The `FHCRC` check does two separate jobs; keep them apart.** *Verify-when-set* is a
**precision** gate: `FLG.FHCRC` is set in about half of random data, so requiring the 16-bit
CRC to match whenever the bit is set drops random survival from 1.0 to
`0.5 + 0.5 × 2⁻¹⁶ ≈ 0.5` — one bit, free, and it applies regardless of class.
*Promote-when-verified* is the separate claim that a verified `FHCRC` lifts gzip from
`SIGNATURE_ONLY` to `SELF_VALIDATING` (§1). A header whose `FHCRC` bit is set but whose
CRC16 is not fully available is `INCOMPLETE`, not a pass.

**`XFL` / `OS` as identity gates — a future investigation, not a present rule.** Measured on
this container, 1,115 gzip streams used `XFL` ∈ {2 ×966, 0 ×145, 4 ×4} and `OS` ∈ {3 ×1,107,
255 ×8}. Three `XFL` values out of 256 would be a real false-positive reduction if it held.
But this is precisely the case the methodology note at the top warns about: `OS` showing two
values is a fact about one distribution's toolchain, not about producers in general, and
decoders provably ignore both fields — a gzip stream still decoded here after `XFL` was set
to 1 and `OS` to 254, so nothing stops a producer writing anything. Settling it needs a
heterogeneous corpus (Windows and macOS producers, Java's `GZIPOutputStream`, Go's
`compress/gzip`, browsers, CDNs) measured for false-negative risk, not just false-positive
reduction. Until then the rule above stands: do not gate identity on them.

Three local checks confirmed the compatibility points:

- a Python-produced LZMA Alone stream still decoded correctly after its dictionary field
  was changed to zero;
- a gzip stream still decoded after changing `XFL` to 1 and `OS` to 254;
- `backports.zstd` decoded a skippable-first stream that archivey's current detector did
  not recognize.

The first is not merely permissive decoder behaviour: the LZMA specification explicitly
allows the zero value. Therefore `_alone_header_plausible()`'s `dict_size != 0` rejection
is an ordering workaround that creates a real false negative. Move ISO ahead of probes and
remove that workaround.

## 6. The filename's role

The filename belongs in several places, but never as an exclusion filter:

- **naming prior:** available from the start; when it agrees, append a `NAME` item to the
  candidate's evidence ledger rather than collapsing agreement into a Boolean;
- **work authorizer:** under a constrained budget, it may justify an otherwise optional
  expensive format-specific check;
- **tie-break:** only between candidates with the same content-evidence class;
- **last-resort answer:** `GUESS`, after all enabled content detectors decline.

It must not:

- prevent a detector for a different format from running;
- promote extension + bounded probe above unconsulted exact/validated evidence;
- suppress a conflict diagnostic;
- raise the winning candidate above `BOUNDED_PROBE`, or change whether a later failure is
  marked probe-only.

The last rule follows from the class ranking rather than discarding filename agreement.
`NAME` ranks below `BOUNDED_PROBE`; adding it preserves both observations in the ledger
but cannot change the strongest content-evidence class. A checksum-valid inner-TAR upgrade
is different: it adds stronger **content** evidence and may move the candidate out of the
bounded-probe class.

#### When `format_unconfirmed` is set — stated once, normatively

Every other statement in this document gives this by example. The rule is:

> `ArchiveyError.format_unconfirmed` SHALL be set on a decode failure when **archivey chose
> the format** and the strongest content-evidence class supporting that choice is at or
> below `BOUNDED_PROBE`.

| how the format was chosen | flag on decode failure |
| --- | --- |
| content probe (`BOUNDED_PROBE`) | **yes** |
| filename only (`NAME`) | **yes** |
| caller's `format=` (`ASSERTED`) | **no** |
| magic, structural hit, or whole-source completion (`SIGNATURE_ONLY` and above) | no |

The clause that carries the weight is **"archivey chose the format"**. It excludes
`ASSERTED` without a name-based exception: *we trust what the caller says, not what the
file says*, and when the caller passes `format=` archivey is not guessing, so it has
nothing to be unconfident about. `ASSERTED` still projects to `GUESS` for *confidence* —
it really is the weakest basis — because confidence and this flag answer different
questions.

**Filename-only belongs on the yes side for a reason stronger than its rank.** The
extension fallback is reached *only because every content signal declined*. That is not
weak evidence, it is the explicit absence of evidence after trying — arguably a better
case for the flag than a probe hit, which at least decoded something successfully.

Two consequences of stating it this way, both changes to shipped behaviour and both
belonging in the migration list (§14):

- **Filename-only failures start carrying the flag.** Measured on `a3dc408`, a 40,000-byte
  zero-filled file named `backup.gz`, `.bz2`, `.xz`, `.zst`, `.br` or `.lzma` is detected by
  extension at `GUESS`, opens, lists one fabricated member, and fails on read with
  `format_unconfirmed=False` — archivey blaming the bytes for a format only the filename
  ever claimed. Same for `backup.rar` of zeros, which raises `CorruptionError` about a file
  that was never a RAR.
- **The diagnostic code must become provenance-neutral.** `PROBE_FORMAT_UNCONFIRMED` names
  one of the three sources; the event is "a decode failed on a format archivey guessed".
  Rename it (e.g. `FORMAT_UNCONFIRMED_ON_DECODE`) and record the provenance in its context.

**The empty-listing codes stay as they are, and the asymmetry is correct.** An empty listing
raises nothing, so there is no exception to carry a flag — that channel is necessarily
diagnostic-only. It is also far narrower than it looks: across 15 formats × 2 payloads
(zeros and random), the only empty listing produced was a zero-filled `.tar`, because a
zero-filled file is a structurally valid empty TAR. Every container — ZIP, RAR, 7z, ISO,
TAR+GZ — raised `CorruptionError` instead. So `EXTENSION_FORMAT_UNCONFIRMED` fires for
essentially one shape, while the situation it is *named* for overwhelmingly ends in a decode
failure. That is what makes the decode-failure side the one worth getting right.

> **Interacts with a shipped bug.** The single-file cases above reach *read* rather than
> *open* only because `SingleFileReader`'s eager open-time validation opens and closes a
> codec stream without reading, and every stdlib codec validates on first read (since
> fixed by `2026-09-25-single-file-open-time-validation`). Fixing that moves these
> failures to open time; it does not by itself make them honest, which is what this rule
> is for.

`format_unconfirmed` must mean "the bytes did not confirm this identity", not "the
identity is probably wrong". A genuinely truncated `x.br` may therefore carry the flag:
its name supports Brotli, but neither bounded decoding nor the truncated stream reached a
content-confirming endpoint. The exposed ledger makes that distinction visible instead
of forcing one Boolean to pretend the filename was absent or conclusive.

This deliberately contests the rule shipped in PR #267/#268 (merged 2026-08-26 as
`a3dc408`), which treats a matching extension as `corroborated=True` and suppresses the
flag. It is therefore a **scheduled replacement of shipped behaviour**, not an objection
to a pending change.

**Measured on two independent trees, the rule buys nothing on the false-positive side.**
#267's post-completeness census: 29 fabrications, none with a matching extension. Re-run
on `a3dc408` over a different tree (63,343 files): 23 content-probe claims, 19
fabrications (0.030%), all 19 stamping, and again **zero** corroborated fabrications.

**Its cost, on genuine damaged files, is now sized rather than asserted.** The same run
found 4 genuine streams, and the whole tree holds exactly 4 files with any magic-less-codec
extension — the same 4. They split:

| genuine stream | name | corroborated | stamps today |
| --- | --- | --- | --- |
| `underscore.min.js.br` | `.br` | yes | no |
| `underscore.min.js.map.br` | `.br` | yes | no |
| `jquery.min.js.brotli` | `.brotli` | **no** | **yes** |
| `jquery.min.map.brotli` | `.brotli` | **no** | **yes** |

`.brotli` is not a registered extension (only `.br` and `.tar.br` are), so two genuine
Brotli streams already carry `format_unconfirmed` on shipped `main`. So removing extension
corroboration newly affects **two files here**, on a tree where two files of the same kind
already pay that exact cost silently. The trade is real but small, and half of it is
already incurred by an unrelated naming gap.

That is a presentation trade-off, not evidence that a filename confirms content. Note also
that `/usr` is the friendliest possible sample for filenames — packaged software has
curated names — so 4-of-4 genuine should not be read as establishing the extension as a
discriminator on the backup corpus `VISION.md` names as the founding workload.

**Reverting #267 is not the way to remove this rule.** #267 never suppressed a stamp the
previous confidence-keyed rule produced: "old stamps, new does not" reduces to `GUESS`
**and** corroborated, which is unreachable — every extension that corroborates a Brotli
result has `stream is BROTLI`, exactly what made `_brotli_probe_confidence` report
`PROBABLE`, the inner-TAR arm forces `PROBABLE`, and zlib and Alone are unconditionally
`PROBABLE`. Reverting would restore the larger blind spot (Alone and zlib never stamping
at all) while leaving the filename rule in place via confidence.

The 98.9% figure — of 1,303 files under `/usr` carrying an extension archivey knows,
1,289 were already answered by near magic at step 2, leaving 2 where an extension and a
content probe agree (recorded in `dev-docs/IDEAS.md`, *Extension-first detection,
and stopping early on agreement*) — argues **against** an extension-agreement shortcut as a
default optimization: near evidence has already captured almost the entire population
where agreement is cheap. The two residual files are too small a sample to justify a new
control-flow rule.

### Rejected: a contradiction check under `format=`

It is tempting to have archivey *notice* when an explicit `format=` contradicts the bytes.
`EXPLICIT_FORMAT_LISTED_EMPTY` already concedes the principle that an override producing a
suspicious outcome gets reported, and the common mistake is real: `format=ZIP` on a
`.tar.gz` raises `CorruptionError: truncated or corrupt ZIP` — archivey blaming the bytes
for a format only the caller ever claimed, the same honesty gap the filename rule above
fixes, with the override standing in the filename's place.

The version worth rejecting is the strongest one, not a strawman: a near-magic check only,
no validator and no scan; firing only on a *positive* contradiction, never on absence (of 26
known formats **14 have no magic entry at all** — `BROTLI`, `ZLIB`, `LZMA_ALONE`,
`DIRECTORY` and every TAR combo — so `format=BROTLI`, the documented way to open a Brotli
stream, must never warn); comparing compatibility rather than equality, reusing
`detection._is_deferred_inner_tar` so `TAR_GZ` over a `GZ` match is not a contradiction; and
diagnostic-only, never raising, since raising is just *the bytes overrule the caller*
arriving through the error path.

**It still fails, on cost that archivey cannot see.** The check needs bytes from the source
head, which on a caller-supplied stream means reading forward and seeking back.
`StreamCapability` is a two-value ordering, `FORWARD_ONLY < SEEKABLE`; there is **no
source-side notion of an expensive seek**. An HTTP range reader and a member stream from a
solid 7z both report `SEEKABLE`, so no capability gate can tell them from a local file.
On the first, the rewind is an extra round trip for a read the ZIP backend — which goes to
the tail first — never wanted. On the second it is re-decoding a solid block, and archivey
already treats that as serious enough for control flow: `_maybe_warn_rewind`
(`archive_stream.py:428`) exists because "`seek(10)` after reading a gigabyte decodes ten
bytes and destroys a gigabyte of progress", and `STREAM_REWIND_REDECOMPRESSES` can be
escalated to stop the caller. The check would therefore trip archivey's own rewind guard,
on the one call where the caller explicitly asked for no detection.

Measuring it on a path is what hid this: `read(4096)` plus matching all 14 near entries is
8.8 µs against 273 µs for the whole `open_archive(format=ZIP)` call — 3.2%, and completely
unrepresentative. The honest statement is that the cost is **unbounded and unknowable** on a
caller-supplied stream. Placement does not rescue it, and the lazy variant (check only after
the open fails) inherits the same rewind on the same sources.

> **So `format=` performs no detection I/O of any kind.** Its contract is *do exactly what I
> said and no work I did not ask for*, and that is the property that makes it usable as an
> escape hatch at all.

**What survives, and it is most of the value.** The `detection=` handoff above already gives
a caller both halves explicitly and with no implicit I/O: `detect_format()` produces the
ledger, `open_archive(source, detection=result)` consumes it, and the reader's evidence then
contains a real `MAGIC` record — so a corroborated identity reports `CERTAIN` rather than a
flat `GUESS`, and a contradiction is visible before the open rather than after it. The
capability is not lost; it moves to where the caller opts into paying for it.
`EXPLICIT_FORMAT_LISTED_EMPTY` remains the zero-cost honesty channel under a bare `format=`,
because the listing happened anyway. And `format=` keeps its settled semantics unchanged:
`ASSERTED`, projecting to `GUESS`, never setting `format_unconfirmed`.

## 7. When agreement may stop work

Agreement may skip only tiers whose maximum evidence cannot dominate the current winner.

Examples:

- validated XZ header + `.xz` may stop ordinary single-result detection after all
  fixed-offset evidence required by the selected policy;
- Brotli bounded probe + `.br` may **not** skip ISO far magic or a validated ZIP tail;
- gzip short header + `.gz` may not skip stronger fixed-offset evidence;
- extension + any probe may skip another equally weak optional probe only if the caller
  explicitly chose that budget and the result says the search is incomplete.

This is the exact branch-and-bound stopping rule:

> Stop when the winner is unique and every unrun detector is either incapable of
> producing a candidate that dominates it, unavailable by source capability, or excluded
> by an explicit budget recorded in the result.

The last arm does not make the result certain; it makes it budget-limited.

## 8. Candidate restrictions

Restrictions that preserve correctness:

- skip fixed-offset evidence only when remaining size proves the offset unreachable;
- restrict compressor SFX needles to `#!`, because that is a real wrapper grammar and
  materially reduces short-magic collisions;
- suppress raw-stream selection after a structurally valid executable cue;
- run an inner-TAR check only after an outer stream candidate exists;
- skip a probe when its backend is unavailable, while recording the unavailable evidence
  path.

Restrictions that are not acceptable:

- probe only the extension's format;
- exclude content candidates because the suffix disagrees;
- use the `(container, stream)` taxonomy to hide another outer container before its
  evidence was checked;
- treat "source is seekable" as proof that a 64 KiB tail read is within the caller's
  budget.

## 9. Brotli

### Confidence split

The compressed/uncompressed-first split is useful telemetry, but it should not determine
public confidence by itself.

The random-data result (`0.014%` compressed-first) does not transfer to the measured real
population measured in the Brotli investigation
(`dev-docs/investigations/brotli-content-probe-results.md`, pre-completeness-gate: 64
fabricated compressed-first claims versus 4 genuine streams). That is a
base-rate and data-distribution failure, not a contradiction in the random experiment.

Recommended mapping:

- complete decode to EOS with the entire source and no forbidden trailing bytes:
  `CERTAIN` content evidence;
- bounded probe refined by a checksum-valid inner TAR: `PROBABLE` or stronger according
  to the resulting TAR evidence;
- bounded probe without exact EOS — Brotli compressed or uncompressed first, zlib, or
  LZMA Alone, with or without a matching name: `GUESS`; retain the first-block class and
  the optional `NAME` item as separate evidence.

This follows from the confidence mapping above rather than being a Brotli-specific rule:
`BOUNDED_PROBE` projects to `GUESS`, and a `NAME` item cannot raise it. Note the scope —
zlib and LZMA Alone report `PROBABLE` unconditionally today, so they move too.

More importantly, every failure whose winning content class remains `BOUNDED_PROBE`
carries `format_unconfirmed=True`. The move away from confidence (#262, implemented in
#267) is correct; the final predicate should be the strongest content-evidence class, not
a `corroborated` Boolean. A matching filename may choose between otherwise equal bounded
candidates, but it neither confirms the bytes nor suppresses the signal.

**The follow-up that lands this touches two sites, not one.** The filename decides the
stamp through `_extension_corroborates` (#267), and decides confidence through
`_brotli_probe_confidence`'s `.br`-to-`PROBABLE` rule (#261). They are the same rule
expressed twice; removing only the first leaves the second contradicting this mapping.
`openspec/specs/error-handling` on `main` already records that scope.

### Completeness

The completeness rule is sound:

```text
if the probe holds every source byte:
    "needs more input" is rejection
```

It is not a "reject small files" heuristic. A nine-byte valid Brotli stream that reaches
EOS survives; an incomplete 15-byte prefix that merely asks for byte 16 does not.

The implementation must know that the prefix contains all bytes **remaining from the
detection origin**. A total underlying stream size that overestimates the remaining size
only loses the optimization; it must never be treated as an exact remaining length.

### Chain walk

The chain walk is worth implementing under an explicit read/link budget. It is derived
from framing, helps the large-source population where the 2²⁴ first-block limit is
vacuous, and does not create false negatives when budget exhaustion means "inconclusive".

It does not violate the non-consuming contract in principle: `peek_more` already exists
to obtain a larger non-consuming prefix, and the inner-TAR probe already reaches beyond
4096 bytes. It does widen the **cost and retention** contract. Keep Brotli knowledge in
the codec by giving the probe a bounded range-read/peek callback rather than moving its
parser into the generic detector.

No better zero-cost invariant is apparent. Once a compressed meta-block begins, finding
its successor requires decoding its Huffman/LZ77 body. The useful next steps are therefore
more structure, not a threshold:

- walk byte-aligned metadata/uncompressed links;
- parse compressed blocks through the real decoder under input/output limits;
- accept a strong result when EOS is reached on the whole source.

One suggested discriminator is
`decoded_output_bytes >= consumed_input_bytes` for compressed-first hits. It may be useful
telemetry, but it is not a Brotli invariant: the format permits a compressed meta-block
whose representation expands, and an unusual encoder need not make the reference
encoder's profitability choice. Never make it a hard rejection rule. It is worth adding
the ratio to the residual census to see whether it improves ranking without false
negatives on the positive corpus.

## 10. Cost model and presets

Expose budgets, not only booleans:

```python
@dataclass(frozen=True)
class DetectionBudget:
    max_prefix_bytes: int
    max_tail_bytes: int
    max_seeks: int
    max_scan_bytes: int
    max_decode_input: int
    max_decode_output: int
    max_index_bytes: int
    max_probe_links: int
    spool_non_seekable_up_to: int
    collect_nonmaximal_candidates: bool
```

Suggested policies:

| policy | behavior |
| --- | --- |
| `BALANCED` (default) | 4096 near; ISO far; ZIP tail disabled until the corpus-cost gate below passes; 2 MiB scan only on cues; bounded probes/inner TAR; no exhaustive scan; no implicit spool |
| `FAST` | caller-selected smaller tail/scan/decode budgets; returns `search_complete=False`; must not silently let a weak result stand in for skipped stronger evidence |
| `THOROUGH` | balanced plus explicit ZIP tail, non-maximal candidate collection, bounded full-stream completion where affordable, and explicit embedded scan on a reopenable/seekable source |

The founding backup-corpus use case argues for `BALANCED`, not extension-first and not
exhaustive. The always-on ZIP tail tier is a **hard implementation gate**, not a
provisional default: the fact that 65,557 bytes is format-bounded proves completeness, not
affordability. Before enabling it in `BALANCED`, measure aggregate bytes, seeks,
central-directory reads, and cold-cache wall time over the backup corpus and make the
acceptance threshold explicit. Until then it may exist only behind an explicit
`THOROUGH`/experimental budget.

The detector should return the actual cost receipt already aligned with archivey's cost
philosophy: prefix bytes requested, unique bytes read, tail bytes, index/central-directory
bytes, seeks/range requests, decoded input/output, and buffered/spooled bytes.
This is detection-specific measured work, complementary to the existing `ListingCost` /
`AccessCost` / `StreamCapability` axes and `CostReceipt`: reuse their vocabulary for
capabilities and kinds of work, but do not overload an archive-open receipt with detection
I/O that happened before a reader existed.

## 11. Non-seekable sources

Do not implicitly buffer an entire pipe to make ZIP detection possible.

Reasons:

- the ZIP backend itself requires random access, so detection alone does not solve open;
- unbounded memory use violates the cost contract;
- waiting for EOF changes a streaming open into a whole-input operation;
- a socket may not have an imminent EOF.

Default degradation:

- near/far prefix evidence and cue-gated forward scans still work through replay buffering;
- ZIP tail evidence is unavailable;
- the result records the skipped capability;
- `open_archive` raises the appropriate non-seekable/capability error if detection finds a
  format whose backend cannot consume the source.

Offer an explicit spool policy that writes at most `N` bytes to a seekable temporary file
and shares that object with the backend. Spill-to-disk is preferable to unbounded RAM.
A prefixed ZIP on a pipe is then detectable only when the caller chose spooling and the
source ended within budget. That is the right trade.

## 12. Polyglots and multiple truths

Archivey should represent multiple **archive** truths, but it should not become a general
file-type detector.

For JPEG + appended ZIP, archivey can truthfully report:

```text
ZIP payload at offset N; prefix is non-archive/other-format bytes
```

It need not identify JPEG. Callers needing both MIME identities should compose archivey
with libmagic or another file detector.

When two archive candidates survive:

- return the unique dominant candidate when one exists;
- if neither dominates, raise `AmbiguousFormatError` carrying both candidates rather than
  selecting whichever backend was registered first;
- leave the name and exact shape of a future all-candidates inspection API open.

That future API is separate from the required exposure of the **winning** candidate's
evidence in §1. The latter must land with the evidence-class redesign so
`format_unconfirmed` errors are self-explanatory; it does not need to wait for polyglot
enumeration.

Without this, the acquisition order becomes an undocumented intent policy. For example,
an executable can contain both an EOF-anchored ZIP and a CRC-valid 7z payload. "ZIP tail
runs first" is not evidence that the producer intended ZIP.

## 13. What to measure next

The weakest support is not the Brotli mechanism; that is well explained. It is the use of
corpora whose base rates do not resemble the founding workload — and, per the methodology
note at the top, the fact that every measurement here comes from a single Debian-family
container.

Open questions this document deliberately does **not** settle:

- **What `detect_format()` reports when an exact `payload_offset` exceeds the index
  budget** (§1): pay for the central-directory walk, raise a budget/incomplete error, or
  separate identification from offset resolution and let the search-completeness record say
  "identified; exact offset not computed". Only the conservative floor is settled — never
  turn unknown into zero.
- **Whether `XFL` / `OS` are worth using as gzip identity gates** (§5), which needs a
  heterogeneous producer corpus measured for false-negative risk, not just false-positive
  reduction.
- **How detection prices a source where seeking is cheap to *permit* and expensive to
  *do*** (§2, §10, §11). `StreamCapability` is a two-value ordering,
  `FORWARD_ONLY < SEEKABLE`, so an HTTP range reader, a member stream from a solid 7z, and
  a local file are indistinguishable to every capability gate in this document. Archivey
  models this carefully on the *member* side — `AccessCost.SOLID`, and
  `_maybe_warn_rewind` / `STREAM_REWIND_REDECOMPRESSES`, whose escalation can stop a caller
  outright — and not at all on the *source* side.

  This surfaced while rejecting the `format=` contradiction check (§6), but it is not
  confined to it. §11 answers "not seekable"; nothing answers "seekable, but each seek costs
  a round trip or a block".

  §2's *I/O shape* rule answers most of it without needing to model the cost at all — one
  forward pass, at most one seek towards the end, one read to end, no rewinds — because that
  shape is affordable on every source, so nothing has to ask how expensive a seek would have
  been. Two residues remain. **Sizing**: the budget's limits are counted in bytes and seeks,
  and on a range-request source the meaningful unit is *round trips*, so `BALANCED`'s 32,775
  ISO bytes and the tail tier's 65,557 are priced in the wrong currency even when the shape
  is right. That matters most for the tail tier's cost gate (§10), which is stated as an
  aggregate byte and seek threshold. **Declaration**: nothing lets a source say which it is.
  `seekable_members=False` already keeps nested member streams `FORWARD_ONLY` by default, so
  the worst case is caller-declared, but a seekable network source is indistinguishable from
  a local file. Options: a third `StreamCapability` value, a source-side cost hint on
  `DetectionCapability`, or accepting the shape rule as sufficient and leaving the unit
  mismatch documented.
- **What bounds detection's decode work, and at what scope** (`DetectionBudget`, §10). The
  budget lists nine limits but never says whether they are per-detection aggregates or
  per-candidate, and the answer decides a measured amplification.

  Scope first, because the terms have been used loosely: a **detection** is one
  `detect_format()` / `open_archive()` call; a **declaration** is one detector
  (format × tier), a fixed set; a **candidate** is one `(format, payload_offset)` under
  consideration. Fixed-offset tiers are self-limiting — all 15 magic entries sit at fixed
  offsets (0, 257, 32,769), so each format matches at most once. **Only the scan tiers
  multiply candidates**, so this is a scan-tier question, not a global one.

  Measured on `a3dc408`, a 2 MiB window packed with back-to-back decoys:

  | | |
  | --- | --- |
  | valid gzip headers found (`resume one byte past` a rejected candidate) | 209,715 |
  | needle search over the window | 27.7 ms, once |
  | cheap header validation, all candidates | 135.6 ms — 0.65 µs each |
  | *failing* decode attempts, all candidates | 0.2 s |
  | **decoys that decode successfully to a 64 KiB per-candidate cap** | **1.26 s, 1,365 MiB output — 683× amplification** |

  Two things this measurement settles. **Memory is not the problem**: each candidate's
  output is discarded, so peak memory is bounded by the per-candidate cap whatever the
  candidate count. **Time is**, and a per-candidate cap cannot bound it — 683× is
  candidate-count × per-candidate cap, so only an aggregate does. Nor would a *ratio* limit
  help: each decoy above is individually 683×, under `ExtractionLimits`' 1000× default, and
  an attacker can trivially tune to 100× per decoy and still do gigabytes of aggregate work.
  `ExtractionLimits` is scoped to `extract` / `extract_all` in any case, so detection-time
  decoding is currently unbounded, and the threat model's O1 covers *listing*-time metadata
  bombs rather than this.

  Candidate mitigations, which fail differently and compose: an **aggregate
  `max_decode_output`** per detection bounds the resource that actually blows up, at the
  cost of an early legitimate candidate starving later ones; a **per-format scan-candidate
  cap** bounds attempts and preserves per-candidate generosity, at the cost of decoy
  resistance — N decoys before the real archive and it is missed. That trade is real and
  unavoidable: "resume one byte past a rejected candidate" buys unlimited decoy resistance
  and is exactly what generates the 209,715.

  **What to measure before choosing:** realistic scan-candidate counts on the founding
  backup corpus. If real prefixed archives yield ≤5 candidates, a cap in the tens closes
  this at no cost and the trade never bites. That legwork pairs with the corpus survey this
  section already needs.

  Two smaller gaps in the same model, neither needing measurement: `DetectionBudget` has no
  field for **far fixed-offset reads**, so `BALANCED`'s "4096 near; ISO far" is
  self-contradictory as a config (the ISO descriptor needs a 32,775-byte prefix); and
  "resume one byte past a rejected candidate" should say past its **start**, since past its
  rejected *extent* would let a decoy hide a real archive inside its claimed range.

Run one labelled, stratified evaluation:

1. real backup trees with names preserved, including wrong/missing extensions;
2. genuine positives from old and current writers for every format;
3. damaged/truncated positives, so validators do not accidentally erase identity;
4. non-archive negatives stratified by file family (executables, source, media, databases,
   VM images, random/encrypted);
5. no-magic positives, deliberately oversampling Brotli, zlib, and LZMA Alone;
6. prefixed archives and deliberate polyglots.

For each detector declaration, report:

- true/false positives before and after structural validation;
- overlap matrix between probes;
- results at offset zero separately from arbitrary-offset scan collisions;
- confidence calibration/positive predictive value by corpus stratum;
- false negatives by writer/version;
- unique bytes read, requested bytes, seeks, retained bytes, decode input/output, and
  cold-cache wall time;
- how often the winner changes when tail/far/scan tiers are disabled.

Two current numbers should not carry decisions they do not measure:

- `1f 8b` appearing 423 times at arbitrary offsets in ELF files is directly relevant to
  an SFX scan, but it says little about false matches at **offset zero**;
- `/usr` having only two extension+probe residuals says little about a Brotli-heavy or
  backup corpus.

Specific experiments:

- measure the always-on ZIP tail tier over the actual backup corpus; its locator-only
  worst-case across 71,983 large files is 4.39 GiB, but the real tail total is
  `sum(min(size, 65557))`, and CD/local validation adds separately budgeted reads;
- enumerate every valid near-header shape and its offset-zero collision rate before/after
  the proposed validator;
- test TAR signed/unsigned checksums and v7 headers from historical writers;
- add legal LZMA Alone dictionary values below 4 KiB, including zero;
- generate zlib streams for every legal `CINFO` and with `FDICT`;
- build a `.br`-rich positive corpus with compressed-, uncompressed-, metadata-, and
  empty-first streams;
- record decoded-output/input ratios for every compressed-first Brotli hit, as a possible
  ranking feature rather than a validity gate;
- add a skippable-first zstd fixture and decide how concatenated/skippable frames compose
  into one detected stream;
- compare a one-shot 65,557-byte ZIP tail read with a 4 KiB-then-expand strategy on the
  residual population: ordinary ZIPs usually stop at near magic, so most tail attempts
  may be non-ZIP misses where the adaptive strategy reads more, not less;
- survey non-executable prefixed 7z/RAR files before treating the cue set as complete;
- survey PE/ELF/Mach-O and non-shebang script wrappers whose first archive-shaped payload
  is a bare gzip/xz/zstd/bzip2 stream with no container magic; use the result to keep the
  `#!`-only rule, widen it with validated needles, or record the false-negative policy;
- seed multi-archive polyglots to exercise the chosen ambiguity policy.

The immediate ambiguity policy is now fixed (`AmbiguousFormatError`), but the probe-overlap
matrix remains a release/migration measurement: quantify how often zlib, LZMA Alone, and
Brotli tie on real negatives and positives so release notes and compatibility guidance can
describe the behavior cliff rather than discovering it from user reports.

Until those results exist, one release gate and three API/calibration decisions remain
open:

- **release gate:** what measured aggregate I/O/latency threshold is sufficient to enable
  the 65,557-byte tail probe in the default corpus budget;
- numeric thresholds behind `CERTAIN`/`PROBABLE`;
- the eventual behavior/name of the all-candidates inspection API and exhaustive
  ambiguity fallback (the immediate policy is settled: raise `AmbiguousFormatError`).
- the exact public field/type names for exposing the winning evidence on detection,
  readers, and `format_unconfirmed` errors; the exposure itself is required.

### Test obligations this design creates

Everything above is *measurement*: it chooses thresholds, once, from corpora. What follows
is *testing*: it pins behaviour afterwards, in CI, where it has to survive later edits. They
are separate deliverables, and only the second belongs in the OpenSpec change rather than in
a one-off script under `scripts/exploration/`.

**Golden fixtures, one per required case.** Each row of §4 needs a committed fixture and a
pinned expected result — format, evidence class, `payload_offset`, `prefix_kind`,
`search_complete`, and the `confidence` / `detected_by` projections — evaluated under the
policy that row names, since two of the ten deliberately fail at `BALANCED`. Pinning the
*ledger* and not only the format is the whole point of §1: two results with the same
`format` can differ in what they justify, and a test asserting `format` alone cannot tell
them apart — it would pass unchanged through every regression this document is trying to
prevent. Negatives carry the same weight as positives: the six `PK\x05\x06` false positives
under `/usr/bin` are a required *non*-detection, and the repo's existing corrupted and
truncated fixtures are what keep a validator from erasing an identity it was only meant to
grade (corpus stratum 3 above).

**Property tests for the stopping rule.** This is the part most likely to break under later
edits, because every declaration added to the registry changes it and none of its invariants
are local to the code being edited. Over randomly generated declaration sets (ceilings,
capabilities, cost estimates) and stub sources with scripted evaluators, assert:

- **soundness** — the winner the scheduler stops on is the winner an exhaustive run of every
  declaration would select. `stop_now` may save work; it may never trade away a stronger
  result;
- **order independence** — permuting declarations within a tier changes the receipt but not
  the winner, or else raises `AmbiguousFormatError`. A registry-order-dependent answer is
  precisely the defect §12 refuses;
- **monotonicity in budget** — a larger budget never yields a *weaker* class for the same
  source, and `THOROUGH` never returns a different winner than `BALANCED`, only more
  retained candidates. This is what makes "re-run it with `THOROUGH`" honest advice instead
  of a coin flip;
- **`search_complete` does not lie** — whenever it is true, no declaration was skipped for
  budget or capability reasons.

These need no real archives — the source is a stub and the evaluators return scripted
candidates — so they are cheap enough to run on every commit, which is the point of choosing
them over more fixtures.

**Fuzzing with decoy-dense inputs.** The 683× amplification above is not a corpus property;
it was constructed, so the regression guarding it must be constructed too. `tests/atheris_fuzz`
already carries a `detect_format` target, but it asserts only that nothing escapes as a
non-`ArchiveyError` — it bounds *crashes*, not *work*. The addition is a seed family packed
with back-to-back near-miss headers for each scan-tier format, plus an assertion that the
aggregate cost receipt stays inside the budget's limits. That assertion is why the
budget-scope question can be deferred at all: it pins the invariant — detection's decode
work is bounded by the declared budget — rather than the mechanism that achieves it, so it
holds whichever way the scope resolves and fails loudly if neither does. Pair it with
structure-aware fuzzing of the §5 validators themselves: every one of them parses
attacker-controlled length and count fields, and a validator that raises an unexpected
exception type converts an identification into a crash.

**One end-to-end pin the CLI already suggests.** `archivey info` over each golden fixture,
output compared against a committed expectation, asserts that the ledger survives the whole
path from detection to public rendering — the path where `main` currently drops the object
at `core.py:386`. It costs one file and catches the class of regression where the evidence
is computed correctly and then thrown away, which is the exact failure this document opens
by documenting.

## 14. Relationship to PR #257

This investigation is the redesign input for
[`prefixed-archive-detection` PR #257](https://github.com/archivey-dev/archivey/pull/257), not a
sibling OpenSpec change and not advisory material to defer until after implementation.
Before #257 implements production code, it should revise its detection-order requirement,
selection/stopping rules, declaration metadata, ambiguity behavior, and ZIP-tail default
gate to match the decisions here. That keeps one OpenSpec change responsible for the
overlapping `format-detection` requirement and avoids another archive-order conflict.

This document remains non-normative: #257's revised delta becomes the contract only after
review and archive. Until that revision exists, #257's first-match algorithm should not be
implemented as written.

### What changes for callers, in one place

The behaviour changes this document proposes are argued in the sections that motivate
them, which means nobody can see the whole set at once. Collected here so #257's revised
delta and its release notes can be written from one list rather than a re-read.

| # | change | today | proposed | where argued |
| --- | --- | --- | --- | --- |
| 1 | **Bounded probes report `GUESS`** | zlib and LZMA Alone are `PROBABLE` unconditionally; Brotli is `PROBABLE` when compressed-first or `.br` | all three are `GUESS`; only a whole-source completion reaches higher | §1 confidence mapping, §9 |
| 2 | **`format_unconfirmed` covers filename-only results** | set only for content-probe failures | set whenever archivey chose the format and its strongest content evidence is at or below `BOUNDED_PROBE` — so a failing `.gz`/`.rar` identified by name alone now carries it; an explicit `format=` still does not | §6 |
| 3 | **`PROBE_FORMAT_UNCONFIRMED` is renamed** | names one of the three provenances | provenance-neutral (e.g. `FORMAT_UNCONFIRMED_ON_DECODE`), with the provenance in its context | §6 |
| 4 | **`detected_by` gains values** | `"magic"`, `"extension"`, `"content_probe"`, `"sfx_scan"` | those four keep their spelling, plus `zip_tail_probe`, `exhaustive_scan`, `declared_by_caller`, `declared_by_container` | §1 public surface |
| 5 | **`sfx_scan` should be renamed** | means "payload at a nonzero offset", so it labels JPEG+ZIP polyglots and `zipapp` as self-extracting | a neutral name (`prefixed_scan` / `embedded_scan`) before these values become public | §1 public surface |
| 6 | **`AmbiguousFormatError` is new, and reaches `open_archive`** | first registry hit wins silently | tied maximal candidates raise, carrying both | §12 |
| 7 | **`detect_format` can report an incomplete search** | always returns or raises `FormatDetectionError` | may additionally report that tiers were skipped by budget or capability; `payload_offset` exhaustion is the open case in §13 | §1, §13 |
| 8 | **Stored-only decodes are regraded** | a `BTYPE=00` zlib stream is `PROBABLE` on the strength of a decode that copied bytes | graded on its 2⁻¹⁰ header alone; still identified as zlib | §1, §5 |
| 9 | **The detection result becomes a public field** | discarded at `core.py:386`; the CLI re-runs `detect_format` to see it | an always-present field on `ArchiveReader` / `ArchiveStream`, with `confidence` and `detected_by` derived from it | §1 public surface |
| 10 | **JPEG+ZIP and bare concatenation need `THOROUGH`** | not detected at all | detected under `THOROUGH`; `FormatDetectionError` under `BALANCED` until the ZIP-tail cost gate passes | §4, §10 |
| 11 | **A source too short to validate is regraded** | all 15 magic entries return `CERTAIN` on a source that is only the magic — 2 bytes of `\x1f\x8b` is a `CERTAIN` gzip | an `INCOMPLETE` validation caps the candidate at `SIGNATURE_ONLY` → `PROBABLE`; the format is still identified | §1 |
| 12 | **An empty source says so** | `FormatDetectionError: no magic-byte match and no usable file extension` — for a file with no bytes to match | the same type, with the incomplete-search record distinguishing a capability shortfall from an exhausted search | §1 |

Items 1, 2, 8 and 11 change what existing callers observe without any API change, so they
are the ones that need release-note prose rather than a changelog line. Items 3–6 are API
surface. Items 9, 10 and 12 are additive.

Two of these are worth flagging as *deliberately* user-visible regressions rather than
improvements: item 1 downgrades the reported confidence of genuine `.br`, `.zz` and
`.lzma` files, and item 10 means a polyglot that a future `THOROUGH` would find returns an
error at the default budget. Both are consequences of rules argued at length above, but a
release note that does not say so will read as a bug.

## 15. Primary format references

- [RFC 1952 — gzip](https://www.rfc-editor.org/rfc/rfc1952)
- [RFC 1950 — zlib](https://www.rfc-editor.org/rfc/rfc1950)
- [RFC 7932 — Brotli](https://www.rfc-editor.org/rfc/rfc7932)
- [RFC 8878 — Zstandard](https://www.rfc-editor.org/rfc/rfc8878)
- [XZ file format](https://tukaani.org/xz/xz-file-format.txt)
- [LZMA file format](https://github.com/tukaani-project/xz/blob/master/doc/lzma-file-format.txt)
- [LZMA SDK specification](https://github.com/jljusten/LZMA-SDK/blob/master/DOC/lzma-specification.txt)
- [LZ4 frame format](https://github.com/lz4/lz4/blob/master/doc/lz4_Frame_format.md)
- [lzip manual](https://lzip.nongnu.org/manual/lzip_manual.html)
- [7z format](https://github.com/ip7z/7zip/blob/main/DOC/7zFormat.txt)
- [PKWARE ZIP APPNOTE 6.3.9](https://pkwaredownloads.blob.core.windows.net/pkware-general/Documentation/APPNOTE-6.3.9.TXT)
- [ECMA-119](https://ecma-international.org/publications-and-standards/standards/ecma-119/)
- [tar format notes](https://man.archlinux.org/man/tar.5.en)

