> **Scope cut on 2026-09-25.** `detection-evidence-ledger` was decided against and archived,
> so everything here that exposes or renders a ledger is withdrawn: the always-present
> ledger field, `DECLARED_BY_CALLER` / `DECLARED_BY_CONTAINER`, `confidence` and
> `detected_by` as derived properties, the `sfx_scan` rename (kept, and documented as an open
> set instead), ledger rendering in `__str__` and `archivey info -v`, and the golden `info`
> pins. The small half shipped separately: the reader keeps the `FormatInfo` it opened by
> (`ArchiveReader.format_info`) and `archivey info` reads it instead of detecting twice.
> **What remains is the `detection=` handoff** (below, and `tasks.md` §2), which can follow
> 0.2.0. Read "the ledger" in the text below as "the `FormatInfo`".

## Context

`core.py:386` is where the detection result dies. `open_archive` reads three things off the
`FormatInfo` — `format`, `payload_offset`, and `chosen_by`/`probe_only` via the private
`_format_provenance` — and drops the object. Nothing downstream can recover
confidence, provenance or corroboration.

`detection-evidence-ledger` makes the result worth keeping: a ranked ledger with a defensible
account of why a format was chosen. This change exposes it, and closes the one gap the ledger
cannot close from inside — a caller who must decide *before* opening.

## Goals / Non-Goals

**Goals:**

- The winner's evidence is publicly reachable from a reader, a stream and standalone
  detection, and from the error that says a format was unconfirmed.
- Detection runs once for a caller who wants to inspect the result and then open.
- Fix the two `detected_by` values that are wrong or absent while they are still changeable.

**Non-Goals:**

- An all-candidates inspection API. Its name and shape stay deliberately open; only the
  winner's evidence is required, because error provenance depends on it.
- Widening public `payload_offset` to `int | None`. That is its own API change with its own
  migration.
- Classifying a prefix beyond the small enumerated kinds. Archivey is not a general file-type
  detector, and no rule branches on the value.
- Deciding whether a caller should care what is *inside* a given archive — the archive-*role*
  idea in `dev-docs/IDEAS.md`, post-1.0.

## Investigations

**What a caller can see today**, measured on `main` at `e54eff7`:

| surface | detection information |
| --- | --- |
| `reader.format` | the answer, ungraded |
| `reader.info` (`ArchiveInfo`) | none — format, version, solidity, member count, comment, encryption, multivolume, cost, extra |
| the reader | none public; `_format_provenance` is private |
| the raised error | `format_unconfirmed: bool`, `source_format` — no *why* |
| `reader.diagnostics` | partial: detection emits into the reader's collector |
| `open_stream()` | returns `detected.format.stream`; the container does not survive |

**The channel is asymmetric.** `FORMAT_EXTENSION_CONFLICT` and the unconfirmed-format code
reach the caller because they are emitted into the collector. So the **negative** signals are
public and the **positive** ones are not: a caller can learn that the name contradicted the
bytes, never that it agreed, nor how strong the evidence was.

**The CLI already pays for it.** `cli/info_cmd.py:52` calls `detect_format(archive)` and then
`open_archive(archive)`. `VISION.md` names the CLI "a wedge and second consumer … useful
evidence of API gaps"; this is that evidence. On a non-seekable source the workaround does not
even exist, because the path cannot be reopened.

**Why `sfx_scan` is the wrong name.** `detection.py:115` defines self-extraction as an offset —
`# nonzero only for SFX archives (is-SFX == payload_offset > 0)`. The same tier finds four
different things, and the label is wrong for three:

| what the tier finds | is it self-extracting? |
| --- | --- |
| a 7z installer behind a PE stub | yes |
| a `zipapp` (`#!` + ZIP) | no — the archive *is* the program, meant to be run |
| a JPEG with an appended ZIP | no |
| junk prepended to a tar | no |

**`corroborated: bool` cannot become public, for a reason already recorded.**
It is already recorded that `False` means both "a probe with nothing corroborating it" and
"not a probe at all", so a ZIP named `a.zip` and one named `b.tar` produce identical output —
`magic` / `certain` / `False` — as do an extensionless Brotli probe hit and one whose `.zip`
name contradicts it. The replacement is the ledger, not a wider bool.

## Decisions

### 1. The field is always present, and absence of detection is recorded as evidence

Never `None`, on the same reasoning that makes a prefix kind always present: a caller should
read it without first testing whether detection happened to run. Where detection did not run,
the ledger says *why nothing was measured*, which is truthful provenance rather than a gap.

`DECLARED_BY_CALLER` projects to `GUESS`, and under the ledger's reframing that is right
rather than insulting: `GUESS` means "the bytes did not confirm this identity", and when the
caller supplied the format the bytes were never consulted. `EXPLICIT_FORMAT_LISTED_EMPTY`
already encodes the same judgement — `format=` is an override that gets reported, not trusted.

### 2. `DECLARED_BY_CONTAINER` inherits the container's class, and is not a class of its own

A member stream inside a checksum-validated 7z is not a guess: the container structurally
declares its codec and the container itself was validated. A single `DECLARED` value would
rank that with a caller's assertion, understating it as badly as ranking it with a bounded
probe would overstate a probe.

### 3. `confidence` and `detected_by` become properties

Making them derived rather than stored is the point, not an implementation detail. Most
callers who care at all want one honest number and not the mechanism, so translating evidence
into trust is the **library's** judgement to make and publish. A stored scalar can be
constructed inconsistent with the ledger it summarizes; a derived one cannot. It also stops
equality and golden-value tests pinning a redundant field.

That a record carries both kind and class is what lets the two coexist without being a second
ranking — they summarize different columns of the same record.

**Rejected: one richer public scalar.** Any single value has to choose between "which detector
answered" and "how strong the answer is", and the composition — bounded probe *and* a matching
name — is exactly what a caller inspecting a marginal result needs. That composition belongs in
`__str__` / `__repr__`, where a human, a log line or `archivey info` can read it.

### 4. Rename `sfx_scan` now, while these values are still changeable

`prefixed_scan` costs nothing today and is a public-value migration once the redesign ships.
Nothing needs to classify the stub — the prefix kind already reports what it *is* — but the
name should stop asserting *why* it is there.

Two measurements bear on the tier itself, from 3 320 ELF/PE files under `/usr/bin`,
`/usr/lib`, `/usr/local` and `/opt`: **zero** carry a real appended ZIP, and all **six**
`PK\x05\x06` tail matches are false positives — `zip`, `zipnote`, `zipsplit`, `zipcloak`,
`libzip.so`, `librevenge-stream.so` — carrying the signature as a string constant and parsing
to nonsense. A concrete instance of the requirement that the tail tier *validate* rather than
locate.

### 5. `detection=` is a separate parameter from `format=`, and that is the whole point

Routing a detection result through `format=` — the only option today — silently launders a
`GUESS` into a trusted assertion, which is the opposite of what a caller who inspected the
result wanted. `detection=` replays evidence archivey itself produced, so the reader's ledger,
confidence and `format_unconfirmed` behaviour are exactly what a self-detecting open would
have produced.

This is also where the rejected `format=` contradiction check's value survives. The ledger
change rejects that check because it needs source-head I/O on a call whose contract is *do
exactly what I said*; here the caller gets both halves explicitly, with no implicit I/O, and a
contradiction is visible **before** the open rather than after it.

### 6. The source token is a typo-catcher, not an integrity check

A result handed to a different source is a caller bug the library should catch rather than
honour. But a path can change on disk between the two calls, so `detection=` inherits exactly
the time-of-check-to-time-of-use window today's detect-then-open pattern already has. Stated
explicitly so nobody later reads the token as a security boundary.

### 7. On a non-seekable source the result is not a pure value object

Detect-then-open works today only because a *path* can be reopened. On a caller-supplied pipe,
detection has already consumed the prefix, so "look before you open" is currently
inexpressible there. The handoff makes it expressible — provided the replay buffer travels
with the result, which ties the result's lifetime to the source's. That is a real constraint
on the type, not a footnote, and it is why this half depends on the prefix workspace.

## Risks / Trade-offs

- [Two public-value migrations at once: `sfx_scan` → `prefixed_scan`, plus four new values] →
  Both land while the redesign is already changing what callers observe, which is the cheapest
  moment. A caller matching `detected_by` exhaustively breaks; the migration note has to say
  so rather than leaving it to a bug report.
- [`confidence` and `detected_by` becoming properties changes dataclass semantics] →
  `FormatInfo` is frozen and the values are derived from a field that is part of `__eq__`, so
  equality is preserved in substance. Tests that constructed a `FormatInfo` with an explicit
  confidence will not compile, which is the intended forcing function.
- [The result must stay constructible and inspectable without a reader] → It already is, and
  nothing here may foreclose it: the `detection=` handoff depends on exactly that property.
- [The ledger could be computed correctly and then thrown away again] → One end-to-end pin:
  `archivey info` over each golden fixture, output compared against a committed expectation.
  It costs one file and catches the exact class of regression this change exists to fix.
- [`detection=` can ship after the field] → It is a new keyword argument with no change to
  existing behaviour, so it needs no migration row and can be split out if the non-seekable
  half is not ready.

## Open Questions

- **The exact public field and type names** for the result on readers, streams and errors. The
  exposure is required; the spelling is not settled here.
- **Whether the detection cost receipt should be public**, carried from
  `detection-prefix-workspace`. Included in the field's shape above as a placeholder; if it
  stays internal the field loses one attribute and nothing else changes.
- **How a caller reaches the evidence from an exception** — the record itself, or a stable
  reference to the retained result. The requirement is that the flag explains itself without a
  second detection; either shape satisfies it.

## Sequencing

Depends on `detection-evidence-ledger` for the evidence types and the derivation. The
`detection=` half additionally depends on `detection-prefix-workspace` for the replay buffer
and spool policy that make it work on a pipe, and may ship after the field if that is not yet
in place.

Last of the five detection changes. `prefixed-archive-detection`, revised, contributes the
`zip_tail_probe` and `exhaustive_scan` values this change reserves.
