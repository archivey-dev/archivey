> **Archive note:** Archived unimplemented on 2026-11-05 (maintainer decision); the `detection=` handoff is dropped.

> **Parked, not part of 0.2.0** (maintainer decision, 2026-10-07). No further work is
> scheduled. The release does not need this change, and the drafted design stays here so a
> later change can pick it up. It is tracked internally. What already shipped is recorded below.

> **Scope cut on 2026-09-25.** `detection-evidence-ledger` was decided against and archived,
> so everything here that exposes or renders a ledger is withdrawn: the always-present
> ledger field, `DECLARED_BY_CALLER` / `DECLARED_BY_CONTAINER`, `confidence` and
> `detected_by` as derived properties, the `sfx_scan` rename (kept, and documented as an open
> set instead), ledger rendering in `__str__` and `archivey info -v`, and the golden `info`
> pins. The small half shipped separately: the reader keeps the `FormatInfo` it opened by
> (`ArchiveReader.format_info`) and `archivey info` reads it instead of detecting twice.
> **What remains is the `detection=` handoff** (below, and `tasks.md` §2), which can follow
> 0.2.0. Read "the ledger" in the text below as "the `FormatInfo`".

## Why

`detection-evidence-ledger` makes detection produce a defensible account of *why* it chose a
format. A caller who opens an archive sees none of it — and the result object is not merely
unexposed, it is **discarded**. Measured on `main` (`e54eff7`):

| surface | what the caller gets |
| --- | --- |
| `reader.format` | the answer, ungraded |
| `reader.info` (`ArchiveInfo`) | format, version, solidity, member count, comment, encryption, multivolume, cost, extra — nothing about detection |
| the reader itself | no public detection attribute; `_format_provenance` is private |
| the raised error | `format_unconfirmed: bool` and `source_format` — no *why* |
| `reader.diagnostics` | the one partial channel |
| `open_stream()` | worst case — the helper returns `detected.format.stream`; not even the container survives |

`open_archive` reads four things off the `FormatInfo` and drops the object at
`core.py:386`. Confidence, `detected_by` and corroboration are lost at open time.

Two consequences are evidence rather than opinion:

- **The diagnostics channel is asymmetric.** A caller can observe
  `FORMAT_EXTENSION_CONFLICT` and the unconfirmed-format code, because those are emitted
  into the reader's collector. So the **negative** signals are public and the **positive**
  ones are not: you can learn that the name contradicted the bytes, never that it agreed,
  nor how strong the evidence was.
- **Archivey's own CLI already pays for the gap.** `cli/info_cmd.py:52` calls
  `detect_format(archive)` and then `open_archive(archive)` — detecting twice, because the
  reader will not tell it. `VISION.md` calls the CLI "a wedge and second consumer … useful
  evidence of API gaps"; this is that evidence, and on a non-seekable source the workaround
  is not even available.

There is a second, larger shape the CLI stands in for: **a caller who must decide on the
detection result before deciding whether, or how, to open.** That caller cannot use a field
on the reader, because the field only exists after the open it was meant to inform. Today
the only way to have both is to detect twice — and the redesign makes the second detection
*more* expensive, not less.

## What Changes

- **The detection result becomes an always-present field** on `ArchiveReader` and
  `ArchiveStream` — never `None`, on the same reasoning that makes `prefix_kind` always
  present: a caller should read it without first testing whether detection happened to run.
- **Where detection did not run, the ledger says so as declared evidence**, which is
  truthful provenance rather than absent provenance:

  | kind | source | class |
  | --- | --- | --- |
  | `DECLARED_BY_CALLER` | the `format=` argument, which skipped detection | `ASSERTED` — nothing verified it |
  | `DECLARED_BY_CONTAINER` | a member stream's codec read from the archive's own metadata (ZIP's compression method, 7z's coder chain) | **inherits the container's class** |

  A member of a checksum-validated 7z is not a guess: the container structurally declares
  its codec and the container itself was validated. Ranking that with a caller's assertion
  would understate it as badly as ranking it with a bounded probe would overstate a probe.
- **`confidence` and `detected_by` become derived properties, not stored fields.** A stored
  scalar can be constructed inconsistent with the ledger it claims to summarize; a derived
  one cannot. It also stops equality and golden-value tests pinning a redundant field.
- **`detected_by` gains values.** `"magic"`, `"extension"`, `"content_probe"` and
  `"sfx_scan"` keep their spelling; `zip_tail_probe`, `exhaustive_scan`,
  `declared_by_caller` and `declared_by_container` are new. **BREAKING** for an exhaustive
  match over the value set.
- **`sfx_scan` is renamed** to a neutral `prefixed_scan`, while these values are still
  changeable. The same tier that finds a real 7z installer also finds a JPEG with an
  appended ZIP, a `zipapp` (where the archive *is* the program and is meant to be run, not
  extracted), and junk prepended to a tar. `detected_by="sfx_scan"` is simply wrong for
  three of those four. **BREAKING** for anyone matching the string.
- **`open_archive()` and `open_stream()` accept `detection=`**, a previously produced
  detection result, and skip detection when given one. This is **not** `format=`: `format=`
  is an override that records `ASSERTED` and suppresses `format_unconfirmed` because the
  caller took responsibility, whereas `detection=` replays evidence archivey itself produced,
  so the reader's ledger and its flag are exactly what a self-detecting open would have
  produced. Routing a detection result through `format=` — the only option today — silently
  launders a `GUESS` into a trusted assertion.
- **The full ledger renders in `__str__` / `__repr__`**, where "bounded probe **and** a
  matching name" can be shown to a human, a log line, or `archivey info` — the composition a
  single scalar deliberately does not carry.
- **The CLI stops detecting twice.** `run_info` reads the field off the reader.

## Capabilities

### New Capabilities

### Modified Capabilities

- `format-detection` — the result's public shape, the derived properties, the widened and
  renamed `detected_by` values, and the `detection=` handoff.
- `archive-reading` — `open_archive` / `open_stream` gain `detection=`, retain the result
  instead of discarding it, and carry it on the reader and the stream.
- `cli` — `archivey info` reads it from the reader instead of re-running detection.

## Decisions

- **The winner's evidence is required; an all-candidates API is not.** Error-provenance
  semantics depend on the winner's ledger — an error marked unconfirmed must explain *why*
  without the caller repeating detection and correlating two operations. Enumerating every
  non-winning candidate is a separate, later API whose name stays open.
- **Public `payload_offset` stays an `int`.** Zero means "confirmed at the detection origin";
  a positive value marks a payload that starts later. `None` exists only on the internal
  candidate and means "not computed within the index budget". The compatibility view must
  either pay to compute the offset or raise; it must never turn unknown into zero. Widening
  the public type would be its own API change, not an incidental consequence.
- **The `detection=` result must name the source it came from.** A result handed to a
  *different* source is a caller bug the library should catch rather than honour: the result
  records an opaque source token and a mismatch raises. This is a typo-catcher, **not** a
  security boundary — a path can change on disk between the two calls, and `detection=`
  inherits exactly the time-of-check-to-time-of-use window that today's detect-then-open
  pattern already has. Worth stating so nobody later reads the token as an integrity check.
- **On non-seekable sources the handoff is not an optimisation but the only way.** Detect-
  then-open works today only because a *path* can be reopened; on a caller-supplied pipe
  detection has already consumed the prefix. The consequence: on such a source the detection
  result **cannot be a pure value object** — it must carry or reference the buffered bytes,
  so its lifetime is tied to the source's.
- **Per-record detail is advisory and unstable.** `bytes_examined`, `estimated_random_bits`
  and anchors may change; the stable commitments are the kinds, the classes, and their
  ordering — the same conservatism that keeps `payload_offset` an `int`.

## Impact

- Modules: `src/archivey/core.py` (stops dropping the result at line 386; the two new
  parameters), `src/archivey/reader.py`, `src/archivey/internal/streams/archive_stream.py`,
  `src/archivey/internal/detection.py`, `src/archivey/cli/info_cmd.py`,
  `src/archivey/internal/format_provenance.py` (subsumed by the ledger).
- Public API: a new always-present field on `ArchiveReader` / `ArchiveStream`; `confidence`
  and `detected_by` become properties; two `detected_by` values change meaning or spelling;
  `detection=` on `open_archive` / `open_stream`. Migration prose is needed for the renames.
- Tests: an end-to-end pin — `archivey info` over each golden fixture, compared against a
  committed expectation — asserts the ledger survives the whole path from detection to public
  rendering, which is exactly where `main` currently drops it. Plus: the field is present for
  `format=` opens and for member streams; a `detection=` result from a different source
  raises; a `detection=` result over a pipe replays without a second read.
- Docs: `docs/opening.md` and `docs/errors-and-diagnostics.md` gain the result and
  the handoff; `docs/cli.md` if `info` output changes shape.
- Depends on `detection-evidence-ledger`. The `detection=` half additionally depends on
  `detection-prefix-workspace`'s workspace and spool policy for the non-seekable case, and may
  ship after the field if that is not yet in place.
