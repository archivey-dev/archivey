# Work plan — turning the simplicity & consistency review into changes

> **Implemented.** W1–W9 landed in **#232** (2026-08-09). The six OpenSpec changes
> are under `openspec/changes/archive/2026-08-09-*`; ADRs 0015–0017 record the
> empty-TAR, RAR-fixture, and bidi-policy decisions. Q13 follow-ons continued as
> `#233`–`#236`. This file is kept as the historical worklist — do not re-open it
> as a TODO. The review directory was archived 2026-08-15.

**What this is.** [`QUESTIONS.md`](QUESTIONS.md) ranks the review's outcomes by *what
unblocks what*. This file is the other axis: **the concrete units of work**, each one a
single PR or a single `openspec` change, with the files it touches, the spec deltas it
needs, and the committed tests that prove it landed. *(Originally analysis-only; the
paragraph below described the pre-implementation state.)*

**How to use it.** Take a deliverable, do it end to end (code + spec + docs in one change,
per `CONTRIBUTING.md` §"Don't accumulate debt"), and tick it off. The deliverables are
ordered so that no item depends on one below it, except where stated.

**Everything except W3 is post-`0.2.0`-safe.** W3 adds a field to a public frozen
dataclass and is the only genuinely tag-gated item in the whole review.

---

## How work lands in this repo

Three vehicles, per `CONTRIBUTING.md` and `AGENTS.md`:

| Vehicle | When | Shape |
|---|---|---|
| **Bugfix PR** | Code disagrees with a spec that is already right | Just the fix + remove the `xfail` marker |
| **`openspec` change** | The *contract* moves — new behaviour, new field, new diagnostic code | `openspec/changes/<id>/` with `proposal.md`, `tasks.md`, `specs/<capability>/spec.md` deltas; implement; then `openspec archive <id> --yes` in a follow-up |
| **Docs-only PR** | Published prose is wrong or missing; no contract change | `docs/` edit; `mkdocs.yml` nav if a new page |

**The red–green signal.** 16 assertions in
[`tests/test_review_simplicity_consistency.py`](../../../tests/test_review_simplicity_consistency.py)
are `@pytest.mark.xfail(strict=True)` — they encode the behaviour the review argues for.
When a fix lands, its red half **XPASSes, which fails the suite**. That is the signal, and
the last step of each deliverable is to delete the marker. Do not delete a marker without
the fix.

**Gates for every deliverable** (`CONTRIBUTING.md` §"Before pushing…"):

```bash
uv run pytest                       # and the three-config rule below
uv run ruff check && uv run ruff format --check
uv run pyrefly check && uv run ty check
openspec validate --all
```

**Three-config runs (`[all]`, `[recommended]`, bare stdlib) are required before pushing,
and they are not a formality.** An earlier revision of this file said they were, on the
grounds that no *finding* depends on an optional library. That is true of the findings and
irrelevant to the tests: the review's own guardrails broke the `core-only` and
free-threaded legs, because **7z reads natively but the corpus writes it with `py7zr`** —
so a format-availability check passes and the builder then dies on `ModuleNotFoundError`.
`[all]` passed on every platform while three legs were red.

Reproduce the reduced legs exactly as CI does:

```bash
uv sync --no-dev
uv run --no-sync python tests/check_zero_dep_core.py
uv run --no-sync --with pytest --with pytest-cov --with pytest-timeout pytest tests/ -q
uv sync --group dev --extra all      # restore
```

**When a corpus-driven test needs an archive, call
`tests.sample_archives.skip_unless_runnable(entry, key)`** — it consults
`READER_PACKAGES`, `BUILDER_PACKAGES` and `BUILDER_BINARIES` together. Do not hand-roll a
gate from `format_availability` alone; that is the mistake above, and it is invisible in
the `[all]` leg.

---

## W1 — Five typed-error and metadata corrections *(bugfix PR, no spec change)*

**One PR.** These are unrelated one-liners that share a vehicle and a review; splitting
them into five PRs costs more review attention than it saves. All five are cases where the
code disagrees with a contract the specs already state.

| Finding | Change | Site |
|---|---|---|
| **F5 / Q5** | Fill `compressed_size` from `SEEK_END` on any **seekable** source, not only a `Path`. Today it is `int` for a path and `None` for an identical `BytesIO`, on all 9 single-file codecs. | `src/archivey/internal/backends/single_file_reader.py:173` |
| **F3 / Q3** | Type the volume-sequence refusals: `ArchiveyUsageError` for an empty sequence; `StreamNotSeekableError` for non-seekable volumes — matching the single-source spelling of the same refusal. | `src/archivey/internal/volumes.py:145`, `:167`, `:269`, `:314` |
| **F4 / Q4** | Carve `"already closed"` out of ZIP's blanket `ValueError → CorruptionError` arm and map it to `ArchiveyUsageError`. A closed handle is a lifecycle fault, not archive damage. | `src/archivey/internal/backends/zip_reader.py:511` (ahead of the blanket arm) |
| **F11 / Q12** | Split `open_stream`'s `is_file()` predicate: `FileNotFoundError` when the path is genuinely missing, `ArchiveyUsageError` naming `open_archive` when it is a directory. | `src/archivey/core.py:332` |
| **F15 / Q15** | Map the `unrar` stdout-pipe `RuntimeError` in the RAR translator or at the spawn site. Defensive — the second pass rated it PLAUSIBLE, not confirmed reachable. | `src/archivey/internal/backends/rar_unrar.py:157` |

**Red halves to delete when green** (6 markers):
`test_single_file_compressed_size_is_not_path_gated[gz]`, `[xz]` ·
`test_empty_source_sequence_is_a_usage_error` ·
`test_non_seekable_volume_sequence_is_a_stream_error` ·
`test_zip_underlying_close_is_a_usage_error` ·
`test_open_stream_directory_error_names_the_real_problem`

**Spec check before writing code, not after** (the `AGENTS.md` pause-and-ask rule):
`error-handling` §`ArchiveyUsageError` already enumerates caller-misuse cases and
`StreamNotSeekableError` is already the single-source spelling, so F3/F4/F11 should need
no delta. **F5 is the one to verify** — `format-single-file-compressors` uses the phrase
"seekable/path" for the sibling trailer/CRC probes, which reads as already permitting
this; if it turns out to say `Path` anywhere, F5 moves into W2 instead of shipping here.

**Not in this PR:** F5's *sibling* problem — `seekable_members` changing `size` and
`hashes` — is W2. They touch neighbouring lines; do W1 first and rebase.

---

## W2 — Decouple metadata harvest from `seekable_members` *(`openspec` change)*

**Change id:** `decouple-member-metadata-from-declared-seekability`

The review's headline finding (**F1 / Q1**): a *stream capability flag* changes
*metadata*. `open_archive(path, seekable_members=True)` on a `.lz` turns `size` from
`None` into `44` and `hashes` from `{}` into `{CRC32: …}`; on `.xz`, `size` `None` → `44`.
Same for `Path` and `BytesIO`. gzip already does the right thing, so this is also an
internal inconsistency.

**What changes:** harvest cheap trailer/index metadata at open **regardless** of the
declared capability, making xz and lzip behave like gzip.

**Spec deltas:** `format-single-file-compressors` — the XZ size row is currently
unconditioned and therefore already wrong in the other direction; fix it in the same
change (`CONTRIBUTING.md`: code and specs move together).

**Red halves:** `test_member_size_does_not_depend_on_declared_seekability[lz]`, `[xz]` ·
`test_lzip_surfaces_crc32_without_declaring_seekable_members`

**Also closes Q16/O3 as a side effect**, in the sense that mattered: the review's verdict
was that *the problem with `seekable_members` was never its name* — it was this. After W2
the flag means only what it says.

---

## W3 — `required_source` on `FormatAvailability` *(`openspec` change · **tag-gated**)*

**Change id:** `format-availability-required-source`

**Do this before `0.2.0`.** `FormatAvailability` is a public frozen dataclass; adding a
field after the tag is a breaking change, and this is the only item in the review with
that property.

Today a caller cannot ask "can this format be read from a pipe?" — the answer exists
(trailing-index formats refuse a non-seekable source; front-indexed ones accept it) but is
undiscoverable without trying. **O4** settled the shape:

```python
required_source: StreamCapability   # the weakest source shape this format can read from
```

`StreamCapability` is **ordered**, so the field is a *minimum requirement* and the caller's
test is a comparison against `reader.cost.stream_capability` — same type, no second
vocabulary:

| Format | `required_source` |
|---|---|
| TAR, single-file codecs | `FORWARD_ONLY` |
| ZIP, ISO, 7z, RAR | `SEEKABLE` |

**Why not the alternatives** (record this in the proposal so it isn't relitigated): a
`set` of shapes can express states no real format has (`{SEEKABLE}` without
`FORWARD_ONLY`); a `streams_from_pipe: bool` needs a second boolean the day a third source
shape appears.

**Spec deltas:** `backend-registry` and/or `packaging-and-extras` (wherever
`FormatAvailability` is specified).

**Pins already committed** (these pass today and must keep passing):
`test_trailing_index_formats_refuse_a_pipe_loudly[…]` ·
`test_front_indexed_formats_accept_a_pipe[…]`

---

## W4 — The diagnostics batch *(one `openspec` change, six codes)*

**Change id:** `review-diagnostics-batch`

**Land these together, not one at a time.** Six separate decisions each add a
`DiagnosticCode`; they share the taxonomy, the context dataclasses and the policy
plumbing, so six changes would mean five rebases over the same files.

| # | Code / behaviour | Decision | Notes |
|---|---|---|---|
| 4a | `encoding=` passed to a backend that ignores it (7z, RAR, ISO, directory, single-file) | **F2 / Q2** | The entry point stays permissive; the discard becomes queryable |
| 4b | `password=` passed to an archive that never needs it | **O5** | **Also make static `password=` and `password=[…]` stop raising.** Today a *provider callable* opens fine on an unencrypted archive while a plain string or list raises — an asymmetry with no defence |
| 4c | Explicit `format=` yields an empty listing where detection would disagree | **F7 / Q7** | `format=` stays an override |
| 4d | `MEMBER_NAME_BIDI_CONTROL` | **F10 / Q10** | The bidi warning is currently the library's **only** advisory with no code — the `VISION.md` warnings-as-data gap verbatim |
| 4e | `EMPTY_ARCHIVE` — a listing completed with zero members | **O8a** | Format-independent. Says the true thing ("empty") rather than guessing ("probably garbage") |
| 4f | Format chosen by **extension**, listing empty, and content detection would have refused the bytes | **O8a** | The layer 4c does not reach. Only runs on an empty result, so it costs nothing normally |

**The rule that governs 4a/4b/4c** — write it into `archive-reading` so the next argument
has an answer instead of a debate:

> Refuse when an argument is an **assertion about this archive** (`format=` — "I claim
> this is a ZIP"). Permit, and record a diagnostic, when it is a **resource offered for
> use if needed** (`password=`, `encoding=`).

**Spec deltas:** `diagnostics` (the six codes + contexts), `archive-reading` (the rule
above), `format-detection` (4c/4f), `testing-contract` (4d — tighten the "warns **or**
rejects" disjunction; see W5, which owns the reject half).

**Red halves:** `test_unusable_encoding_argument_is_refused[iso]`, `[7z]`, `[dir]` ·
`test_wrong_explicit_format_does_not_silently_succeed`
**Pin:** `test_bidi_name_warning_has_no_diagnostic_code` (passes today; it must **fail**
after 4d — it asserts the absence this change removes, so delete it in the same commit).

**4b has documentation consequences — find them before you ship, not after.** The
current "static password on a format without encryption raises" rule is written down in at
least three places, and all of them become false:

| Where | What it says today |
|---|---|
| `review/docs/independent/must-explain.md:169` (#13) | *"Static passwords on formats without encryption → `UnsupportedOperationError`"* |
| `review/docs/outline.md:167` | mirrors the same claim in the docs plan |
| the gate itself | `src/archivey/core.py:221–229` |

Grep for `UnsupportedOperationError` alongside "password" before finalising; the published
`docs/` pages may carry it too. **Say so in the changelog under a behaviour heading** —
churn is free before `0.2.0`, but this one is caller-visible.

---

## W5 — Reject bidi overrides during safe extraction *(`openspec` change)*

**Change id:** `reject-bidi-overrides-in-safe-extraction`

**O7**, and the distinction that makes it answerable: **bidi controls are not one
category.**

- **Reject** — overrides and isolates U+202A–202E, U+2066–2069. They reorder surrounding
  text; the `…gnp.exe` disguise needs one. No legitimate filename does.
- **Keep warn-only** — directional marks U+061C, U+200E, U+200F. Invisible hints that do
  *not* reorder; they appear in legitimate Arabic and Hebrew filenames.

> ⚠️ **Do not reuse `_BIDI_CONTROLS` as the reject set.** The existing frozenset at
> `src/archivey/internal/naming.py:32` contains **all twelve** codepoints, marks included.
> Rejecting that set would break legitimate RTL filenames. Write the reject set out
> explicitly as the two override/isolate ranges.

RTL *script* is not affected at all: an Arabic or Hebrew filename gets its direction from
its letters' own properties. Nothing in `فهرس.txt` is in either list.

**Scope:** rejection belongs to the **safe-extraction** path, where a name becomes a
filesystem path. Listing and reading still present the name as stored, with 4d's
diagnostic — the library does not get to decide a name is unreadable.

**Spec deltas:** `safe-extraction` (the reject rule), `testing-contract` (the disjunction
W4 tightened now has both branches implemented).

**Depends on W4** for the diagnostic code that covers the warn-only half.

---

## W6 — `strict_archive_eof` asserts what it promises *(`openspec` change)*

**Change id:** `strict-archive-eof-trailing-bytes`

**O8b.** The flag documents "a provably complete listing" but today ignores everything
after the TAR trailer — 4 KiB of arbitrary appended junk passes silently (**F20**).

> With `strict_archive_eof=True`, after the two-block null trailer every remaining byte to
> EOF MUST be zero; any non-zero byte raises. With `strict_archive_eof=False`, unchanged.

Consequences, all deliberate:

- **Zero padding still passes.** Writers pad to 10 KiB routinely. This is why the rule is
  "nothing but zeros", not "EOF immediately".
- **An ISO still passes** — its 32 KiB system area is zeros, so it is a valid empty TAR
  with padding. `EMPTY_ARCHIVE` (4e) is what covers that case, not this flag.
- **Trailing junk now fails** — the point of the change.
- **Concatenated archives now fail under `strict`.** Accepted: they *are* multiple
  archives and the reader listed only the first. The flag is opt-in and off by default,
  which is the argument for letting it mean the strong thing.

**Cost, document it on the flag:** the check must read to EOF, so `strict_archive_eof`
goes from O(512 bytes) to O(tail length). On a non-seekable source that is a real scan.

**Spec deltas:** `format-tar`.

**Pins already committed:** `test_strict_archive_eof_ignores_trailing_junk[False]`,
`[True]` — the `[True]` case must **flip to failing** and be rewritten to assert the raise.
`test_legitimately_empty_tar_stays_valid` and
`test_zero_filled_dot_tar_opens_empty_via_extension[…]` must keep passing: **a zero-member
TAR must not raise** (O8a — an empty tar is 10240 zero bytes, byte-identical to garbage,
so no predicate over the bytes can separate them).

---

## W7 — The rewind diagnostic becomes cost-based *(`openspec` change)*

**Change id:** `rewind-diagnostic-redecode-cost`

**F19 / O1** — the review's one behaviour change that needed design, now fully specified.

**The bug:** `STREAM_REWIND_REDECOMPRESSES` fires on *codec identity*, not on cost. A
single-block `.xz` has exactly one seek point `(0, 0)`, so a full rewind re-decodes
everything and emits **nothing** — which means a `RAISE` policy, the diagnostic's one real
job, cannot fire on the case it exists for.

**The predicate:** the seek's actual re-decode distance —
`target − nearest preceding seek point` — computed at seek time, against an **absolute**
byte threshold.

> **Why absolute and not relative** (record this; the review initially argued the other
> way): on a 1 GB single-block `.xz`, seeking from the end back to 900 MB re-decodes
> 900 MB but only jumps ~100 MB — ratio 0.11×, under any sane relative threshold. Relative
> goes quietest exactly where absolute cost is highest. Absolute also matches the existing
> `RAPIDGZIP_AUTO_MIN_COMPRESSED_SIZE` precedent, so there is one threshold vocabulary.

**Record once, escalate always:** keep recording the diagnostic at most once per stream
(bounded output), but **evaluate the policy on every qualifying seek**, so a `RAISE` policy
stops the second expensive seek too. Deduplication is a presentation concern; escalation is
control flow for a caller who asked to be stopped.

> This changes how a deduplicated diagnostic relates to its policy **in general**. Decide
> in this change whether it is the rule for all once-per-stream codes or a local exception,
> and write it down either way — otherwise the next deduplicated code inherits the
> question.

**One unknown, and it is a measurement not a decision:** does `rapidgzip` expose its index
spacing? If not, that arm keeps the accelerator-presence rule and the spec must say the
predicate is not uniform across codecs. **Check the API first** — it changes what the spec
delta says.

**Spec deltas:** `seekable-decompressor-streams` — the line *"XZ, lzip, and
unix-compress … SHALL NOT emit this event"* is what has to move.

**Red half:** `test_full_rewind_emits_regardless_of_codec`
**Pin:** `test_single_block_xz_rewind_is_silent` (pins today's blind spot; must flip)

---

## W8 — Spec and docs corrections *(one docs/spec PR)*

Cheap, unrelated, and they share a reviewer's attention better batched.

| Finding | Change |
|---|---|
| **F6 / Q6** | Drop `directory` from the leading-index row of `access-mode-and-cost`'s topology table. The code returns no report peek, consistent with its own `listing_cost=REQUIRES_SCANNING` — **the spec is the thing that is wrong.** |
| **F9 / Q9** | `docs/reading-members.md` — bound the "passwords are lazy" bullet to *data* encryption, pointing at `formats.md` for header-encryption cases. The published claim is currently false. |
| **F13 / Q14** | `review/docs/independent/must-explain.md:333` (#25) still says *"Directory path forces DIRECTORY even if `format=` says otherwise"* — `#225` made that an `ArchiveyUsageError`. Reword to "**rejected for a directory path**", not "always rejected": F7 is the case where a wrong `format=` still wins. `review/docs/outline.md:161` mirrors the same stale claim — fix both. |
| **F14 / Q14** | Switch the two CLI imports to the public path. |
| **O2a** | Record in `access-mode-and-cost` that a solid out-of-order `open()` **deliberately** emits no warning, and why (`cost.access_cost == SOLID` already says it at open, before the caller does anything). **This is the deliverable — the behaviour is already correct.** Three separate reviews have now rediscovered this; it will happen again until the spec says so. |

> ⚠️ **F6 carries a tripwire.** `test_directory_report_peek_matches_index_topology_spec[…]`
> is `xfail(strict=True)` against the *spec's* claim. If it starts XPASSing **before** this
> PR lands, someone changed the **code** to match the spec instead — which is the wrong
> half. Check which happened before deleting the marker.

---

## W9 — Make the RAR conformance sweep runnable *(CI/testing change)* — *diagnosis needed first*

**F16 / Q11 / O6.** The 41 declarative RAR corpus cases run **nowhere**: they need a RAR
*writer*, and the fixtures are platform-dependent. `0.2.0` headlines a native RAR reader,
which is what makes this worth closing now rather than after.

**This is the one item still open on *how*.** Two candidate shapes: make the digest
expectations platform-independent (keeps the corpus's "no committed binaries" property,
more work), or commit a small pre-built fixture set (straightforward, against the design).

**Diagnose before choosing.** One hypothesis is already ruled out: the corpus asserts
`act.size == len(exp.contents)` and digest **key presence**, not digest *values*, so the
platform-dependence is **not in the payload**. Start instead by diffing the recorded member
**metadata** for the same corpus entry built on Linux and macOS — in order of likelihood:
**mode bits** (umask; the executable bit differs across platforms), **uid/gid**, **mtime**
granularity.

**Pin already committed:** `test_rar_column_is_unmeasured_without_the_rar_writer` — it
documents the gap and will need deleting when the sweep runs.

---

## Deliberately not scheduled

**Holding the solid-block decoder open across `open()` calls (O2b), and what that means
under `concurrent_members` (O2c).** Registered as backlog in
[`dev-docs/IDEAS.md`](../../../dev-docs/IDEAS.md) §Performance & robustness with the full
argument and the measurements.

The direction is agreed and the payoff is real — a single-folder solid 7z costs **4.5× one
pass** to walk via `open()` where `.tar.gz` costs **1.0×**, and because the stream is not
held, in-order and reverse order cost the same. It is a no-reuse problem, not a
backward-seek problem, and therefore a cross-backend inconsistency rather than a property
of solid formats.

It is parked because the concurrency half is unbrainstormed, and the cheap hope that the
two mechanisms might not interact is **disproved by measurement**: under
`concurrent_members=True`, two members of the *same* solid folder open simultaneously hold
**two independent live decodes** (`bytes_decompressed = 1 400 000` for two 200 KB members
of a 1.2 MB payload). Member data is not materialized; the CONCURRENT fan-out is over the
*listing* snapshot. So N concurrent opens means N live LZMA states, and "hold the decoder
open" has to answer what happens to all of them on close. That needs a design session and
its own `openspec` change, not a patch.

---

## Dependency order

```
W1 ──► W2                     (neighbouring lines in single_file_reader.py)
W3                            independent — do first, it is the only tag-gated item
W4 ──► W5                     (W5 needs W4's diagnostic code for the warn-only half)
W4 ──► W6                     (W6 defers the empty-ISO case to W4's EMPTY_ARCHIVE)
W7                            independent
W8                            independent — but check F6's tripwire before deleting markers
W9                            independent — blocked on its own diagnosis, not on other work
```

Suggested sequence: **W3** (deadline) → **W1** → **W2** → **W4** → **W5** + **W6** →
**W7** → **W8** → **W9**.

**When each `openspec` change is implemented**, archive it in a small follow-up PR
(`openspec archive <id> --yes`, commit the resulting `openspec/specs/` updates) —
`scripts/checks/check_openspec_archived.py` enforces this.
