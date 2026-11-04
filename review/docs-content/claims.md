# Claims — steps 2 and 3 of Topic 8

> **`dev-docs/open-issues.md` left the repo on 2026-10-09**; its open items are tracked
> internally. Citations of it here, line numbers included, refer to its last committed
> state: `git show bd135512:dev-docs/open-issues.md`.

The baseline this pass ran on, and every checkable claim the published guide makes,
grouped by **capability** and deduplicated across pages.

Written against `main` @ `adb2e3f` (`d4668c3` + `#240`/`#242`/`#245`, none of which
touched a file under `docs/`). Guide today: **15 pages, 2 108 lines**; the sixteenth,
`how-it-works.md`, still does not exist.

Inputs: [`brief.md`](brief.md) (the specification) and [`scope.md`](scope.md) (pass 0,
merged in `#242`). `scope.md` is a **settled input** — its routing rulings and its six
decided questions are carried in here, not re-derived.

**Merged from two independent passes.** Two agents ran steps 2–3 without contact — PR
#246 (this file's base, 400 rows) and PR #247 (`cursor/docs-content-claims-fbb3`, 190
rows). Line-coverage was measured on both and came out close (**73% vs 67%** of the
guide's 2 108 lines), so the row-count gap is granularity, not coverage. §Provenance
records what converged, the two claims #247 caught that #246 missed, and the one place
the two passes disagreed about the baseline — which turned out to be the most useful
thing either of them produced.

**Pass 1 verification complete (2026-08-18).** Capability workers filled every
`Verdict` cell as `verified` / `wrong` / `unverifiable (reason)` / `out of scope ([TM])`.
What was settled in steps 2–3 remains: *what the guide asserts*, *where each assertion
appears*, and *which line of `src/` or `openspec/specs/` would decide it*. Worker
evidence lives under `worker-inputs/verdicts-*.md`; harvest under
`../problem-catalogue/harvest/`.

---

# Part 1 — Baseline (step 2)

## Environment

`scripts/setup-dev-env.sh` run 2026-08-17; its closing verification block read:

```
=== verification
ok   unrar: /usr/bin/unrar
ok   7z: /usr/bin/7z
ok   benchmark toolchain complete
```

Both named tools are present, so the ~109 quiet skips `CLAUDE.md` warns about did **not**
happen in this session (23 skips total, itemised below). The apt step emitted two
`403 Forbidden` proxy warnings for the `deadsnakes` and `ondrej/php` PPAs; neither
supplies a package this repo uses, and every package the script asks for resolved.

| | |
|---|---|
| Python | 3.11.15 (CPython, GIL-ed) |
| Platform | `Linux-6.18.5-fc-v20-x86_64-with-glibc2.39` |
| Dependency config | **`[all]`** (`uv sync --group dev --extra all`) — the everyday leg |
| `archivey.__version__` | `0.2.0.dev0` |

Optional packages present: `rarfile 4.3`, `py7zr 1.1.3`, `pycdlib 1.16.0`, `lz4 4.4.5`,
`brotli 1.2.0`, `rapidgzip 0.16.0`, `cryptography 49.0.0`, `pyppmd 1.3.1`, `pybcj 1.0.7`,
`inflate64 1.0.4`, `multivolumefile 0.2.3`, `tqdm 4.68.4`.
Binaries: `unrar`, `7z`, `rar` (no `bsdtar`).
Absent by design on this leg: `indexed_bzip2`, `zstandard`, `python-xz`, `isal`,
`zlib-ng` — none is a declared runtime dependency (`acknowledgements.md:59-68`).

> **Dependency-config note (brief §Hard constraints).** Everything below was measured on
> **`[all]`**. Any claim whose truth depends on an optional library — the `[recommended]`
> codecs, the `[seekable]` accelerator, `[core-only]` fallbacks — is true *on this leg*
> and must be re-checked on `[all-lowest]` and `[core-only]` before it is called verified.
> Rows where that matters carry **`cfg`** in the Verdict column's note space.

## `./scripts/check.sh` — **PASS**

All seven gates green, including the two the brief names as the docs baseline:

```
=== openspec validate      Totals: 25 passed, 0 failed (25 items)
=== docs nav               docs/: 15 pages, all in nav; repo, site and anchor links all resolve.
=== docs build             (mkdocs build; only the upstream Material "MkDocs 2.0" advisory)
all checks passed
```

That reproduces the brief's commission-time baseline (§The surface being reviewed) at
`adb2e3f`: 15 pages, all in nav, every repo/site/anchor link resolving.

> Worth stating because it is the pass's most easily-misread green: `check_docs_nav.py`
> proves links **resolve**. It does not read a sentence. The whole of Part 2 exists in the
> gap between those two things.

## `./scripts/test.sh` — **PASS**

```
2453 passed, 23 skipped, 3 deselected, 6 warnings in 98.83s
TOTAL coverage 88%
```

The 23 skips, itemised so "green" is not taken on trust. **None** is a missing format
backend:

| Skips | Reason | Bears on a claim? |
|---:|---|---|
| 7 | External corpora not configured (`ARCHIVEY_{RARFILE,PY7ZR,LIBARCHIVE}_TEST_FILES`) | No — dev oracles (`acknowledgements.md:29-39`) |
| 4 | Optional package **is installed**, so the missing-backend path cannot be exercised (`rapidgzip` ×2, `pyppmd`, `brotli`) | Indirectly — the `[core-only]` leg is where those paths run |
| 4 | Fixture builder declined (`rar` did not split a volume set; `7z` CLI cannot build an anti-item update archive; two RAR multi-volume/BytesIO shapes) | Only for the multi-volume rows (A-18…A-21) |
| 2 | RAR wrong-password fixtures do not open standalone from a `BytesIO` | No |
| 2 | Platform-gated (`Windows`-only pipe-seek characterisation; `os.DirEntry.is_junction()` needs 3.12+) | **Yes** — `extracting.md:47-48` NTFS junctions is unverifiable on this session (see C-19) |
| 1 | `rar` writer present, so the RAR corpus column is measurable | No |
| 3 | deselected (not skipped) | No |

## `format_availability()` — re-measured 2026-08-18 (this verification session)

`scripts/setup-dev-env.sh` closing block: `ok unrar`, `ok 7z`. Config **`[all]`**.

**Corrected sweep (F4):** driven by `list_known_formats()` — **26 formats, all FULL**.
Named `ArchiveFormat` attributes alone under-count by five composed TAR variants
(`TAR`+`LZIP` / `LZMA_ALONE` / `ZLIB` / `BROTLI` / `UNIX_COMPRESS`); those five are
also FULL / FORWARD_ONLY here. `UNKNOWN` is a named attribute not returned by
`list_known_formats()` and reports NONE. Seekable-required among known formats:
DIRECTORY, ISO, RAR, SEVEN_Z, ZIP. Do not inherit older baselines without re-running.

---

## `format_availability()` — every format **FULL** in this session

The brief requires this because "a page claiming a format works is unverifiable if that
format is unavailable in the session". On this leg **nothing is unavailable**, so
*format unavailability is not an admissible "unverifiable" reason for any row below.*
A worker writing `unverifiable` must name a different reason.

**Scoped to this leg, and workers must re-measure.** Availability is a property of the
container, not of the repository: a fresh session can differ, and this very sweep read
differently between the two passes. Re-run `format_availability()` in your own session
before inheriting the sentence above. Do **not** carry it forward as a standing rule that
format claims can never be `unverifiable` — that generalisation is what #247's baseline
made, and it is unsafe.

`format_availability(fmt)` takes one `ArchiveFormat` and returns a `FormatAvailability`
(`src/archivey/internal/registry.py:69`, `:314`). Full sweep of all 22 members:

| Format | Support | `required_source` | `missing` |
|---|---|---|---|
| `ZIP` · `SEVEN_Z` · `RAR` · `ISO` · `DIRECTORY` | `FULL` | `SEEKABLE` | — |
| `TAR` · `TAR_GZ` · `TAR_BZ2` · `TAR_XZ` · `TAR_ZST` · `TAR_LZ4` | `FULL` | `FORWARD_ONLY` | — |
| `GZ` · `BZ2` · `XZ` · `ZST` · `LZ4` · `LZIP` · `LZMA_ALONE` · `BROTLI` · `ZLIB` · `Z` | `FULL` | `FORWARD_ONLY` | — |
| `UNKNOWN` | `NONE` | `SEEKABLE` | — |

Two observations that become claim rows rather than findings here:

- **`ZST` reports `FULL`, and the reason is `backports.zstd`** — installed as version
  1.6.0 on this leg (Python 3.11.15), so the availability answer is correct and
  `formats.md:18`'s "`[recommended]` → `backports.zstd`" row describes it accurately.
  Row **G-6** stands as a claim to verify, not as an anomaly. *(An earlier draft of this
  file read the anomaly the other way, from a package-name check that missed the
  installed distribution. Corrected here rather than left for a worker to re-derive.)*
- **But `format_availability()` answers for a public type it does not know.**
  `StreamFormat.ZSTD` and `ArchiveFormat.ZST` are distinct `__all__` members that both
  carry the value `'zst'`, and they get different answers:
  `ArchiveFormat.ZST → FULL / FORWARD_ONLY` against
  `StreamFormat.ZSTD → NONE / SEEKABLE / missing=()`. `StreamFormat.ZSTD` is not in
  `list_known_formats()`, so the call **fabricates a verdict instead of raising** — a
  wrong negative with nothing in `missing` to explain it, disagreeing with the real record
  on `required_source`, the field `opening-and-listing.md:70-85` teaches callers to branch
  on. This is a **library** question, not a docs claim: filed as
  `dev-docs/open-issues.md` **P10** — whose framing was **corrected 2026-08-17**: the
  signature takes an `ArchiveFormat` only and both `pyrefly` and `ty` reject a
  `StreamFormat`, so a typed caller is protected. What remains is that the wrong-typed
  call *fabricates* a record instead of raising `ArchiveyUsageError`. Read P10, not this
  paragraph's original wording. Not fixed here — **fixed since**, in
  `2026-08-17-reject-wrong-typed-format-arguments`: all four entry points that take a
  format now raise `ArchiveyUsageError` on a value outside their declared types, so the
  sweep above is a record of the *old* behaviour on this one call. A worker writing
  `install.md`'s `format_availability()` section takes the contract from **G-25a**.
- **`format_availability()` is a per-format query, not a matrix dump.** `install.md`'s
  inbound §B row 2 ("the `format_availability()` support-level query", ~10 lines) has to
  be written against that signature; a reader cannot call it once and get a table. Noted
  for step 6, not a claim.

## What the baseline does *not* establish

- No `python` code block in the guide was executed. 35 blocks, none run by CI
  (brief §A, last row); making them run is Definition-of-done row 8, not this step.
  Every code block below is therefore a **claim row**, not a verified example.
- Coverage is 88%, which is a test-suite property, not a documentation one.
- `[all-lowest]` and `[core-only]` were **not** run. The three-config rule
  (`CONTRIBUTING.md` §"Before pushing…") applies to the page PRs, and the `cfg`-marked
  rows below are the ones it will bite.

---

# Part 2 — The claim inventory (step 3)

## How to read a row

| Column | Means |
|---|---|
| **#** | Stable id. `A-7`, `C-12`. Cite these; they are what the capability workers report against |
| **Claim** | Stated so it can be true or false. Not a topic — a proposition |
| **Stated at** | **Every** page that states it, `page:line`. One row, N pages. This column is the whole point of building the inventory centrally (brief §How to run this) |
| **Settles it** | The `src/` or `openspec/specs/` line that decides the claim. `safe-extraction:130` means `openspec/specs/safe-extraction/spec.md:130`; a `src/` path is written in full. A **spec** reference is preferred where one exists — O-26: the code may be the thing that is wrong |
| **Ruling** | `scope.md`'s routing for the block, verbatim. `Keep` · `Trim` · `→ DS` · `→ page` · `→ TM` |
| **V** | Verdict — `verified` / `wrong` / `unverifiable (reason)` / `out of scope ([TM])`. Evidence in `worker-inputs/verdicts-*.md` |

**A row whose co-cited pages disagree must be split, not merged.** If two pages state
different versions of the same fact, do not pick one as "the claim" and file the other
page as a co-citation: that hides the contradiction behind a single verdict, and a worker
can mark the row `verified` against the code while the other page stays wrong. Split into
one row per version, and flag the pair. **A-16 is the worked example** — #247 merged
exactly this pair and the contradiction survived.

Rows carrying `[code]` are code blocks: the claim is "this block runs, imports, and does
what its surrounding prose says". Rows carrying `[TM]` were routed to
`dev-docs/threat-model.md`; per the brief they are **recorded but out of scope to verify
here** — verify when the threat-model edit is written, so the register does not inherit
an unverified claim. Rows carrying `cfg` depend on an optional dependency and need the
three-config check.

## Coverage — all 16 pages, none silently omitted

| Page | Lines | Rows citing it | Clusters it lands in |
|---|---:|---:|---|
| `index.md` | 93 | 23 | A, B, C, D, E, G, I |
| `install.md` | 34 | 12 | E, G |
| `opening-and-listing.md` | 203 | 47 | A, C, D, E |
| `reading-members.md` | 184 | 37 | B, D |
| `gotchas.md` | 107 | 43 | B, C, D, E, F |
| `extracting.md` | 228 | 73 | C, D, E, F |
| `access-and-cost.md` | 188 | 58 | A, B, D, E, F |
| `formats.md` | 228 | 92 | A, B, C, E, F, G, I |
| `errors-and-diagnostics.md` | 201 | 54 | A, B, C, D, H |
| `cli.md` | 48 | 20 | C, D, G, H |
| `migrating.md` | 174 | 35 | A, B, C, D, E, H, I |
| `support-matrix.md` | 152 | 25 | B, D, G |
| `philosophy.md` | 79 | 25 | A, B, C, E, F, I |
| `api.md` | 91 | 5 | I |
| `acknowledgements.md` | 98 | 24 | E, F, G, I |
| `how-it-works.md` | **0** | **0** | — |

`how-it-works.md` contributes **zero rows and that is correct, not a gap**: a page with
no prose makes no claim. Its content is `scope.md` §16's specification and Definition-of-
done row 3's deliverable, and every fact it will receive is already a row here under the
page that states it today (`access-and-cost.md:35-45` → F-6/F-7,
`migrating.md:130-132` → E-31).

The right-hand column counts **appearances**, so it sums to 573 against a row total of
**400** — that gap *is* the dedupe. **134 rows cite more than one page**; 10 cite no page
line at all (seven unwritten claims, two `api.md` omissions, and the missing page).
Pages sharing a row most often:
`formats`+`gotchas` (14), `access-and-cost`+`formats` (12), `extracting`+`gotchas` (11),
`formats`+`opening-and-listing` (10), `formats`+`migrating` (10).

Of the 400 rows: **34 carry `[code]`**, and between them they cover **all 39 fenced
blocks in the guide** (35 `python`, 4 `bash` — the brief's count, re-measured here and
unchanged); **8 carry `[TM]`** and are recorded-but-unverified by design; **12 carry
`cfg`** and need the three-config check.

## Where a claim was *not* extracted, and why

Per the brief: *every claim ends as a row; "I did not get to this page" is a legitimate
state and must be visible.* There is no such state in this file — all 15 published pages
were walked line by line. What is deliberately **not** a row:

1. **Blocks ruled `Cut` by `scope.md`.** Nothing receives them, so there is nothing to
   keep true. Each is listed in §Recorded drops below so the drop stays visible.
2. **Pure navigation and prose scaffolding** — section headings, "see X" links whose only
   assertion is that a page exists (`check_docs_nav.py` already proves those, and proves
   them every commit).
3. **Positioning and register**, which are Topic 7's and pass 3's. `index.md:46-61`
   §Highlights is in as **claims** (I-2…I-5) because each bullet asserts a capability;
   whether the framing persuades is not this pass's question.

## Recorded drops — `Cut` blocks, no row

| Where | What is lost | Ruling |
|---|---|---|
| `formats.md:53-54` | "A native ZIP reader could recover the other entries; today it cannot" | `Cut` — roadmap |
| `formats.md:92` | "A future native TAR reader may close this gap" | `Cut` — roadmap |
| `support-matrix.md:64-68` | The second "Measured on CPython 3.13.7t", duplicated four lines after the first | `Cut` — duplicate, no unique claim |
| `index.md` (never written) | A fifth Home recipe receiving the `formats.md` dedupe use case | Dropped by maintainer decision, `scope.md` Q6 |
| `extracting.md` (never written) | The bounded-recursion worked recipe | Dropped by maintainer decision, `scope.md` Q5 — the pointer at `203-206` is the coverage (row C-44) |

---

# A. Opening, detection, sources

Specs: `format-detection`, `archive-reading`, `compressed-streams`.
Pages: `opening-and-listing`, `install`, `formats`, `index`, `migrating`, `philosophy`.

Evidence: [`worker-inputs/verdicts-A.md`](worker-inputs/verdicts-A.md); harvest [`../problem-catalogue/harvest/A-opening.md`](../problem-catalogue/harvest/A-opening.md).

| # | Claim | Stated at | Settles it | Ruling | V |
|---|---|---|---|---|---|
| A-1 | `open_archive(path)` detects the format and returns a reader; iterating it yields members in **archive order** | `opening-and-listing.md:11-13`, `index.md:9-11`, `migrating.md:14-15` | `archive-reading:20`, `archive-reading:259` | Keep | verified |
| A-2 | `reader.members()` returns the **full** list or raises — never a quietly shortened one | `opening-and-listing.md:15`, `opening-and-listing.md:155-156`, `errors-and-diagnostics.md:116-117` | `archive-reading:199`, `documentation:103` | Keep | verified |
| A-3 | `reader.get(name)` returns the member with that name | `opening-and-listing.md:16` | `archive-reading:406` | Keep | verified |
| A-4 | An open reader exposes `.format` and `.cost` | `opening-and-listing.md:17` | `access-mode-and-cost:151` | Keep | verified |
| A-5 | **By default any member may be opened in any order** — random access is the default access mode | `opening-and-listing.md:20-23` | `access-mode-and-cost:19` | Keep | verified |
| A-6 | Without `streaming=True` a non-seekable source **fails at open**, not halfway through, and archivey never silently buffers it to memory or a temp file. **Reword:** the no-buffering half is true of the *pipe* case it sits in (ADR 0010's scope) but reads as absolute, and RAR-from-a-seekable-stream contradicts the absolute reading — see **E-71** | `opening-and-listing.md:25-28`, `access-and-cost.md:141-143`, `philosophy.md:42`, `migrating.md:170-172` | `access-mode-and-cost:50`, `archive-reading:701`, ADR 0010 (scoped to non-seekable) | Keep, **reword** | **`wrong` as written** (absolute reading). Repro §Coordinator-verified |
| A-7 | `open_archive` on a plain `.gz` yields an archive with **exactly one** member, named after the file | `opening-and-listing.md:41-43`, `formats.md:143` | `format-single-file-compressors:27` | Keep | verified |
| A-8 | `open_stream(path)` returns the decompressed bytes rather than an archive | `opening-and-listing.md:36-39`, `migrating.md:20` | `compressed-streams:36` | Keep | verified |
| A-9 | `[code]` the `open_archive` / `open_stream` two-liner runs | `opening-and-listing.md:36-39` | — (executable) | Keep | verified |
| A-10 | A path to a **directory** opens as a pseudo-archive, one member per file | `opening-and-listing.md:50`, `formats.md:136-137` | `format-directory:20` | Keep | verified |
| A-11 | Passing a `format=` that is anything but `DIRECTORY`, for a path that is a directory, raises `ArchiveyUsageError` rather than reading the tree | `opening-and-listing.md:54-55` | `src/archivey/core.py:240-247` | Keep | verified |
| A-12 | A **seekable stream is read from its current position**: that position is treated as byte 0, so an archive at a known offset opens without copying it out | `opening-and-listing.md:57-61` | `archive-reading:20` | Keep | verified |
| A-13 | There is **no matching end bound** — the archive must run to the end of the stream, else the caller wraps it in a bounded view | `opening-and-listing.md:61-62` | `archive-reading:20` | Keep | verified |
| A-14 | A non-seekable stream with `streaming=True` works for **TAR (including compressed tar) and the single-file compressors** | `opening-and-listing.md:64-66`, `formats.md:11-12` | `access-mode-and-cost:50`, `format-tar:20` | Keep | verified |
| A-15 | **ZIP, 7z, RAR and ISO must seek**; opening one from a pipe raises `StreamNotSeekableError`, fix is to buffer to a file or `BytesIO` | `opening-and-listing.md:66-68` | `format-zip:118`, `format-iso:22`, `format-7z:25`, `format-rar:25` | Keep | verified |
| A-16 | **`access-and-cost.md` is the wrong side.** It names only **ZIP (stdlib) and ISO** as always needing seek, which implies 7z and RAR can be opened from a pipe under `streaming=True`. They cannot. `opening-and-listing.md:66-68` is correct | `access-and-cost.md:145-146` vs `opening-and-listing.md:66-68` | `access-mode-and-cost:233`; `required_source` is `SEEKABLE` for ZIP / 7z / RAR / ISO alike (Part 1 sweep) | Keep (`opening-and-listing`) · **fix** `access-and-cost.md:145-146` | **`wrong` — `access-and-cost.md`.** Repro §Coordinator-verified |
| A-17 | `format_availability(fmt).required_source` is **the weakest source shape the format can be read from**, so a comparison replaces a `try`/`except` | `opening-and-listing.md:70-73` | `src/archivey/internal/registry.py:69`, `:314` | Keep — canonical home | verified |
| A-18 | `[code]` the `required_source` / `StreamCapability` comparison block runs as written (imports `StreamCapability, detect_format, format_availability` from `archivey`) | `opening-and-listing.md:74-81` | — (executable) | Keep | wrong |
| A-19 | `StreamCapability` is **ordered**, `FORWARD_ONLY < SEEKABLE`, and the same comparison works against `reader.cost.stream_capability` | `opening-and-listing.md:83-85`, `access-and-cost.md:48-52` | `src/archivey/cost.py:48-84` | Keep — canonical home | verified |
| A-20 | **Only 7z and RAR** split across volumes | `opening-and-listing.md:89` | `format-7z:180`, `format-rar:345`, `format-zip:169` | Keep | verified |
| A-21 | Passing **any one volume** finds the rest, in all three listed naming schemes (`.7z.001…`, `.partN.rar`, `.rar`+`.rNN`) | `opening-and-listing.md:89-96` | `format-rar:345`, `format-7z:180`, `src/archivey/internal/volumes.py` | Keep | verified |
| A-22 | A **7z** volume set is checked for completeness — a missing middle part errors rather than short-reading | `opening-and-listing.md:98-99` | `format-7z:180` | Keep | verified |
| A-23 | The **old RAR scheme needs its `.rar`**; a `.rNN` alone is read as a lone file, not as part of a set | `opening-and-listing.md:99-101` | `format-rar:345` | Keep | verified |
| A-24 | An explicit ordered **sequence** of paths or streams is used in the order given, with no discovery | `opening-and-listing.md:103-105` | `archive-reading:152` | Keep | verified |
| A-25 | A **one-item** sequence is treated as a single source | `opening-and-listing.md:105-106` | `archive-reading:152` | Keep | verified |
| A-26 | A multi-volume sequence for any format **other than 7z or RAR raises** | `opening-and-listing.md:106-107` | `src/archivey/core.py:115-124` | Keep | verified |
| A-27 | `detect_format(p)` returns a `FormatInfo` carrying `.format` and `.confidence` | `opening-and-listing.md:114-117`, `formats.md:227-228`, `migrating.md:21` | `format-detection:19` | Keep — canonical home | verified |
| A-28 | **Content wins over filename**: bytes first, extension only when the bytes are inconclusive | `opening-and-listing.md:119-120`, `formats.md:224`, `migrating.md:109-110`, `philosophy.md:66` | `format-detection:68` | Keep — canonical home | verified |
| A-29 | When bytes and extension disagree, the bytes are used **and** a `FORMAT_EXTENSION_CONFLICT` diagnostic names both candidates | `opening-and-listing.md:120-123` | `format-detection:84`, `src/archivey/diagnostics.py:64` | Keep | verified |
| A-30 | `detect_format` reports **the same format `open_archive` would use** | `opening-and-listing.md:125` | `format-detection:19` | Keep | verified |
| A-31 | Telling `.tar.zst` from plain `.zst` needs decompressing a little to look for a tar header; **when the compressor's package is absent the check cannot run** and the bare compressor is reported | `opening-and-listing.md:126-128` | `format-detection:174` | Keep · `cfg` | verified · cfg `[all]` |
| A-32 | Opening such a file then raises **`UnsupportedFormatError`, naming the package to install** | `opening-and-listing.md:128-130` | `compressed-streams:124` | Keep | verified |
| A-33 | **Conflicts with A-32:** `formats.md` says a missing backend raises **`PackageNotInstalledError`**. Two pages name two exception types for one situation | `formats.md:36-37`, `formats.md:58-59` vs `opening-and-listing.md:128-130` | `compressed-streams:124`, `src/archivey/exceptions.py:113`, `:224` | Keep (both) | wrong |
| A-34 | **SFX stubs** are detected when the payload sits behind an executable header | `formats.md:225-226` | `format-detection:231` | `→ page, 2 lines` — the SFX line is the unique claim and stays on `formats.md` | wrong |
| A-35 | Detection lives on `opening-and-listing.md`; `formats.md` §Detection is a second copy of magic-first + confidence | `formats.md:222-228` (dup of `opening-and-listing.md:109-131`) | `format-detection:68` | `→ page, 2 lines` | verified |
| A-36 | `password=` accepts **three forms** — a string, a list, a `PasswordProvider` callable — and all three behave alike on the unused-password rule | `opening-and-listing.md:136-137`, `:148` | `archive-reading:632` | Trim | verified |
| A-37 | **Put the most likely password first**: every wrong candidate costs work before rejection, especially on 7z | `opening-and-listing.md:140-141`, `access-and-cost.md:154-158` | `archive-reading:668`, `format-7z:197` | Trim | verified |
| A-38 | A password passed to a format with **no encryption at all** is accepted, never consulted, and records `PASSWORD_ARGUMENT_UNUSED` | `opening-and-listing.md:143-147`, `errors-and-diagnostics.md:59` | `diagnostics:253` | Trim | verified |
| A-39 | A **wrong** password on a genuinely encrypted archive raises `EncryptionError` | `opening-and-listing.md:150-151`, `migrating.md:135` | `src/archivey/exceptions.py:133`, `archive-reading:632` | Trim | verified |
| A-40 | `[code]` the `is_current` filter block runs | `opening-and-listing.md:191-194` | — (executable) | Keep | verified |
| A-41 | `[code]` the history-view loop runs | `opening-and-listing.md:198-203` | — (executable) | `Trim to one` — this is the block slated for removal; the claim is still recorded so the removal is a decision, not a loss | verified |
| A-42 | `[code]` the Home open+list snippet runs | `index.md:6-12` | — (executable) | Keep | verified |
| A-43 | `[code]` Home recipe 4 — reading from a pipe with `streaming=True` and `stream_members()` | `index.md:37-40` | — (executable) | Keep, frozen | verified |
| A-44 | `[code]` the `zipfile` before/after pair runs, and the "after" half is the idiomatic equivalent of the "before" half | `migrating.md:25-41` | — (executable) | Keep | verified |

## A — problems and gaps met while extracting

- **A-16 and A-33 are the two live cross-page contradictions in this cluster**, and both
  are the O-2 shape: a fact stated on two pages, checked against each other rather than
  against the spec. Neither was in `scope.md` §Findings.
- `opening-and-listing.md:126-131`'s wrinkle is the only place the guide describes a
  *detection* outcome that changes with the installed extras. It is the row most likely
  to read differently on `[core-only]`.

---

# B. Reading, member lifetime, concurrency

Specs: `archive-reading`, `reader-concurrency`, `archive-data-model`.
Pages: `reading-members`, `access-and-cost`, `gotchas`, `support-matrix`,
`opening-and-listing`, `migrating`, `philosophy`.

Evidence: [`worker-inputs/verdicts-B.md`](worker-inputs/verdicts-B.md); harvest [`../problem-catalogue/harvest/B-reading.md`](../problem-catalogue/harvest/B-reading.md).

| # | Claim | Stated at | Settles it | Ruling | V |
|---|---|---|---|---|---|
| B-1 | `reader.open(name)` as a context manager and `reader.read(name)` are the same thing, one in two calls and one in one | `reading-members.md:9-15`, `migrating.md:17` | `archive-reading:435` | Keep | verified |
| B-2 | `[code]` the read-a-member block runs | `reading-members.md:9-15` | — (executable) | Keep | verified |
| B-3 | **`read()` has no size limit** — it returns the whole member however large | `reading-members.md:17-19`, `gotchas.md:37-39` | `archive-reading:435` | Keep | verified |
| B-4 | Member streams are **forward-only by default**; `seek()` raises unless opened with `seekable_members=True` | `reading-members.md:24-26`, `access-and-cost.md:90-92`, `philosophy.md:39-40`, `gotchas.md:15-16` | `archive-reading:93`, `seekable-decompressor-streams:20` | Keep | verified |
| B-5 | Specifically, without the flag a member stream reports **`seekable() is False`** and `seek()` raises **`io.UnsupportedOperation`** | `access-and-cost.md:90-91` | `archive-reading:93` | Keep, tighten | verified |
| B-6 | **One live member stream at a time by default**; a second overlapping `open()` raises `ConcurrentAccessError` unless `concurrent_members=True` | `reading-members.md:26-28`, `access-and-cost.md:127-128`, `support-matrix.md:112-115`, `philosophy.md:39`, `migrating.md:164-166` | `reader-concurrency:22` | Keep (`support-matrix.md:110-127` → `Trim to ~4 + links` as the fourth copy) | verified |
| B-7 | `[code]` the two-flag `open_archive` block runs | `reading-members.md:30-37` | — (executable) | Keep | verified |
| B-8 | **Neither flag is free** | `reading-members.md:39` | `access-mode-and-cost:233`, `:265` | Keep | verified |
| B-9 | `reader.stream_members()` walks the archive **in order**, yielding `(member, stream)` | `reading-members.md:43-45`, `index.md:31-35` | `archive-reading:492` | Keep | verified |
| B-10 | `[code]` the `stream_members` loop with the `stream is None` guard runs | `reading-members.md:47-53`, `index.md:31-35` | — (executable) | Keep | verified |
| B-11 | `reader.cost.access_cost` tells you which of the two reading strategies you are in | `reading-members.md:55-56` | `access-mode-and-cost:151` | Keep | verified |
| B-12 | For **ZIP or uncompressed TAR** `access_cost` is `DIRECT`: members are stored independently, so one costs the same as all | `reading-members.md:56-58`, `formats.md:10-11`, `access-and-cost.md:42` | `access-mode-and-cost:151`, `format-zip:20`, `format-tar:20` | Keep | verified |
| B-13 | For **solid 7z/RAR or any compressed tar** it is `SOLID`: reading a middle member decompresses everything before it, and per-member opens turn a linear read quadratic | `reading-members.md:60-63`, `access-and-cost.md:66-67`, `gotchas.md:20-23`, `formats.md:11-12`, `migrating.md:86-88`, `philosophy.md:33-34` | `access-mode-and-cost:151`, `format-7z:243`, `format-rar:168` | Keep | verified |
| B-14 | **Nothing warns you about the solid-open cost** — it is slow, not wrong; check `access_cost` instead | `reading-members.md:63-65` | `access-mode-and-cost:151` | Keep | verified |
| B-15 | **A yielded stream is valid only until you advance**: the iterator closes it before producing the next pair | `reading-members.md:69-71` | `archive-reading:492` | Keep | verified |
| B-16 | **Non-file members yield `None`** — directories, symlinks and hardlinks all come through as `(member, None)` | `reading-members.md:72-73`, `reading-members.md:132-133` | `archive-reading:480` | Keep | verified |
| B-17 | **Nothing is decompressed until you read**: a skipped member is never opened and no password is requested for it, so "I iterated without error" does not prove the password | `reading-members.md:74-77` | `archive-reading:492`, `archive-reading:632` | Keep | verified |
| B-18 | B-17 applies to **data** encryption only; **header**-encrypted 7z and RAR need the password at `open_archive()` and raise `EncryptionError` before any member exists | `reading-members.md:79-84`, `formats.md:106`, `formats.md:117` | `format-7z:197`, `format-rar:308` | Trim | verified |
| B-19 | `reader.open()` **follows links**; `stream_members()` deliberately does not, so a loop that skips `None` skips links | `reading-members.md:86-93`, `reading-members.md:130-133` | `archive-reading:539` | Keep | verified |
| B-20 | Following a link means reading the target's bytes, which in a single forward pass may already be behind you — formats that *could* reach it follow the same rule so loop shape does not vary | `reading-members.md:87-90` | `archive-reading:539` | Keep | verified |
| B-21 | `member.link_target` lets you resolve links yourself | `reading-members.md:92-93` | `archive-data-model:122` | Keep | verified |
| B-22 | A `stream_members()` pass **owns the reader**: `open()`, `members()` or another pass inside the loop raises `ArchiveyUsageError` | `reading-members.md:95-97`, `support-matrix.md:104-106` | `reader-concurrency:192`, `access-mode-and-cost:120` | Keep | verified |
| B-23 | Reading a member **to its end** verifies it wherever the archive stores a checksum, and raises rather than handing over short or wrong data | `reading-members.md:101-102`, `errors-and-diagnostics.md:136-138`, `index.md:25-26` | `compressed-streams:254`, `archive-reading:435` | Keep | verified |
| B-24 | **A broken link raises `LinkTargetNotFoundError`; a cycle raises rather than spinning** | `reading-members.md:131-132` | `archive-reading:539`, `src/archivey/exceptions.py:137` | Keep | verified |
| B-25 | `reader.open()` on a **directory or other non-file entry** raises `ArchiveyUsageError` naming the type | `reading-members.md:135-137` | `archive-reading:435` | Keep | verified |
| B-26 | **A member belongs to the reader that produced it** — passing an `ArchiveMember` from another archive raises `ArchiveyUsageError` rather than resolving it against the wrong offsets | `reading-members.md:139-141` | `archive-reading:406` | Keep | verified |
| B-27 | `member in reader` tests **identity, not name**; a string raises `TypeError` and points at `reader.get(name)` | `reading-members.md:141-144` | `archive-reading:406` | Keep | verified |
| B-28 | **A member stream does not outlive its reader**: closing the reader closes open member streams, matching `ZipFile.close()` / `TarFile.close()` | `reading-members.md:146-150`, `support-matrix.md:136-137` | `archive-reading:581`, `reader-concurrency:166` | Keep | verified |
| B-29 | `[code]` the nested-`with` block runs | `reading-members.md:152-156` | — (executable) | Keep | verified |
| B-30 | Under `streaming=True` the random-access methods — `members()`, `get()`, `open()`, `read()` — raise **`UnsupportedOperationError`** | `reading-members.md:166-168` | `access-mode-and-cost:50`, `access-mode-and-cost:120` | Keep | verified |
| B-31 | What remains is `__iter__`, `stream_members()` and `extract_all()`, and **you get one of them**: the first consumes the source, even after an early `break` | `reading-members.md:168-170`, `access-and-cost.md:150-152`, `gotchas.md:25-26` | `access-mode-and-cost:50` | Keep (`access-and-cost.md:148-152` → `Trim to 2 + link`, third copy) | verified |
| B-32 | `scan_members()` is how you drain/finish for a full list after a partial pass | `access-and-cost.md:152` | `access-mode-and-cost:85`, `archive-reading:339` | Trim (the one unique claim of the block) | verified |
| B-33 | `[code]` the streaming-mode pipe block runs | `reading-members.md:160-164` | — (executable) | Keep | verified |
| B-34 | **`archivey.extract(src, dest)` has no `members=` argument** — selecting a subset needs `reader.extract_all(members=...)` | `reading-members.md:179-181` | `safe-extraction:21`, `safe-extraction:65` | Keep | verified |
| B-35 | **`extract()` accepts a non-seekable source**, opening it in streaming mode for you, where `open_archive` refuses one without `streaming=True` | `reading-members.md:182-184` | `safe-extraction:21` | Keep | verified |
| B-36 | After materialization, workers may `open()` **different** members concurrently; same-stream access still needs caller synchronization | `access-and-cost.md:134-135`, `support-matrix.md:44-46`, `support-matrix.md:145-146` | `reader-concurrency:22`, `reader-concurrency:149` | Keep | verified |
| B-37 | Reader-wide passes (`__iter__` / `stream_members` / `extract_all`) remain **single-owner** | `access-and-cost.md:135-136`, `support-matrix.md:104-106`, `support-matrix.md:147-148` | `reader-concurrency:192` | Keep | verified |
| B-38 | **`streaming=True` cannot combine with `concurrent_members=True`** | `access-and-cost.md:137` | `access-mode-and-cost:233` | Keep | verified |
| B-39 | `[code]` the one-line `open_archive(src, concurrent_members=True)` block runs | `access-and-cost.md:130-132` | — (executable) | Keep | verified |
| B-40 | `close()` is **safe to call twice** and **not safe to race** against in-flight opens; it can block on I/O finishing elsewhere | `support-matrix.md:136-139`, `support-matrix.md:149` | `reader-concurrency:166`, `reader-concurrency:266` | Keep | verified |
| B-41 | **Separate `ArchiveReader` objects share no mutable state** and are safe across threads | `support-matrix.md:150` | `reader-concurrency:22` | Keep | verified |
| B-42 | The single-stream default exists so a reader can **hold one decode position per archive**, which is the cheap path for every format | `support-matrix.md:124-126` | `reader-concurrency:22`, `access-mode-and-cost:233` | `Trim to ~4 + links` — this sentence is the block's unique claim | verified |
| B-43 | `[code]` the fail-fast `ConcurrentAccessError` demo runs and raises where the comment says | `support-matrix.md:117-121` | — (executable) | `Trim to ~4 + links` | verified |
| B-44 | `[code]` the free-threading fan-out example runs | `support-matrix.md:48-54` | — (executable) | Keep, tighten to ~12 | verified |
| B-45 | `stdlib` peers behave differently on three points archivey inverts: `extractfile` can return `None` (archivey raises typed), `tarfile` re-decompresses silently (archivey exposes cost), `tarfile` stops silently on truncation (archivey gives prefix + error) | `migrating.md:84-91` | `format-tar:125`, `archive-reading:199` | Keep | verified |
| B-46 | **`read()` is all-or-raise** for migrators: a truncated member raises rather than returning a short body; a chunked loop gets the recoverable prefix | `migrating.md:167-169` | `compressed-streams:155`, `archive-reading:435` | Keep | verified |
| B-47 | Format differences surface **as data** (`None`, documented sentinels, cost receipts), never as a different API per backend | `philosophy.md:22-23` | `archive-data-model:21`, `archive-reading:20` | Keep | verified |
| B-48 | `[code]` the `tarfile` before/after pair runs, and `reader.read("etc/config")` is the stated equivalent of `tf.extractfile(...).read()` | `migrating.md:59-76` | — (executable) | Keep | verified |

## B — problems and gaps met while extracting

- **B-6 is stated on five pages.** `scope.md` counted four (`reading-members`,
  `access-and-cost`, `support-matrix`, `philosophy`); `migrating.md:164-166` is a fifth.
  Whatever the trim does to `support-matrix.md`, the migration page's copy has to be
  checked too — it is the one a reader arrives at with stdlib habits.
- The **`stream_members()` link asymmetry** (B-19) is the single most load-bearing
  behaviour in the cluster and is stated in two places on one page. It is not stated on
  `gotchas.md`, which is defensible (the digest cannot hold everything) but is worth a
  deliberate call rather than an accident.

---

# C. Extraction, policies, results

Spec: `safe-extraction`.
Pages: `extracting`, `index`, `cli`, `gotchas`, `migrating`, `opening-and-listing`.

Evidence: [`worker-inputs/verdicts-C.md`](worker-inputs/verdicts-C.md); harvest [`../problem-catalogue/harvest/C-extraction.md`](../problem-catalogue/harvest/C-extraction.md).

| # | Claim | Stated at | Settles it | Ruling | V |
|---|---|---|---|---|---|
| C-1 | Extraction is **safe by default — you opt out, not in** | `extracting.md:3`, `index.md:21-22`, `index.md:56-57`, `philosophy.md:27-29`, `migrating.md:7-8` | `safe-extraction:130` | Keep | verified |
| C-2 | `[code]` the one-shot block runs, and its comment states the true defaults: `policy=ExtractionPolicy.STRICT`, `overwrite=ERROR`, `on_error=STOP` | `extracting.md:7-10`, `index.md:23` | `safe-extraction:21`, `src/archivey/internal/extraction_types.py:59`, `:75`, `:94` | Keep | verified |
| C-3 | **The archive is untrusted in every byte** — names, link targets, sizes, timestamps, comments, header structures, compressed streams; crafted archives are in scope for *all* guarantees | `extracting.md:14-16` | `safe-extraction:130` | `Trim to ~3 lines; rest → TM` — this clause is one of the two that stay | verified |
| C-4 | **An earlier extracted member is untrusted input to every later one** — which is why symlink targets are re-resolved against the live tree after creation | `extracting.md:17-20` | `safe-extraction:311` | `Trim`; the clause stays | verified |
| C-5 | `[TM]` The local process and other local processes are trusted; a local attacker racing the extraction is out of scope | `extracting.md:21-24` | `safe-extraction:130` (scope statement) | `→ TM` — verify when the threat-model edit is written | out of scope ([TM]) |
| C-6 | `[TM]` Optional dependencies and external tools are trusted code but not trusted to be robust; their failures surface as translated archivey errors, never silently wrong data | `extracting.md:25-27` | `error-handling:259`, `compressed-streams:137` | `→ TM` — verify when the threat-model edit is written | out of scope ([TM]) |
| C-7 | **Path traversal is rejected before any write**: `..` on any separator, absolute paths, drive letters, UNC prefixes, null bytes; the destination parent is resolved and containment-checked | `extracting.md:31-33`, `index.md:21-22`, `migrating.md:45-48`, `philosophy.md:27-28` | `safe-extraction:130` | `Trim → one clause` | verified |
| C-8 | `[TM]` A **file** member whose normalized name is `"."` or `""` is rejected with `PathTraversalError`; only a directory member may name the extraction root | `extracting.md:34-37` | `safe-extraction:130` | `→ TM` — verify when the threat-model edit is written | out of scope ([TM]) |
| C-9 | `[TM]` Symlink escapes are caught in **three layers** — lexical check at planning, parent-dir resolution, post-`os.symlink` re-resolution against the real filesystem — and escaping links are removed and rejected | `extracting.md:38-41` | `safe-extraction:311` | `→ TM` — verify when the threat-model edit is written | out of scope ([TM]) |
| C-10 | **Symlink escapes are blocked by default** (the caller-visible half of C-9) | `index.md:21-22`, `index.md:56-57`, `migrating.md:46-48`, `philosophy.md:27` | `safe-extraction:311` | Keep | verified |
| C-11 | `[TM]` Hardlink targets are containment-checked and **resolved positionally**, so a crafted duplicate-name archive cannot redirect a link | `extracting.md:42-43` | `safe-extraction:332` | `→ TM`; the caller-visible identity rule survives as C-35 | out of scope ([TM]) |
| C-12 | **Overwrite handling never writes through a symlink** — it replaces them, never follows | `extracting.md:44-45` | `safe-extraction:404`, `safe-extraction:829` | `Trim → one clause` | verified |
| C-13 | Writes are **atomic**: temp file + `os.replace`, so an interrupted extraction never leaves a half-written destination file | `extracting.md:45-46` | `safe-extraction:404` | `Trim → one clause` | verified |
| C-14 | Temp files are named **`.archivey-tmp-<random>`** and staged **inside the destination directory** | `extracting.md:80-82` | `safe-extraction:404` | Keep | verified |
| C-15 | Any Python-level failure removes them; **only a hard kill (SIGKILL, power loss) leaves one behind**, and leftovers are safe to delete before re-running | `extracting.md:82-84`, `extracting.md:181` | `safe-extraction:404` | Keep | verified |
| C-16 | **Special files** (devices, FIFOs, sockets) are **always** rejected — at every policy | `extracting.md:47-48` | `safe-extraction:130` | `Trim → one clause` | verified |
| C-17 | NTFS **junctions** are detected, flagged, and never traversed | `extracting.md:47-48` | `safe-extraction:130` | `Trim → one clause` | unverifiable (platform) |
| C-18 | A member name or link target containing a bidi **override or isolate** (U+202A–202E, U+2066–2069) is rejected with `DeceptiveNameError` under `STRICT` **and `STANDARD`** | `extracting.md:49-52` | `safe-extraction:878`, `src/archivey/exceptions.py:174` | Keep, shorter | verified |
| C-19 | The three **directional marks** (U+061C, U+200E, U+200F) are **not** rejected — they reorder nothing and occur in legitimate Arabic and Hebrew filenames | `extracting.md:53-55`, `errors-and-diagnostics.md:61` | `safe-extraction:878`, `src/archivey/diagnostics.py:129` | Keep, shorter | verified |
| C-20 | Right-to-left script itself is unaffected: `فهرس.txt` contains no control character | `extracting.md:55-56` | `safe-extraction:878` | Keep, shorter | verified |
| C-21 | Listing and reading **always present either kind exactly as stored**, with a `MEMBER_NAME_BIDI_CONTROL` diagnostic | `extracting.md:56-57`, `errors-and-diagnostics.md:61` | `diagnostics:211`, `src/archivey/diagnostics.py:63` | Keep, shorter | verified |
| C-22 | **`TRUSTED` lifts the bidi rejection** and extracts the member under its stored name; a caller filter that renames also works at any policy since the check runs on the final name | `extracting.md:59-65` | `src/archivey/internal/extraction_types.py:48-65`, `safe-extraction:367` | `→ DS + one line` | verified |
| C-23 | **Decompression bombs** are capped five ways at extraction: cumulative output, per-member ratio, archive-wide static ratio, **live** ratio for unknown-size/pipe sources, and an entry-count cap | `extracting.md:66-68`, `extracting.md:189-190` | `safe-extraction:479`, `:499`, `:779`, `:807`, `:850` | `Trim → one clause` (§Limits is the detail) | verified |
| C-24 | The **global** guards halt even under `OnError.CONTINUE` | `extracting.md:68`, `extracting.md:176`, `gotchas.md:37-40` | `safe-extraction:521`, `safe-extraction:712` | Keep | verified |
| C-25 | **setuid/setgid/sticky are stripped except under `TRUSTED`**; ownership is applied only under `TRUSTED` as root | `extracting.md:69-70`, `extracting.md:178`, `philosophy.md:54` | `safe-extraction:367` | `Trim → one clause` | verified |
| C-26 | `[TM]` Cross-platform name safety under STRICT/STANDARD is casefold+NFC collision tracking, reserved device names and `:` rejected, trailing-dot/space strip, non-UTF-8 percent-escape sanitization, `OverwritePolicy.RENAME` | `extracting.md:71-73` | `safe-extraction:878` | `→ TM`; the caller-visible consequences survive as C-33/C-37/C-39 | out of scope ([TM]) |
| C-27 | `[TM]` C++-threaded accelerators are close-guarded with `weakref.finalize` so crafted-input error paths cannot leave aborting threads | `extracting.md:76-78` | `seekable-decompressor-streams:161` | `→ TM`; the caller rule survives as F-24 | out of scope ([TM]) |
| C-28 | `[code]` the §Policies block runs, and its `import` line resolves all five names (`ExtractionPolicy, OverwritePolicy, OnError, ExtractionLimits, ListingLimits`) | `extracting.md:88-106` | `src/archivey/config.py:97`, `:119`, `src/archivey/internal/extraction_types.py:36`, `:66`, `:83` | Keep | verified |
| C-29 | `ListingLimits(max_members=…)` passed via `ArchiveyConfig` makes `reader.members()` raise `ResourceLimitError` when the central directory is larger | `extracting.md:100-105`, `extracting.md:191-193` | `archive-reading:339`, `safe-extraction:104` | Keep | verified |
| C-30 | **`OnError` governs per-member failures only** — corrupt/truncated data, write errors, overwrite conflicts under `ERROR` | `extracting.md:108-109` | `safe-extraction:712` | Keep | verified |
| C-31 | **A policy block is always recorded as `BLOCKED` and extraction continues**, under either `STOP` or `CONTINUE` | `extracting.md:109-111`, `extracting.md:177`, `cli.md:28-29` | `safe-extraction:712`, `safe-extraction:595` | Keep | verified |
| C-32 | `abort_on` exists, is **independent of `OnError`**, and names exactly three events | `extracting.md:113-122` | `safe-extraction:951`, `src/archivey/internal/extraction_types.py:98-128` | Keep | verified |
| C-33 | `[code]` the `abort_on={AbortOn.BLOCKED_MEMBER}` example runs | `extracting.md:116-120` | — (executable) | Keep | verified |
| C-34 | `AbortOn.BLOCKED_MEMBER` fires when a member is refused by a path-safety check or a policy filter, and raises the underlying `FilterRejectionError` | `extracting.md:124-126` | `safe-extraction:951`, `src/archivey/internal/extraction_types.py:116` | `→ DS` — the depth exists as a `#` comment today (`scope.md` §Precondition) | verified |
| C-35 | `AbortOn.NAME_COLLISION` fires when a second member resolves to an already-written destination (non-`TRUSTED`), raising `NameCollisionError` | `extracting.md:127` | `safe-extraction:951`, `src/archivey/internal/extraction_types.py:121` | `→ DS` | verified |
| C-36 | `AbortOn.NAME_SANITIZED` fires when a name is rewritten to its portable spelling, raising `NameRewrittenError` | `extracting.md:128` | `safe-extraction:951`, `src/archivey/internal/extraction_types.py:128` | `→ DS` | verified |
| C-37 | **An abort is immediate: no later member is processed and no report is returned** — you handle an exception, not a return value | `extracting.md:130-131` | `safe-extraction:951` | Keep, one line | verified |
| C-38 | Output already written stays on disk; an abort **stops** the run, it does not roll it back | `extracting.md:131-133` | `safe-extraction:951`, `safe-extraction:712` | Keep, one line | verified |
| C-39 | `NAME_COLLISION` fires on **every** collision whatever `OverwritePolicy` does — replaced, skipped, errored or renamed — because the trigger is the collision, not its resolution | `extracting.md:135-137` | `safe-extraction:951`, `safe-extraction:404` | `→ DS` — verbatim in the `NAME_COLLISION` comment already | verified |
| C-40 | `NAME_SANITIZED` is a **narrow escape hatch**: it fires on a *successful* rewrite, and no policy or preset implies it | `extracting.md:139-141` | `safe-extraction:951` | `→ DS` | verified |
| C-41 | To merely **audit** rewrites, read `ExtractionResult.presented_name` and let extraction finish | `extracting.md:142-143`, `extracting.md:172` | `safe-extraction:595` | `→ DS` / Keep (the `Need to know` row) | verified |
| C-42 | **S-2 (pre-seeded by `scope.md` §Findings, found independently by #241).** The policy table lists **two** rows for a **three-member** enum: `STANDARD` is absent, while the page's own prose uses it four times | `extracting.md:145-149` (table) vs `extracting.md:51`, `:71`, `:173`, `:175` | `src/archivey/internal/extraction_types.py:36-64` (three members), `safe-extraction:367` | **Keep, fix** — carried in, not re-derived | verified |
| C-43 | `STRICT` is for untrusted archives and is the default | `extracting.md:147`, `extracting.md:9`, `migrating.md:82-83` | `src/archivey/internal/extraction_types.py:59`, `safe-extraction:21` | Keep, fix | verified |
| C-44 | `TRUSTED` allows ownership / sticky bits when running as root and **still refuses traversal** | `extracting.md:148`, `extracting.md:178`, `philosophy.md:54` | `src/archivey/internal/extraction_types.py:61-64`, `safe-extraction:367` | Keep, fix | verified |
| C-45 | Archivey's three policies are **`STRICT` / `STANDARD` / `TRUSTED`** and apply to *every* format, not just tar; `STRICT` is closest to `tarfile`'s `filter="data"` | `migrating.md:80-83` | `src/archivey/internal/extraction_types.py:36-64`, `safe-extraction:367` | Keep | verified |
| C-46 | `[code]` the selective-extract block (`reader.extract_all("out/", members=["only/this.txt"])`) runs | `extracting.md:152-155` | `safe-extraction:65` | Keep | verified |
| C-47 | `get(name)` is **last-wins** when names collide | `extracting.md:161`, `opening-and-listing.md:173-174`, `gotchas.md:28-29` | `archive-reading:406` | Keep | verified |
| C-48 | `extract_all(members=["x"])` matches **every** member named `x`; pass an `ArchiveMember` for one identity | `extracting.md:162-163`, `opening-and-listing.md:182-187`, `gotchas.md:28-31` | `archive-reading:805`, `src/archivey/internal/selection.py:11-38` | Keep | verified |
| C-49 | **Hardlink targets resolve to an earlier same-named member by `member_id`**, not to whichever `get` would return | `extracting.md:164-166` | `safe-extraction:332` | Keep — receives the rule from `42-43` | verified |
| C-50 | Members with `is_current=False` stay visible in listings but are **skipped on extract by default**, and the skip is reported as **`ExtractionStatus.SUPERSEDED`** — distinct from `NOT_OVERWRITTEN`, which is about a file already on disk | `extracting.md:166-167`, `opening-and-listing.md:176-180`, `formats.md:120-122` | `safe-extraction:254`, `src/archivey/internal/extraction_types.py` (`ExtractionStatus.SUPERSEDED`) | Keep | verified |
| C-51 | **Safe ≠ unlimited**: huge/hostile archives can still raise `ResourceLimitError` unless you raise limits | `extracting.md:171`, `extracting.md:189-197` | `safe-extraction:479` | Keep (the table row is `Trim to ~6 rows`; §Limits keeps it) | verified |
| C-52 | **STRICT rewrites some names** — trailing dots/spaces stripped, non-UTF-8 percent-escaped — so the disk path may differ from `member.name` | `extracting.md:172`, `gotchas.md:33-36` | `safe-extraction:878` | Keep (one of the six surviving rows) | verified |
| C-53 | Under `STRICT`/`STANDARD`, `README`/`readme` **and NFC/NFD twins collide on all platforms**, not just Windows | `extracting.md:173`, `gotchas.md:34-35` | `safe-extraction:878` | Keep (surviving row) | verified |
| C-54 | `OverwritePolicy.REPLACE` **is not a silent merge**: the clobbered member's result is revised to `OVERWRITTEN` | `extracting.md:173` | `safe-extraction:404`, `safe-extraction:595` | Keep (surviving row) | verified |
| C-55 | `OverwritePolicy.RENAME` produces `photo (1).jpg`-style names for intentional duplicates | `extracting.md:173`, `cli.md:18` | `safe-extraction:404`, `src/archivey/internal/extraction_types.py:80` | Keep (surviving row) | verified |
| C-56 | `ExtractionResult.collided_with` names the already-written path a member collided with, **under every resolution**, and is `None` when the destination was simply already on disk | `extracting.md:174` | `safe-extraction:595` | Keep (surviving row) | verified |
| C-57 | Reserved device names and `:` are rejected under `STRICT`/`STANDARD` **on every platform** (`CON`, `NUL`, `file:ads`) | `extracting.md:175` | `safe-extraction:878` | Keep (surviving row) | verified |
| C-58 | Excluding a hardlink's source can **orphan the link** (especially on streaming sources), and `OnError` decides fail vs continue | `extracting.md:179` | `safe-extraction:332` | Keep (surviving row) | verified |
| C-59 | Unlike `tarfile`, archivey **does not copy target bytes through a symlink** on symlink-hostile filesystems — you get a typed failure or skip | `extracting.md:180` | `safe-extraction:829` | Keep (surviving row) | verified |
| C-60 | **Nested-archive recursion is caller-driven**; a zip-quine loops only if you loop | `extracting.md:182`, `extracting.md:204-206`, `gotchas.md:41-44` | `safe-extraction:521` | Keep | verified |
| C-61 | **The bomb tracker is per-archive and not nesting-aware**, so a zip-of-zips can amplify past your budget one level at a time | `extracting.md:203-206`, `gotchas.md:41-43` | `safe-extraction:521`, `safe-extraction:779` | Keep, unchanged (Q5: the pointer is the coverage) | verified |
| C-62 | **Bomb guards apply during extraction; `ListingLimits` apply to every listing call, `stream_members()` and `for member in reader` included** (was "`stream_members()` is intentionally unguarded"; changed by PR 773) | `extracting.md` §Limits, `opening-and-listing.md` §streaming limitations | `safe-extraction:521`, `archive-reading` §listing limits | Update | re-check |
| C-63 | `ExtractionLimits` caps total extracted bytes, compression ratio and entry count; trips raise `ResourceLimitError` | `extracting.md:189-190` | `safe-extraction:479`, `:499`, `:807` | Keep, unchanged | verified |
| C-64 | `ListingLimits` caps member count **and retained metadata bytes**, on `members()` / `scan_members()` / extract-prep materialization | `extracting.md:191-193` | `archive-reading:339`, `archive-reading:378` | Keep, unchanged | verified |
| C-65 | Limits are loosened per call with `limits=` (**extraction only**), `listing_limits` at `open_archive(config=…)`, or the two `UNLIMITED` sentinels | `extracting.md:195-197`, `philosophy.md:54-55` | `safe-extraction:104`, `src/archivey/config.py:97`, `:119` | Keep, unchanged | verified |
| C-66 | **must-explain #8 (§B row 4's survivor, ~3 lines, unwritten):** `extract_all(config=)` cannot raise the listing ceiling set at open time | *no page states it* | `safe-extraction:104`, `archive-reading:717` | **Guide** — the last open §B row-4 sub-row | verified |
| C-67 | RAR member data may be decompressed by the system `unrar`, whose availability and behaviour are part of your deployment's trust boundary — keep it updated | `extracting.md:218-220`, `index.md:54-55`, `formats.md:22-23` | `format-rar:127`, `packaging-and-extras:142` | Keep | verified |
| C-68 | Prefer extracting untrusted archives into a **dedicated directory with limited permissions**, then validating before promoting | `extracting.md:222-223` | — (operational guidance; no spec line) | Keep | verified |
| C-69 | **Every block and every name rewrite is recorded on the returned `ExtractionReport`**, not only in logs | `extracting.md:227-228`, `errors-and-diagnostics.md:43-45`, `gotchas.md:105-106` | `safe-extraction:595`, `safe-extraction:755` | Keep | verified |
| C-70 | `zipfile.extractall` **mangles** absolute paths and `..` but happily writes symlinks pointing outside the destination — archivey blocks both and reports `ExtractionStatus.BLOCKED` | `migrating.md:45-48` | `safe-extraction:130`, `safe-extraction:311`, `src/archivey/internal/extraction_types.py:144` | Keep — the page's strongest safety claim | verified |
| C-71 | `shutil.unpack_archive` returns `None`; `archivey.extract` returns an `ExtractionReport` saying what was written, skipped or blocked | `migrating.md:112-113` | `safe-extraction:755` | Keep | verified |
| C-72 | Archives that "worked" with `extractall` may now report `BLOCKED` members — check the `ExtractionReport` rather than assuming success | `migrating.md:161-163` | `safe-extraction:595` | Keep | verified |
| C-73 | `[code]` the `shutil.unpack_archive` before/after pair runs | `migrating.md:95-103` | — (executable) | Keep | verified |
| C-74 | `[code]` the `patool` / `subprocess 7z` before/after pair runs, and `archivey.extract("archive.7z", dest)` needs no external binary | `migrating.md:117-124` | — (executable) | Keep | verified |

## C — problems and gaps met while extracting

- **C-42 (S-2) has a second half nobody has stated.** The missing table row is the found
  defect; the *reason* it is easy to miss is that `STANDARD` has no `api.md`-rendered
  docstring either (`extraction_types.py:60` carries a `#` comment). Whoever fixes the
  table under Q1's carve-out can drain both at once.
- **C-66 is the one §B row-4 survivor and no page states it.** It is a *silence* claim in
  the brief's sense ("silence is a claim too"), so it is recorded as a row with no
  `Stated at` rather than as a gap note — otherwise it disappears at the next re-tally.
- Seven `extracting.md` blocks are `→ TM` — C-5, C-6, C-8, C-9, C-11, C-26, C-27 — and
  `formats.md`'s `NumCyclesPower` clamp (E-34) is an eighth elsewhere. All eight carry
  `[TM]` and are **not** verified here. The register must not inherit them unverified;
  that check belongs to whoever writes the threat-model edit.

---

# D. Errors, diagnostics, translation

Specs: `error-handling`, `diagnostics`, `logging`.
Pages: `errors-and-diagnostics`, `extracting`, `gotchas`, `opening-and-listing`,
`reading-members`, `support-matrix`.

Evidence: [`worker-inputs/verdicts-D.md`](worker-inputs/verdicts-D.md); harvest [`../problem-catalogue/harvest/D-errors.md`](../problem-catalogue/harvest/D-errors.md).

| # | Claim | Stated at | Settles it | Ruling | V |
|---|---|---|---|---|---|
| D-1 | **Every failure from the archive or its environment derives from `ArchiveyError`**, so one `except` covers them all | `errors-and-diagnostics.md:8-9`, `index.md:60-61` | `error-handling:20` | Keep | verified |
| D-2 | `[code]` the `except ArchiveyError` block runs | `errors-and-diagnostics.md:11-19` | — (executable) | Keep | verified |
| D-3 | `OpenError` covers `FormatDetectionError`, `UnsupportedFormatError`, `StreamNotSeekableError` | `errors-and-diagnostics.md:25` | `src/archivey/exceptions.py:105-119`, `error-handling:20` | Keep — the table is the exception tree's only reference until §D is settled | verified |
| D-4 | `EncryptionError` is raised when a password is required, missing, or wrong | `errors-and-diagnostics.md:26` | `src/archivey/exceptions.py:133` | Keep | verified |
| D-5 | `CorruptionError` / `TruncatedError` mean the archive is malformed or cut short | `errors-and-diagnostics.md:27` | `src/archivey/exceptions.py:125`, `:129` | Keep | verified |
| D-6 | `PackageNotInstalledError` means an optional package **or tool** is absent (e.g. the `unrar` binary) | `errors-and-diagnostics.md:28` | `src/archivey/exceptions.py:224`, `compressed-streams:124`, `packaging-and-extras:142` | Keep | verified |
| D-7 | `FilterRejectionError` means extraction blocked an unsafe member, and covers `PathTraversalError`, `SymlinkEscapeError`, `SpecialFileError` | `errors-and-diagnostics.md:29` | `src/archivey/exceptions.py:149-163` | Keep | verified |
| D-8 | **Completeness question for the D-7 row:** the tree also carries `UnportableNameError` and `DeceptiveNameError` under `FilterRejectionError`, which the table does not name | `errors-and-diagnostics.md:29` (omission) | `src/archivey/exceptions.py:165`, `:174` | Keep — coupled to §D (`scope.md` Q3) | verified |
| D-9 | `NameCollisionError` / `NameRewrittenError` are **raised only when you opted in with `abort_on`**; without it a collision or rewrite is recorded in the result, not raised | `errors-and-diagnostics.md:30`, `extracting.md:135-143` | `safe-extraction:951`, `src/archivey/exceptions.py:190`, `:201` | Keep | verified |
| D-10 | `ResourceLimitError` means a listing or extraction safety limit was exceeded | `errors-and-diagnostics.md:31` | `src/archivey/exceptions.py:211`, `safe-extraction:479` | Keep | verified |
| D-11 | **Mistakes in your code are deliberately outside the hierarchy**: misuse raises `ArchiveyUsageError` (e.g. `ConcurrentAccessError`), which is **not** an `ArchiveyError`, so a blanket `except ArchiveyError` never swallows a bug | `errors-and-diagnostics.md:33-37`, `support-matrix.md:128-132`, `access-and-cost.md:128` | `error-handling:84`, `src/archivey/exceptions.py:237`, `:259` | Keep (`support-matrix.md:128-132` → `→ page`) | verified |
| D-12 | When an **archive** genuinely cannot provide an operation — seeking a non-seekable member, a format that cannot list — that is a real `ArchiveyError`: `UnsupportedOperationError` | `errors-and-diagnostics.md:37-39` | `src/archivey/exceptions.py:228`, `error-handling:20` | Keep | verified |
| D-13 | Diagnostics are **structured, queryable advisories** on the reader and on the extraction report, not only log lines | `errors-and-diagnostics.md:43-46`, `gotchas.md:105-106`, `extracting.md:227-228` | `diagnostics:21`, `logging:40` | Keep | verified |
| D-14 | Each listed condition has a `DiagnosticCode` you can match on, and **any** of them can be escalated to an exception with a `DiagnosticPolicy` | `errors-and-diagnostics.md:50-52` | `diagnostics:153`, `src/archivey/diagnostics.py:58`, `:470` | Keep the table; trim the cells | verified |
| D-15 | `EMPTY_ARCHIVE` — the listing finished with no error and no members; an empty tar is real and **byte-identical to a zero-filled junk file of the same size** | `errors-and-diagnostics.md:56`, `gotchas.md:91-95` | `diagnostics:286` | Keep table / `Trim to ~3 + link` on `gotchas` | verified |
| D-16 | `EXTENSION_FORMAT_UNCONFIRMED` — the format came from the filename, nothing in the bytes confirmed it, and the listing came back empty | `errors-and-diagnostics.md:57`, `gotchas.md:97-99` | `format-detection:289`, `diagnostics:286` | Keep table | verified |
| D-17 | `EXPLICIT_FORMAT_LISTED_EMPTY` — you passed `format=`, the listing was empty, detection disagrees; `format=` stays an override so this tells you rather than refusing | `errors-and-diagnostics.md:58`, `gotchas.md:99-100` | `diagnostics:286` | Keep table | verified |
| D-18 | `ENCODING_ARGUMENT_UNUSED` — you passed `encoding=` to a backend that decodes names another way (7z stores UTF-16, RAR decodes in its own parser, directory and single-file names come from the filesystem) | `errors-and-diagnostics.md:60` | `diagnostics:253` | Keep table | verified |
| D-19 | **`detect_format()` does refuse zero-filled bytes**, because a tar's `ustar` magic lives inside a member header — so an empty tar reaches the TAR reader only by extension or explicit `format=` | `gotchas.md:100-103` | `format-detection:147`, `format-detection:117` | `Trim to ~3 + link` | verified |
| D-20 | Empty tars are common in practice: **Docker/OCI images carry a 1024-byte one as the empty layer** behind every metadata-only instruction | `gotchas.md:94-97` | — (external fact; no spec line — verify against the OCI image spec) | `Trim to ~3 + link` — the one clause `scope.md` rules kept | verified |
| D-21 | `tar`'s `-b` blocking factor makes every block-aligned zero length legitimate (`tar -b 64` writes a 32 768-byte empty archive) | `gotchas.md:93-95` | `format-tar:125` | `Trim` — the derivation leaves; recorded so it is a decision | verified |
| D-22 | **Per-member extraction outcomes are not diagnostics**: `ExtractionReport.results` is the **sole** record of what happened to each member — blocked, failed, collided, renamed, rewritten | `errors-and-diagnostics.md:63-69` | `diagnostics:153` (admission), `safe-extraction:595` | `Trim to ~6` | verified |
| D-23 | Practically: **read `results`, not `report.diagnostics`** | `errors-and-diagnostics.md:71-72` | `diagnostics:153`, `safe-extraction:755` | `Trim to ~6` — the actionable sentence | verified |
| D-24 | The summary still carries what was observed **while reading** during extraction (invalid timestamps, unresolvable symlinks, unverifiable digests, stream rewinds) — the events with no per-member result to live on | `errors-and-diagnostics.md:72-74` | `diagnostics:115`, `src/archivey/diagnostics.py:74-78` | `Trim to ~6` | verified |
| D-25 | Escalation is not lost: **`abort_on` is the named opt-in** for being stopped by a blocked member, a collision, or a name rewrite | `errors-and-diagnostics.md:76-78`, `extracting.md:113-122` | `safe-extraction:951` | Keep | verified |
| D-26 | `[code]` the `DiagnosticPolicy.strict()` block runs, and its `import` resolves `ArchiveyConfig, DiagnosticPolicy, ARCHIVE_INTEGRITY_CODES` | `errors-and-diagnostics.md:85-89` | `src/archivey/diagnostics.py:335`, `:470` | Keep, tighten | verified |
| D-27 | **`DiagnosticPolicy.strict()` raises on `ARCHIVE_INTEGRITY_CODES`** — the codes reporting the archive's own bytes or metadata as anomalous — and collects the rest | `errors-and-diagnostics.md:91-92` | `diagnostics:333`, `src/archivey/diagnostics.py:486-500` | Keep, tighten | verified |
| D-28 | **`DiagnosticPolicy.pedantic()` raises on everything** | `errors-and-diagnostics.md:93` | `diagnostics:333` | Keep, tighten | verified |
| D-29 | **Exactly five codes are outside the strict set**, and they are `EMPTY_ARCHIVE`, `PASSWORD_ARGUMENT_UNUSED`, `ENCODING_ARGUMENT_UNUSED`, `EXPLICIT_FORMAT_LISTED_EMPTY`, `STREAM_REWIND_REDECOMPRESSES` | `errors-and-diagnostics.md:95-100` | `src/archivey/diagnostics.py:335-360`, `diagnostics:333` | Keep, tighten | verified |
| D-30 | `ARCHIVE_INTEGRITY_CODES` **is exported**, so a caller can build their own policy from it | `errors-and-diagnostics.md:100-101` | `src/archivey/diagnostics.py:586` (`__all__`) | Keep, tighten | verified |
| D-31 | **New codes may appear in minor releases**, so `default=RAISE` is not version-stable; `strict()` is versioned alongside the taxonomy and is the recommended strict mode; **removing** a code stays a breaking change | `errors-and-diagnostics.md:103-106` | `diagnostics:333` | Keep | verified |
| D-32 | `members()` / `scan_members()` assert a **complete** listing and raise on terminal archive damage | `errors-and-diagnostics.md:116-117`, `opening-and-listing.md:155-156` | `documentation:103`, `archive-reading:199`, `error-handling:184` | Keep — canonical home | verified |
| D-33 | `[code]` the `members_report()` recipe runs, and `report.error` is the documented attribute | `errors-and-diagnostics.md:120-127` | `archive-reading:199`, `src/archivey/diagnostics.py:542` | Keep — canonical home | verified |
| D-34 | `__iter__` / `stream_members()` **yield the prefix then raise** on the same failures | `errors-and-diagnostics.md:129`, `opening-and-listing.md:158-159` | `error-handling:184`, `archive-reading:199` | Keep — canonical home | verified |
| D-35 | **Diagnostics alone are not the primary signal** for damage | `errors-and-diagnostics.md:129-130` | `error-handling:184` | Keep | verified |
| D-36 | **This is not salvage** (no resync past damage); `--salvage` remains reserved | `errors-and-diagnostics.md:130-131`, `cli.md:48`, `migrating.md:173-174` | `cli:247` | Keep | verified |
| D-37 | **Random-access extract fail-closes before writing** when listing ends in terminal damage | `errors-and-diagnostics.md:131-132` | `error-handling:184`, `safe-extraction:21` | Keep | verified |
| D-38 | **Errors always come from `read()`, never from `close()`** — a `finally` block cannot mask one | `errors-and-diagnostics.md:139-140` | `compressed-streams:155` | Keep | verified |
| D-39 | **"To its end" means** `read(-1)`, reading until `read()` returns `b""`, or — for a member with a declared size — reading that many bytes | `errors-and-diagnostics.md:142-143` | `compressed-streams:254`, `archive-reading:435` | Keep | verified |
| D-40 | **We try to raise on every error we can detect — not on every error.** Some formats store no checksum, and some damage decodes into something valid-looking | `errors-and-diagnostics.md:146-148`, `gotchas.md:56-57` | `compressed-streams:254` | Keep | verified |
| D-41 | **`CorruptionError` vs `TruncatedError` is a best-effort guess, not a diagnosis** — do not branch on which one you got; `except archivey.ReadError` catches both | `errors-and-diagnostics.md:149-152` | `src/archivey/exceptions.py:121-131`, `compressed-streams:137` | Keep | verified |
| D-42 | **Bytes delivered before the error are of unknown quality** — not known-good, not known-bad (O-17's worked example, and O-16's safety-claim class) | `errors-and-diagnostics.md:153-156` | `compressed-streams:254` | Keep | verified |
| D-43 | **A full-length return means the checksum matched** | `errors-and-diagnostics.md:157-158` | `compressed-streams:254` | Keep | verified |
| D-44 | **A short return with no exception does not mean "complete"**: `read(member.size)` on a truncated member returns quietly; the *next* read raises | `errors-and-diagnostics.md:159-161`, `errors-and-diagnostics.md:189`, `reading-members.md:106-110` | `compressed-streams:155`, `archive-reading:435` | Keep | verified |
| D-45 | `read(member.size)` **raises on corruption and withholds the chunk that reached the size**, but returns a short buffer on truncation | `errors-and-diagnostics.md:190`, `errors-and-diagnostics.md:195-198`, `reading-members.md:106-109` | `compressed-streams:155` | Keep — D-e's named exception, stays on both pages | verified |
| D-46 | `[code]` the chunked-loop block runs and `archivey.ReadError` is the right except clause | `errors-and-diagnostics.md:167-175`, `reading-members.md:114-122` | — (executable) | `errors` = Keep, canonical home; `reading-members.md:114-126` = `→ page` (byte-identical duplicate) | verified |
| D-47 | A plain `stream.read()` with no argument asks for the whole member, so a damaged one **raises and you get nothing back** | `reading-members.md:124-126` | `compressed-streams:155` | `→ page` | verified |
| D-48 | `VerificationMode.STRICT` **verifies a whole member before returning any of it** | `errors-and-diagnostics.md:177-179` | `compressed-streams:254` | Keep — canonical home | wrong |
| D-49 | The call × failure matrix is correct in all 14 cells, for a member of declared size 500 truncated after 110 | `errors-and-diagnostics.md:183-193` | `compressed-streams:155`, `compressed-streams:254` | Keep | verified |
| D-50 | **Members with no declared size** cannot self-certify from `read(n)` — use `read(-1)` or read until `b""` | `errors-and-diagnostics.md:200-201` | `format-single-file-compressors:87`, `compressed-streams:254` | Keep | verified |
| D-51 | **§B row 5's survivor, unwritten:** known third-party exceptions are translated into the `ArchiveyError` tree; unrecognized ones **propagate raw** rather than being swallowed by a catch-all; `OSError` / `KeyboardInterrupt` / `MemoryError` pass through unchanged except where a spec says otherwise; `ArchiveyUsageError` is deliberately outside the tree | *no page states it* — receives `extracting.md:74-75` | `error-handling:259`, `error-handling:84`, `compressed-streams:137`, `CONTRIBUTING.md:221-230` | **Guide** (inbound to `errors-and-diagnostics.md`); `extracting.md:74-75` is `→ page` | verified |
| D-52 | **§B row 9's survivor, unwritten (`#236`):** `ArchiveyError` / `ArchiveyUsageError` escape archive-derived text **at construction** and `Diagnostic` escapes its `message`, so printing one to a terminal cannot move the cursor or forge output | *no page states it* | `error-handling:273`, `error-handling:311`, `diagnostics:384`, `src/archivey/terminal.py` | **Guide** (inbound, ~3 lines) | verified |
| D-53 | Archive-derived text is **escaped exactly once** — no double-escaping between library and CLI | *no page states it* | `error-handling:311`, `cli:164` | **Guide** (part of D-52's inbound) | verified |
| D-54 | **Archivey is stricter than the stdlib about damage**: where `tarfile` and `gzip` often stop quietly, archivey raises or emits a diagnostic, so ported code may start seeing errors | `gotchas.md:59-61`, `migrating.md:90-91` | `format-tar:125`, `error-handling:184` | Keep | verified |
| D-55 | Prefer `reader.diagnostics` and the extraction report **over logs** — advisories are queryable data | `gotchas.md:105-107`, `errors-and-diagnostics.md:43-45` | `logging:40`, `diagnostics:21` | Keep | verified |

## D — problems and gaps met while extracting

- **D-8 is a completeness claim the page does not know it is making.** The 7-row subtype
  table is the exception tree's only published reference (21 of the 26 types have no
  `api.md` entry), so an omission there is invisible in a way it would not be if `api.md`
  enumerated them. This is exactly the evidence `scope.md` Q3 says would settle §D's
  shape: the inventory is supposed to say *how much of the table is accurate and how many
  types a reader is ever told about*. Counted here: **26 exception classes in
  `src/archivey/exceptions.py`; the table names 12; `api.md` renders 5.**
- **D-51, D-52, D-53 are silence rows.** They are recorded with an empty `Stated at`
  because a worklist that only lists written prose loses them — the trap the brief names
  three times.

---

# E. Formats, codecs, stored digests

Specs: the seven `format-<name>` specs, `archive-data-model`.
Pages: `formats`, `install`, `support-matrix`, `gotchas`, `index`, `migrating`.

Evidence: [`worker-inputs/verdicts-E.md`](worker-inputs/verdicts-E.md); harvest [`../problem-catalogue/harvest/E-formats.md`](../problem-catalogue/harvest/E-formats.md).

| # | Claim | Stated at | Settles it | Ruling | V |
|---|---|---|---|---|---|
| E-1 | The quick matrix is correct row by row: Core?, Extra/tool, Listing, Random member access, Notes — 11 rows | `formats.md:8-20` | the seven `format-*` specs; `packaging-and-extras:50`; the `format_availability()` sweep in Part 1 | Keep | wrong |
| E-2 | ZIP listing is **indexed (central directory)**, access **direct**, and a **seekable source is required** | `formats.md:10`, `formats.md:31-33` | `format-zip:20`, `format-zip:118` | Keep | verified |
| E-3 | ZIP **listing** uses stdlib `zipfile`; member **data** decodes through archivey's shared codec layer | `formats.md:31-33`, `migrating.md:14` | `format-zip:20`, `format-zip:57` | Keep | verified |
| E-4 | ZIP data needs a seekable source **even with `streaming=True`** | `formats.md:32-33`, `access-and-cost.md:145-146` | `format-zip:118` | Keep | verified |
| E-5 | With `[recommended]`, ZIP gains **Deflate64 and PPMd** (`inflate64` / `pyppmd` — the same packages the 7z reader uses) and **Zstd** (`backports.zstd`, or stdlib on 3.14+) | `formats.md:34-37` | `format-zip:57`, `packaging-and-extras:50` | Keep · `cfg` | verified · cfg `[all]` |
| E-6 | **Multi-volume / split ZIP (`.z01`…`.zip`) is detected and rejected with `UnsupportedFeatureError`** | `formats.md:38-39`, `opening-and-listing.md:89` | `format-zip:169` | Keep | verified |
| E-7 | Unsupported ZIP compression methods: **listing succeeds; reading raises `UnsupportedFeatureError`** | `formats.md:40-41` | `format-zip:57` | Keep | verified |
| E-8 | ZIP timestamps: DOS base, with **NTFS / Extended Timestamp extras overriding when present** | `formats.md:42` | `format-zip:135` | Keep | verified |
| E-9 | Names flagged UTF-8 decode as UTF-8; for an **unflagged** name archivey prefers UTF-8 when the bytes are valid UTF-8, else falls back to `ArchiveyConfig.zip_unflagged_fallback_encoding` (**default `cp437`**) | `formats.md:43-47` | `format-zip:245`, `src/archivey/config.py:140` | Keep | verified |
| E-10 | When UTF-8 is inferred for an unflagged name, a **`member_name_encoding_inferred`** diagnostic records it | `formats.md:47-48` | `src/archivey/diagnostics.py:62`, `format-zip:245` | Keep | verified |
| E-11 | Passing `encoding=` to `open_archive` **is authoritative** — used verbatim, disables the sniff | `formats.md:48-49` | `format-zip:245`, `diagnostics:253` | Keep | verified |
| E-12 | **A wrongly-set UTF-8 bit-11 makes the whole archive unlistable**: stdlib `zipfile` raises while parsing the central directory, so the failure is archive-wide rather than confined to one name | `formats.md:50-54` | `format-zip:245`, `format-zip:20` | **Keep, 2 lines** (the roadmap clause at `53-54` is `Cut`) | verified |
| E-13 | **ZipCrypto multi-password confirmation is expensive on STORED members** | `formats.md:55-56`, `access-and-cost.md:155-158` | `format-zip:188` | Keep | verified |
| E-14 | **WinZip AES** (method 99 / AE-1, AE-2) decrypts via `[recommended]` (PBKDF2 + AES-CTR + HMAC-SHA1); **AE-2 members expose no `crc32`**; without the extra an AES member raises `PackageNotInstalledError` **but is still listed as encrypted** | `formats.md:56-59`, `migrating.md:50-51` | `format-zip:85` | Keep · `cfg` | verified · cfg `[all]` |
| E-15 | Uncompressed seekable TAR gets **random access via `tarfile`** | `formats.md:63`, `formats.md:11` | `format-tar:20` | Keep | verified |
| E-16 | TAR **hardlinks are first-class at extraction**, and an unfiltered `extract_all` resolves them in one pass | `formats.md:66-67` | `format-tar:78`, `safe-extraction:332` | Keep | verified |
| E-17 | TAR `concurrent_members=True` uses a **per-reader shared-handle lock**, the same shape as ISO | `formats.md:68` | `format-tar:222`, `format-iso:89` | Keep | verified |
| E-18 | **Stdlib `tarfile` treats a corrupt member header after the first as a clean end of archive** — no exception, iteration just stops early | `formats.md:69-72`, `gotchas.md:59-61` | `format-tar:125` | Keep, tighten | verified |
| E-19 | When the shortened scan stops on a **rejected (non-null) header block**, archivey raises `CorruptionError` **by default**; in random-access reads this holds even for the archive's final block | `formats.md:73-76` | `format-tar:125` | Keep, tighten | verified |
| E-20 | A tar that ends **cleanly on a member boundary without the two-block null trailer** is warned about via `ARCHIVE_EOF_MARKER_MISSING`, not raised — the three shapes (trailer-less, `cat`-joined, truncation at a boundary) are byte-identical | `formats.md:77-81`, `gotchas.md:71-74` | `format-tar:125`, `documentation:150`, `src/archivey/diagnostics.py:72` | Keep, tighten | verified |
| E-21 | `ArchiveyConfig(strict_archive_eof=True)` **escalates that warning to `TruncatedError`** | `formats.md:80-81`, `gotchas.md:72-74` | `format-tar:257`, `error-handling:167`, `src/archivey/config.py:140` | Keep, tighten | verified |
| E-22 | `strict_archive_eof=True` additionally requires **every byte after the trailer to be zero**, so trailing junk and concatenated archives raise `CorruptionError` | `formats.md:82-84`, `gotchas.md:75-77` | `format-tar:257` | Keep, tighten (`gotchas.md:75-79` → `Trim to 1 + link`) | verified |
| E-23 | **Zero padding still passes** — `tar` writes 10 KiB records, so "nothing but zeros" is the strongest rule that does not reject what `tar` produces | `formats.md:84-86`, `gotchas.md:77` | `format-tar:257` | Keep / `Trim to 1 + link` | verified |
| E-24 | The strict check **reads to EOF**, costs O(tail length), and on a compressed tar the tail is decompressed to inspect it — which is why the flag is opt-in | `formats.md:86-87`, `gotchas.md:78-79` | `format-tar:257` | Keep / `Trim to 1 + link` | verified |
| E-25 | **Truncation inside a member's data always raises `TruncatedError` during iteration, regardless of the flag** | `formats.md:88-89` | `format-tar:125` | Keep, tighten | verified |
| E-26 | **Streaming caveat:** a corrupt header as the *final* block is caught in random-access reads but **not** in forward-only streaming, where it surfaces as the missing-trailer warning | `formats.md:90-92`, `gotchas.md:72-74` | `format-tar:125` | Keep (the roadmap clause at `92` is `Cut`) | verified |
| E-27 | 7z uses a **native header parse** plus stdlib codecs for LZMA/LZMA2/BCJ/Delta/Deflate/BZip2/stored — **no `py7zr` on the read path** | `formats.md:96-97`, `index.md:54-55`, `migrating.md:128-129`, `migrating.md:153-155`, `acknowledgements.md:35` | `format-7z:46`, `format-7z:115` | Keep | verified |
| E-28 | `[recommended]` adds **PPMd, Deflate64, Zstd, Brotli and AES** to 7z | `formats.md:98`, `migrating.md:129` | `format-7z:115`, `packaging-and-extras:50` | Keep · `cfg` | verified · cfg `[all]` |
| E-29 | **BCJ2 is detected and rejected with `UnsupportedFeatureError` — never garbage output** | `formats.md:15`, `formats.md:99` | `format-7z:162` | Keep | verified |
| E-30 | 7z **solid folders**: `stream_members()` decodes each folder once; a random `open()` of a mid-folder member may re-decode from the folder start | `formats.md:100-101`, `access-and-cost.md:66-67` | `format-7z:243` | Keep | verified |
| E-31 | **AES + store/copy with no folder digest and no member CRC**: 7z has no password check value, a wrong password can yield garbage (matching 7-Zip), and archivey emits `DIGEST_UNVERIFIABLE` with `reason="no_integrity_anchor"` | `formats.md:102-104`, `gotchas.md:62-65` | `format-7z:197`, `src/archivey/diagnostics.py:76`, `:256` | Keep | verified |
| E-32 | **A 7z header decoded with a wrong password that yields zero file records is rejected as `EncryptionError`** — never a silent empty listing | `formats.md:105-106`, `gotchas.md:66-69` | `format-7z:197` | Keep | verified |
| E-33 | The residual: a wrong password that decodes to a **plausible non-empty** header can still parse, so "0 members" is not proof of emptiness without checking diagnostics | `gotchas.md:66-69` | `format-7z:197` | Keep | verified |
| E-34 | `[TM]` `NumCyclesPower` is capped at ≤24 or the `0x3F` no-hash sentinel (7-Zip's own clamp); values 25–62 raise `UnsupportedFeatureError` | `formats.md:107-108` | `format-7z:63`, `format-7z:197` | `→ TM` — verify when the threat-model edit is written | out of scope ([TM]) |
| E-35 | **7z writing is not shipped**; `py7zr` is a dev oracle only | `formats.md:109`, `migrating.md:138-140`, `acknowledgements.md:35` | `format-7z:25`, `archive-writing` (Phase 9, unlanded) | Keep | verified |
| E-36 | RAR **metadata / listing is a native RAR 1.5–RAR5 parser and works without `unrar`** | `formats.md:16`, `formats.md:113`, `index.md:54-55`, `install.md:20-21`, `install.md:27-28`, `migrating.md:130-131`, `acknowledgements.md:36` | `format-rar:46`, `format-rar:127` | Keep | verified |
| E-37 | RAR **member data** needs the RARLAB `unrar` on `PATH` — **not `unrar-free`, `unar`, or `7z`**, and no pip extra can supply it | `formats.md:22-23`, `formats.md:114`, `install.md:20-21`, `install.md:26-28`, `acknowledgements.md:72-73` | `format-rar:127`, `packaging-and-extras:142` | Keep | verified |
| E-38 | RAR passwords are passed as **bare `-p` with the secret on stdin, not in argv** | `formats.md:114-115` | `format-rar:145` | Keep | verified |
| E-39 | `[recommended]` covers **header-encrypted RAR5** | `formats.md:117`, `formats.md:16` | `format-rar:308`, `packaging-and-extras:50` | Keep · `cfg` | verified · cfg `[all]` |
| E-40 | **BLAKE2sp verification needs no package** — implemented natively on stdlib `hashlib` | `formats.md:117-118`, `acknowledgements.md:73-74` | `src/archivey/internal/hashing/blake2sp.py`, `format-rar:230` | Trim | verified |
| E-41 | RAR5 members with the **HASHMAC** flag verify tweaked digests via UnRAR's `ConvertHashToMAC` when a password is available; **tweaked values are not exposed as plain `member.hashes`** | `formats.md:118-119` | `format-rar:230` | **Trim** — the actionable half (not exposed) stays; the UnRAR function name → TM | verified |
| E-42 | RAR **file-version history (`-ver`)**: revision rows appear in `members()` as `path;1` with `extra["rar.file_version"]` and `is_current=False`; the live path stays `is_current=True`; default extract **skips** non-current rows | `formats.md:120-122`, `extracting.md:166-167` | `format-rar:92`, `safe-extraction:254` | Keep | verified |
| E-43 | **Solid RAR**: one `unrar p` pipe for `stream_members()`; random solid opens may use explicit temp materialization | `formats.md:123-124` | `format-rar:168`, `format-rar:191` | Keep | verified |
| E-71 | **Stated by no page.** Reading a RAR member that is not directly readable (compressed, or any member of a solid archive) from a **stream** source copies the **whole archive** to a temp `.rar` in the system temp directory — `_ensure_archive_path`, "materialize streams once". Unbounded in size, absent from `CostReceipt.notes` *and* from `diagnostics`, removed on reader close. A stored member from a stream never triggers it (`_can_direct_read`), so the same call is free or a full disk copy depending on the member's compression | *(nowhere — gap)* | `src/archivey/internal/backends/rar_reader.py:532-555` (`_ensure_archive_path`), `:438-459` (`_materialize_stream_volumes`), `:889-897` (the `_can_direct_read` branch); `format-rar:168`; ADR 0002 | **Guide — new prose.** Which page is `scope.md`'s call: `formats.md` §RAR (beside E-43) or `access-and-cost.md`. Honest-cost half filed as `open-issues.md` **P11** | **`wrong` — silence is a claim.** Repro §Coordinator-verified |
| E-44 | RAR is **read-only — no RAR writer** | `formats.md:16`, `formats.md:125`, `migrating.md:138-139` | `format-rar:25` | Keep | verified |
| E-45 | **ISO needs `[recommended]` (`pycdlib`) and a seekable source** | `formats.md:17`, `formats.md:129`, `access-and-cost.md:145-146` | `format-iso:22`, `packaging-and-extras:50` | Keep · `cfg` | verified · cfg `[all]` |
| E-46 | ISO namespace is **auto-selected Rock Ridge → Joliet → plain ISO 9660** and reported in `ArchiveInfo.extra["iso.namespace"]` | `formats.md:130-131` | `format-iso:47` | Keep | verified |
| E-47 | Raw CD sector images (`.bin`) are **recognised and refused** with `UnsupportedFeatureError` naming the layout, not read | `formats.md:190-192` | `format-iso:108` | Keep | verified (2026-09-23; the earlier "stripped to 2048-byte payloads" wording was never implemented, #315 S22-K6) |
| E-48 | **`import archivey` patches pycdlib process-globally** — a hang-safety guard inside pycdlib's namespace, which other code in the same process sees as a strict superset of correct results on valid trees | `gotchas.md:87-90` | `format-iso:22`, `src/archivey/internal/backends/iso_reader.py` | Keep on `gotchas`; **`formats.md` §ISO must state it** — `scope.md` row 10, currently a link with no landing | verified |
| E-49 | The Directory backend keeps the **same default stream contract as archives** — forward-only, one live stream, until you declare `SEEKABLE`/`CONCURRENT` | `formats.md:138-139`, `formats.md:13` | `format-directory:82` | Keep | verified |
| E-50 | Single-file compressors present **one synthetic member**, named from the source path or `data` for anonymous streams | `formats.md:143`, `opening-and-listing.md:41-43` | `format-single-file-compressors:27` | Keep | verified |
| E-51 | `.gz` may expose `extra["gzip.original_filename"]` when the header carries **`FNAME`** — and it is **not** used as the member name | `formats.md:144` | `format-single-file-compressors:126` | Keep | verified |
| E-52 | `.gz` surfaces the **trailer CRC-32** as `member.hashes["crc32"]` for a **single-member** file on a seekable/path source — omitted for multi-member gzip (the trailer covers only the last member) and for non-seekable sources | `formats.md:145-147`, `formats.md:186` | `format-single-file-compressors:180` | Keep | verified |
| E-53 | **With the `[seekable]` rapidgzip accelerator on a seekable `.gz`, truncation detection is best-effort** (empty→stdlib fallback + single-member ISIZE) — stronger than naked rapidgzip, weaker than stdlib alone; use `use_rapidgzip=OFF` when you need certainty | `formats.md:148-151`, `gotchas.md:80-84` | `seekable-decompressor-streams:69`, `format-single-file-compressors:87` | Keep — O-2's subject, load-bearing · `cfg` | verified · cfg `[all]` |
| E-54 | That caveat applies to **bare** `.gz` / `open_stream` (and bare zlib/raw deflate), **not** to ZIP/7z members, which carry their own CRC/size and fail via `VerifyingStream` | `formats.md:151-153`, `gotchas.md:83-84` | `compressed-streams:254`, `src/archivey/internal/streams/verify.py` | Keep | verified |
| E-55 | `.lz` surfaces a whole-member CRC-32 **whenever the source can be seeked** — a file path and an in-memory stream qualify, a pipe does not | `formats.md:154-156`, `formats.md:187` | `format-single-file-compressors:180` | **Trim to the rule** | verified |
| E-56 | `seekable_members=True` is **not required and makes no difference** here: it is about `seek()` on a *member stream*, while the lzip trailer is a bounded backward peek — same for the `.xz` size read from the stream index | `formats.md:156-158`, `access-and-cost.md:113-115` | `format-single-file-compressors:87`, `seekable-decompressor-streams:52` | Keep | verified |
| E-57 | For **multi-member lzip** the value is derived by combining per-trailer CRCs with each member's uncompressed size, so it equals `crc32` of the concatenated payloads | `formats.md:158-160`, `formats.md:174-175`, `formats.md:187` | `src/archivey/internal/hashing/combine.py`, `format-single-file-compressors:180` | **Trim to the rule** — the derivation → TM or spec | verified |
| E-58 | `.bz2` / `.xz` / zlib / brotli / `.Z` have **no cheap whole-member stored digest** | `formats.md:161`, `formats.md:188` | `format-single-file-compressors:180` | Keep | verified |
| E-59 | zlib's RFC 1950 **Adler-32 is still verified by the decompressor on read** but is not surfaced on `member.hashes` | `formats.md:161-164` | `compressed-streams:254` | **Trim to the fact** — the parenthetical rationale leaves | verified |
| E-60 | `.Z` (unix-compress) is **core (native LZW)** | `formats.md:20`, `formats.md:165` | `format-single-file-compressors:161`, `packaging-and-extras:23` | Keep | verified |
| E-61 | `.Z` truncation is **best-effort**: nonzero leftover bits after the last complete code raise `TruncatedError` on the next `read()` after delivering available bytes; **zero-leftover cuts remain silent** | `formats.md:165-168`, `gotchas.md:85-86` | `format-single-file-compressors:87` | Keep | verified |
| E-62 | `.Z` forward decode works on **non-seekable** sources; **CLEAR boundaries provide seek points** when seekability is declared | `formats.md:20`, `formats.md:167-168` | `seekable-decompressor-streams:280` | Keep | verified |
| E-63 | `archivey.open_stream(...)` matches the archive rule: **non-seekable unless `seekable=True`** | `formats.md:169-170` | `compressed-streams:36` | Keep | verified |
| E-64 | `member.hashes` holds digests the archive **already stores**, keyed by `HashAlgorithm`, values always `bytes` — CRC-32 as four **big-endian** bytes (compare `zlib.crc32(data).to_bytes(4, "big")`; `crc32_digest` went private in PR 896) | `formats.md:173-178` | `archive-data-model:122`, `src/archivey/types.py` | Keep | verified |
| E-65 | They are **readable without decompressing** when the backend documents them, and are **not computed digests** — a full `read()` still verifies through the normal path | `formats.md:178-179`, `philosophy.md:67-68` | `format-single-file-compressors:180`, `documentation:129` | Keep | verified |
| E-66 | The stored-digest matrix is correct in all six rows (ZIP FILE/SYMLINK · 7z FILE · RAR5 crc32/blake2sp · `.gz` single-member-seekable · `.lz` seekable · the none row) | `formats.md:181-188` | `documentation:129`, `format-zip:135`, `format-7z:260`, `format-rar:230`, `format-single-file-compressors:180` | **Keep** — D-f: "the matrix is archivey knowledge and stays" | verified |
| E-67 | `[code]` the `content_key` dedupe recipe runs: `HashAlgorithm.BLAKE2SP` / `HashAlgorithm.CRC32` membership tests against `member.hashes`, `reader.open(member)`, `member.is_file`, `member.is_current` | `formats.md:195-217` | `documentation:129`, `archive-data-model:122` | **Cut to ~8, floor raised** (Q6: this is now the guide's only dedupe example) | verified |
| E-68 | **Stored digests are weaker or format-specific; computed digests are stronger but cost a full decode** — pick by provenance | `formats.md:219-220` | `documentation:129` | Cut to ~8 | verified |
| E-69 | The single-file compressor list on Home is complete and correct: gzip, bzip2, xz, zstd, lz4, lzip, zlib, brotli, Unix compress | `index.md:48-50`, `formats.md:141-170` | `compressed-streams:52`, `compressed-streams:72` | Keep, frozen | verified |
| E-70 | `[code]` the `py7zr` before/after pair runs | `migrating.md:142-151` | — (executable) | Keep | verified |

## E — problems and gaps met while extracting

- **E-48 is `scope.md` row 10 and it is a *link with no landing*** — `gotchas.md:90`
  points at `formats.md#iso-9660` for the pycdlib patch, and that section is silent. The
  claim is recorded once here so the fix and the verification are the same row.
- **E-53 is the highest-stakes row in this cluster.** It is O-2's original subject, it is
  a *negative* safety claim ("do not rely on it"), and it is the one row where
  `use_rapidgzip=OFF` is the reader's action. Anything that softens it is O-16's failure
  mode.
- **E-1 is one row for an 11×6 table** and will be the most expensive single verification
  in the pass. It is deliberately not split: splitting it would let two workers give two
  answers about the same cell, which is the failure this inventory exists to prevent.

---

# F. Cost, accelerators, measurement

Specs: `access-mode-and-cost`, `seekable-decompressor-streams`.
Pages: `access-and-cost`, `gotchas`, `formats`, `philosophy`, `reading-members`.

Evidence: [`worker-inputs/verdicts-F.md`](worker-inputs/verdicts-F.md); harvest [`../problem-catalogue/harvest/F-cost.md`](../problem-catalogue/harvest/F-cost.md).

| # | Claim | Stated at | Settles it | Ruling | V |
|---|---|---|---|---|---|
| F-1 | The wall-time bands are **targets, not CI hard-fails**; the PR gate enforces structural invariants (bytes decompressed, seeks, solid decode-once) instead | `access-and-cost.md:8-9`, `philosophy.md:70-72` | `testing-contract`, `benchmarks/harness` | Keep | verified |
| F-2 | `[code]` the harness command runs as written: `uv run --extra all python -m benchmarks.harness --mode full --scale realistic` | `access-and-cost.md:12-14` | `benchmarks/harness.py` | Keep | verified |
| F-3 | **S-1 (pre-seeded, = [O-4](../archive/2026-10-06-docs/observations.md), already open — do not re-file).** The nightly-run link points at `github.com/davitf/archivey-**2**/actions/runs/29992136861`; the repo was renamed 2026-07-25 and GitHub redirects, so it resolves but is stale | `access-and-cost.md:17-18` | [O-4](../archive/2026-10-06-docs/observations.md) | `Trim to ~6` | verified |
| F-4 | The four aspirational bands are the stated ones (≤1.3× read, ≤~2× extract, ≤2–3× open+list, ≈1.25× 7z/RAR open+list) | `access-and-cost.md:21-26` | `benchmarks/harness.py`, `dev-docs/IDEAS.md` | `Trim to ~6` — the band table is the half that stays | verified |
| F-5 | The measured column, the corpus description, the above-band ZIP-extract admission and the **L5** lazy-derivation follow-up are accurate as of run 29992136861 | `access-and-cost.md:16-33` | `dev-docs/IDEAS.md`, the nightly run | `Trim to ~6` — this is the maintainer-evidence half being removed | verified |
| F-6 | `reader.cost` is a machine-readable receipt whose fields are `listing_cost`, `access_cost`, `stream_capability`, `solid_block_count` | `access-and-cost.md:37-44` | `src/archivey/cost.py:86-108`, `access-mode-and-cost:151` | `→ DS` — a field table is D-f's own example of a lookup; `CostReceipt` has an `api.md` entry | verified |
| F-7 | **Completeness question on F-6:** `CostReceipt` also carries a public `notes: tuple[str, ...]` field (`cost.py:108`) that the four-row table does not mention | `access-and-cost.md:40-44` (omission) | `src/archivey/cost.py:108`, `access-mode-and-cost:151` | `→ DS` — the docstring promotion is where it lands | verified |
| F-8 | `listing_cost` values are `INDEXED` / `REQUIRES_SCANNING` / `REQUIRES_DECOMPRESSION` | `access-and-cost.md:41` | `src/archivey/cost.py:16-36` | `→ DS` | verified |
| F-9 | `access_cost` values are `DIRECT` (member N independent) and `SOLID` (may need earlier bytes) | `access-and-cost.md:42` | `src/archivey/cost.py:37-47` | `→ DS` | verified |
| F-10 | `solid_block_count` is the count of distinct solid blocks, **when known** | `access-and-cost.md:44` | `src/archivey/cost.py:103` | `→ DS` | verified |
| F-11 | **Cost never changes what is legal** — it describes what an access pattern will pay | `access-and-cost.md:46`, `philosophy.md:66-67` | `access-mode-and-cost:151`, `access-mode-and-cost:219` | Keep | verified |
| F-12 | **`listing_cost` and `access_cost` are *not* ordered** — their values name kinds of work, not strengths | `access-and-cost.md:52-53` | `src/archivey/cost.py:16-47` | Keep — the clause prevents a real mistake | verified |
| F-13 | **RAR reports `listing_cost=INDEXED`**: the native parser walks all file headers at open and builds the member table in memory before `members()` is called | `access-and-cost.md:57-59`, `formats.md:16` | `format-rar:230`, `format-rar:46` | Keep, trim — **canonical home is the cost page** (revised after #241) | verified |
| F-14 | **Open-time cost scales with member count; once open, `members()` / `get()` return from the in-memory table at O(1)** | `access-and-cost.md:60-62` | `format-rar:230` | Keep, trim — the surviving half | verified |
| F-15 | The optional **Quick Open** record (a pre-built central directory in some RAR5 archives) is read but is **not the primary source** — every archive header is still traversed | `access-and-cost.md:58-61` | `format-rar:46` | Keep, trim — this half is a parser internal, → `formats.md` §RAR or the spec | verified |
| F-16 | `[code]` the solid-archive "do this" block runs | `access-and-cost.md:71-74` | — (executable) | Keep | wrong |
| F-17 | `[code]` the "avoid this" block runs (and does what the comment says: may restart the solid block each time) | `access-and-cost.md:78-82` | — (executable) | Keep | verified |
| F-18 | **`concurrent_members=True` does not remove solid open-order cost** — it only makes overlapping streams correct | `access-and-cost.md:85-86`, `gotchas.md:22-23` | `reader-concurrency:22`, `access-mode-and-cost:265` | Keep | verified |
| F-19 | With `seekable_members=True`: **XZ / lzip seek via native indexes** | `access-and-cost.md:95` | `seekable-decompressor-streams:52` | Keep, tighten | verified |
| F-20 | With `seekable_members=True`: **gzip / zlib / raw deflate / bzip2 can use `[seekable]` (`rapidgzip`) when installed** | `access-and-cost.md:96`, `formats.md:148`, `acknowledgements.md:53` | `seekable-decompressor-streams:69`, `seekable-decompressor-streams:90` | Keep, tighten · `cfg` | verified · cfg `[all]` |
| F-21 | Otherwise **a backward seek may re-decompress from the start** | `access-and-cost.md:97-98`, `gotchas.md:16-18`, `philosophy.md:33-34` | `seekable-decompressor-streams:182` | Keep, tighten | verified |
| F-22 | **`STREAM_REWIND_REDECOMPRESSES` fires on cost, not on codec name** — when the rewind discards more than about a megabyte of decoded progress. The threshold is named: `REWIND_REDECODE_WARN_BYTES` = 1 MiB. **Verifier's trap:** the guide names a *different* 1 MiB constant, `RAPIDGZIP_AUTO_MIN_COMPRESSED_SIZE` (`access-and-cost.md:119`), so "about a megabyte" has two distinct sources and the page names only the other one | `access-and-cost.md:100-102`, `gotchas.md:17-18` | `src/archivey/config.py:93` (`REWIND_REDECODE_WARN_BYTES`), `seekable-decompressor-streams:182`, `src/archivey/diagnostics.py:78`, `:281` | Keep, tighten | verified |
| F-23 | **A single-block `.xz`** (what `lzma.compress` and un-threaded `xz` produce) has exactly one seek point at the origin, so rewinding it costs the same as a codec with no index — and an engaged rapidgzip can hold an index sparse enough for the same thing; **small rewinds stay quiet on every codec** | `access-and-cost.md:103-107` | `seekable-decompressor-streams:52`, `seekable-decompressor-streams:182` | Keep, tighten — the shortest proof the rule is not a codec whitelist | verified |
| F-24 | Set to `RAISE`, that code **fires on every qualifying seek, not only the first**, while the report still records one entry | `access-and-cost.md:109-111` | `src/archivey/diagnostics.py:78`, `diagnostics:86` | `→ DS` (`DiagnosticCode.STREAM_REWIND_REDECOMPRESSES`) | verified |
| F-25 | **The flag changes what member streams can do and nothing else**: `member.size` and `member.hashes` are the same with and without it, because the xz index and lzip trailer are read from any seekable source | `access-and-cost.md:113-115`, `formats.md:156-158` | `seekable-decompressor-streams:20`, `format-single-file-compressors:87` | Keep + one clause | verified |
| F-26 | Under `use_rapidgzip=AUTO` (the **default**) rapidgzip is selected only when seekability is **declared** *and* the known compressed input is ≥ `RAPIDGZIP_AUTO_MIN_COMPRESSED_SIZE` (**1 MiB**) | `access-and-cost.md:117-120` | `src/archivey/config.py:76`, `:148`, `seekable-decompressor-streams:90` | Keep + one clause | wrong |
| F-27 | Smaller members **stay on stdlib `zlib`/`gzip`** so archives of many tiny entries do not pay per-stream accelerator setup | `access-and-cost.md:119-121` | `src/archivey/config.py:76-95` | Keep + one clause | verified |
| F-28 | `use_rapidgzip=ON` forces the accelerator regardless of size; `OFF` disables it | `access-and-cost.md:121`, `formats.md:150`, `gotchas.md:82` | `src/archivey/config.py:16-25` | Keep + one clause | verified |
| F-29 | **must-explain #16's open half, unwritten:** with the package **absent**, `ON` raises `PackageNotInstalledError` while `AUTO` **falls back silently** | *no page states it* | `src/archivey/config.py:19-31`, `compressed-streams:124` | **Guide, ~2 lines** — `scope.md` §B row 3 (corrected after #241) · `cfg` | verified · cfg `[all]` |
| F-30 | **Declare seek only when you need it** (e.g. parquet-in-zip random reads) | `access-and-cost.md:123`, `philosophy.md:40` | `seekable-decompressor-streams:20` | Keep | verified |
| F-31 | Multiple password candidates can trigger **confirmation reads**; **ZipCrypto STORED** is the expensive niche — a wrong candidate passing the weak open check may force a full-member CRC scan | `access-and-cost.md:155-158`, `formats.md:55-56` | `archive-reading:668`, `format-zip:188` | Keep | verified |
| F-32 | The `[seekable]` path is **`rapidgzip` covering gzip / zlib / raw deflate + bzip2**, is C++, and **does not tolerate its Python source disappearing mid-decode**: upstream that raises through a `terminate()` boundary and aborts the process | `access-and-cost.md:163-165`, `acknowledgements.md:44-45`, `acknowledgements.md:53` | `seekable-decompressor-streams:69`, `seekable-decompressor-streams:115` | `Trim to ~4` | verified |
| F-33 | **Archivey contains that fault**: a caller-owned source is wrapped so it becomes a benign EOF toward the accelerator and is re-raised as an ordinary Python exception — so closing a source under a live stream is a **clean failure, not a crash**. Still don't do it | `access-and-cost.md:167-172`, `gotchas.md:45-48` | `seekable-decompressor-streams:115`, `seekable-decompressor-streams:161` | `Trim to ~4` — the caller rule is the half that stays | verified |
| F-34 | The evidence for F-33 is `tests/test_accelerator_bug3_trap.py`, which asserts the untrapped path aborts while archivey's exits cleanly | `access-and-cost.md:169-170` | `tests/test_accelerator_bug3_trap.py` | `Trim to ~4` — → TM as evidence | verified |
| F-35 | **One residual is genuinely upstream and not contained**: some **path**-source truncations and CRC mismatches can still `std::terminate` during worker finalization after a Python exception | `access-and-cost.md:174-177` | `seekable-decompressor-streams:161`, `dev-docs/known-issues.md` | **Keep** — round-2 finding 2 exists because this was once contradicted across pages; both halves stay stated | verified |
| F-36 | **Turn accelerators off for untrusted input under a hard latency budget** (`AcceleratorMode.OFF`) or enforce your own timeout: crafted input can busy-loop in C++ where a Python timeout cannot cleanly interrupt it | `extracting.md:210-216`, `gotchas.md:49-52` | `seekable-decompressor-streams:115`, `src/archivey/config.py:16` | **Trim** (the harness sentence → TM) | verified |
| F-37 | `[seekable]` accelerators are **a performance path, not part of the defended fuzz surface** | `extracting.md:210-212` | `testing-contract`, `seekable-decompressor-streams:115` | Trim | verified |
| F-38 | The §Checklist table's six situation→API rows are correct | `access-and-cost.md:181-188` | `access-mode-and-cost:120`, `reader-concurrency:22`, `safe-extraction:21` | **Keep as-is** | verified |
| F-39 | **§B row 3's survivor, unwritten:** `enable_measurement()` is **opt-in and open-scoped**, and `reader.io_stats()` returns `None` outside it (must-explain #28) | *no page states it* | `src/archivey/measurement.py`, `src/archivey/internal/measurement.py` | **Guide, ~8 lines** — inbound to `access-and-cost.md`; field meanings stay in `IoStats.__doc__` | verified |
| F-40 | **`ArchiveyConfig`'s field-by-field defaults** are a lookup with no published home; the config-at-a-glance screen dissolves to `ArchiveyConfig.__doc__` (`scope.md` §B row 3) | `access-and-cost.md:179-188` is the actionable half that stays; the enumeration is unwritten | `src/archivey/config.py:140`, `archive-reading:717` | `→ DS` | verified |
| F-41 | Archivey loads **one** accelerator library per process: rapidgzip covers gzip and bzip2, and standalone `indexed_bzip2` is deliberately **not** imported because loading both corrupts the heap on macOS | `acknowledgements.md:43-48`, `acknowledgements.md:54` | `seekable-decompressor-streams:69`, `dev-docs/known-issues.md` | Keep | verified |

## F — problems and gaps met while extracting

- **F-7 is a silent completeness gap in a block that is about to become a docstring.**
  If the four-row table is promoted verbatim to `CostReceipt.__doc__`, the missing
  `notes` field is promoted with it — a `→ DS` ruling inherits whatever the table got
  wrong. Worth checking before the promotion, not after.
- **F-35 is the row to be most careful with.** It is a *negative* containment claim
  sitting four lines after a positive one (F-33), and #223's round-2 finding 2 exists
  because a previous pass kept one and dropped the other. Verify them as a pair.
- **F-3 (S-1) is carried, not re-filed.** It is O-4 in `review/archive/2026-10-06-docs/observations.md`.

---

# G. Packaging and platform

Spec: `packaging-and-extras`.
Pages: `install`, `support-matrix`, `acknowledgements`, `migrating`, `index`, `formats`.

Evidence: [`worker-inputs/verdicts-G.md`](worker-inputs/verdicts-G.md); harvest [`../problem-catalogue/harvest/G-packaging.md`](../problem-catalogue/harvest/G-packaging.md).

| # | Claim | Stated at | Settles it | Ruling | V |
|---|---|---|---|---|---|
| G-1 | **The core installs with no dependencies at all** and reads ZIP, TAR, directories and the stdlib codecs | `install.md:3-4`, `index.md:52-53`, `formats.md:8-14`, `acknowledgements.md:61` | `packaging-and-extras:23` | Keep | verified |
| G-2 | **Exactly four extras exist and there are no per-format ones** — member codecs are shared across containers, so a format name would be the wrong thing to install | `install.md:15-16`, `acknowledgements.md:70-72`, `formats.md:35-36` | `packaging-and-extras:50` | Keep | verified |
| G-3 | `[code]` the four `pip install` lines are the correct four, with the correct one-line descriptions (`archivey`, `[recommended]`, `[seekable]`, `[all]`) | `install.md:8-13` | `packaging-and-extras:50`, `pyproject.toml` | Keep — the page's deliverable | verified |
| G-4 | **`[recommended]` is "every format and codec that installs everywhere"** | `install.md:10`, `formats.md:25-26` | `packaging-and-extras:50` | Keep | verified |
| G-5 | **`[seekable]` is rapidgzip**, giving gz/bz2 random access and speed | `install.md:11`, `acknowledgements.md:66`, `formats.md:25-26` | `packaging-and-extras:50`, `seekable-decompressor-streams:69` | Keep | verified |
| G-6 | `[recommended]` pulls exactly: `pyppmd`, `inflate64`, `brotli`, `lz4`, `pybcj`, `backports.zstd` (before 3.14; 3.14+ uses stdlib `compression.zstd`), `cryptography`, `pycdlib`, `tqdm` | `acknowledgements.md:65`, `formats.md:18` | `packaging-and-extras:50`, `packaging-and-extras:157`, `pyproject.toml` | Keep · `cfg` — see the Part 1 note: this session has zstd working with **neither** package installed under those names | verified · cfg `[all]` |
| G-7 | `[all]` is `[recommended]` + `[seekable]` | `install.md:12`, `acknowledgements.md:68` | `packaging-and-extras:50` | Keep | verified |
| G-8 | On a free-threaded build use **`archivey[free-threaded]`** — the measured subset of extras that leaves the GIL disabled | `install.md:16-18`, `install.md:30-34`, `support-matrix.md:67-68`, `acknowledgements.md:67` | `packaging-and-extras:50`, `packaging-and-extras:197` | `install.md:30-34` = **`→ page` (fold)**, near-verbatim repeat of `15-18` | verified |
| G-9 | **`archivey[free-threaded]` is exactly** `pycdlib`, `lz4`, `tqdm`, `backports.zstd`, and `cryptography` on 3.14+ only | `acknowledgements.md:67`, `support-matrix.md:70-78` | `packaging-and-extras:50`, `pyproject.toml` | Keep | wrong |
| G-10 | **`archivey` requires Python 3.11+** and is pure Python with no compiled extensions of its own | `support-matrix.md:9-10`, `acknowledgements.md:76-82` | `packaging-and-extras:197`, `pyproject.toml` | Keep | verified |
| G-11 | The CI matrix is exactly the six listed legs (Linux 3.11–3.14 all extras; Linux 3.11+3.14 core; Linux 3.11 all-lowest; Linux 3.13t; macOS 3.11+3.14; Windows 3.11+3.14) | `support-matrix.md:12-20` | `.github/workflows/ci.yml`, `packaging-and-extras:197` | Keep | verified |
| G-12 | **The minimum-versions leg tests the floor of each declared range**, because optional libraries change behaviour by version as well as presence | `support-matrix.md:21-24` | `.github/workflows/ci.yml`, `CONTRIBUTING.md` §"Before pushing…" | Keep | verified |
| G-13 | **Other platforms (BSDs, other CPython builds) are expected to work and are not tested** — an explicit non-claim | `support-matrix.md:25-27` | `packaging-and-extras:197` | Keep | verified |
| G-14 | **Non-CPython interpreters are not tested**; the core is pure Python but the accelerators and codec backends are C/C++ | `support-matrix.md:29-33` | `packaging-and-extras:197` | Keep | verified |
| G-15 | **An undeclared C extension makes CPython silently re-enable the GIL** on a free-threaded build | `support-matrix.md:62-64` | `packaging-and-extras:197` | Keep — the fact the whole section exists for | verified |
| G-16 | The free-threading package table is correct in all seven rows (pycdlib / backports.zstd / lz4 / tqdm yes; `cryptography` 3.14+ only; `rapidgzip` no; `pyppmd`+`inflate64`+`brotli` no) | `support-matrix.md:70-78` | `packaging-and-extras:50`, `.github/workflows/ci.yml` | Keep — the actionable core | verified |
| G-17 | **`pip install archivey[recommended]` fails on free-threaded 3.13** because `cryptography`'s `cffi` dependency rejects it outright; it installs on 3.14t | `support-matrix.md:76`, `support-matrix.md:86-88` | `packaging-and-extras:50` | Keep | verified |
| G-18 | **`[free-threaded]` is a moving set**, not a guarantee about archivey's own code, and may eventually stop being a separate extra | `support-matrix.md:89-91` | `packaging-and-extras:50` | Keep | verified |
| G-19 | **The CI job asserts the GIL is still disabled after installing `[free-threaded]`**, so a package regression fails the job rather than quietly testing a GIL-ed interpreter | `support-matrix.md:93-96` | `.github/workflows/ci.yml` | Keep | verified |
| G-20 | The free-threading claim is verified by a **required CI job on Linux CPython 3.13t running the whole test suite** in two stages (zero-dep core, then core + GIL-safe extras) | `support-matrix.md:56-58` | `.github/workflows/ci.yml` | Keep | verified |
| G-21 | Four explicit **non-claims**: macOS/Windows free-threaded builds, the "No"-row packages, everything except member streams, and parallel **speedup** | `support-matrix.md:98-108` | `reader-concurrency:22`, `.github/workflows/ci.yml` | Keep — what an explicit non-coverage list looks like when done well | verified |
| G-22 | **`archivey`'s console entry point ships with the base package** | `cli.md:3`, `install.md:8-9` | `packaging-and-extras:262` | Keep | verified |
| G-23 | **Progress bars need `tqdm`, which comes with `[recommended]`; without it the command still runs** | `cli.md:3-4`, `acknowledgements.md:65` | `packaging-and-extras:50`, `cli:16` | Keep · `cfg` | verified · cfg `[all]` |
| G-24 | **§B row 2's second half, unwritten:** a four-row **extra → formats re-index** (core / `[recommended]` / `[seekable]` / `[free-threaded]`), naming which formats each unlocks, with `formats.md` still authoritative | `install.md:23-28` is the section that receives it | `packaging-and-extras:50` | **Guide, ~12 lines** — restored by maintainer decision (`scope.md` Q4), bounded to a re-index | verified |
| G-25 | **§B row 2's first half, unwritten:** `format_availability()` as a runtime query — FULL / PARTIAL / NONE and what `missing` gives you (must-explain #15) | `install.md:23-28` receives it | `src/archivey/internal/registry.py:58-90`, `:314` | **Guide, ~10 lines** | verified |
| G-25a | **When G-25 is written, the query takes an `ArchiveFormat` and nothing else.** A `StreamFormat` (or any other type) raises `ArchiveyUsageError` rather than returning a record — as does a wrong-typed `format=` on `open_archive` / `extract` / `open_stream`. Shipped after this baseline was taken (P10, `2026-08-17-reject-wrong-typed-format-arguments`), so the section must not be written from the old behaviour | `install.md:23-28` receives it | `src/archivey/internal/format_args.py`; `backend-registry` §"Format support is tri-state and compositional" and §"A format argument outside its declared type is a usage error" (named rather than numbered — this PR's own inserts move the line) | **Guide** — one sentence inside G-25's ~10 lines | verified |
| G-26 | The stdlib modules archivey always uses are `zipfile`, `tarfile`, `gzip`, `bz2`, `lzma`, `zlib`, and on 3.14+ `compression.zstd` | `acknowledgements.md:76-82` | `packaging-and-extras:23`, `compressed-streams:72` | Keep | verified |
| G-27 | The **dev/test dependency table** is accurate: the PEP 735 `dev` / `docs` / `fuzz` groups, and each listed package's stated use | `acknowledgements.md:84-98` | `pyproject.toml`, `packaging-and-extras:181` | Keep | verified |

## G — problems and gaps met while extracting

- **G-6 is the one row where the baseline already disagrees with the page.** Python 3.11
  in this session reports `ZST` as `FULL` with an empty `missing`, while neither
  `zstandard` nor a package importable as `backports.zstd` shows in
  `importlib.metadata`. Either the page's "`[recommended]` → `backports.zstd`" row names
  the wrong thing, or the probe used in Part 1 is looking under the wrong distribution
  name. **Not resolved here** — it is a claim row, and it is exactly the kind of
  spec/design discrepancy the brief says to pause on rather than settle silently.
- `install.md` is 34 lines and carries **two unwritten §B rows** (G-24, G-25) that
  roughly double it. It is also the page most exposed to `[core-only]`: every line of it
  is a dependency claim.

---

# H. Command line

Spec: `cli`. Page: `cli` (48 lines — the thinnest page against the largest recent change
to CLI output).

Evidence: [`worker-inputs/verdicts-H.md`](worker-inputs/verdicts-H.md); harvest [`../problem-catalogue/harvest/H-cli.md`](../problem-catalogue/harvest/H-cli.md).

| # | Claim | Stated at | Settles it | Ruling | V |
|---|---|---|---|---|---|
| H-1 | The six verb forms in the block are correct: bare path = `list`, `l`, `t`, `x`, `info`/`detect`, `--version -v` | `cli.md:6-13` | `cli:16`, `cli:213`, `cli:233`, `src/archivey/cli/main.py:229-330` | Keep | verified |
| H-2 | `archivey t` is a **full-read integrity check** | `cli.md:9` | `cli:16`, `src/archivey/cli/test_cmd.py` | Keep | verified |
| H-3 | `archivey info` reports format / identity **and access cost** | `cli.md:11` | `cli:213` | Keep | verified |
| H-4 | `archivey --version -v` prints version **plus the format availability matrix for this install** | `cli.md:12` | `cli:233` | Keep · `cfg` | verified · cfg `[all]` |
| H-5 | **CLI extract defaults are `policy=strict`, `overwrite=rename`, `on_error=continue`** | `cli.md:18` | `src/archivey/cli/main.py:267-292`, `cli:16` | Keep, restructure | verified |
| H-6 | **must-explain #23, unwritten as its own block:** those CLI defaults **diverge from the library**, which defaults to `ERROR` / `STOP` — "it is what breaks scripts ported from one to the other" | `cli.md:18-22` states the CLI half **inside a bash comment**; the divergence is never stated as such | `src/archivey/cli/main.py:267-292` vs `src/archivey/internal/extraction_types.py:75`, `:94` | **Guide, ~6 lines** — `scope.md` §B row 7 | verified |
| H-7 | **With no `-d`, a multi-entry archive lands in `./<stem>/` rather than the current directory** (tarbomb-safe) | `cli.md:18-20` | `cli:16`, `src/archivey/cli/extract_cmd.py:96-142` | Keep, restructure | verified |
| H-8 | **Hostile/corrupt members are reported and skipped; remaining members are still extracted** | `cli.md:20-21` | `cli:16`, `safe-extraction:712` | Keep, restructure | verified |
| H-9 | `-d .` is the opt-in for classic unzip-into-cwd | `cli.md:25-26` | `cli:16` | Keep | verified |
| H-10 | `--stop-on-error` is all-or-nothing on member **failures** (library `STOP`); **policy blocks are still reported and skipped** | `cli.md:28-30` | `cli:277`, `safe-extraction:712` | Keep | verified |
| H-11 | **Filters:** positionals are includes, `--exclude` subtracts; unmatched includes warn on stderr; **extract/test exit 1 when nothing matched** while list warns but stays 0; a sole unmatched pattern that looks like a destination gets a `-d` hint | `cli.md:32-35` | `cli:16`, `cli:277`, `src/archivey/cli/filters.py` | Keep | verified |
| H-12 | `[code]` all six bash invocations in the demo run and behave as their comments say | `cli.md:17-37` | — (executable) | Keep, restructure | verified |
| H-13 | **Verbs are bare words**; dash-prefixed forms like `-x` are not mode selectors, and a file whose name is a verb word is reached with an explicit verb (`archivey list ./x`) | `cli.md:41-43` | `cli:261`, `src/archivey/cli/main.py:229-330` | Keep | verified |
| H-14 | **Exit codes:** `0` success · `1` operation failed or extract aborted on a member failure · `2` usage (argparse) · `3` extract **completed** with ≥1 policy block and no member failure, under CONTINUE or STOP · **`≥4` reserved** | `cli.md:44-47` | `cli:277`, `src/archivey/cli/exit_codes.py:5-11` | Keep — exit `3` is the one an automation author must handle | verified |
| H-15 | `--salvage`, stdin (`-`), and `hash` / `create` / `convert` are **reserved for later** | `cli.md:48`, `errors-and-diagnostics.md:130-131`, `migrating.md:173-174` | `cli:247`, `cli:261`, `cli:308` | Keep | verified |
| H-16 | **Unwritten, `scope.md` §10 item:** **passwords on argv are visible to `ps`** | *no page states it* | `src/archivey/cli/password.py`, `format-rar:145` | **Guide, ~2 lines** | verified |
| H-17 | **Unwritten, `scope.md` §10 item (`#236`):** the CLI prints archive-derived names and messages, and escaping happens at message construction, so its output is terminal-safe | *no page states it* | `cli:164`, `error-handling:311`, `src/archivey/terminal.py` | **Guide, ~1 line + link** | verified |

## H — problems and gaps met while extracting

- **H-6 is the sharpest instance of "silence is a claim".** The CLI's three divergent
  defaults *are* stated — inside a bash comment, at `cli.md:18` — but the fact that they
  diverge is not, and that is what breaks a ported script. The claim row therefore has
  both a `Stated at` (the comment) and an unwritten half.
- The whole page predates `#236`. **Three of its 17 rows (H-4, H-16, H-17) touch output
  the escaping change moved**, and none of them is stated today.

---

# I. Coordinator-owned — documentation shape, positioning, attribution

Spec: `documentation` (the coordinator's own — `brief.md` §Capability clusters).
Pages: `api`, `index`, `philosophy`, `acknowledgements`.

Evidence: [`worker-inputs/verdicts-I.md`](worker-inputs/verdicts-I.md); harvest [`../problem-catalogue/harvest/I-docs-shape.md`](../problem-catalogue/harvest/I-docs-shape.md).

| # | Claim | Stated at | Settles it | Ruling | V |
|---|---|---|---|---|---|
| I-1 | **"Everything documented here is re-exported from the top-level `archivey` package and listed in `archivey.__all__`"** — true as written, but it reads as a completeness claim it does not make: `api.md` carries **56 of 87** names | `api.md:3-5` | `src/archivey/__init__.py` (`__all__`), `documentation:18` | **Keep, reword — §D.** The sentence is `QUESTIONS.md`'s, not a routing call | verified |
| I-2 | `api.md`'s twelve sections and 56 `::: archivey.X` entries all resolve to real public names | `api.md:7-91` | `src/archivey/__init__.py`, `documentation:18` | Keep | verified |
| I-3 | **31 `__all__` names have no `api.md` entry**, 21 of them the exception tree; the named absentees are `ARCHIVE_INTEGRITY_CODES`, `DEFAULT_ARCHIVEY_CONFIG`, `DetectionConfidence`, `DiagnosticContext`, `ExtractionProgress`, `FormatAvailability`, `FormatInfo`, `FormatSupport`, `MissingComponent`, `__version__` | `api.md` (omission); `brief.md` §D counts it | `src/archivey/__init__.py`, `documentation:18` | Keep — **§D's input**, and `scope.md` Q3 gives it a deadline: before `errors-and-diagnostics.md` is written | verified |
| I-4 | **Enum members and dataclass fields render from their docstrings** — the mechanism every `→ DS` ruling depends on, and the reason a `#` comment reaches no reader | `api.md` (implicit); `scope.md` §Precondition states it | `documentation:32`, `scripts/docs/griffe_extensions.py:125` | Keep — verified by pass 0, recorded so it is not re-derived | verified |
| I-5 | The Diagnostics prose note ("formerly log-only warnings"; see the `diagnostics` capability spec for lifecycle, retention, and policy) is accurate | `api.md:40-41` | `diagnostics:115`, `diagnostics:153` | Keep — the one narrative sentence, and it earns its place | verified |
| I-6 | **One interface for every format**, and the nine-format list on Home is complete | `index.md:3-4`, `index.md:48-50`, `philosophy.md:14-15` | `archive-reading:20`, `archive-data-model:21` | Keep, frozen | verified |
| I-7 | **Automatic format detection from content, not just the extension** | `index.md:51`, `philosophy.md:66` | `format-detection:68` | Keep, frozen | verified |
| I-8 | **Streaming-friendly** — read straight from a pipe in a single forward pass, with explicit, predictable access costs for solid archives and seeking | `index.md:58-59` | `access-mode-and-cost:50`, `access-mode-and-cost:151` | Keep, frozen | verified |
| I-9 | **Consistent handling of symlinks, timestamps, permissions, passwords, and a single exception hierarchy** | `index.md:60-61` | `archive-data-model:122`, `error-handling:20` | Keep, frozen | verified |
| I-10 | The §User guide list mirrors the nav in the right order, and becomes 15 entries when `how-it-works.md` lands | `index.md:63-78` | `mkdocs.yml` nav, `documentation:78`, `scripts/checks/check_docs_nav.py` | Keep — `check_docs_nav.py` is the guardrail | verified |
| I-11 | **The site is the user guide and nothing else**; contributor material lives in the repository, and the four named links (`CONTRIBUTING.md`, `openspec/specs/`, `dev-docs/`, `VISION.md`) resolve | `index.md:80-93`, `formats.md:4`, `api.md:5` | `documentation:78`, `documentation:183` | Keep — D1/D3 shape | verified |
| I-12 | **`openspec/specs/` is the authoritative behaviour contract** (asserted on three pages) | `index.md:87-88`, `formats.md:4`, `api.md:5` | `documentation:78`, `openspec/project.md` | Keep | verified |
| I-13 | The one-sentence positioning — "the default Python library for archives … the way `requests` became the default for HTTP" | `philosophy.md:9-10` | `VISION.md` | Keep — Topic 7 owns whether it persuades; this row is only whether it is *true of the library today* | verified |
| I-14 | The escape-hatch table's five rows are correct and complete as *the* explicit hatches | `philosophy.md:49-55` | `access-mode-and-cost:19`, `archive-reading:93`, `reader-concurrency:22`, `safe-extraction:367`, `src/archivey/config.py:140` | Keep — not `→ DS`: it is the page's argument in table form | verified |
| I-15 | **Content-first**: reading, streaming and metadata are the primary surface; extraction is first-class but second in priority | `philosophy.md:58-60` | `VISION.md` | Keep | verified |
| I-16 | **Writing may land after a "reads everything" 1.0**, and there is **no in-place modify and no async in v1** | `philosophy.md:60-61`, `philosophy.md:76` | `openspec/project.md:83`, `archive-writing` (Phase 9, unlanded) | Keep | verified |
| I-17 | **Not a compatibility shim** for `zipfile`/`tarfile`/`py7zr` APIs — one clean API with a migration guide rather than a drop-in replacement | `philosophy.md:78-79`, `migrating.md:6-8` | `VISION.md` | Keep | verified |
| I-18 | **License texts for adapted kernels live next to the code**, at the two named paths | `acknowledgements.md:8-11` | `src/archivey/internal/streams/codecs/unix_compress_decoder.py`, `src/archivey/internal/backends/rar_parser.py` | Keep — license-bearing, not optional | verified |
| I-19 | The **adapted-source** table is accurate: `uncompresspy` (BSD-3-Clause, LZW kernel vendored, `[unix-compress]` extra removed) and `rarfile` (ISC, RAR3 SHA-1/string-to-key and Unicode filename decompression ported) | `acknowledgements.md:22-28` | the two source files' headers, `packaging-and-extras:157` | Keep | verified |
| I-20 | The **oracles and corpora** table is accurate, including the three env-var names (`ARCHIVEY_PY7ZR_TEST_FILES`, `ARCHIVEY_RARFILE_TEST_FILES`, `ARCHIVEY_LIBARCHIVE_TEST_FILES`) — all three confirmed present as skip reasons in Part 1 | `acknowledgements.md:29-39` | `testing-contract`, the Part 1 skip list | Keep | verified |
| I-21 | The **seekable-stream design references** table is accurate on each project's disposition (evaluated / deferred / used / deliberately not imported) | `acknowledgements.md:41-57` | `dev-docs/library-analysis.md`, `seekable-decompressor-streams:69` | Keep — crediting an evaluated-and-rejected library **is** this page's job | verified |
| I-22 | **`how-it-works.md` does not exist**, so nav is 15 where `outline.md` says 16 | measured, not stated | `mkdocs.yml`, `documentation:78`, `scripts/checks/check_docs_nav.py` | **Guide, ~110** — Definition-of-done row 3; needs a `documentation` spec delta (`documentation:78-93`) | verified |
| I-23 | `[code]` the §Simple API block runs — one opener, one reader shape, one member model | `philosophy.md:16-20` | — (executable) | Keep | verified |
| I-24 | Two published pages point a reader at **`IDEAS.md`** as a bare filename. The file is at **`dev-docs/IDEAS.md`**, and `dev-docs/` is deliberately outside the site (D1/D3), so the reference resolves to nothing for a reader on the site | `access-and-cost.md:33`, `acknowledgements.md:55` | `dev-docs/IDEAS.md` exists; `docs/index.md:89-91` is how the guide links `dev-docs/` elsewhere (full GitHub URL) | `Trim to ~6` / Keep — both blocks survive, so the reference has to resolve | verified |

## I — problems and gaps met while extracting

- **I-3 is the row that unblocks `scope.md` Q3.** The brief asks what would settle §D's
  shape; the counted answer is now here and in D-8: the exception tree has **26 classes**,
  `errors-and-diagnostics.md`'s table names **12**, and `api.md` renders **5**. A tree
  that is mostly unreferenced argues for generate-the-list plus a guardrail. That is a
  finding for `QUESTIONS.md`, not a decision this pass takes.
- **I-4 is recorded even though pass 0 already proved it**, because it is a precondition
  six `→ DS` rulings rest on and a fresh container has no memory. Marking it verified
  costs one line and saves the re-derivation.

---

# Where the suspect claims concentrate — the step-4 read

Ranked by expected defect density, not by row count. This is the input to the fan-out
decision, and it is a *prediction*, not a verdict — the whole table is unverified.

1. **`cli.md` — thinnest page, largest recent change.** 48 lines, 17 rows, and **three of
   them (H-4, H-16, H-17) sit directly on top of `#236`**, which moved escaping to message
   construction and removed the CLI's own `logging.Formatter`. H-6 is a must-explain the
   page states only inside a bash comment. The brief flagged this page and the inventory
   agrees: the highest ratio of "changed underneath it" to "lines that could have caught
   it" on the site.

2. **`extracting.md` §What is enforced — seven rows routed to the threat model, all
   unverified.** C-5, C-6, C-8, C-9, C-11, C-26, C-27 (plus E-34 from `formats.md`) are
   `[TM]`. They are *out of scope to verify here* by the brief's own rule, which means
   the threat model is about to receive eight assertions nobody has checked. That is the
   single largest block of deliberately-unverified claims in the file, and recording them
   as rows leaves this pass in a defined state rather than a silent one.

3. **The `#235` sweep — `migrating.md` is the page nobody synced.** `#235` removed four
   diagnostic codes, added `ExtractionStatus.OVERWRITTEN` / `presented_name` /
   `collided_with` / `failure_group_*`, and introduced `abort_on`. `extracting.md` and
   `errors-and-diagnostics.md` were updated *in that PR*. `migrating.md:48` names
   `ExtractionStatus` members and `migrating.md:112` describes the report shape, and it was
   **not** in that PR's diff. C-70 and C-71 are the rows.

4. **Two live cross-page contradictions, neither in `scope.md` §Findings.**
   **A-16**: `opening-and-listing.md:66-68` says ZIP, 7z, RAR *and ISO* must seek;
   `access-and-cost.md:145-146` says only ZIP and ISO. **A-33**: a missing codec backend
   raises `UnsupportedFormatError` on one page and `PackageNotInstalledError` on another.
   Both are the O-2 shape — a fact checked against its neighbour rather than the spec —
   and both are cheap to settle.

5. **`formats.md`'s ISO section — a link with no landing.** E-48: `gotchas.md:90` sends
   the reader to `formats.md#iso-9660` for the process-global pycdlib patch and the
   section says nothing about it. Round-2 finding 3's exact shape, and `scope.md` row 10.

6. **Two dangling references, both cheap.** **F-3 (= O-4)** is the stale `archivey-2`
   nightly link, already open and carried in from `scope.md` §Findings. **I-24** is new
   from this pass: `access-and-cost.md:33` and `acknowledgements.md:55` cite `IDEAS.md`
   as a bare filename, but the file is `dev-docs/IDEAS.md` and `dev-docs/` is
   deliberately outside the site (D1/D3) — so for a reader on the site the reference
   resolves to nothing. `check_docs_nav.py` does not catch it because it is prose, not a
   link.

7. **Completeness claims that no one is counting.** D-8 (the exception table names 12 of
   26 types), F-7 (the `CostReceipt` table omits `notes`), I-3 (31 of 87 `__all__` names
   have no reference entry). None of the three is *false*; all three read as complete and
   are not. F-7 is the urgent one, because a `→ DS` promotion would carry the omission
   into the docstring.

8. **Ten claims are unwritten** — C-66, D-51, D-52, D-53, F-29, F-39, G-24, G-25, H-16,
   H-17. Each is a row whose `Stated at` names no page (or names only the section that
   will *receive* it) rather than a line in a worklist, so a later re-tally cannot lose
   them. Together they are `scope.md`'s re-derived §B worklist made checkable, and they
   are the reason "unverifiable" and "unwritten" stay distinguishable in this file.

**Where the errors are *not* expected**: `philosophy.md` and `acknowledgements.md` (11 and
12 rows, both net-zero in `scope.md`, both making claims about the project rather than
about behaviour that changed) and `support-matrix.md`'s free-threading table, which is
the only section on the site whose every row cites a CI job by name.

---

# Coordinator-verified out of band — three rows

**These three carry verdicts where every other row is empty.** The maintainer asked two
direct questions after the checkpoint — whether 7z/RAR really need seek, and whether RAR
extraction works from a stream given `unrar` needs a file — so they were run rather than
left for a worker. Repros below; a worker should **not** redo them.

### A-16 — all four formats need seek; `access-and-cost.md` is wrong

```python
class Pipe(io.RawIOBase):          # non-seekable wrapper
    def seekable(self): return False
    ...
for fmt in (zip, 7z, rar, tar):
    open_archive(Pipe(data), streaming=False) ; open_archive(Pipe(data), streaming=True)
```

| Format | `streaming=False` from a pipe | `streaming=True` from a pipe |
|---|---|---|
| ZIP | `StreamNotSeekableError` | `StreamNotSeekableError` |
| 7z | `StreamNotSeekableError` | `StreamNotSeekableError` |
| RAR | `StreamNotSeekableError` | `StreamNotSeekableError` |
| TAR | `StreamNotSeekableError` | **OK** |

`format_availability().required_source` is `SEEKABLE` for ZIP, 7z, RAR and ISO alike. So
this was never a behavioural split: `opening-and-listing.md:66-68` is right, and
`access-and-cost.md:145-146`'s "ZIP (stdlib) and ISO" singles out two of four and implies
7z and RAR behave differently. **Fix the sentence on `access-and-cost.md`.** ISO was not
run (no fixture in-tree) but declares `SEEKABLE`; a worker should confirm the row rather
than inherit it.

### E-71 — RAR from a stream works, by copying the whole archive to disk

`unrar` needs a filesystem path, and archivey supplies one: `_ensure_archive_path()` writes
the entire archive to `tempfile.mkstemp(suffix=".rar")` the first time a member cannot be
read directly. Measured on a `rar -m5` archive read from a `BytesIO`:

```
member: big.txt  size: 300000        READ FROM STREAM: 300000 bytes, ok=True
_ensure_archive_path calls: 1        -> /tmp/tmpqee8ey8z.rar   (whole archive)
diagnostics: []                      CostReceipt.notes: ()     (identical to a path source)
temp .rar after close: 0             (cleaned up)
```

So the answer to "do we support extraction for RAR opened via a stream" is **yes, via a
full temp-file spill** — and three things follow:

1. **No page says so.** A caller handing over a 4 GiB `BytesIO` gets a 4 GiB temp file, and
   nothing in the guide, the cost receipt or the diagnostics channel mentions it.
2. **ADR 0010 is not violated, but `access-and-cost.md:142` reads as though it is.** The ADR
   forbids buffering *a non-seekable source* to fake seekability; this is a *seekable* stream
   copied to satisfy an external binary. Different decision, same sentence covers both to a
   reader — hence A-6's reword.
3. **The trigger is per-member, not per-archive.** A stored member from a stream costs
   nothing (`_can_direct_read`); the next member, compressed, costs a full archive copy.
   Same call, same source, two very different costs.

The **honest-cost half** — that a whole-archive disk copy appears in neither
`CostReceipt.notes` nor `diagnostics`, against VISION's "behaviour differences are data,
never silent guesses" — is a library question, filed as `dev-docs/open-issues.md` **P11**.
The **documentation half** is E-71 and belongs to this pass.

# Provenance — merged from two independent passes

Two agents ran steps 2–3 without contact. This file is **#246's**, with #247's two unique
claims folded in and its baseline instruction rejected. Recorded because the repo's own
rule (`brief.md` §How to run this; `docs/independent-brief.md`) is that agreement between
passes with shared priors is weak evidence and **divergence is the informative half**.

**Measured, not asserted.** Every `page:line` citation in both files was expanded into
line sets and compared against the guide:

| | Rows | Guide lines cited | Coverage |
|---|---:|---:|---:|
| #246 (this base) | 400 | 1 540 / 2 108 | **73%** |
| #247 | 190 | 1 406 / 2 108 | **67%** |

So the 2× row gap is **granularity, not coverage**. The 6-point difference is four pages
where #246 went broad (`acknowledgements` 76 vs 24 lines, `migrating` 118 vs 60, `index`
69 vs 34, `philosophy` 39 vs 18) against three where #247 went deeper
(`opening-and-listing` 145 vs 125, `errors-and-diagnostics` 153 vs 137, `access-and-cost`
145 vs 137). On `extracting`, `formats`, `gotchas`, `cli`, `install` and `reading-members`
they are within a few lines of each other.

**Converged** — treat as settled unless a verdict reopens it: the eight capability
clusters as the grouping; one row per claim with N page citations; `Cut` blocks get no
row; `→ TM` rows recorded but unverified; S-1 and S-2 carried without re-derivation;
`how-it-works.md` contributing zero rows is correct rather than an omission.

**Diverged, and what was taken from each:**

| Divergence | Resolution |
|---|---|
| **#247 caught `ExtractionStatus.SUPERSEDED`**; #246 never named it, though C-50 cited the very line that does (`opening-and-listing.md:177`) | Folded into **C-50** rather than added as a near-duplicate row — one row, correct claim |
| **#247 named `REWIND_REDECODE_WARN_BYTES`**; #246 had the behaviour but not the constant | Folded into **F-22**, which also now records a trap neither pass caught: two distinct 1 MiB constants, and the page names only the other one |
| **#247 excluded attribution prose** ("attribution-only sentences are not behavioural claims") | **Rejected.** Cluster I proves the opposite — license-text paths, the adapted-source table, three oracle env-var names and the dangling `IDEAS.md` references (I-24) are all checkable and all drift. This is O-2's fact-class |
| **#247's argument that `philosophy.md` carries no unique behavioural claims** | **Partly adopted** — and #246 already does the narrow version: I-13 records that Topic 7 owns whether the positioning persuades, and this row asks only whether it is true of the library today |
| **#247's page-coverage checklist** | **Not ported.** §Coverage here is a superset: per-page row counts, cluster mapping, the 573 → 400 dedupe arithmetic, code-block and `[TM]`/`cfg` tallies, and an explicit "where a claim was *not* extracted, and why" |
| **#247 merged the A-16 pair into one row** (`C-open-07`) and asserted one side as the claim | **Rejected**, and turned into a rule — see §How to read a row. This is the concrete cost of coarse rows: the contradiction survives a `verified` verdict |
| **The two baselines disagreed about zstd** | **Both were right about different things.** Reconciled in Part 1; the reconciliation found a library question neither pass had (`open-issues.md` P5), which is the strongest argument for having run two passes |

**A-16 was confirmed by hand** while merging: `opening-and-listing.md:66-68` says ZIP, 7z,
RAR and ISO all have to seek, while `access-and-cost.md:145-146` says *"ZIP (stdlib) and
ISO always need seek today — even `streaming=True` cannot open them from a pure pipe."*
The pages disagree about whether `streaming=True` opens **7z and RAR** from a pipe. The
verdict is still a worker's; the contradiction is not in doubt.

**A-33 was checked and does not reproduce as stated.** `opening-and-listing.md:129`
(`UnsupportedFormatError`) and `formats.md:37` (`PackageNotInstalledError`) describe
different situations — detection ambiguity for `.tar.zst` vs `.zst`, against a missing
backend at open. It stays a row to verify, not a contradiction.

# Pass 1 verification summary (coordinator merge)

Filled **402** rows (all claim IDs in this file). Session: `[all]`, `unrar`+`7z` present,
`list_known_formats()` → 26×FULL (F4); `UNKNOWN` named-attr only → NONE.

| Verdict | Count |
|---|---:|
| verified | 382 |
| wrong | 11 |
| out of scope ([TM]) | 8 |
| unverifiable (platform) | 1 (C-17 NTFS junctions) |

**Wrong IDs:** A-6, A-16, A-18, A-33, A-34, D-48, E-1, E-71, F-16, F-26, G-9.

O-26 classification, cross-cluster consistency, and maintainer questions:
[`QUESTIONS.md`](QUESTIONS.md). Per-cluster evidence: `worker-inputs/verdicts-*.md`.
Harvest: `../problem-catalogue/harvest/`.

## Cross-cluster consistency check (mandatory)

Checked seek lists, buffering absolute wording, rapidgzip, exception-name pairs,
accelerator containment, sticky under STANDARD, AUTO threshold, SFX, Directory listing
cost.

| Pair / topic | Outcome |
|---|---|
| A-16 vs E-4 / E-45 | **Consistent.** E rows verify ZIP/ISO seek requirement; A-16 correctly marks `access-and-cost.md:145-146` incomplete for 7z/RAR. No conflicting verdict. |
| A-6 vs E-71 | **Consistent.** A-6 = absolute no-buffer prose wrong; E-71 = RAR seekable-stream whole-archive spill silence. Same root honesty issue, different sentences. |
| A-33 vs A-32 / formats exceptions | **Consistent.** A-33 marked `wrong` as a *false conflict*; A-32 verified. Workers agree: different situations. |
| E-53 vs F rapidgzip / gotchas | **Consistent.** E-53 verified (do not soften); F-20/F-32 align. |
| F-33 vs F-35 (accelerator abort vs contain) | **Consistent.** Both halves true on `access-and-cost`; gotchas states only containment — incomplete pair harvested, not a verdict contradiction. |
| C-25 sticky STANDARD (guide+code vs safe-extraction matrix) | **Not a cross-worker conflict.** Guide claim verified against code; spec drift escalated in QUESTIONS (code vs spec). |
| B-26 foreign-member exception | **Not a cross-worker conflict.** Guide verified (`ArchiveyUsageError`); `archive-reading` still says `ValueError` — QUESTIONS. |

No worker pair returned contradictory verdicts for the same behavioural fact.

## What this pass still did not do

- **No guide prose written, and no file under `docs/` edited.**
- **No library defect fixed** in this PR (O-26 → separate vehicles in QUESTIONS).
- **`[all-lowest]` and `[core-only]` were not run end-to-end.** `cfg` rows used `[all]`
  plus existing monkeypatch/tests for absence paths where noted in worker files.
- **Page PRs** wait on P11 and scope.md Q3 (and QUESTIONS answers).
