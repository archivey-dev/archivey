# Harvest I — Documentation shape, positioning, attribution

Bounded drop from Worker I verification (Topic 8 pass 1). Neutral phrasing; no
investigation beyond what the claim rows already touched.

---

### 1. `api.md` documents 56 of 87 `__all__` names

- **Problem:** Lead sentence is true of rendered symbols but reads like the
  reference is complete.
- **Symptom:** Callers scanning only `api.md` miss 31 public names.
- **Evidence:** `docs/api.md:3-5`; `len(archivey.__all__) == 87`; 56 `:::`
  entries; I-1, I-3.
- **Today:** Everything on the page is in `__all__`; the converse is false.

### 2. Exception tree mostly absent from the API reference

- **Problem:** Errors section lists five roots; 21 further exception types are
  in `__all__` with no `api.md` entry (scope Q3 / §D input).
- **Symptom:** Hierarchy discoverability depends on `errors-and-diagnostics.md`
  (and even that table is partial vs the full tree).
- **Evidence:** I-3 measurement; `documentation` Generate API reference; cluster
  note on 26 / 12 / 5.

### 3. Ten non-exception public names also omitted from `api.md`

- **Problem:** Named absentees include availability/detection helpers and
  version (`FormatInfo`, `FormatAvailability`, `FormatSupport`,
  `DetectionConfidence`, `MissingComponent`, `DiagnosticContext`,
  `ExtractionProgress`, `DEFAULT_ARCHIVEY_CONFIG`, `ARCHIVE_INTEGRITY_CODES`,
  `__version__`).
- **Symptom:** Same completeness illusion as (1); several are what install /
  formats prose already point callers at.
- **Evidence:** I-3 named list; all present in `__all__`, none in `api.md`.

### 4. `how-it-works.md` still missing (15 pages vs outline 16)

- **Problem:** Outline / DoD still assume a sixteenth end-user page.
- **Symptom:** Nav and `docs/` stay at 15; Guide budget (~110) unspent.
- **Evidence:** no `docs/how-it-works.md`; `mkdocs.yml` 15 entries;
  `check_docs_nav.py` green; I-22; `documentation:78-93` would need a delta
  when the page lands.

### 5. Bare ``IDEAS.md`` on two published pages

- **Problem:** Site-relative / bare filename cannot resolve; file lives under
  `dev-docs/`, outside MkDocs.
- **Symptom:** Reader on the guide hits a dead reference.
- **Evidence:** `docs/access-and-cost.md:33`; `docs/acknowledgements.md:55`;
  `dev-docs/IDEAS.md` exists; `documentation` requires absolute
  `github.com/archivey-dev/archivey/blob/main/…` URLs for maintainer paths; I-24.

### 6. Home single-file codec list omits LZMA Alone

- **Problem:** Highlights parenthetical lists nine codecs; `ArchiveFormat.LZMA_ALONE`
  is FULL and in the data-model stream set.
- **Symptom:** “Complete” reading of that list understates shipped single-file
  formats (`.lzma`).
- **Evidence:** `docs/index.md:48-50`; `format_availability(LZMA_ALONE)` FULL;
  `archive-data-model` StreamFormat list; I-6 note.

### 7. `api.md` / `formats.md` name `openspec/specs/` without a GitHub URL

- **Problem:** Authoritative-contract pointer is prose/backticks, not a
  resolvable link (index does link correctly).
- **Symptom:** From those two pages a browser user cannot open the specs.
- **Evidence:** `docs/api.md:5`; `docs/formats.md:4` vs `docs/index.md:87-88`;
  I-12.

### 8. Claim-text section count on `api.md` drifted

- **Problem:** Extracted claim said twelve sections; source has nine `##`
  headings.
- **Symptom:** Meta drift only — all 56 entries still resolve.
- **Evidence:** I-2; `docs/api.md` headings Opening…Errors.
