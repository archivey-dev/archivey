## ADDED Requirements

### Requirement: Published tree completeness is enforced in CI

CI SHALL fail when a file under `docs/` has no entry in `mkdocs.yml`'s nav, when a
nav entry names a file that does not exist, or when an absolute
`https://github.com/archivey-dev/archivey/blob/main/<path>` URL in `docs/**` or
`README.md` names a repository path that does not exist. `mkdocs build --strict`
alone is insufficient: it reports unlisted pages as INFO and exits 0, which is how
six pages became published, URL-reachable and search-indexed while absent from the
navigation.

#### Scenario: tree-completeness matrix

| Case | Expected |
| --- | --- |
| File added under `docs/` with no nav entry in the same commit | Check fails, naming the file |
| Nav entry names a file that does not exist | Check fails, naming the entry |
| `blob/main/dev-docs/…` URL in a published page whose target was renamed | Check fails, naming the URL and the page it appears on |
| Every `docs/` file navigable and every repo URL resolvable | Check passes; the docs job proceeds to `mkdocs build --strict` |

## MODIFIED Requirements

### Requirement: Per-format compression-library choices are documented

The documentation SHALL include `dev-docs/library-analysis.md`. For each read
codec it MUST name the chosen library, alternatives considered, and criteria:
non-seekability, seeking, corruption/truncation detection, error fidelity,
installability, and maintenance.
Each decision SHALL be self-contained; external links such as
`davitf/archivey-dev#214` MAY provide provenance but MUST NOT replace the recorded
rationale.

#### Scenario: library-analysis matrix

| Case | Expected |
| --- | --- |
| Contributor reads `dev-docs/library-analysis.md` | Each read codec (gzip, bzip2, xz/lzma, lzip, zstd, lz4, brotli, unix-compress, deflate64, ppmd) has chosen library, rejected alternatives, and rationale |
| XZ decision is documented | Native-parser rationale is recorded in full, including why stdlib `lzma.open` and `python-xz` were rejected; external link is provenance only |

### Requirement: End-user guide is separate from internal reference

The MkDocs site SHALL publish end-user material only. Every file under `docs/` MUST
be an end-user page carrying a nav entry; maintainer material — decision log, threat
model, codec analysis, known issues, open-issues triage, finished investigations,
and superseded historical prose — SHALL live under `dev-docs/`, outside the site,
rather than under `docs/` behind an exclusion list. The user narrative covers
philosophy, basic usage, gotchas, access costs/pitfalls, formats/extras, safe
extraction, and the API reference. Gotchas SHALL sit immediately after basic usage
in primary navigation. A published page SHALL NOT link to a path outside `docs/`;
where maintainer depth is worth preserving the link MUST be an absolute
`https://github.com/archivey-dev/archivey/blob/main/…` URL.

#### Scenario: docs information architecture

| Case | Expected |
| --- | --- |
| User opens the docs home | Every nav entry is an end-user page; no internal, grab-bag, or decision-log section exists |
| User finishes basic usage | Next recommended page is Gotchas |
| Contributor looks up “why not py7zr” | Answer is in `dev-docs/decisions/` in the repository, not on the site |
| Published page needs maintainer depth | Absolute `github.com/archivey-dev/archivey/blob/main/dev-docs/…` URL, never a site-relative path into unpublished material |
