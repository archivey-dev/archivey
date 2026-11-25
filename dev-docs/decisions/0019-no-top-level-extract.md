# 0019 — No top-level `extract()`; extract through an open reader

- **Status:** accepted
- **Date:** 2026-10-06
- **Provenance:** maintainer decision (davitf, 2026-10-06); OpenSpec change
  `openspec/changes/archive/2026-10-06-remove-top-level-extract/`

## Context

Until 0.2.0, the package had a one-call extraction function next to the reader method:

```python
archivey.extract(source, dest)                 # removed

with archivey.open_archive(source) as reader:  # the one way now
    reader.extract_all(dest)
```

`extract()` was justified as a direct replacement for `shutil.unpack_archive` and the
stdlib `extractall` calls. To stay a single call it could not behave exactly like
`open_archive()` followed by `extract_all()`, and each difference had a cost:

- **No `members=` or `filter=`.** Selecting a subset needs the member list, which the
  one call could only get by opening, listing and reopening. Callers who wanted a subset
  had to learn the other API anyway.
- **A different diagnostics scope.** Its report's diagnostics covered detection, open
  and extraction, because the caller had no reader to ask. `extract_all()`'s report
  covers that call only. The same `ExtractionReport` type meant two things depending on
  which function returned it, and the diagnostics spec and docs carried both scopes.
- **Automatic streaming on a pipe.** It opened a non-seekable source in streaming mode
  by itself, while `open_archive()` refuses one unless the caller passes
  `streaming=True`. One entry point guessed and the other failed fast (ADR 0010).
- **Duplicated argument checks.** It re-validated every argument before opening the
  source, so that a wrong type was refused before any I/O and the message named
  `extract()`. That was a second copy of the checks `open_archive()` and
  `extract_all()` already make, with its own tests.

## Decision

Remove `archivey.extract()` before the first public release, with no deprecation shim.
Extraction goes through an open reader: `open_archive()` then `extract_all()`.

The reasons, as the maintainer gave them:

- The alternative is cheap: two lines instead of one.
- Keeping a near-identical wrapper causes more confusion than it saves. Every
  difference above needed explaining, and readers kept asking which call to use.
- A caller doing anything that needs diagnostics or options is better off with
  `open_archive()` anyway, because the reader is where those live.

## Consequences

- One extraction API, one report scope: `ExtractionReport.diagnostics` always covers its
  `extract_all()` call, and detection and open diagnostics are on `reader.diagnostics`.
- Extracting from a pipe or socket needs `pipe=True` on `open_archive()`, the same as
  every other read of a source that cannot seek. The docs say so where they show
  extraction.
- Migration docs map `shutil.unpack_archive(p, d)` and `extractall(d)` to the two-line
  form rather than to a single call.
- The CLI's `archivey extract` is unaffected: it always went through `open_archive()`.

**Re-opening this needs a new argument.** "It would be a drop-in for
`shutil.unpack_archive`" and "one line is shorter than two" were weighed when this was
decided and are not enough on their own.
