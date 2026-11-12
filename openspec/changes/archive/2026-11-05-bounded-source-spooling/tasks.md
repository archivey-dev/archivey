# Tasks — bounded source spooling

> **Split on 2026-09-26.** Tasks marked *(shipped)* landed in
> `openspec/changes/archive/2026-09-26-rar-stream-spool-limit/`, which bounded RAR's
> existing stream-source copy with `ArchiveyConfig.spool_limits` and raises
> `ResourceLimitError`. What is left is the non-seekable spool, `spool_dir` and the
> pre-flight. `None` on `max_bytes` shipped as *no limit*; the "none" setting below is
> `max_bytes=0`.

> **Specs-first proposal. Nothing here is implemented.** These tasks describe the
> implementation for when the change is accepted and scheduled. Run tools through `uv`
> (`uv run pytest`, `uv run pyrefly check`, `uv run ty check`, `uv run ruff`).
>
> **The four design questions are settled** (`design.md` §Decisions the maintainer settled):
> a 1 GiB default, a frozen `SpoolLimits` with an `UNLIMITED` classvar, a
> `SpoolLimitExceededError` subclassing `ResourceLimitError`, and `streaming=True` reading
> forward from the spooled file. They are inputs here, not implementation choices — except
> the third: on 2026-09-27, before 0.2.0, `SpoolLimitExceededError` was folded into plain
> `ResourceLimitError` (ADR 0012 amendment). Raise `ResourceLimitError`; do not re-add
> the subclass.

> **Re-derive the `archive-reading` "Explicit configuration object" block before archiving.**
> `one-member-listing-per-reader` archived a version of that block adding
> `read_link_targets` (and the two fields the schema had missed). This change's MODIFIED
> block predates it and would delete those lines on archive.

## 1. The setting

- [x] 1.1 *(shipped)* Add a frozen `SpoolLimits` dataclass with an `UNLIMITED` classvar,
      matching `ExtractionLimits` and `ListingLimits`, and hang it on `ArchiveyConfig`
      beside `listing_limits`. Its limit takes a byte count, `UNLIMITED` (`None`), or `0`,
      and **defaults to 1 GiB**.
- [ ] 1.2 Put the spool directory on the same object.
- [ ] 1.3 Export any new public name from `archivey.__all__` and give it an `api.md` entry.
- [ ] 1.4 Docstrings on the field and any new type — `api.md` renders from docstrings, and
      a `#` comment reaches no reader (`review/docs-content/scope.md` §Precondition).

## 2. The spool primitive

- [ ] 2.1 One internal helper performing a bounded spool: takes the limit, the directory, a
      source and an optional known size; returns a path; raises `ResourceLimitError` on
      the limit; registers cleanup with the reader's close.
- [x] 2.1a *(shipped)* Add `SpoolLimitExceededError` subclassing `ResourceLimitError`, and
      widen `ResourceLimitError`'s docstring to name `SpoolLimits`.
- [x] 2.2 *(shipped, `archivey.internal.spool.SpoolBudget`)* Check the size **before**
      writing when it is known; enforce during the write when it is not, removing the
      partial file on the way out.
- [ ] 2.3 Best-effort free-space pre-flight per `design.md` Decision 5 — a fast-fail, never
      a promise, and not reachable as a guarantee from any public docstring.
- [x] 2.4 *(shipped)* Extend the existing open-time caveat (`rar_reader.py:119`) to name
      the configured limit. Do **not** append a note when a spool happens: `CostReceipt`
      is an immutable open-time description and `format-rar` already forbids a post-open
      note. No diagnostic.
- [ ] 2.5 Refusal path for the "none" setting, raising the same `ResourceLimitError` —
      a limit of none is a limit of zero bytes. Keep `StreamNotSeekableError` for the
      non-seekable-source case, extending its message to name the setting.

## 3. Route the existing RAR materialization through it

- [x] 3.1 *(shipped)* `RarReader._ensure_archive_path()` uses the primitive and raises
      `ResourceLimitError`.
- [x] 3.2 *(shipped)* `RarReader._materialize_stream_volumes()` likewise, with the limit
      measured across the whole volume set rather than per volume.
- [x] 3.3 *(shipped)* Confirm no behaviour change for path sources, for listing a stream
      source, and for stored-member reads from a stream — none of those may spool.

## 4. Spooling a non-seekable source

- [ ] 4.1 At open, when the format requires seekability, the source is not seekable, and the
      limit permits it: spool, then proceed as for a seekable source.
- [ ] 4.2 When the limit is none, keep raising `StreamNotSeekableError`, with the message
      naming the setting so the error teaches the fix.
- [ ] 4.3 `streaming=True` over a spooled source reads forward from the spooled file and
      does not switch to random access. Implement it explicitly rather than letting it fall
      out of whether the source happens to be seekable.

## 5. Tests

- [ ] 5.1 Red-green for the P11 case: a compressed RAR member read from a `BytesIO` records
      a `CostReceipt.notes` entry, and exceeds a low limit with `ResourceLimitError`.
      Verify by reverting the fix and watching each fail.
- [x] 5.1a *(shipped)* Drive the **1 GiB default** boundary directly. No corpus archive
      comes near it (the largest RAR is 188 KiB), so nothing else will catch a wrong
      default. A sparse or synthesised source keeps this off the corpus.
- [x] 5.1b *(shipped)* `except ResourceLimitError` catches the spool refusal.
- [ ] 5.2 Every row of the four delta scenario matrices — spool limit, reporting, timing,
      pre-flight/directory — plus the RAR matrix.
- [ ] 5.3 Timing specifically: listing a RAR from a stream does **not** spool; the first
      compressed member does; the second does not spool again.
- [ ] 5.4 Cleanup: temporary file or directory gone after `close()`, and after an exception
      raised mid-spool.
- [ ] 5.5 Non-seekable source for ZIP, 7z and ISO — the formats `StreamNotSeekableError`
      refuses today — under a permitting limit and under none.
- [ ] 5.6 Cross-platform: Windows temp-file semantics differ (an open file cannot always be
      replaced or removed). Name the spool file and close handles so cleanup works there —
      CI matrixes Windows and macOS, and the container is Linux.

## 6. Registers and docs

- [x] 6.1 *(shipped)* Close the open-issue entry for the disk copy, recording the limit that
      shipped. Its `CostReceipt.notes` half is already closed — the note ships today;
      update the entry's stale "no signal" measurement at the same time.
- [ ] 6.2 Threat-model pass: untrusted bytes at a predictable path, spool-directory
      permissions, cleanup after a hard kill. Match `docs/extracting.md`'s existing
      `.archivey-tmp-*` treatment rather than inventing a second convention.
- [ ] 6.3 Update `review/docs-content/claims.md` **E-71** — the row records that no page
      states the spill; when this lands the page states the limit instead. Do **not** edit
      pages under `docs/` from this change; Topic 8 owns the guide.
- [ ] 6.4 Track the payload-cache idea internally, recorded as a
      **caller-side wrapper-stream** concern archivey might ship or recommend later — not
      as a deferred version of this change.
- [ ] 6.5 Before archiving, re-derive this change's `format-rar` `MODIFIED` block from the
      live requirement and re-apply only this change's own edits. A `MODIFIED` delta
      replaces the whole requirement block, so anything the live text has gained since this
      block was written is deleted on archive, silently -- `openspec validate --strict`
      cannot see it. Do the same for the `archive-reading` and `access-mode-and-cost`
      blocks.
- [ ] 6.6 Dry-run the archive on a scratch tree and read the **diff** of
      `openspec/specs/`, not the `~ n modified` count: the count cannot tell an intended
      edit from a deletion. Every removed line should be one this change means to replace.
- [ ] 6.7 `openspec archive` this change in the implementing PR — CI checks it on PRs.
