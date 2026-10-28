# Tasks — salvage step 1

No code until the maintainer has reviewed the design. Two implementation PRs, RAR first;
each is labelled `needs-minor`.

## 0. Design review

- [ ] 0.1 Maintainer decisions 1 to 3 (`design.md` §Decisions, §B) recorded in the
      design with their date.

## 1. RAR: resume past a damaged header (PR 1)

- [ ] 1.1 Fixtures: generate damaged copies of `basic_nonsolid__.rar`,
      `basic_nonsolid__rar4.rar` and a solid RAR5 in the test, from committed
      fixtures (header end byte, name byte, size vint, type byte set to `ENDARC` and to
      SERVICE, the 3rd and 5th headers damaged, the 3rd and 4th damaged), and pin
      `unrar lb` / `unrar t` on each, and `lsar` where the design measured it, in a test
      that skips without the program (DR-24).
- [ ] 1.2 `rar_parser.py`: in both walks, on a damaged header after MAIN, compute the
      next position from the damaged sizes, confirm the header there and the one after
      it (CRC, type, fields; a damaged one after it by the same rule) and resume; never
      past a damaged header that does not parse in full or whose type reads `ENDARC`;
      keep a skipped FILE-typed header as an unlisted entry; record each span on
      `RarArchive` with a cap; keep `damaged` as the first. Encrypted headers do not
      resume.
- [ ] 1.3 `ARCHIVE_DAMAGE_SKIPPED`, `DamageSkippedContext`, `DiagnosticCodeStr`, the
      diagnostics catalogue row and the API surface listing.
- [ ] 1.4 `rar_reader.py`, `rar_unar.py`: emit the diagnostic per span during the walk.
      Count unlisted entries as payload FILE entries in the solid-pass split (`unrar` and
      `unar`), the include mask selection, the glob refusal, the dictionary check and
      `unar_entry_index`. An unlisted entry whose name `unrar` cannot read the way
      archivey does takes the mask rule's `UnsupportedFeatureError` (and `auto`'s route
      to `unar`).
- [ ] 1.5 Tests: the `format-rar` damaged-header matrix in both access modes,
      `members_report()`, `extract_all()` (writes every reached member, then raises),
      `archivey test` and `archivey list` output, a file copy or hard link whose source
      was skipped, a two-volume set, `rar_decompressor="unar"` after a skip (with an
      `unar` that archivey accepts), a duplicate name across a skip, and a crafted RAR
      1.5-4 whose damaged size lands on a header that passes CRC16 while the next does
      not (the two-header check), and the new rows of the four modified counting
      requirements (solid split, mask, glob refusal, dictionary).
- [ ] 1.6 `formats/rar.md` §1: replace "unrar searches past the damage" with what the
      source and the measurements show, and add the resume rule and its reasons.
      `docs/errors-and-diagnostics.md`: the new code.

## 2. Fixed decoder feeding (PR 2, after the per-member overhead PRs merge)

- [ ] 2.1 Check whether every `DecompressorStream` source is already read through a
      full-count reader; write the answer in the design.
- [ ] 2.2 Benchmark baseline on `main` (ZIP whole-member read, gzip and xz read-all).
- [ ] 2.3 `decompressor_stream.py`: slices aligned to 64 KiB of compressed offset from
      the decoder start, 64 KiB output per call, surplus buffered; a large source read
      sliced inside `_read_decompressed_chunk`. Remove `_COMPRESSED_READ_SIZE_MAX`
      scaling only if the benchmark allows; otherwise keep the large source read.
- [ ] 2.4 Tests: the `compressed-streams` prefix matrix (read sizes, a short-read pipe,
      deflate / xz / bzip2 / zstd, a ZIP member).
- [ ] 2.5 rapidgzip: measure the prefix against the in-process decoder; if they differ,
      take the choice in `design.md` §B "Accelerators" to the maintainer.
- [ ] 2.6 Benchmark gate after the change; record the numbers in the PR.

## 3. Close

- [ ] 3.1 `dev-docs/IDEAS.md` "Salvage mode": say that confirmed RAR resume shipped and
      list what is left (TAR, a search mode).
- [ ] 3.2 Archive this change (`openspec archive salvage-step-1 --yes`).
