## 1. Library

- [x] 1.1 `open_archive(pipe=)`: argument check, overloads, `streaming` implied,
  `concurrent_operations` refused, directory refused
- [x] 1.2 `ArchiveSource.read_as_pipe` over a seekable source
- [x] 1.3 Refusals: a non-seekable source without `pipe=True` in both modes; the
  capability refusal worded for `pipe=True`

## 2. Callers

- [x] 2.1 CLI read-once inputs open with `pipe=True`
- [x] 2.2 Tests that read a non-seekable source pass `pipe=True`; new tests for the mode

## 3. Docs and specs

- [x] 3.1 User docs: reading, formats, extracting, recipes, cheat sheet, gotchas, opening,
  migrating, api, remote
- [x] 3.2 Specs updated and this change archived
