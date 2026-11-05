## 0. Scope

Cut down on 2026-09-25: `detection-evidence-ledger` was decided against, so the ledger
field, the derived properties, the value migrations and the ledger rendering are withdrawn
(see the note at the top of `proposal.md`). Groups 1 and 2 record what shipped; group 3 is
what remains. **The handoff depends on `bounded-source-spooling`** (or equivalent) for the
replay buffer on a non-seekable source.

## 1. Retain the result (shipped)

- [x] 1.1 The reader keeps the `FormatInfo` it opened by, exposed as
      `ArchiveReader.format_info` (`None` under `format=`)
- [x] 1.2 A directory reports `DIRECTORY` / `CERTAIN` / `"directory"`
- [x] 1.3 `archivey info` reads `reader.format_info` and detects once; it falls back to
      `detect_format` only to print identity when the open fails
- [ ] 1.4 `open_stream` exposes the detected container, not only the stream codec

## 2. The `detection=` handoff

- [ ] 2.1 Failing test: `detect_format` then `open_archive(source, detection=result)` runs
      detection once, and `reader.format_info` is the result
- [ ] 2.2 Failing test: the same result routed through `format=` is **not** stamped on a read
      failure, while through `detection=` it is
- [ ] 2.3 Add `detection=` to `open_archive` and `open_stream`; skip detection when given
- [ ] 2.4 `format=` and `detection=` together is a usage error
- [ ] 2.5 Decide whether the result records a source token; if it does, a mismatch raises,
      and the docstring says it is a typo-catcher, **not** an integrity check
- [ ] 2.6 Non-seekable sources: the replay buffer travels with the result; a result whose
      buffer was released raises rather than re-reading bytes that are gone
- [ ] 2.7 Confirm `format=` still performs **no** detection I/O of any kind
- [ ] 2.8 `docs/opening.md`: inspect-then-open

## 3. Verify

- [ ] 3.1 `./scripts/check.sh --fix`
- [ ] 3.2 `./scripts/test.sh --all-configs`
- [ ] 3.3 `openspec validate --strict detection-result-surface`
