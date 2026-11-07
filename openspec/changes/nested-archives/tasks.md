## 1. Hook

- [x] 1.1 `ForwardStream.take(n)` and its `_TakenBytes` stream.
- [x] 1.2 `ReaderContext.open_nested(data, format)`, wired by the plugin adapter
      (`_open_nested`, `_nested_spans`, `_NestedData`, `_outer_copy`).
- [x] 1.3 `DiagnosticCollector.member_ids_from(first)`.
- [x] 1.4 `BaseArchiveReader._nested_reader`: no presentation checks at registration.
- [x] 1.5 `tests/test_format_api_nested.py`: one pass from a pipe, random access, the
      report's member id, names checked once, the walk resumes after `take`, a cut inner
      archive, ZIP accepted and 7z refused, the call outside a walk refused, `take` alone.
- [x] 1.6 `docs/adding-a-format.md` §"An archive inside the archive".

## 2. First user

- [ ] 2.1 The deb reader (its own pull request).
