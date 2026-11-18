## 1. LZMA2 entry turns xz off

- [x] 1.1 `FormatPolicy`: an LZMA2 entry refuses an xz file, an xz stream format and an
  xz member; an XZ entry leaves 7z LZMA2 open
- [x] 1.2 Tests in `tests/test_format_policy_methods.py`
- [x] 1.3 `FormatPolicy` docstrings and `docs/opening.md`
- [x] 1.4 Sync the delta spec and archive this change in the same PR
