## 1. Code

- [x] 1.1 `ArchiveStream.__init__` becomes a deprecated pass-through to `_setup`; backends and `open_codec_stream` build streams with `_blank()._setup(...)`
- [x] 1.2 `MemberPass.__init__` deprecated; the reader builds passes with `MemberPass._new`
- [x] 1.3 `ArchiveStream`'s docstring says what a caller needs; the responsibilities list moves to a comment

## 2. Tests and docs

- [x] 2.1 `tests/test_deprecated_constructors.py` pins the warnings and that the reader's own paths emit none; other tests build through the private factories
- [x] 2.2 `dev-docs/api-surface.txt` regenerated
- [x] 2.3 `openspec validate --strict reader-built-streams-and-passes`, then archive
