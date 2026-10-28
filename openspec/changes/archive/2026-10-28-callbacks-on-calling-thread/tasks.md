## 1. Docs and tests

- [x] 1.1 `docs/reading.md` §"Several members at once" states where caller functions run
- [x] 1.2 `tests/test_concurrent_multithread.py` pins `on_diagnostic`, `filter=` and `on_progress` to the calling thread
- [x] 1.3 `openspec validate --strict callbacks-on-calling-thread`, then archive
