## 1. Implementation

- [x] 1.1 `Bzip3Decompressor.decompress`: the look-ahead does not raise; an error after output in the same call is raised from the next call
- [x] 1.2 Tests in `tests/test_bzip3.py`
- [x] 1.3 `openspec validate bzip3-output-before-error --strict`, then archive
