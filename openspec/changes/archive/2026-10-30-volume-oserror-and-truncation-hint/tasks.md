## 1. Volume open errors

- [x] 1.1 A missing or unreadable volume path the caller listed raises its `OSError`, as the first path does
- [x] 1.2 `EMFILE` / `ENFILE` opening a volume raises `ResourceUnavailableError`
- [x] 1.3 Tests in `tests/test_volumes.py`

## 2. TruncatedError as a hint

- [x] 2.1 `TruncatedError`'s docstring and the errors guide say a cut-short file may be fetched again or resumed, best effort
