## 1. Restore birth time

- [x] 1.1 `internal/birth_time.py`: `SetFileTime` on Windows, `setattrlist` / `fsetattrlist` on macOS, no-op elsewhere
- [x] 1.2 `ExtractionCoordinator._apply_metadata` sets it after `os.utime`
- [x] 1.3 Tests: real birth time on Windows and macOS CI, call order everywhere, refusal swallowed
- [x] 1.4 `docs/extracting.md` and the `created` docstring
