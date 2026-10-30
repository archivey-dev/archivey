## 1. Kept errors raise fresh copies

- [x] 1.1 `kept_errors.KeptError`: keep an unraised copy and the first traceback as text
- [x] 1.2 `DecompressorStream` deferred and spent errors, `ArchiveStreamImpl` verdict and
  lazy-open error raise through it
- [x] 1.3 The stream's error boundary drops its locals as the raise leaves it
- [x] 1.4 Tests: same type and arguments with an `EarlierRaise` cause; streams freed with
  the garbage collector off
