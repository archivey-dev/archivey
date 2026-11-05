# Tasks

- [x] 1.1 `keep_output_before_errors()` on `BaseDecoder`; `DecompressorStream` calls it
      for a source that cannot seek, outside probe streams.
- [x] 1.2 `ZlibDecoder` / `GzipDecoder`: copy before each inflate step, replay one byte
      per call on an error, raise from the next call.
- [x] 1.3 Tests: gzip, zlib and raw deflate from a pipe in `read(512)` and `read(1 MiB)`
      steps, and a damaged second gzip member, get the file's prefix.
- [x] 1.4 Pipe read cost measured.
