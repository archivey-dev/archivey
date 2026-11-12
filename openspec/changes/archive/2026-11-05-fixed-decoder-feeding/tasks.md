# Tasks

- [x] 1.1 `decompressor_stream.py`: slices to the next 64 KiB boundary from the decoder
      start; 64 KiB output per bounded call; surplus buffered.
- [x] 1.2 A read whose decoder call raises returns what it holds first.
- [x] 1.3 Probe streams ask for exact reads (`probe_streams`).
- [x] 1.4 Decode again to the failing byte on a seekable source.
- [x] 1.5 Tests: the prefix matrix (read sizes, short-read pipe, gzip / xz / bzip2 /
      zstd, two-member gzip, whole-stream read, rapidgzip parity, every byte before
      the error on a file).
- [ ] 1.6 Benchmark compare against `main` (benchmark-compare workflow); numbers in
      the PR.
