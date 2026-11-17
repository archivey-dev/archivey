## 1. Reader

- [x] 1.1 `single_file_reader.py`: the one member's `compression` names the stream's method, from the same map `FormatPolicy` uses for `exclude=`; `UNKNOWN` for a stream with no `CompressionAlgorithm` member

## 2. Tests

- [x] 2.1 `tests/test_single_file.py`: each codec from a file and from a pipe; a stacked `.xz.gz`; a `.tar.gz` member stays `STORED`

## 3. Docs and archive

- [x] 3.1 `docs/opening.md`
- [x] 3.2 `openspec validate single-file-member-compression`, then `openspec archive single-file-member-compression --yes`
