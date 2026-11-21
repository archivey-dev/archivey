# Tasks — salvage step 2 (TAR)

- [x] 1.1 `tar_parser.py`: follow a header that fails its checksum (with the `ustar`
      magic and fields that parse), confirm the block its size points at, runs of 8,
      stop at the first damage otherwise; pipes look ahead at most 4 MiB.
- [x] 1.2 `tar_reader.py`: `MEMBER_HEADER_DAMAGED` on each read through the base hook;
      `CorruptionError` at the end of the pass.
- [x] 1.3 Tests: `tests/test_tar_damaged_header_resume.py` (three access modes, GNU and
      ustar, extended headers, runs, trailer, magic, v7, pipe limit, `.tar.gz`, STRICT,
      `extract_all`, CLI); older tests that damaged only a checksum now damage the size
      too, so they still test the stop.
- [x] 1.4 Docs: `dev-docs/formats/tar.md`, `docs/errors-and-diagnostics.md`.
