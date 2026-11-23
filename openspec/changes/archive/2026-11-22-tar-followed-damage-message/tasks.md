# Tasks — TAR followed-damage message

- [x] 1.1 `tar_reader.py`: the end-of-pass error names the first four followed headers,
      each as a member or an extended header, and counts the rest.
- [x] 1.2 `tar_parser.py`: a stop past the 4 MiB hold on a seekable source opened with
      `streaming=True` says to open it without `streaming=True`.
- [x] 1.3 Tests: `tests/test_tar_damaged_header_resume.py`.
- [x] 2.1 `openspec validate --strict tar-followed-damage-message`, then archive.
