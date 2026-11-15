Findings: 2
Ran: 2
Fix first: R1 — a truncated pipe member returns invented zero bytes and passes its digest.

Audited `main` at `6476c96cb6dee34a37ffd277e331eaf630e67acf`, on Linux x86-64,
CPython 3.11.18. Tools: RARLAB `rar` 7.23 and `unrar` 7.23 (27 June 2026), downloaded
from RARLAB; `rar` 6.24 (3 October 2023) for RAR4 creation. Installed with
`uv sync --extra recommended` (includes the dev group), then the repository test script
synced all extras. No changes under `src/`. This is a reading-correctness review, with
no security assessment.

Both findings were checked against `dev-docs/known-issues.md`; neither is listed there.
The strict xfail tests also ran with `--runxfail`: R1 failed because the expected error
was absent; R2 failed in `_rar5_extra_without_hash`. Each standalone reproduction takes
less than one second here. The scripts below run from the repository root, with RARLAB
`rar` and `unrar` on `PATH`.

### R1: A truncated pipe member returns invented zero bytes and passes its digest

- Severity: high
- Status: RAN (on main at 6476c96cb6dee34a37ffd277e331eaf630e67acf)
- Where: `src/archivey/internal/backends/rar_forward_reader.py:_PaddedSpan.read`,
  `_ForwardPass._release_early`, `RarForwardReader._plan` (lines 196, 292, 903).
- Input: `rar a -cfg- -ma5 -m0 a.rar zeros`, where `zeros` holds 6 MiB of zeros.
  Cut the archive to 5 MiB. Open as a non-seekable source with `streaming=True` and
  `SpoolLimits(max_bytes=2 << 20)`. Read the first member, then close the pass.
- Expected: Refuse the member's incomplete data. `unrar t` exits 3. The same bytes in
  a seekable `BytesIO` raise `TruncatedError` on the member read. OpenSpec
  `format-rar`, “Read a RAR archive forward from a non-seekable source,” requires a
  cut-short member to raise; its long-cut exception permits `CorruptionError` instead
  of `TruncatedError`, not a successful read. `dev-docs/formats/rar.md` §2.6 says a
  longer cut member is padded and “fails its own digest check.”
- Actual: The pipe member read returns all 6,291,456 declared bytes and verifies the
  CRC successfully, although fewer than 5 MiB of packed member data exist. Closing
  after that member succeeds. Exact reproduction output:

  ```text
  unrar t: exit 3
  seekable: TruncatedError: Decompressed content ended after 5242809 of 6291456 expected bytes. (member='zeros', format=RAR)
  pipe, reduced limit: read zeros: 6291456 bytes; all zero=True
  ```

  Exhausting the full listing still raises its terminal `TruncatedError`. This is
  **not** a claim that `verify_all()` silently accepts the entire archive: the bug is
  that a completed member read supplies bytes missing from the source and verifies
  them. A caller that stops after that member sees no error.

  Also reproduced through an actual OS pipe (`sys.stdin.buffer`) with the default
  spool limit: a 24 MiB zero member cut at 20 MiB returns all 25,165,824 bytes. Both
  CRC32 and `rar -htb` BLAKE2sp archives exhibit this successful read.
- Reproducer:

  ```sh
  uv run --no-sync python review/outside-rar-sweep-2026-11-15/reproduce.py R1
  uv run --no-sync pytest -o addopts= --runxfail -q \
    tests/test_audit_outside_rar_sweep_2026_11_15.py::test_a_truncated_pipe_member_never_verifies_zero_padding
  # Default spool limit, CRC32 and BLAKE2sp variants:
  uv run --no-sync python review/outside-rar-sweep-2026-11-15/reproduce.py R1-default
  uv run --no-sync python review/outside-rar-sweep-2026-11-15/reproduce.py R1-blake
  ```

  [`reproduce.py`](reproduce.py) is self-contained: it creates the input with `rar`,
  invokes `unrar`, then compares seekable and non-seekable member reads.
- Cause (if known): `_PaddedSpan` supplies zeros after the real source ends and marks
  the member cut. A member larger than one rolling volume is released before that
  cut becomes known. `_plan` checks the cut flag only when it assigns the member's
  stream. Completion subsequently checks the fabricated bytes' size and digest,
  without rechecking that flag. A missing zero tail therefore satisfies the CRC.

### R2: Splitting a RAR5 member rejects extra-area padding that unrar accepts

- Severity: high
- Status: RAN (on main at 6476c96cb6dee34a37ffd277e331eaf630e67acf)
- Where: `src/archivey/internal/backends/rar_rolling.py:_rar5_extra_without_hash`
  (line 211), called by `_part_rar5` (line 180).
- Input: A hand-built RAR5 containing one stored 10,040-byte file `a`, a correct
  CRC32, and a FILE extra area consisting of one zero padding byte. The native
  `_walk_rar5_file_extras` explicitly permits one padding byte. Read from a path,
  or from a pipe with the default spool limit, then repeat the pipe read with
  `SpoolLimits(max_bytes=4000)` to force a member split.
- Expected: Return the same 10,040 bytes in each read. `unrar t` exits 0 and
  `unrar p` returns exactly the input. OpenSpec `format-rar`, “Read a RAR archive
  forward from a non-seekable source,” promises matching members and bytes; this
  member has none of its listed forward-only exclusions. The native reader and
  RARLAB both tolerate the padding. This is not a request to relax the main header
  parser: it already accepts this input without a diagnostic.
- Actual: The seekable read and default-limit pipe read succeed. With the smaller
  spool limit, `stream_members()` raises before delivering the first member:

  ```text
  unrar t: exit 0
  seekable: read a: 10040 bytes; all zero=False
  pipe, default limit: read a: 10040 bytes; all zero=False
  pipe, reduced limit: CorruptionError: Invalid RAR5 variable-length integer (format=RAR)
  ```

  Traceback excerpt:

  ```text
  rar_rolling.py:180 in _part_rar5
      extra = _rar5_extra_without_hash(extra)
  rar_rolling.py:218 in _rar5_extra_without_hash
      kind, _ = load_vint(extra, body)
  rar_parser.py:1737 in load_vint
      raise CorruptionError("Invalid RAR5 variable-length integer")
  ```
- Reproducer:

  ```sh
  uv run --no-sync python review/outside-rar-sweep-2026-11-15/reproduce.py R2
  uv run --no-sync pytest -o addopts= --runxfail -q \
    tests/test_audit_outside_rar_sweep_2026_11_15.py::test_extra_area_padding_survives_a_rolling_volume_split
  ```

  [`reproduce.py`](reproduce.py) builds every header and its CRC with the standard
  library, then invokes `unrar` and archivey. No fixture download is needed.
- Cause (if known): The rolling writer removes BLAKE2sp records from non-final
  parts. Its separate extra-record walker treats the final padding byte as a
  record size, then tries to read a type beyond the buffer. The native header
  walk permits that byte. The failing input carries CRC32, not BLAKE2sp, but the
  split writer runs the removal walk anyway.

`unar` comparison was not completed. Building upstream XADMaster 1.10.8 with the
repository installer failed because the Objective-C compiler (`cc1obj`) and GNUstep
build dependencies are absent. No finding relies on an untested `unar` claim. The
full project suite and cross-platform runs were not performed.

Cases checked and found correct:

- Existing rolling/pipe suites: **830 passed, 6 skipped** with RARLAB 7.23. The skips
  were inputs that the seekable fixture walk also could not list.
- 36 generated RAR4/RAR5 combinations: stored, normal and maximum compression;
  solid and nonsolid; plain, data-encrypted and header-encrypted. Seekable and pipe
  passes matched at default and 4,000-byte spool limits. Inputs included empty
  files, a file after an empty entry, hard links, symlinks, a directory, Unicode
  names and `-htb` where supported.
- 54 generated volume-set combinations, including RAR4 old and new numbering and
  RAR5 new numbering: reverse and repeated random reads matched the original
  single-volume bytes, from paths and explicit lists of open file objects, with a
  4,000-byte spool limit. These used `-v16k`; highly compressed cases can fit one
  volume. No data mismatch or unexpected error occurred.
- The regression controls: R1's seekable cut-member read raises; R2 passes RARLAB
  test/extraction-to-stdout, path reading and an unsplit pipe pass.
