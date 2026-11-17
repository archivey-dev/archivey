You are checking the RAR support of archivey (github.com/archivey-dev/archivey, branch `main`), a pure-Python library that reads many archive formats behind one API: `open_archive(path)`, then `reader.members()`, `reader.open(member)`, `reader.stream_members()`, `reader.extract_all()`, `reader.verify_all()`. I want reading-correctness bugs in its RAR code: cases where archivey lists, reads or verifies a RAR archive differently from what RARLAB's `unrar` (or `rar`) does, or differently from what its own docs say.

Clone current `main` and install it with its dev dependencies (`uv sync`, or `pip install -e ".[recommended]"` plus the test tools in `pyproject.toml`). Install `rar` and `unrar` from RARLAB (and `unar` if you can) to build and compare archives.

## How archivey reads RAR

archivey parses RAR headers itself (RAR 1.5 to 5) and hands the decoding to an external `unrar` or `unar` program. Read these first:
- `dev-docs/formats/rar.md` and `openspec/specs/format-rar/spec.md` (the behaviour it promises),
- `dev-docs/decisions/0002-native-rar-metadata-unrar-data.md`,
- `dev-docs/known-issues.md` (do not report what is already listed there).

The code is in `src/archivey/internal/backends/rar_*.py`:
- `rar_parser.py`, `rar_detect.py`: headers, detection, volume names.
- `rar_reader.py`, `rar_unrar.py`, `rar_unar.py`: the main reader and the two decoders.
- `rar_synthetic.py`, `rar_copy_sources.py`: for solid archives and file copies, archivey writes a small synthetic RAR holding only the members it needs and hands that to `unrar`.
- `rar_rolling.py` (new, #1552): multi-volume archives are fed to `unrar` volume by volume, as rolling volumes, instead of as whole copies.
- `rar_forward.py`, `rar_forward_reader.py` (new, #1564): reading a RAR archive from a pipe in one streaming pass.

The two newest pieces (#1552 and #1564) have had the least use. Start there.

## What counts as a bug

- **Different contents.** Member names, sizes, types, timestamps, link targets, or bytes that differ from `unrar` on a valid archive.
- **Results that depend on how the archive is read.** The same archive must give the same members, bytes, diagnostics and errors from a path, a file object, a pipe, `stream_members()` or `members()` + `open()`, whole or split into volumes, and with `unrar` or `unar` as the decoder (where both can read it).
- **Wrong or untyped errors.** A raw `IndexError`, `struct.error`, `KeyError`, `ValueError`, `AssertionError` or a subprocess error leaking out of a public call, or a damaged archive reported as a password error (or the reverse).
- **Silent wrong data.** A damaged or truncated archive that lists or verifies as complete, a CRC or BLAKE2sp check that should fail but passes, a member missing with no diagnostic.
- **Docs that say something the code does not do.**

On clearly damaged data archivey may refuse where `unrar` goes on; that is deliberate.

## Inputs worth trying

- RAR 5 and RAR 4 (`rar -ma4`), solid (`-s`) and not, with `-m0` to `-m5`, large and small dictionaries.
- Multi-volume sets (`-v`): old (`.r00`) and new (`.partN.rar`) naming, members spanning volumes, a missing or extra volume, volumes opened from the first part or a middle part, the set read from a pipe.
- File copies and hard links (`-oh`, `-oi`), symlinks (`-ol`), directories, empty files, empty members in solid archives, file versions (`-ver`), comments, recovery records (`-rr`), quick-open info (`-qo`), locked archives, `-htb` BLAKE2 checksums, Unicode and long names.
- Encrypted data (`-p`) and encrypted headers (`-hp`), with the right and wrong password.
- Reading order: members in reverse order, the same member twice, solid members out of order, stopping a `stream_members()` loop halfway.
- From a pipe (`cat a.rar | python ...`, or `open_archive(sys.stdin.buffer)`): every case above that the docs say a pipe supports.

## Rules

- **Run every claim.** A finding you only read in the code is allowed, but mark it READ ONLY and say why you could not run it.
- Keep each reproducer small: a script that builds the archive with `rar` (or by hand) and shows the wrong behaviour in under a minute. Say which `rar`/`unrar` versions you used.
- Check a finding against the docs and known issues before reporting it, and merge findings with one cause.
- No style or refactoring advice, and no "this might be a problem" without an input that shows it.

## Report format

Start with three lines: how many findings, how many you ran, and the one you would fix first. Then one block per finding, most severe first:

```
### R<n>: <one-line title saying what goes wrong>

- Severity: high | medium | low
  (high = silent wrong data, or results that depend on how the archive is read;
   medium = untyped or wrong error, disagreement with unrar on a valid archive, missing diagnostic;
   low = docs mismatch or cosmetic)
- Status: RAN (on main at <commit>) | READ ONLY (<why not run>)
- Where: <file>:<function or line>
- Input: <archive, how it was made, how it was opened>
- Expected: <what unrar does, or what the docs say, with the doc it comes from>
- Actual: <what archivey does, with the exact output or traceback excerpt>
- Reproducer:
  <a self-contained script or shell commands>
- Cause (if known): <one or two sentences>
```

End with a short list of the cases you checked and found correct.

## Deliverable

One pull request against `main` from the branch `review/outside-rar-sweep-2026-11-15` (or a `git format-patch main` patch if you cannot push), with no change under `src/`:
- the report as `review/outside-rar-sweep-2026-11-15/SUMMARY.md`, with this prompt as `brief.md` beside it;
- `tests/test_audit_outside_rar_sweep_2026_11_15.py`: one test per finding you ran, asserting the correct behaviour and marked `@pytest.mark.xfail(strict=True, reason="R<n>: <title>")`, as in `tests/test_audit_extraction.py`. Skip a test when `rar`/`unrar` is missing, as the existing RAR tests do. Add passing tests only for checked cases that no existing test covers.

## User follow-up

> do not do any security work, focus on correctness and performance only
