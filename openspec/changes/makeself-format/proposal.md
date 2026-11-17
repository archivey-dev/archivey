# Read makeself self-extracting archives

## Why

A makeself `.run` installer (NVIDIA and other Linux drivers, VirtualBox extension
packs, many vendor SDKs) is a shell script followed by one or more compressed TARs.
Today it fails detection: `#!` cues the SFX scan, which has no needle for a compressed
stream, and the TAR and single-file readers refuse a start offset. The idea was parked
twice: as "Makeself-aware payload location" in `dev-docs/IDEAS.md`, and as the
compressor-needle block of the archived `prefixed-archive-detection` change.

## What Changes

- New built-in format `ContainerFormat.MAKESELF` / `ArchiveFormat.MAKESELF`, a
  sequential reader written against `archivey.formats`. Detection by the header's first
  two lines at offset 0.
- The header is parsed, never run: the variable block at the top as shell
  double-quoted assignments, and the payload command and the old offset lines as whole
  lines of the script after it. makeself 2.2.0 and later.
- Every payload's TAR is listed, in order, through `ReaderContext.open_nested`. Every
  compressor archivey has a codec for, and base64, are read. gpg and openssl payloads
  are refused by name; openssl decryption follows in its own change.
- The header's CRC (POSIX `cksum`), MD5 and SHA-256 of each payload are all checked. A
  match raises every file of the payload to `Verification.CHECKSUM`; a mismatch makes
  them failures of `verify_all()`. This needs an internal hook for a check over several
  members that a reader written against `archivey.formats` runs itself
  (`ReaderContext._spanning_check`, `format_adapter.SpanningCheck`). It is not public.
- A forced other `format=` (`TAR_GZ`, `TAR`, `ZIP`) still fails at byte 0, and its
  error says the file is a makeself archive.
- `ArchiveInfo.extra` keys `makeself.label`, `makeself.script`, `makeself.target_dir`,
  `makeself.compression`, `makeself.encryption`, `makeself.payloads`,
  `makeself.signed`; `format_version` is the makeself version the header names.
- Threat model: a self-extracting archive's program is not run, so what archivey lists
  is not proof of what running the file does (accepted).

## Impact

- New: `src/archivey/internal/backends/makeself_reader.py`, `tests/test_makeself.py`,
  `tests/fixtures/makeself/` (makeself's own output, 2.2.0 to 2.7.1),
  `dev-docs/formats/makeself.md`.
- Changed: `types.py` (format, extra keys), `formats.py` and `format_adapter.py`
  (the internal spanning-check hook), `core.py` (the forced-format hint), user docs.
- Non-goals here: openssl decryption (next change, with password plumbing for readers
  written against `archivey.formats`), and the generic `#!` compressor-needle scan for
  other script launchers such as CPack STGZ and conda installers (the change after).
