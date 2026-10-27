## Why

A Windows installer can carry a ZIP far past the 2 MiB SFX window. The IRPF 2026 installer
(install4j, 110 MB) puts its ZIP at offset 35 536 406, behind a 34 MB obfuscated block, and
`detect_format` refuses it although `open_archive(format=ZIP)` lists all 174 members. The
ZIP tail probe that would find it was struck from `prefixed-archive-detection` on
2026-09-25 for four reasons: off under `BALANCED`, no measured real appended ZIP, six false
positives on a developer tree, and `format=ZIP` already opens one. This change answers
each one for one narrow case. It is a real file a user hit. A PE header says, for free,
whether a file carries an appended payload at all, so the probe never runs on an ordinary
program. And the six false positives are rejected by checks the probe makes anyway.

The same PE layout also tells detection where a classic SFX payload starts: in the 7-Zip
and WinRAR installers the archive starts exactly at the end of the last section.

## What Changes

- **A PE layout helper.** From the bytes detection already holds, read the end of the
  last section's raw data (the *overlay start*) and the Authenticode certificate range.
  No extra I/O. A header that does not parse gives no layout, and detection behaves as
  today.
- **An overlay-start check before the forward scan.** For a PE whose overlay starts inside
  the scan window, judge the RAR / 7z / ZIP candidate at the overlay start first. A valid
  hit there is the answer, ahead of an earlier needle in the stub. A 7z there that ends
  where the certificate starts counts as ending at end of source. The RAR and 7z parsers'
  own scans apply the same rule, so forced `format=` opens the same payload.
- **A ZIP tail probe, gated on the PE layout.** It runs only when all of these hold: the
  forward scan found nothing, the source is a PE whose overlay runs past what the window
  covered, and the tail can be read cheaply. It searches the 65 558 bytes before the
  certificate (or before end of file when there is none), and confirms the end record
  against the central directory and a local header before answering `ZIP` / `PROBABLE` /
  `sfx_scan`.
- **Accounting.** The tail read is counted in `unique_bytes_read` and recorded under a
  new tier name, `sfx_tail`. No new budget field.
- **Not breaking.** Files detected today are detected the same way, except a PE whose
  stub holds a valid needle ahead of a valid payload at its overlay start. That one now
  answers with the overlay payload (design §3).

## Capabilities

### New Capabilities

### Modified Capabilities
- `format-detection`: the SFX requirement gains the overlay-start rule; a new requirement
  for the PE-gated ZIP tail probe.
- `detection-cost`: a new requirement for how the tail probe is bounded, recorded and
  charged.

## Impact

- `internal/sfx.py` (PE layout helper next to `_is_pe`), `internal/detection.py` (overlay
  check, tail probe), `internal/backends/zip_parser.py` (the end-record search and checks,
  shared), `rar_parser.py` and `sevenzip_parser.py` (overlay-start rule in their scans).
- No public API change. `detected_by` keeps its values. `TierSkip.tier` gains `sfx_tail`.
- Tests: synthetic PE files with a section table and a certificate entry; no real
  installer is committed.
- Docs: `dev-docs/topics/prefixed-archives.md`, `dev-docs/topics/detection.md`,
  `docs/formats.md`, `dev-docs/IDEAS.md`, and a pointer from the struck Block 2 of
  `prefixed-archive-detection`.
