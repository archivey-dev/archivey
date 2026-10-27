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
  hit there is the answer, ahead of any other needle in the window, including a 7z there
  that ends short of end of source. The RAR and 7z parsers' scans and the forward ZIP walk
  apply the same rule, so forced `format=` opens the same payload, seekable or not.
- **A ZIP tail probe, gated on the PE layout.** It runs only when all of these hold: the
  forward scan found nothing, the source is a PE whose overlay runs past what the window
  covered, and the tail can be read cheaply. It searches the 65 558 bytes before the
  certificate (or before end of file when there is none), and confirms the end record
  against the central directory and a local header before answering `ZIP` / `PROBABLE` /
  `sfx_scan`.
- **`FormatInfo.prefixed`.** A new `bool`, `True` when detection had to recognise or skip
  leading bytes before the archive, even when the archive's own offsets count them in. It replaces `payload_offset > 0` as the documented test
  for a self-extractor: a ZIP found from its end record reports the base its end record
  implies, which is 0 when its offsets count from the start of the file.
- **`FormatInfo.payload_end` and readers bounded by it.** Detection reports where a signed
  PE's certificate starts; `open_archive` passes it to the reader beside the start offset,
  and the reader treats the source as `[start, end)`. Under forced `format=` the readers'
  own payload scans derive the same end. The ZIP end-record search stops there, so the
  reader finds every record the tail probe accepts, and the ZIP, 7z and RAR trailing-data
  checks stop there, so a signed installer no longer warns about its own certificate.
- **Accounting.** The tail read is counted in `unique_bytes_read` under a defined tail
  allowance and recorded under a new tier name, `sfx_tail`. No new budget field.
- **Not breaking.** Files detected today are detected the same way, except a PE with a
  valid payload at its overlay start and another valid needle elsewhere in the window.
  That one now answers with the overlay payload (design §3). A signed SFX stops emitting
  `ARCHIVE_TRAILING_DATA` for its certificate (design §12, maintainer decision), which
  also lets it open under `DiagnosticPolicy.STRICT`.

## Capabilities

### New Capabilities

### Modified Capabilities
- `format-detection`: `FormatInfo` gains `prefixed` and `payload_end`; the SFX requirement gains the
  overlay-start rule; the access-shape requirement gains the tail probe's reads; a new
  requirement for the PE-gated ZIP tail probe.
- `detection-cost`: *Detection declares what it may spend, and reports what it spent*
  gains the tail allowance, in its definitions and in the within-budget rule. The spec's
  Purpose note, which expects a tail probe to bring its own budget field, is amended by
  hand at archive (deltas do not carry Purpose text).
- `archive-reading`: *Honour detection payload_offset at open* passes the payload end too,
  and binds backends to the `[start, end)` view.
- `format-zip`, `format-7z`, `format-rar`: their trailing-data requirements stop at the
  payload end; the ZIP end-record search does too.

## Impact

- `internal/sfx.py` (PE layout helper next to `_is_pe`), `internal/detection.py` (overlay
  check, tail probe), `internal/backends/zip_parser.py` (the end-record search and checks,
  shared), `rar_parser.py`, `sevenzip_parser.py` and `zip_local_walk.py` (overlay-start
  rule in their scans), `detection_workspace.py` (a tail read that ends at a given offset
  and records its decline under the caller's tier), `core.py` and `base_reader.py` (the end
  passed to `open_read`), and the ZIP, 7z and RAR readers' end-record and trailing-data
  code.
- Public API: `FormatInfo.prefixed` and `FormatInfo.payload_end` are added (additive, last
  fields) in `src/archivey/detection.py`, the public module, and the `info` verb
  (`src/archivey/cli/info_cmd.py`) prints them. `detected_by` keeps its values.
  `TierSkip.tier` gains `sfx_tail`.
- Tests: synthetic PE files with a section table and a certificate entry; no real
  installer is committed.
- Docs: `dev-docs/topics/prefixed-archives.md`, `dev-docs/topics/detection.md`,
  `docs/formats.md`, `dev-docs/IDEAS.md`, and a pointer from the struck Block 2 of
  `prefixed-archive-detection`.
