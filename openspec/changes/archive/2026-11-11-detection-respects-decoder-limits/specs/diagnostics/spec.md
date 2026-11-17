## ADDED Requirements

### Requirement: Report a detection step the decoder memory cap stopped

When the caller's `DecoderLimits.max_decoder_memory` refuses a decoder a detection step
needs (`format-detection`), the system SHALL emit `DETECTION_DECODER_LIMITED`. It
travels as every detection diagnostic does: on `FormatInfo.diagnostics`, on the
reader's diagnostics when `open_archive` detects, and through `on_diagnostic`. A step
that refuses once per candidate SHALL be reported once per detection pass for each
stream format.

#### Scenario: detection cap diagnostic

- **WHEN** a detection step's decoder is over the caller's cap
- **THEN** the code is emitted as below

| Case | Expected |
| --- | --- |
| `.tar.zst`, 8 MiB window, `max_decoder_memory=4 MiB` | `ZST`; one `DETECTION_DECODER_LIMITED` on `FormatInfo.diagnostics`; WARNING on `archivey.detection`; `on_diagnostic` called |
| Same file through `open_archive` | The same diagnostic reaches `on_diagnostic` before the read raises `ResourceLimitError` |
| `.lzma` (LZMA Alone) under `max_decoder_memory=1024` | One diagnostic for the content probe |
| LZMA Alone between 4 KiB and 64 KiB long, cap between the window's and the re-check's dictionary | The hit stands; one diagnostic for the whole-source re-check |
| `.tar.xz` declaring 64 MiB, cap 32 MiB | `TAR_XZ`; no diagnostic (the probe reserves 4 KiB) |

### Requirement: Only the caller's cap is reported as a detection limit

The code SHALL be emitted only when the caller's cap refused the decoder. A probe's own
fixed ceiling (an lzop or mozlz4 block, a bzip3 block size over 16 MiB, a zstd window
over 128 MiB) and a `ResourceUnavailableError` (a decoder child that could not run) are
not the caller's setting, and SHALL stay an INFO log on `archivey.detection`.

#### Scenario: a probe ceiling is not the caller's cap

- **WHEN** a `.tar.zst` whose window is over 128 MiB is detected with no cap
- **THEN** it is `ZST` with `inner_tar` recorded as `CAPABILITY_UNAVAILABLE`, and no `DETECTION_DECODER_LIMITED` is emitted

### Requirement: Detection limit context

The context of `DETECTION_DECODER_LIMITED` SHALL be `DetectionDecoderLimitContext`, a
member of the `DiagnosticContext` union: `kind="detection_decoder_limit"`,
`archive_name`, `tier` ∈ `{"inner_tar","content_probe","probe_completion"}` (the
receipt's name for the step), `stream_format` (the codec's `StreamFormat` name),
`max_decoder_memory` (the cap) and `needed` (what the decoder would have reserved, or
`None` when the decoder only says it is over the cap, as libzstd does for a window).

#### Scenario: detection limit context fields

- **WHEN** the `.tar.zst` with an 8 MiB window is detected under a 4 MiB cap
- **THEN** the context is `tier="inner_tar"`, `stream_format="ZSTD"`, `max_decoder_memory=4194304`, `needed=None`, and the message names `max_decoder_memory=4194304`

### Requirement: The detection limit code is advisory

`DETECTION_DECODER_LIMITED` SHALL NOT be a member of `ARCHIVE_INTEGRITY_CODES`: it
reports the caller's cap, not the archive's bytes, and the read that follows refuses
the same decoder with `ResourceLimitError`. Its log record is WARNING, as for any code
outside `_INFO_LOG_CODES`.

#### Scenario: the detection limit code under policies

- **WHEN** the `.tar.zst` above is detected under `DiagnosticPolicy.STRICT`
- **THEN** detection answers `ZST` and does not raise
- **WHEN** it is detected with `raise_on=["detection_decoder_limited"]`
- **THEN** `detect_format` raises `DiagnosticRaisedError`
