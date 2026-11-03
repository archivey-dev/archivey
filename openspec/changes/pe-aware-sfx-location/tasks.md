## Implementation blocks

Three PRs, in order. Block 1 gives every reader the payload end, so a signed installer
stops warning about its own certificate and the ZIP reader searches where the tail probe
will. Block 2 is the tail probe, which fixes the missed file and relies on Block 1's end.
Block 3 is the overlay-start rule. Each reuses Block 1's PE layout helper.

## 1. PE layout, `payload_end` and `prefixed` (Block 1)

- [ ] 1.1 Test helper: build a minimal PE (DOS header, `PE\0\0`, optional header with data
      directories, section table) with a chosen section layout, overlay bytes and
      certificate entry.
- [ ] 1.2 `internal/sfx.py`: `PeLayout` and a parser from the prefix bytes (design §2).
      Unit tests: unsigned, signed, certificate not at end, section table past the prefix,
      overflowing fields, PE32 and PE32+.
- [ ] 1.3 `FormatInfo.prefixed: bool = False` and `FormatInfo.payload_end: int | None =
      None`, added last (design §11, §12); set on every `sfx_scan` answer; the `info` CLI
      verb prints both; tests for the scenario rows of *detect_format() returns a
      FormatInfo*.
- [ ] 1.4 `ReadBackend.open_read` takes an end offset beside `start_offset`;
      `open_archive` passes `payload_end`. A RAR, 7z or ZIP backend opened at start 0 with
      no end derives it from its own leading bytes with the PE helper (design §12): the
      RAR and 7z parser scans and the ZIP forward walk from the bytes they scan, the
      seekable `ZipReader._open_index` from one read of its first bytes. No scan accepts a
      candidate at or past a known payload end.
- [ ] 1.5 Readers honour the end: the ZIP end-record search ends there; the ZIP, 7z and RAR
      trailing-data checks stop there. Update the 7z reader's `_report_trailing_data`
      docstring, which records the reversed rule, and any test that pins a warning on a
      certificate.
- [ ] 1.6 Tests for the new rows of the `archive-reading`, `format-zip`, `format-7z` and
      `format-rar` scenarios, each through auto-detect and forced `format=`, including a
      ZIP whose offsets count from byte 0 behind a certificate over 64 KiB.
- [ ] 1.7 Docs: the `FormatInfo.payload_offset` docstring and `docs/opening.md`, which call
      `payload_offset > 0` the test for a self-extractor (name `prefixed`, describe the
      base-0 case); `docs/formats.md` on trailing-data warnings for signed installers;
      the changelog entry for `prefixed` and `payload_end`; `prefixed-archives.md` §6 (the
      row saying `prefix_kind` "is not shipped") and its §9 in-flight note, which name
      `prefixed` as the yes-or-no part of the struck `prefix_kind` (design §11).
- [ ] 1.8 Handbook pages for the certificate rule (design §12): `7z.md` §5 Sharp edges
      (the row saying "`STRICT` refuses a signed self-extractor") and §8 Verify ("SFX tail
      measured from the archive's end"); a §6 Decisions row in `7z.md` with the reversal,
      the decider and date, and what would reopen it (a caller that needs to tell an
      identified certificate from unexplained bytes); `zip.md` and `rar.md` point at that
      row.

## 2. The ZIP tail probe (Block 2)

- [ ] 2.1 `zip_parser`: expose the end-record checks of design §5 as one function taking
      `read_at`, the end-record offset and the overlay start; reuse
      `locate_classic_record` for the search.
- [ ] 2.2 `PrefixWorkspace.read_tail`: take an end offset and the tier name a decline is
      recorded under (design §7); the trailer step passes `trailer`. Receipt and records:
      tail bytes in `unique_bytes_read`, not `scanned_bytes`; prefix-held bytes not fetched
      again; `sfx_tail` *not enabled by policy* / *capability unavailable*; nothing
      recorded for an excluded source. Add the tail allowance to `within_budget`
      (`tests/detection_cost_util.py`) on the condition the validator allowance uses,
      `scanned_bytes > 0`; no new receipt field.
- [ ] 2.3 `internal/detection.py`: the tail probe after a scan miss, gated as in the spec,
      answering `ZIP` / `PROBABLE` / `sfx_scan` with `payload_offset` = the EOCD-derived
      base (design §10, maintainer decision), `prefixed=True`, and `payload_end`.
- [ ] 2.4 Tests for every row of the tail-probe matrix, the receipt scenario and the
      access-shape rows, including both ZIP write conventions and a certificate larger than
      64 KiB.
- [ ] 2.5 Docs: `prefixed-archives.md` (§2 tier table, §3 cost, §7 decisions), `detection.md` (tier list and the "no ZIP tail probe" lines),
      `docs/formats.md` (SFX bullet), and a pointer from the struck Block 2 note in
      `prefixed-archive-detection/tasks.md`.

## 3. Overlay start first (Block 3)

- [ ] 3.1 `internal/detection.py`: judge the candidate at the overlay start before the
      forward scan; `VALID` and `VALID_SHORT` there both answer (design §3).
- [ ] 3.2 `rar_parser._find_sfx_header`, the 7z signature search and
      `ZipForwardReader._scan_for_local_header`: take the same layout and apply the same
      rule, so forced `format=`, seekable or streaming, agrees.
- [ ] 3.3 Tests for every row of the overlay-start scenario, each checked through both
      `detect_format` and forced `format=` (streaming too for the ZIP row).
- [ ] 3.4 `IDEAS.md` "Bound the SFX search at the PE overlay": 3.1 covers every PE whose
      layout parses; narrow the entry to stubs without one (bare `MZ`, ELF, Mach-O), and
      keep `test_short_7z_hit_scan_cost_is_bounded_by_the_window` as it is.
- [ ] 3.5 Docs: `prefixed-archives.md` §2 and `docs/formats.md` SFX bullet.

## 4. Verify

- [ ] 4.1 `./scripts/check.sh --fix` and `./scripts/test.sh`
- [ ] 4.2 By hand, on the installers in the design's table: IRPF detects as `ZIP`; WinRAR's
      installer opens with no trailing-data warning, while GitHub Desktop's still warns
      (its ZIP sits inside `.rsrc`, so program bytes follow it); the other files
      give the same answers as today; record timings before and after for one large file
- [ ] 4.3 `openspec validate --strict pe-aware-sfx-location`
- [ ] 4.4 At archive: amend the `detection-cost` Purpose note, which expects a tail probe
      to bring its own budget field, to say the PE gate stands in for one (design §8)
