## Implementation blocks

Three PRs, in order. Block 1 gives every reader the payload end, so a signed installer
stops warning about its own certificate and the ZIP reader searches where the tail probe
will. Block 2 is the tail probe, which fixes the missed file and relies on Block 1's end.
Block 3 is the overlay-start rule. Each reuses Block 1's PE layout helper.

## 1. PE layout, `payload_end` and `prefixed` (Block 1)

- [x] 1.1 Test helper: build a minimal PE (DOS header, `PE\0\0`, optional header with data
      directories, section table) with a chosen section layout, overlay bytes and
      certificate entry.
- [x] 1.2 `internal/sfx.py`: `PeLayout` and a parser from the prefix bytes (design §2).
      Unit tests: unsigned, signed, certificate not at end, section table past the prefix,
      overflowing fields, PE32 and PE32+.
- [x] 1.3 `FormatInfo.prefixed: bool = False` and `FormatInfo.payload_end: int | None =
      None`, added last (design §11, §12); set on every `sfx_scan` answer; the `info` CLI
      verb prints both; tests for the scenario rows of *detect_format() returns a
      FormatInfo*.
- [x] 1.4 `ReadBackend.open_read` takes an end offset beside `start_offset`;
      `open_archive` passes `payload_end`, and under a forced `format=` reads it itself
      from the source's first 4096 bytes with the PE helper for a backend with
      `SFX_MAGIC` (design §12); no backend derives one. Detection reads the layout from
      those 4096 bytes whatever `max_prefix_bytes` says. No scan accepts a candidate at or
      past a known payload end.
- [x] 1.5 Readers honour the end: the ZIP end-record search ends there; the ZIP, 7z and RAR
      trailing-data checks stop there. Update the 7z reader's `_report_trailing_data`
      docstring, which records the reversed rule, and any test that pins a warning on a
      certificate.
- [x] 1.6 Tests for the new rows of the `archive-reading`, `format-zip`, `format-7z` and
      `format-rar` scenarios, each through auto-detect and forced `format=`, including a
      ZIP whose offsets count from byte 0 behind a certificate over 64 KiB.
- [x] 1.7 Docs: the `FormatInfo.payload_offset` docstring and `docs/opening.md`, which call
      `payload_offset > 0` the test for a self-extractor (name `prefixed`, describe the
      base-0 case); `docs/formats.md` on trailing-data warnings for signed installers;
      the changelog entry for `prefixed` and `payload_end` (left to the release, which
      writes the changelog); `prefixed-archives.md` §6 (the
      row saying `prefix_kind` "is not shipped") and its §9 in-flight note, which name
      `prefixed` as the yes-or-no part of the struck `prefix_kind` (design §11).
- [x] 1.8 Handbook pages for the certificate rule (design §12): `7z.md` §5 Sharp edges
      (the row saying "`STRICT` refuses a signed self-extractor") and §8 Verify ("SFX tail
      measured from the archive's end"); a §6 Decisions row in `7z.md` with the reversal,
      the decider and date, and what would reopen it (a caller that needs to tell an
      identified certificate from unexplained bytes); `zip.md` and `rar.md` point at that
      row.

## 2. The ZIP tail probe (Block 2)

- [x] 2.1 `zip_parser`: expose the end-record checks of design §5 as one function taking
      `read_at`, the end-record offset and the overlay start; reuse
      `locate_classic_record` for the search.
- [x] 2.2 `PrefixWorkspace.read_tail`: take an end offset and the tier name a decline is
      recorded under (design §7); the trailer step passes `trailer`. Receipt and records:
      tail bytes in `unique_bytes_read`, not `scanned_bytes`; prefix-held bytes not fetched
      again; `sfx_tail` *not enabled by policy* / *capability unavailable*; nothing
      recorded for an excluded source. Add the tail allowance to `within_budget`
      (`tests/detection_cost_util.py`) on the condition the validator allowance uses,
      `scanned_bytes > 0`; no new receipt field.
- [x] 2.3 `internal/detection.py`: the tail probe after a scan miss, gated as in the spec,
      answering `ZIP` / `PROBABLE` / `sfx_scan` with `payload_offset` = the EOCD-derived
      base (design §10, maintainer decision), `prefixed=True`, and `payload_end`.
- [x] 2.4 Tests for every row of the tail-probe matrix, the receipt scenario and the
      access-shape rows, including both ZIP write conventions and a certificate larger than
      64 KiB.
- [x] 2.5 Docs: `prefixed-archives.md` (§2 tier table, §3 cost, §7 decisions), `detection.md` (tier list and the "no ZIP tail probe" lines),
      `docs/formats.md` (SFX bullet), and a pointer from the struck Block 2 note in
      `archive/2026-11-05-prefixed-archive-detection/tasks.md`.

## 3. Overlay start first (Block 3)

- [x] 3.1 `internal/detection.py`: judge the candidate at the overlay start before the
      forward scan; `VALID` and `VALID_SHORT` there both answer (design §3).
- [x] 3.2 `rar_parser._find_sfx_header`, the 7z signature search and
      `ZipForwardReader._scan_for_local_header`: take the same layout and apply the same
      rule, so forced `format=`, seekable or streaming, agrees.
- [x] 3.3 Tests for every row of the overlay-start scenario, each checked through both
      `detect_format` and forced `format=` (streaming too for the ZIP row).
- [x] 3.4 `IDEAS.md` "Bound the SFX search at the PE overlay": 3.1 covers every PE whose
      layout parses; narrow the entry to stubs without one (bare `MZ`, ELF, Mach-O), and
      keep `test_short_7z_hit_scan_cost_is_bounded_by_the_window` as it is.
- [x] 3.5 Docs: `prefixed-archives.md` §2 and `docs/formats.md` SFX bullet.

## 5. ELF and Mach-O overlay start (maintainer decision 2026-11-07)

- [x] 5.1 `internal/sfx.py`: `executable_layout` returns the overlay start of an ELF
      (header, program headers, segments, section header table, and each section when
      that table is in the prefix, as the Go linker writes it), a thin Mach-O (load
      commands, segments) or a fat Mach-O (last slice), with no payload end; `PeLayout`
      becomes `ExecutableLayout`. Headers that do not fit the prefix give no layout.
- [x] 5.2 Detection's overlay-start judgement, `overlay_start_of` (RAR and 7z parser
      scans) and the forward ZIP walk use it; the tail probe keeps `pe_layout`.
- [x] 5.3 Tests: the layouts (ELF32/64, both byte orders, no section table, extended
      numbering, headers past the prefix; thin 32/64 and fat Mach-O; a Java class
      file), and the overlay-start rows through detection and forced `format=`,
      streaming too for ZIP (`tests/test_executable_overlay.py`).
- [x] 5.4 Docs: `docs/formats.md` SFX bullet, `prefixed-archives.md` §2, `7z.md` §6,
      `IDEAS.md`.

## 4. Verify

- [x] 4.1 `./scripts/check.sh --fix` and `./scripts/test.sh` (each of #1303, #1304, #1306,
      #1311; the one failure, `test_prepare_holds_history_up_to_head_only`, fails on main
      too)
- [x] 4.2 By hand, on the installers in the design's table: IRPF detects as `ZIP`; WinRAR's
      installer opens with no trailing-data warning, while GitHub Desktop's still warns
      (its ZIP sits inside `.rsrc`, so program bytes follow it); the other files
      give the same answers as today; record timings before and after for one large file.
      Done 2026-11-11 on main (dcf2a69) against a7353d74 (before #1303), auto-detect and
      forced `format=` giving the same answer on every file:
      - IRPF 2026 1.3: was `FormatDetectionError`; now `ZIP` at 35 536 406, `payload_end`
        110 923 264, 174 members, no trailing data, opens under `STRICT`. Forced
        `format=ZIP` listed the same 174 members with a trailing-data warning before.
        Detection 11 ms (a miss) before, 24 ms (the tail probe) after; forced open 12 ms
        before, 26 ms after.
      - WinRAR 7.22: 28 members both before and after; the trailing-data warning is gone.
      - GitHub Desktop: `ZIP` at 169 888, 5 members, still warns (and `STRICT` refuses),
        as before.
      - 7-Zip 26.01: `SEVEN_Z` at 46 080, 107 members, unchanged. Git for Windows 2.51
        (Inno Setup) and Notepad++ 8.9.8.1 (NSIS): refused, unchanged.
- [x] 4.3 `openspec validate --strict pe-aware-sfx-location`: no errors; 11 warnings, all
      the table-form scenarios and long requirements the main specs carry too
- [x] 4.4 At archive: amend the `detection-cost` Purpose note, which expects a tail probe
      to bring its own budget field, to say the PE gate stands in for one (design §8)
