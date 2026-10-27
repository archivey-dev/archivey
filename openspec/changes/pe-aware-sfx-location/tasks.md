## Implementation blocks

Two PRs, in order. Block 1 fixes the missed file; Block 2 is the overlay-start rule, which
reuses Block 1's helper.

## 1. PE layout helper and the ZIP tail probe (Block 1)

- [ ] 1.1 Check first that the ZIP reader, opened at a `payload_offset` behind a PE stub,
      reaches an end record hidden by more than 65 558 bytes of tail through its
      local-header walk. If it walks from byte 0 instead, stop and settle design §4 again
      before going on.
- [ ] 1.2 Test helper: build a minimal PE (DOS header, `PE\0\0`, optional header with data
      directories, section table) with a chosen section layout, overlay bytes and
      certificate entry.
- [ ] 1.3 `internal/sfx.py`: `PeLayout` and a parser from the prefix bytes (design §2).
      Unit tests: unsigned, signed, certificate not at end, section table past the prefix,
      overflowing fields, PE32 and PE32+.
- [ ] 1.4 `zip_parser`: expose the end-record checks of design §5 as one function taking
      `read_at`, the end-record offset and the overlay start; reuse
      `locate_classic_record` for the search.
- [ ] 1.5 `internal/detection.py`: the tail probe after a scan miss, gated as in the spec,
      answering `ZIP` / `PROBABLE` / `sfx_scan` with `payload_offset` = the EOCD-derived
      base (design §10, maintainer decision); decline a base-0 record outside the last
      65 558 bytes.
- [ ] 1.6 `PrefixWorkspace.read_tail`: take an end offset and the tier name a decline is
      recorded under (design §7); the trailer step passes `trailer`. Receipt and records:
      tail bytes in `unique_bytes_read`, not `scanned_bytes`; prefix-held bytes not fetched
      again; `sfx_tail` *not enabled by policy* / *capability unavailable*; nothing
      recorded for an excluded source. Add the tail allowance to the test suite's
      within-budget check.
- [ ] 1.7 Tests for every row of the tail-probe matrix and the receipt scenario,
      including both ZIP write conventions and a certificate larger than 64 KiB.
- [ ] 1.8 Docs: `prefixed-archives.md` (§2 tier table, §3 cost, §6 sharp edges, §7
      decisions), `detection.md` (tier list and the "no ZIP tail probe" lines),
      `docs/formats.md` (SFX bullet), a pointer from the struck Block 2 note in
      `prefixed-archive-detection/tasks.md`, and the `FormatInfo.payload_offset`
      docstring and `docs/opening.md`, which call `payload_offset > 0` the test for a
      self-extractor: name `prefixed` as the test and describe the base-0 case.
- [ ] 1.9 `FormatInfo.prefixed: bool = False`, added last (design §11); set on every
      `sfx_scan` answer, the tail probe's included; the `info` CLI verb prints it; tests
      for the scenario rows of *detect_format() returns a FormatInfo*.

## 2. Overlay start first (Block 2)

- [ ] 2.1 `internal/detection.py`: judge the candidate at the overlay start before the
      forward scan; `VALID` and `VALID_SHORT` there both answer (design §3).
- [ ] 2.2 `rar_parser._find_sfx_header`, the 7z signature search and
      `ZipForwardReader._scan_for_local_header`: take the same layout and apply the same
      rule, so forced `format=`, seekable or streaming, agrees.
- [ ] 2.3 Tests for every row of the overlay-start scenario, each checked through both
      `detect_format` and forced `format=` (streaming too for the ZIP row).
- [ ] 2.4 `IDEAS.md` "Bound the SFX search at the PE overlay": 2.1 covers every PE whose
      layout parses; narrow the entry to stubs without one (bare `MZ`, ELF, Mach-O), and
      keep `test_short_7z_hit_scan_cost_is_bounded_by_the_window` as it is.
- [ ] 2.5 Docs: `prefixed-archives.md` §2 and `docs/formats.md` SFX bullet.

## 3. Verify

- [ ] 3.1 `./scripts/check.sh --fix` and `./scripts/test.sh`
- [ ] 3.2 By hand, on the installers in the design's table: IRPF detects as `ZIP`; the
      other files give the same answers as today; record timings before and after for one
      large file
- [ ] 3.3 `openspec validate --strict pe-aware-sfx-location`
- [ ] 3.4 At archive: amend the `detection-cost` Purpose note, which expects a tail probe
      to bring its own budget field, to say the PE gate stands in for one (design §8)
