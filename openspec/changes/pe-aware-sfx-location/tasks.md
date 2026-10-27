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
      answering `ZIP` / `PROBABLE` / `sfx_scan` with `payload_offset` per design Open
      Questions (first entry, unless the maintainer decides otherwise).
- [ ] 1.6 Receipt and records: tail bytes in `unique_bytes_read`, not `scanned_bytes`;
      `sfx_tail` *not enabled by policy* / *capability unavailable*; nothing recorded for
      an excluded source.
- [ ] 1.7 Tests for every row of the tail-probe matrix and the receipt scenario,
      including both ZIP write conventions and a certificate larger than 64 KiB.
- [ ] 1.8 Docs: `prefixed-archives.md` (§2 tier table, §3 cost, §6 sharp edges, §7
      decisions), `detection.md` (tier list and the "no ZIP tail probe" lines),
      `docs/formats.md` (SFX bullet), and a pointer from the struck Block 2 note in
      `prefixed-archive-detection/tasks.md`.

## 2. Overlay start first (Block 2)

- [ ] 2.1 `internal/detection.py`: judge the candidate at the overlay start before the
      forward scan; a 7z ending at the payload end counts as exact-end.
- [ ] 2.2 `rar_parser._find_sfx_header` and the 7z signature search: take the same layout
      and apply the same rule, so forced `format=` agrees.
- [ ] 2.3 Tests for every row of the overlay-start scenario, each checked through both
      `detect_format` and forced `format=`.
- [ ] 2.4 Update `IDEAS.md` "Bound the SFX search at the PE overlay": the signed-7z case
      is covered by 2.1; keep what is left of it, or remove the entry.
- [ ] 2.5 Docs: `prefixed-archives.md` §2 and `docs/formats.md` SFX bullet.

## 3. Verify

- [ ] 3.1 `./scripts/check.sh --fix` and `./scripts/test.sh`
- [ ] 3.2 By hand, on the installers in the design's table: IRPF detects as `ZIP`; the
      other files give the same answers as today; record timings before and after for one
      large file
- [ ] 3.3 `openspec validate --strict pe-aware-sfx-location`
