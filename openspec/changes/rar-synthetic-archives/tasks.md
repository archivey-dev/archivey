## 1. Decisions

- [ ] 1.1 Maintainer decides D1-D4 (`design.md` §"Decisions for the maintainer"); record the rulings in `design.md` and `dev-docs/formats/rar.md` §6
- [ ] 1.2 Update the spec deltas to the rulings if they differ from the recommendations

## 2. Spec deltas that follow the decisions

- [ ] 2.1 MODIFIED `Serve random access and extraction with bounded explicit temp use`: stream sources copy one member, chain or batch, not the archive; the open-time `CostReceipt.notes` caveat says so; path sources are bounded by the spool limit for synthetic copies
- [ ] 2.2 MODIFIED `Constrain unrar argv by call site`: the synthetic-file argv, `-ver` on every synthetic read, the placeholder mask
- [ ] 2.3 MODIFIED `Stream solid RAR archives through one unrar pipe`: one `unrar` run per solid stream, from a synthetic file
- [ ] 2.4 Under D1 = A or B: REMOVED `Return a named member's own bytes when its mask selects others`, `Refuse a glob member name whose mask also matches earlier members` and `Under auto, read a member unrar cannot name with unar`
- [ ] 2.5 Under D4: MODIFIED `archive-reading` config schema to mark `rar_allow_glob_member_concatenation` deprecated
- [ ] 2.6 MODIFIED `Count the RAR dictionary against the decoder memory cap` and the `RewindWarning` floor: count the chain, not the archive prefix

## 3. Writer

- [ ] 3.1 New module beside `rar_unrar.py`: build the signature, MAIN and ENDARC for RAR5 and RAR 1.5-4, and patch a stored FILE header (placeholder name, Unicode flag, split flags, packed size, header size, CRC)
- [ ] 3.2 Re-read each needed header from the source (decrypting with the cached key for `-hp`) and check its CRC against the listing
- [ ] 3.3 RAR 1.5-4 joined member past 4 GiB: insert the high size fields, or keep the original route
- [ ] 3.4 Unit tests for the writer: every committed RAR fixture member, synthetic read byte-identical to `unrar p` on the original

## 4. Reader

- [ ] 4.1 `_open_member_with_program`: route per D1; spool budget per copy; temp file lifetime tied to the member stream and respawn
- [ ] 4.2 Solid chains: chain start from the per-member solid flag; dictionary cost and `_solid_prefix` per chain
- [ ] 4.3 Solid streams: one synthetic file per stream for the reader's lifetime, extended by appending (rewrite ENDARC); a solid pass reads it with one `unrar` run
- [ ] 4.4 Nonsolid pass batching (D3) with the per-member fallback
- [ ] 4.5 Remove `_ensure_archive_path`'s whole-archive copy where no route needs it any more; keep it for `unar`
- [ ] 4.6 Under D1 = A or B: remove the mask model, the dot-rule probe, the glob refusal and the `unar` fallback for unaddressable names; deprecate the config flag (D4)

## 5. Measurement and compatibility

- [ ] 5.1 Run `scripts/exploration/rar_synthetic_probe.py` on each pinned `unrar` (Linux 7.00, Windows WinRAR 7.23, the 6.x floor)
- [ ] 5.2 RAR 1.5 and 2.x fixtures and the RAR corpus: synthetic read equals the original read
- [ ] 5.3 A solid archive with NTFS streams (`rar -os -s`) on Windows: service headers inside a chain
- [ ] 5.4 Benchmarks: rerun the `open()`, `extract_all()` and stream-source rows of `design.md` and record them in the PR

## 6. Docs

- [ ] 6.1 `dev-docs/formats/rar.md` §2.3, §6 and §7: the new routes, the measurements, the settled §7 question
- [ ] 6.2 `docs/` security and formats pages: what a synthetic temp file holds for `-hp` archives, and the smaller stream-source copy
- [ ] 6.3 `openspec validate --strict rar-synthetic-archives`
