# Tasks — salvage step 4 (RAR)

Three PRs, after step 3's switch PR (`salvage-mode` §1).

## 0. Design

- [x] 0.1 Rulings carried from the salvage design §0 (2026-11-20); measurements in
  `design.md` §1.
- [ ] 0.2 Maintainer review of this change and its open questions (`design.md` §17).
- [ ] 0.3 Agree the four driver additions with step 3 (`design.md` §15) before PR 1.

## 1. Finders and the search (PR 1)

- [ ] 1.1 `rar_search.py`: `find_rar5_header` and `find_rar3_header` (`design.md` §3,
  §4); the prefix-CRC check for candidates over 4 KiB; the QO-record test.
- [ ] 1.2 Unit tests: every header of every committed plain-header RAR fixture is
  found (recall, both versions); a FILE header with split flags is found; no false
  header in 16 MiB of seeded random bytes for RAR5; the crafted 2 MiB-candidate input
  finishes within a bound; prefix CRCs equal direct CRCs.
- [ ] 1.3 `rar_parser.py`: both walks call the driver at each stop point of §2;
  confirmation (§5); the headers of §6; `RarMemberInfo` records the find (method,
  offset, confirmed); the lost ranges per volume. The `CorruptionError` text under
  salvage.
- [ ] 1.4 Tests on damaged copies made in the test from committed fixtures
  (`many_list_store_nonsolid__.rar`, `many_list_store__.rar`, `basic_*__rar4.rar`, and a
  RAR 2.9 archive written by the test): the 15 damage kinds of `design.md` §1; the
  add-only prefix check (the default's members and diagnostics first, unchanged); zero
  listed members outside the original; `salvage=False` unchanged; `unrar lb` / `unrar x`
  counts pinned in a test that skips without `unrar` (DR-24); `STRICT`.

## 2. Lost start and volumes (PR 2, stacked on 1)

- [ ] 2.1 Lost start (§8.1): both finders, version from the first confirmed header,
  buffered RAR 1.5-4 candidates, flags from file headers. Damaged MAIN (§8.2). A later
  volume's lost start with volume 1's flags (§8.3).
- [ ] 2.2 Volumes (§9): go on after a damaged volume; the join rule; `next_volume`.
- [ ] 2.3 Tests: head deleted, signature zeroed, MAIN damaged, `.bin` with and without
  `format="rar"`; five-volume sets made in the test (or committed `tinyvol*` sets) with
  a volume zeroed inside, at its start, and missing.

## 3. Reading found members (PR 3, stacked on 1)

- [ ] 3.1 `rar_reader.py`: the solid-chain rule (§7) before any program runs; the
  synthetic route for every found member (no include-mask read, no one-pipe pass over
  the original); the `unar` refusal; `verifiable` (§13); `supports_salvage`.
- [ ] 3.2 `rar_synthetic.py`: a chain that holds found headers.
- [ ] 3.3 Tests: solid `-s`, solid groups `-s10`, stored solid; a found member over
  the in-place threshold (a test-only lower threshold); `extract_all()` and
  `stream_members()` over found members; `rar_decompressor="unar"`; `-hp` gives
  `SALVAGE_UNAVAILABLE`; `-p` found members with the password.

## 4. Docs and close

- [ ] 4.1 `dev-docs/formats/rar.md`: a salvage section (finders, confirmation, lost
  start, volumes, solid rule) with the measurements. User salvage page: RAR, and "run
  `rar r` or WinRAR's repair first" (Q13).
- [ ] 4.2 Sync specs, archive the change.
