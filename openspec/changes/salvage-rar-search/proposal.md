# Salvage, step 4: search past RAR header damage

## Why

The default RAR walk follows a damaged header's own sizes when the next headers confirm
them (`2026-11-21-salvage-step-1`). It cannot cross damage that no size confirms: a
zeroed region, a size field that is itself the damaged byte, deleted bytes, a lost
start, a damaged volume. `unrar` stops there too. In the salvage corpus that is most of
what is left: on damaged copies of committed fixtures, the default reads 2 168 members
of a 256-member RAR5 archive over 15 damaged copies, `unrar` 2 207, and a header search
3 355 (`design.md` §1).

Step 3 (`salvage-mode`) adds `open_archive(salvage=True)`, the search driver, its
budget and its diagnostics, and uses them for TAR, CPIO and ar. This change uses the
same API for RAR, the format the salvage design measured as having the most to gain.

## What Changes

- **RAR5 header search.** After the default walk stops, salvage searches each byte for
  a header that passes its CRC-32. The filter before the CRC checks only what the RAR5
  format note and the walk require. It puts no condition on the header flags: the
  design prototype's flags filter dropped every member that continues into the next
  volume. A found RAR5 header is confirmed by its 32-bit CRC, claims its data, and the
  normal walk goes on after it.
- **RAR 1.5-4 header search.** The same for FILE and SUB headers, checked by their
  CRC16. A found header is confirmed when the position after its data confirms by step
  1's rule for a second header; otherwise it is listed with `confirmed=False`, and the
  search goes on inside it.
- **Headers that are not members**: nested MAIN and ENCRYPTION headers, end blocks
  reached after a search, and quick-open header copies are recognised and not listed.
- **Solid archives.** A found member whose solid stream lost bytes before it raises on
  read without running `unrar`. A found member that starts a new solid stream, or is
  stored, reads.
- **Lost start.** No signature, a damaged MAIN, or a later volume whose start is lost:
  the search starts at the beginning, the version comes from the first confirmed header,
  and the solid and volume flags come from the file headers or from volume 1.
- **Volume sets.** After a volume that ends at damage, salvage goes on into the later
  volumes present. A missing volume is unchanged: the default already lists past it.
- **Reading found members**: stored ones directly, others through `unrar` on a
  synthetic archive (`rar_synthetic.py`), never on the original archive.
- **Encrypted headers**: no search; `SALVAGE_UNAVAILABLE`.
- **Diagnostics**: the step-3 codes. `SalvageScanContext` and `RegionSkippedContext`
  get `volume_index`, and `method` gets `"next_volume"`.

New public names: the `volume_index` context field and the `"next_volume"` method value.
No new code, no new keyword, no config field. `salvage=False` reads exactly as before.
Release note: **Added** (with step 3's salvage entry).

Out of scope: QO copies as a second copy for a lost header, a search in RAR5 `-hp`
archives, and three default-mode gaps found while measuring (`design.md` §16, §17).
Recovery records are not used (Q13).

## Capabilities

### New Capabilities

None.

### Modified Capabilities

- `format-rar`: header search, lost start, later volumes, reading found members, and
  encrypted headers, all in salvage mode.
- `diagnostics`: `volume_index` on the two salvage contexts, `method="next_volume"`, and
  `SALVAGE_UNAVAILABLE` for header-encrypted RAR (on top of `salvage-mode`'s
  requirement).

## Impact

- `src/archivey/internal/backends/rar_search.py` (new): the two finders, the
  prefix-CRC check for large candidates, the QO-record test.
- `src/archivey/internal/backends/rar_parser.py`: both walks call the step-3 driver at
  each stop point; confirmation; the lost-start and damaged-MAIN entry; volume merge
  after a damaged volume; `RarMemberInfo` records how a member was found;
  `RarArchive` records the lost ranges per volume.
- `src/archivey/internal/backends/rar_reader.py`: the diagnostics; the solid-chain rule;
  the synthetic route for every found member; the `unar` refusal; `supports_salvage`.
- `src/archivey/internal/backends/rar_synthetic.py`: a chain that holds found headers.
- `src/archivey/diagnostics.py`: the two context fields.
- `internal/salvage.py` (step 3): window size from the overlap; reject a candidate
  without ending the region (`design.md` §15).
- `dev-docs/formats/rar.md`, `docs/` salvage page: the RAR rules.
