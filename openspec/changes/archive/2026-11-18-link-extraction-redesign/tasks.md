## 0. Decisions

- [x] 0.1 D1 placeholders (maintainer, 2026-11-17): chosen.
- [x] 0.2 D2 refuse writes under the run's own symlinks (maintainer, 2026-11-17): chosen,
      under every policy, `TRUSTED` included, in the next minor release.
- [x] 0.3 D3 streaming exception: kept as the documented difference between the modes.

## 1. Fuzzer as a test

- [x] 1.1 `tests/test_link_parity_property.py` (#1638): the strategy from
      `evidence/linkfuzz.py`; held, stream and dry runs against the made run; every
      overwrite policy and extraction policy.
- [x] 1.2 (#1638) No `xfail` list: the one known difference, the D3 streaming
      exception, is checked as such. The case-insensitive held-link mismatch the
      test found was fixed in #1641. Every CI leg runs 300 fixed
      examples; the daily `link-parity-soak` job runs 20,000 random ones on Linux and
      8,000 on macOS.

## 2. Placeholders (D1): #1620

- [x] 2.1 First pass: a held link runs the FILE path with empty data; later links to the
      same source link to it.
- [x] 2.2 Second pass: the source is read once and fills each name that still holds its
      placeholder (same device, inode, size 0), at the physical path where it was made.
- [x] 2.3 Failures: a source failure removes its placeholders and fails its links as one
      group.
- [x] 2.4 `OnError.STOP` and a member fault fill the placeholders made before the stop.
- [x] 2.5 Reservation model removed (`reservations`, `_meet_reservation`,
      `_reservation_at`, `_folds_case`, the orphan queue).
- [x] 2.6 S1: a link to the parked earlier copy of its own name is made to that copy.
- [x] 2.7 Spec: the held-link paragraph and rows of "Hardlink Two-Pass Extraction".

## 3. Leaves (D2, next minor): #1622, with the scope rule in #1621

- [x] 3.1 Refuse a member whose parent reaches a run symlink (`_refuse_through_run_link`,
      matched by device and inode, so a case variant is refused too).
- [~] 3.2 Not done, on purpose: the physical-path bookkeeping stays. A symlink the caller
      had in `dest` is still followed and can then be replaced by the archive's own link,
      so the superseded-copy take-back and the placeholder fill still need it.
- [x] 3.3 Spec, `docs/extracting.md`, threat model, `needs-minor` label.

## 4. Later

- [~] 4.1 Not started: a spec model as an oracle.
- [~] 4.2 Not started: a planned single pass from a free listing.
