## 0. Decisions

- [ ] 0.1 D1 placeholders (maintainer)
- [ ] 0.2 D2 refuse writes under the run's own symlinks (maintainer)
- [ ] 0.3 D3 streaming exception (maintainer)

## 1. Fuzzer as a test

- [ ] 1.1 `tests/test_link_parity_property.py`: Hypothesis strategy from
      `evidence/linkfuzz.py`; held, stream and dry runs against the made run; every
      overwrite policy and extraction policy.
- [ ] 1.2 Known mismatches as an `xfail` list keyed by shape; CI runs a small example
      count, the nightly schedule a large one.

## 2. Placeholders (D1)

- [ ] 2.1 First pass: a held link runs the FILE path with empty data; later links to the
      same source link to it.
- [ ] 2.2 Second pass: per source, read once to a temp file, move onto each name with
  the
      placeholder's identity, apply the link's metadata; no ordering between sources.
- [ ] 2.3 Failures: the recorded-size refusal and a failed read fail every surviving
  name
      of that source as one group and remove them.
- [ ] 2.4 `OnError.STOP` and an abort fill or remove the placeholders made before the
  stop.
- [ ] 2.5 Remove the reservation model (`reservations`, `_meet_reservation`,
      `_reservation_at`, `_folds_case`, `_SecondPass` ordering).
- [ ] 2.6 S1: a link to the parked earlier copy of its own name is made against it.
- [ ] 2.7 Spec: replace the held-link paragraph and rows of "Hardlink Two-Pass
  Extraction".

## 3. Leaves (D2, next minor)

- [ ] 3.1 Refuse a member whose parent reaches a run symlink, in the parent check.
- [ ] 3.2 Drop the physical-path bookkeeping kept only for run symlinks.
- [ ] 3.3 Spec, `docs/extracting.md`, threat model, `needs-minor` label.

## 4. Later

- [ ] 4.1 A spec model as an oracle, written without reading `extraction.py`.
- [ ] 4.2 Planned single pass from a free listing, if a solid-archive benchmark asks.
