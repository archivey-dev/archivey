# Tasks — stage, then place, a ZIP extracted from a pipe

## 0. Before coding

- [x] 0.1 The maintainer rules on the two Open Questions in `design.md`: whether staged
      data is extraction output or implicit temporary storage, and the progress order.
      If it is storage, add the `format-zip` declaration and the `spool_limits` clause
      to the deltas; if output, add a sentence to the `archive-reading` delta saying
      "Bounded implicit temporary storage" does not reach extraction output.
      The implementation took both recommended answers (output, and the order of
      Decision 5), and the `archive-reading` sentence is added. The maintainer
      ratified both during PR 920's review (2026-10-20) and again on 2026-10-25.
- [x] 0.2 `openspec validate --strict pipe-zip-stage-then-commit`.

## 1. Groundwork (no behaviour change)

- [x] 1.1 Extract the forward pass's per-member body (`_run_pass`'s loop body) into one
      function that takes a member and its stream, and run the forward pass through it.
      The full suite passes unchanged.
- [x] 1.2 Add the staged-file landing to `_write_file_atomic` (Decision 4) behind a
      parameter nothing passes yet, with a unit test: metadata applied, bytes not
      counted again, the source name gone after the landing.

## 2. Staging

- [x] 2.1 For a reader with `_REVISES_YIELDED_MEMBERS`, the pass stages each member the
      selection may take into `<dest_root>/.archivey-tmp-<uuid>/<index>` (Decision 2):
      no filter call, recorded-size check before decoding, bomb limits counted when
      staged.
- [x] 2.2 The universal checks and the name policy run on the local header's name
      before staging (Decision 2). A test: a first member `../../etc/passwd` under
      `abort_on={BLOCKED_MEMBER}` raises before the second member is decoded.
- [x] 2.3 A data failure while staging stops an `OnError.STOP` run at once, and under
      `OnError.CONTINUE` is decided at placement.
- [x] 2.4 Remove the staging directory in the run's `finally`, opening up modes first; a
      refused removal stays, with a warning (test with a read-only staged file on
      Windows, and an unremovable directory via a patched `rmdir`).

## 3. Placement

- [x] 3.1 After the walk, place the final listing in order through the function from
      1.1: staged file as the stream, `_PassedData` where nothing was staged, the
      end-of-walk failures and missing members as results in listing order
      (Decision 3).
- [x] 3.2 Refund from the byte cap and the entry count each staged member that is not
      placed; the archive-wide ratio keeps it (Decision 5).
- [x] 3.3 Progress: each member's reports while it is staged, and one report with the
      final tallies after placement (Decision 5).
- [x] 3.4 `MEMBER_SELECTOR_UNMATCHED` is reported after the walk, before placement.

## 4. Delete the revision machinery

- [x] 4.1 Remove the functions, `_RunState` fields and `_MemberState` fields Decision 7
      names, and every call to them. Nothing outside `internal/extraction.py` refers to
      them; check with `grep`.
- [x] 4.2 Re-read every comment in `internal/extraction.py` that names a removed function
      or describes revising a written member; `scripts/review_prep.py` sweeps the docs.

## 5. Specs and docs

- [x] 5.1 Update `tests/` that pin today's pipe-ZIP behaviour to the delta specs: the
      stopped-run take-back, the caller's entries moved aside, the filter called twice,
      the `docs\r.txt` filter case.
- [x] 5.2 `docs/extracting.md`: the leftover note covers a `.archivey-tmp-*` directory
      and says the entries are safe to delete once no extraction is running; the
      pipe-ZIP section states what a stopped run leaves.
- [x] 5.3 `dev-docs/formats/zip.md`, `native-zip-reader/design.md` and
      `dev-docs/threat-model.md` (the temp-sibling write and the leftover residual):
      point the end-of-pass description at this change for the extraction side.

## 6. Verify

- [x] 6.1 Every scenario row in the three delta specs has a test; the changed rows fail
      on `main` (`scripts/review_prep.py red-on-base`).
- [x] 6.2 `./scripts/check.sh`, `./scripts/test.sh` and `./scripts/test.sh --all-configs`.
- [x] 6.3 `openspec validate --strict pipe-zip-stage-then-commit`.
- [x] 6.4 Dry-run the archive: apply it on a scratch tree, read the **diff** of
      `openspec/specs/` (not the modified count, which cannot tell an intended edit from
      a deletion), then reset. Every delta here replaces a whole requirement block.
- [x] 6.5 `openspec archive pipe-zip-stage-then-commit` in the implementing PR, as its
      last task.
