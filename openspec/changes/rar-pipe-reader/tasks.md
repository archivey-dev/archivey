## 1. Forward walk

- [ ] 1.1 Forward view over `ArchiveSource`: own position, seek to here is a no-op,
  forward seek skips, backward seek raises
- [ ] 1.2 `_Rar5Walk.blocks()` / `_Rar3Walk.blocks()` yield each member with its header
  bytes before the data skip; `run()` drains them (seekable path unchanged)
- [ ] 1.3 `forward=True` switch: no quick-open, no end-of-source seeks, no seek back
  after the trailing or zeros scan, SFX skip by `start_offset`
- [ ] 1.4 Walk tests: every committed RAR fixture walked forward lists what `run()`
  lists

## 2. Forward reader

- [ ] 2.1 `RarForwardReader` routed by `RarReadBackend.open_read` for a non-seekable
  source; `SUPPORTS_STREAMING_NON_SEEKABLE = True`
- [ ] 2.2 Open walks `MAIN` / `ENCRYPTION`; refusals of design Decision 8 and Decision 5
  (RAR 1.5-4 candidates)
- [ ] 2.3 Synthetic members from the header bytes the walk read (no re-read), data from
  a bounded view of the forward source
- [ ] 2.4 The pass: rolling volumes over the walk generator, members queued to the
  caller's thread, demultiplexed with the solid pass's checks
- [ ] 2.5 Running metadata budget and dictionary costs; RAR5 data password from the
  first PswCheck in the first volume
- [ ] 2.6 File copies refused on first read; links and directories as in the seekable
  pass; a failed member ends the pass

## 3. Tests and docs

- [ ] 3.1 `tests/test_rar_forward.py`: every committed RAR fixture from a pipe against
  the seekable reader; solid, nonsolid, `-p`, `-hp`, RAR 1.5-4; refusals; spool peak;
  early close removes the volumes
- [ ] 3.2 `docs/formats.md`, `docs/opening.md`, `docs/security.md`,
  `dev-docs/formats/rar.md`, `dev-docs/threat-model.md`
- [ ] 3.3 Sync the delta specs and archive this change in the PR that finishes it
