## 1. Forward walk

- [x] 1.1 `ForwardSource` over `ArchiveSource`: own position, forward seek skips, a seek
  back lands in the last 4 MiB read, anything else raises
- [x] 1.2 `_Rar5Walk.walk()` / `_Rar3Walk.walk()` yield each member before the data
  skip; `run()` drains them (seekable path unchanged)
- [x] 1.3 `open_forward_walk`: no quick-open, end-of-source checks answered by what the
  source holds (`holds`), SFX skip by `start_offset`
- [x] 1.4 Walk tests: every committed RAR fixture walked forward lists what `run()`
  lists

## 2. Forward reader

- [x] 2.1 `RarForwardReader` routed by `RarReadBackend.open_read` for a non-seekable
  source; `SUPPORTS_STREAMING_NON_SEEKABLE = True`
- [x] 2.2 Open walks `MAIN` / `ENCRYPTION`; refusals of design Decision 8 and Decision 5
  (RAR 1.5-4 data candidates refused per member)
- [x] 2.3 Synthetic members from the header bytes the walk read (no re-read), data from
  a bounded view of the forward source
- [x] 2.4 The pass: rolling volumes over the walk generator, members queued to the
  caller's thread, demultiplexed with the solid pass's checks
- [x] 2.5 Running metadata budget and dictionary costs; RAR5 data password from the
  first PswCheck in the first volume
- [x] 2.6 File copies refused on first read; links and directories as in the seekable
  pass; a failed member ends the pass

## 3. Tests and docs

- [x] 3.1 `tests/test_rar_forward.py`: every committed RAR fixture from a pipe against
  the seekable reader; solid, nonsolid, `-p`, `-hp`, RAR 1.5-4; refusals; spool peak;
  early close removes the volumes
- [x] 3.2 `docs/formats.md`, `docs/opening.md`, `docs/security.md`,
  `dev-docs/formats/rar.md`, `dev-docs/threat-model.md`
- [x] 3.3 Sync the delta specs and archive this change in the PR that finishes it
