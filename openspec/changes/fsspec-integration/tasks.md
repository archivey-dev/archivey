# Tasks — fsspec integration

> **Design only.** Nothing here starts before the `v0.2.0` tag. The order puts the
> benchmark first, so each later stage lands with its request counts measured against a
> committed baseline. Each numbered section is one pull request, or a few by context.

## 1. Remote benchmark axis

- [x] 1.1 `benchmarks/remote.py`: `CountingFileSystem` over local files, recording each
      range read, size/info call and `ls` (design §Benchmark).
- [ ] 1.2 Gated cases on `benchmarks/remote.py`'s own seeded `ci` scale, with member
      sizes varied (design §Benchmark) before 1.4 commits the baseline, and the planner
      constants set small through a private seam once it exists (stage 2); before that,
      today's code needs no seam. The production constants run on the `realistic` scale in the
      change-guarded nightly, reported and not gated.
- [ ] 1.3 Cases: list; first, middle and last member; `extract_all()`;
      `stream_members()` under `streaming=True`; eight threads reading eight ZIP members;
      more member streams than the pool's window limit. Record the four counts and
      `bytes_fetched / bytes_needed`, and print the modelled time.
- [x] 1.4 Run against today's code with a caller-opened fsspec file (no cache, and
      fsspec's default cache) and commit `benchmarks/baselines/remote.json`, so the
      planner's gain is a reviewed baseline diff.
- [ ] 1.5 `benchmarks/remote_http.py`: the same cases over a local range server and
      `HTTPFileSystem`; fail when its request counts differ from 1.3's. Off the PR path.

## 2. `OpenFile` sources and the fetch planner

- [ ] 2.1 `open_archive()`, `open_stream()` and `detect_format()` accept
      `fsspec.core.OpenFile`, alone and in sequences; the check runs only when `fsspec`
      is in `sys.modules`. Refuse a non-`"rb"` mode and a resolved compression. `name`
      is `of.path`; `size` is `fs.size()` as a fact. Test that a `str` that looks
      like a URL makes no request and that `import archivey` imports no fsspec.
- [ ] 2.2 `RangeSource`: size once, `cat_file` fetches, doubling from the third
      sequential read, read-through of short forward gaps, one 32 MiB window pool per
      reader with the shrinking-fetch rule and unbuffered reads past the window limit
      (design D2), and the private seam for the three internal constants. Add
      `ArchiveyConfig.max_read_through`, checked as the limit fields are. Unit-test the
      planner on a recorded read trace, independent of any format.
- [ ] 2.3 `ArchiveSource` uses `RangeSource` for an `OpenFile`; `seek_is_expensive` is
      `True`; `close()` drops the fetched windows, and nothing of the caller's is closed
      (no file object is ever opened).
- [ ] 2.4 Run the full corpus and the short-returning-source tests through a memory-backed
      `OpenFile`: identical listings and bytes to a path source.
- [ ] 2.5 Change detection, tier 3 (design D7): `SourceChangedError`, the size
      comparison on each fetch, and `SOURCE_CHANGE_UNDETECTABLE` at open, with its
      context type, `DiagnosticCodeStr` spellings and its place outside
      `ARCHIVE_INTEGRITY_CODES`.
- [ ] 2.6 Update the remote baseline; the diff is the evidence for the PR.

## 3. Backend range hints

- [ ] 3.1 `source.will_read(start, end)` on `ArchiveSource`, a no-op off `RangeSource`.
- [ ] 3.2 ZIP: tail hint at open, central-directory hint when larger, member span hint
      `[local header, next header or directory)`.
- [ ] 3.3 7z: next-header hint at open; pack-stream hint per member, folder start for
      solid folders.
- [ ] 3.4 ISO extent hints; RAR header-position hints during the listing walk.
- [ ] 3.5 Batched span fetches for `extract_all()` and `stream_members()` over
      non-solid ZIP and 7z: `merge_offset_ranges` then one `cat_ranges` per batch,
      into the window pool (design D5).
- [ ] 3.6 Check the ceilings in `specs/fsspec-integration` against the baseline; update
      the baseline.

## 4. `ArchiveyFileSystem`

- [ ] 4.1 `archivey/fsspec.py` with `ArchiveyFileSystem` (design D3), and the
      `fsspec.specs` entry point in `pyproject.toml`.
- [ ] 4.2 The tree from the extraction view: reuse the code `extract_all()` uses to map a
      member to its relative path and to refuse it (DR-23a: these must agree, so share
      them). Refused members become diagnostics.
- [ ] 4.3 `info`, links, errors, read-only methods, pickling, `policy=`,
      `cachable = False`, `close()` and a `weakref.finalize` that closes the reader.
      Red-green: open 10 000 distinct `archivey://` URLs, drop every reference, and
      check no reader stays open.
- [ ] 4.4 Consumer tests: pandas CSV, pyarrow Parquet, dask over two threads and over
      a process pool (pickling), a nested `archivey::archivey::` chain. These tests
      skip when the consumer package is missing; CI installs them on one leg.
- [ ] 4.5 The remote benchmark's file-system case.

## 5. Volumes over fsspec

- [ ] 5.1 Split `discover_volume_siblings` so the naming rules run on a list of names.
- [ ] 5.2 fsspec discovery through one `ls` of the parent; each volume its own
      `RangeSource`. Tests on `memory://` for all three naming schemes.

## 6. Docs

- [ ] 6.1 `docs/` page "Remote archives and fsspec": the two ways in, why an
      `OpenFile` beats an open file, the `OpenFile` fields archivey refuses, the cache to
      pick when passing an open file (from 1.5's numbers), the file system, its
      extraction-view tree and `policy=`, the RAR download, and that an `archivey://`
      URL reaches the network where `open_archive(str)` never does (member names from a
      caller go to `fs.open()`, never into a URL).
- [ ] 6.2 `dev-docs/threat-model.md`: a remote-source section with two lines: chained
      URLs reach the protocol they name, and a same-length replacement of an unpinned
      remote object is not detected (design D7).
- [ ] 6.3 IDEAS.md: replace the fsspec entry with a pointer to this change, and add
      a persisted member index (offsets saved so a later open lists with no walk) as a
      separate idea.

## 7. Later, each on its own evidence

- [ ] 7.1 RAR sparse spool investigation (design D6): measure what `unrar` reads, with
      the garbage-filled-holes test, before any code.
- [ ] 7.2 A changed remote object, tiers 1 and 2 (design D7): version pinning and
      `If-Match`, per file system.
- [ ] 7.3 CLI URL arguments (maintainer, 2026-10-25: yes; design §Decisions 2), as its
      own OpenSpec change with a `cli` delta.

## 8. Verify

- [ ] 8.1 `openspec validate --strict fsspec-integration`
