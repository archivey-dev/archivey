No task starts until the maintainer approves the 2026-10-25 revision of `design.md`. Each numbered group is one PR.

## 1. Format identity, registry, detection and the adapter

- [ ] 1.1 Add `PluginContainer` (`StrEnum` base) to `types.py`; type
      `ArchiveFormat.container` as `ContainerFormat | PluginContainer`; keep a
      `PluginContainer` member in `__post_init__`; `display_name` drops `_UNCOMPRESSED`
      for a pair with no named constant.
- [ ] 1.2 `internal/plugin_adapter.py`: `PluginBackend(ReadBackend)` and
      `PluginReaderAdapter(BaseArchiveReader)` (locator on `_raw`, name normalization,
      size and digest verification, `ArchiveInfo` and `CostReceipt` built by the adapter,
      handle lock for plugins that keep their own handle).
- [ ] 1.2a Sequential shape in the adapter: the forward pass over `walk()`
      (`_iter_with_data`, `_list_before_extraction`, the `_pull_member` hand-off), span
      windows with skip-on-advance, recorded offsets for random access on a seekable
      source, link targets read from data.
- [ ] 1.2b Move TAR's codec-stream opening (`_open_byte_stream`) to a helper shared
      with the adapter, for compressed sequential plugins.
- [ ] 1.3 `archivey/plugins.py`: `FormatPlugin`, `PluginReader`, `IndexedReader`,
      `SequentialReader`, `MemberRecord`, `MemberSpan`, `MemberData`, `ForwardStream`, `PluginSource`, `PluginContext`, `PluginArchiveInfo`, `Magic`,
      `register_format`. Registration refuses clashing container values, already
      registered formats, and extensions a built-in format claims.
- [ ] 1.4 Detection: plugin signals counted only when no built-in signal matched at the
      same or a higher confidence; probes get the peeked prefix only. `_probe_inner_tar`
      becomes an inner-container probe (TAR first, then sequential plugin magic ending
      within 512 bytes), under the same budget.
- [ ] 1.5 `format_args.py`: plugin spellings after built-in ones. Check the default
      branch of each `ContainerFormat` test in `core.py`, `detection.py`,
      `cli/common.py`, `cli/extract_cmd.py` for a plugin container.
- [ ] 1.6 Tests: a minimal in-test plugin through `open_archive`, `stream_members`,
      `extract_all`, `detect_format`, `format_availability`, the CLI; a short member
      stream raises `TruncatedError`; a wrong digest raises; a member named `../x` is
      refused like a built-in's; a plugin magic never outranks a built-in one. A
      sequential test plugin read from a pipe, gzip-compressed, under
      `stream_members`, `extract_all` and a `CONCURRENT` reader.
- [ ] 1.7 `FormatInfo.from_plugin` (maintainer, 2026-10-25).

## 2. ISO onto the interface

- [ ] 2.1 `IsoReader` implements `IndexedReader`; `IsoReadBackend` becomes a
      `FormatPlugin` registered with `register_format`.
- [ ] 2.2 `self._emit_*` calls go through `PluginContext`; `_handle_guard` moves to the
      adapter; the raw-sector-image refusal moves from `core.py` into `open`.
- [ ] 2.3 The ISO suite passes unchanged; `--all-configs` without pycdlib still reports
      ISO as known with `NONE` support and the install hint.

## 3. CPIO package

- [ ] 3.1 `packages/archivey-cpio/` (unpublished): a `SequentialReader` for binary, odc,
      newc, newc-with-CRC; `.cpio.gz` / `.cpio.xz`; read from a file and a pipe.
- [ ] 3.2 Fixtures written by GNU `cpio` and `bsdcpio`: files, directories, symlinks,
      hard links, device nodes (listed as `OTHER`), a damaged checksum, a truncated
      member.
- [ ] 3.3 A test that fails if the package imports `archivey.internal`.
- [ ] 3.4 CI job that installs the package and runs its tests.

## 4. Docs and specs

- [ ] 4.1 User page "Adding a format" (Opus), with the trust section; API page entry.
- [ ] 4.2 New spec `format-plugins`; deltas to `backend-registry`, `format-detection`,
      `archive-data-model`, `format-iso`.
- [ ] 4.3 `dev-docs/IDEAS.md` and `VISION.md`: the public backend API item points here.
