# Tasks — format policy

Design approved 2026-10-27. Implemented in three pull requests, one per part below; the
last one archives the change.

## 1. Policy, refusals and detection (part 1)

- [x] 1.1 `FormatPolicy` (frozen; `only`, `exclude`, `plugins`; `allows()`), with the
      construction checks in `design.md` §3: entry types, `C.UNKNOWN`, `S.UNCOMPRESSED`
      in `exclude`, an entry in both lists, a plugin container in `only` with
      `plugins=False`. Exported at the root.
- [x] 1.2 `ArchiveyConfig.formats: FormatPolicy = FormatPolicy()`.
- [x] 1.3 `open_archive` refuses an off format with `UnsupportedFeatureError` naming the
      entry to change, right after the format is known and before every other refusal;
      `format=` does not bypass it. `open_stream` makes the same check on the format it
      opens (a bare `StreamFormat` is its raw stream).
- [x] 1.4 Leave a plugin the policy turns off out of detection: its magic (near and
      far), its extensions, and its content probe, also under
      `always_probe_content=True` and in `open_stream`; record each skipped tier as
      `NOT_ENABLED_BY_POLICY`; name the policy in the `FormatDetectionError` message
      when it left a plugin out and nothing matched. The internal detections
      (`probe_config`) carry the policy too.
- [x] 1.5 Tests: each row of the `design.md` §3 table; the construction refusals;
      `format=` does not bypass the policy; the policy refusal comes before the
      read-once refusal; `open_stream`; an off plugin's probe is not called, its magic
      does not shadow an allowed plugin that matches the same file, its extension is
      not a guess; a built-in answer does not depend on the policy.
- [x] 1.6 Docs: `FormatPolicy` in the API reference, the config page and the security
      page (the upload-server policy, and one sentence that the policy bounds which
      reader runs, not what detection reads).

## 2. Replacement plugins (part 2)

- [x] 2.1 `FormatPolicy(replace=)`, with the checks in `design.md` §5: the plugin's
      `format` is a built-in `ArchiveFormat(key, UNCOMPRESSED)` for ZIP, 7z, RAR or ISO,
      it declares no extensions, magic or probe, and `only` or `exclude` does not turn
      the replaced container off.
- [x] 2.2 `BackendRegistry.reader_for_format(fmt, policy)`: return the replacement
      backend, after checking its `requires` (a missing one raises
      `PackageNotInstalledError` before the plugin's `open` runs). Replacement backends:
      `_backend_class` over the built-in format with no detection signals, cached per
      plugin class.
- [x] 2.3 `core.py`: refuse multi-volume sets, SFX-found archives and read-once sources
      for a replaced container, before the plugin's `open` runs.
- [x] 2.4 Tests: a replacement reads a ZIP, `reader.format` is the built-in format and
      `from_plugin` is false, `detect_format` answers the same with and without it; the
      construction refusals; a replacement is refused on a volume set, an SFX-found
      archive and a pipe.
- [x] 2.5 Docs and spec: the "Adding a format" guide (replacement plugins); the
      `FormatPlugin.format`, `extensions`, `magic` and `probe` docstrings in
      `plugins.py`, which today describe registration only; the `format-plugins` delta.

## 3. Optional libraries and availability (part 3)

- [ ] 3.1 `OptionalLibrary` and `OptionalLibraryStr`, exported at the root, with a test
      that pins the `Literal` against the enum. Every place inside archivey that names
      one of archivey's own optional packages uses the member: the codec requirements,
      `LazyOptional`, backend `OPTIONAL_DEPENDENCY` / `REQUIRED_MODULES`, the
      availability checks. `MissingComponent.name` stays `str` and holds the member for
      those packages.
- [ ] 3.2 `FormatPolicy(exclude_libraries=)` takes `OptionalLibrary | OptionalLibraryStr`
      and stores `frozenset[OptionalLibrary]`, refusing any other entry; a named plugin
      whose `requires` holds an excluded package is refused. The cross-field check in
      `ArchiveyConfig.__post_init__`: an excluded `rapidgzip` with `use_rapidgzip=ON`
      or `use_indexed_bzip2=ON`.
- [ ] 3.3 Carry the excluded names from `ArchiveyConfig.formats` on the reader config
      and the stream config, and pass them to every place that answers "is this package
      available": `LazyOptional`, `registry._optional` / `_missing_dependency`,
      `codecs.registry.is_codec_available`, `StreamCodec.available` /
      `_backend_present`, backend `REQUIRED_MODULES`. An excluded name answers "absent"
      first; no module global changes per call. Build the `MissingComponent` per call
      with `reason` naming `config.formats`.
- [ ] 3.4 `format_availability(fmt, config=None)` and `list_supported_formats(config=None)`
      count excluded libraries as absent; the list does not filter by `allows()`. Update
      both docstrings in `registry.py`, which today say the answer does not change with
      `ArchiveyConfig`. Under `replace=` answer for the replacement's backend and its
      `requires`. Also update the `config.py` RAR docstring ("the `format_availability()`
      query takes no config") and the comment on `RarReader.missing_programs`.
- [ ] 3.5 Widen the `UnsupportedFeatureError` and `PackageNotInstalledError` docstrings
      to cover policy refusals, and add `PackageNotInstalledError.missing` (the
      components the raise is about), set on every raise; the unrar sites fill it from
      `rarlab_unrar_missing()`, the `CliToolFinder.find` refusal from the finder's
      `display_name` and `install_hint`, and it is empty only for a program that is
      found but cannot start. Messages keep naming the package.
- [ ] 3.6 Tests: an excluded `pyppmd` makes a PPMd 7z member raise
      `PackageNotInstalledError` while the other members read; an excluded `rapidgzip`
      under `AUTO` falls back and under `ON` is refused; an excluded lazy package is
      never imported; two threads, one excluding `pyppmd` and one not, each get their
      own answer; `format_availability(SEVEN_Z, config=...)` answers `PARTIAL` with
      `pyppmd` installed and excluded; availability answers for the replacement (NONE,
      `P.open` not called); `list_supported_formats(config=...)` does not filter by
      `allows()`; excluding `compression.zstd` falls through to `backports.zstd`; a
      misspelled library name is refused; a missing `unrar` and a missing `unar` each
      fill `exc.missing`; a registered plugin the policy does not name, whose
      `requires` holds an excluded package, reads as NONE and refuses at open.
- [ ] 3.7 Docs: excluded libraries on the config and security pages.

## 4. Archive

- [ ] 4.1 `openspec archive format-policy --yes`, in the pull request for part 3.
