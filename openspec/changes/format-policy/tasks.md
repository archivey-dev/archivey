# Tasks — format policy

Not started. Design approved 2026-10-27; starts once the plugin API stack has merged.

## 1. Policy type

- [ ] 1.1 `FormatPolicy` (frozen; `only`, `exclude`, `exclude_libraries`, `plugins`,
      `replace`; `allows()`), with the construction checks in `design.md` §3, §5 and
      §5a: the fixed set of library names, and a named plugin whose `requires` holds an
      excluded package. Exported at the root.
- [ ] 1.2 `ArchiveyConfig.formats: FormatPolicy = FormatPolicy()`, and the cross-field
      check in `ArchiveyConfig.__post_init__` (an excluded `rapidgzip` with
      `use_rapidgzip=ON` or `use_indexed_bzip2=ON`).

## 2. Reader choice

- [ ] 2.1 `BackendRegistry.reader_for_format(fmt, policy)`: refuse an off format with
      `UnsupportedFeatureError` naming the entry to add; return the replacement backend,
      after checking its `requires` (a missing one raises `PackageNotInstalledError`
      before the plugin's `open` runs).
- [ ] 2.2 Replacement backends: `_backend_class` over the built-in format with no
      detection signals, cached per plugin class.
- [ ] 2.3 `core.py`: refuse multi-volume sets and SFX-found archives for a replaced
      container; the `open_stream` check.

## 3. Detection and member open

- [ ] 3.1 Skip the content probe of a plugin the policy turns off, also under
      `always_probe_content=True` and in `open_stream`; record it as
      `NOT_ENABLED_BY_POLICY`; name the policy in the `FormatDetectionError` message
      when that was the only probe left out.
- [ ] 3.2 `exclude_libraries`: carry the excluded names from `ArchiveyConfig.formats` on
      the reader config and the stream config, and pass them to every place that answers
      "is this package available": `LazyOptional`, `registry._optional` /
      `_missing_dependency`, `codecs.registry.is_codec_available`,
      `StreamCodec.available` / `_backend_present`, backend `REQUIRED_MODULES`. An
      excluded name answers "absent" first; no module global changes per call. Build the
      `MissingComponent` per call with `reason` naming `config.formats`.
- [ ] 3.3 `format_availability(fmt, config=None)` and `list_supported_formats(config=None)`
      count excluded libraries as absent; the list does not filter by `allows()`. Update
      both docstrings in `registry.py`, which today say the answer does not change with
      `ArchiveyConfig`. Under `replace=` answer for the replacement's backend and its
      `requires`. Also update the `config.py` RAR docstring ("the `format_availability()`
      query takes no config") and the comment on `RarReader.missing_programs`.
- [ ] 3.4 Widen the `UnsupportedFeatureError` and `PackageNotInstalledError` docstrings
      to cover policy refusals, and add `PackageNotInstalledError.missing` (the
      components the raise is about), set on every raise; the unrar sites fill it from
      `rarlab_unrar_missing()`, the `CliToolFinder.find` refusal from the finder's
      `display_name` and `install_hint`, and it is empty only for a program that is
      found but cannot start. Messages keep naming the package.

## 4. Tests and docs

- [ ] 4.1 Tests: each row of the `design.md` §3 table; `format=` does not bypass the
      policy; an off plugin's probe is not called; a replacement reads a ZIP and
      `detect_format` answers the same with and without it; the refusals in §5; an
      excluded `pyppmd` makes a PPMd 7z member raise
      `PackageNotInstalledError` while the other members read; an excluded `rapidgzip`
      under `AUTO` falls back and under `ON` is refused; an excluded lazy package is
      never imported; two threads, one excluding `pyppmd` and one not, each get their
      own answer; `format_availability(SEVEN_Z, config=...)` answers `PARTIAL` with
      `pyppmd` installed and excluded; a replacement is refused on a volume set, an
      SFX-found archive and a pipe. And one test per delta scenario not named above:
      availability answers for the replacement (NONE, `P.open` not called);
      `list_supported_formats(config=...)` does not filter by `allows()`; excluding
      `compression.zstd` falls through to `backports.zstd`; a missing `unrar` and a
      missing `unar` each fill `exc.missing`; a registered plugin the policy does not
      name, whose `requires` holds an excluded package, reads as NONE and refuses at
      open.
- [ ] 4.2 Docs: the config page; the security page (the upload-server policy, and one
      sentence that the policy bounds which reader runs, not what detection reads); the
      "Adding a format" guide (replacement plugins); the `FormatPlugin.format`,
      `extensions`, `magic` and `probe` docstrings in `plugins.py`, which today describe
      registration only.
