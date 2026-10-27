# Tasks — format policy

Not started. Design approved 2026-10-27; starts once the plugin API stack has merged.

## 1. Policy type

- [ ] 1.1 `FormatPolicy` (frozen; `only`, `exclude`, `plugins`, `replace`; `allows()`),
      with the construction checks in `design.md` §3 and §5. Exported at the root.
- [ ] 1.2 `ArchiveyConfig.formats: FormatPolicy = FormatPolicy()`.

## 2. Reader choice

- [ ] 2.1 `BackendRegistry.reader_for_format(fmt, policy)`: refuse an off format with
      `UnsupportedFeatureError` naming the entry to add; return the replacement backend.
- [ ] 2.2 Replacement backends: `_backend_class` over the built-in format with no
      detection signals, cached per plugin class.
- [ ] 2.3 `core.py`: refuse multi-volume sets and SFX-found archives for a replaced
      container; the `open_stream` check.

## 3. Detection and member open

- [ ] 3.1 Skip the content probe of a plugin the policy turns off.
- [ ] 3.2 `exclude_libraries`: thread the policy into the optional-package checks
      (`deps.py`, `LazyOptional`, backend `REQUIRED_MODULES`), so an excluded package
      reads as absent for the call, with a reason naming `config.formats`.

## 4. Tests and docs

- [ ] 4.1 Tests: each row of the `design.md` §3 table; `format=` does not bypass the
      policy; an off plugin's probe is not called; a replacement reads a ZIP and
      `detect_format` answers the same with and without it; the refusals in §5; an excluded `pyppmd` makes a PPMd 7z member raise
      `PackageNotInstalledError` while the other members read; an excluded `rapidgzip`
      under `AUTO` falls back and under `ON` is refused; an excluded lazy package is
      never imported.
- [ ] 4.2 Docs: the config page, the security page (the upload-server policy), and the
      "Adding a format" guide (replacement plugins).
