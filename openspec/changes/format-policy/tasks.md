# Tasks — format policy

Not started. The maintainer picks an approach in `design.md` §7 first.

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

## 3. Detection

- [ ] 3.1 Skip the content probe of a plugin the policy turns off.

## 4. Tests and docs

- [ ] 4.1 Tests: each row of the `design.md` §3 table; `format=` does not bypass the
      policy; an off plugin's probe is not called; a replacement reads a ZIP and
      `detect_format` answers the same with and without it; the refusals in §5.
- [ ] 4.2 Docs: the config page, the security page (the upload-server policy), and the
      "Adding a format" guide (replacement plugins).
