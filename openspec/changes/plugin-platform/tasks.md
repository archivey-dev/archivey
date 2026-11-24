## 1. Manifest and lazy loading, inside core

- [ ] 1.1 The entry shape and core's own table: one entry per format on main, the 13
  plugin-shaped readers and ZIP, TAR, 7z, RAR, single-file and directory
- [ ] 1.2 Registry built from entries; handler modules imported on first open
- [ ] 1.3 Detection in three phases (design.md §4): family from data, bounded
  refinement after a signature match, availability
- [ ] 1.4 `refines` and `preempts` replace the deb-before-ar import order and the
  trailer preempt list; deb's refinement as a longer signature
- [ ] 1.5 Remove the side-effect imports in `backends/__init__.py`
- [ ] 1.6 A test that `import archivey` loads no reader module, with the module count
  and the import time recorded before and after
- [ ] 1.7 Detection parity: pkg and plain xar, deb and plain ar, with correct, missing
  and misleading suffixes; `detect_format()` and `open_archive()` agree; read budgets
  measured on seekable and forward-only sources
- [ ] 1.8 Spec deltas: `format-manifest` (new), `backend-registry`, `format-detection`

## 2. Open names (breaking)

- [ ] 2.1 `ContainerFormat`, `StreamFormat`, `CompressionAlgorithm`, `OptionalLibrary`
  as open string types with core's constants; construction refuses an unknown name
- [ ] 2.2 Remove `PluginContainer`, `PluginStream` and the `Literal` spelling lists
- [ ] 2.3 `FormatInfo.provider` replaces `from_plugin`; `FormatPolicy(plugins=False)`
  means the `archivey` distribution only
- [ ] 2.4 `register_format` and `register_builtin_format` become one function that
  takes an entry
- [ ] 2.5 `CHANGELOG.md` **Breaking:** lines; `dev-docs/api-surface.txt` updated
- [ ] 2.6 Spec deltas: `archive-data-model`, `format-plugins`

## 3. Pilot wheel (after 0.6.0 is cut)

- [ ] 3.1 Passive discovery: list the `archivey.plugins` entry points without loading,
  locate each package with `find_spec`, parse `archivey-manifest.toml`; sorted, once, on
  first use; cost measured in a small and a large environment
- [ ] 3.2 Policy before import: no dotted path of an installed package is imported
  before the call's policy allows its provider and format
- [ ] 3.3 The recorder test: a wheel whose `__init__` records that it ran; discovery,
  opening a core ZIP and `format_availability()` under the default policy,
  `plugins=False` and `FormatPolicy.COMMON`, in both orders
- [ ] 3.4 Ownership: one owner per name, extension and signature; `refines` and
  `preempts` only with the owner's consent; refusals reported; a bad manifest skipped
  and reported
- [ ] 3.5 The off switch (environment variable and function)
- [ ] 3.6 The hint table, and the test that keeps it equal to the packages' manifests
- [ ] 3.7 `packages/archivey-package-formats` with ar, cpio and rpm; its extra
- [ ] 3.8 CI: build the wheel, install it beside a core wheel in a fresh environment,
  run the public-imports test and the pilot checks (discovery, plain and compressed
  CPIO, limits, cleanup); wheel, editable and zipped installs
- [ ] 3.9 `archivey.formats.API_VERSION`; the conformance recipe
- [ ] 3.10 A session that did not work on the migration writes the guide's indexed
  example from the guide alone; its unchanged wheel is tried against the next minor
- [ ] 3.11 Spec deltas: `format-manifest`, `format-plugins`, `packaging-and-extras`

## 4. Services, pulled by the reader that needs them

- [ ] 4.1 Codec entries: names, method namespaces with vacant and occupied slots, the
  stream facet
- [ ] 4.2 Eligibility before priority: a second implementation runs only when the
  name's owner lists it or the caller selects it; the provider that ran is in
  `BackendUse`
- [ ] 4.3 Tests: a vacant slot with and without its provider; an unrelated
  distribution claiming a higher priority for a stock method; an approved
  `archivey-codecs` decoder and its fallback; an allow-list keeps its decoder set
- [ ] 4.4 ZIP legacy methods through `("zip", n)`; the ZIP reader's legacy table gone
- [ ] 4.5 `archivey-codecs` decoders as approved second implementations;
  `kernels/_select.py` reduced to that rule
- [ ] 4.6 `ReaderContext.decompress` by name; the block call (SquashFS, DMG)
- [ ] 4.7 Public listing-limit, timestamp and Unix-mode helpers (ISO, xar, CAB, DMG,
  LHA, ARJ)
- [ ] 4.8 SFX stub scan declared on the entry (LHA, ARJ)
- [ ] 4.9 Crypto facade (makeself, DMG, ARJ)
- [ ] 4.10 Nested-archive helpers folded into `ReaderContext.open_nested` (deb, pkg)
- [ ] 4.11 `ReaderSource` source helpers (ISO, DMG)
- [ ] 4.12 Spec deltas: `compressed-streams`, `format-plugins`

## 5. The other moves, one pack at a time

- [ ] 5.1 The rest of `archivey-package-formats`: deb, xar, pkg, makeself
- [ ] 5.2 `packages/archivey-legacy-formats`: CAB, LHA, ARJ, the legacy ZIP methods
- [ ] 5.3 `packages/archivey-disk-images`: ISO, UDF, CD images, SquashFS, DMG
- [ ] 5.4 For each pack: the pilot checks, the public-imports test, and a corpus run on
  a core-only install (refused with the hint) and a full install (same results as
  before the move)
- [ ] 5.5 Extras; `[recommended]`, `[all]` and `archivey-cli` include the three;
  publish matrix rows
- [ ] 5.6 The 13 moved constants as deprecated aliases
- [ ] 5.7 Spec deltas: `packaging-and-extras`, the moved format specs
- [ ] 5.8 Remove `openspec/changes/plugin-api`, which this change replaces

## 6. The concurrency cut (its own pull request, any time after group 1)

- [ ] 6.1 The cut, and the three-sentence thread contract in `archivey.formats`
- [ ] 6.2 A check that `archivey.fsspec` reads several member streams from threads and
  closes cleanly
- [ ] 6.3 Spec delta: `reader-concurrency`

## 7. Afterwards

- [ ] 7.1 Remove the aliases one release later
- [ ] 7.2 Rewrite `docs/adding-a-format.md` against the settled contract
- [ ] 7.3 `openspec validate --strict plugin-platform`
