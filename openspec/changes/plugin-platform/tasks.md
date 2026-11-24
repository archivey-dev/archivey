## 1. Manifest and lazy loading, inside core

- [ ] 1.1 `FormatEntry` and core's literal table: one entry per format on main, the 13
  plugin-shaped readers and ZIP, TAR, 7z, RAR, single-file and directory
- [ ] 1.2 Registry built from entries; handler modules imported on first open
- [ ] 1.3 Detection from entry data; probes as dotted paths, imported on demand
- [ ] 1.4 `refines` replaces the deb-before-ar import order; pkg refines xar
- [ ] 1.5 Remove the side-effect imports in `backends/__init__.py`
- [ ] 1.6 A test that `import archivey` loads no reader module, with the module count
  and the import time recorded before and after
- [ ] 1.7 Spec deltas: `format-manifest` (new), `backend-registry`, `format-detection`

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

## 3. The reader API is enough, in tree

- [ ] 3.1 The public-imports test, listing the ten readers as expected failures
- [ ] 3.2 Public listing-limit, timestamp and Unix-mode helpers (ISO, xar, CAB, DMG,
  LHA, ARJ)
- [ ] 3.3 SFX stub scan declared on the entry (LHA, ARJ)
- [ ] 3.4 Crypto facade (makeself, DMG, ARJ)
- [ ] 3.5 Nested-archive helpers folded into `ReaderContext.open_nested` (deb, pkg)
- [ ] 3.6 `ReaderSource` source helpers (ISO, DMG)
- [ ] 3.7 The concurrency cut and the three-sentence thread contract
- [ ] 3.8 `archivey.formats.API_VERSION`
- [ ] 3.9 No expected failure left in 3.1
- [ ] 3.10 Spec deltas: `format-plugins`, `reader-concurrency`

## 4. Codecs by name

- [ ] 4.1 `CodecEntry` with method bindings, the stream facet and priority
- [ ] 4.2 `ReaderContext.decompress` by name; the block call (SquashFS, DMG)
- [ ] 4.3 ZIP legacy methods through `("zip", n)` bindings; the ZIP reader's table gone
- [ ] 4.4 `archivey-codecs` decoders as second implementations; `kernels/_select.py`
  reduced to that rule; parity tests as the entry bar
- [ ] 4.5 Spec delta: `compressed-streams`

## 5. Discovery and the move

- [ ] 5.1 `archivey.plugins` entry-point collection, sorted, once, on first use; the
  cost measured in a small and a large environment
- [ ] 5.2 Guardrails: one owner per name, extension and signature; refusals reported; a
  failing manifest skipped and reported
- [ ] 5.3 The off switch (environment variable and function)
- [ ] 5.4 The hint table, and the test that keeps it equal to the packages' manifests
- [ ] 5.5 `packages/archivey-disk-images`, `packages/archivey-package-formats`,
  `packages/archivey-legacy-formats`: files moved, manifests, constants exported
- [ ] 5.6 Extras; `[recommended]`, `[all]` and `archivey-cli` include the three
- [ ] 5.7 CI: wheel-install job with the public-imports test; publish matrix rows
- [ ] 5.8 The 13 moved constants as deprecated aliases
- [ ] 5.9 Corpus run on a core-only install (every moved format refused with its hint)
  and on a full install (same results as before the move)
- [ ] 5.10 Spec deltas: `format-manifest`, `packaging-and-extras`, the moved format
  specs
- [ ] 5.11 Remove `openspec/changes/plugin-api`, which this change replaces

## 6. Afterwards

- [ ] 6.1 Remove the aliases one release later
- [ ] 6.2 Rewrite `docs/adding-a-format.md` against the settled contract
- [ ] 6.3 `openspec validate --strict plugin-platform`
