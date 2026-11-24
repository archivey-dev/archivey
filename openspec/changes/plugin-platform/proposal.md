## Why

The plugin interface (`archivey.formats`) was built beside the built-in path, not in
place of it. On main today:

- A format registers with `register_reader`, `register_builtin_format` or
  `register_format`, depending on who wrote it. A built-in is named by a
  `ContainerFormat` member, a plugin by a `PluginContainer` subclass, and detection
  ranks the two differently.
- `CompressionAlgorithm` and `ContainerFormat` are closed enums that already hold names
  only plugin-shaped readers use (LZX, LZH, ADC, LZFSE; DMG, CAB, LHA and ten more).
- `backends/__init__.py` imports all 19 reader modules for their side effect, so
  `import archivey` loads 210 modules, and detection order is import order.
- `register_codec` adds a whole stream format only. A plugin cannot supply a method that
  the ZIP or 7z reader uses.
- 13 readers are written on `archivey.formats`; ten of them still import
  `archivey.internal`.
- The plugin guide tells a plugin to pin `archivey==X.Y.Z`, so two plugins tested on
  different versions cannot be installed together.

The maintainer's direction (2026-11-24): split the non-core formats into a few packages,
make no distinction between our plugins and other people's, let plugins register codecs
that other formats use, and solve the import cost with the same mechanism.

## What Changes

- **Manifest.** One entry per format or codec, core's included: a data file that core
  reads without running the package. Reader modules are imported on first use.
- **Open names. Breaking.** `ContainerFormat`, `StreamFormat`, `CompressionAlgorithm`
  and `OptionalLibrary` become open string types with constants for core's own names.
  `PluginContainer`, `PluginStream`, the `Literal` spelling lists and
  `FormatInfo.from_plugin` are removed; `FormatInfo.provider` is added.
- **Discovery.** Installed packages announce a manifest through the `archivey.plugins`
  entry point group. Core reads it without importing the package, and applies a call's
  policy before it imports any code of an installed package. `register_format()` and
  `register_codec()` stay and take the same entries. This replaces the 2026-10-25
  explicit-only rule.
- **Hint table.** Core lists formats it knows and does not ship, with the package that
  reads each.
- **Codec registry.** Codecs by name, method bindings per container, and a second
  implementation of a name only where its owner or the caller approves it.
- **Reader API.** Public helpers replace each `archivey.internal` import of the moved
  readers. `API_VERSION` replaces the exact version pin. The thread rules are the short ones
  that the concurrency cut, a separate change that lands first, leaves.
- **Packages.** `archivey-disk-images`, `archivey-package-formats` and
  `archivey-legacy-formats` under `packages/`, with extras of the same names;
  `[recommended]`, `[all]` and `archivey-cli` include all three.

## Capabilities

Deltas are written with each implementation step, not in this plan.

### New Capabilities

- `format-manifest`: entries, discovery, the hint table, ownership of names.

### Modified Capabilities

- `format-plugins`: one registration path, the reader contract, the API version.
- `backend-registry`: lazy loading, providers, refusals.
- `format-detection`: detection from manifest data, `refines`.
- `compressed-streams`: codecs by name, method bindings, second implementations.
- `packaging-and-extras`: the three packages and their extras.
- `archive-data-model`: open name types.
- The format specs of the formats that move: where they live, nothing else.

## Impact

- **Callers.** `ContainerFormat.ZIP` and string comparisons keep working.
  `list(ContainerFormat)`, exhaustive `match` on the enums and the `Literal` types stop
  working. The 13 moved constants warn for one release, then go.
- **Installs.** Bare `archivey` stops reading the moved formats and says which package
  to install. `archivey[recommended]` and `archivey-cli` read everything as before.
- **Same archive, same contents.** Extended to installs: an archive reads the same way
  or is refused with a hint. Installing a package never changes how a file that already
  opened is read.
- **Servers that read uploads.** An allow-list policy (`FormatPolicy.COMMON`, `only=`)
  is not affected by installed packages. `plugins=False` keeps its meaning: only code
  in the `archivey` distribution runs.
- **Plugin authors.** The interface changes shape once more (it is experimental), then
  gets a version number.
- **Releases.** Three more distributions published with each archivey release, in the
  same workflow as `archivey-cli`.
