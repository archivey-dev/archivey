> **Design only.** Written 2026-10-21 for the maintainer's review. No implementation PR
> starts until the maintainer approves `design.md`. `specs/format-plugins` is a first draft of the
> new spec; the deltas to the existing specs come with the implementation PRs.

## Why

`VISION.md` and `dev-docs/IDEAS.md` ("Public backend API") both say a public backend API
turns format coverage from one maintainer's work into an ecosystem: rare formats (CPIO,
CAB, SquashFS, WIM, XAR) can live in other packages. Today that is not possible. A
backend subclasses `ReadBackend` and `BaseArchiveReader` in `archivey.internal`, the
registry is internal, and `ArchiveFormat` refuses any container that is not a member of
the closed `ContainerFormat` enum.

`BaseArchiveReader` cannot simply be made public. It is about 3,900 lines, and most of it
is the shared machinery that makes the readers agree (one member walk, link resolution,
listing limits, error stamping). A subclass sees all of it, so every internal change
would become a public change under the stability policy (deprecate first, one minor).

The maintainer asked (2026-10-21) to design a narrow public plugin API now and to move
existing formats onto it where that fits.

## What changes

- **New public submodule `archivey.plugins`** (not re-exported at the root, DR-13):
  `FormatPlugin`, two reader shapes (`IndexedReader`, `SequentialReader`),
  `MemberRecord`, `MemberSpan`, `ForwardStream`, `PluginSource`, `PluginContext`,
  `PluginArchiveInfo`, `Magic`, `register_format()`. Provisional, explicit
  registration only (maintainer, 2026-10-25).
- **Sequential plugins read pipes** and sit inside an outer compression stream
  (`x.cpio.gz` detects as CPIO over gzip).
- **New public type `archivey.PluginContainer`**, a `StrEnum` base class. A plugin's
  container enum subclasses it. `ArchiveFormat.container` becomes
  `ContainerFormat | PluginContainer`.
- **Internal adapter** `PluginReaderAdapter(BaseArchiveReader)` and
  `PluginBackend(ReadBackend)`, so the registry, detection, `open_archive`,
  `format_availability` and the CLI treat a plugin format like a built-in one.
- **Detection** reads plugin magic, extensions and probes from the registry, after the
  built-in signals. The inner-TAR probe becomes an inner-container probe.
- **`FormatInfo.from_plugin`**, one boolean.
- **String spellings** (`format="cpio"`) resolve plugin formats.
- **ISO moves onto the interface.** `IsoReader` becomes an `IndexedReader`; its parsing
  code does not change.
- **A CPIO plugin** in `packages/archivey-cpio/` (not published), tested in CI against `cpio` and
  `bsdcpio` output, using only `archivey.plugins` and the root API.
- **Docs:** a new user page, "Adding a format", and an entry on the API page.

Nothing that exists today changes for a caller who registers no plugin.

## Impact

- Specs: `backend-registry`, `format-detection`, `archive-data-model` (the container
  type), `format-iso`, a new `format-plugins` spec.
- Code: `types.py`, `internal/registry.py`, `internal/detection.py`,
  `internal/format_args.py`, `cli/common.py`, `cli/extract_cmd.py`, `core.py` (the ISO
  sector-image refusal moves into the plugin's `open`), `internal/backends/iso_reader.py`,
  new `plugins.py` and `internal/plugin_adapter.py`.
- Public API: one new submodule and one new root name. Both additive.
