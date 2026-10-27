> **Design only.** Written 2026-10-27 for the maintainer's review. No implementation PR
> starts until the maintainer picks an approach in `design.md`. It builds on the plugin
> API stack (`plugin-api`), which is in review now.

## Why

A caller cannot choose which format readers one `open_archive` call may use. Three
needs are open:

- **Turn readers off.** An upload server that only expects ZIP and TAR still runs the
  7z, RAR and ISO parsers on whatever arrives. With the plugin API, any library the
  program imports can call `register_format` and widen that set for every open in the
  process. The plugin API stack review (2026-10-27, finding 6) asked for a per-call
  opt-out of plugin formats.
- **Turn on a subset only.** The same server would rather list what it accepts than
  list everything it refuses, so that a format added in a later archivey release is off
  until the server asks for it.
- **Replace a built-in reader with a plugin.** A caller who needs a feature the
  built-in reader refuses (for example PKWARE Strong Encryption in ZIP) can write a
  plugin for it today, but cannot make archivey use it for `.zip` files: registration
  refuses a built-in container or extension, and a built-in magic match always wins
  over a plugin's.

The maintainer asked (2026-10-27) for a design that covers both plugins and built-in
readers, including an opt-in path and replacement.

## What changes (recommended option A)

- **New public type `archivey.FormatPolicy`**, a frozen dataclass like
  `DiagnosticPolicy`, and a new field `ArchiveyConfig.formats: FormatPolicy`. Its
  arguments:
  - `only=`: containers and compressions that may open. `None` (the default) means all.
  - `exclude=`: containers and compressions that may not open.
  - `plugins=`: `False` turns off every registered plugin format.
  - `replace=`: a built-in container mapped to the plugin that reads it instead.
  - `allows(fmt)`: whether a format may open under the policy.
- **Detection does not change.** It finds the true format with every known format.
  The policy then decides whether that format opens, and which reader opens it. A
  refused format raises `UnsupportedFeatureError` that names the policy.
- **The code of a plugin that is off does not run.** Its content probe is skipped in
  detection; its magic and extensions, which archivey matches itself, still name it.
- **A replacement plugin** has a built-in `ArchiveFormat` as its `format`, declares no
  detection signals, and is used only through `replace=`. It is not registered.

Nothing changes for a caller who does not set `formats`.

## Impact

- Specs: `backend-registry` (policy and reader selection), `format-detection` (skipped
  probes), `format-plugins` (replacement plugins), `archive-reading` (the refusal).
- Code: `config.py`, a new `FormatPolicy` (in `config.py` or `types.py`),
  `internal/registry.py` (`reader_for_format` takes the policy),
  `internal/detection.py` (plugin probes filtered), `internal/plugin_adapter.py`
  (replacement backends), `core.py` (one check at the reader choice, and the volume and
  SFX refusals for a replacement).
- Public API: one new root name and one new config field. Both additive.
- Cost: one set lookup per open.
