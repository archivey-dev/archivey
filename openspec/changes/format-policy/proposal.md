> **Design approved 2026-10-27** (option A and every call in `design.md` §7). The
> implementation builds on the plugin API stack (`plugin-api`) and starts once that
> stack has merged. This change carries deltas for `backend-registry`,
> `format-detection`, `packaging-and-extras` and `error-handling`; the deltas to
> `format-plugins` and `archive-reading` come with the implementation PR.

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

## What changes

- **New public type `archivey.FormatPolicy`**, a frozen dataclass like
  `DiagnosticPolicy`, and a new field `ArchiveyConfig.formats: FormatPolicy`. Its
  arguments:
  - `only=`: containers and compressions that may open. `None` (the default) means all.
  - `exclude=`: containers and compressions that may not open.
  - `exclude_libraries=`: optional packages (`pyppmd`, `inflate64`, ...) that read as
    not installed for the call.
  - `plugins=`: `False` turns off every registered plugin format.
  - `replace=`: a built-in container mapped to the plugin that reads it instead.
  - `allows(fmt)`: whether a format may open under the policy.
- **Detection does not change.** It finds the true format with every known format.
  The policy then decides whether that format opens, and which reader opens it. A
  refused format raises `UnsupportedFeatureError` that names the policy.
- **The code of a plugin that is off does not run.** Its content probe is skipped in
  detection; its magic and extensions, which archivey matches itself, still name it.
- **An excluded library** behaves exactly as an absent one does today: accelerators
  fall back, a member that needs it raises `PackageNotInstalledError`, a format that
  needs it refuses at open. Today a caller cannot avoid a library that is installed
  system-wide (`design.md` §5a).
- **A replacement plugin** has a built-in `ArchiveFormat` as its `format`, declares no
  detection signals, and is used only through `replace=`. It is not registered.

Nothing changes for a caller who does not set `formats`.

## Impact

- Specs: `backend-registry` (policy and reader selection), `format-detection` (skipped
  probes), `format-plugins` (replacement plugins), `archive-reading` (the refusals),
  `packaging-and-extras` (excluded libraries), `error-handling`
  (`PackageNotInstalledError.missing`).
- Code: `config.py`, a new `FormatPolicy` (in `config.py` or `types.py`),
  `internal/registry.py` (`reader_for_format` takes the policy), `internal/detection.py`
  (plugin probes filtered), `internal/plugin_adapter.py` (replacement backends), the
  codec and backend availability checks (`deps.py`), `core.py` (one check at the reader
  choice, and the volume and SFX refusals for a replacement).
- Public API: one new root name, one new config field, a keyword `config=` on
  `format_availability` and `list_supported_formats`, and a `missing` attribute on
  `PackageNotInstalledError`. All additive. The
  `UnsupportedFeatureError` and `PackageNotInstalledError` docstrings widen to cover a
  policy refusal.
- Cost: one set lookup per open.
