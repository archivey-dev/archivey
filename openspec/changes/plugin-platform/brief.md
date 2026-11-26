# plugin-platform — one manifest for every format, and formats in separate packages

**Status:** Plan only, written to circulate and be refined. The maintainer agreed the
direction and ten decisions on 2026-11-24 and revised three of them on 2026-11-26
(design.md §Decisions, R1 to R10). R9 retires the 2026-10-28 rule that left a turned-off
plugin format out of detection. No spec deltas yet: each implementation PR brings the
deltas for its step. No code until the maintainer has read this plan. It replaces `openspec/changes/plugin-api`, whose
interface it keeps and whose registration, naming and packaging it rewrites.
Target: steps 1 and 2 with the other breaking trims of 0.6.0, the package split in
0.7.0.

**Why it matters:** archivey has two of everything: one path for its own formats and one
for plugins. Core's enums list formats that only a plugin-shaped reader reads,
`import archivey` loads every reader (210 modules), and a plugin cannot add a codec that
a core reader uses. The maintainer wants archivey to be a platform: core reads the main
formats, the other formats live in a few packages, and our packages are plugins like
anyone else's.

**What it does:**

- Every format and codec, core's own included, is described by a manifest entry: a
  data file with its name, extensions, signatures and the dotted path of its reader.
  Core reads it without running the package and imports a reader only when an archive
  needs it and the caller's policy allows it.
- Format, stream, method and library names become open strings. Core keeps constants for
  what it ships. `PluginContainer`, `PluginStream` and `FormatInfo.from_plugin` go.
- Installed packages are found through an entry point, behind guardrails: a plugin adds
  formats and never takes over a name, extension or signature; an allow-list reads the
  same formats whatever is installed, and `providers=` decides whose code runs; one
  switch turns discovery off.
- Core keeps a hint table of formats it does not ship, so a missing package is named in
  the error and an archive is never read as another format.
- Codecs register by name and bind to a container's method number. The Rust package
  stays a library that archivey imports, reached by any reader through one public
  helper.
- `archivey.formats` grows until our own packages import no private name, gets a
  version number, and takes the shorter thread rules of the concurrency cut, a separate
  change that has landed (archived 2026-11-25).
- Four packages under `packages/`, released with core: `archivey-disk-images`,
  `archivey-dmg`, `archivey-package-formats`, `archivey-legacy-formats`.

**After it lands:** `pip install archivey` is the lean core, `archivey[recommended]`
reads every format as today, and a format from outside the repo is installed with pip
and nothing else.
