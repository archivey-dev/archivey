# plugin-platform — one manifest for every format, and formats in separate packages

**Status:** Plan only, written to circulate and be refined. The maintainer agreed the
direction and all ten decisions on 2026-11-24 (design.md §Decisions). No spec deltas
yet: each implementation PR brings the deltas for its step. No code until the
maintainer has read this plan. It replaces `openspec/changes/plugin-api`, whose
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

- Every format and codec, core's own included, is described by a manifest entry: plain
  data with its name, extensions, signatures and the dotted path of its reader. Core
  imports a reader only when an archive needs it.
- Format, stream, method and library names become open strings. Core keeps constants for
  what it ships. `PluginContainer`, `PluginStream` and `FormatInfo.from_plugin` go.
- Installed packages are found through an entry point, behind guardrails: a plugin adds
  formats and never takes over a name, extension or signature; allow-list policies are
  not affected; one switch turns discovery off.
- Core keeps a hint table of formats it does not ship, so a missing package is named in
  the error and an archive is never read as another format.
- Codecs register by name, bind to a container's method number, and may have a second
  implementation (the Rust package) under the accelerator rule.
- `archivey.formats` grows until our own packages import no private name, gets a
  version number, and its thread rules shrink to three sentences.
- Three packages under `packages/`, released with core: `archivey-disk-images`,
  `archivey-package-formats`, `archivey-legacy-formats`.

**After it lands:** `pip install archivey` is the lean core, `archivey[recommended]`
reads every format as today, and a format from outside the repo is installed with pip
and nothing else.
