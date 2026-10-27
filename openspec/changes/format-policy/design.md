# Design — choosing the format readers for one open

> **Design approved by the maintainer (2026-10-27): option A and every call in §7.**
> Section 1 is the design in short. Section 2 compares the options. Sections 3 to 6 are
> the detail of option A. Section 7 records the calls.

## 1. The design

Add one policy object to `ArchiveyConfig`, set per call, the same way
`diagnostic_policy` is set:

```python
from archivey import ArchiveyConfig, ContainerFormat as C, FormatPolicy, StreamFormat as S

# Upload server: ZIP, and TAR with or without gzip or xz. Nothing else opens,
# including formats a later archivey release adds and plugins any import registers.
UPLOADS = ArchiveyConfig(formats=FormatPolicy(only={C.ZIP, C.TAR, S.GZIP, S.XZ}))

# Everything except RAR, and no plugin formats.
NO_RAR = ArchiveyConfig(formats=FormatPolicy(exclude={C.RAR}, plugins=False))

# Read ZIP files with my plugin, which supports PKWARE Strong Encryption.
MY_ZIP = ArchiveyConfig(formats=FormatPolicy(replace={C.ZIP: StrongZipPlugin}))

with open_archive("upload.bin", config=UPLOADS) as reader:  # a 7z here raises
    ...
```

The rules, in the order archivey applies them:

1. **Detection finds the true format, with every format it knows.** The policy does
   not change what `detect_format` answers. One exception: the content probe of a plugin
   that the policy turns off does not run, because that probe is plugin code (§4).
2. **The policy decides whether that format opens.** A refused format raises
   `UnsupportedFeatureError` with `source_format` set and a message that names the
   policy and the entry to add. `format=` does not bypass the policy.
3. **The policy decides which reader opens it.** A container in `replace=` opens with
   the plugin named there. Every other format opens with its registered reader.

## 2. The options

### A. A per-call policy object on `ArchiveyConfig` (chosen)

As in §1. Everything about the choice is in the config object the caller already
passes, so two parts of one program can use different policies at the same time, and a
library that registers a plugin cannot change what another part of the program accepts.

- For: no global state (archivey has no process-wide default config today). Thread-safe
  by construction. Follows the `DiagnosticPolicy` precedent (DR-14: extend what exists).
  One field to explain (DR-14a). A server writes it once in the config it already builds.
- Against: four arguments on one new type. Each maps to one of the four needs, so none
  of them is a convenience over another.

### B. Process-wide switches

`archivey.disable_format(C.RAR)`, `register_format(StrongZipPlugin, replaces=C.ZIP)`,
`archivey.plugin_formats(False)`.

- For: one call at start-up covers every open, including opens in libraries the
  program does not control.
- Against: global mutable state, which archivey has avoided so far. Any import can call
  them, so finding 6's problem (an imported library widens the parser surface) becomes
  worse: an imported library could *replace* the hardened ZIP reader for the whole
  process. Tests need a scope to undo them. Two threads cannot disagree.

### C. A caller predicate

`ArchiveyConfig(format_filter=lambda fmt: fmt.container in {C.ZIP, C.TAR})`, and
replacement as a registration priority.

- For: any rule a caller can write.
- Against: archivey cannot read it back. `allows()`, a CLI flag and a refusal message
  that names what to add all need data, not code. It is also easy to get wrong on the
  first try (DR-14a): the predicate above lets every TAR compression through, including
  ones a later release adds, which its writer may not have meant.

### D. Remove off formats from detection

Like A, but a format that is off is left out of every detection table, so detection
answers as if it did not exist. Replacement then falls out for free: with ZIP off, a
plugin with `PK\x03\x04` magic matches.

- For: replacement needs no new plugin kind.
- Against: it gives wrong answers, which DR-1 ranks worst. With TAR off, `backup.tar.gz`
  would detect as a gzip single-file stream and open as one member named `backup.tar`.
  The caller asked for "no TAR" and got a TAR's bytes, through the gzip reader, with no
  error. The same file would also get a different `detect_format` answer under different
  configs (DR-5). And a replacement plugin would have to copy the built-in's detection
  (magic, SFX scan, extensions) to find the same files.

**Why A over B.** The person who sets the policy is the one who opens the untrusted
file. A per-call object puts the choice there and nowhere else. B is the only way to
cover opens inside libraries the program does not control, but those libraries pass
their own config anyway, and a global switch that any import can flip is the problem
finding 6 raised.

## 3. `FormatPolicy`

```python
FormatEntry = ContainerFormat | PluginContainer | StreamFormat

@dataclass(frozen=True)
class FormatPolicy:
    only: frozenset[FormatEntry] | None = None
    exclude: frozenset[FormatEntry] = frozenset()
    exclude_libraries: frozenset[str] = frozenset()  # §5a
    plugins: bool = True
    replace: Mapping[ContainerFormat, type[FormatPlugin]] = {}  # stored read-only

    def allows(self, fmt: ArchiveFormat) -> bool: ...
```

Arguments take any iterable, as `DiagnosticPolicy` does, and the fields hold frozensets.

**When a format may open.** An `ArchiveFormat` is a `(container, stream)` pair, so the
entries are containers and compressions, and both halves must pass:

- The container passes when `only` is `None` or lists it, `exclude` does not list it,
  and, for a plugin container, `plugins` is true or `only` lists it by name.
- The stream passes when it is `UNCOMPRESSED`, or `only` is `None` or lists it, and
  `exclude` does not list it.

Examples, with `C` and `S` as in §1:

| Policy | Opens | Refuses |
|---|---|---|
| `only={C.ZIP, C.TAR}` | `.zip`, `.tar` | `.tar.gz` (add `S.GZIP`), `.gz` (add `C.RAW_STREAM`), `.7z`, every plugin |
| `only={C.TAR, *StreamFormat}` | `.tar` with any compression | `.gz`, `.zip`, ... |
| `only={C.RAW_STREAM, S.GZIP}` | `.gz` only | `.tar.gz`, `.xz` |
| `exclude={S.BROTLI}` | everything else | `.br`, `.tar.br` |
| `exclude={C.RAR}, plugins=False` | every built-in except RAR | `.rar`, `.cpio` (a plugin) |
| `only={C.ZIP, CpioContainer.CPIO}` | `.zip`, `.cpio` | other plugins, other built-ins |

`only` refusing `.tar.gz` when `S.GZIP` is missing is deliberate. The alternative rule,
"no compression listed means every compression", would make adding `S.XZ` to a working
policy turn gzip off. The refusal message says which entry to add, so the first try
fails with the fix in hand rather than opening more than the caller listed.

`C.DIRECTORY` is an entry like the others, so `only={C.ZIP}` also refuses a directory
path. `C.UNKNOWN` is refused as an entry (`ArchiveyUsageError`). An entry in both `only`
and `exclude` is refused, as `DiagnosticPolicy` refuses a code in both lists.

**`plugins=False` and `only`.** `plugins` is for the deny-list form. Under `only`, a
plugin opens only when listed, so `plugins=False` adds nothing; listing a plugin
container with `plugins=False` is refused as a contradiction.

## 4. Detection and plugin code

Detection keeps every table (DR-1, DR-5), with one change. archivey matches magic and
extensions itself, so a plugin's magic and extensions still name its format when the
plugin is off, and the open is refused by name. A plugin's **content probe** is the
plugin's own code, so it does not run when the policy turns that plugin off. A file that
only that probe would recognise gets `FormatDetectionError`, which is a reported absence
(DR-1), not a wrong answer.

So `detect_format(source, config=...)` can differ by config in one case only: a file
that only an off plugin's probe recognises. Built-in probes always run; they are
archivey's code and the policy is not a reason to report a different format.

The caller can ask `config.formats.allows(info.format)` after `detect_format` to decide
before opening. `FormatInfo` gets no new field (DR-13).

## 5. Replacing a built-in reader

```python
class StrongZipPlugin(FormatPlugin):
    format = ArchiveFormat.ZIP   # a built-in format, not a PluginContainer
    # no extensions, magic or probe: detection stays the built-in's
    def open(self, source, context): ...
```

- **Detection stays the built-in's.** The file is found by the built-in's magic, SFX
  scan, extensions and probes, and reports `ArchiveFormat.ZIP`. Only the reader
  changes. So a plugin cannot change what any file detects as (DR-5), and it does not
  need to copy the built-in's detection.
- **Not registered.** `register_format` keeps refusing a built-in container. The plugin
  is checked when the `FormatPolicy` is built (the checks `register_format` runs, plus:
  its `format` is `ArchiveFormat(key, UNCOMPRESSED)`, and it declares no extensions,
  magic or probe). A bad plugin fails there, before any open (DR-15b).
- **Format identity.** `reader.format` is `ArchiveFormat.ZIP` and
  `format_info.from_plugin` is false, because the format is the built-in one. The caller
  named the plugin in its own config, so no new field says which reader ran.
- **What the built-in did around its reader.** A replacement gets what any indexed
  plugin gets: a seekable source, from the start of the archive. In v1 an open that
  needs more is refused with `UnsupportedFeatureError` naming the replacement:
  - a multi-volume set (7z, RAR and ZIP parts);
  - an archive found behind an SFX stub (the plugin would see the stub);
  - a read-once source, as for any indexed plugin.
  The format-specific options (`zip_unflagged_fallback_encoding`, `rar_decompressor`,
  ...) reach the plugin through `PluginContext.config`. Honouring them is the plugin's
  job, and the plugin guide says so.
- **Which containers.** ZIP, 7z, RAR and ISO, which an indexed plugin can read. TAR and
  `RAW_STREAM` wait for the sequential shape (`plugin-api` task 1b). `DIRECTORY` and
  `DMG` are refused as keys.
- A replaced container that `only` or `exclude` turns off is refused as a contradiction.

## 5a. Optional libraries

The maintainer asked (2026-10-27) whether a caller could turn off a codec because of a
security or performance problem in it, and then ruled that the switch is per library,
not per algorithm: "if a library is installed systemwide, there's currently no way for a
library user to avoid its use, which can be dangerous". A problem lives in a library,
and one algorithm can have several (deflate decodes through `zlib` or `rapidgzip`), so
turning off `DEFLATE` would also turn off the safe path.

```python
FormatPolicy(exclude_libraries={"pyppmd", "inflate64"})
```

- **The names** are the package names that `MissingComponent.name` (on
  `FormatAvailability.missing`) already reports: `pyppmd`, `inflate64`, `brotli`, `lz4`,
  `backports.zstd`, `rapidgzip`, `pycdlib`, `cryptography`. An unknown name, a standard
  library module (`zlib`, `bz2`, `lzma`, `compression.zstd`) and a program are refused
  with `ArchiveyUsageError`. The standard library is not optional: turn off the formats
  or compressions it reads instead. The programs (`unrar`, `unar`) keep their own
  setting, `rar_decompressor`.
- **An excluded library reads as not installed, for that call.** archivey already has
  this path: under PyPy, `deps.py` treats some installed packages as absent and gives
  the reason in place of the install hint (`MissingComponent.reason`). So every
  consequence is one that a missing package already has, and is already tested:
  - an accelerator under `AUTO` falls back to the standard library (DR-11);
  - a member that needs the library raises `PackageNotInstalledError` when opened, and
    the format reports `PARTIAL` (a PPMd member in ZIP or 7z, an encrypted member
    without `cryptography`);
  - a format that needs it raises at open (ISO without `pycdlib`, `.br` without
    `brotli`).
  Only the message changes: it names `config.formats` as the reason, not an install
  command, since installing the package would not help.
- **Never used, and if lazy, never imported.** An excluded library decodes nothing in
  that call. `brotli`, `pyppmd`, `inflate64` and `rapidgzip` are imported on first use
  (`LazyOptional`), so a process whose every call excludes one never imports it. `lz4`,
  zstd and `pycdlib` are imported when archivey loads, so they are loaded but unused.
  Making those lazy too is a separate change, worth doing only if the import itself is
  the concern.
- **Conflicts.** `use_rapidgzip=ON` (or `use_indexed_bzip2=ON`) with `rapidgzip` excluded
  is refused at construction as a contradiction; `AUTO` with it excluded is the normal
  fallback.
- **RAR.** `unrar` decodes RAR members, PPMd blocks included, so no Python library is
  involved; the maintainer ruled that fine (2026-10-27), since the concern is library
  problems.
- **Plugins.** A plugin's `requires` names the modules it needs. Excluding one of them
  turns that plugin off for the call, as a missing module does today.

`format_availability` gains no `config` argument in this change: it answers what the
environment provides. A caller that wants the policy's view asks
`config.formats.allows(fmt)` for the format and reads `exclude_libraries` itself.

## 6. Where it is checked

- `open_archive` asks `BackendRegistry.reader_for_format(fmt, policy)`, after
  detection and before the availability check. It refuses an off format and returns
  the replacement backend (built once per plugin class and cached) or the registered
  one. `open_stream` makes the same `allows` check before it opens the codec, so the
  CLI, which uses only these, follows the policy too.
- Detection reads `policy` only to filter plugin probes.
- The CLI gets no flag in this change. `--formats` can follow if someone asks.

## 7. Calls for the maintainer

All decided by the maintainer on 2026-10-27: call 1 on the decision card, calls 2 to 5
by agreeing to the rest of the design. Call 5 first named algorithms; the maintainer
then moved it to libraries.

1. **Option A (per call), not B (process-wide).**
2. **Plugins are on by default once registered.** Registration is already the
   program's explicit choice; `plugins=False` and `only=` turn them off.
3. **Replacement scope in v1: ZIP, 7z, RAR and ISO, with volumes and SFX refused.** TAR
   follows with the sequential shape.
4. **Name.** `FormatPolicy` and `ArchiveyConfig.formats`, after `DiagnosticPolicy`.
5. **Optional libraries can be turned off** (§5a), by package name, not by
   algorithm: `exclude_libraries=`. A deny-list only.
