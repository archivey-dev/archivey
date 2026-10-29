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

1. **Detection finds the true format among the formats it may consider.** Every
   built-in format is always considered, so the policy never changes a built-in answer.
   A plugin format the policy turns off is not considered at all: its magic, extensions
   and content probe are left out of that call's detection (§4).
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
    exclude_libraries: frozenset[OptionalLibrary] = frozenset()  # §5a
    plugins: bool = True
    replace: Mapping[ContainerFormat, type[FormatPlugin]] = {}  # stored read-only

    def allows(self, fmt: ArchiveFormat) -> bool: ...
```

Arguments take any iterable, as `DiagnosticPolicy` does, and the fields hold frozensets.

**When a format may open.** An `ArchiveFormat` is a `(container, stream)` pair, so the
entries are containers and compressions, and both halves must pass:

- The container passes when `only` is `None` or lists it, `exclude` does not list it,
  and, for a plugin container, `plugins` is true.
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
path. `C.UNKNOWN` is refused as an entry (`ArchiveyUsageError`). So is
`S.UNCOMPRESSED` in `exclude`: it would turn off every container without outer
compression, ZIP, TAR, 7z, RAR, ISO and directories included, which a caller says more
clearly by listing those containers. An entry in both `only` and `exclude` is refused,
as `DiagnosticPolicy` refuses a code in both lists.

**`plugins=False` and `only`.** `plugins` is for the deny-list form. Under `only`, a
plugin opens only when listed, so `plugins=False` adds nothing; listing a plugin
container in `only` with `plugins=False` is refused as a contradiction at construction.

**Where each check runs.** `FormatPolicy.__post_init__` checks what the policy alone can
see: entry types, `C.UNKNOWN`, `S.UNCOMPRESSED`, overlaps, the replacement plugins
(§5) and the library names (§5a). Checks against other config fields (an excluded
`rapidgzip` with `use_rapidgzip=ON`) run in `ArchiveyConfig.__post_init__`, beside its
other cross-field checks, since a policy cannot see those fields.

## 4. Detection and plugin code

Detection keeps every built-in table (DR-1, DR-5). A plugin format the policy turns off
is not a candidate in that call: its magic, its extensions and its content probe are all
left out, as if the plugin were not registered. The maintainer asked for this
(2026-10-28), for two reasons:

- **Its code must not run.** A content probe is the plugin's own code.
- **It must not shadow an allowed plugin.** Plugin magic is matched in registration
  order. If an off plugin's magic overreaches, it would claim a file that an allowed
  plugin also matches, and the open would be refused instead of reaching the plugin
  the caller allowed. Extensions cannot collide (registration refuses a taken one), but
  they are left out too, so that an off plugin contributes no signal at all.

This is §2's option D applied to plugins only, and the reason D is wrong for built-ins
does not carry over. Built-in magic always wins over plugin magic (the tie rule), so
leaving a plugin out never changes a built-in answer. And no format is layered inside a
plugin format the way TAR sits inside gzip, because the plugin API leaves out outer
compression around a plugin format. If that is added later, this rule needs a second
look: with an off plugin left out, `x.cpio.gz` would open as one gzip member.

A file that only an off plugin would recognise gets `FormatDetectionError`, a reported
absence (DR-1), not a wrong answer. This also holds under `always_probe_content=True` and
in `open_stream`, which run every probe the policy allows. When the policy left a
plugin out at any step and nothing matched, the `FormatDetectionError` message names the policy rather than
the three ways to read a nameless probe-only stream, none of which reaches a plugin that
is off. Each tier that left an off plugin out (`near_magic`, `far_magic`, `content_probe`,
`extension`) is recorded in the detection receipt as
`TierSkipReason.NOT_ENABLED_BY_POLICY`, the reason detection already gives a probe the
extension rule leaves out, so the receipt does not look like a complete search.
`format=` naming an off plugin's format is still refused by name, with
`UnsupportedFeatureError` (§1, rule 2).

**What the policy does not bound.** It decides which *reader* runs, not how much of the
file detection reads. Far magic, the SFX scan and the built-in content probes still run
on every input, under `detection_budget`. The security page says so in one sentence.

So `detect_format(source, config=...)` can differ by config only for plugin formats: a
file an off plugin would have claimed gets `FormatDetectionError`, or the allowed plugin
that also matches it. Built-in signals always run; they are archivey's code and the
policy is not a reason to report a different built-in format.

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
class OptionalLibrary(StrEnum):
    PYPPMD = "pyppmd"
    INFLATE64 = "inflate64"
    BROTLI = "brotli"
    LZ4 = "lz4"
    BACKPORTS_ZSTD = "backports.zstd"
    COMPRESSION_ZSTD = "compression.zstd"
    RAPIDGZIP = "rapidgzip"
    PYCDLIB = "pycdlib"
    CRYPTOGRAPHY = "cryptography"

OptionalLibraryStr = Literal["pyppmd", "inflate64", ...]  # one per member

FormatPolicy(exclude_libraries={OptionalLibrary.PYPPMD, "inflate64"})
```

**The type.** The maintainer asked (2026-10-28) for an enum or a literal set, so that a
caller knows exactly which names exist and a typo cannot silently leave a library on.
`exclude_libraries` follows `DiagnosticPolicy(ignore=)`: it takes
`Iterable[OptionalLibrary | OptionalLibraryStr]` and stores
`frozenset[OptionalLibrary]`. A type checker rejects a wrong name in either spelling,
an editor completes both, and the docs list the members. Construction still converts
each entry with `OptionalLibrary(name)` and refuses anything else with
`ArchiveyUsageError` that lists the members, for a caller without a type checker. A
test pins the `Literal` against the enum, as for `DiagnosticCodeStr`.

- **The names** are the package names that `MissingComponent.name` (on
  `FormatAvailability.missing`) already reports: `pyppmd`, `inflate64`, `brotli`, `lz4`,
  `backports.zstd`, `rapidgzip`, `pycdlib`, `cryptography`, one `OptionalLibrary`
  member each. The set is fixed: it does not read the plugin registry, so a policy
  accepts the same names whenever it is built. A new optional package adds a member
  and a `Literal` entry in the same change.
  `compression.zstd` is accepted too: it is the zstd module
  on 3.14 and later, and an optional part of a CPython build. An entry names a module,
  not a capability, so excluding one zstd module falls through to the other, as when it
  is absent; to turn off zstd decoding on every interpreter, exclude both. Excluding
  `backports.zstd` on 3.14 and later, where it is not used, changes nothing, and the
  docs say so.
- **What cannot be excluded.** An unknown name, `zlib`, `bz2` and `lzma`, and a program
  are refused with `ArchiveyUsageError`. Those three standard library codecs cannot be
  turned off: core formats depend on them, and per-algorithm control is out of scope by
  the maintainer's call 5. A caller who distrusts one can refuse only the containers and
  outer compressions that carry it, through `only=` and `exclude=`; a Deflate, bzip2 or
  LZMA member inside a ZIP or 7z still decodes while those containers are allowed. The
  programs (`unrar`, `unar`) keep their own setting, `rar_decompressor`.
- **An excluded library reads as not installed, for that call.** The consequences are
  the ones a missing package already has, and are already tested; under PyPy, `deps.py`
  already treats some installed packages as absent and gives the reason in place of the
  install hint (`MissingComponent.reason`). The mechanism is new, because every
  availability answer today is fixed for the process (see "How the policy reaches the
  checks" below):
  - an accelerator under `AUTO` falls back to the standard library (DR-11);
  - a member that needs the library raises `PackageNotInstalledError` when opened (a
    PPMd member in ZIP or 7z, an encrypted member without `cryptography`), and
    `format_availability(fmt, config=...)` reports the format `PARTIAL` for a member
    codec package (`cryptography` does not lower support, as today);
  - a format that needs it raises at open (ISO without `pycdlib`, `.br` without
    `brotli`).
  Only the message changes: it names `config.formats` as the reason, not an install
  command, since installing the package would not help. The reason is data, not only
  prose: the `MissingComponent` for an excluded package is built per call with `reason`
  set, so `advice` (which the refusal text and `format_availability` already use) says
  "turned off by `config.formats`". The raise carries it too: `PackageNotInstalledError`
  gains a `missing: tuple[MissingComponent, ...]` attribute holding the components this
  raise is about, set on every raise, policy or not.
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
- **Plugins.** A plugin's own modules are not names `exclude_libraries` takes: a caller
  turns a plugin off by its container, in `exclude=` or by leaving it out of `only=`.
  When a plugin the policy names (in `replace=`, or a container listed in `only=`)
  lists an excluded package in its `requires`, such as a replacement that needs
  `cryptography` with `cryptography` excluded, the policy is refused at construction as
  a contradiction. A replacement is never quietly swapped back to the built-in reader.
  The reason is that the caller named that plugin, so a policy that cannot use it is a
  mistake in the policy, and construction is the earliest place to say so. A registered
  plugin the policy does not name is different: excluding a package it requires makes
  its format NONE under that config, and opening one of its files raises
  `PackageNotInstalledError` naming the policy, as for a built-in format whose package is
  excluded.

**Asking up front.** `format_availability` and `list_supported_formats` gain a keyword
`config=None`. Without it they answer what the environment provides, as today. With it,
an excluded library counts as absent: it appears in `missing` with the policy as its
`reason`, and `support` drops to `PARTIAL` or `NONE` as it would if the package were not
installed. So with `pyppmd` installed and excluded, `format_availability(SEVEN_Z,
config=cfg)` answers `PARTIAL` with `pyppmd` in `missing`. The two questions stay apart:
`format_availability(fmt, config=cfg)` says what can decode, `cfg.formats.allows(fmt)`
says what may open. A caller needs both to know whether a format will read, and the
docs say so next to each. `list_supported_formats(config=cfg)` follows
`format_availability`: it returns the formats whose support under `cfg` is `FULL` or
`PARTIAL`, and it does not filter by `allows()`. So with `only={C.ZIP}` it still lists
7z, RAR, ISO and every registered plugin format. A caller that wants the formats it
may open writes `[f for f in list_supported_formats(config=cfg) if
cfg.formats.allows(f)]`; a helper for that one line is not added (DR-14).

`replace=` is the one other field that changes the availability answer. For a replaced
container `format_availability(fmt, config=cfg)` answers for the backend that would
read it, the replacement, not the built-in. The replacement's `requires` count as a
registered plugin's do: a missing one makes the format `NONE` with that package in
`missing`, and the open raises `PackageNotInstalledError` before the plugin's `open`
runs. An excluded one cannot reach this point, since the policy is refused when it is
built (the Plugins bullet above). `only`, `exclude` and `plugins` do not change the answer.

**How the policy reaches the checks.** Every place that answers "is this package
available" is process-wide today: `LazyOptional._present` (fixed at construction, module
globals in `deps.py`), `registry._optional` (memoised, never invalidated) and
`_missing_dependency`, `codecs.registry.is_codec_available`, `StreamCodec.available`
and `_backend_present`, and the module-level `MissingComponent` constants. None of them
is mutated per call: archivey is sync but readers are used from several threads, and a
global flipped for one call would give another thread the wrong answer in both
directions. Instead each of these takes the set of excluded names, carried from
`ArchiveyConfig.formats` on the objects that already reach a codec open (the reader's
config and the stream config). An excluded name answers "absent" before the
process-wide answer is consulted; an empty set (the default) leaves every check as it
is today.

**Exception types.** The refusals reuse `UnsupportedFeatureError` and
`PackageNotInstalledError` (DR-13): a caller that wants to tell a policy refusal from
another one has it as data. For a format refusal it asks
`config.formats.allows(exc.source_format)`. For a library refusal it reads
`exc.missing`: a component whose `name` is in its `exclude_libraries` was refused by its
own policy, and any other component needs installing. That holds when one raise has both
causes. `missing` is filled on every raise for an absent package or program: the unrar
sites fill it from `rarlab_unrar_missing()`, and the `unar` refusal when no usable
`unar` is found (`CliToolFinder.find`) builds one from the finder's `display_name` and
`install_hint`. It is empty only when the program is found but cannot start
(`spawn_for_stdout`'s `not_started`), where nothing is missing to name. The message
keeps naming the package and its install hint, as the format specs require: the
error-handling rule against repeating a structured name in the message is about names
`__str__` renders, and `__str__` does not render `missing`.
`missing` is an additive attribute on an existing type, not a new type (DR-13). Both
docstrings widen in the same change: `UnsupportedFeatureError` also covers "the caller's
`FormatPolicy` refuses this format", and `PackageNotInstalledError` also covers "the
caller's `FormatPolicy` excludes the package; the message says so instead of an install
command". A new exception type for policy refusals would be a public name for the
maintainer, and no caller is known that would act on it differently.

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
