# plugin-platform — design

A plan, not a specification. It states the architecture, the decisions the maintainer
has taken, and the questions still open. Signatures here are sketches; each
implementation step settles its own and writes the spec delta.

## Context

Checked on main `2b66e25` (2026-11-24).

- **Two paths.** Built-in formats register with `register_reader`, or with
  `register_builtin_format` and backend overrides a plugin cannot declare. Plugins
  register with `register_format`. A built-in container is a `ContainerFormat` member
  (20 of them), a plugin's is a `PluginContainer` subclass. A plugin's detection signals
  count only when no built-in signal matched.
- **Closed enums that are not closed.** `CompressionAlgorithm` (31 members) already
  holds LZX, LZH, ARJ_FAST, QUANTUM, LZFSE, LZVN and ADC, which only plugin-shaped
  readers use. `OptionalLibrary` says that a plugin's own module "is not a member", so
  `MissingComponent.name` holds two kinds of value.
- **Loading.** `archivey/internal/backends/__init__.py` imports all 19 reader modules
  for their side effect: 210 modules and 0.27 s warm for `import archivey`. A comment
  keeps `deb_reader` ahead of `ar_reader`, because a `.deb` starts with ar's signature
  and the first registered signature wins.
- **Codecs.** `register_codec` adds a stream format (a file type with extensions and a
  signature). ZIP method numbers and 7z coder ids map to an internal `Codec` enum in
  tables inside the readers.
- **Reader API.** 13 readers are written on `archivey.formats`. ar, cpio and rpm import
  public names only. The other ten import `archivey.internal` (§5 lists what).
- **Size.** The 13 readers and their helper modules are about 24,000 lines. ZIP, TAR,
  7z, RAR, single-file and directory are about 43,000.
- **Core barely names the formats that would move.** Outside the readers and the enum,
  the 13 `ContainerFormat` members appear in four places: a makeself hint in `core.py`,
  one list in `cli/common.py`, `REPLACEABLE_CONTAINERS` in `format_adapter.py`, and two
  speed-up tables in `registry.py`.
- **Diagnostic codes are generic.** None of the 49 is format-specific.

### How other projects do it

Read on 2026-11-24.

- **fsspec** names protocols by string. Its `known_implementations` table lists other
  projects' classes by dotted path with an error text ("Install s3fs to access S3"),
  imports a class on first use, and also collects the `fsspec.specs` entry point group,
  storing paths without importing. This is the closest model: a platform whose main
  providers are other packages, mentioned by name in core and treated like its own.
- **numcodecs** names codecs by `codec_id` string. It collects the `numcodecs.codecs`
  entry points at import without loading them and loads one only when its id is asked
  for and not yet registered.
- **imageio** keeps a `known_plugins` table of `PluginConfig(name, class_name,
  module_name, install_name)` and imports the module lazily.
- **Pillow** names formats by string and its own formats call the same
  `register_open()` an outside plugin calls. It loads five common formats first and all
  the others only if those fail. An outside plugin must be imported by the program,
  which is the explicit-only cost in practice.
- **pytest** autoloads the `pytest11` entry point group after its built-in plugins and
  has two off switches: `PYTEST_DISABLE_PLUGIN_AUTOLOAD` and `-p no:name`.
- **Sphinx** loads the modules a project lists, each with `setup(app)`. A config-file
  tool can ask for an explicit list; a library has no such file.
- **libarchive** keeps formats and filters as two lists that combine freely, and a
  program enables each per handle. archivey already has both ideas: the two halves of
  `ArchiveFormat`, and `FormatPolicy`.
- **pluggy** calls every plugin for every hook. archivey needs one provider per name, so
  it is not a fit.

## Goals / Non-Goals

**Goals**

- One way to declare, find, name and load a format or a codec, used by core too.
- `import archivey` loads no reader.
- Core holds no type, enum member or code path that exists only for plugins. A short
  mention of a package, such as an install hint, is allowed.
- A core reader can use a codec that another package supplies.
- Our own packages use public names only, and a CI job proves it.
- A reader is straightforward to write: a short contract, with archivey doing the
  shared work.

**Non-Goals**

- Archive writing.
- Moving ZIP, TAR, 7z or RAR onto `archivey.formats`. The 2026-10-30 survey found
  little of their code would move.
- New diagnostic codes for plugins.
- A `--plugin` option for the CLI. Installed packages are found without one.
- Moving rapidgzip, compress-utils or cramjam onto the codec registry's priority rule.
  Possible later; nothing here needs it.
- Declaring the plugin API stable. That stays the maintainer's call.

## Architecture

```text
 archivey (core)        our format packages        anyone's package
        \                       |                       /
         +---- manifest files (data, nothing imported) ----+
                               |
                     manifest table in core
          name, extensions, signatures, dotted path of the code
              a name, extension or signature has one owner
                 /             |                \
          detection      format readers      codec registry
        (table alone)  (imported on first   (by name or method
                         open of a format)    number)
                               |
   hint table: a known format whose package is missing is refused
          with its install line, never read as another format
```

### 1. The manifest

A manifest is a data file, not Python. Core reads it without importing or running
anything from the package that ships it.

```toml
# archivey_dmg/archivey-manifest.toml
api = "1.0"

[[format]]
name = "dmg"
extensions = [".dmg"]
trailer = { offset = -512, hex = "6b6f6c79" }      # "koly"
preempts = ["bz2", "xz"]
handler = "archivey_dmg.reader:DmgHandler"

[[codec]]
name = "lzfse"
decoder = "archivey_dmg.lzfse:LzfseCodec"
```

- A format entry carries what `FormatHandler` declares as class attributes today:
  name, extensions, signatures at a fixed offset, trailer signatures, `requires`, the
  install hint, whether it reads in one pass, whether it takes a password. It adds the
  handler's dotted path, and optionally `refines`, `preempts` and a dotted path to a
  refinement check or a probe (§4).
- Dotted paths are text until a call's policy has allowed the provider and the format
  (§3). Only then is a probe, a handler or a decoder imported.
- Core's own formats are entries in the same shape, in a table inside `archivey`. Their
  handler paths point into `archivey.internal`. The table does not care which base
  class a handler is built on.
- `register_format()` and `register_codec()` take the same entry as an object, for a
  program that adds a format of its own at run time. That is the program's own code,
  which it chose to run.

### 2. Names

A name is a short lowercase string. A registry decides what a name means when an
operation uses it.

```python
ContainerFormat.ZIP          # a constant, for what core ships
ContainerFormat("dmg")       # any well-formed name
ArchiveFormat("dmg")         # stream defaults to uncompressed
fmt.container == "dmg"       # True, as today

from archivey_dmg import DMG            # = ArchiveFormat("dmg")
```

What changes:

- `ContainerFormat`, `StreamFormat`, `OptionalLibrary`: open string types, equal to a
  plain string of the same spelling, as the `StrEnum` members are today.
- `CompressionAlgorithm`: an open value type that is **not** a string, as it is not one
  today (a plain `Enum`). It is equal only to another `CompressionAlgorithm`. This
  keeps `FormatPolicy.exclude` correct, where `StreamFormat("xz")` (refuse `.xz` files)
  and `CompressionAlgorithm("xz")` (turn the decoder off everywhere) sit in one set
  and mean different things. A string type equal to both would make one exclude the
  other, and no equality rule can separate two string subclasses that both equal
  `"xz"` (review A2).
- Constants stay for core's own names in all four.
- `PluginContainer`, `PluginStream`, `ContainerFormatStr`, `StreamFormatStr`,
  `OptionalLibraryStr`: removed.
- `DiagnosticCode`, `HashAlgorithm`: unchanged. A plugin digest is already named by
  string in `MemberDigest`, and `ArchiveMember.extra` keys are namespaced strings.

Rules:

- **One owner.** The registry refuses a second registration of a name or a signature
  and never switches providers silently. A signature that extends another entry's
  signature (`FOOBAR` over `FOO`) is a refinement and follows the consent rule of §4;
  among the signatures that may match, the longest is tried first, before distribution
  order. An extension is weaker evidence (`.img`, `.bin` and `.run` are shared by
  unrelated formats): when a second entry claims an extension that is taken, only that
  extension is dropped from the second entry, and its name and signatures register.
- **Refusals have a place to be read.** A query in `archivey.formats` lists every
  provider found with its state and reason, and `archivey --version -v` prints it. A
  refused entry and a manifest that does not parse have no format name to pass to
  `format_availability()`, so this query is the only place they show.
- **A name that cannot run is still known.** A manifest has an envelope that never
  changes with the API version: `api`, and the `name` of each format and codec. Core
  reads it from any manifest it can parse. The names of an incompatible provider are
  kept for diagnostics and are not eligible to run. So a lookup by name has three
  outcomes that do not blur: a name nobody declares is `ArchiveyUsageError`; a name
  whose package is missing is `PackageNotInstalledError` with the hint; a name whose
  provider is installed and incompatible is reported as incompatible, with both API
  versions, by `format_availability()` and by the error on open (§5).
- **A name is a value; a registry is asked when an operation resolves it.** Building
  `ContainerFormat("dmg")` or `ArchiveFormat("outside-format")` checks the spelling
  only (lowercase letters, digits, `.`, `_`, `-`), touches no registry and starts no
  discovery. So a name read from a config file loads on a machine without the plugin,
  and building a value never depends on what is installed or on which call ran first.
  Membership is checked when a call resolves the name against its effective registry
  and policy, before any I/O: `open_archive(path, format="dgm")` raises
  `ArchiveyUsageError` for a name nobody knows, and `PackageNotInstalledError` with the
  hint for a name that is known and not installed. Core's named constants stay.
- **Provenance is data.** `FormatInfo.provider` is the distribution name: `"archivey"`
  for core.
- **`providers=` replaces `plugins=` (ruling R2).** `FormatPolicy(providers={...})`
  names the distributions whose code may run. `plugins=False` is the same check as
  today, "the `archivey` distribution only", but what it allows shrinks at the split:
  with `archivey[recommended]` installed it opens an ISO in 0.6.0 and refuses it in
  0.7.0. So the flag is not described as unchanged. It warns for one minor, means
  `providers={"archivey"}`, and the changelog carries the narrowing under
  **Breaking:**. A server that wants our packages and nobody else's writes
  `providers={"archivey", "archivey-disk-images"}`.
- **Libraries (ruling R5).** `only_libraries` cannot be computed by subtracting from an
  open type, so it is defined directly: under `only_libraries` a library may be used when it is
  listed, whoever requires it. Today a plugin's own module stays enabled under
  `only_libraries`; that exception goes, since core no longer knows which modules are
  a plugin's (**Breaking:** in step 2). A name in either library set is checked when a
  call starts, against the libraries that core and the installed manifests declare, so
  a typo is still an error and cannot leave a library on. `OptionalLibrary` stays a
  type that extends `str` (ruling R8), and each package exports a constant for every
  library it uses (`archivey_dmg.CRYPTOGRAPHY`-style names beside core's
  `OptionalLibrary.PYPPMD`), so a caller rarely types a library name at all.
- **Policy sets are stored by role.** `FormatPolicy` keeps containers, streams and
  methods apart inside, whatever the caller passed in one `exclude=` set, so no lookup
  compares a method with a stream.
- **Constants live with their owner.** Core has no `ContainerFormat.DMG`. The moved
  constants stay one release as aliases that warn and name the package: 13 on
  `ContainerFormat`, `StreamFormat.PBZX`, the 14 matching class constants on
  `ArchiveFormat`, and 11 on `CompressionAlgorithm` (the four legacy ZIP methods, LZX,
  LZH, ARJ_FAST, QUANTUM, LZFSE, LZVN, ADC). The warning needs a class-level hook that
  both type checkers accept, and core's own code (`FormatPolicy.COMMON`) names the
  moved methods by string so that importing archivey does not warn.

### 3. Discovery and loading

```toml
[project.entry-points."archivey.plugins"]
disk-images = "archivey_disk_images"
```

Discovery is passive: it reads metadata and one data file per package, and executes no
installed code.

1. `import archivey` loads the public types, the config and core's own table. It scans
   nothing.
2. The first call that needs the registry lists the `archivey.plugins` entry points
   without loading them, once, in sorted order of distribution name, so the result does
   not depend on install order. An entry's value names a top-level package, and the
   entry point belongs to one distribution. Core reads `archivey-manifest.toml` as a
   file of **that distribution** and parses it with `tomllib`. Nothing is imported.
3. Detection of a format's family runs on manifest data alone.
4. Each call applies its effective `FormatPolicy` (provider, then format) **before**
   any dotted path of an installed package is imported: a refinement check, a probe, a
   handler or a decoder. Under `plugins=False`, or under an allow-list that does not
   name the format, no module of the package is imported in that call. The policy of
   one call does not depend on what an earlier call did, apart from modules being
   already in `sys.modules`.
5. A handler module is imported when an archive of its format is opened.

Guardrails:

- **The provider that is authorized is the one that runs.** The import system resolves
  a module name on the path and knows nothing of distributions, so a name alone does
  not say whose code loads: two installed distributions can expose the same top-level
  module. At every place where a manifest turns into code, core establishes the owner
  first, from metadata, and refuses when it cannot:
  - a top-level module named by a manifest must belong to exactly one installed
    distribution, and that one must be the manifest's own. A name two distributions
    expose is refused for both and reported;
  - the module the import system would load (`find_spec`, which runs no package code)
    must be a file of that distribution, where its file list says so;
  - this holds for the manifest, a handler, a probe, a refinement check and a decoder,
    in the caller's process and in the decoder child alike;
  - a codec's `native` object usually lives in a dependency (the library it wraps), not
    in the package. Its module must be one the entry lists in `requires`, the library
    policy (`exclude_libraries`, `only_libraries`) governs it, and the one-owner check
    applies to its top-level name too.
  Test: two distributions that expose the same import name, one allowed by
  `providers=` and one not, with the recorder of the next point in both. Neither runs.
- **Policy before import** (point 4). The test: a wheel whose `__init__` records that it
  ran, installed beside core. Discovery, opening a core ZIP, and
  `format_availability()` are run under the default policy, `plugins=False` and
  `FormatPolicy.COMMON`, in both orders, and the recorder must stay empty except where
  a call opens one of that wheel's formats under a policy that allows it.
- **A plugin adds and never takes over** (the one-owner rule of §2, and §6 for codecs).
  Replacing a reader stays an explicit choice of the calling program,
  `FormatPolicy(replace=...)`.
- **Allow-lists do not move.** `FormatPolicy.COMMON` and any `only=` policy name what
  may run, whatever is installed.
- **One off switch for a deployment.** `ARCHIVEY_PLUGIN_AUTOLOAD=0`, or
  `archivey.formats.disable_autoload()` before first use, skips the listing in point 2.
  It is a default for the process. A caller's policy works without it.
- **Visible.** `archivey --version`, `format_availability()` and `BackendUse` name the
  provider of each format and decoder. The provider query of §2 lists what was refused
  or skipped.
- **A bad manifest does not break core.** A file that does not parse is skipped and
  reported with the reason. One the host's API version does not accept is reported as
  incompatible (§5).

Rejected: a manifest as a Python module that the entry point loads. Importing it runs
the package's `__init__` before any policy is known, so `plugins=False` could not keep
its promise, and catching an error cannot undo the execution (review C1).

### 4. Detection order, refinements and the hint table

Detection has three phases, the same on every install:

1. **Family, from data.** Extensions, signatures at a fixed offset and trailers, from
   core's table, the installed manifests and the hint table. This settles which family
   the file belongs to (ar, xar, a UDIF image) without code from any package.
   Trailers keep today's access shape: when the trailer tier runs, it adds one seek
   towards the end, **one** read and one seek back, however many entries declare a
   trailer. All declarations are matched against one shared tail window with a fixed
   cap (the largest today is DMG's 512 bytes). A manifest whose trailer does not fit
   the cap is refused when it is loaded, and never costs a second range read on a
   network source.
2. **Refinement, bounded.** A family may have narrower readings: deb over ar, pkg over
   xar. This runs **after** a signature has matched, as `_near_magic_hit` does today,
   and under the same read budget (the near window on a forward-only source, up to the
   read ceiling on one that can seek).
   - A refinement that data can state is data: a `.deb` is ar's signature followed by a
     member named `debian-binary`, which is a longer signature at a fixed offset. Core
     decides it on any install.
   - A refinement that needs parsing names a check by dotted path, with the shape
     `MAGIC_REFINEMENTS` has today: `(peek, name) -> bool`, under the detection budget.
     pkg's check looks at the suffix and, for an unnamed file, reads up to 256 KiB of
     the xar table of contents, which no fixed signature or 4 KiB prefix can express.
     The check runs only when the package is installed and the call's policy allows it.
   - A refinement and its base ship in one distribution. So when the package is
     missing, the refusal names the right package even where core cannot tell pkg from
     xar. This is the one place the guarantee is weaker, and it is stated: on a
     core-only install `detect_format()` reports the family (`xar`) with its provider
     missing, not the refinement.
3. **Availability.** The format's provider is installed and allowed, or the call is
   refused with the hint.

`refines` and `preempts` take something from another entry: a refinement takes files
its base would read, and a preempting trailer outranks a signature (a UDIF image whose
first block is bzip2 or xz data must not be read as a `.bz2`). Both need the consent of
the entry they take from: they are valid inside one distribution, when the owner's own
table lists them, or when the calling program's policy names the refining format. Core's
hint table lists the DMG trailer (and its encrypted headers) over core's bzip2 and xz
signatures, so a UDBZ or ULMO image is never read as a `.bz2` or `.xz`, with or without
the package. A package cannot refine or preempt ZIP on its own word, and a format
layered on another project's format (an `.ipk` over ar, an AppImage over SquashFS)
stays possible: by a line in the owner's table, or by the caller's choice.

Every phase sees every entry. Discovery is complete before the first detection, and it
is never put off until core's own signals have failed: a compressed UDIF image, an
`initrd.cpio.gz` and any outside format inside a gzip stream all match a core signature
first, and would be read as plain `.bz2` or `.gz` (review A3).

**The hint table** is the same entry data, in core, with a package name in place of
the dotted paths. When the package is missing, opening such an archive raises
`PackageNotInstalledError` naming the package. It is what keeps "same archive, same
contents" true across installs: an archive reads the same way or is refused with a
hint, and is never read as another format. A CI test keeps the table equal to our
packages' manifests. An outside project adds its line by pull request, as projects do
in fsspec.

**A hint is also a reservation.** It reserves the name, the extensions, the signatures
and the method slots it lists for the distribution it names, when the registry is
built, whether or not that distribution is installed. Another package that claims
`ar`, or ZIP method 1, is refused as it would be with the owner present. Otherwise
installing an unrelated wheel would turn a named refusal into a different reader, and
installing the expected package later would change the winner again. Only an entry
from the named distribution fills a reserved place, unless the calling program chooses
a replacement. Tests: the owner absent, both installed, and the owner installed but
incompatible.

Tests for this section, before any reader moves: a UDBZ and a ULMO image, a
`.cpio.gz`, a real pkg and a plain xar, a real deb and a plain ar, each with a correct,
a missing and a misleading suffix, on a core-only and a full install;
`detect_format()` and `open_archive()` must agree; read budgets are measured on
seekable and forward-only sources. Success is the same format and contents where the
reader is available, and a truthful refusal where it is not.

### 5. The reader API

The shape of `archivey.formats` stays: a handler that declares, and an indexed or a
sequential reader that hands archivey members and bytes.

**Two levels of code, one contract.** Registration, naming, detection and policy are
the same for every format. Code inside the `archivey` distribution may use
`archivey.internal`; code in any other package, ours included, may not.

**The public-names test is the definition of done.** It fails on an import of
`archivey.internal` and on any use of a private attribute (`._name`) of an archivey
object, as `tests/test_cli_uses_public_api.py` does for the CLI. An import-only test
would pass while a moved reader still reached into `ReaderContext`.

What the ten readers import from `archivey.internal` today, and how each is resolved:

- Own decoders (LZX, LZH, LArc, ARJ fast, ADC, LZFSE), used by CAB, LHA, ARJ, DMG: move
  with the format.
- Own helper modules (CD sectors, cue sheets, UDF, UDIF, HFS+, APFS, the xar reader),
  used by ISO, DMG, pkg: move with the format.
- The Rust or Python kernel switch (`kernels`), used by CAB, LHA and DMG: a public
  kernel helper (§6, "Kernels"). It is not the codec registry.
- The child-process decoder switch (`Natives`), codec requirements and excluded
  libraries, used by SquashFS and ISO: a block call on `ReaderContext` (§6).
- Listing-limit helpers (`str_retained_bytes`, `metadata_limit_error`), used by ISO,
  xar, CAB, DMG: public, beside `ReaderContext.charge_metadata`.
- Timestamp and Unix-mode helpers, used by ISO, LHA, ARJ: public, beside `set_unix_time`
  and `unix_member_type`.
- The SFX stub scan, used by LHA and ARJ: the entry declares that the format may sit
  behind a stub, and core runs the scan.
- AES and key-derivation primitives and the password error, used by makeself, DMG, ARJ:
  a small public crypto facade beside `charge_key_derivation` and `NeedsPassword`.
- Nested-archive helpers (`HeldInnerData`, `DependencyIndex`), used by deb and pkg:
  folded into `ReaderContext.open_nested`.
- Path helpers (`collision_key`, `extracted_segments`, `is_rooted`,
  `strip_absolute_root` and their kin), used by deb and pkg for the layout rules of
  `dpkg-deb` and `pkgutil`: public as they are. They are path rules, not nesting.
- Limit checks (`refuse_past_archive_ratio`, `check_decoder_memory`), used by DMG and
  CAB: public, beside `charge_metadata`.
- `override`: a three-line shim in each package (Python 3.11 has none in `typing`).
- Source helpers (`JoinedViews`, the trailing scan, the callback source), used by ISO
  and DMG: methods on `ReaderSource`.
- `register_builtin_format` and its overrides, used by all 13: the manifest entry.

Private attributes of public objects that the readers use today, each of which
becomes a public call or goes:

- `context._spanning_check`, `_spanning_pass` (makeself digests, DMG `verify_all()`).
- `context._decompress_coder` (xar: one stream, bytes after it are damage): an option
  of `ReaderContext.decompress` (§6).
- `context._nest`, `_track_decoded`, `_usage` (decoded-byte and decoder-use accounting
  in CAB, ARJ, SquashFS, DMG, makeself).
- `context._listing_draw`, `_keep_metadata` (DMG, UDIF, APFS listing budgets).
- `source._origin`, `_will_read`, `_progress_reporter`, `_raw` (SFX offsets in LHA and
  ARJ; range hints in ISO, UDF, DMG; progress over a multi-file cue sheet).

**Typed `extra` keys (ruling R3).** `MemberExtra` and `ArchiveInfoExtra` carry 62
`@overload`s today, one per known key: 20 for core's formats and 42 for the formats
that move. An outside plugin cannot add one. All of them go, core's too, and one
mechanism serves every format:

```python
# archivey: the whole mechanism
class ExtraKey(str, Generic[T]): ...

class MemberExtra(dict[str, object]):
    @overload
    def __getitem__(self, key: ExtraKey[T], /) -> T: ...
    @overload
    def __getitem__(self, key: str, /) -> object: ...

# archivey_dmg: a format declares its keys beside its reader
class DmgExtra:
    RESOURCE_FORK_SIZE = ExtraKey[int]("dmg.resource_fork_size")

member.extra[DmgExtra.RESOURCE_FORK_SIZE]     # int, no cast
member.extra["dmg.resource_fork_size"]        # works as today, typed object
```

A key is a string, so the dictionary and its contents do not change, and `get()` is
typed the same way. Core's formats declare their keys in the same shape. The
conformance checks fail a reader that sets a key it did not declare. **Breaking:** for
type checking only: a caller who subscripts with a string literal, for a ZIP key too,
gets `object` until it uses the constant. It lands with the open names in step 2.

Each new public helper lands in the pull request of the reader that needs it. Nothing
is added on speculation.

**Threads.** The concurrency cut is a separate change that lands before this one
(decision 9), and it owns the thread contract a reader author sees
(`openspec/changes/archive/2026-11-25-concurrency-cut`). This change takes that
contract as it stands and does not restate it, so the two cannot drift apart. What the
plugin work needs from it:

- archivey calls the methods of one reader from one thread at a time;
- a pass over the archive runs with nothing else reading the archive beside it;
- several member streams of one reader may be open at once, each read by one thread
  at a time, which is what `archivey.fsspec` needs.

A sequential reader may still see `walk()` start again while an earlier walk is open,
because each open member stream that reads its data through a walk has a walk of its
own. A reader keeps a walk's state in the generator. The rules are the same for every
format.

**Version.** `archivey.formats.API_VERSION` is a pair, `(major, minor)`, with its own
numbering, apart from archivey's version.

- Within one major the API only grows. A minor adds names and never removes or changes
  one. Any breaking change, during the experimental period too, raises the major.
- A manifest states the API it needs: `api = "1.2"` means major 1 and at least minor 2.
  A host accepts it when the majors are equal and the host's minor is not lower.
- The check runs on the manifest, before any code of the package is imported.
- A refused plugin is reported as **incompatible**, with both versions, in
  `format_availability()` and in the error on open. This is a different outcome from a
  missing package, with a different message. It works for a format outside the hint
  table too, because the names in a manifest's envelope are read whatever its API
  version (§2).
- Tests: an older and a newer plugin against the first two host releases, and an
  unsupported pair.

Until the API is declared stable, a host minor release may raise the API major. Our
packages depend on one minor of core (`archivey>=0.7,<0.8`) and are released with it,
so they never meet that case; the tests above use a plugin outside that lockstep so
the rule is exercised and not hidden by it.

### 6. Codecs

```toml
[[codec]]
name = "shrink"
decoder = "archivey_legacy_formats.zip_methods:ShrinkCodec"
methods = { zip = [1] }        # a vacant slot in ZIP's method namespace
# native = "somelib:Decompressor"   a native decoder object, for process isolation
# stream = { extensions = [".lzo"], hex = "..." }   for a file format of its own
```

- **Method binding.** The ZIP reader reads method 1 and asks the registry for
  `("zip", 1)`. With the package installed it gets the decoder. Without it, the hint
  table names the method and the package, and the member lists and refuses to read with
  that hint. 7z coder ids use the `"7z"` namespace. A plugin container may open a
  namespace of its own.
- **Stream facet.** What `CodecHandler` declares today: the single-file format and the
  `.tar.<ext>` pair.
- **By name from a reader.** `ReaderContext.decompress(data, "<name>", ...)` takes a
  string. The caller's limits and `FormatPolicy` apply inside the call, the same for
  every codec. An option asks for one stream with nothing after it, which xar needs.
- **Block call.** A new `ReaderContext` call for block formats (SquashFS, DMG): bytes
  in, bytes out, a stated size, under the same limits.
- **What a method binding passes.** A decoder bound to a method needs what the
  container knows. `CodecCall` gains the matched method id (Reduce serves ZIP methods
  2 to 5 and takes its factor from the number), the container's flags as the namespace
  defines them (Implode reads ZIP general-purpose bits 1 and 2), and whether the input
  runs on past the member (Shrink refuses an unsized streamed member).
- **Password confirmation.** An entry states whether its decoder rejects random input
  within a few bytes. The four legacy ZIP methods do, and password confirmation uses
  that to try a candidate on 64 KiB and not on the whole member.
- **Availability of a container.** `format_availability(ZIP)` counts the methods in
  core's table and in the hint table: `FULL` when each has its decoder. A core-only
  install is `PARTIAL` and names `archivey-legacy-formats`, and `[recommended]` is
  `FULL` as today. A method that only an outside package declares never counts.

**Process isolation (ruling R4).** `ProcessIsolation.NATIVE_DECODERS` moves native
decoders to the decoder child. Today a codec registered through the public API runs
in the caller's process whatever the setting. The child is already generic: it builds
one decoder object, calls the method it is told with the bytes it is given, and sends
back the output with the object's `eof`, `needs_input` and `unused_data`. Only its
table of loaders is fixed, and the child imports nothing from archivey.

So a package gets isolation without writing any of it:

- A codec entry names its native object: `native = "somelib:Decompressor"`.
- The codec asks archivey for that object (`call.native(...)`). It gets the object
  itself, or under `NATIVE_DECODERS` a stand-in with the same methods that runs in a
  child. The child imports that one dotted path and nothing else. The codec's own
  logic stays in the caller's process and is the same in both cases.
- A library that is not shaped like a decoder object (a one-shot function) needs a
  small adapter class, in a module of the package that imports only the library.
- An error raised in the child reaches the codec's `translate_exception` as something
  it can recognise. The mapping rule is settled with the implementation.
- A codec with no `native` is pure Python and never pays for a process.
- The dotted path is loaded only for a provider and a format that the call's policy
  allows, like every other path of a manifest.

The limit that remains is stated in the security page and the threat model: a package
that runs native code without declaring it is not isolated. `providers=` is how a
caller keeps such a package out.

**Who may decode what.** Installing a package must not change which code decodes a
member that already decoded. Priority alone would allow that, so eligibility comes
first:

- **A vacant slot may be filled.** The owner of a method namespace (ZIP's reader for
  `"zip"`) says which numbers it decodes itself. Any other number is vacant unless the
  hint table reserves it (§4), and one package may fill it: legacy ZIP Shrink at
  `("zip", 1)`. A slot has one owner, like a name.
- **An occupied slot or an existing name is replaced only with consent.** A second
  implementation is eligible when the owner of the name lists it or when the calling
  program selects it in its policy. An unlisted package that claims a higher priority
  for ZIP's Deflate is refused and reported. Nothing of ours uses this at first.
- **Priority ranks eligible implementations only.** The one that ran is named in
  `BackendUse`.
- **An approved implementation follows the accelerator rule:** the same bytes and the
  same error type as the first, the parity tests as the entry bar, and the host's
  limits and isolation around it.
- **An allow-list keeps its decoder set.** Under `only={ZIP}` the decoders that may run
  are the ones ZIP's owner approved, before and after an unrelated wheel is installed.

Tests: a vacant slot with and without its provider; an unrelated distribution claiming
a higher priority for a stock method (refused, reported, the stock decoder runs); a
test wheel that the owner lists, and its fallback.

**Kernels (ruling R1).** `archivey-codecs` does not go through the codec registry.
Review A1 showed that it cannot:

- Eight of its ten kernels are not incremental stream decoders: a checksum (CRC-16), a
  cipher (ZipCrypto), filters (BCJ2 with four inputs, ARM64, RISC-V), one-shot block
  calls (LZFSE, LZVN, LZO1X), LZX with a size set between frames, LZW with snapshots.
- The package has no Python dependency and its own release tags. archivey imports it,
  never the reverse, and skips a kernel whose revision is too old. A manifest and an
  API version would reverse that.
- archivey's wrapper turns a Rust panic (a `BaseException`) into `CorruptionError`,
  latches the object that panicked, and runs the decoding kernels in the child under
  `NATIVE_DECODERS`. A codec entry has none of that.

So `archivey-codecs` stays what it is: an optional library, named by
`OptionalLibrary("archivey_codecs")`, that speeds up decoders and changes no result.
What becomes public is the switch. A reader asks `ReaderContext` for a kernel by name
and passes its own Python decoder as the other side; it gets the Rust kernel, wrapped
with the revision check, the panic guard and the child, or its own decoder back. Core
(ZIP, 7z, `.Z`), `archivey-dmg` (LZFSE, LZVN), `archivey-package-formats` (CAB's LZX)
and `archivey-legacy-formats` (LHA's CRC-16) call the same helper, and each Python
twin moves with its format.

Other rules:

- **Register a codec only when another package uses it.** LZX (CAB alone) and LZH (LHA
  and ARJ, which ship together) stay plain imports inside their package, with the
  kernel helper for LZX's Rust side.
- **What is part of parsing stays with the parser.** The 7z filters, ZipCrypto and AES
  stay in core.
- The decoder interface plugins see stays the incremental `Decompressor`. The
  full-decoder hook stays private (maintainer, 2026-10-30).

### 7. Packages

All under `packages/` in this repository, each a flat top-level module
(`archivey_disk_images`), released with core at the same version. Four format
packages (rulings R6 and R7); sizes measured on 2026-11-26, readers with the helpers
and decoders only they use.

- `archivey` (core): ZIP, TAR and its compressors, 7z, RAR, single compressed files,
  directories. About 43,000 lines of readers. No moved format stays: ISO, ar and cpio
  leave too, and `VISION.md`, which names ISO in the baseline, is updated to say it
  comes with `[recommended]`.
- `archivey-disk-images`: ISO 9660, UDF, CD images (6,100 lines), SquashFS (1,200).
- `archivey-dmg`: DMG alone, 7,200 lines: UDIF, HFS+, APFS, encryption, partition
  maps, the LZFSE, LZVN and ADC decoders. It is the one format with two file-system
  parsers and an encryption path of its own, and the one that may get a support tier
  or a release pace of its own. A name published on PyPI stays, so it is split before
  the first release and not after.
- `archivey-package-formats`: deb, rpm, ar, cpio, xar, pkg, makeself, pbzx, and CAB
  with its LZX decoder (2,000 lines), which current Windows tooling still writes.
  About 7,400 lines.
- `archivey-legacy-formats`: LHA and ARJ with their decoders; ZIP shrink, reduce,
  implode and DCL implode as registered codecs. About 3,900 lines.
- `archivey-codecs`: unchanged. It is a library that archivey imports, not a plugin (§6).

`[recommended]`, `[all]`, `[free-threaded]` and `archivey-cli` include all four. The
packages are pure Python, so they keep the GIL off, and leaving them out of
`[free-threaded]` would drop 13 formats from those installs and from the 3.13t and
3.15t jobs. There is no extra named after a package: `packaging-and-extras` already
rules out format-named extras, because a published extra can never be removed, and
`archivey[disk-images]` would freeze today's grouping. One package alone is installed
by its own name, `pip install archivey-disk-images`. A hint names that package.

The type checkers, the fuzz targets and `test.sh --all-configs` cover `src` only
today. Each move adds its package to them in the same pull request, or 25,000 lines
would stop being checked without a single failure.

One repository because the corpus, the fuzz targets, the review rules and CI are
shared, and a reader fix often touches a public helper in the same change. What a
separate repository would prove, the wheel-install CI job proves: it builds each
package, installs it beside a core wheel, and fails on any import outside the public
names. A separate repository makes sense for a package only after the API is stable.

Because names are strings, discovery is by manifest and no extra names a package,
regrouping changes one hint-table line and what `[recommended]` lists, and no caller.
What it cannot undo is a published package name, which is why DMG is split now.

## Decisions

All ten were put to the maintainer and agreed on 2026-11-24. Decisions 5, 6 and 7 were
revised by the maintainer on 2026-11-26, after review round A (rulings R1 to R8 below).

1. **Installed plugins load by themselves, behind the guardrails of §3.** This replaces
   the 2026-10-25 rule (explicit `register_format()` only), which the maintainer
   describes as a simplification taken while the API was a sketch, not a permanent
   rule. Rejected: explicit only (every program imports each package; the 2026-10-28
   objection). Rejected: core importing our packages by a fixed name (a first-party
   path).
2. **Open string names** (§2). Rejected: enums for core plus plain `str` for the rest
   (two kinds of value in one field).
3. **A hint table in core** (§4), counted as the allowed small mention of our packages.
4. **Codecs by name with method bindings** (§6). The 7z filters, ZipCrypto and AES stay
   in core.
5. ~~`archivey-codecs` is a second implementation of a codec name.~~ Replaced by R1.
6. ~~Three format packages, DMG in disk-images.~~ Replaced by R7: four.
7. **`[recommended]` and `archivey-cli` install every format package.**
8. **One repository, released together**, each package depending on one minor of core.
9. **The concurrency cut comes first, as a separate change** (maintainer, 2026-11-24).
   This plan builds on the contract it leaves (§5) and carries none of its tasks.
10. **Timing.** Steps 1 and 2 with the breaking trims of 0.6.0; the split in 0.7.0.

**The manifest is a data file** (maintainer, 2026-11-24, after review C1), not a Python
entry point that callers opt in to.

**Rulings of 2026-11-26**, each taken by the maintainer on its own, with the options
and the evidence in front of him (review round A):

- **R1. `archivey-codecs` stays a library behind one public kernel helper** (§6).
  Rejected: the codec registry for all ten kernels (eight are not stream decoders);
  the registry for LZW and LZX only (two mechanisms for one package).
- **R2. `FormatPolicy(providers=...)` replaces `plugins=`** (§2). Rejected: keeping
  `plugins=False` alone; keeping both.
- **R3. Typed key constants for every format; all `extra` overloads go** (§5).
  Rejected: overloads leaving core only for the moved formats; keeping all 62.
- **R4. A codec declares its native object, and archivey runs it in the child under
  `NATIVE_DECODERS`** (§6). Rejected: documenting the limit only; refusing package
  codecs under the setting.
- **R5. `only_libraries` is plain membership** (§2). Rejected: governing only the
  libraries core names.
- **R6. All 13 formats leave core**, ISO, ar and cpio included (§7). Rejected: ISO in
  core; ISO, ar and cpio in core.
- **R7. Four packages: DMG alone, CAB with the package formats** (§7). Rejected: DMG
  and CAB each alone; three packages with CAB in either group.

- **R8. `OptionalLibrary` stays a type that extends `str`**, like `ExtraKey` (§2). Each
  package defines constants for the libraries it uses, so a caller writes a policy
  from names and not from spellings. Rejected: plain strings with no type.

Changed without a ruling to revise, because the plan contradicted a spec or the code:
`CompressionAlgorithm` stays a non-string type, no extra is named after a package, and
the format packages join `[free-threaded]`.

Earlier rulings kept: the composition interface with `BaseArchiveReader` private
(2026-10-25); ZIP, 7z and RAR on the internal base (2026-10-30); the private
full-decoder hook (2026-10-30); same archive, same contents; accelerators never change
the result or the error type; an established package as an extra over our own decoder.

Superseded: "built in, like ISO" (2026-10-28), by the 2026-11-24 direction to split.

## Risks / Trade-offs

- **Entry-point lookup cost.** `importlib.metadata` reads the metadata of every
  installed distribution: usually a few milliseconds, more in a large environment. It
  runs once, on first use. Measured in step 3. There is no lazy fallback: collecting
  only after core's signals fail is not equivalent (§4).
- **Establishing an owner without importing.** A wheel's metadata lists its files and
  its top-level names. An editable install lists less, and a package with a custom
  import hook could resolve elsewhere. Step 3 tests wheels, editable installs and
  zipped installs. Where the owner of a module cannot be established, the provider is
  reported and its code is not imported (§3).
- **Open names lose static checks.** No exhaustive `match`, no `Literal` typo check.
  The check when a call resolves the name replaces them.
- **A lean core surprises someone.** A user of bare `archivey` loses ISO on upgrade.
  The error names the package, the changelog says it under **Breaking:**, and the
  documented install line is `[recommended]`.
- **Lockstep releases of four distributions.** One workflow and one version, as
  `archivey-cli` does today.
- **Helpers made public too early.** Mitigated by landing each with the reader that
  needs it, and by the API staying experimental until declared stable.

## Migration Plan

Each step ships by itself and leaves main working. One thing is proved at a time, so a
failure points at the API, at detection or at distribution, and not at all three.

1. **Manifest and lazy loading, inside core.** No public name changes. Proves that
   detection, with the three phases of §4, gives the same answers from data, and that
   `import archivey` loads no reader.
2. **Open names.** The breaking step. Proves that core has no plugin-only type left.
3. **Pilot wheel.** Passive discovery and policy-before-import (§3), then cpio and
   rpm, two of the three readers that already use public names only, built as the
   first cut of `archivey-package-formats`. ar is the third, and it waits: deb refines
   ar, and a base and its refinements move in the same step, so that no release has
   them in two distributions (review C4). ar moves with deb in step 5, as xar moves
   with pkg. The wheel is installed beside a core wheel in a fresh
   environment. Checked through the public API: discovery, a plain and a compressed
   CPIO read, limits, cleanup, and the recorder test. The conformance recipe starts
   here. A session that did not work on the migration writes the guide's indexed
   example from the guide alone, and its unchanged wheel is tried against the next
   minor of core. Lands after 0.6.0 is cut, since it moves two formats out.
4. **Services, pulled by the reader that needs them.** Codecs by name with the
   eligibility rule, the block call, and the public helpers of §5, each landing with
   the first reader that needs it. The legacy ZIP methods are the first codec to cross
   a package boundary. A reader moves when it passes the public-imports test, not
   before, so there is no stage where all ten must pass at once.
5. **The other moves, one pack at a time.** The rest of the package formats (ar with
   deb, xar with pkg, makeself, CAB), then legacy, then disk images, then DMG. Each pack repeats the
   pilot's checks and the corpus comparison.
6. **Afterwards.** Aliases removed one release later; the plugin guide rewritten,
   shorter.

**The concurrency cut is not in this sequence.** It is a separate change that lands
first (decision 9), so that the reader contract is already the short one when step 1
starts and the migration guide of step 3 is written against it.

Rollback: steps 1 and 4 are internal and revert cleanly. Steps 2, 3 and 5 are released
behaviour; their rollback is a new release.

## Open Questions

For the next rounds of this plan. None blocks step 1.

1. Field names of the manifest file, and whether `FormatHandler` keeps its declaring
   class attributes or reads them from its entry.
2. The package name `archivey-legacy-formats`.
3. Whether a known name with no installed package may be detected by signature, or by
   extension only, when the signature needs a probe.
4. The exact spelling of the off switch and of the provider query.
5. How a method namespace is declared by a plugin container, and whether 7z coder ids
   are bytes or their hex spelling in an entry.
6. The crypto facade's size: which primitives, and whether it requires `cryptography`
   as core does today.
7. Whether the conformance kit (`archivey.testing`) is part of step 5 or later.
8. For the decoder child of package codecs (R4): how an error from the child is handed
   to `translate_exception`, and the process-pool and memory-limit rules, which have
   special cases for pyppmd today.
9. The exact shape of the kernel helper, and whether a package may bring a kernel of
   its own or only use those of `archivey-codecs`.
10. Parallel decoding for readers on `IndexedReader`. Today every stream such a reader
    returns is read under the per-reader lock. A stream that archivey itself builds
    over the shared source (a slice, or a decoder over one) touches no reader state
    and could skip the lock, so SquashFS, xar, CAB, LHA, ARJ and DMG would decode
    members in parallel as ZIP does. A speed-up, not a contract change: it comes after
    the concurrency cut and after the moves.
