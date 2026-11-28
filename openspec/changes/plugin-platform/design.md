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
- **Reader API.** 13 readers are written on `archivey.formats`. ar, cpio and rpm
  import two internal names only (`register_builtin_format` and `override`, as all
  13 do). The other ten import more of `archivey.internal` (§5 lists what). The
  seven stream codecs that move (R11) are not on the public interface at all: each is
  an internal `StreamCodec`, and so is pbzx, which moves with pkg (eight codecs).
- **Size.** The 13 readers and their helper modules are about 24,000 lines. ZIP, TAR,
  7z, RAR, single-file and directory are about 43,000.
- **Core barely names the formats that would move.** Outside the readers and the enum,
  the 13 `ContainerFormat` members appear in four places: a makeself hint in `core.py`,
  one list in `cli/common.py`, `REPLACEABLE_CONTAINERS` in `format_adapter.py`, and two
  speed-up tables in `registry.py`.
- **Diagnostic codes are nearly all generic.** No moving reader needs a code of its
  own, but three of the 49 are reported only by readers that move:
  `ARCHIVE_STRUCTURE_INCONSISTENT` (DMG), `ARCHIVE_UNREAD_SESSION` (ISO and CD
  images) and `MEMBER_NAME_DUPLICATE_UNEXPECTED` (CAB). R23 keeps them as general codes.

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
# ... and the two encrypted shapes: "encrcdsa" at offset 0, a "cdsaencr" trailer
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
- Dotted paths are text until a call's policy has allowed the provider (§3). Only
  then is a probe, a refinement check, a handler or a decoder imported. The format
  policy does not gate a code load: it gates opening and decoding the format that
  detection found (R9).
- Core's own formats are entries in the same shape, in a table inside `archivey`. Their
  handler paths point into `archivey.internal`. The table does not care which base
  class a handler is built on.
- `register_format()` and `register_codec()` take the same entry as an object, for a
  program that adds a format of its own at run time. Both take an optional
  `provider=` name, `None` by default (R17). An entry with no provider runs only
  under a policy that does not restrict providers; no value of `providers=` can
  allow it, so `providers={"archivey"}` and `COMMON` bar it, as `plugins=False`
  does today. An entry with a provider name is allowed like a package of that name.
  The name may not be `archivey` nor the name of an installed distribution that
  ships a manifest. `FormatInfo.provider` is `None` for an entry without one.

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
  signature (`FOOBAR` over `FOO`) is a refinement and follows the consent rule of §4.
  When data signals of two owners match one file, the owner decides before the
  length does (decision 1, "a plugin adds, never takes over"; review F1): core's
  signals and the hint table's come first, then the other distributions in sorted
  order, and the longest signature is tried first only among one owner's. This
  keeps main's rule that a plugin's magic waits for every built-in signature, for
  a signature at another offset (28 bytes at offset 30 of an EPUB against ZIP's
  four at 0), a stub needle and a trailer without `preempts` alike. The outside
  format is then opened with `format=`, or by a line in the owner's table.
  An extension is weaker evidence (`.img`, `.bin` and `.run` are shared by
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
  outcomes that do not blur (and a fourth when autoload is off, §3): a name nobody
  declares is `ArchiveyUsageError`; a name whose package is missing is
  `PackageNotInstalledError` with the hint; a name whose provider is installed and
  incompatible is reported as incompatible, with both API versions, by
  `format_availability()` and by the error on open (§5).
- **A name is a value; a registry is asked when an operation resolves it.** Building
  `ContainerFormat("dmg")` or `ArchiveFormat("outside-format")` checks the spelling
  only (ASCII letters, digits, `.`, `_`, `-`), touches no registry and starts no
  discovery. So a name read from a config file loads on a machine without the plugin,
  and building a value never depends on what is installed or on which call ran first.
  Canonical names are compared as written, with no case folding:
  `StreamFormat("Z")` keeps its value, and a library name is an import name, which may have capitals
  (`PIL`). New format and method names are lowercase by convention, and the registry
  refuses two names that differ only in case. A test checks every core constant
  against the spelling rule. The caller's side keeps today's rule (`backend-registry`:
  a format "by its name and by its file extension, in any case"): `format="ZIP"`, an
  extension and a spelling alias are folded when a call resolves them, and the result
  is the canonical name. That lookup is unambiguous because no two names differ only
  in case. Library names are not folded.
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
  call starts, against the libraries that core, the hint table and the installed
  manifests declare, so a typo is still an error and cannot leave a library on, and
  a policy that excludes `brotli` stays valid on an install without the compressors
  (review F7). Method names in `exclude=` are checked against the same three sets.
  No library constant leaves core: every one of the 15 `OptionalLibrary` members
  names a library that core's own extras install, so they stay, and a package's
  constant for a library is the same value. `OptionalLibrary` stays a
  type that extends `str` (ruling R8), and each package exports a constant for every
  library it uses (`archivey_dmg.CRYPTOGRAPHY`-style names beside core's
  `OptionalLibrary.PYPPMD`), so a caller rarely types a library name at all.
- **Container and stream names share one namespace (ruling R10).** A name is a
  container or a stream, never both. The registry refuses a container name that a
  stream already owns, and the reverse, and the hint table reserves a name for both
  roles (§4). The reason is the policy's one mixed set: `ContainerFormat("xz")` and
  `StreamFormat("xz")` are equal strings, so `exclude={...}` with both would hold one
  value and could not say which role was meant. No name is in both lists today (20
  container names, 18 stream names). A format that is both a wrapper and an archive
  takes two names. `CompressionAlgorithm` is outside this rule: it is not a string, and
  `"xz"` is both a stream and a method on purpose.
- **Policy sets are stored by role.** `FormatPolicy` keeps containers, streams and
  methods apart inside, whatever the caller passed in one `exclude=` set, so no lookup
  compares a method with a stream. The role comes from the registry when a call
  resolves the policy, not from the Python type of the value (review AG8): a set
  cannot hold `ContainerFormat("xz")` and `StreamFormat("xz")` apart, since they are
  equal strings. A name passed under the wrong role, such as `ContainerFormat("xz")`,
  raises `ArchiveyUsageError` and never becomes an exclusion that excludes nothing.
- **What the closed enums gave for free is stated** (review AG8).
  `ArchiveFormat(container, stream)` refuses a `StreamFormat` as its container and a
  `ContainerFormat` as its stream when it is built, as today. A plain string cannot
  be checked then, so `ArchiveFormat("gz")` is built and fails when a call resolves
  it, with an error that says `gz` is a stream and names `ArchiveFormat.GZ`.
  `display_name` no longer comes from an enum member's name. Every entry carries a
  display name (`LZIP` for `lz`, `UNIX_COMPRESS` for `Z`); core's entries keep
  today's, so `TAR_LZIP` and `CPIO_GZIP` do not change, and an entry without one
  gets its name in capitals. A pair with an unknown name shows the names as written.
- **Constants live with their owner.** Core has no `ContainerFormat.DMG`. The moved
  constants stay one release as aliases that warn and name the package: 13 on
  `ContainerFormat`, eight on `StreamFormat` (PBZX and the seven of R11), the matching
  class constants on `ArchiveFormat`, and the methods only the packages decode on
  `CompressionAlgorithm` (the four legacy ZIP methods, LZX, LZH, ARJ_FAST, QUANTUM,
  LZFSE, LZVN, ADC, and those of R11). The warning needs a class-level hook that
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
4. Each call applies its effective **provider** policy **before** any dotted path of
   an installed package is imported: a refinement check, a probe, a handler or a
   decoder. Under `plugins=False`, or under `providers=` that leaves the package out,
   no module of the package is imported in that call. The **format** policy is applied
   after detection (ruling R9, §4): it decides whether the identified format is read,
   and so it gates the handler and the decoders, not the code that identifies. The
   **library** policy is a second gate on code, beside the provider (review AG2):
   a probe, a refinement check or a stub validator of an entry is neither imported
   nor run when `exclude_libraries` or `only_libraries` bars a library the entry
   lists (in `requires` or in `speedups`, §6), as on main today, where a caller who
   excludes `brotli` gets no Brotli probe and no import of `brotli`. A check skipped
   for that reason reads as a library that is not installed and records nothing
   in `unavailable_tiers`. For a probe that means the file is not identified. For a
   refinement check or a stub validator it must not mean a second reading (review
   F13): the base's file is refused, naming the library the policy bars, and is not
   read as the base. The
   policy of one call does not depend on what an earlier call did, apart from modules
   being already in `sys.modules`.
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
  - the top-level module the import system would load must be a file of that
    distribution, where its file list says so. `find_spec` answers this without
    running package code for a top-level name only: asked for `pkg.reader`, it imports
    `pkg` first and runs its initializer. So core never calls it on a dotted name;
  - a dotted target (`pkg.reader:Handler`) is checked against the distribution's file
    list first: the file for each part of the path must be listed there. Only then is
    anything imported. Where the file list cannot show it (a custom import hook),
    the provider is refused and reported before any lookup that could run an
    initializer;
  - an editable install lists only its `.pth` file and metadata, never the package's
    files (review AG5), and the packages under `packages/` are installed that way in
    development. One case is accepted: the distribution's `direct_url.json` marks it
    editable, and the `.pth` file it lists holds directory lines only. The package
    directory under such a directory then counts as the distribution's file tree, for
    the manifest and for each origin compared below. A `.pth` file with an `import`
    line, and an editable install that works through an import hook, are refused: no
    metadata says which file would run;
  - the file that was checked is the file that runs (review C1). A dotted import
    finds each child through its parent's `__path__` and the active finders, so a
    parent that changes its search path can lead to another file although the listed
    one exists. Core therefore loads the path one part at a time: once a parent is
    loaded, it asks for the child's spec, compares the spec's origin with the listed
    file, and executes that same spec. It never looks the name up a second time. A
    part whose spec has another origin, or a loader that cannot name one, is refused
    before that part runs;
  - this holds for the manifest, a handler, a probe, a refinement check and a decoder,
    in the caller's process and in the decoder child alike. The child imports nothing
    from archivey, so it does not repeat the metadata work (review F12): the parent
    resolves and checks each part and sends the child the list of origins, and the
    child loads each part from that origin and refuses a spec whose origin differs;
  - a codec's `native` target is one of two things (review AG3). It is a module of
    a library the entry lists, in `requires` or in `speedups` (§6): the library
    policy (`exclude_libraries`, `only_libraries`) governs it, and the one-owner
    check applies to its top-level name too. Or it is a worker module of the
    manifest's own distribution, checked like any other dotted path of it, which
    imports only listed libraries and nothing of `archivey`; a static test of the
    package holds that, as `tests/test_worker_scripts.py` does for core's workers.
  Tests: two distributions that expose the same import name, one allowed by
  `providers=` and one not, with the recorder of the next point in both, and neither
  runs; a dotted target whose file the distribution does not list, with a
  recorder in the parent package's initializer that stays empty; and a parent whose
  `__path__` puts another file ahead of the listed child, where both exist and the
  other one must not run. The last is run in the decoder child too.
- **Policy before import** (point 4). The test: a wheel whose `__init__` records that it
  ran, installed beside core. Discovery, opening a core ZIP, and
  `format_availability()` are run under the default policy, `plugins=False` and
  `FormatPolicy.COMMON`, in both orders, and the recorder must stay empty except where
  a call opens one of that wheel's formats under a policy that allows it, or where an
  allowed provider's check is needed to identify the file (R9). Under a policy that
  bars the provider it stays empty for every input.
- **A plugin adds and never takes over** (the one-owner rule of §2, and §6 for codecs).
  Replacing a reader stays an explicit choice of the calling program,
  `FormatPolicy(replace=...)`.
- **Allow-lists do not move.** `FormatPolicy.COMMON` and any `only=` policy name what
  is **read**, whatever is installed. An allow-list does not keep an installed
  package's detection code from running (R9); `providers=` does, and `COMMON`
  carries `providers={"archivey"}` for that reason (R11).
- **One off switch for a deployment.** `ARCHIVEY_PLUGIN_AUTOLOAD=0`, or
  `archivey.formats.disable_autoload()` before first use, skips the listing in point 2.
  It is a default for the process. A caller's policy works without it. Our own five
  packages are plugins like any other, so the switch turns them off too: with it on,
  an `archivey[recommended]` install reads core's formats only. A deployment that
  wants some packages names them: `archivey.formats.load_provider("archivey-dmg")`
  reads the manifest of that one installed distribution, under the same owner and API
  checks as the listing (pytest pairs its switch with `-p name` the same way). A
  format whose package is installed and not loaded is its own lookup outcome: the
  error says the package is installed and autoload is off, and names the call, where
  a missing package gets the install hint.
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
     The check runs when the package is installed and the call's policy allows its
     **provider**, whatever the policy says about the format. This rule and
     `providers=` arrive in the same step (step 2), and `COMMON` gains
     `providers={"archivey"}` in that step too, before step 3 turns discovery on: at
     no release does the upload preset let an installed package's code identify a
     file. Until then a plugin format the policy turns off stays out of detection, as
     today.
   - A refinement by code check and its base ship in one distribution. So when the
     package is missing, the refusal names the right package even where core cannot tell
     pkg from xar. This is the one place the guarantee is weaker, and it is stated: on a
     core-only install `detect_format()` reports the family (`xar`) with its provider
     missing, not the refinement. A refinement from **another** distribution must be
     data (a longer signature at a fixed offset, or a trailer) and sits in the owner's
     table: core then decides it on any install and under any policy, and refuses with
     the refining provider's name when that provider is missing or barred. Otherwise the
     same file would be the base under one policy and the refinement under another,
     which R9 rules out.
3. **Availability.** The format's provider is installed and allowed, or the call is
   refused with the hint.

**Probes.** A format with no reliable signature (binary cpio today) names a probe by
dotted path, and so may a codec's stream facet (§6). A probe is code, so it belongs
to no data phase, and its rule is today's, kept:

- It runs after phase 1, only when no signature settled the family, and only where
  the name's extension says it is that format or the caller set
  `always_probe_content` (`_probe_named`).
- It runs on the bytes detection already holds: the prefix, or the first decoded
  bytes inside a compressor, which is how a binary `initrd.cpio.gz` is found.
- It runs only for a provider the call's policy allows (§3 point 4), under the
  detection read budget and the caller's decoder limits. R9 applies to its result.
- Core's own probes run first, then the others in distribution order.
- The public probe is `(bytes) -> bool` today, which is enough for binary cpio. It is
  not enough for Brotli, which leaves core (R11): with no signature at all, its probe
  decodes a trial piece, and core's internal probe shape gives it a bounded
  `read_at`, a `charge_decode` allowance, the caller's `process_isolation` and the
  decoder limits. Step 0 makes that a public argument (a probe context), optional so
  that a one-line probe stays one line. A trial decode by a native library runs in
  the child, as any other decode of that codec does (R4).
- A probe grades its answer. Today the grade for Brotli is worked out in core's
  own detection code (`_brotli_probe_confidence`, which imports Brotli's framing
  parser): `PROBABLE` when the extension agrees or the first block is compressed,
  `GUESS` otherwise. Core cannot keep format-specific code for a format it does not
  ship, so every probe returns one of three verdicts and never a bool (maintainer,
  2026-11-26): no, a weak match (`GUESS`), a match (`PROBABLE`). A probe that only
  knows yes from no returns no or match. This has landed, with the existing probes
  changed in the same pull request (1850). Core adds what only it knows, that the extension
  agrees, and still decides whether a later decode failure is marked
  `format_unconfirmed`. `CERTAIN` stays for a signature and is never a probe's to
  give.
- A probe is the only evidence for its format, so on a nameless source with
  `always_probe_content` every allowed provider's probe runs, and a loose probe in an
  outside package can claim a file core would call "not an archive". It can never
  take a file from a format with a signature, because probes run only when none
  matched. The test kit (R19, task 3.9a) tests a probe against the non-archive
  corpus, and `providers=` is the caller's control.
- A hinted format whose package is missing has no probe to run, so it is known by
  its extension only (Open Question 3 asks whether that is enough). That is not
  enough where a recognized wrapper would then read the file as something else: an
  unnamed gzip around a binary CPIO, opened with `always_probe_content`, is
  `(CPIO, GZIP)` with the package and would be a plain gzip stream without it.
- **A hint may carry a check that core runs (ruling R13).** For that case core keeps
  the check itself: the binary CPIO check is 12 lines of arithmetic on the first
  bytes (the two-byte magic, and a name of the declared size that ends in NUL). Core
  runs it wherever the package's probe would run, so recognition is the same on every
  install and under every provider policy, and a missing or barred package means a
  refusal with the hint, never another reading and never a good file refused. The
  package's handler names the same function, published in `archivey.formats`, so
  there is one implementation. The bar for such a check is high: arithmetic over the
  bytes detection already holds, no decoding, no reading, a few lines, and only where
  the alternative is a second reading of the same file. Brotli does not qualify (its
  probe decodes) and does not need it (nothing else reads an unnamed Brotli stream).
  UDIF needs none: its `koly` trailer and encrypted headers are data, declared by the
  DMG reader today and listed in the hint table after the move.

**Detect first, judge after (ruling R9).** Every format of an allowed provider takes
part in detection, whatever the format policy says, and the format policy judges the
format that detection found. A policy that allows `xar` and bars `pkg` identifies an
installer package as `pkg` and refuses it; it does not read it as a plain XAR. This is
the rule core formats follow today ("detected under every policy and refused after
detection"), now the rule for every format, and it keeps "same archive, same contents"
true under every policy. It replaces the 2026-10-28 rule that left a plugin format the
policy turns off out of detection; what that rule protected against, one format taking
another's files, is now covered by the consent rule below. Three things follow:

- Barring a **format** is not a way to keep its code from running. The code that
  identifies a barred format still runs on the file. Only the provider policy
  (`providers=`), or not installing the package, keeps a package's code out, and the
  user docs say so.
- Detection code is cheap by contract. A refinement check and a probe run under the
  detection read budget and under the caller's decoder limits, so a format that is slow
  or costly to read is not slow or costly to identify.
- A caller who wants the base reading asks for it by name (`format="xar"`).

`refines` and `preempts` take something from another entry: a refinement takes files
its base would read, and a preempting trailer outranks a signature (a UDIF image whose
first block is bzip2 or xz data must not be read as a `.bz2`). Both need the consent of
the entry they take from: they are valid inside one distribution, or when the owner's own
table lists them. A policy never turns one on (review AG9): the same file would be
the base under one policy and the refinement under another, which R9 rules out. Core's
hint table lists the DMG trailer (and its encrypted headers) over core's bzip2 and xz
signatures, so a UDBZ or ULMO image is never read as a `.bz2` or `.xz`, with or without
the package. A package cannot refine or preempt ZIP on its own word, and a format
layered on another project's format (an `.ipk` over ar, an AppImage over SquashFS)
stays possible: by a data line in the owner's table (phase 2), or by the caller
asking for the format by name.

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
  behind a stub, and core runs the scan. The declaration has three parts, as the
  readers have today (review AG4): the needles, whether the parser scans, and a
  validator by dotted path. The validator is required whenever needles are declared:
  ARJ's needle is two bytes (`60 EA`), which 2 MiB of any program holds about 32
  times by chance, and only the header's CRC-32 tells a real archive from them. A
  validator is code, gated like a probe (provider and library policy, §3).
  The validators the readers have today parse a header, and core keeps neither.
  With `archivey-legacy-formats` missing, core still refuses both stubs with the
  hint (ruling R16). LHA's method ids (`-lh5-` and its kin, five bytes at a fixed
  place in the header) are strong enough to stand in the hint table alone. For ARJ
  the hint carries a check that core runs, as for binary CPIO (R13): after `60 EA`,
  a header size of 30 to 2600 and the CRC-32 of that many bytes, about ten lines of
  arithmetic over bytes the scan already holds, with one chance in 2^32 of a false
  match. The package's validator starts from the same function, published in
  `archivey.formats`.
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

What the seven stream codecs that move (R11) import from `archivey.internal` today.
None of them is written on the public `CodecHandler`: lz4, mozlz4, Brotli, lzop,
bzip3, Snappy and `.Z` each subclass the internal `StreamCodec`
(`internal/streams/codecs/base.py`).

- `StreamCodec`, `Codec`, `CodecParams`, `StreamConfig`, `FramedDecoder` and the
  decompressor stream, used by all seven: the port to `CodecHandler` and `CodecCall`.
- Hooks `StreamCodec` has and `CodecHandler` lacks, each used by a moving codec:
  `stream_index` (restart points for seeking: lz4, lzop, bzip3, Snappy), `frame_check`
  and `stream_start` (lz4), `extract_metadata` (the stored name and time: lzop,
  mozlz4), `missing_speedups` (the slow-path notice: lzop, Snappy), and `open`, the
  full decoder (Brotli, `.Z`, raw LZO1X). Ruling R15: the four small hooks become
  optional members of `CodecHandler`, and `open` stays private. None of the three
  needs `open` itself: each returns core's own decompressor stream around a
  richer decoder (`BaseDecoder`), which reports restart points while it decodes, can
  be built again at one, holds an error back until the bytes before it are read,
  counts the bytes after the stream's end, and may give its output only when the
  input ends. That decoder becomes public as a second,
  optional method of `CodecHandler`, with the types it needs (the decoder protocol,
  the result of one step, the restart point). Core still builds the stream, so the
  limits and the rules for the end of the data stay the same for every codec.
  Restart points are optional in it (review C15). Raw LZO1X, which SquashFS stores
  one block at a time, reports none: its decoder holds a block of bounded size and
  returns the output at the end of the input. The check of the declared size against
  the decoder memory limit runs in core before the decoder is built, as it does
  today, and a last block that decodes to less than the block size stays valid.
- pbzx (review AG6) is the eighth: it moves with xar and pkg to
  `archivey-package-formats`, and is an internal `StreamCodec` too. Its chunks are xz
  streams, and it takes five helpers from core's xz decoder and `declared_memory`:
  it reads each chunk's LZMA2 dictionary size, records it, and builds a decoder
  capped by `max_decoder_memory`, so a pkg nested in an archive cannot step around
  that limit. A package codec gets this from core and does not rebuild it:
  `CodecCall` gives a decoder for a core codec by name (`xz` here), already capped
  and already counted against the caller's limits. The same call serves any outside
  codec that wraps a core one.
- The child-process switch (`isolated.IN_PROCESS`, `Natives`, the decoder worker and
  child), used by lz4, mozlz4, Brotli, lzop and Snappy: `call.native(...)` (R4).
- The kernel switch (`kernels`, `LzwDecompressor`), used by lzop and `.Z`: the public
  kernel helper, as for CAB, LHA and DMG.
- `detection_workspace`, used by Brotli's probe: the probe context (§4).
- `script_payload.check_lz4`, shared by lz4 and makeself: public, or one copy in each
  package.
- The diagnostics collector and the timestamp helper: public, as for the readers.
- `override`: the same shim.

Private attributes of public objects that the readers use today, each of which
becomes a public call or goes:

- `context._spanning_check`, `_spanning_pass` (makeself digests, DMG `verify_all()`).
- `context._decompress_coder` (xar: one stream, bytes after it are damage): an option
  of `ReaderContext.decompress` (§6), `one_stream=True` (done, pull request 1855).
- `context._nest`, `_track_decoded`, `_usage` (decoded-byte and decoder-use accounting
  in CAB, ARJ, SquashFS, DMG, makeself).
- `context._listing_draw`, `_keep_metadata` (DMG, UDIF, APFS listing budgets).
- `source._origin`, `_will_read`, `_progress_reporter`, `_raw` (SFX offsets in LHA and
  ARJ; range hints in ISO, UDF, DMG; progress over a multi-file cue sheet).
- Found by review AG7, each needing a public call or a line in the entry:
  `MAX_PENDING_HINTS` from `internal.remote` (ISO), `special_file_has_data_report`,
  `release_decoder` and stream helpers (ISO), `SourceReadReporter` (cue sheets),
  `context._checkpoint` (DMG), `config.formats._codec_refusal` and `_libraries_off`
  (HFS+, UDIF, SquashFS, LHA, makeself, CAB: "may this method or library be used"
  becomes a public question on the context), `member._listing_checksum` and the
  reader's `_park` and `_read` (CAB).

Seven couplings sit outside the readers (reviews AG7 and F2), and no step may find
them by breaking:

- `format_policy.py` holds two tables that name moved formats: `_STREAM_METHODS`
  (stream format to its method, so that `exclude={CompressionAlgorithm.LZ4}` also
  refuses a `.lz4` file) and `_DECODES_WITH` (LZFSE also decodes LZVN). Both become
  data on the codec entry: which method a stream facet runs, and which other methods
  a decoder also decodes.
- The CLI iterates `OptionalLibrary` for `archivey --version -v` and indexes three
  moved members. An open type has no members to iterate, so core gains a public
  query for the known libraries (core's and the installed manifests').
- `cli/common.py` decides whether a format has an outer stream to peel by a list of
  containers and `isinstance(..., PluginContainer)`. That becomes a public property
  of the format, read from its entry.
- `core.py` imports `raw_layout_of` and `refuse_raw_sector_image` from the ISO reader
  at module level and calls them before the backend opens, for a replacement reader
  too. An entry may name a check that runs before open, by dotted path, gated like
  the handler; the ISO entry names this one. Due in step 1, or `import archivey`
  still loads a reader.
- `core.py` imports makeself's magic to add "open it with `format=`" when a forced
  format fails. The magic is in the entry and in the hint table; core reads it
  there. Due in step 1 as well.
- `registry.py` keeps `_CONTAINER_SPEEDUP_CODECS`, which codecs get the rapidgzip
  speed-up inside SquashFS, xar, pkg, rpm, deb and makeself. It becomes a field of
  the format entry, or those formats lose the speed-up at the move with no test
  failing.
- `format_adapter.py` keeps `REPLACEABLE_CONTAINERS`, the domain of
  `FormatPolicy(replace=)`, seven of them moved formats. It becomes a field of the
  entry ("may be replaced").

A test holds the class: core's source names no moved format outside the hint table.

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

A key is a string, so the dictionary and its contents do not change. Three details
(review AG11):

- `get()` is typed the same way, with two overloads for a key (`T | None`, and
  `T | D` with a default) placed ahead of the `str` ones, because an `ExtraKey` is
  also a `str` and the first match wins. Both type checkers are run on it.
- Core's existing `EXTRA_*` constants keep their names and become `ExtraKey` values,
  so a caller who already uses a constant keeps its narrowing. The constant of a
  format that moves stays in core one minor as a deprecated alias, with the moved
  format constants (task 5.6).
- A format declares its keys on its handler class, as a tuple of `ExtraKey`s. Core's
  keys that belong to no format (`is_junction`, `is_reparse_point`, `is_file_copy`,
  `alternate_raw_name`, `size_mod_2_32`, `special_file_type`) are allowed to every
  reader and are not declared again.

Core's formats declare their keys in the same shape. The
conformance checks fail a reader that sets a key it did not declare. **Breaking:** for
type checking only: a caller who subscripts with a string literal, for a ZIP key too,
gets `object` until it uses the constant. It lands with the open names in step 2.

Each new public helper lands in the pull request of the reader that needs it. Nothing
is added on speculation.

**Threads.** The concurrency cut was a separate change that landed before this one
(decision 9, archived 2026-11-25), and it owns the thread contract a reader author sees
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

**Options of one format** (R24). A format or codec that has settings of its own
ships a frozen options class whose fields hold plain values only: text, numbers,
booleans, a named choice, a path. `ArchiveyConfig(format_options=[...])` takes such
objects, at most one per class; a reader or codec asks its context for its class and
gets the caller's object or the class default. Core does not know a plugin's class.
Core's own formats use the same shape: `ZipOptions` and `RarOptions` replace the four
per-format fields of `ArchiveyConfig`. The config trim of R21 makes that change and
builds `format_options` and the context call with it, since it lands before step 2;
step 2 adds only the manifest's side. A
manifest entry names its options class under a short name, so a name and a mapping of
plain values can be turned into the object, and back, without importing anything
else: an unknown name or field is refused when it is read. No reader or writer of
config files is built now; the two rules keep one possible, and the command line is
its likely first user.

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
# isolation = "known_crashes"       the lowest setting that isolates it (bzip3)
# requires = ["somelib"]            without it the format is unavailable
# speedups = ["fastlib"]            without it the package's Python decoder runs
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
  itself, or, where the caller's setting isolates it (`NATIVE_DECODERS`, or the
  entry's own floor below), a stand-in with the same methods that runs in a
  child. The child imports that one dotted path and nothing else. The codec's own
  logic stays in the caller's process and is the same in both cases.
- A library that is not shaped like a decoder object (a one-shot function, as
  `lz4.block` for mozlz4), or a decoder that needs two libraries (Snappy with its
  CRC-32C package), needs a small worker class, in a module of the package that
  imports only those libraries. `native` may name that module (§3).
- **Hard requirements and speed-ups are listed apart** (review AG3). `requires`
  lists what the codec cannot work without: when one is missing the format reports
  `FormatSupport.NONE`. `speedups` lists native libraries that replace a Python
  decoder the package has: when one is missing the format stays `FULL`, reports it
  in `faster_with`, and decodes in Python. lzop, raw LZO1X and Snappy list
  `compress-utils` (and Snappy its other choices) there, so they still read on
  PyPy, Intel macOS and 3.13t. The library policy, `BackendUse` and `call.native`
  treat both lists alike.
- **A codec may ask for more isolation than the caller's setting gives by default**
  (review AG1). On main, libbzip3 runs in a child under the default
  `ProcessIsolation.KNOWN_CRASHES` too, and a `.bz3` file raises
  `ResourceUnavailableError` where no child can start. A rule that isolates only
  under `NATIVE_DECODERS` would lose that when bzip3 moves. So an entry may declare
  the lowest setting at which its native target runs in the child: `known_crashes`
  or, by default, `native_decoders`. bzip3 declares `known_crashes`. Under
  `ProcessIsolation.NONE` nothing is isolated, as today. The declaration can only
  add isolation, so it needs no consent.
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

**Kernels (ruling R1).** `archivey-speedups` does not go through the codec registry.
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

So `archivey-speedups` stays what it is: an optional library, named by
`OptionalLibrary("archivey_speedups")`, that speeds up decoders and changes no result.
What becomes public is the switch. A reader asks `ReaderContext.speedup(name)` (a codec,
`CodecCall.speedup(name)`); it gets the Rust kernel, wrapped with the revision check,
the panic guard and the child, or `None`, and then uses its own Python decoder
(`context.speedup("lzw") or twin.Decompressor`, maintainer, 2026-11-28, who also chose
the name `speedup` over `kernel`). The interface of each kernel is public in
`archivey.speedups`. Core gives back the decoder child of each kernel object when the
member stream or the reader closes. Core (ZIP, 7z), `archivey-dmg` (LZFSE, LZVN),
`archivey-package-formats` (CAB's LZX) and `archivey-legacy-formats` (LHA's CRC-16,
`.Z`'s LZW) call the same helper, and each Python twin moves with its format.

Other rules:

- **Register a codec only when another package uses it.** LZX (CAB alone) and LZH (LHA
  and ARJ, which ship together) stay plain imports inside their package, with the
  kernel helper for LZX's Rust side.
- **What is part of parsing stays with the parser.** The 7z filters, ZipCrypto and AES
  stay in core.
- A codec gives core a decoder and never a stream. The simple one is the incremental
  `Decompressor`. A codec that it does not fit (restart points inside a stream, an
  error held back, a block decoded whole at the end of its input) gives the richer
  decoder of R15 (§5). The hook that returns a whole stream stays private
  (maintainer, 2026-10-30), so no plugin can step around the shared rules for limits
  and the end of the data.

### 7. Packages

All under `packages/` in this repository, each a flat top-level module
(`archivey_disk_images`), released with core at the same version. Five packages: four
for formats (rulings R6 and R7) and one for compressions (R11); sizes measured on
2026-11-26, readers with the helpers and decoders only they use.

- `archivey` (core): ZIP, TAR, 7z, RAR, single compressed files, directories, and nine
  stream formats (R11): gz, bz2, xz, zst; `.lzma`, `.zz` and `.lz`, which are other
  wrappers around decoders core has anyway; and the uu and base64 encodings, which
  need no package and are read through (`files.tar.uu` lists the tar). About 43,000
  lines of readers. No moved format stays: ISO, ar and cpio
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
  implode and DCL implode as registered codecs; and Unix compress (`.Z`), whose LZW
  code Shrink shares. About 4,800 lines.
- `archivey-compressors` (R11, named by R12): lz4 and mozlz4,
  Brotli, lzop, bzip3 and Snappy, about 3,900 lines. The wheel is pure Python and
  requires none of their libraries, as core does not today: each codec entry names
  its library in `requires`, and a missing one raises the same error that names it.
  Each is a codec entry with a stream
  facet (§6), so it also serves other readers by name: SquashFS blocks in LZ4 or LZO,
  and the 7z methods `04 F7 11 02` (Brotli) and `04 F7 11 04` (LZ4), which only the
  7-Zip-zstd fork writes and which this package binds in the `"7z"` namespace. Without
  the package those members are refused with the hint. `04 F7 11 01` (Zstandard)
  stays bound in core, where the decoder is.
- `archivey-speedups`: the Rust kernels, a library that archivey imports and not a
  plugin (§6). It is `archivey-codecs` on main today, never published; R12 renames it
  before its first release, with the extra `[speedups]` and the library name
  `archivey_speedups`, so that it is not taken for the package that adds compressors.
  The rename is its own change, outside this plan's steps.

`[recommended]`, `[all]`, `[free-threaded]` and `archivey-cli` include all five. The
libraries the compressors use stay where they are selected today, in core's extras,
one capability at a time: `lz4`, `brotli`, `compress-utils` and the CRC-32C package in
`[recommended]` with their markers, `brotli` left out of `[free-threaded]` because it
can turn the GIL back on, and `bzip3` in its own `[bzip3]` extra and in none of the
others. The `[bzip3]` extra also requires `archivey-compressors` (review C14), so
the documented `pip install archivey[bzip3]` still reads `.bz3` and `.tar.bz3` by
itself, and the hint for a missing bzip3 reader or library names that extra, since
it supplies both. Putting them behind the wheel as its requirements would give every install
profile the same set and lose those choices. Because they remain direct requirements
of archivey's extras, `tests/check_free_threaded_gil.py`, which reads that metadata,
still imports each of them. The packages themselves are pure Python, so they keep the
GIL off, and leaving them out of
`[free-threaded]` would drop 13 formats from those installs and from the 3.13t and
3.15t jobs. There is no extra named after a package: `packaging-and-extras` already
rules out format-named extras, because a published extra can never be removed, and
`archivey[disk-images]` would freeze today's grouping. One package alone is installed
by its own name, `pip install archivey-disk-images`. A hint names that package.
A hint must fix the problem in one step (review AG12). Where the format also needs
a library the wheel does not pull (LZ4, mozlz4, Brotli, and the 7z LZ4 and Brotli
methods), the hint's command names both: `pip install archivey-compressors lz4`.
bzip3 names its extra, which supplies both. lzop and Snappy decode in Python, so the
package alone is enough.

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
revised by the maintainer on 2026-11-26, after review round A (rulings R1 to R17
below), and extended on 2026-11-27 after the direction-review check (R18 to R24).

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
5. ~~`archivey-speedups` is a second implementation of a codec name.~~ Replaced by R1.
6. ~~Three format packages, DMG in disk-images.~~ Replaced by R7 (four) and R11
   (a fifth, for compressors).
7. **`[recommended]` and `archivey-cli` install every format package.**
8. **One repository, released together**, each package depending on one minor of core.
9. **The concurrency cut comes first, as a separate change** (maintainer, 2026-11-24).
   This plan builds on the contract it leaves (§5) and carries none of its tasks.
10. **Timing.** Steps 0 to 2 with the breaking trims of 0.6.0; the split in 0.7.0.

**The manifest is a data file** (maintainer, 2026-11-24, after review C1), not a Python
entry point that callers opt in to.

**Rulings of 2026-11-26**, each taken by the maintainer on its own, with the options
and the evidence in front of him (review round A):

- **R1. `archivey-speedups` stays a library behind one public kernel helper** (§6).
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

- **R9. Detect first, judge after** (§3, §4). Every format of an allowed provider takes
  part in detection; the format policy refuses after detection; only the provider
  policy keeps a package's code from running. Retires the 2026-10-28 rule that left
  turned-off plugin formats out of detection. Rejected: leaving a barred format out of
  detection (the same file would read as two things under two policies), and refusing
  every file of the base format.

- **R10. Container and stream names share one namespace** (§2). The policy API stays
  as it is. Rejected: separate policy arguments per role (every existing `only=` and
  `exclude=` call would change), and making the two types unequal non-strings (it
  reverses decision 2).

- **R11. Seven stream formats leave core; `FormatPolicy.COMMON` stays** (§7). lz4,
  mozlz4, Brotli, lzop, bzip3, Snappy and `.Z` move; the 7z bindings for LZ4 and Brotli
  move with their decoders. Core keeps nine stream formats. `COMMON` is not deleted: it stays an
  explicit list that does not follow what core ships, because it is narrower than core
  today (it leaves out `.lzma`, `.zz`, `.lz`, uu and base64) and core may gain formats
  later that an upload preset should not accept. Its definition may change, and it
  gains `providers={"archivey"}`, so no package's detection code runs under it (R9).
  The docstring's recipe for building on `COMMON` copies `only` and `exclude` by
  hand today and would drop that field (review F9), and its own example, adding
  LZ4, needs the compressors as a provider after the split. The recipe is rewritten
  in the same step to carry `providers` and to name the package it adds
  (`providers=FormatPolicy.COMMON.providers | {"archivey-compressors"}`), with a
  test that a policy built by the recipe bars an outside probe. R22 makes the
  recipe a `dataclasses.replace` call, so no field is copied by hand.
  Rejected: all 13 other streams leaving core, dropping `COMMON` for
  `providers={"archivey"}` alone, and all streams staying.

- **R12. Two names** (§7). The compression package is `archivey-compressors`: the
  word a person holding a `.lz4` file uses, and the one the formats page already uses.
  The Rust kernel library is renamed from `archivey-codecs` to `archivey-speedups`
  before its first release, because "codecs" does not say that it is an optional
  accelerator. Rejected: `archivey-compression-formats` (other archives seem to fit),
  `archivey-compression-methods`, `archivey-accelerators`, `archivey-native`.

- **R13. Core keeps the binary CPIO check** (§4). A hint may carry a small check that
  core runs when the format has no signature strong enough to be data and a wrapper
  would otherwise read the file differently. Rejected: a weak two-byte signature that
  refuses on a match (it would refuse good files), keeping CPIO in core, and
  documenting the difference as an exception.

- **R14. Interface first** (Migration Plan, step 0; the maintainer's proposal of
  2026-11-26). Before the manifest and before any wheel, the plugin interface is
  updated and every reader and codec that will move is ported to it in place, with
  no import from `archivey.internal` left. Rejected: porting each reader just before
  its move (the earlier task 5.0), which would find a gap in the interface only
  after packages were already released against it.

- **R15. The codec hooks become public, the richer decoder too, the stream hook does
  not** (§5, §6). `CodecHandler` gains the optional hooks for restart points, the
  per-frame check, stored metadata and the slow-path notice, and an optional method
  that returns a decoder with restart points. Core builds the stream in every case.
  Rejected: publishing the hook that returns a whole stream (a plugin could bypass
  the shared rules, which the 2026-10-30 ruling guards), rewriting Brotli and `.Z`
  onto the simple decoder (`.Z` would lose its restart points), and keeping the two
  in core.

- **R16. Core keeps the ARJ stub check** (§5). An ARJ archive behind a
  self-extracting stub is refused with the hint on a core-only install: core checks
  the header size and its CRC-32 at each `60 EA` the scan finds. Rejected: leaving
  such a file unrecognised without the package, an exception to "read the same or
  refused with a hint".

- **R17. A run-time entry has an optional provider name, `None` by default** (§1,
  review F8; maintainer, 2026-11-27). `register_format()` and `register_codec()`
  take `provider=`. Without it the entry runs only when the policy does not restrict
  providers, and nothing can put it on an allow list. Only a program that restricts
  providers has to name its own entries. Rejected: a required name (a new argument
  for every caller); one fixed or default name for all such entries (a package that
  registers at run time, in place of a manifest, would share the program's name and
  be allowed with it); and leaving such entries outside `providers=` (it loosens
  `COMMON`).

- **R18. The format packages get lighter compatibility checks and the same safety
  checks** (§7; maintainer, 2026-11-27). A change to core runs core and every package
  on the full matrix. A change to one package runs core and that package on Linux,
  and with it each package that uses it. Neither kind of use is an install
  dependency (SquashFS reaches the compressors' LZ4 and LZO by codec name, and
  `archivey-speedups` is optional everywhere), so the edges are read from two places
  that already have to be right: a codec entry's `speedups` list in a manifest, and
  each package's test dependency group in its `pyproject.toml`, which names the
  other packages its tests need (disk-images names the compressors). A package's
  tests run in an environment holding core, the package and that group only, so an
  edge left out fails the package's own run and cannot be missed.
  `archivey-speedups` keeps Windows and macOS on its own changes, as the only
  native code, and DMG keeps its macOS job,
  which compares the reader with `hdiutil`. The full matrix for everything runs
  nightly and before a release. Fuzz targets, limit checks and the type checkers
  are not lightened. A job the rule skips reports success, so the merge queue does
  not wait for it. Rejected: core's rules for every package (the split would then
  save no maintenance), and a lighter rule for two packages only.

- **R19. The test kit is a helper in the repository during step 0 and a public
  module at the pilot** (§5; maintainer, 2026-11-27). Each port uses it and shapes
  it: truncation and bit flips, short reads and a pipe, a repeated listing, small
  limits, early close, hostile names through extraction, and the probe over files
  that are not archives. With R18 a package change runs only core and that package,
  and the kit is what that run checks the package with. It is published as
  `archivey.testing` (name to be confirmed then) with the pilot wheel, where the
  outside-author trial needs it installed. No outside author is assumed: its users
  are our packages. Rejected: a public module from step 0 (its names would change in
  public through thirteen ports), and a written recipe only (each package would copy
  the test code).

- **R20. No placeholder releases** (§7; maintainer, 2026-11-27). Each package is
  published when it has code. PyPI discourages empty projects, and owning five names
  does not stop a sixth `archivey-` name from being registered. Each step that
  publishes a package checks the name first; a taken name means a rename before any
  file names it.

- **R21. All four breaking trims ship in 0.6.0** (decision 10; maintainer,
  2026-11-27): one extraction error setting, the tiered root namespace, the smaller
  `ArchiveyConfig`, and the diagnostic-code audit
  (`review/direction-2026-11/assessment.md`, items 4 to 7). They are a separate
  change and share no files with step 0. The root tiering lands before step 2, so
  that a root name step 2 retypes moves once.

- **R22. A policy is built from `COMMON` with `dataclasses.replace`** (§2;
  maintainer, 2026-11-27). The docstring's recipe becomes
  `dataclasses.replace(FormatPolicy.COMMON, only=...)`, which carries every field,
  `providers` included, and a test keeps that call working. Rejected: a new method
  on `FormatPolicy` (a new public name; it could not be called `replace`, which is
  a field), and a recipe that copies each field by hand.

- **R23. The three codes only packages report stay in core as general codes**
  (§Context; maintainer, 2026-11-27, after the diagnostic-code audit).
  `ARCHIVE_STRUCTURE_INCONSISTENT`, `ARCHIVE_UNREAD_SESSION` and
  `MEMBER_NAME_DUPLICATE_UNEXPECTED` each name a problem another format could
  have. Their docstrings describe the problem and stop naming a format, and any
  reader may report them. No reader that moves needs a code of its own, so codes
  declared by a plugin stay a Non-Goal until a format needs one. Rejected: folding
  them into broader codes (less precise reports), and package-declared codes (new
  public surface with no reader that needs it).

- **R24. A format takes its own options as a typed object** (§5; maintainer,
  2026-11-27). One frozen class per format or codec, passed in
  `ArchiveyConfig(format_options=...)` and read through the context; ZIP and RAR use
  the same shape as a plugin. So that a config can later be written to and read from
  a file, the manifest names each options class under a short name and option fields
  hold plain values only. Rejected: a mapping of names and values per format
  (untyped, and a typo shows late), and a group for core's options only (ZIP and RAR
  would change shape again when a plugin needs options).

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
- **Lockstep releases of five plugin distributions.** One workflow and one version, as
  `archivey-cli` does today.
- **Helpers made public too early.** Mitigated by landing each with the reader that
  needs it, and by the API staying experimental until declared stable.

## Migration Plan

Each step ships by itself and leaves main working. One thing is proved at a time, so a
failure points at the API, at detection or at distribution, and not at all three.

0. **Interface first: every class that will move is ported in place** (R14). The
   public plugin interface grows what the moving readers and codecs need (the public
   helpers of §5, the probe context of §4, the codec hooks and the richer decoder of R15),
   and each of the 13 readers and eight codecs (the seven of R11 and pbzx) is ported
   while it still lives in core, one pull request each, until its module imports nothing
   from `archivey.internal`. The public-names test starts here and its list of modules
   grows with each port. Nothing moves and the manifest is not needed. Registration
   leaves the reader's module in this step (review F3): core registers each handler
   class from a table of its own, the first form of step 1's table, and what DMG and
   pkg pass through the internal call today (magic, trailer, refinements) becomes declarations
   on the
   handler. `override` is a three-line shim in the module. This step adds public
   names to `archivey.formats`, which task 2.5's surface update covers; the one
   change for existing plugins, the probe's three-valued verdict, has landed
   (pull request 1850). Proves that the interface is
   enough before anything depends on a wheel, so a gap shows as a failing test in core
   and not as a package that cannot be built.
1. **Manifest and lazy loading, inside core.** No public name changes. Proves that
   detection, with the three phases of §4, gives the same answers from data, and that
   `import archivey` loads no reader.
2. **Open names.** The breaking step. Proves that core has no plugin-only type left.
3. **Pilot wheel.** Passive discovery and policy-before-import (§3), then rpm
   alone, built as the first cut of `archivey-package-formats`. Two rules decide
   what may move by itself. A base and its refinements move in the same step, so
   that no release has them in two distributions (review C4): ar waits for deb. A
   format and every format that opens it through `open_nested` move in the same
   step, so that no core format depends on a plugin (review F4): cpio waits for
   pkg, which reads its payloads as nested CPIO. rpm parses its own payload and
   nothing opens it. The wheel is installed beside a core wheel in a fresh
   environment. Checked through the public API: discovery, an rpm read with a
   compressed payload, limits, cleanup, and the recorder test. The test kit is published
   here. A session that did not work on the migration writes the guide's indexed
   example from the guide alone, and its unchanged wheel is tried against the next
   minor of core. Lands after 0.6.0 is cut, since it moves a format out.
4. **The manifest side of codecs.** The public helpers of §5 and the Python side of
   every service land in step 0, with the port that needs them. What is left here
   needs the manifest: method bindings, the eligibility rule, `native` and the
   stub declaration read from entries. The legacy ZIP methods are the first codec
   to cross a package boundary.
5. **The other moves, one pack at a time.** The rest of the package formats (ar with
   deb, cpio and xar with pkg, makeself, CAB), then legacy (with `.Z`), then disk images, then
   DMG, then `archivey-compressors`. Each move is files, manifest entry and hint
   line only, since the code was ported in step 0. Each pack repeats the pilot's
   checks and the corpus comparison.
6. **Afterwards.** Aliases removed one release later; the plugin guide rewritten,
   shorter.

**The concurrency cut is not in this sequence.** It was a separate change and has
landed (decision 9, archived 2026-11-25), so the reader contract is already the short
one when step 0 starts and the migration guide of step 3 is written against it.

Rollback: steps 1 and 4 are internal and revert cleanly. Step 0 adds public names
and steps 2, 3 and 5 are released behaviour; once released, their rollback is a new
release.

## Open Questions

For the next rounds of this plan. None blocks the start of step 0.

1. Field names of the manifest file, and whether `FormatHandler` keeps its declaring
   class attributes or reads them from its entry.
2. The package name `archivey-legacy-formats`. The plan places `.Z` there, because
   Shrink shares its LZW decoder; that placement is the plan's proposal and stands
   unless the maintainer moves it to the compressors.
3. Whether a known name with no installed package may be detected by signature, or by
   extension only, when the signature needs a probe (the last point of §4 Probes).
4. The exact spelling of the off switch and of the provider query.
5. How a method namespace is declared by a plugin container, and whether 7z coder ids
   are bytes or their hex spelling in an entry.
6. The crypto facade's size: which primitives, and whether it requires `cryptography`
   as core does today.
7. The public name and layout of the test kit when it is published at the pilot
   (R19).
8. For the decoder child of package codecs (R4): how an error from the child is handed
   to `translate_exception`, and the process-pool and memory-limit rules, which have
   special cases for pyppmd today.
9. Whether a package may bring a kernel of its own or only use those of
   `archivey-speedups`. The helper's shape is settled (§6, "Kernels").
10. Parallel decoding for readers on `IndexedReader`. Today every stream such a reader
    returns is read under the per-reader lock. A stream that archivey itself builds
    over the shared source (a slice, or a decoder over one) touches no reader state
    and could skip the lock, so SquashFS, xar, CAB, LHA, ARJ and DMG would decode
    members in parallel as ZIP does. A speed-up, not a contract change: it comes after
    the concurrency cut and after the moves.
11. The public names and exact shape of the richer decoder of R15, and the wording
    of its rule that every pass offers the same restart points. Settled by the first
    port that uses it (`.Z`), in step 0.
