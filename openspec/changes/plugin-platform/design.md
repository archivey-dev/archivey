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
 archivey (core)   our format packages   archivey-codecs   anyone's package
        \                  |                    |                /
         +------- manifest files (data, nothing imported) -------+
                               |
                     manifest table in core
          name, extensions, signatures, dotted path of the code
              a name, extension or signature has one owner
                 /             |                \
          detection      format readers      codec registry
        (table alone)  (imported on first   (by name or method
                         open of a format)    number; priority)
                               |
   hint table: a known format whose package is missing is refused
          with its install line, never read as another format
```

### 1. The manifest

A manifest is a data file, not Python. Core reads it without importing or running
anything from the package that ships it.

```toml
# archivey_disk_images/archivey-manifest.toml
api = "1.0"

[[format]]
name = "dmg"
extensions = [".dmg"]
trailer = { offset = -512, hex = "6b6f6c79" }      # "koly"
preempts = ["bz2", "xz"]
handler = "archivey_disk_images.dmg:DmgHandler"

[[codec]]
name = "lzfse"
decoder = "archivey_disk_images.lzfse:LzfseCodec"
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

from archivey_disk_images import DMG    # = ArchiveFormat("dmg")
```

What changes:

- `ContainerFormat`, `StreamFormat`, `CompressionAlgorithm`, `OptionalLibrary`: open
  string types. Constants stay for core's own names.
- `PluginContainer`, `PluginStream`, `ContainerFormatStr`, `StreamFormatStr`,
  `OptionalLibraryStr`: removed.
- `DiagnosticCode`, `HashAlgorithm`: unchanged. A plugin digest is already named by
  string in `MemberDigest`, and `ArchiveMember.extra` keys are namespaced strings.

Rules:

- **One owner.** The registry refuses a second registration of a name, an extension or
  an exact signature and reports the refused provider in `format_availability()`. It
  never switches providers silently.
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
  for core. `FormatPolicy(plugins=False)` keeps its meaning: only code shipped in the
  `archivey` distribution runs.
- **Constants live with their owner.** Core has no `ContainerFormat.DMG`. The 13 moved
  constants stay one release as aliases that warn and name the package.

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
   not depend on install order. An entry's value names a top-level package. Core
   locates that package with `importlib.util.find_spec`, which does not run the
   package's `__init__`, and parses `archivey-manifest.toml` beside it with `tomllib`.
3. Detection of a format's family runs on manifest data alone.
4. Each call applies its effective `FormatPolicy` (provider, then format) **before**
   any dotted path of an installed package is imported: a refinement check, a probe, a
   handler or a decoder. Under `plugins=False`, or under an allow-list that does not
   name the format, no module of the package is imported in that call. The policy of
   one call does not depend on what an earlier call did, apart from modules being
   already in `sys.modules`.
5. A handler module is imported when an archive of its format is opened.

Guardrails:

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
  provider of each format and decoder.
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
2. **Refinement, bounded.** A family may have narrower readings: deb over ar, pkg over
   xar. This runs **after** a signature has matched, as `_near_magic_hit` does today,
   and under the same read budget (the near window on a forward-only source, up to the
   read ceiling on one that can seek).
   - A refinement that data can state is data: a `.deb` is ar's signature followed by a
     member named `debian-binary`, which is a longer signature at a fixed offset. Core
     decides it on any install.
   - A refinement that needs parsing (pkg reads the xar table of contents) names a
     check by dotted path. The check runs only when the package is installed and the
     call's policy allows it.
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
the entry they take from: they are valid inside one distribution, or when the owner's
own table lists them. Core's hint table lists the DMG trailer over its stream
signatures. A package cannot refine or preempt ZIP on its own word.

**The hint table** is the same entry data, in core, with a package name in place of
the dotted paths. When the package is missing, opening such an archive raises
`PackageNotInstalledError` naming the package. It is what keeps "same archive, same
contents" true across installs: an archive reads the same way or is refused with a
hint, and is never read as another format. A CI test keeps the table equal to our
packages' manifests. An outside project adds its line by pull request, as projects do
in fsspec.

Tests for this section, before any reader moves: a real pkg and a plain xar, a real
deb and a plain ar, each with a correct, a missing and a misleading suffix, on a
core-only and a full install; `detect_format()` and `open_archive()` must agree; read
budgets are measured on seekable and forward-only sources. Success is the same format
and contents where the reader is available, and a truthful refusal where it is not.

### 5. The reader API

The shape of `archivey.formats` stays: a handler that declares, and an indexed or a
sequential reader that hands archivey members and bytes.

**Two levels of code, one contract.** Registration, naming, detection and policy are
the same for every format. Code inside the `archivey` distribution may use
`archivey.internal`; code in any other package, ours included, may not.

**The public-imports test is the definition of done.** What the ten readers import from
`archivey.internal` today, and how each is resolved:

- Own decoders (LZX, LZH, LArc, ARJ fast, ADC, LZFSE), used by CAB, LHA, ARJ, DMG: move
  with the format.
- Own helper modules (CD sectors, cue sheets, UDF, UDIF, HFS+, APFS, the xar reader),
  used by ISO, DMG, pkg: move with the format.
- The Rust or Python kernel switch (`kernels`), used by CAB, LHA, DMG: the codec
  registry's approved second implementation (§6).
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
- Nested-archive helpers (`HeldInnerData`, `DependencyIndex`, name filters), used by
  deb and pkg: folded into `ReaderContext.open_nested`.
- Source helpers (`JoinedViews`, the trailing scan, the callback source), used by ISO
  and DMG: methods on `ReaderSource`.
- `register_builtin_format` and its overrides, used by all 13: the manifest entry.

Each new public helper lands in the pull request of the reader that needs it. Nothing
is added on speculation.

**Threads.** The concurrency cut is a separate change that lands before this one
(decision 9), and it owns the thread contract a reader author sees
(`openspec/changes/concurrency-cut`). This change takes that contract as it stands and
does not restate it, so the two cannot drift apart. What the plugin work needs from it:

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
  missing package, with a different message.
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
  string. The caller's limits, process isolation and `FormatPolicy` apply inside the
  call, the same for every codec.
- **Block call.** A new `ReaderContext` call for block formats (SquashFS, DMG): bytes
  in, bytes out, a stated size, under the same limits and isolation.

**Who may decode what.** Installing a package must not change which code decodes a
member that already decoded. Priority alone would allow that, so eligibility comes
first:

- **A vacant slot may be filled.** The owner of a method namespace (ZIP's reader for
  `"zip"`) says which numbers it decodes itself. Any other number is vacant, and one
  package may fill it: legacy ZIP Shrink at `("zip", 1)`. A slot has one owner, like a
  name.
- **An occupied slot or an existing name is replaced only with consent.** A second
  implementation is eligible when the owner of the name lists it (core's entry for LZX
  names `archivey-codecs`, as core names rapidgzip for Deflate today), or when the
  calling program selects it in its policy. An unlisted package that claims a higher
  priority for ZIP's Deflate is refused and reported.
- **Priority ranks eligible implementations only.** The one that ran is named in
  `BackendUse`.
- **An approved implementation follows the accelerator rule:** the same bytes and the
  same error type as the first, the parity tests as the entry bar, and the host's
  limits and isolation around it.
- **An allow-list keeps its decoder set.** Under `only={ZIP}` the decoders that may run
  are the ones ZIP's owner approved, before and after an unrelated wheel is installed.

Tests: a vacant slot with and without its provider; an unrelated distribution claiming
a higher priority for a stock method (refused, reported, the stock decoder runs); an
approved `archivey-codecs` decoder and its fallback.

Other rules:

- **Register a codec only when another package uses it.** LZX (CAB alone) and LZH (LHA
  and ARJ, which ship together) stay plain imports inside their package.
- **What is part of parsing stays with the parser.** The 7z filters, ZipCrypto and AES
  stay in core.
- The decoder interface plugins see stays the incremental `Decompressor`. The
  full-decoder hook stays private (maintainer, 2026-10-30).

### 7. Packages

All under `packages/` in this repository, each a flat top-level module
(`archivey_disk_images`), released with core at the same version.

- `archivey` (core): ZIP, TAR and its compressors, 7z, RAR, single compressed files,
  directories. About 43,000 lines of readers.
- `archivey-disk-images`: ISO 9660, UDF, CD images, SquashFS, DMG with HFS+ and APFS;
  the LZFSE, LZVN and ADC decoders. About 14,500 lines.
- `archivey-package-formats`: deb, rpm, ar, cpio, xar, pkg, makeself; pbzx. About 5,000
  lines.
- `archivey-legacy-formats`: CAB, LHA, ARJ with their decoders; ZIP shrink, reduce,
  implode and DCL implode as registered codecs. About 6,000 lines.
- `archivey-codecs`: unchanged, apart from how archivey finds its decoders (§6).

Extras `[disk-images]`, `[package-formats]` and `[legacy-formats]` name the packages.
`[recommended]`, `[all]` and `archivey-cli` include all three.

One repository because the corpus, the fuzz targets, the review rules and CI are
shared, and a reader fix often touches a public helper in the same change. What a
separate repository would prove, the wheel-install CI job proves: it builds each
package, installs it beside a core wheel, and fails on any import outside the public
names. A separate repository makes sense for a package only after the API is stable.

Because names are strings and discovery is by manifest, regrouping later (DMG to a
package of its own) changes the install line and one hint-table line, and no caller.

## Decisions

All ten were put to the maintainer and agreed on 2026-11-24.

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
5. **`archivey-codecs` is a second implementation of a codec name**, not a special
   case, under the accelerator rule.
6. **Three format packages** (§7). DMG stays in disk-images for now.
7. **`[recommended]` and `archivey-cli` install all three.**
8. **One repository, released together**, each package depending on one minor of core.
9. **The concurrency cut comes first, as a separate change** (maintainer, 2026-11-24).
   This plan builds on the contract it leaves (§5) and carries none of its tasks.
10. **Timing.** Steps 1 and 2 with the breaking trims of 0.6.0; the split in 0.7.0.

Earlier rulings kept: the composition interface with `BaseArchiveReader` private
(2026-10-25); ZIP, 7z and RAR on the internal base (2026-10-30); the private
full-decoder hook (2026-10-30); same archive, same contents; accelerators never change
the result or the error type; an established package as an extra over our own decoder.

Superseded: "built in, like ISO" (2026-10-28), by the 2026-11-24 direction to split.

## Risks / Trade-offs

- **Entry-point lookup cost.** `importlib.metadata` reads the metadata of every
  installed distribution: usually a few milliseconds, more in a large environment. It
  runs once, on first use. Measure in step 5 before it is settled. Fallback: collect
  only when a core signal has not settled the format; this is equivalent for detection
  because core signals rank first, but it must be shown for listing calls too.
- **Locating a manifest without importing.** `find_spec` on a top-level package runs
  no package code for a normal or an editable install, but a package with a custom
  import hook could differ. Step 3 tests wheels, editable installs and zipped installs,
  and a package whose manifest cannot be located is reported, not imported.
- **Open names lose static checks.** No exhaustive `match`, no `Literal` typo check.
  The runtime check at construction replaces them.
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
3. **Pilot wheel.** Passive discovery and policy-before-import (§3), then ar, cpio and
   rpm, the three readers that already use public names only, built as the first cut of
   `archivey-package-formats` and installed as a wheel beside a core wheel in a fresh
   environment. Checked through the public API: discovery, a plain and a compressed
   CPIO read, limits, cleanup, and the recorder test. The conformance recipe starts
   here. A session that did not work on the migration writes the guide's indexed
   example from the guide alone, and its unchanged wheel is tried against the next
   minor of core. Lands after 0.6.0 is cut, since it moves three formats out.
4. **Services, pulled by the reader that needs them.** Codecs by name with the
   eligibility rule, the block call, and the public helpers of §5, each landing with
   the first reader that needs it. The legacy ZIP methods are the first codec to cross
   a package boundary. A reader moves when it passes the public-imports test, not
   before, so there is no stage where all ten must pass at once.
5. **The other moves, one pack at a time.** The rest of the package formats (deb, xar,
   pkg, makeself), then legacy, then disk images. Each pack repeats the pilot's checks
   and the corpus comparison.
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
2. The package name `archivey-legacy-formats` and whether CAB belongs there or with the
   package formats.
3. Whether a known name with no installed package may be detected by signature, or by
   extension only, when the signature needs a probe.
4. The exact spelling of the off switch, and whether `FormatPolicy` gains a
   `providers=` allow-list beside `plugins=False`.
5. How a method namespace is declared by a plugin container, and whether 7z coder ids
   are bytes or their hex spelling in an entry.
6. The crypto facade's size: which primitives, and whether it requires `cryptography`
   as core does today.
7. Whether the conformance kit (`archivey.testing`) is part of step 5 or later.
