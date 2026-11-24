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
         +------------ manifest entries (data only) ------------+
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

A manifest is plain data that core reads without importing a reader.

```python
# archivey_disk_images/_manifest.py: imports archivey.formats and nothing else
MANIFEST = PluginManifest(
    api=(1, 0),
    formats=[
        FormatEntry(
            name="dmg",
            extensions=(".dmg",),
            trailer=Trailer(offset=-512, data=b"koly"),
            handler="archivey_disk_images.dmg:DmgHandler",
        ),
    ],
    codecs=[...],
)
```

- A `FormatEntry` carries what `FormatHandler` declares as class attributes today:
  name, extensions, signatures at a fixed offset, trailer signatures, `requires`, the
  install hint, whether it reads in one pass, whether it takes a password. It adds the
  handler's dotted path, and optionally a probe's dotted path and `refines`.
- Core's own formats are entries in a literal table inside `archivey`. Their handler
  paths point into `archivey.internal`. The table does not care which base class a
  handler is built on.
- `refines="ar"` says that the format is a more specific reading of another one (deb
  over ar, pkg over xar). Detection prefers the refinement. This replaces import order.
  A refinement must come from the distribution that owns the base format, so a stranger
  cannot refine ZIP.
- A probe is a dotted path to a small function, imported only when extensions and
  signatures have not settled the format. `zip_detect`, `rar_detect` and
  `sevenzip_detect` already have this shape.

### 2. Names

A name is a short lowercase string, and the registry is what makes a string valid.

```python
ContainerFormat.ZIP          # a constant, for what core ships
ContainerFormat("dmg")       # any registered or known name
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
- **Unknown names fail early.** `ArchiveFormat("dgm")` raises `ArchiveyUsageError` when
  built. A name that is known and not installed builds, and fails at open with the hint.
- **Provenance is data.** `FormatInfo.provider` is the distribution name: `"archivey"`
  for core. `FormatPolicy(plugins=False)` keeps its meaning: only code shipped in the
  `archivey` distribution runs.
- **Constants live with their owner.** Core has no `ContainerFormat.DMG`. The 13 moved
  constants stay one release as aliases that warn and name the package.

### 3. Discovery and loading

```toml
[project.entry-points."archivey.plugins"]
disk-images = "archivey_disk_images._manifest:MANIFEST"
```

1. `import archivey` loads the public types, the config and core's own table. It scans
   nothing.
2. The first call that needs the registry collects the `archivey.plugins` group, once,
   in sorted order of distribution name, so the result does not depend on install
   order. Loading an entry imports its manifest module, which is small by contract.
3. Detection runs on manifest data.
4. A handler module is imported when an archive of its format is opened.
5. `register_format()` and `register_codec()` take the same entries, for a program that
   adds a format at run time. They are a second door into the same table.

Guardrails:

- **A plugin adds and never takes over** (the one-owner rule). Replacing a reader stays
  an explicit choice of the calling program, `FormatPolicy(replace=...)`.
- **Allow-lists do not move.** `FormatPolicy.COMMON` and any `only=` policy name what
  may run, whatever is installed.
- **One off switch.** `ARCHIVEY_PLUGIN_AUTOLOAD=0`, or
  `archivey.formats.disable_autoload()` before first use. After that only core and
  explicit registrations count.
- **Visible.** `archivey --version` and `format_availability()` name each provider.
- **A plugin that fails to load does not break core.** A manifest that raises, or one
  written for another API major version, is skipped and reported as unavailable with
  the reason.

### 4. The hint table

Core lists formats it knows and does not ship: the same `FormatEntry` data with a
package name in place of a handler. When the package is missing, opening such an
archive raises `PackageNotInstalledError` naming the package.

The table is what keeps "same archive, same contents" true across installs: an archive
reads the same way or is refused with a hint, and is never read as another format. A
`.deb` on a core-only install must not open as something less specific.

A CI test keeps the table equal to our packages' manifests. An outside project adds its
line by pull request, as projects do in fsspec.

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
  registry's second-implementation rule (§6).
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

**Threads.** With the concurrency cut (tracked internally), the contract a reader
author sees is three sentences:

1. archivey calls the methods of one reader from one thread at a time.
2. A walk has the reader to itself from its first member to its end. A second walk
   never starts while one runs.
3. A stream that `open_member` returned may be read while other streams of the same
   reader are open, each by one thread at a time.

Rule 2 removes today's warning that `walk()` may run more than once at the same time,
and with it the cases a plugin's tests would have to cover: a pass beside random
access, two passes at once, a close that waits for other threads. Rule 3 is what
`archivey.fsspec` needs. The rules are the same for every format.

**Version.** `archivey.formats.API_VERSION` is a pair. A manifest states the version it
was written for. Until the API is declared stable it may change in a minor release,
never in a patch. Our packages depend on one minor of core (`archivey>=0.7,<0.8`).

### 6. Codecs

```python
CodecEntry(
    name="shrink",
    decoder="archivey_legacy_formats.zip_methods:ShrinkCodec",
    methods={"zip": (1,)},     # a container's method number
    stream=None,               # or StreamEntry(extensions=..., magic=...)
    priority=0,                # a second implementation of a name has a higher one
)
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

Rules:

- **Register a codec only when another package uses it.** LZX (CAB alone) and LZH (LHA
  and ARJ, which ship together) stay plain imports inside their package.
- **What is part of parsing stays with the parser.** The 7z filters, ZipCrypto and AES
  stay in core.
- **A second implementation follows the accelerator rule.** More than one package may
  implement a name. The highest priority that the caller's policy allows wins. It gives
  the same bytes and the same error type as the first, and the parity tests are the
  entry bar. `archivey-codecs` registers its Rust decoders this way and stays one
  package. The Python decoder ships with the format that needs it.
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
9. **The concurrency cut is part of this change** where it shortens the reader contract
   (§5).
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
- **A light manifest is a convention.** A package could import its readers from its
  manifest module. The conformance test for our packages checks it; an outside package
  only costs itself time.
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

Each step ships by itself and leaves main working. Files move only in step 5.

1. **Manifest and lazy loading, inside core.** No public name changes. Proves that
   detection works from data alone and that `import archivey` loads no reader.
2. **Open names.** The breaking step. Proves that core has no plugin-only type left.
3. **The API is enough, in tree.** One pull request per reader or shared helper until
   all ten pass the public-imports test while still in `src/`. The concurrency cut lands
   here. Proves §5's list, line by line.
4. **Codecs by name.** The legacy ZIP methods are the first codec to cross the boundary,
   still in tree. Proves that a core reader can use a codec it does not ship.
5. **Discovery and the move.** Proves that a core-only install refuses a DMG with the
   right hint and that a full install reads the whole corpus as before.
6. **Afterwards.** Aliases removed one release later; the plugin guide rewritten,
   shorter.

Rollback: steps 1, 3 and 4 are internal and revert cleanly. Step 2 and step 5 are
released behaviour; their rollback is a new release.

## Open Questions

For the next rounds of this plan. None blocks step 1.

1. Names of the entry types and fields (`FormatEntry`, `CodecEntry`, `PluginManifest`),
   and whether `FormatHandler` keeps its declaring class attributes or reads them from
   its entry.
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
