## 0. Interface first: port in place (R14)

- [ ] 0.1 The public-names test: a list of modules that may import only public
  names, empty at first. No reader passes today: all 13 import
  `register_builtin_format` and `override` from `archivey.internal`
- [ ] 0.1a Registration leaves the reader modules (review F3): core registers the 13
  handler classes from a table; DMG's magic and trailer and pkg's refinement become
  handler declarations; `override` is a shim in each module. cpio, rpm and ar then
  pass the test of 0.1
- [ ] 0.2 For each of the other ten readers, one pull request: the reader still lives
  in core, the public interface gains what it needs (tasks 0.4 to 0.9, the probe
  context), and its module joins the list of 0.1. What each
  still takes from `archivey.internal` is listed in design.md §5
- [ ] 0.3 The same for the eight stream codecs that move (the seven of R11 and pbzx,
  whose xz chunks come from `CodecCall` as capped core decoders), onto `CodecHandler`
  with the hooks of R15; `.Z` goes first among those that need the richer decoder,
  and settles its public shape (Open Question 11); raw LZO1X uses it with no restart
  points (a SquashFS LZO image and a direct block decode that ends at end of input;
  the size check before any allocation; a short last block)
- [ ] 0.3a The in-process registration a ported codec uses before the manifest
  exists: the handler class declares its native target and takes the probe context
  in Python, and core's present dispatch by method id and by block call reaches the
  new handler, so every entry point the codec has today still works (file
  detection, whole-file read, container method, block). Group 4 then reads the same
  declarations from the manifest. Brotli's port passes its probe and read tests, the
  7z member path and the isolation checks in this step
- [ ] 0.4 The public kernel helper (revision check, panic guard, child), used by core
  and by the moved readers; `archivey-speedups` unchanged (R1)
- [ ] 0.5 `ReaderContext.decompress` by name, with the single-stream option (xar); the
  block call (SquashFS, DMG)
- [ ] 0.6 Public listing-limit, timestamp and Unix-mode helpers (ISO, xar, CAB, DMG,
  LHA, ARJ)
- [ ] 0.7 Crypto facade (makeself, DMG, ARJ)
- [ ] 0.8 Nested-archive helpers folded into `ReaderContext.open_nested`; the path
  helpers public (deb, pkg)
- [ ] 0.8a Public calls for each private attribute listed in design.md §5 (spanning
  checks, decoded-byte and decoder-use accounting, listing budgets, source origin,
  range hints and progress), each with the reader that needs it
- [ ] 0.9 `ReaderSource` source helpers (ISO, DMG)
- [ ] 0.10 No behaviour change: the full suite and the corpus comparison pass
  unchanged after each port

## 1. Manifest and lazy loading, inside core

- [ ] 1.1 The entry shape and core's own table: one entry per format on main, the 13
  plugin-shaped readers and ZIP, TAR, 7z, RAR, single-file and directory
- [ ] 1.1a Core's table has codec entries too (review F5): for every stream codec on
  main, its stream facet, the method it runs and the methods it also decodes, so
  the policy's tables can be read from data in step 2. Method bindings and
  eligibility stay in group 4
- [ ] 1.1b The two imports of reader modules in `core.py` go (review F2): the ISO
  raw-sector refusal becomes a check the entry names, run before open and for a
  replacement too; the makeself hint reads the magic from the entry
- [ ] 1.2 Registry built from entries; handler modules imported on first open
- [ ] 1.3 Detection in three phases (design.md §4): family from data, bounded
  refinement after a signature match, availability; the probe step between them
- [ ] 1.4 `refines` and `preempts` replace the deb-before-ar import order and the
  trailer preempt list; deb's refinement as a longer signature
- [ ] 1.5 Remove the side-effect imports in `backends/__init__.py`
- [ ] 1.6 A test that `import archivey` loads no reader module, with the module count
  and the import time recorded before and after
- [ ] 1.7 Detection parity: pkg and plain xar, deb and plain ar, with correct, missing
  and misleading suffixes; `detect_format()` and `open_archive()` agree; read budgets
  measured on seekable and forward-only sources
- [ ] 1.7a One tail window for every trailer declaration: several declarations on a
  source that counts range reads, and on a member stream; a trailer over the cap
  refused at load
- [ ] 1.7b Core's binary CPIO check (R13): a binary `.cpio` is CPIO with no stream
  format, and a binary `initrd.cpio.gz` is `(CPIO, GZIP)`, named and unnamed
- [ ] 1.8 Spec deltas: `format-manifest` (new), `backend-registry`, `format-detection`

## 2. Open names (breaking)

- [ ] 2.0 Usage audit, written into the pull request: every use of enum iteration, enum
  attributes, the `Literal` aliases and persisted values in `src/`, `tests/`, `docs/`
  and the CLI; which names get a deprecation window under DR-12a (the stable ones) and
  which go at once (the experimental ones)
- [ ] 2.0a The couplings outside the readers that step 2 touches (design.md §5): the
  policy's stream-to-method and decodes-with tables read from the codec entries of
  1.1a, a public query for the known libraries (the CLI's version report), a public
  "has an outer stream" property in place of the CLI's container list, the speed-up
  codecs and "may be replaced" as entry fields; a test that core's source names no
  moved format outside the hint table
- [ ] 2.1 `ContainerFormat`, `StreamFormat`, `OptionalLibrary` as open string types and
  `CompressionAlgorithm` as an open non-string type, with core's constants;
  construction checks spelling only and touches no registry; membership is checked
  when a call resolves the name, before I/O
- [ ] 2.1a Tests: a known name whose package is missing, a typo at resolution, and a
  value built from a stored string before any discovery
- [ ] 2.1f Role and display name without enums (review AG8): `ArchiveFormat` refuses
  a typed name in the wrong position at construction; `ArchiveFormat("gz")` and
  `FormatPolicy(exclude={ContainerFormat("xz")})` raise `ArchiveyUsageError` at
  resolution; `display_name` from the entries, with every pair name of today pinned
- [ ] 2.1b `FormatPolicy` stores containers, streams and methods by role;
  `only_libraries` by membership; a test that `exclude={StreamFormat("xz")}` still
  reads an xz member of a ZIP
- [ ] 2.1d One namespace for container and stream names (R10): the registry refuses a
  name the other role owns, and a test pins that core's two lists do not overlap
  (the hint table's reservation across roles is task 3.6)
- [ ] 2.1e Every core constant of the four types passes the spelling rule; names are
  case-sensitive and two names differing only in case are refused
- [ ] 2.1g `format="ZIP"`, a mixed-case extension and a spelling alias still resolve,
  on an explicit open and in `format_availability()`
- [ ] 2.2 Remove `PluginContainer`, `PluginStream` and the `Literal` spelling lists
- [ ] 2.2a `ExtraKey` and the generic overloads on `MemberExtra` and
  `ArchiveInfoExtra`; key constants for every format; the 62 per-key overloads
  removed; the conformance check that a reader sets only declared keys (R3); the two
  `get()` overloads ahead of the `str` ones, under both type checkers; the `EXTRA_*`
  constants retyped in place; keys declared on the handler, core's shared keys
  allowed to every reader
- [ ] 2.3 `FormatInfo.provider` replaces `from_plugin`; `FormatPolicy(providers=...)`,
  with `plugins=False` as a deprecated spelling of `providers={"archivey"}` (R2)
- [ ] 2.3a Detect first, judge after (R9), in the same pull request as `providers=`: a
  policy that allows a base and bars its refinement refuses the refined file and
  names the refinement; a barred provider's check and probe never run; the
  2026-10-28 "left out of detection" tests are rewritten. Until this lands, a plugin
  format the policy turns off stays out of detection
- [ ] 2.3b `FormatPolicy.COMMON` gains `providers={"archivey"}` (R11) with 2.3a, with a
  **Breaking:** line; the docstring's recipe for building on `COMMON` rewritten to
  carry `providers`, with a test that its result bars an outside probe (review F9);
  the recorder test uses a file that would run an outside probe
  and one that would run an outside refinement check under another policy
- [ ] 2.4 `register_format` and `register_builtin_format` become one function that
  takes an entry
- [ ] 2.5 `CHANGELOG.md` **Breaking:** lines; `dev-docs/api-surface.txt` updated
- [ ] 2.6 Spec deltas: `archive-data-model`, `format-plugins`

## 3. Pilot wheel (after 0.6.0 is cut)

- [ ] 3.1 Passive discovery: list the `archivey.plugins` entry points without loading,
  read `archivey-manifest.toml` as a file of the entry point's distribution; sorted,
  once, on first use; cost measured in a small and a large environment
- [ ] 3.1a Owner before code: a manifest's module names belong to one distribution, the
  manifest's own, and the resolved file is that distribution's; checked for handlers,
  probes, refinement checks, decoders and the child's `native` target; two
  distributions with one import name are both refused and reported; `find_spec`
  never called on a dotted name; a dotted target the file list does not show is
  refused with the parent's initializer not run; each part of a dotted path is
  executed from the spec whose origin was compared with the listed file, and a
  parent `__path__` that leads elsewhere is refused, in the host and in the child
- [ ] 3.2 Policy before import: no dotted path of an installed package is imported
  before the call's policy allows its provider and every library its entry lists
  (`exclude_libraries={"brotli"}` and `only_libraries=set()` with the compressors
  installed: no Brotli probe, no import of `brotli`). The provider policy gates every code
  load; the format policy gates opening and decoding the detected format (R9), so a
  probe or refinement of an allowed provider runs for a format the call refuses; a
  refinement check skipped for a barred library refuses the base's file with that
  reason
- [ ] 3.3 The recorder test: a wheel whose `__init__` records that it ran; discovery,
  opening a core ZIP and `format_availability()` under the default policy,
  `plugins=False` and `FormatPolicy.COMMON`, in both orders; and the files of 2.3b,
  since opening a ZIP alone cannot show that a probe ran
- [ ] 3.4 Ownership: one owner per name and signature, owner before length (an
  outside signature at another offset, a stub needle and a trailer over a core ZIP:
  core's answer stands), longest first inside one owner, a
  clashing extension dropped alone; `refines` and `preempts` only with the owner's
  consent, never by a policy (an outside refinement is opened with `format=`); a
  refinement from another distribution is data only, and the file is refused, never read
  as its base, when that provider is missing or barred; a bad manifest skipped
- [ ] 3.4a The provider query and `archivey --version -v`: found, refused, unparsable
  and incompatible providers, each with its reason
- [ ] 3.5 The off switch (environment variable and function); it turns our own packages
  off too; `load_provider()` for one named distribution under the same checks; the
  error for an installed package that was not loaded differs from the install hint
- [ ] 3.6 The hint table, and the test that keeps it equal to the packages' manifests;
  it reserves a name for both roles (R10) and lists the libraries and methods of the
  moved formats, so a policy that names one stays valid without the package
- [ ] 3.7 `packages/archivey-package-formats` with rpm alone (cpio waits for pkg,
  which opens it nested; a test lists every `open_nested` target of a core reader
  and fails when one is not a core format), exporting a constant for every library
  it uses (R8, as each later package does), added to
  `[recommended]`, `[all]` and `[free-threaded]`; type checkers, fuzz targets and
  `test.sh --all-configs` extended to `packages/`
- [ ] 3.8 CI: build the wheel, install it beside a core wheel in a fresh environment,
  run the public-names test of 0.1 and the pilot checks (discovery, an rpm with a
  compressed payload, limits, cleanup); wheel, editable and zipped installs; the editable rule of
  design.md §3 (a `.pth` of directory lines is accepted, one with an `import` line
  and a hook-based install are refused)
- [ ] 3.9 `archivey.formats.API_VERSION` with the acceptance rule of design.md §5,
  checked on the manifest before import; the manifest envelope (`api` and names) read
  whatever the version; `format_availability()` and an open by name pinned for an
  incompatible outside format, a missing known package and an unknown name; an older
  and a newer plugin tried against two host versions
- [ ] 3.9a The conformance recipe
- [ ] 3.9b Timing: cold import and first successful operation, on a core-only, a
  recommended and a crowded environment
- [ ] 3.10 A session that did not work on the migration writes the guide's indexed
  example from the guide alone; its unchanged wheel is tried against the next minor
- [ ] 3.11 Spec deltas: `format-manifest`, `format-plugins`, `packaging-and-extras`

## 4. Services, pulled by the reader that needs them

- [ ] 4.1 Codec entries: names, method namespaces with vacant and occupied slots, the
  stream facet
- [ ] 4.2 Eligibility before priority: a second implementation runs only when the
  name's owner lists it or the caller selects it; the provider that ran is in
  `BackendUse`
- [ ] 4.3 Tests: a vacant slot with and without its provider; an unrelated
  distribution claiming a higher priority for a stock method; a test wheel that
  the name's owner lists, and its fallback; an allow-list keeps its decoder set
- [ ] 4.4 ZIP legacy methods through `("zip", n)`; the ZIP reader's legacy table gone;
  `CodecCall` carries the method id, the container flags and whether the input runs
  on; the entry says whether the decoder rejects random input; Implode with both
  window sizes, Reduce at each factor, and a password list on an encrypted legacy
  member stay as fast as before
- [ ] 4.4a `format_availability(ZIP)` counts core's and the hint table's methods
- [ ] 4.6a Process isolation for package codecs (R4): `native` on a codec entry (the
  Python declaration and `call.native(...)` are from 0.3a), the child loading each part
  of an allowed dotted path from the origin the parent checked and sent, the error mapping; a
  test wheel with a native decoder that runs in the child under `NATIVE_DECODERS` and
  in process otherwise; the `isolation` floor (a `.bz3` file decodes in a child under
  the default config and raises `ResourceUnavailableError` where none can start);
  `native` naming a worker module of the package; `requires` apart from `speedups`
  (lzop and Snappy stay `FULL` with `faster_with` when `compress-utils` is absent);
  `docs/security.md` and the threat model state the undeclared case
- [ ] 4.7a The probe declared on the manifest entry. The three-valued verdict as the
  only return type of a probe has landed (pull request 1850); the probe context and
  Brotli's probe on it are from 0.3a; `_brotli_probe_confidence` out of core
- [ ] 4.8 SFX stub scan declared on the entry (LHA, ARJ): needles, whether the
  parser scans, and a required validator by dotted path, gated like a probe; a 2 MiB
  program with chance `60 EA` bytes is not ARJ; on a core-only install an LHA stub
  and an ARJ stub are both refused with the hint, ARJ by core's size and CRC-32
  check (R16), which the package's validator reuses
- [ ] 4.12 Spec deltas: `compressed-streams`, `format-plugins`

## 5. The other moves, one pack at a time

- [ ] 5.0 Each move is the files, the manifest entry and the hint line, with no
  change to the code: the port was group 0
- [ ] 5.1 The rest of `archivey-package-formats`: ar with deb, cpio and xar with pkg and the
  pbzx codec, makeself, CAB; a base and its refinements in one pull request
- [ ] 5.1a With cpio: the two files of 1.7b on a core-only install, a full install and with the
  provider barred: detected the same in all three, read with the package and refused
  with the hint without it; the package's handler reuses core's check
- [ ] 5.2 `packages/archivey-legacy-formats`: LHA, ARJ, the legacy ZIP methods, `.Z`
- [ ] 5.3 `packages/archivey-disk-images`: ISO, UDF, CD images, SquashFS
- [ ] 5.3a `packages/archivey-dmg`: DMG with HFS+, APFS and encryption
- [ ] 5.3b `packages/archivey-compressors` (R11): lz4, mozlz4, Brotli, lzop,
  bzip3, Snappy as codec entries with stream facets; the 7z LZ4 and Brotli bindings;
  their libraries stay in core's extras as today (`brotli` out of `[free-threaded]`,
  `bzip3` in `[bzip3]` only); the wheel resolves on macOS and 3.13t, and LZ4 is read in
  the free-threaded job;
  SquashFS with LZ4 or LZO, and a 7z with those methods, refused with the hint when
  the package is missing; the hint for LZ4, mozlz4 and Brotli names the package and
  the library in one command, and a core-only install that runs it reads the file
- [ ] 5.3c `VISION.md`: ISO comes with `[recommended]`, not with the bare install
- [ ] 5.4 For each pack: the pilot checks, the public-imports test, and a corpus run on
  a core-only install (refused with the hint) and a full install (same results as
  before the move)
- [ ] 5.5 `[recommended]`, `[all]`, `[free-threaded]` and `archivey-cli` include the
  five; `[bzip3]` requires `archivey-compressors` beside the library, and a clean
  install of that extra alone opens `.bz3` and `.tar.bz3` on a supported platform;
  no extra named after a package; publish matrix rows; type checkers, fuzz
  targets and `--all-configs` cover each moved package
- [ ] 5.6 The moved constants as deprecated aliases (13 containers, eight
  streams, their `ArchiveFormat` constants, the moved methods), clean under both type
  checkers; importing archivey warns nothing
- [ ] 5.7 Spec deltas: `packaging-and-extras`, the moved format specs
- [ ] 5.8 Remove `openspec/changes/plugin-api`, which this change replaces, only
  after its requirements that survive are in `openspec/specs/` (review AG10): the
  reader contract, `hold()`, `data_on_demand`, inner-stream detection and
  `CodecHandler` exist only in that change's deltas today. Either `plugin-api` is
  archived first, or the implementing change of step 2 folds them into its
  `format-plugins` and `compressed-streams` deltas; a dry-run `openspec archive`
  shows it
- [ ] 5.8a Archive `nested-archives`, `plugin-passwords` and `dmg-reader` before the
  readers they describe move, so their format specs are in `openspec/specs/` when
  step 5 edits them

## 6. Afterwards

- [ ] 6.1 Remove the aliases one release later
- [ ] 6.2 Rewrite `docs/adding-a-format.md` against the settled contract
- [ ] 6.3 `openspec validate --strict plugin-platform`
- [ ] 6.4 Archive the change (`openspec archive plugin-platform --yes`) in the pull
  request that ticks the last box
