# Backend Registry

## Purpose

The backend registry maps detected archive formats to stateless read backend
factories. It knows core and optional formats at import time, reports
availability with install hints, and keeps format detection separate from backend
selection.

## Related specs

| Spec | Relationship |
| --- | --- |
| `format-detection` | Central magic/probe/extension matching before registry lookup |
| `compressed-streams` | Codec descriptors and codec availability used in format support |
| `archive-reading` | `open_archive()` calls detection then registry selection |
| `error-handling` | `FormatDetectionError`, `PackageNotInstalledError`, `UnsupportedFeatureError` |
| `packaging-and-extras` | Extras that satisfy optional dependencies |

## Requirements

### Requirement: Backends self-register at import time

The system SHALL register all known core and optional backends when `archivey`
imports. Optional library-backed backends (ISO, ZST, LZ4) and optional 7z writing
SHALL be imported behind `try/except ImportError` guards and registered
regardless of dependency availability. Missing dependencies make a format known
but unavailable, not unknown, and import MUST NOT fail.

Each backend SHALL declare dependency metadata as data. Availability SHALL be
derived centrally from the module-or-`None` sentinel idiom (`_optional("pycdlib")`
returns module or `None`), not per-backend booleans. 7z and RAR reading are
native and known; RAR data reads additionally require the external `unrar` binary
at read time. That binary SHALL be counted as an optional tool (see *Format support is
tri-state and compositional*): RAR reports PARTIAL, with `unrar` in `missing`, when no
usable RARLAB `unrar` or `rar` is on `PATH`, and a member read that needs it raises
`PackageNotInstalledError`.

```python
pycdlib = _optional("pycdlib")

class IsoReadBackend(ReadBackend):
    FORMATS = (ArchiveFormat.ISO,)
    EXTENSIONS = {".iso": ArchiveFormat.ISO}
    MAGIC = ((32769, b"CD001", ArchiveFormat.ISO),)
    OPTIONAL_DEPENDENCY = "pycdlib"

    def open_read(self, source, format, streaming, password, encoding, archive_name):
        assert pycdlib is not None
        ...

register_reader(IsoReadBackend)
```

The sentinel SHALL type-check cleanly under Pyrefly and ty because uses occur
behind `is not None` or equivalent registry-selection guarantees.

#### Scenario: import registration matrix

| Case | Expected |
| --- | --- |
| `import archivey` with no optional extras | Core formats plus native 7z/RAR register; supported formats show FULL/PARTIAL where applicable |
| `pycdlib` absent at import | No `ImportError`; ISO absent from supported formats but present in known formats with NONE support and install hint |

### Requirement: Backend classes are stateless factories

Each `ReadBackend` subclass SHALL hold no per-archive state.
All archive state lives in the returned `ArchiveReader`.
Multiple readers from the same backend class MUST be independent.

#### Scenario: stateless backend matrix

| Case | Expected |
| --- | --- |
| `open_archive("a.zip")` and `open_archive("b.zip")` are both open | Independent `ArchiveReader` instances; operations do not affect each other |

### Requirement: Detection owns matching and registry selects by format

The system SHALL keep format detection and backend selection separate.
`detect_format()` is the authority for source format: it aggregates backend
`MAGIC`, `TRAILER`, `EXTENSIONS`, and `CONTENT_PROBES`, performs special probes through
the detection workspace, consumes no bytes, and raises `FormatDetectionError` when no
format matches. The registry SHALL map the resolved `ArchiveFormat` to a
registered available backend. If a detected format has no available backend,
lookup SHALL raise `PackageNotInstalledError` with the install hint.

A backend that declares the format and sets `READ_IMPLEMENTED` false is not a missing
dependency. `format_availability` SHALL report `NONE` with an empty `missing`, and
`reader_for_format` SHALL raise `UnsupportedFeatureError` with that backend's message
rather than `PackageNotInstalledError`.

```python
class BackendRegistry:
    def register_reader(self, backend_cls: type[ReadBackend]) -> None: ...
    def reader_for_format(self, format: ArchiveFormat) -> type[ReadBackend]: ...
    def list_known_formats(self) -> list[ArchiveFormat]: ...
    def list_supported_formats(self) -> list[ArchiveFormat]: ...
```

#### Scenario: detection/selection matrix

| Case | Expected |
| --- | --- |
| Detection reports `ArchiveFormat.SEVEN_Z` | `reader_for_format()` returns native `SevenZReadBackend` |
| Detected backend's optional dependency is missing | `PackageNotInstalledError` names missing package and install hint |
| Detected format whose backend sets `READ_IMPLEMENTED` false (`DMG`) | `UnsupportedFeatureError` naming the format; `missing` is empty |
| No magic/probe/extension matches | `FormatDetectionError`; no backend lookup |

### Requirement: Read backends declare detection signals as data

Read backends SHALL declare all detection signals as data, and each signal SHALL
name the `ArchiveFormat` it implies so multi-format backends can map each
extension/magic/probe to the correct format without re-inspecting the source.
Magic-less or weak-signature formats SHALL use `CONTENT_PROBES` plus extensions;
there is no weak-magic flag.

```python
class MagicSignature(NamedTuple):
    offset: int
    magic: bytes
    format: ArchiveFormat

class ReadBackend(ABC):
    FORMATS: tuple[ArchiveFormat, ...]
    EXTENSIONS: Mapping[str, ArchiveFormat] = {}
    MAGIC: tuple[MagicSignature, ...] = ()
    CONTENT_PROBES: tuple[tuple[ArchiveFormat, Callable[[bytes], bool]], ...] = ()
    SUPPORTS_STREAMING_NON_SEEKABLE: bool = False
    OPTIONAL_DEPENDENCY: str | None = None

    @abstractmethod
    def open_read(self, source, format, streaming, password, encoding, archive_name) -> ArchiveReader: ...
```

The `format` argument SHALL be the already-resolved `ArchiveFormat`; multi-format
backends use it to choose a variant, while single-format backends may ignore it.

**Writing is not shipped.** There is no write backend ABC, no writer half in the
registry and no `archivey.create`. Unused scaffolding for them would only drift from
the design, so the writer surface stays in
[`archive-writing-design.md`](../../../dev-docs/investigations/archive-writing-design.md)
until an OpenSpec change for writing adds it.

#### Scenario: backend ABC matrix

| Case | Expected |
| --- | --- |
| `SingleFileBackend.MAGIC` has gzip and bzip2 signatures | Detector resolves `GZ` vs `BZ2`; both are served by one backend |

### Requirement: Optional dependencies degrade gracefully

The system SHALL degrade missing optional components to NONE or PARTIAL support
rather than import crashes. Opening a format or reading a member that needs a
missing component SHALL raise an error naming the package/tool and install
command from the same metadata exposed by `format_availability()`.

| Missing component kind | Support | Later error |
| --- | --- | --- |
| Single-codec format backend/codec missing (ISO without `pycdlib`, `.zst` without zstd backend before 3.14, `.lz4` without `lz4`) | NONE | `PackageNotInstalledError` at open with hint, except a non-seekable source for a format that needs seek (ISO), which gets `StreamNotSeekableError` (`access-mode-and-cost`) |
| Multi-codec container missing optional member codec/tool | PARTIAL | Opens/lists; member read raises `PackageNotInstalledError` or documented missing-tool error |
| 7z writing (not yet implemented) | Read support unaffected | Write raises `UnsupportedFeatureError` |

#### Scenario: graceful degradation matrix

| Case | Expected |
| --- | --- |
| ISO magic source opened without `pycdlib` | `PackageNotInstalledError` names `pycdlib` and `pip install archivey[recommended]`; no `ImportError` |
| `list_supported_formats()` without `pycdlib` | ISO absent; native 7z/RAR and satisfied formats present |

### Requirement: Codec availability and install hints come from descriptors

The system SHALL derive compositional support and missing-component install hints
from codec descriptor `requirement` fields. The separate `_CODEC_REQUIREMENT`
table SHALL not exist. FULL/PARTIAL/NONE results MUST remain unchanged by this
refactor.

#### Scenario: codec requirement matrix

| Case | Expected |
| --- | --- |
| Single-codec format's backend is missing | `format_availability()` reports NONE with descriptor-sourced install hint |
| ZIP / 7z / `tar.<codec>` availability is queried with missing optional codecs | Support level and missing list match the previous behavior, computed from descriptors |

### Requirement: Format support is tri-state and compositional

The system SHALL report readability as FULL, PARTIAL, or NONE:

```python
class FormatSupport(Enum):
    FULL = "full"
    PARTIAL = "partial"
    NONE = "none"

@dataclass(frozen=True)
class MissingComponent:
    name: str
    install_hint: str
    unlocks: tuple[str, ...]
    reason: str = ""

    @property
    def advice(self) -> str: ...

@dataclass(frozen=True)
class FormatAvailability:
    format: ArchiveFormat
    support: FormatSupport
    missing: tuple[MissingComponent, ...]
    required_source: StreamCapability = StreamCapability.SEEKABLE

def format_availability(
    format: ArchiveFormat,
    *,
    check_programs: bool = True,
    config: ArchiveyConfig | None = None,
) -> FormatAvailability: ...
def list_supported_formats(
    *, config: ArchiveyConfig | None = None
) -> list[ArchiveFormat]: ...
def list_known_formats() -> list[ArchiveFormat]: ...
```

Support SHALL be computed across the format backend and codecs/tools:

- NONE when the format backend is unavailable, or a single-codec format's only
  codec/backend is unavailable.
- FULL for an available multi-codec container only when every optional codec/tool
  it can use is present.
- PARTIAL for available multi-codec containers with missing optional codecs/tools.
- ZIP follows the same rule: FULL with every optional member-codec package (Deflate64,
  Zstd, PPMd) installed, PARTIAL when any is missing.
- The optional member codecs of 7z are PPMd, Deflate64, Zstd, Brotli and LZ4: every
  codec in its method table that needs a package. A test pins the list against that
  table, and ZIP's against its own.
- RAR counts one optional tool: a RARLAB `unrar` or `rar` 6.0 or later on `PATH`, the
  program the default `rar_decompressor` (`AUTO`) uses. Without one RAR is PARTIAL and
  `missing` names `unrar`; it still opens and lists, and stored members read. A usable
  `unar` does not make RAR FULL, because it reads fewer archives than `unrar`. The
  public `format_availability()` finds out by running each candidate once to read its
  banner (cached per binary, as for a member read), and the `unrar` entry's
  `install_hint` is the refusal that probe gives a member read. `reason` is set when the
  package may be installed but archivey does not use it on the running interpreter, and
  `advice` is `reason` when set, otherwise `install_hint`; every report of a missing
  component prints `advice`. `open_archive` and `list_supported_formats()` do not run
  it: a missing tool never makes a format NONE, so they need no answer about tools.
  `rar_decompressor` does not change the answer. `check_programs=False` runs no
  program and counts no tool, for a caller who wants no external program run.
- `cryptography`, which only encrypted members need, SHALL NOT lower support.
- By-design unsupported features such as unknown 7z method IDs SHALL
  not lower support; members using them raise `UnsupportedFeatureError`.

Without `config` the answer SHALL NOT depend on `ArchiveyConfig`. With `config`, two of
its fields change it, and no other:

- `config.formats.exclude_libraries`: an excluded package counts as absent (see
  `packaging-and-extras`, *An excluded optional library reads as not installed*).
- `config.formats.replace`: for a replaced container the answer is for the
  replacement's backend, not the built-in's. The replacement's `requires` count as a
  registered plugin's do, so a missing one makes the format NONE, and the open raises
  `PackageNotInstalledError` before the plugin's `open` runs. (A replacement whose
  `requires` holds an excluded package is refused when the policy is built; see
  `packaging-and-extras`.) The `cryptography` rule above is about the built-in readers,
  where only encrypted members need it; a replacement that lists it in `requires`
  reads nothing without it.

The policy's `only`, `exclude` and `plugins` SHALL NOT change the answer;
`config.formats.allows(fmt)` answers whether a format may open.

`list_supported_formats()` SHALL return FULL plus PARTIAL formats; with `config`, the
formats that are FULL or PARTIAL under that config. It SHALL NOT filter by
`config.formats.allows()`.
`list_known_formats()` SHALL return every known format including NONE.

`format_availability()` SHALL answer only for an `ArchiveFormat`. Any other argument —
a `StreamFormat`, `None`, or a value of an unrelated type — SHALL raise
`ArchiveyUsageError` per the boundary rule below, and MUST NOT produce a
`FormatAvailability`: returning one would put a value in its `format` field that
violates the type declared above, and a fabricated `NONE` with an empty `missing` is
indistinguishable from a legitimate unsupported verdict. The refusal SHALL key on the
argument's **type**, never on the shape of the verdict: `ArchiveFormat.UNKNOWN` answers
`NONE` with an empty `missing`, and that is a real answer.

`required_source` SHALL report **the weakest source shape the format can be read
from**, so that the split between formats readable from a pipe and formats that must
seek is queryable as data rather than discovered by catching
`StreamNotSeekableError`. It SHALL be derived from the backend's
`SUPPORTS_STREAMING_NON_SEEKABLE` declaration — the same fact `open_archive()`
enforces — and MUST NOT be declared separately per backend:

| `SUPPORTS_STREAMING_NON_SEEKABLE` | `required_source` | Formats |
| --- | --- | --- |
| `True` | `StreamCapability.FORWARD_ONLY` | TAR and its compressed combos, ZIP, the single-file compressors, UDIF |
| `False` | `StreamCapability.SEEKABLE` | ISO, 7z, RAR, directory |

`DMG` sets the flag even though nothing reads it. `open_archive` raises
`UnsupportedFeatureError` before the seekability check, and `SEEKABLE` would send
the published spool recipe through a copy that ends in the same refusal.

`required_source` SHALL be reported independently of `support`: a format whose
optional dependency is missing still answers the source-shape question. For a format
with no registered backend at all, `required_source` SHALL be `SEEKABLE` — the
conservative answer.

#### Scenario: format support matrix

| Case | Expected |
| --- | --- |
| 7z availability without the optional 7z packages | PARTIAL; missing names each absent package and `[recommended]`; LZMA2/bzip2/copy members still read |
| ZSTD availability before Python 3.14 without zstd backend | NONE with `backports.zstd` / `pip install archivey[recommended]` hint |
| GZIP availability | FULL; no missing components |
| 7z with the optional 7z packages installed | FULL even though an unknown method ID still raises `UnsupportedFeatureError` |
| 7z without `lz4` | PARTIAL; `missing` names `lz4` |
| RAR with no usable RARLAB `unrar` or `rar` on `PATH` | PARTIAL; `missing` names `unrar` with the probe's refusal as its hint (a too-old binary is named with its version); RAR is in `list_supported_formats()` |
| `format_availability(RAR, check_programs=False)` | No program runs; FULL when no codec is missing |
| RAR with a usable RARLAB `unrar` on `PATH` | FULL; no missing components |
| ZIP with every optional member codec installed | FULL; no missing components |
| ZIP missing deflate64 and/or zstd packages | PARTIAL; missing names absent codec packages; stored/deflate members still list/read |
| `format_availability(StreamFormat.ZSTD)` | `ArchiveyUsageError`; no `FormatAvailability` returned |
| `format_availability(ArchiveFormat.UNKNOWN)` | `NONE` with an empty `missing` — a hintless NONE is an answer, not a fabrication |

#### Scenario: required source matrix

| Case | Expected |
| --- | --- |
| `format_availability(TAR).required_source` | `FORWARD_ONLY` |
| `format_availability(TAR_GZ).required_source` | `FORWARD_ONLY` |
| `format_availability(GZ).required_source` | `FORWARD_ONLY` |
| `format_availability(DMG).required_source` | `FORWARD_ONLY` — open refuses before the seekability check; the field keeps the spool recipe from copying the file |
| `format_availability(ZIP).required_source` | `FORWARD_ONLY` — `streaming=True` reads a ZIP forward over its local headers |
| `format_availability(ISO \| SEVEN_Z \| RAR \| FOLDER).required_source` | `SEEKABLE` |
| ISO queried without `pycdlib` | `support=NONE` **and** `required_source=SEEKABLE` — the answer does not depend on installability |
| `required_source <= reader.cost.stream_capability` for a format opened successfully from that source | `True` for every format/source pair the library accepts |

#### Scenario: The supported list does not filter by the format policy

- **WHEN** a caller asks `list_supported_formats(config=cfg)` with
  `cfg.formats == FormatPolicy(only={ContainerFormat.ZIP})` and 7z readable
- **THEN** the list holds `ArchiveFormat.SEVEN_Z`
- **AND** `cfg.formats.allows(ArchiveFormat.SEVEN_Z)` is false

#### Scenario: Availability answers for the replacement

- **WHEN** a caller asks `format_availability(ArchiveFormat.ZIP, config=cfg)` with
  `cfg.formats == FormatPolicy(replace={ContainerFormat.ZIP: P})`,
  `P.requires == ("acme_zipcrypt",)` and `acme_zipcrypt` not installed
- **THEN** the answer is NONE and its `missing` names `acme_zipcrypt`
- **AND** opening a ZIP file with `cfg` raises `PackageNotInstalledError`, and `P.open`
  is not called

### Requirement: A format argument outside its declared type is a usage error

Four public functions take a format argument. Each SHALL accept a value of the types
its own signature declares, **or that format spelled as a string**, and SHALL reject
anything else with `ArchiveyUsageError` — which sits outside `ArchiveyError`
(`error-handling`), so `except ArchiveyError` cannot swallow a caller bug — **before**
resolving, peeking or reading the source:

| Call | Accepts | Anything else |
| --- | --- | --- |
| `format_availability(format)` | `ArchiveFormat`, its spelling | `ArchiveyUsageError` |
| `open_archive(source, format=…)` | `ArchiveFormat`, its spelling, `None` (auto-detect) | `ArchiveyUsageError` |
| `open_stream(source, format=…)` | `StreamFormat`, raw-stream or compressed-tar `ArchiveFormat`, either spelling, `None` | `ArchiveyUsageError` |

`open_stream`'s wider argument is by design, not an inconsistency to remove: a raw
compressed stream has no container, so the codec alone identifies it. A compressed-tar
`ArchiveFormat` (`TAR_GZ`, `(TAR, LZIP)`, …) is accepted too: `open_stream` decodes its
outer codec and returns the tar bytes (`compressed-streams`). Only the compressed tars
with a named constant (`TAR_GZ`, `TAR_BZ2`, `TAR_XZ`, `TAR_ZST`, `TAR_LZ4`) have a
string spelling; the three unnamed pairs — `(TAR, LZIP)`, `(TAR, ZLIB)`,
`(TAR, BROTLI)` — have none, because the spellings are built from the named-format
table, so they are passed as the `ArchiveFormat` object. Any other container
`ArchiveFormat`, an uncompressed `TAR` included, remains a usage error, because it has
no compression layer for `open_stream` to remove.

An `ArchiveFormat` is a `(container, stream)` pair rather than an `Enum`, so it has no
`value` to spell. Its spellings SHALL be its **file extension** (`"zip"`, `"tar.gz"`)
and its **attribute name** (`"TAR_GZ"`), both derived from the existing tables so a
format added later is spellable without a second edit. `DIRECTORY` and `UNKNOWN` have
no extension, so the name alone spells those. Case is ignored and `-` and `_` are
interchangeable, matching the boundary rule in `error-handling`. No two formats may
share a spelling, and the test suite SHALL fail if a new format introduces a collision.

`open_stream` SHALL resolve a string against `ArchiveFormat` before `StreamFormat`. The
spellings the two types share name the same format at two levels, so the order picks a
representation rather than a meaning — and picks the one `open_archive` would.

A `StreamFormat` **object** passed where an `ArchiveFormat` is required SHALL still be
refused rather than widened: accepting `"gz"` as a spelling does not make the codec
half a valid pair.

A `ContainerFormat` **object** SHALL be refused on the same grounds, and for a reason
that needs stating because it is easy to get wrong: both component enums mix in `str`,
so every member passes an `isinstance(value, str)` test and its value is exactly a
spelling the coercion table keys on. The wrong-type check therefore SHALL run before
the spelling lookup. Otherwise `format=ContainerFormat.TAR` is completed into
`ArchiveFormat.TAR` and a healthy `.tar.gz` is read as an uncompressed tar, reporting a
caller's mistake as damaged input.

The rejection SHALL be a refusal, never a substitute answer: the call MUST NOT fall
back to auto-detection, return a fabricated record, or let an internal `AttributeError`
reach the caller.

The message SHALL name **what was passed** and **what was expected**. For a
`StreamFormat` passed where an `ArchiveFormat` was required — the likeliest mistake,
since `open_stream` accepts one — it SHALL also name the predefined `ArchiveFormat`
pairs built on that codec, so one message ends the mistake:

```
format_availability() takes an ArchiveFormat, but got StreamFormat.ZSTD. A StreamFormat
is only the codec half of an ArchiveFormat's (container, stream) pair, so pass the pair
instead: ArchiveFormat.ZST (a raw .zst stream) or ArchiveFormat.TAR_ZST (a tar
compressed with it).
```

Those names SHALL be derived from the predefined `ArchiveFormat` instances rather than
a separate table, so a codec added later is named here without a second edit.

#### Scenario: wrong-typed format argument matrix

| Case | Expected |
| --- | --- |
| `format_availability(StreamFormat.ZSTD)` | `ArchiveyUsageError` naming `StreamFormat.ZSTD`, `ArchiveFormat.ZST` and `ArchiveFormat.TAR_ZST` |
| `format_availability(None)` | `ArchiveyUsageError` — the query has no auto-detect form |
| `open_archive("a.tar.gz", format=ContainerFormat.TAR)` | `ArchiveyUsageError` naming `ContainerFormat.TAR` and the pairs built on it, never a `TruncatedError` |
| `open_archive(path, format=StreamFormat.ZSTD)` | `ArchiveyUsageError`, not `AttributeError: 'StreamFormat' object has no attribute 'container'` |
| `open_stream(src, format=object())` | `ArchiveyUsageError`; the source is not read and detection does not run |
| `open_stream(src, format=StreamFormat.GZIP \| ArchiveFormat.GZ \| None)` | Opens as before |
| `open_stream(src, format=ArchiveFormat.TAR_GZ)` | Opens the gzip layer; returns the tar bytes |
| `open_stream(src, format=ArchiveFormat.TAR \| ArchiveFormat.ZIP)` | `ArchiveyUsageError` |
| `open_archive(path, format=ArchiveFormat.ZIP \| None)` | Opens as before |
| `open_archive(src, format=…)` with an `UNKNOWN` container (`ArchiveFormat.UNKNOWN`, `"unknown"`, or an unnamed pair such as `(UNKNOWN, GZIP)`) | `ArchiveyUsageError` before the source is read; `format_availability(ArchiveFormat.UNKNOWN)` still answers `NONE` |
| `open_stream(src, format=…)` with an `UNKNOWN` container (`ArchiveFormat.UNKNOWN`, `"unknown"`, or an unnamed pair such as `(UNKNOWN, GZIP)`) | `ArchiveyUsageError` before the source is read, also for a missing path or a directory; it does not call it a container format or point to `open_archive`, which refuses it too |
| `except ArchiveyError` around any of the refusals | Does not catch it |

#### Scenario: format spelled as a string

| Case | Expected |
| --- | --- |
| `open_archive(path, format="zip")` | Opens as `ArchiveFormat.ZIP` |
| `format_availability("zip")` | Same record as `format_availability(ArchiveFormat.ZIP)` |
| Every format, by its name and by its file extension, in any case | Resolves to that format |
| `open_stream(src, format="gz")` | `ArchiveFormat.GZ` — what `open_archive` would resolve it to |
| `open_stream(src, format="gzip")` | `StreamFormat.GZIP` — no `ArchiveFormat` spells it |
| `open_archive(path, format="not-a-format")` | `ArchiveyUsageError` naming the accepted spellings |
| Two formats sharing a normalized spelling | Test suite fails |

### Requirement: The caller's format policy decides whether a detected format opens

`ArchiveyConfig.formats` SHALL hold a `FormatPolicy`. After detection, or after an
explicit `format=`, `open_archive` and `open_stream` SHALL refuse a format the policy
does not allow, with `UnsupportedFeatureError` whose `source_format` is that format and
whose message names the policy entry that would allow it. The policy SHALL NOT change
which built-in format detection reports (see `format-detection` for plugin formats).

#### Scenario: A compression missing from an allow-list is refused

- **WHEN** a caller opens a gzip-compressed TAR with
  `FormatPolicy(only={ContainerFormat.TAR})`
- **THEN** the open raises `UnsupportedFeatureError` that names `StreamFormat.GZIP`
- **AND** `detect_format` on the same file still reports `ArchiveFormat.TAR_GZ`

### Requirement: A replacement plugin reads a built-in container

A `FormatPolicy(replace={container: plugin})` SHALL open that built-in container with
the plugin's reader. Detection SHALL stay the built-in's, `reader.format` SHALL be the
built-in format, and `format_info.from_plugin` SHALL stay false.

The replacement SHALL NOT be given a multi-volume set or an archive found behind an SFX
stub; each SHALL raise `UnsupportedFeatureError` that names the replacement. A read-once
source SHALL raise `StreamNotSeekableError`, as it does for any indexed plugin. A raw CD
sector image detected as ISO SHALL be refused as the built-in reader refuses it. Each
refusal SHALL come before the plugin's `open` runs.

#### Scenario: A ZIP opens with the replacement

- **WHEN** a caller opens a ZIP file with `FormatPolicy(replace={ContainerFormat.ZIP: P})`
- **THEN** `P.open` reads it and `reader.format` is `ArchiveFormat.ZIP`

#### Scenario: A replacement is not given a volume set

- **WHEN** a caller opens the first part of a multi-volume ZIP set with
  `FormatPolicy(replace={ContainerFormat.ZIP: P})`
- **THEN** the open raises `UnsupportedFeatureError` that names `P`
- **AND** `P.open` is not called
