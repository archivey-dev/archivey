# backend-registry — format policy delta

## ADDED Requirements

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

## MODIFIED Requirements

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
