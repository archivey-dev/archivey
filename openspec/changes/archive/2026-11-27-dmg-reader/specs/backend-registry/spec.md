## MODIFIED Requirements

### Requirement: Detection owns matching and registry selects by format

The system SHALL keep format detection and backend selection separate.
`detect_format()` is the authority for source format: it aggregates backend `MAGIC`,
`TRAILER`, `HEADER_CHECKS`, `EXTENSIONS`, and `CONTENT_PROBES`, performs special
probes through the detection workspace, consumes no bytes, and raises
`FormatDetectionError` when no format matches. The registry SHALL map the resolved
`ArchiveFormat` to a registered available backend. If a detected format has no
available backend, lookup SHALL raise `PackageNotInstalledError` with the install
hint.

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
| Detected format whose backend sets `READ_IMPLEMENTED` false (none ships today) | `UnsupportedFeatureError` naming the format; `missing` is empty |
| No magic/probe/extension matches | `FormatDetectionError`; no backend lookup |

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
    faster_with: tuple[MissingComponent, ...] = ()

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
`config.formats.allows()`. `list_known_formats()` SHALL return every known format
including NONE.

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
| `True` | `StreamCapability.FORWARD_ONLY` | TAR and its compressed combos, ZIP, RAR, the single-file compressors |
| `False` | `StreamCapability.SEEKABLE` | ISO, 7z, DMG, directory |

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
| `format_availability(DMG).required_source` | `SEEKABLE` — the run table is at the end of the image and the filesystem metadata can be anywhere in it |
| `format_availability(ZIP).required_source` | `FORWARD_ONLY` — `pipe=True` reads a ZIP forward over its local headers |
| `format_availability(RAR).required_source` | `FORWARD_ONLY` — `pipe=True` reads a single-volume RAR forward with RARLAB `unrar` 7.00 or later; without it the open raises `StreamNotSeekableError` naming the fix |
| `format_availability(ISO \| SEVEN_Z \| FOLDER).required_source` | `SEEKABLE` |
| ISO queried with every optional package absent | `support=FULL` **and** `required_source=SEEKABLE`: ISO needs no optional package |
| `required_source <= reader.cost.stream_capability` for a format opened successfully from that source | `True` for every format/source pair the library accepts |

#### Scenario: Speed-up packages are reported apart from missing ones

`faster_with` SHALL list the optional packages that are not installed and would only
make reading the format faster: archivey reads the same data without them. They never
change `support` and never appear in `missing`. A package is listed once, with the
policy's or the interpreter's `reason` when `config.formats` turns it off or archivey
does not use it there. A package that `config` would not use even when installed (an
accelerator set to `OFF`, or rapidgzip under `process_isolation=NONE`) is left out. The
member and payload codecs of ZIP, 7z, SquashFS, XAR, PKG, RPM, DEB and makeself count. A
format whose `support` is NONE lists none.

| Case | `faster_with` |
| --- | --- |
| `.lzo`, SquashFS without compress-utils | compress-utils (LZO1X decodes in Python) |
| `.sz` without compress-utils or cramjam, and without google-crc32c or crc32c | compress-utils and google-crc32c |
| gzip, zlib, bzip2, a TAR in one of them, ZIP or 7z without rapidgzip | rapidgzip (no parallel decoding) |
| `exclude_libraries={"rapidgzip"}` with rapidgzip installed, for gzip | rapidgzip, with the policy's reason |
| gzip with `use_rapidgzip=OFF`, or any with `process_isolation=NONE`, rapidgzip absent | empty |
| XAR, PKG, RPM, DEB or makeself without rapidgzip | rapidgzip (members or payload in gzip, zlib or bzip2) |
| xz, TAR, or every package installed | empty |

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
