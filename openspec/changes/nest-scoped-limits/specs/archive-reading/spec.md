## MODIFIED Requirements

### Requirement: Opening an archive for reading

The system SHALL expose:

```python
archivey.open_archive(
    source: str | Path | BinaryIO | Sequence[str | Path | BinaryIO],
    *,
    format: ArchiveFormat | None = None,
    streaming: bool = False,
    seekable_members: bool = False,
    concurrent_operations: bool = False,
    password: PasswordInput = None,
    encoding: str | None = None,
    config: ArchiveyConfig | None = None,
    parent: ForwardArchiveReader | None = None,
) -> ArchiveReader  # ForwardArchiveReader when streaming may be True; see below
```

The return type SHALL follow the access mode, through two `typing.overload`
signatures: `streaming=False` (the default, or the literal `False`) returns
`ArchiveReader`, and `streaming=True` or a `bool` whose value is not known statically
returns `ForwardArchiveReader`. `ForwardArchiveReader` is the public ABC that
declares every reader method except `members()`, `get()`, `open()` and `read()`, the
four a streaming reader refuses; `ArchiveReader` subclasses it and adds those four.
The distinction SHALL be static only: every reader returned at run time is an
`ArchiveReader` instance, and a streaming reader still raises `ArchiveyUsageError`
from the four methods.

`tests/test_public_api.py` checks each case under both type checkers the project uses (ty and Pyrefly).

`source`, multi-volume ordering, `streaming`, password candidates/providers,
encoding, configuration precedence, and backend selection retain their existing
contracts. `parent` names the open reader whose archive this one was read from; the new
reader then shares that reader's limits (see "A reader opened inside another shares its
nest's limits"). `format=None` auto-detects; an explicit format bypasses detection.

**An explicit argument the resolved backend cannot act on is handled by its
*intent*, and the rule SHALL be applied to every such argument:**

> **Refuse** when the argument is an **assertion about this archive**. **Permit, and
> record a diagnostic**, when it is a **resource offered for use if needed.**

| Argument | Intent | Behaviour when the backend cannot act on it |
| --- | --- | --- |
| `format=` | assertion — "I claim this is a ZIP" | refuse when it cannot hold (see the directory rule below) |
| `password=` | resource — a keyring | permit in **every** form; `PASSWORD_ARGUMENT_UNUSED` for a concrete value, none for a provider |
| `encoding=` | resource — a hint for name decoding | permit; `ENCODING_ARGUMENT_UNUSED` |

`password=` on a format with no encryption SHALL NOT raise, in any of its forms — a
single value, an ordered sequence, and a provider callable SHALL open identically
(accepted, never consulted). A single value or a sequence records one diagnostic; a
provider callable records none, because it offers a password only if asked. A *wrong* password on an *encrypted*
archive is unaffected and still raises. Each backend SHALL declare whether it consumes
`encoding` (`ReadBackend.USES_ENCODING`) the same way it declares
`ReadBackend.SUPPORTS_PASSWORD`, so the check is central rather than per-backend
silence.

A **directory path** resolves to `ArchiveFormat.DIRECTORY`. An explicit `format=`
naming anything else SHALL raise `ArchiveyUsageError` rather than being discarded:
silently overruling it returns a reader over the directory tree to a caller who
asserted a different format, so every read downstream succeeds on the wrong data.
`format=ArchiveFormat.DIRECTORY` and `format=None` both remain valid. The mirror
conflict, a `format=` with a `DIRECTORY` container on a stream or on a path that exists
and is not a directory, SHALL raise the same `ArchiveyUsageError`. A path the
operating system cannot stat SHALL raise the OS's own error (`FileNotFoundError`,
`NotADirectoryError`, …), the same class it raises under every other `format=`. This
is the assertion half of the rule above, not a special case.

**Diagnostics at open (observable):** On success, advisory events from automatic
detection (if any) appear in this reader's cumulative `diagnostics` for its
lifetime and are not duplicated. Explicit `format=` skips detection, so open
adds no detection diagnostics. Unused-argument diagnostics are emitted before the
reader is returned, so they are readable without listing anything. If open raises,
no reader is returned.

Handoff mechanics (one shared collector/budget, no copy/re-seed): see
`format-detection` and `diagnostics`.

#### Scenario: open matrix

- **WHEN** `open_archive` is called as each row says
- **THEN** it behaves as the row's Expected column says

| Case | Expected |
| --- | --- |
| Auto-detect succeeds | Detection events visible on `reader.diagnostics`; not duplicated |
| `format=ArchiveFormat.ZIP` succeeds | No detection diagnostics from open |
| Open raises | No reader returned |
| `password="secret"` | Returned reader uses that password for encrypted members |
| `password=` a value or a sequence, format with no encryption | Opens; `PASSWORD_ARGUMENT_UNUSED`; no raise |
| `password=` a provider callable, format with no encryption | Opens; no diagnostic; provider never called |
| `encoding=` on a backend that decodes names another way | Opens; `ENCODING_ARGUMENT_UNUSED`; names unchanged |
| Directory path, no `format=` | Opens as `DIRECTORY` |
| Directory path, `format=ArchiveFormat.DIRECTORY` | Opens as `DIRECTORY` |
| Directory path, `format=ArchiveFormat.ZIP` | `ArchiveyUsageError`, naming the path and the requested format |
| File path or stream, `format=ArchiveFormat.DIRECTORY` or an unnamed pair such as `(DIRECTORY, GZIP)` | `ArchiveyUsageError`, naming the source and the requested format |
| Path that does not exist, `format=ArchiveFormat.DIRECTORY` | `FileNotFoundError`, as under `format=ArchiveFormat.ZIP` or `None`; not `ArchiveyUsageError` |
| Path under a file (`a.txt/sub`), `format=ArchiveFormat.DIRECTORY` | The OS's own error, the class it raises under `format=ArchiveFormat.ZIP` or `None` (`NotADirectoryError` on POSIX, `FileNotFoundError` on Windows) |

## ADDED Requirements

### Requirement: A reader opened inside another joins its nest

A nest SHALL be an archive's reader and every reader opened inside it: by
`ReaderContext.open_nested`, or by `open_archive(..., parent=reader)` at any depth.
With `parent=` and no `config`, the reader SHALL use its parent's config. `parent` SHALL
be an open archivey reader, else `ArchiveyUsageError`. A nest deeper than 8 levels, both
kinds counted, SHALL raise `UnsupportedFeatureError`. Closing a parent SHALL NOT close
the readers opened inside it.

#### Scenario: joining a nest

- **WHEN** a reader is opened as each row says
- **THEN** it joins the nest, or is refused, as the row's Expected column says

| Case | Expected |
| --- | --- |
| `parent=outer`, no `config` | Uses `outer`'s config; in `outer`'s nest |
| `parent=` with a `config` whose `diagnostic_policy` differs | Its own policy; the nest's limits |
| `parent=` a closed reader, or an object that is not a reader | `ArchiveyUsageError` |
| Nine levels opened with `parent=` | The ninth raises `UnsupportedFeatureError` |
| Outer closed after the inner opened | The inner keeps reading and counting against the nest |

### Requirement: Limits apply per nest

The config's limits SHALL apply per nest, taken from the outermost reader's config.
`max_decoder_memory` and `max_metadata_bytes` SHALL be shared by the levels open at once
(an inner level gets what they left and gives its charge back when it closes).
`max_ratio` SHALL be measured against the outermost archive's compressed bytes.
`max_members`, `max_key_derivation_rounds`, `SpoolLimits.max_bytes` and
`max_total_decoded_bytes` SHALL be summed over every level, closed ones included; a
member `open_nested` yields SHALL count once. `ListingLimits.max_decoded_bytes`,
`max_ppmd_held_input` and `ExtractionLimits` SHALL stay per pass, decoder and call.

#### Scenario: nest limit matrix

- **WHEN** an inner archive is read as each row says
- **THEN** the nest's limits hold as the row's Expected column says

| Case | Expected |
| --- | --- |
| Outer ZIP of 1 KiB holding an inner ZIP, `max_ratio=800`; inner opened with `parent=outer` from a temporary-file copy | Each level is held to 800 times the outer archive's 1 KiB, not to 800 times the inner archive's size |
| `ListingLimits(max_members=5)`, outer of 3 members, inner opened with `parent=` holding 3 | The inner listing raises `ResourceLimitError` naming `max_members=5` |
| The same, inner opened without `parent=` | Lists all 3: a separate nest |
| A reader opened with `parent=` inside one `open_nested` built | Both share the nest's limits |
| `ExtractionLimits(max_extracted_bytes=N)`, outer and inner each extracted | Each `extract_all` call is held to N on its own |
