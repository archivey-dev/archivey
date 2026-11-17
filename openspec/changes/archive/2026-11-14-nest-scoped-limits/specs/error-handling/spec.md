## MODIFIED Requirements

### Requirement: Object-typed public arguments are refused at the boundary

Every public entry point SHALL raise `ArchiveyUsageError` — outside `ArchiveyError`,
per the misuse requirement above, and also a `TypeError` (a `ValueError` for a refused
value of a usable type) — when a non-enum argument is of a type it cannot use, and SHALL
do so at the call the caller wrote rather than wherever the value is eventually read.

Enum-typed parameters are **out of scope of this requirement**, and this requirement
says nothing about how they behave. It covers the arguments listed below and no
others.

The refusal is what makes the boundary observable. Deferred to its point of use, a
wrong-typed argument surfaces as an `AttributeError`, a `TypeError`, or a `LookupError`
from library internals, naming a private attribute of ours (`'str' object has no
attribute 'max_extracted_bytes'`) and never naming the argument. Such a message both
leaks an internal field name and fails to say what the caller did wrong, which is the
no-internal-leakage rule.

The arguments covered:

| Entry point | Arguments |
| --- | --- |
| `open_archive()`, `open_stream()`, `detect_format()` | `config` |
| `open_archive()`, `open_stream()`, `detect_format()` | `source` |
| `open_archive()` | `encoding`, `password`, `parent` (an archivey reader) |
| `ArchiveReader.extract_all()` | `dest`, `limits`, `on_progress` |
| `ArchiveReader.extract_all()`, `ArchiveReader.stream_members()` | `members` |
| `ArchiveReader.extract_all()` | `filter` |
| `ArchiveReader.open()` / `.read()` | `member` |
| `ArchiveyConfig(...)` | `extraction_limits`, `listing_limits`, `diagnostic_policy`, `on_diagnostic`, `zip_unflagged_fallback_encoding`, `max_retained_diagnostic_references`, `detection_budget` (a `DetectionBudget`; a `DetectionBudgetPreset` or its spelling is converted, see below) |
| `ExtractionLimits(...)`, `ListingLimits(...)` | every guard field |
| `DetectionBudget(...)` | every field |

`ArchiveyConfig`, the `*Limits` types and `DetectionBudget` SHALL validate their own
fields at construction, through one shared field check. Validating `config=` at an entry
point does not reach them: the object passed there is of the right type and the wrong
one is a field in, and a limit is a promise about an operation that has not begun, so
construction is the last place a message can still name what the caller wrote.

A value that silently disables a guard SHALL be refused on the same footing as a wrong
type: `None` on a field that is not optional, and a NaN or an infinity on a float
field, since nothing exceeds an infinity and every comparison against a NaN is false.
`None` remains the way to disable a guard deliberately, on the fields that allow it.

An `encoding` SHALL be refused unless it names a codec that can decode bytes to text,
so that a byte-to-byte transform (`"rot13"`, `"base64"`) is refused where it is written
rather than several frames into a member-name decode.

The raw exceptions the contract already permits SHALL continue to escape unchanged:
`KeyError` for an unknown member **name**, `TypeError` for `len()` / `in`,
`io.UnsupportedOperation` for an unsupported `seek`,
`ValueError` for I/O on a closed stream, and `OSError`. Boolean flags read for their
truthiness are not covered, there being no wrong type to find, except
`ArchiveyConfig`'s guard switches (`rar_allow_glob_member_concatenation`,
`read_link_targets`), which SHALL be a `bool`: a string such as `"false"` is truthy
and would silently switch the guard.

An empty string passed as a path SHALL raise an `ArchiveyUsageError` that is also a
`ValueError` at the entry point, before anything is read or created. This covers the
`source` of `open_archive()` (alone or as an item of a volume list), `open_stream()` and
`detect_format()`, and the `dest` of `ArchiveReader.extract_all()`. `Path("")` is
`Path(".")`, so an empty string, typically an unset environment variable, would
otherwise open the current directory as a directory archive or extract into it.

#### Scenario: object argument refusal matrix

- **WHEN** a call is made as each row says
- **THEN** it behaves as the row's Expected column says

| Case | Expected |
| --- | --- |
| `open_archive(src, config="strict")` | `ArchiveyUsageError` naming `config`; never `AttributeError: 'str' object has no attribute 'diagnostic_policy'` |
| `ArchiveyConfig(extraction_limits="none")` then `extract_all(...)` | `ArchiveyUsageError` at construction, not `AttributeError` part-way through the extraction |
| `ArchiveyConfig(listing_limits="x")` then listing | `ArchiveyUsageError` at construction, not `AttributeError` mid-listing |
| `ArchiveyConfig(max_retained_diagnostic_references="x")` | `ArchiveyUsageError` at construction |
| `ArchiveyConfig(on_diagnostic=0)` | `ArchiveyUsageError` at construction, not when the first diagnostic fires |
| `ArchiveyConfig(rar_allow_glob_member_concatenation="false")` | `ArchiveyUsageError` at construction; the refusal is never switched off by a truthy string |
| `ListingLimits(max_members="x")` | `ArchiveyUsageError` at construction, not `TypeError` mid-listing |
| `DecoderLimits(max_ratio=float("nan"))` | `ArchiveyUsageError`; a NaN would leave the ratio guard switched off silently |
| `DecoderLimits(ratio_activation_threshold=None)` or `DecoderLimits(live_ratio_activation_threshold=None)` | `ArchiveyUsageError`; the field is not optional and `None` disables nothing |
| `ExtractionLimits(max_extracted_bytes=True)` | `ArchiveyUsageError`; `bool` is an `int` subclass and would cap at one byte |
| `DetectionBudget(..., max_far_bytes=None)` or a negative or `float` field | `ArchiveyUsageError` at construction naming the field; not a `TypeError` or `ValueError` mid-detection, and not a tier silently switched off |
| `open_archive(src, encoding="rot13")` | `ArchiveyUsageError` naming the argument; not a `LookupError` during a member-name decode |
| `open_archive(src, encoding=0)` | `ArchiveyUsageError`; not silently ignored |
| `open_archive(src, parent=10)` | `ArchiveyUsageError` naming `parent=`, also a `TypeError` |
| `extract_all(dest, on_progress=0)` | `ArchiveyUsageError` before any output is written |
| `extract_all(dest, filter=0)` | `ArchiveyUsageError` before the first member is offered |
| `extract_all(dest, members="notes.txt")` | `ArchiveyUsageError` naming the list spelling; not a clean extraction of nothing |
| `extract_all(dest, members=0)` | `ArchiveyUsageError` at the call, before `dest` is created |
| `stream_members(members=0)` | `ArchiveyUsageError` at the call, not on first `next()` |
| `ArchiveyConfig(detection_budget=0)` | `ArchiveyUsageError` naming `detection_budget`; never `AttributeError: 'int' object has no attribute 'max_prefix_bytes'` |
| `reader.open(0)` | `ArchiveyUsageError`; never a message naming `_archive_id` |
| `reader.get(b"a.txt")`, `reader.get(member)` | `ArchiveyUsageError`; never `None` for a member that exists. `reader.open(b"a.txt")` is refused the same way; `reader.open(member)` reads the member |
| `reader.open("absent.txt")` | `KeyError` — unchanged, and specified by `archive-reading` |
| `open_archive(0)` | `ArchiveyUsageError` that is also a `TypeError`: `unsupported source type` |
| `extract_all(0)` | `ArchiveyUsageError` that is also a `TypeError`, naming `dest`; never `expected str, bytes or os.PathLike object` |
| `ListingLimits(max_members=-1)` | `ArchiveyUsageError` that is also a `ValueError` |
| `open_archive("")`, `open_archive(["", ...])`, `detect_format("")`, `open_stream("")` | `ArchiveyUsageError` that is also a `ValueError`, naming the empty path; the current directory is not read |
| `extract_all("")` | `ArchiveyUsageError` that is also a `ValueError`, before anything is written; nothing is extracted into the current directory |
