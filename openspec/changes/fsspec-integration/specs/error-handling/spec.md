## MODIFIED Requirements

### Requirement: Single rooted archive exception hierarchy

The system SHALL define every library-detected archive/environment failure under
this exact `ArchiveyError` hierarchy:

```text
ArchiveyError(Exception)
├── OpenError
│   ├── FormatDetectionError
│   └── StreamNotSeekableError
├── ReadError
│   ├── CorruptionError
│   │   └── TruncatedError
│   ├── EncryptionError
│   ├── LinkTargetNotFoundError
│   └── SourceChangedError
├── ExtractionError
│   ├── FilterRejectionError
│   ├── NameCollisionError            raised only under abort_on=
│   └── NameRewrittenError            raised only under abort_on=
├── ResourceLimitError
│   └── ResourceUnavailableError
├── UnsupportedFeatureError
├── PackageNotInstalledError
└── DiagnosticRaisedError
```

Subclass boundaries SHALL keep their existing meanings:
`UnsupportedFeatureError` / `PackageNotInstalledError` may occur at open or read
time, and `StreamNotSeekableError` is an `OpenError`. `OpenError` means reading could
not start (no recognized format, a non-seekable source the format needs to seek, a
volume file that cannot be opened); a recognized archive whose header is damaged, cut
short or encrypted raises a `ReadError` subclass, from `open_archive()` as from any
later call, except a damaged method, codec or version id in a header with no checksum,
which raises `UnsupportedFeatureError` (see the error split below). `DiagnosticRaisedError` is direct
because advisory escalation can happen during detection, open, read, stream, or
extraction. `ResourceLimitError` is direct because configurable resource caps can
trip during listing materialization, extraction bomb guarding, opening a member's
codec, or copying a stream source to temporary storage; it is not an
`ExtractionError` subclass.

A type SHALL be public only when a caller would act on it differently from its parent;
anything finer goes in the message. So the checks behind `FilterRejectionError` (path
traversal, symlink escape, special file, unportable name, deceptive name) share that one
type, and a `SpoolLimits` trip is a plain `ResourceLimitError`.

`TruncatedError` SHALL be a `CorruptionError` subclass: data that ends before its
structure says it should is damaged data, and from the bytes alone a decoder often cannot
tell a cut stream from damage that decodes short. So `except CorruptionError` catches
truncation too. Which of the two is raised is a best-effort label, not a diagnosis, and
the documentation SHALL NOT tell callers to branch on it.

| Error split | Meaning |
| --- | --- |
| `UnsupportedFeatureError` | The archive uses, or its header appears to use, a recognized feature Archivey does not implement (unsupported ZIP method, unknown 7z coder, a 7z coder graph that is not a tree of chains, a raw CD sector image), or the archive or backend cannot serve a valid request (writing any format, a RAR password with a line break for `unrar`). An unknown method, codec or version id read from a header with no checksum (such as a ZIP method) may instead mean that header is damaged; Archivey cannot tell the two apart and SHALL report it as `UnsupportedFeatureError`, with a message that says a damaged header reads the same way. |
| `PackageNotInstalledError` | A package or external tool the format or member needs is absent: at open for a format whose backend or single codec is missing (ISO without `pycdlib`), at read for one member's codec. |
| `ResourceLimitError` | A configured resource limit was exceeded (`ListingLimits` materialization caps, `ExtractionLimits` bomb guards, a `DecoderLimits` cap on archive-declared decoder memory or key-derivation work, or `SpoolLimits`). |
| `SourceChangedError` | A `ReadError` subclass: the remote object an `fsspec.core.OpenFile` source names changed while archivey was reading it (a version or `ETag` mismatch, or a different total size; `fsspec-integration`). Raised at open or at any later read. It is not damage, so not a `CorruptionError`, and the caller acts differently: reopen and retry. |
| `ResourceUnavailableError` | A `ResourceLimitError` subclass: the system did not give a resource and no configured limit was exceeded. A decoder child or helper program ended by SIGKILL, a decoder that `process_isolation` runs only in a child when none can start, a PPMd child that cannot allocate its model. The caller acts differently (retry with more memory, or where processes can start), and catching `ResourceLimitError` still catches it. |

#### Scenario: archive exception matrix

| Case | Expected |
| --- | --- |
| Any open/read/extract/write failure detected by Archivey | Instance of `ArchiveyError`; `except ArchiveyError` catches it |
| Diagnostic policy escalates | `DiagnosticRaisedError` is caught by `except ArchiveyError` |
| Member name with a bidi override, extracted | `FilterRejectionError` whose message names the override; caught by `except ExtractionError` |
| Recognized archive with a damaged header, opened | `CorruptionError` or `TruncatedError` from `open_archive()`; not an `OpenError`. A method, codec or version id damaged to an unknown value in a header with no checksum is the exception (next row) |
| gzip member whose compression-method byte is damaged to 7, opened | `UnsupportedFeatureError` from `open_archive()`; its message says a damaged header reads the same way |
| Member data that ends early, read | `TruncatedError`; caught by `except CorruptionError` and by `except ReadError` |
| Remote object replaced with one of a different length mid-read | `SourceChangedError`; caught by `except ReadError`, not by `except CorruptionError` |
