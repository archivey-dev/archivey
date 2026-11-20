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
│   └── LinkTargetNotFoundError
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

Subclass boundaries SHALL keep their existing meanings: `UnsupportedFeatureError` /
`PackageNotInstalledError` may occur at open or read time, and `StreamNotSeekableError`
is an `OpenError`. `OpenError` means reading could not start (no recognized format, a
non-seekable source the format needs to seek, a volume that is not a regular file); a
recognized archive whose header is damaged, cut short or encrypted raises a `ReadError`
subclass, from `open_archive()` as from any later call, except a damaged method, codec
or version id in a header with no checksum, which raises `UnsupportedFeatureError` (see
the error split below). `DiagnosticRaisedError` is direct because advisory escalation
can happen during detection, open, read, stream, or extraction. `ResourceLimitError` is
direct because configurable resource caps can trip during listing materialization,
extraction bomb guarding, opening a member's codec, or copying a stream source to
temporary storage, and its `ResourceUnavailableError` can come from opening a volume; it
is not an `ExtractionError` subclass.

A type SHALL be public only when a caller would act on it differently from its parent;
anything finer goes in the message. So the checks behind `FilterRejectionError` (path
traversal, symlink escape, special file, unportable name, deceptive name) share that one
type, and a `SpoolLimits` trip is a plain `ResourceLimitError`.

`TruncatedError` SHALL be a `CorruptionError` subclass: data that ends before its
structure says it should is damaged data, and from the bytes alone a decoder often
cannot tell a cut stream from damage that decodes short. So `except CorruptionError`
catches truncation too. Which of the two is raised is a best-effort label, not a
diagnosis. The documentation SHALL present `TruncatedError` as that: a hint that the
source was most likely cut short, such as an interrupted download that fetching again or
resuming may complete, and SHALL tell callers to catch `CorruptionError` to handle both.

| Error split | Meaning |
| --- | --- |
| `UnsupportedFeatureError` | The archive uses, or its header appears to use, a recognized feature Archivey does not implement (unsupported ZIP method, unknown 7z coder, a 7z coder graph that is not a tree of chains, a raw CD sector image), or the archive or backend cannot serve a valid request (writing any format, a RAR password with a line break for `unrar`). An unknown method, codec or version id read from a header with no checksum (such as a ZIP method) may instead mean that header is damaged; Archivey cannot tell the two apart and SHALL report it as `UnsupportedFeatureError`, with a message that says a damaged header reads the same way. |
| `PackageNotInstalledError` | A package or external tool the format or member needs is absent: at open for a format whose backend or single codec is missing (`.lz4` without `lz4`), at read for one member's codec. |
| `ResourceLimitError` | A configured resource limit was exceeded (`ListingLimits` materialization caps, `ExtractionLimits` bomb guards, a `DecoderLimits` cap on archive-declared decoder memory or key-derivation work, or `SpoolLimits`). |
| `ResourceUnavailableError` | A `ResourceLimitError` subclass: the system did not give a resource and no configured limit was exceeded. A decoder child or helper program ended by SIGKILL, a decoder that `process_isolation` runs only in a child when none can start, a PPMd child that cannot allocate its model, a volume file that cannot be opened because the process is out of file descriptors (`EMFILE` / `ENFILE`, the `OSError` as its cause). The caller acts differently (retry with more memory or file descriptors, or where processes can start), and catching `ResourceLimitError` still catches it. |

#### Scenario: archive exception matrix

| Case | Expected |
| --- | --- |
| Any open/read/extract/write failure detected by Archivey | Instance of `ArchiveyError`; `except ArchiveyError` catches it |
| Diagnostic policy escalates | `DiagnosticRaisedError` is caught by `except ArchiveyError` |
| Member name with a bidi override, extracted | `FilterRejectionError` whose message names the override; caught by `except ExtractionError` |
| Recognized archive with a damaged header, opened | `CorruptionError` or `TruncatedError` from `open_archive()`; not an `OpenError`. A method, codec or version id damaged to an unknown value in a header with no checksum is the exception (next row) |
| gzip member whose compression-method byte is damaged to 7, opened | `UnsupportedFeatureError` from `open_archive()`; its message says a damaged header reads the same way |
| Member data that ends early, read | `TruncatedError`; caught by `except CorruptionError` and by `except ReadError` |

### Requirement: Original cause and traceback are preserved centrally

The system SHALL preserve original decoding-library exceptions as `__cause__`
using `raise ... from exc`; libraries MUST NOT swallow the original traceback.
Type translation is per underlying library (for example `zlib`, `lzma`,
`unrar`, crypto backend), not per format. The `ArchiveReader` base class
SHALL centrally stamp `source_format`, `archive_name`, and `member_name` on
propagating `ArchiveyError`s; backends do not hand-fill those fields.

No internal library exception SHALL escape unwrapped when it originates from a
decoding library taxonomy. A backend that serves raw bytes through no decoding
library (directory backend, stored member stream) SHALL NOT wrap plain `OSError`;
there is no codec taxonomy to translate.

#### Scenario: translation matrix

| Case | Expected |
| --- | --- |
| `zlib.error` from a damaged DEFLATE member is wrapped as `CorruptionError` | `__cause__` is the original `zlib.error` |
| `traceback.print_exc()` after catching `ArchiveyError` | Chained output includes original exception and traceback |
| Decoder raises an unexpected taxonomy exception | Re-raised as an `ArchiveyError` subclass with `raise ... from exc` |
| Context-free translator raises while reading 7z member `"data/file.txt"` from `"/tmp/a.7z"` | Base reader stamps `SEVEN_Z`, archive name, and member name |
