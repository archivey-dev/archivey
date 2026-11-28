# API reference

This page lists archivey's public API, grouped by what you use it for. Each entry is headed by the
full name to import, such as `archivey.open_archive` or `archivey.terminal.quoted`, and each group
links to the page that explains it, where there is one.

The most used names come straight from `archivey`: `open_archive`, the reader, member, format
and policy types, and the errors you are most likely to catch. Every other name comes from its
submodule, such as `from archivey.config import DecoderLimits`. Until 0.6.0 those names came
from `archivey` too; that spelling still works in the 0.6 releases, with a `DeprecationWarning`
that names the new import.

## Opening

See [Opening an archive](opening.md).

::: archivey.open_archive
::: archivey.open_stream
::: archivey.detect_format
::: archivey.detection.FormatInfo
::: archivey.detection.DetectionConfidence
::: archivey.format_availability
::: archivey.types.FormatAvailability
::: archivey.types.FormatSupport
::: archivey.types.MissingComponent
::: archivey.types.OptionalLibrary
::: archivey.types.BackendUse
::: archivey.types.BackendKindStr
::: archivey.core.list_supported_formats
::: archivey.core.list_known_formats

## Readers and streams

See [Choosing how to read](reading.md), in particular [Reading once](reading.md#reading-once).

`open_archive` returns an `ArchiveReader` unless you pass `streaming=True` or `pipe=True`. Then its
return type is `ForwardArchiveReader`, which leaves out `members`, `get`, `read` and `open`, so a
type checker flags calls to them. The object is still an `ArchiveReader` at run time, and those
calls raise `ArchiveyUsageError`. `stream_members()` is the way to read members.

::: archivey.ForwardArchiveReader
::: archivey.ArchiveReader
::: archivey.ArchiveStream
::: archivey.types.Verification
::: archivey.diagnostics.VerifyReport
::: archivey.reader.MemberPass
::: archivey.reader.MemberSelector
::: archivey.diagnostics.MemberListReport

## Members and archive details

See [Open and list](index.md#open-and-list) and [Members with the same
name](opening.md#members-with-the-same-name).

::: archivey.ArchiveMember
::: archivey.ArchiveInfo
::: archivey.types.HashAlgorithm

::: archivey.types.MemberExtra
    options:
      members:
        - __getitem__

::: archivey.types.ArchiveInfoExtra
    options:
      members:
        - __getitem__

## Formats and member types

See [Format](opening.md#format).

::: archivey.ArchiveFormat
::: archivey.ContainerFormat
::: archivey.types.PluginContainer
::: archivey.StreamFormat
::: archivey.types.PluginStream
::: archivey.MemberType
::: archivey.types.CompressionMethod
::: archivey.types.CompressionAlgorithm
::: archivey.types.CreateSystem

## Extraction

See [Extracting](extracting.md).

::: archivey.ExtractionReport
::: archivey.types.ExtractionResult
::: archivey.types.ExtractionStatus
::: archivey.types.NameRewrite
::: archivey.types.ExtractionProgress
::: archivey.ExtractionPolicy
::: archivey.types.OverwritePolicy
::: archivey.OnProblem
::: archivey.types.MemberFilter
::: archivey.paths.sanitize_names

## Configuration and passwords

See [Configuration](opening.md#configuration), [Passwords](opening.md#passwords) and
[Hardening](security.md#hardening).

::: archivey.ArchiveyConfig
::: archivey.config.DEFAULT_ARCHIVEY_CONFIG
::: archivey.types.SourceProgress
::: archivey.types.OnSourceRead
::: archivey.FormatPolicy
::: archivey.config.ExtractionLimits
::: archivey.config.ListingLimits
::: archivey.config.DecoderLimits
::: archivey.config.SpoolLimits
::: archivey.config.SalvageLimits
::: archivey.config.AcceleratorMode
::: archivey.config.ProcessIsolation
::: archivey.config.RarDecompressor
::: archivey.config.PartialDataRecovery
::: archivey.config.PasswordInput
::: archivey.config.PasswordRequest
::: archivey.config.PasswordProvider

## Diagnostics

See [Diagnostics](errors-and-diagnostics.md#diagnostics).

::: archivey.Diagnostic
::: archivey.diagnostics.DiagnosticContext
::: archivey.DiagnosticCode
::: archivey.DiagnosticPolicy
::: archivey.diagnostics.ARCHIVE_INTEGRITY_CODES
::: archivey.diagnostics.DiagnosticSummary
::: archivey.diagnostics.OnDiagnostic

## Errors

archivey's exceptions have two roots. `ArchiveyError` covers problems with the archive
or its environment. `ArchiveyUsageError` covers mistakes in the calling code and is
deliberately outside that tree, so `except ArchiveyError` does not hide them. The
entries below follow the class tree: each group starts with its base class, except the
group from `ResourceLimitError` to `DiagnosticRaisedError`. Those four are direct
subclasses of `ArchiveyError` and unrelated to each other, and only `ResourceLimitError`
has a subclass, `ResourceUnavailableError`, listed after it.
[Errors and diagnostics](errors-and-diagnostics.md) explains which one to catch.

::: archivey.ArchiveyError

::: archivey.exceptions.OpenError
::: archivey.FormatDetectionError
::: archivey.exceptions.StreamNotSeekableError

::: archivey.exceptions.ReadError
::: archivey.CorruptionError
::: archivey.TruncatedError
::: archivey.EncryptionError
::: archivey.exceptions.LinkTargetNotFoundError
::: archivey.exceptions.LinkTargetNotFoundReason
::: archivey.exceptions.SourceChangedError

::: archivey.exceptions.ExtractionError
::: archivey.exceptions.FilterRejectionError
::: archivey.exceptions.NameCollisionError
::: archivey.exceptions.NameRewrittenError

::: archivey.ResourceLimitError
::: archivey.exceptions.ResourceUnavailableError
::: archivey.UnsupportedFeatureError
::: archivey.PackageNotInstalledError
::: archivey.exceptions.DiagnosticRaisedError

::: archivey.ArchiveyUsageError

## Access cost

See [Solid archives](reading.md#solid-archives) for what these mean for your reads.

::: archivey.cost.CostReceipt
::: archivey.cost.ListingCost
::: archivey.cost.AccessCost
::: archivey.cost.StreamCapability

## Detection budgets

These live in the `archivey.detection_cost` module and are not re-exported from `archivey`. A budget
bounds what [`detect_format`][archivey.detect_format] and `open_archive` may read and decode before
they answer. You set it with `ArchiveyConfig(detection_budget=...)`, and `BALANCED_BUDGET` is the
default. The receipt on [`FormatInfo.cost_receipt`][archivey.detection.FormatInfo] says what
detection actually did.

::: archivey.detection_cost.DetectionBudget
::: archivey.detection_cost.DetectionBudgetPreset
::: archivey.detection_cost.BALANCED_BUDGET
::: archivey.detection_cost.FAST_BUDGET
::: archivey.detection_cost.THOROUGH_BUDGET
::: archivey.detection_cost.DetectionCostReceipt
::: archivey.detection_cost.TierSkip
::: archivey.detection_cost.TierSkipReason

## fsspec file system

`ArchiveyFileSystem` lives in the `archivey.fsspec` module, the only archivey module that
imports [fsspec](https://filesystem-spec.readthedocs.io/). fsspec finds it as the `archivey`
protocol without an import, so `pandas.read_csv("archivey://t.csv::s3://bucket/a.7z")` works
once archivey is installed.

::: archivey.fsspec.ArchiveyFileSystem
    options:
      members: [reader, close]

## Display and naming helpers

These live in the `archivey.terminal` and `archivey.paths` modules and are not
re-exported from `archivey`. archivey's own command-line tool is built on them.

The `archivey.terminal` helpers are for showing archive-derived text, such as member
names, to a person without letting it control the terminal ([Names in other
encodings](opening.md#names-in-other-encodings)).

::: archivey.terminal.escape_control_chars
::: archivey.terminal.display_path
::: archivey.terminal.quoted

`archivey.paths` holds the naming rules extraction applies to destination paths, for a
front end that moves or renames what extraction wrote and wants the names a direct
extraction would have chosen.

::: archivey.paths.numbered_name

It also holds two functions that turn patterns into a `members=` argument, for
selecting by pattern where `members=` itself matches names exactly. They read the same
pattern differently: `match_glob` keeps `*` inside one folder, as archivey's CLI does,
and `match_tar_glob` follows `tar`, where `*` also matches `/` ([Extracting all or some
members](extracting.md#extracting-all-or-some-members)).

::: archivey.paths.match_glob
::: archivey.paths.match_tar_glob
