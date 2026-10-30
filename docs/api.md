# API reference

This page lists archivey's public API, grouped by what you use it for. Each entry is headed by the
full name to import, such as `archivey.open_archive` or `archivey.terminal.quoted`, and each group
links to the page that explains it, where there is one.

## Opening

See [Opening an archive](opening.md).

::: archivey.open_archive
::: archivey.open_stream
::: archivey.detect_format
::: archivey.FormatInfo
::: archivey.DetectionConfidence
::: archivey.format_availability
::: archivey.FormatAvailability
::: archivey.FormatSupport
::: archivey.MissingComponent
::: archivey.OptionalLibrary
::: archivey.list_supported_formats
::: archivey.list_known_formats

## Readers and streams

See [Choosing how to read](reading.md), in particular [Reading once](reading.md#reading-once).

`open_archive` returns an `ArchiveReader` unless you pass `streaming=True`. Then its return type is
`ForwardArchiveReader`, which leaves out `members`, `get`, `read` and `open`, so a type checker
flags calls to them. The object is still an `ArchiveReader` at run time, and those calls raise
`ArchiveyUsageError`. `stream_members()` is the way to read members.

::: archivey.ForwardArchiveReader
::: archivey.ArchiveReader
::: archivey.ArchiveStream
::: archivey.Verification
::: archivey.MemberPass
::: archivey.MemberSelector
::: archivey.MemberListReport

## Members and archive details

See [Open and list](index.md#open-and-list) and [Members with the same
name](opening.md#members-with-the-same-name).

::: archivey.ArchiveMember
::: archivey.ArchiveInfo
::: archivey.HashAlgorithm

::: archivey.MemberExtra
    options:
      members:
        - __getitem__

::: archivey.ArchiveInfoExtra
    options:
      members:
        - __getitem__

## Formats and member types

See [Format](opening.md#format).

::: archivey.ArchiveFormat
::: archivey.ContainerFormat
::: archivey.PluginContainer
::: archivey.StreamFormat
::: archivey.MemberType
::: archivey.CompressionMethod
::: archivey.CompressionAlgorithm
::: archivey.CreateSystem

## Extraction

See [Extracting](extracting.md).

::: archivey.ExtractionReport
::: archivey.ExtractionResult
::: archivey.ExtractionStatus
::: archivey.NameRewrite
::: archivey.ExtractionProgress
::: archivey.ExtractionPolicy
::: archivey.OverwritePolicy
::: archivey.OnError
::: archivey.AbortOn
::: archivey.MemberFilter
::: archivey.sanitize_names

## Configuration and passwords

See [Configuration](opening.md#configuration), [Passwords](opening.md#passwords) and
[Hardening](security.md#hardening).

::: archivey.ArchiveyConfig
::: archivey.DEFAULT_ARCHIVEY_CONFIG
::: archivey.FormatPolicy
::: archivey.ExtractionLimits
::: archivey.ListingLimits
::: archivey.DecoderLimits
::: archivey.SpoolLimits
::: archivey.AcceleratorMode
::: archivey.ProcessIsolation
::: archivey.RarDecompressor
::: archivey.PasswordInput
::: archivey.PasswordRequest
::: archivey.PasswordProvider

## Diagnostics

See [Diagnostics](errors-and-diagnostics.md#diagnostics).

::: archivey.Diagnostic
::: archivey.DiagnosticContext
::: archivey.DiagnosticCode
::: archivey.DiagnosticPolicy
::: archivey.ARCHIVE_INTEGRITY_CODES
::: archivey.DiagnosticSummary
::: archivey.OnDiagnostic

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

::: archivey.OpenError
::: archivey.FormatDetectionError
::: archivey.StreamNotSeekableError

::: archivey.ReadError
::: archivey.CorruptionError
::: archivey.TruncatedError
::: archivey.EncryptionError
::: archivey.LinkTargetNotFoundError
::: archivey.LinkTargetNotFoundReason

::: archivey.ExtractionError
::: archivey.FilterRejectionError
::: archivey.NameCollisionError
::: archivey.NameRewrittenError

::: archivey.ResourceLimitError
::: archivey.ResourceUnavailableError
::: archivey.UnsupportedFeatureError
::: archivey.PackageNotInstalledError
::: archivey.DiagnosticRaisedError

::: archivey.ArchiveyUsageError

## Access cost

See [Solid archives](reading.md#solid-archives) for what these mean for your reads.

::: archivey.CostReceipt
::: archivey.ListingCost
::: archivey.AccessCost
::: archivey.StreamCapability

## Detection budgets

These live in the `archivey.detection_cost` module and are not re-exported from `archivey`. A budget
bounds what [`detect_format`][archivey.detect_format] and `open_archive` may read and decode before
they answer. You set it with `ArchiveyConfig(detection_budget=...)`, and `BALANCED_BUDGET` is the
default. The receipt on [`FormatInfo.cost_receipt`][archivey.FormatInfo] says what detection
actually did.

::: archivey.detection_cost.DetectionBudget
::: archivey.detection_cost.DetectionBudgetPreset
::: archivey.detection_cost.BALANCED_BUDGET
::: archivey.detection_cost.FAST_BUDGET
::: archivey.detection_cost.THOROUGH_BUDGET
::: archivey.detection_cost.DetectionCostReceipt
::: archivey.detection_cost.TierSkip
::: archivey.detection_cost.TierSkipReason

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
