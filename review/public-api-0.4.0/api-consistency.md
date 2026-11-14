# Public API consistency findings

Reviewed `main` at
[`733a1b63577915f3796267c35f88af5266c21d8a`](https://github.com/archivey-dev/archivey/commit/733a1b63577915f3796267c35f88af5266c21d8a).
Findings are ranked by user impact. Runtime claims were checked with small Python
probes. The full suite and optional accelerators were not run.

“Non-breaking” includes corrections to behavior that violates an existing
documented contract. Migration-sensitive behavior is called out separately.
Observed behavior, inferred defects, and proposed design changes are distinct.

## F1. Equivalent decompression calls apply different ratio protection

**Status (2026-11-14):** Fixed in #1553 (0.4.0). DR-9's 2026-10-30 ruling settles it: `max_ratio` holds every decode, and the ruling names the unguarded bare `.bz2` spelling as its reason. `open_stream()` is that spelling, and the threat model records no exception for it. Not a question for the maintainer.

**Compatibility: breaking to fix. Confidence: behavior confirmed; intent unclear.**

**Both sides:** [`src/archivey/config.py:635`][f1-config] defines
`max_ratio=800.0` and describes protection for “Every decode of member data.”
[`src/archivey/core.py:1305`][f1-core], however, documents `open_stream()`'s
limits only in terms of decoder memory.

**Observed:** With identical gzip bytes and config,
`open_archive(...).read(member)` raises `ResourceLimitError`, while
`open_stream(...).read()` returns all 6 MiB. This happens with both the default
ratio and an explicit `max_ratio=2`.

**Why it matters:** Switching to the simpler single-stream API silently removes
a protection carried by the same configuration object.

**Proposed change:** Enforce the same ratio and activation-threshold rules in
`open_stream()`, including unknown-size sources. This newly rejects some
previously successful reads. Treating the omission as an API defect is an
inference: the ratio documentation enumerates reader methods without explicitly
naming `open_stream()`.

Runnable reproduction:

```python
import gzip
import io
import archivey

packed = gzip.compress(b"0" * (6 * 1024 * 1024))
config = archivey.ArchiveyConfig(
    decoder_limits=archivey.DecoderLimits(
        max_ratio=2,
        ratio_activation_threshold=1024,
        live_ratio_activation_threshold=1024,
    ),
)
try:
    with archivey.open_archive(io.BytesIO(packed), config=config) as reader:
        reader.read(reader.members()[0])
except archivey.ResourceLimitError:
    print("archive: ratio refused")
with archivey.open_stream(io.BytesIO(packed), config=config) as stream:
    print("stream:", len(stream.read()))  # 6291456
```

## F2. FormatPolicy discards library policies supplied as generators

**Status (2026-11-14):** Fixed in #1554 (0.4.0): the iterable is read once.

**Compatibility: non-breaking contract correction. Confidence: confirmed bug.**

**Both sides:** [`src/archivey/format_policy.py:467`][f2-signature] accepts
`Iterable[...]` for both `exclude_libraries` and `only_libraries`. But
[`src/archivey/format_policy.py:152`][f2-consume] first consumes that iterable
with `sorted(v for v in values ...)`, then passes the exhausted iterator to
conversion at line 163.

**Observed:** `exclude_libraries=iter(["brotli"])` produces an empty exclusion
set; the equivalent list excludes Brotli. An iterator containing `"TYPO"` is
silently accepted, whereas a list raises. `only_libraries` generators become empty
allowlists.

**Why it matters:** An advertised input shape can silently enable code the caller
explicitly excluded. With an allowlist it instead disables intended dependencies.

**Proposed change:** Materialize the iterable once and use that materialization
for validation and conversion.

```python
from archivey import FormatPolicy

print(FormatPolicy(exclude_libraries=["brotli"]).exclude_libraries)
# frozenset({OptionalLibrary.BROTLI})
print(FormatPolicy(exclude_libraries=iter(["brotli"])).exclude_libraries)
# frozenset()
print(FormatPolicy(only_libraries=iter(["brotli"])).only_libraries)
# frozenset()
```

## F3. Report truth tests have incompatible meanings

**Status (2026-11-14):** Maintainer decision, pending. Recommendation: make `bool()` raise on `ExtractionReport` and `MemberListReport` as it does on `VerifyReport`, and give `MemberListReport` `ok` and `raise_for_failure()`. Breaking, so before 0.4.0.

**Compatibility: breaking to fix. Confidence: confirmed behavior; design recommendation.**

**Both sides:** [`src/archivey/diagnostics.py:1782`][f3-extraction] and
[`src/archivey/diagnostics.py:1841`][f3-listing] give extraction/listing reports
length-based truthiness. [`src/archivey/diagnostics.py:1884`][f3-verify] makes
`bool(VerifyReport)` raise: “test VerifyReport.ok”.

**Observed:** A successful empty extraction report is false; a nonempty failed
extraction report is true. Verification reports reject either interpretation.

**Why it matters:** Similar outcome objects invite similar conditionals, but an
innocent `if report:` can conceal failure.

**Proposed change:** Make all report truth tests raise and require explicit
success/completeness checks. Add `MemberListReport.ok` and `raise_for_failure()`
alongside the extraction/verification equivalents. This is a design recommendation,
not an implementation bug: the sequence behavior is documented.

## F4. Boolean validation differs between configuration and operation arguments

**Status (2026-11-14):** Fixed in #1554 (0.4.0). The fix reverses the error-handling spec's sentence that exempted truthiness flags, and the matching test exemptions. DR-15 and the config switches' guard support it. The maintainer merges the PR.

**Compatibility: non-breaking invalid-input rejection. Confidence: confirmed for the opening flags.**

**Both sides:** [`src/archivey/config.py:1109`][f4-config] explicitly rejects
non-booleans because `"false"` is truthy. [`src/archivey/core.py:593`][f4-core]
and line 604 instead apply ordinary truth tests to the public flags.

**Observed:** `streaming="false"` enables streaming;
`seekable_members="false"` enables seeking;
`concurrent_operations="false"` is accepted.

**Why it matters:** Configuration loaded from text can silently change access
mode or concurrency instead of producing the promised argument error.

**Proposed change:** Require actual `bool` values at public entry points,
consistently covering `streaming`, `seekable_members`, `concurrent_operations`,
`seekable`, `dry_run`, and `password_only`. Reject invalid types before I/O.
The last three are part of the proposed consistency sweep; the runtime probe
specifically confirmed the three `open_archive()` flags above.

## F5. The policy reference overstates protection against external symlinks

**Status (2026-11-14):** Fixed in #1556 (docs).

**Compatibility: non-breaking documentation correction. Confidence: confirmed.**

**Both sides:** [`src/archivey/types.py:1895`][f5-type] says checks holding
under “every policy” include “a name or link that leads outside the destination.”
[`docs/extracting.md:193`][f5-doc] says `trusted` writes an absolute symlink
target as stored.

**Observed:** A TAR symlink to `/etc/passwd` extracts successfully under
`policy="trusted"` and reports `ok=True`.

**Why it matters:** A user reading the enum reference can reasonably believe
that external links themselves are always refused.

**Proposed change:** State the distinction precisely: member destinations cannot
escape, and extraction cannot write through links leading outside; `TRUSTED` may
nevertheless create absolute symlinks pointing outside. The prose page already
makes this distinction. This finding does not claim an extraction write escaped
the destination.

## F6. Some invalid config combinations escape the ValueError contract

**Status (2026-11-14):** Fixed in #1554 (0.4.0): both conflicts raise the usage error that is also a `ValueError` (DR-15).

**Compatibility: non-breaking. Confidence: confirmed.**

**Both sides:** [`src/archivey/exceptions.py:464`][f6-contract] says unusable
argument values raise an `ArchiveyUsageError` that is also a `ValueError`.
[`src/archivey/config.py:1224`][f6-raise] and line 1230 raise plain
`ArchiveyUsageError` for contradictory accelerator settings.

**Observed:** `ArchiveyConfig(use_rapidgzip=AcceleratorMode.ON,
process_isolation=ProcessIsolation.NONE)` raises an exception for which
`isinstance(error, ValueError)` is false.

**Why it matters:** An ordinary configuration-validation handler misses these
failures while catching negative limits and unknown enum values.

**Proposed change:** Use the same usage/value-error subclass used for other
invalid argument combinations. Existing `ArchiveyUsageError` handlers continue
to work.

## F7. Documented string construction conflicts with constructor types

**Status (2026-11-14):** Maintainer decision, pending. Recommendation: keep the enum-only field annotations (`config.py`'s `_convert_enum_fields` docstring and `tests/test_enum_arguments.py` record that choice), and change the docstring examples to the enum spelling.

**Compatibility: non-breaking. Confidence: intentional discrepancy; design recommendation.**

**Both sides:** [`src/archivey/config.py:844`][f7-config] documents
`process_isolation` as accepting `"known_crashes"`, `"native_decoders"`, and
`"none"`, but annotates it only as `ProcessIsolation`.
[`src/archivey/types.py:235`][f7-format] explicitly demonstrates
`ArchiveFormat("raw_stream", "gz")`, while its fields accept only enum types.

In contrast, [`src/archivey/diagnostics.py:1701`][f7-policy] gives
`DiagnosticPolicy` a constructor accepting enum/string inputs while keeping
normalized fields precisely typed.

**Why it matters:** Typed users cannot consistently use documented construction
examples without suppressions.

**Proposed change:** Give `ArchiveyConfig` and `ArchiveFormat` constructors input
annotations/overloads accepting their supported strings and presets, while
retaining normalized field annotations. This discrepancy is intentional, as
[`src/archivey/config.py:1161`][f7-intent] explains; reconsidering that choice
is a consistency recommendation, not a claim that the conversion is broken.
No type checker was executed for this finding.

## F8. The documented list of formats readable from pipes is stale

**Status (2026-11-14):** Fixed in #1556 (docs): the docstrings point at `required_source`, and the user pages list every forward-only format.

**Compatibility: non-breaking documentation correction. Confidence: confirmed.**

**Both sides:** [`src/archivey/core.py:548`][f8-core] says every format
except “TAR, ZIP and the single-file compressed streams” needs seeking.
[`src/archivey/types.py:104`][f8-type] documents RPM as readable “from a pipe
too”; the same applies to ar, CPIO, deb, and makeself.

**Observed:** Public `format_availability(...).required_source` reports
`FORWARD_ONLY` for all five omitted containers.

**Why it matters:** Users may unnecessarily spool archives to disk, reject
supported inputs, or provision temporary-storage limits.

**Proposed change:** Correct `open_archive()`'s exception documentation and
`stream_members()`'s nested-source restriction text. Prefer directing users to
`required_source` over repeating exhaustive format lists.

## F9. open_stream(seekable=False) incorrectly promises no accelerator

**Status (2026-11-14):** Fixed in #1556 (docs).

**Compatibility: non-breaking documentation correction. Confidence: confirmed contradiction.**

**Both sides:** [`src/archivey/core.py:1274`][f9-core] says “no seek index or
accelerator is instantiated.” [`src/archivey/config.py:812`][f9-config]
allows `AUTO` acceleration without seeking for qualifying sequential reads.

**Observed:** With default `seekable=False` and `use_rapidgzip=ON`, reading
attempts accelerator selection and raises `PackageNotInstalledError` when
rapidgzip is absent. The probe did not install or execute the optional accelerator.

**Why it matters:** Forward-only operation does not imply the promised absence
of optional packages, accelerator processes, or their costs.

**Proposed change:** Document seeking capability separately from decoder
selection. Explain that sequential acceleration can still occur, and point to
`AcceleratorMode.OFF` when callers require it disabled.

## F10. Several public annotations cannot be resolved at runtime

**Status (2026-11-14):** Fixed in #1555: every public annotation resolves; `tests/test_public_annotations.py` keeps it so.

**Compatibility: non-breaking. Confidence: confirmed.**

**Both sides:** [`src/archivey/format_policy.py:467`][f10-use] uses
`OptionalLibraryStr` in its constructor, but
[`src/archivey/format_policy.py:32`][f10-import] imports that alias only under
`TYPE_CHECKING`. [`src/archivey/exceptions.py:40`][f10-exceptions] similarly
hides types referenced by public exception constructors.

**Observed:** `typing.get_type_hints(FormatPolicy.__init__)` and several
exception constructors raise `NameError`. So do
`get_type_hints(ArchiveMember.diagnostics.fget)` and
`get_type_hints(archivey.detect_format)`.

**Why it matters:** Documentation generators and integrations that inspect
public signatures cannot reliably consume the annotations.

**Proposed change:** Ensure every public annotation resolves after package
initialization. Import noncyclic aliases at runtime and bind cyclic public types
once their modules finish loading.

## F11. Report slicing works but is typed as integer indexing only

**Status (2026-11-14):** Fixed in #1555: `int` and `slice` overloads.

**Compatibility: non-breaking. Confidence: confirmed.**

**Both sides:** [`src/archivey/diagnostics.py:1785`][f11-extraction] declares
`__getitem__(index: int) -> ExtractionResult`, then returns
`self.results[index]`. [`src/archivey/diagnostics.py:1844`][f11-listing]
repeats this for listing reports.

**Observed:** `report[:]` works and returns a tuple, contrary to the signatures.

**Why it matters:** Typed callers cannot use ordinary sequence operations on
objects advertised as indexing like their underlying sequences; the return
annotation is also false for slices.

**Proposed change:** Add separate `int` and `slice` overloads with element and
tuple return types, respectively.

## F12. Nesting depth is an unadjustable limit with a different error category

**Status (2026-11-14):** Won't fix; settled by DR-9. The depth bound is DR-9's structural case: `MAX_NESTED_DEPTH`'s comment says it keeps a self-nesting walk under Python's recursion limit, and the bound has a spec row (`format-plugins`, `archive-reading`). It is not a configured resource limit, so `ResourceLimitError` ("configured resource exhaustion") would be the wrong category. `UnsupportedFeatureError` stays.

**Compatibility: breaking exception change. Confidence: confirmed behavior; inferred design concern.**

**Both sides:** [`src/archivey/core.py:464`][f12-doc] documents adjustable
nest totals alongside a fixed nine-archive chain.
[`src/archivey/core.py:662`][f12-raise] raises `UnsupportedFeatureError` at
the depth boundary, whereas [`src/archivey/exceptions.py:343`][f12-error]
assigns configured resource exhaustion to `ResourceLimitError`.

**Observed:** The tenth linked reader raises `UnsupportedFeatureError` even
with `ListingLimits.UNLIMITED` and `DecoderLimits.UNLIMITED`.

**Why it matters:** A recursive scanner cannot lower the depth allowance for
uploads or raise it for trusted input, and its resource-limit handler misses
this refusal.

**Proposed change:** Add an explicit depth field, define whether it counts the
root, retain the current default, and raise `ResourceLimitError`. This is an
inferred design concern, not undocumented behavior: the fixed bound is documented.
Adding the field is additive; changing the documented exception type is breaking.

[f1-config]: https://github.com/archivey-dev/archivey/blob/733a1b6/src/archivey/config.py#L635
[f1-core]: https://github.com/archivey-dev/archivey/blob/733a1b6/src/archivey/core.py#L1305
[f2-signature]: https://github.com/archivey-dev/archivey/blob/733a1b6/src/archivey/format_policy.py#L467
[f2-consume]: https://github.com/archivey-dev/archivey/blob/733a1b6/src/archivey/format_policy.py#L152
[f3-extraction]: https://github.com/archivey-dev/archivey/blob/733a1b6/src/archivey/diagnostics.py#L1782
[f3-listing]: https://github.com/archivey-dev/archivey/blob/733a1b6/src/archivey/diagnostics.py#L1841
[f3-verify]: https://github.com/archivey-dev/archivey/blob/733a1b6/src/archivey/diagnostics.py#L1884
[f4-config]: https://github.com/archivey-dev/archivey/blob/733a1b6/src/archivey/config.py#L1109
[f4-core]: https://github.com/archivey-dev/archivey/blob/733a1b6/src/archivey/core.py#L593
[f5-type]: https://github.com/archivey-dev/archivey/blob/733a1b6/src/archivey/types.py#L1895
[f5-doc]: https://github.com/archivey-dev/archivey/blob/733a1b6/docs/extracting.md#L193
[f6-contract]: https://github.com/archivey-dev/archivey/blob/733a1b6/src/archivey/exceptions.py#L464
[f6-raise]: https://github.com/archivey-dev/archivey/blob/733a1b6/src/archivey/config.py#L1224
[f7-config]: https://github.com/archivey-dev/archivey/blob/733a1b6/src/archivey/config.py#L844
[f7-format]: https://github.com/archivey-dev/archivey/blob/733a1b6/src/archivey/types.py#L235
[f7-policy]: https://github.com/archivey-dev/archivey/blob/733a1b6/src/archivey/diagnostics.py#L1701
[f7-intent]: https://github.com/archivey-dev/archivey/blob/733a1b6/src/archivey/config.py#L1161
[f8-core]: https://github.com/archivey-dev/archivey/blob/733a1b6/src/archivey/core.py#L548
[f8-type]: https://github.com/archivey-dev/archivey/blob/733a1b6/src/archivey/types.py#L104
[f9-core]: https://github.com/archivey-dev/archivey/blob/733a1b6/src/archivey/core.py#L1274
[f9-config]: https://github.com/archivey-dev/archivey/blob/733a1b6/src/archivey/config.py#L812
[f10-use]: https://github.com/archivey-dev/archivey/blob/733a1b6/src/archivey/format_policy.py#L467
[f10-import]: https://github.com/archivey-dev/archivey/blob/733a1b6/src/archivey/format_policy.py#L32
[f10-exceptions]: https://github.com/archivey-dev/archivey/blob/733a1b6/src/archivey/exceptions.py#L40
[f11-extraction]: https://github.com/archivey-dev/archivey/blob/733a1b6/src/archivey/diagnostics.py#L1785
[f11-listing]: https://github.com/archivey-dev/archivey/blob/733a1b6/src/archivey/diagnostics.py#L1844
[f12-doc]: https://github.com/archivey-dev/archivey/blob/733a1b6/src/archivey/core.py#L464
[f12-raise]: https://github.com/archivey-dev/archivey/blob/733a1b6/src/archivey/core.py#L662
[f12-error]: https://github.com/archivey-dev/archivey/blob/733a1b6/src/archivey/exceptions.py#L343
