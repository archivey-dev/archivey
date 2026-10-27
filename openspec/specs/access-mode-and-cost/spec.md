# Access Mode and Cost

## Purpose

Callers declare access pattern via `streaming: bool` at open, and read a
machine-readable `CostReceipt` (`listing` / `access` / `stream` axes + solid
block count). This spec is the **canonical** access-mode × method table;
`archive-reading` summarizes the same rules for the reader surface.

## Related specs

| Spec | Relationship |
| --- | --- |
| `archive-reading` | Reader API that obeys these rules |
| `reader-concurrency` | `MemberStreams.CONCURRENT` within random-access mode |
| `diagnostics` | Runtime rewind / seek-index events (not frozen into `CostReceipt`) |
| `safe-extraction` | `extract_all` as a forward-pass entry point |

## Requirements

### Requirement: Declaring access mode at open_archive()

`open_archive(..., streaming: bool = False)` SHALL accept exactly two modes:

| Mode | Meaning |
| --- | --- |
| `streaming=False` (default) | **Random access.** Load indexes when available. Fail fast at open if the source is non-seekable and the format cannot adapt — never silently degrade to forward-only. Seek points for single-stream formats are built **lazily** on first `seek()`. |
| `streaming=True` | **Forward-only, single pass.** Disable index loading where possible; works on non-seekable sources **where the backend reads front to back** (see below). Random-access / full-materialization APIs disabled **uniformly** (independent of any loaded index). `members_report_if_available()` stays callable (never scans). |

Non-seekable sources are never given random access: with `streaming=False` the
library fails fast at open when the format needs seek (it does not buffer the
source into memory or a temp file). `streaming=True` is the fix for pipes and
sockets **only where the backend reads front to back** (TAR, ZIP, the single-file
compressors). A format that needs seek in either mode (ISO, 7z, RAR) SHALL be
refused with one message naming a seekable source as the fix, in both modes, rather
than proposing a `streaming=True` retry the same call would then refuse. That refusal
SHALL come before the format's availability check: a pipe cannot be read even with the
optional package installed, so a missing package MUST NOT be reported first. The
`streaming=False` refusal for a format that does read front to back stays after the
availability check, because there the missing package is a real step on the way.
Eager seek-point building is not exposed.

Every source `open_archive` and `open_stream` take SHALL cross one boundary, which
returns one `ArchiveSource`; standalone `detect_format` does not cross it. Every consumer
of the raw source SHALL receive one of three things: the `ArchiveSource`; a wrapper over
it that preserves the four guarantees below (a view that clamps its reads and does not
close its inner); or, for a parser that opens a path itself, the `ArchiveSource`'s path.
The `ArchiveSource` SHALL carry every source-level guarantee itself, whatever the caller
passed — a path, a stream, or a volume list:

| Guarantee | What `ArchiveSource` SHALL do |
| --- | --- |
| Full-count | `read(n)` returns `n` bytes unless the source is exhausted. A raw `read(n)` may legally return short, and header parsers, archivey's and the stdlib's alike, issue one `read(n)` and treat a short as EOF. A `None` from the caller's `read` (nothing ready on a non-blocking stream, raw or already buffered) is not exhaustion: `ArchiveSource` raises `BlockingIOError` instead of returning a short read or EOF, including when `None` follows a short chunk. That short chunk has already left the source and is not returned. A read that no fact length clamps asks again after a short return, whatever the source's shape, because a non-blocking buffered stream returns what has arrived short and answers `None` only on the next read |
| Ownership | Close what archivey opened or built — a path's handle, a joined volume set, its own read buffer — and never the caller's object, including a caller stream inside a volume list |
| Bounded reads | No `read(n)` asks the source for more than it can still supply: clamped when the remaining length is a fact, served in steps when it is not, so a length an archive declares cannot become an allocation at the source |
| Cheap facts | The path when a real file exists (not a pipe or device, which is read once, through the source), the volume paths of a joined set, the size when it is a fact (so that anything built over the source, which asks `source_byte_size`, clamps on a fact or steps too), a caller's `size` hint kept apart for reporting only, and the name, each settled once at the boundary |

How full-count is supplied differs by source, and the difference is read-ahead:

| Source | Read-ahead added at the boundary |
| --- | --- |
| Path | The file's own `io.BufferedReader`, opened on first read |
| Seekable stream that is already buffered (a `BytesIO`, an `open()` handle) | **None.** It is already full-count; `fileno()` still forwards |
| Seekable stream, not already buffered | A fixed-size read buffer. Bounded, and recoverable by seeking |
| Non-seekable stream that is already `io.BufferedReader` / `io.BufferedRandom` | **Only the detection prefix**, when detection ran, as for any non-seekable source. Past it the caller's buffer, not a second one, supplies full-count, and its read-ahead is the caller's. The caller's `peek` is not used for detection: it returns at most one buffer's worth, less than the detection window can need |
| Non-seekable stream, not already a CPython buffer | **Only the detection prefix**, when detection ran, filled by `peek` and drained by the first reads. Past it, missing bytes are re-asked for, so a `read(n)` takes exactly `n` from the source. Codec layers above it may still buffer |

The detection prefix holds only what detection peeked: `DETECTION_LIMIT` bytes, 32 774
when the ISO probe triggers, up to 1 MiB for the inner-TAR probe
(`_INNER_TAR_MAX_PROBE_BYTES`) and content-probe chain walks
(`PROBE_READ_AT_MAX_OFFSET_NONSEEKABLE`), and never more than the self-extracting scan's
2 MiB (`SFX_MAX`), which only an executable-looking head triggers.

Neither is the materialization forbidden above: `ArchiveSource` over a non-seekable
source SHALL hold no buffered bytes beyond the detection prefix, which never grows past
that 2 MiB cap, and SHALL report `seekable()` as `False`, so `streaming=False` over it
still fails fast at open.

This is how "archivey never closes a caller-supplied `BinaryIO`" (`archive-reading`) is
kept regardless of what a backend builds on top of the source: the caller's object is
never handed past the boundary, so no wrapper a backend adds can reach it except through
`ArchiveSource`, which borrows it.

#### Scenario: a non-blocking read is not end of file

| Case | Expected |
| --- | --- |
| Non-seekable raw stream, `read` returns `None` | `ArchiveSource.read`, `read(-1)`, `readall`, `readinto` and `peek` raise `BlockingIOError` |
| Same stream returns a short chunk, then `None` | Same error. The short chunk is not the result of the read. Those bytes have already left the source and cannot be read again |
| Non-seekable already-buffered stream, `read` returns `None` | Same five methods raise `BlockingIOError` |
| Non-seekable already-buffered stream returns what has arrived short, then `None` on the next read | Same five methods raise `BlockingIOError`. The short return is asked again, not taken as the end of the source |
| `open_archive(..., streaming=True)` on a stream with nothing ready | `BlockingIOError`, not an empty-archive detection error |
| `open_archive(..., streaming=True)` on an already-buffered stream with nothing ready | `BlockingIOError`, not an empty-archive detection error |
| `open_archive(..., streaming=True)` on a stream that returns a complete gzip and then `None` | `BlockingIOError`. The member those bytes happen to hold is not returned |
| `open_archive(..., streaming=True)` on an already-buffered stream that returns a complete gzip and then `None` | `BlockingIOError`. The member those bytes happen to hold is not returned |
| `open_archive(..., streaming=True)` on an already-buffered stream that has delivered the first 100 bytes of a tar and then stalls | `BlockingIOError`, not a format detection error |
| `detect_format` on a raw or already-buffered stream with nothing ready | `BlockingIOError`, not "there are no bytes to read" |
| `detect_format` on a raw or already-buffered stream that returns 100 bytes and then `None` | `BlockingIOError`, not a format detection error over the 100 bytes |
| A volume list with a caller stream whose `read` returns `None` | `BlockingIOError`, not `TruncatedError` |

#### Scenario: open mode matrix

| Case | Expected |
| --- | --- |
| `streaming=False` on indexed ZIP | Central directory loaded; random access available |
| `streaming=True` on `.tar.gz` | No full-archive index scan; members as stream is read |
| `streaming=False` on non-seekable source, backend reads front to back | Error at open (before member data) naming `streaming=True` — library does not buffer |
| Either mode on non-seekable source, backend needs seek | Same error and same message in both modes, naming a seekable source (buffer to disk or a `BytesIO`) — library does not buffer |
| Either mode on non-seekable source, backend needs seek, its optional package missing (ISO without `pycdlib`) | The same seekability error, not `PackageNotInstalledError` |
| `streaming=False` on non-seekable source, backend reads front to back, its codec package missing (`.tar.lz4` without `lz4`) | `PackageNotInstalledError` first; the `streaming=True` hint follows once the package is installed |
| Non-seekable source refused by either refusal rule (needs seek in either mode, or `streaming=False` on a front-to-back format), with `password=` for a format with no encryption (ISO, TAR) | `PASSWORD_ARGUMENT_UNUSED` (and `ENCODING_ARGUMENT_UNUSED` likewise) is emitted before the refusal, the same for both rules. The availability refusal (`.tar.lz4` without `lz4`) emits neither: `PackageNotInstalledError` is raised before the argument diagnostics run |
| Seekable stream source, either mode | Full-count `read(n)` from the `ArchiveSource`: a source that is not already buffered gets a fixed-size read buffer (bounded readahead only), and one that already is (a `BytesIO`, an `open()` handle) gets no readahead. Never materialized to memory or disk |
| Non-seekable stream source, `streaming=True` | The `ArchiveSource` gives full-count `read(n)` with no read-ahead beyond the detection prefix: `seekable()` stays `False`; reads drain the prefix first, and once it is drained (or when an explicit `format=` meant it was never filled) a `read(n)` on *that stream* takes exactly `n` bytes from the source. Codec layers above the boundary read differently: a codec over a non-seekable source reads what has arrived (`arrived_view`), one source read per feed, so an end-to-end `read(20)` on a compressed non-seekable open makes one source read per decoder feed, each for up to one feed (64 KiB, more for a large sized read), and decodes what it returns. A short return is not the end of the source; only an empty one is |
| Non-seekable stream that is already `io.BufferedReader` | No second full-count buffer is added: the caller's buffer supplies full-count. The detection prefix sits in front of it when detection ran, and is drained first. `fileno()` forwards through the `ArchiveSource` |
| Non-seekable stream source, metadata probes | The `ArchiveSource` answers what the probes need: a source carrying `name` still answers `source_name`, so `ResolvedSource.archive_name` does not degrade. A `size` that a non-seekable caller stream carries is a claim nothing can check: it bounds no read and is not `compressed_source_size` (safe-extraction, archive-wide ratio); detection still takes it as the total size. It is not transparent in general — what a backend sees is the `ArchiveSource`'s surface, not the source's class, so `read1` / `detach` / `BytesIO.getvalue` do not survive it, and `peek` is the `ArchiveSource`'s own replay prefix, not the source's. `tell()` does not become available either — it raises, as the seek-required refusals depend on |
| Non-seekable short-returning source, any supported streaming format, with and without `format=` | Opens, lists, and reads identically to the full-count source — the guarantee does not depend on detection having run or on a third-party reader's internal buffering |
| Any stream source, every format, measurement on or off | The reader closing does not close the caller's stream, and the caller can still read from it. Holds for a failed open too: the backend releases what it opened, which never includes the caller's object |
| Archive whose header declares a length far past the source's end (a 4 GiB directory record in a 55 KiB ISO image), path and stream sources | Refused as `CorruptionError`; no allocation near the declared length is made at the source. A path source and a stream with no cheap size are both bounded |
| A backend that needs only the path (a directory, `unrar` over a path), with or without detection | No handle on the source stays open after detection returns. Detection opens and closes its own handle from the path, and the `ArchiveSource`'s handle opens only when a backend reads from it |

### Requirement: Access-mode enforcement — streaming is forward-only

On `streaming=True`, `members()` / `get()` / `open()` / `read()` SHALL raise
`ArchiveyUsageError` uniformly. No `__len__`/`__getitem__`
(`archive-reading`); `member in reader` is scan-free identity membership (both
modes).

Forward-pass entry points: `__iter__`, `stream_members`, `extract_all`. The first
consumes the single pass; any later call to any of them SHALL raise — even after
completion (no streaming `__iter__` cache-replay). Early `break` still consumes.
Member selection for extraction is `extract_all(members=...)` (`safe-extraction`).

`members_report()` MAY run before the pass (starts+finishes it), after an
interrupted pass (drains remainder), or after completion (returns the stored
report). Every pass enforces `ListingLimits` (`archive-reading` §listing
limits): a pass that crosses one raises `ResourceLimitError` and keeps no stored
report, and `members_report()` after an interrupted pass raises it where the
remainder crosses the limit. Starting the pass consumes it. It returns
`MemberListReport` instead of raising on terminal archive-level listing errors
(`archive-reading`); a caller that needs complete-or-raise raises `report.error`.
A caller that wants each member as the pass reaches it, without the data,
iterates `stream_members()` (or the reader) and ignores the streams.
`members_report_if_available()` never begins/advances/consumes the pass.

On both access modes, `__iter__` and `stream_members` SHALL yield every
recovered member before propagating a terminal archive-level listing error
(yield-then-raise). `members()` remains complete-or-raise.

#### Scenario: streaming enforcement matrix

| Case | Expected |
| --- | --- |
| `get` / `members` / `open` / `read` on `streaming=True` | `ArchiveyUsageError` |
| First `__iter__` or `stream_members` | Yields in archive order |
| Terminal archive error after prefix (either mode) | Prefix yielded; then raise |
| Second forward-pass method after begin/complete | `ArchiveyUsageError` (all formats) |
| Early `break` then `members_report()` | Drains remainder; fully-resolved report (prefix + `error` on terminal damage); later pass methods raise |
| `stream_members()` / `__iter__` past `ListingLimits` | Members within the limits yielded; then `ResourceLimitError` |
| Early `break` before a limit, then `members_report()` past it | `ResourceLimitError` |
| `members_report()` then `stream_members()` on fresh streaming reader | Report returned; subsequent pass raises (any index topology) |
| `members()` on streaming | `ArchiveyUsageError` whose message points at `members_report()` and `stream_members()` |
| `members_report()` on streaming with terminal archive error after prefix | Report with prefix + `error`; pass consumed; no raise from `members_report` |

### Requirement: members_report_if_available() — a report peek

`members_report_if_available() -> MemberListReport | None` is a **report peek**:
no forward scan, no member-data reads, never consumes the pass. It returns the
stored `MemberListReport` (complete or incomplete) when one exists without scanning,
or the upfront index as a complete report for backends that carry one; else `None`.
The peek follows whether the backend holds a member list after open, not its
`listing_cost`: RAR's listing is `REQUIRES_SCANNING`, but the walk runs inside
`open_archive`, so its peek returns the complete report.
Guaranteed fully-resolved complete list → `members()` (RA), or `members_report()`
with `error is None` (either mode).

| Index topology | Availability |
| --- | --- |
| Leading (ISO) | Both modes, as complete report |
| Scan-based (directory) | `None` until a pass completes — the filesystem walk is lazy, so before it there is nothing to peek at |
| Scan at open (RAR) | Both modes, as complete report |
| Trailing (ZIP CD, 7z EOF header), seekable source | Both modes, as complete report |
| Trailing, non-seekable source (ZIP under `streaming=True`) | `None` until the pass has read the index after the last member; then the complete report, as for TAR after a completed pass |
| No-index (TAR), no prior materialization/pass | `None` |
| No-index after completed successful pass / `members_report` / `members` | Complete report |
| No-index after a terminal archive error was stored after a recoverable prefix | Incomplete report (`members` is prefix, `error` set); count is a floor |

Index-only listings SHALL leave data-stored link targets unset (`link_target` /
`link_target_member`); resolving them needs member-data reads that
`members()`/`members_report()` perform. The members of an upfront-index report SHALL be
the same `ArchiveMember` objects that every other listing method and pass on this
reader returns, and a repeated peek SHALL return the same objects. When
`members()`/`members_report()` later resolve data-stored link targets, they SHALL fill
them in place on those objects (`archive-data-model`: members are live objects). An
upfront-index listing that ends in terminal archive damage SHALL be returned as the
stored incomplete report (prefix plus `error`), not raised. Returning an incomplete
report to a caller MUST NOT change the complete-or-raise behaviour of `members()` /
`get(name)`; the report self-labels via `error` and those methods still raise.

#### Scenario: index-only listing matrix

| Case | Expected |
| --- | --- |
| Streaming ZIP from a seekable source (upfront index) | Full list; no scan/data read; forward pass still available |
| Streaming ZIP from a pipe, before the pass has read the central directory | `None` |
| No-index, not yet iterated | `None` |
| Directory archive, either mode, not yet iterated | `None` — its walk is lazy |
| No-index after completed pass / `members_report` | Complete fully-resolved report |
| No-index after incomplete pass already ran | Incomplete report with recovered prefix and `error` |
| ZIP symlink via `members_report_if_available` | Link fields unset; `members`/`members_report` resolve them |
| `members_report_if_available()` twice on an upfront index | Same member objects both times |
| ZIP symlink held from a peek, then `members()` | `members()` returns that same object, now with its link fields set |
| Upfront index whose listing ends in terminal damage | Incomplete report (prefix plus `error`); `members()` still raises |
| Streaming pass that raised a listing limit, upfront index or not | `None`, as from a pipe: the pass handed out its prefix and cannot be walked again |

### Requirement: Access mode × method behaviour summary

The system SHALL behave per this canonical table (`✅` allowed,
`⛔` → `ArchiveyUsageError`):

| Method | `streaming=False` | `streaming=True` |
| --- | --- | --- |
| `__iter__` | ✅ repeatable after **successful** complete cache; yield-then-raise on terminal archive error | ✅ **once** (no replay); yield-then-raise on terminal archive error |
| `stream_members` | ✅; yield-then-raise on terminal archive error | ✅ once; yield-then-raise |
| `extract_all` | ✅; write-then-raise on terminal listing error (the listed prefix, then the error) | ✅ once; write-then-raise |
| `members_report` | ✅ returns `MemberListReport` on terminal archive damage; raises on limits and usage errors | ✅ finishes/returns pass; same returns and raises |
| `members_report_if_available` | ✅ report peek: stored report (complete or incomplete) / upfront index / `None`; never scans | ✅ report peek, no-consume |
| `members` / `get` / `open` / `read` | ✅; `members`/`get` complete-or-raise | ⛔ |
| `in` (identity) | ✅ no scan (incl. recovered report members) | ✅ no scan |
| `cost` / `info` / `format` / `close` / CM | ✅ | ✅ |
| at `open_archive()` | fail fast if source not RA-capable | any source |

In streaming mode, `__iter__` / `stream_members` / `extract_all` share one pass.

#### Scenario: summary checks

| Case | Expected |
| --- | --- |
| `members_report()` either mode on clean archive | Complete fully-resolved report (RA: same members as `members()`; streaming finishes pass) |
| Full streaming `__iter__`, then iterate again | Second → `ArchiveyUsageError` |
| RA `__iter__` on TAR rejected-header after prefix | Yields prefix members, then `CorruptionError` |
| `members_report()` row present either mode | ✅ returns report |

### Requirement: Exposing a CostReceipt describing access costs

Every opened archive SHALL expose `ar.cost` (also in `ar.info.cost`), computed
during open before heavy I/O. Three **orthogonal** axes + solid-block count:

```python
class ListingCost(Enum):
    INDEXED = "indexed"                     # O(1) listing via index/CD
    REQUIRES_SCANNING = "requires_scanning" # header-to-header, no payload decode
    REQUIRES_DECOMPRESSION = "requires_decompression"  # must decompress to list

class AccessCost(Enum):
    DIRECT = "direct"  # member N independent of others
    SOLID = "solid"    # may need earlier bytes in the block

@functools.total_ordering
class StreamCapability(Enum):
    SEEKABLE = "seekable"        # source seekable
    FORWARD_ONLY = "forward_only"  # pipe/socket; revisit needs a new stream

@dataclass(frozen=True)
class CostReceipt:
    listing_cost: ListingCost
    access_cost: AccessCost
    stream_capability: StreamCapability
    solid_block_count: int | None  # distinct solid blocks, or None
    notes: tuple[str, ...] = ()    # caveats — not an occurrence log
```

| Axis | About |
| --- | --- |
| `stream_capability` | Source bytes — can they be `seek()`ed? |
| `access_cost` | Format layout — `DIRECT` vs `SOLID` (re-decompress cost lives here, not in seekability) |
| `listing_cost` | Enumerating names+metadata |

`StreamCapability` SHALL be **totally ordered by strength**, weakest first:
`FORWARD_ONLY < SEEKABLE`. A seekable source can serve every read a forward-only one
can, so the ordering is the "is at least as strong as" relation and comparing two
capabilities SHALL answer whether one source shape satisfies a requirement stated as
the other. `ListingCost` and `AccessCost` are **not** ordered: their members name
kinds of work, not strengths of the same resource.

Examples: ZIP file → `INDEXED`+`DIRECT`+`SEEKABLE`; plain tar file →
`REQUIRES_SCANNING`+`DIRECT`+`SEEKABLE`; tar on pipe → same + `FORWARD_ONLY`; ZIP on
pipe → `REQUIRES_SCANNING`+`DIRECT`+`FORWARD_ONLY` (members found by local headers);
`.tar.gz` file → `REQUIRES_DECOMPRESSION`+`SOLID`+`SEEKABLE`; solid 7z →
`INDEXED`+`SOLID`+`SEEKABLE` with `solid_block_count` = folder count.

#### Scenario: cost receipt matrix

| Case | Expected |
| --- | --- |
| Successful open | `ar.cost` populated without separate member scan/read |
| ZIP | `listing_cost=INDEXED`, `access_cost=DIRECT` |
| ZIP on a pipe, `streaming=True` | `listing_cost=REQUIRES_SCANNING`, `access_cost=DIRECT`, `stream_capability=FORWARD_ONLY` |
| `.tar.gz` | `REQUIRES_DECOMPRESSION` + `SOLID` |
| Same plain tar: file vs pipe | `stream_capability` SEEKABLE vs FORWARD_ONLY; `access_cost=DIRECT` both |
| Solid 7z, multiple folders | `info.is_solid`, `access_cost=SOLID`, `solid_block_count` = folder count |

#### Scenario: stream capability ordering matrix

| Case | Expected |
| --- | --- |
| `FORWARD_ONLY < SEEKABLE` | `True` |
| `SEEKABLE >= FORWARD_ONLY` | `True` |
| `FORWARD_ONLY <= FORWARD_ONLY` | `True` |
| `SEEKABLE < FORWARD_ONLY` | `False` |
| Comparison against a non-`StreamCapability` | `TypeError` |
| `sorted(StreamCapability)` | `[FORWARD_ONLY, SEEKABLE]` |

### Requirement: CostReceipt remains an immutable open-time cost description

`CostReceipt` SHALL describe static open-time properties only — not runtime
diagnostics. Slow rewinds / seek-index failures go to reader/stream diagnostic
aggregates (`diagnostics`). Static `notes` MAY caveat capability; SHALL NOT act as
an occurrence log or counter.

#### Scenario: cost immutability matrix

| Case | Expected |
| --- | --- |
| Backward seek re-decompresses | `STREAM_REWIND_REDECOMPRESSES` on diagnostics; `CostReceipt` unchanged |
| Optional seek-index degrades | `SEEK_INDEX_DEGRADED` on aggregate; no diagnostic field on `CostReceipt` |

### Requirement: Declared capabilities compose with the two access modes

`streaming` SHALL remain the only access-mode choice. `seekable_members` /
`concurrent_operations` SHALL declare stream capabilities **within** a mode (not a third
mode; no `ArchiveyConfig` equivalent). Ownership, leases, materialization, and
free-threaded rules for declared concurrency live in `reader-concurrency`; this
requirement only states how the capabilities compose with `streaming`.

| Mode | Capability composition |
| --- | --- |
| `streaming=False` | `concurrent_operations` and/or `seekable_members` MAY be declared; concurrent-open semantics are `reader-concurrency`. Without `concurrent_operations`, one live member stream (`archive-reading`). |
| `streaming=True` | Random `open`/`read` still unavailable. Single progressive pass is exclusive. **`concurrent_operations=True` incompatible** → `ArchiveyUsageError` at open. `seekable_members=True` alone MAY be declared. |

Random-access `stream_members()` is exclusive on a default reader. Under
`concurrent_operations=True`, random `open()`, the other random-access calls, further
`stream_members()` passes and `extract_all()` run beside it on every format (see
`reader-concurrency`, "Random-access calls beside a pass").
Detected pass/open/close overlap → later op `ArchiveyUsageError`; active pass stays usable. The exception is `close()`
while the pass is suspended at a yield: the reader closes and resuming the pass raises
`ArchiveyUsageError` (maintainer's ruling, 2026-10-10; see `archive-reading`). Ops
after `reader.close()` → `ArchiveyUsageError` (idempotent `close`).

#### Scenario: mode × capability matrix

| Case | Expected |
| --- | --- |
| `streaming=True` + `concurrent_operations=True` | `ArchiveyUsageError` at open; no reader |
| RA + `concurrent_operations=True` (or without) | Concurrent-open / single-live-stream rules per `reader-concurrency` / `archive-reading` |
| Active pass + conflicting pass/open, or close while the pass executes | Later → `ArchiveyUsageError`; original pass usable |
| Pass suspended at a yield + `close()` | Reader closed; resuming the pass → `ArchiveyUsageError` |
| RA `stream_members` active + `open()` or another `stream_members` | `ArchiveyUsageError`, unless `concurrent_operations=True` |
| `extract_all` drives child `stream_members` | Permitted composition; unrelated public pass rejected |

### Requirement: Concurrent-stream cost is informational

`access_cost` / `solid_block_count` describe work (including under a declared
simultaneous schedule). They SHALL NOT permit or deny capabilities —
`concurrent_operations` is the only gate (`reader-concurrency`). Solid open-*order* cost
is reported here and steered toward `stream_members()`, not gated.

**An out-of-order `open()` on a solid archive SHALL emit no diagnostic and no warning,
and this is deliberate.** Three separate reviews have now proposed adding one, so the
reason is recorded here rather than rediscovered a fourth time:

- The signal already exists, *earlier*, and is impossible to miss: `cost.access_cost`
  is `SOLID` on the receipt every reader publishes at open, before the caller does
  anything. Compare the rewind case (`seekable-decompressor-streams`), which has **no**
  open-time signal at all and is the reason that one does emit — if the case with no
  prior warning does not justify an ambient one, the case that already told you at open
  certainly does not.
- A `warnings.warn` here would be about an archive, against the project rule that
  prefers structured diagnostics precisely because "a logging warning most applications
  never see is a surprise deferred, not avoided" (`VISION.md`). A `DeprecationWarning`
  is a different case: it is about the caller's code (`design-rules.md` DR-12a).
- Emitting per `open()` on the workload that provokes it (walking every member of a
  solid archive) would produce one occurrence per member — noise proportional to the
  thing already reported once, accurately, as a cost.

The library's answer to solid open-order cost is the receipt plus the `open()`
docstring's pointer to `stream_members()`. A caller who wants to be *stopped* has
`ListingLimits` and the extraction ratio guards, not an advisory.

#### Scenario: cost vs capability

| Case | Expected |
| --- | --- |
| `concurrent_operations=True` on `DIRECT` and `SOLID` readers, multiple streams | Both supported and byte-correct; only reported/repeated work differs |
| Out-of-order `open()` on a solid 7z / RAR / compressed TAR | Members read correctly; **no** diagnostic and **no** `warnings.warn`; `cost.access_cost == SOLID` was the signal, at open |

### Requirement: Detection cost is a sibling of CostReceipt, not part of it

`CostReceipt` describes an **opened archive**. Detection's I/O happens before a reader
exists, so its measured work SHALL be reported through the separate `DetectionCostReceipt`
(`detection-cost`) and SHALL NOT be folded into `CostReceipt` or `ArchiveInfo.cost`.

The two SHALL share vocabulary where they describe the same thing — the kinds of work
counted — so a caller reading both sees one cost model rather than two.

#### Scenario: the two receipts stay separate

| Case | Expected |
| --- | --- |
| `open_archive` on a path, detection read 32 774 bytes | `ar.cost` unchanged by those bytes; the detection receipt carries them |
| Standalone `detect_format` | A detection receipt exists; no `CostReceipt` does, because no archive was opened |
| A caller comparing the two | Work-kind names match; the totals are of different things and are not summed |
