# Detection Cost

## Purpose

Detection declares what it may spend (`DetectionBudget`) and reports what it spent
(`DetectionCostReceipt`). A sibling of `access-mode-and-cost`'s archive-open
`CostReceipt` — detection's I/O happens before a reader exists.

**Stability note.** The types live in `archivey.detection_cost` and a caller sets one
through `ArchiveyConfig.detection_budget`, which `detect_format`, `open_archive` and
`open_stream` all read; they are **not** re-exported from `archivey.__all__`.

This spec describes **what ships today**. The budget and the receipt carry no field for a
tier that does not exist: a ZIP tail probe, if one is ever scheduled, adds its own budget
and receipt fields then. A candidate ledger with its own budget fields was considered and
decided against.

## Related specs

| Spec | Relationship |
| --- | --- |
| `format-detection` | Tiers that spend against the budget |
| `access-mode-and-cost` | Shared vocabulary; detection receipt is not folded into `CostReceipt` |

## Requirements

### Requirement: Detection declares what it may spend, and reports what it spent

The system SHALL expose a detection budget and a detection cost receipt in one shared
vocabulary — the budget is an upper bound, the receipt is measured work:

```python
@dataclass(frozen=True)
class DetectionBudget:
    max_prefix_bytes: int
    max_far_bytes: int
    max_scan_bytes: int
    max_decode_input: int
    max_decode_output: int
    completion_window_bytes: int   # largest source a content-probe hit is re-checked whole

@dataclass(frozen=True)
class DetectionCostReceipt:
    prefix_bytes: int      # sum of range lengths requested from the workspace
    unique_bytes_read: int # bytes fetched from the source. The prefix counts each byte once; a trailer read counts its block again when a later tier reads those bytes as part of the prefix
    far_bytes: int
    scanned_bytes: int
    decode_input: int
    decode_output: int
    passes: int            # detection passes summed (2 after following a stub), each under the full budget
```

Every `DetectionBudget` field SHALL be a non-negative `int`, checked at construction
with the same field check as the `*Limits` types (`error-handling`): a `bool`, a
`float`, `None` or a negative value raises `ArchiveyUsageError` naming the field.

The budget SHALL be set through `ArchiveyConfig.detection_budget`, which takes a
`DetectionBudget`, a `DetectionBudgetPreset` or its string spelling, and the same budget
SHALL govern `detect_format` and the detection `open_archive` / `open_stream` run. The
receipt SHALL be detection's own and SHALL NOT be merged into the archive-open
`CostReceipt`: detection's I/O happens before a reader exists. The receipt SHALL cover the
work of the whole `detect_format` call: when a stub-only executable is followed to its
sibling split volume, the receipt and the skips SHALL be those of both passes together,
with each repeated skip kept once. Each pass runs under the full budget, so the receipt
SHALL say how many passes it sums (`passes`, 2 here), and it is judged against that many
budgets. `max_far_bytes` is separate from `max_prefix_bytes` because a
far fixed-offset signature needs a ~32 KiB window that a 4 096-byte near budget would
otherwise forbid.

Budget fields that gate detection: `max_prefix_bytes` (near peek clamp), `max_far_bytes`,
`max_scan_bytes` (SFX window), `max_decode_input` / `max_decode_output`, and
`completion_window_bytes` (see `format-detection`: a content-probe hit on a source no
larger than this is re-checked against the whole source). Content-probe header reads at
an offset have no budget field: the Brotli walk caps them at `CHAIN_MAX_LINKS` (8) header
reads of 24 bytes, and that is the probe-seek allowance below. The Brotli chain decode
(see `format-detection`) reads `[0, end)`, and the fields bound it: it runs only when `end`
is within the prefix/far/scan ceiling and the decode allowance covers it. The UDIF trailer is the same kind
of fixed read: one 512-byte block on a cheap seek, with no budget field of its own, and
that length is the trailer allowance below.

`max_decode_input` SHALL be one allowance for the whole `detect_format` pass, not a limit
per tier or per candidate: every tier that decodes draws on what earlier tiers left, so
adding tiers or candidates cannot multiply the compressed input a budget allows decoded.
Today four tiers draw on it. `max_decode_output` bounds the inner-TAR probe only; a
content probe's output is bounded by the codec's own drain (4 KiB, 64 KiB when the whole
source is in hand, and the sample length, up to 1 MiB, for the Brotli chain decode) and
is not charged to `decode_output`. That is deliberate for the chain decode too: its
output is mostly a copy of the input it was charged for. Each content probe is
charged the sample it was handed, whether or not a header check turned it away before
decoding; a probe the remaining allowance cannot cover does not run, and `content_probe`
is recorded *budget exhausted* (or *not enabled by policy* when `max_decode_input` is 0).
The completion check is charged the whole source it decodes and records `probe_completion`
*budget exhausted* when the allowance cannot cover it (a zero allowance stops the probes
before any hit asks for completion), and *not enabled by policy* when
`completion_window_bytes` is 0. The Brotli chain decode is charged the `end` bytes it
decodes, and records `content_probe_decode` *budget exhausted* when the allowance cannot
cover them or `end` is past the prefix/far/scan ceiling or the 1 MiB reach; the probe's
verdict then stands. The inner-TAR probe caps its compressed input at the
smaller of what is left and 1 MiB, is charged whether its decode succeeds or fails, and
records `inner_tar` as *budget exhausted* when the cap cut it short or less than one
512-byte TAR header of output is left. Content-probe `read_at` seeks on cheap
random-access sources (path, non-`ArchiveStream` seekable streams) without
growing the prefix through `[0, offset)`, and take the part of a read the prefix already
holds from the prefix; non-seekable and expensive-seek sources grow
under the smaller of 1 MiB and the budget's prefix/far/scan ceiling, and record
`BUDGET_EXHAUSTED` past it. A far signature that ends past a positive `max_far_bytes`
SHALL be recorded as `far_magic` *budget exhausted* rather than searched in a window too
short to hold it, unless the source is provably too short to hold it anyway, and as *not
enabled by policy* when `max_far_bytes` is 0. An SFX scan that misses in a window a
positive `max_scan_bytes` made shorter than the 2 MiB structural bound SHALL be recorded
as `sfx_scan` *budget exhausted*, on the same carve-out, and as *not enabled by policy*
when `max_scan_bytes` is 0. An SFX scan in which any format reaches the
rejected-candidate cap, or in which a hit validator's view is clamped at the validator
allowance, SHALL be recorded as `sfx_scan` *budget exhausted* too, whether or not it
answers. A near signature that ends past a positive `max_prefix_bytes` SHALL be recorded
as `near_magic` *budget exhausted*, and as *not enabled by policy* when `max_prefix_bytes`
is 0. The self-checking header step needs one whole 512-byte block: a positive
`max_prefix_bytes` under 512 SHALL record `header_check` *budget exhausted*, and 0 SHALL
record it *not enabled by policy*.

A receipt is within its budget when each bounded counter is at most `passes` times its
limit: `far_bytes`, `scanned_bytes`, `decode_input` and `decode_output` against the field
of the same name, and `unique_bytes_read` against the largest of `max_prefix_bytes`,
`max_far_bytes` and `max_scan_bytes` plus the probe-seek allowance, the trailer allowance,
and, when `scanned_bytes` is positive, the SFX validator allowance: the smaller of
`VALIDATOR_PEEK_MAX` and `max_scan_bytes`, the bytes a hit validator may read past the
window end to judge a candidate that starts inside it. `prefix_bytes` is not compared,
because it bills overlapping requests in full and `unique_bytes_read` stands in for it. A
receipt that is not within its budget SHALL carry a *budget exhausted* or *capability
unavailable* skip naming the tier that was cut short. The library does not expose this
check; the test suite asserts it.

#### Scenario: receipt reflects the source kind

| Case | Expected |
| --- | --- |
| Path, near magic hit at offset 0 | `unique_bytes_read` is the single prefix read |
| Growing 4 KiB → 32 KiB → 2 MiB | `unique_bytes_read` counts each byte once; `prefix_bytes` counts requests |
| A tier the budget turns off (`completion_window_bytes` 0 under `FAST`) | Recorded as *not enabled by policy* — a distinct reason, because it does not make the search incomplete |
| SFX scan miss under `FAST` | `scanned_bytes` ≤ `max_scan_bytes`; `unique_bytes_read` ≤ scan ceiling + probe allowance + the 512-byte trailer; `sfx_scan` recorded *budget exhausted* when the source is longer than the window |
| SFX miss then extension guess (`.zip`) | Within budget under `BALANCED` and `FAST` |
| ISO under a `max_far_bytes` smaller than the `CD001` span | Extension `GUESS`; `far_magic` recorded *budget exhausted*; `far_bytes` 0 |
| `.tar.bz2` whose first block exceeds `FAST`'s decode input | Bare `BZ2`; `decode_input` ≤ 64 KiB; `inner_tar` recorded *budget exhausted*; within `FAST` |
| Expensive-seek source, content probe asks past the budget ceiling | `read_at` returns `None`; `content_probe_read_at` recorded *budget exhausted*; within budget |
| Pipe or member stream that reaches the trailer step (a bzip2 stream with a `koly` block after it) | Tail not read; `trailer` recorded *capability unavailable*; the near-magic answer (`BZ2`) stands |
| Source shorter than the 512-byte trailer block | Tail not read; nothing recorded: there is no block to miss |
| Stub-only `vol.exe` beside `vol.7z.001` | `SEVEN_Z`; the receipt includes the stub pass's SFX scan; `passes` 2; within two budgets, not one; a skip both passes record is kept once |
| `max_decode_output` below one 512-byte TAR header | Inner-TAR probe not run; `inner_tar` recorded *budget exhausted*; nothing charged |
| `max_decode_input` 0, zlib stream | No content probe runs; `content_probe` recorded *not enabled by policy*; `decode_input` 0; detection fails |
| `max_decode_input` smaller than the samples the probes ahead of zlib were charged | Probing stops before zlib; `content_probe` recorded *budget exhausted*; `decode_input` within the budget |
| Brotli chain decode of 270 KiB (a `.pyc`-shaped file), `BALANCED` | Decoded and charged; the claim is rejected; within budget |
| The same under `FAST` | Not decoded; `content_probe_decode` recorded *budget exhausted*; the `BROTLI` claim stands; within budget |

### Requirement: FormatInfo reports the receipt and the tiers that did not run

`detect_format` SHALL return its receipt on `FormatInfo.cost_receipt` and the tiers it
did not run on `FormatInfo.unavailable_tiers`. Both are public:

```python
class TierSkipReason(Enum):
    NOT_ENABLED_BY_POLICY = "not_enabled_by_policy"
    CAPABILITY_UNAVAILABLE = "capability_unavailable"
    BUDGET_EXHAUSTED = "budget_exhausted"

@dataclass(frozen=True)
class TierSkip:
    tier: str
    reason: TierSkipReason
```

`cost_receipt` SHALL be set on every `FormatInfo` that `detect_format` returns (the zero
receipt for a directory) and SHALL be `None` only on a `FormatInfo` that other code built.
`unavailable_tiers` SHALL list each skipped tier once, in the order it was first recorded,
and SHALL be empty when every tier ran. `NOT_ENABLED_BY_POLICY` SHALL NOT mean that the
search was incomplete; `CAPABILITY_UNAVAILABLE` and `BUDGET_EXHAUSTED` SHALL mean that it
was. Neither field SHALL take part in `FormatInfo` equality or `repr`, so two results that
found the same format at a different cost compare equal. `tier` names an open set: a later
release MAY add a tier.

#### Scenario: receipt and skips on FormatInfo

| Case | Expected |
| --- | --- |
| `detect_format` on a file | `cost_receipt` is a `DetectionCostReceipt`, not `None` |
| Directory path | `cost_receipt` is the zero receipt (`passes` 1); `unavailable_tiers` is empty |
| ZIP under the default budget | `unavailable_tiers` is empty |
| Two results that differ only in receipt or skips | Compare equal |

### Requirement: Remaining length is measured, never estimated

An overestimated total size SHALL NOT be treated as proof that a later offset is reachable;
a size gate may skip a detector only when the remaining source is *provably* too short.
The remaining length of a seekable source is measured from the caller's entry position,
not from offset 0.

#### Scenario: remaining length

| Case | Expected |
| --- | --- |
| Caller-positioned seekable stream | Remaining length measured from the entry position, not from offset 0 |
| Pipe that has not reached EOF | Remaining length unknown |

### Requirement: Detection budget presets

The system SHALL provide three presets, and `BALANCED` SHALL be the default. Preset
behaviour below is what detection **runs today**.

| preset | behaviour today |
| --- | --- |
| `BALANCED` | near prefix; far fixed-offset evidence; cued bounded SFX scan (`max_scan_bytes` = 2 MiB); the 512-byte UDIF trailer on a cheap seek; bounded content probes; whole-source completion of a probe hit up to 64 KiB; inner TAR; no exhaustive scan; no spool |
| `FAST` | same tiers as `BALANCED` with a smaller SFX scan (`max_scan_bytes` = 256 KiB), smaller decode ceilings, and no whole-source completion (`probe_completion` recorded *not enabled by policy* when a probe hit could have used it) |
| `THOROUGH` | same scheduled tiers as `BALANCED` today, with whole-source completion as far as the 1 MiB decode allowance reaches (the probes' samples are charged first, so a source just under 1 MiB may not complete) |

No preset scans for a ZIP end-of-central-directory. Every preset reads one fixed
512-byte block at the end of a cheap-seek source, looking for a UDIF `koly` signature,
before the content probes. A ZIP behind a prefix that does not cue the SFX scan is
still not found. Format boundedness proves the search is complete for the tiers a
policy enables.

#### Scenario: preset boundaries (shipping)

| Case | `BALANCED` | `FAST` | `THOROUGH` (today) |
| --- | --- | --- | --- |
| Ordinary ZIP / gzip / ISO at a known offset | Found | Found | Found (same tiers) |
| MZ stub + junk, no archive magic, `.zip` name | Extension `GUESS`; scan charged ≤ 2 MiB | Extension `GUESS`; scan charged ≤ 256 KiB | Same as `BALANCED` |
| ZIP behind a non-cueing prefix (JPEG + appended ZIP) | Not found | Not found | Not found — no tier looks for a ZIP trailer |
| `zipapp` (`#!` prefix + ZIP) | Not found — shebang is not an executable cue today | Not found | Not found |
| Exhaustive whole-source scan | Never | Never | Never (opt-in later, not by preset alone) |

### Requirement: Non-seekable sources degrade explicitly, and are never spooled

Detection SHALL NOT buffer a whole pipe or spool it to a temporary file. Near and far
prefix evidence and cued forward scans SHALL still work through replay buffering; a
content probe that would read past what the budget lets a pipe buffer SHALL be recorded as
*budget exhausted* rather than attempted.

#### Scenario: pipe behaviour

| Case | Expected |
| --- | --- |
| Pipe, default budget, settled before the trailer step (ZIP, gzip) | Prefix tiers run; `unavailable_tiers` empty; no unbounded buffering |
| Pipe, default budget, reaches the trailer step (bzip2, xz or zlib, 512 bytes or more) | Prefix tiers run; tail not read; `trailer` recorded *capability unavailable* (see *receipt reflects the source kind*); no unbounded buffering |
| Detection finds a format whose backend cannot consume the source | `open_archive` raises the capability error rather than opening |
