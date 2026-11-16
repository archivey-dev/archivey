## MODIFIED Requirements

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
    max_probe_forward_bytes: int = 0  # furthest offset a probe may buffer through

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
`CostReceipt`: detection's I/O happens before a reader exists. The receipt SHALL cover
the work of the whole `detect_format` call: when a stub-only executable is followed to
its sibling split volume, the receipt and the skips SHALL be those of both passes
together, with each repeated skip kept once. Each pass runs under the full budget, so
the receipt SHALL say how many passes it sums (`passes`, 2 here), and it is judged
against that many budgets. `max_far_bytes` is separate from `max_prefix_bytes` because a
far fixed-offset signature needs a ~32 KiB window that a 4 096-byte near budget would
otherwise forbid.

Budget fields that gate detection: `max_prefix_bytes` (near peek clamp),
`max_far_bytes`, `max_scan_bytes` (SFX window), `max_decode_input` /
`max_decode_output`, and `completion_window_bytes` (see `format-detection`: a
content-probe hit on a source no larger than this is re-checked against the whole
source). Content-probe header reads at an offset are capped at `CHAIN_MAX_LINKS` (8)
header reads of 24 bytes, plus one 2-byte end check when length is unknown. That is the
probe-seek allowance below. Cheap header seeks may inspect any offset.
`max_probe_forward_bytes` bounds how far a probe may grow the buffer on a forward-only
source; it does not restrict existing seekable-source checks or bytes already
buffered. The Brotli chain decode (see `format-detection`) reads `[0, end)`, and the
fields bound it: it runs only when `end` is within the prefix/far/scan ceiling and the
decode allowance covers it. The UDIF trailer is the same kind of fixed read: one
512-byte block on a cheap seek, with no budget field of its own, and that length is the
trailer allowance below. The PE tail probe (`format-detection`, *A ZIP in a PE's overlay
is found from its end record*) is the third: the 65 558-byte search span plus the fixed
parts of the two records it confirms (a 46-byte central header and a 30-byte local
header), 65 634 bytes in all, on the same cheap seek. That is the tail allowance below.
It has no budget field because its gate, a PE whose overlay runs past the scan window,
keeps it off every other source. It runs only when `max_scan_bytes` is above 0, is
recorded as `sfx_tail` *not enabled by policy* when that field is 0 and *capability
unavailable* when the source does not allow the read (a member stream, or a pipe whose
bytes run past the window, whose end is not known), and records nothing on a source its
gate excludes. Its bytes count in `unique_bytes_read` and not in `scanned_bytes`.

`max_decode_input` SHALL be one allowance for the whole `detect_format` pass, not a
limit per tier or per candidate: every tier that decodes draws on what earlier tiers
left, so adding tiers or candidates cannot multiply the compressed input a budget allows
decoded. Today four tiers draw on it. `max_decode_output` bounds the inner-TAR probe
only; a content probe's output is bounded by the codec's own drain (4 KiB, 64 KiB when
the whole source is in hand, and the sample length, up to 1 MiB, for the Brotli chain
decode) and is not charged to `decode_output`. That is deliberate for the chain decode
too: its output is mostly a copy of the input it was charged for. Each content probe is
charged the sample it was handed, whether or not a header check turned it away before
decoding; a probe the remaining allowance cannot cover does not run, and `content_probe`
is recorded *budget exhausted* (or *not enabled by policy* when `max_decode_input` is
0). The completion check is charged the whole source it decodes and records
`probe_completion` *budget exhausted* when the allowance cannot cover it (a zero
allowance stops the probes before any hit asks for completion), and *not enabled by
policy* when `completion_window_bytes` is 0. The Brotli chain decode is charged its
`end`-byte input ceiling before fetching input, and records `content_probe_decode` *budget exhausted* when the
allowance cannot cover that ceiling or `end` is past the prefix/far/scan ceiling or the 1 MiB
reach; the probe's verdict then stands. The inner-TAR probe caps its compressed input at
the smaller of what is left and 1 MiB, is charged whether its decode succeeds or fails,
and records `inner_tar` as *budget exhausted* when the cap cut it short or less than one
512-byte TAR header of output is left. Content-probe `read_at` seeks on cheap
random-access sources (path, non-`ArchiveStream` seekable streams) without growing the
prefix through `[0, offset)`, and take the part of a read the prefix already holds from
the prefix. Seekable expensive-seek sources retain buffer growth under the smaller
of 1 MiB and the budget's prefix/far/scan ceiling. Forward-only sources also obey
`max_probe_forward_bytes`. Required pipe buffer growth with a zero forward allowance
SHALL record `content_probe_read_at` as `NOT_ENABLED_BY_POLICY`; an insufficient
positive allowance or buffer-growth limit SHALL record `BUDGET_EXHAUSTED`. Header
seeks on cheap random-access sources SHALL NOT acquire an absolute-offset cap.
The source policy SHALL be checked before charging a chain decode, so a refused
forward read does not spend the decode allowance. Available pipe observations SHALL
NOT wait for optional bytes. An enabled pipe chain decode SHALL feed arrived chunks
until it fails, finishes, or reaches its input/output bound. Its input ceiling
remains charged when it finishes early.
Whole-source completion
remains governed by `completion_window_bytes`, independent of this forward allowance. A
far signature that ends past a positive `max_far_bytes` SHALL be recorded as `far_magic`
*budget exhausted* rather than searched in a window too short to hold it, unless the
source is provably too short to hold it anyway, and as *not enabled by policy* when
`max_far_bytes` is 0. An SFX scan that misses in a window a positive `max_scan_bytes`
made shorter than the 2 MiB structural bound SHALL be recorded as `sfx_scan` *budget
exhausted*, on the same carve-out, and as *not enabled by policy* when `max_scan_bytes`
is 0. An SFX scan in which any format reaches the rejected-candidate cap, or in which a
hit validator's view is clamped at the validator allowance, SHALL be recorded as
`sfx_scan` *budget exhausted* too, whether or not it answers. A near signature that ends
past a positive `max_prefix_bytes` SHALL be recorded as `near_magic` *budget exhausted*,
and as *not enabled by policy* when `max_prefix_bytes` is 0. The self-checking header
step needs one whole 512-byte block: a positive `max_prefix_bytes` under 512 SHALL
record `header_check` *budget exhausted*, and 0 SHALL record it *not enabled by policy*.

A receipt is within its budget when each bounded counter is at most `passes` times its
limit: `far_bytes`, `scanned_bytes`, `decode_input` and `decode_output` against the
field of the same name, and `unique_bytes_read` against the largest of
`max_prefix_bytes`, `max_far_bytes`, `max_scan_bytes` and the 4096-byte executable
header span (read under any prefix budget, so the layout matches a forced `format=`'s)
plus the probe-seek allowance, the trailer allowance, and, when `scanned_bytes` is
positive, the SFX validator allowance and the tail allowance. The validator allowance is
the smaller of `VALIDATOR_PEEK_MAX` and `max_scan_bytes`, the bytes a hit validator may
read past the window end to judge a candidate that starts inside it. The tail allowance
is granted on the same condition because the probe runs only after an SFX scan, and the
receipt can show that a scan ran but not that the probe did; a source that scanned
without probing gets the allowance unused, and a source that did not scan never gets it.
`prefix_bytes` is not compared, because it bills overlapping requests in full and
`unique_bytes_read` stands in for it. A receipt that is not within its budget SHALL
carry a *budget exhausted* or *capability unavailable* skip naming the tier that was cut
short. The library does not expose this check; the test suite asserts it.

#### Scenario: receipt reflects the source kind

- **WHEN** detection inspects a source listed below
- **THEN** its receipt and skipped tiers match the corresponding row.

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
| Signed PE with a 3 MiB overlay and a ZIP at its end, default budget | `ZIP`; `unique_bytes_read` ≤ scan ceiling + probe allowance + trailer allowance + tail allowance + validator allowance; `scanned_bytes` ≤ `max_scan_bytes` |
| The same PE under `FAST` | Probe runs; the same bound under `FAST`'s scan ceiling |
| The same PE as an `ArchiveStream` | Tail not read; `sfx_tail` recorded *capability unavailable*, not `trailer` |
| Ordinary signed PE larger than the window | No `sfx_tail` record; no tail read; within budget |
| Non-executable source (no SFX scan) | `scanned_bytes` 0, so no tail allowance in the bound |
| Stub-only `vol.exe` beside `vol.7z.001` | `SEVEN_Z`; the receipt includes the stub pass's SFX scan; `passes` 2; within two budgets, not one; a skip both passes record is kept once |
| `max_decode_output` below one 512-byte TAR header | Inner-TAR probe not run; `inner_tar` recorded *budget exhausted*; nothing charged |
| `max_decode_input` 0, zlib stream | No content probe runs; `content_probe` recorded *not enabled by policy*; `decode_input` 0; detection fails |
| `max_decode_input` smaller than the samples the probes ahead of zlib were charged | Probing stops before zlib; `content_probe` recorded *budget exhausted*; `decode_input` within the budget |
| Brotli chain decode of 270 KiB (a `.pyc`-shaped file), `BALANCED` | Decoded and charged; the claim is rejected; within budget |
| The same under `FAST` | Not decoded; `content_probe_decode` recorded *budget exhausted*; the `BROTLI` claim stands; within budget |

### Requirement: Detection budget presets

The system SHALL provide three presets, and `BALANCED` SHALL be the default. Preset
behaviour below is what detection **runs today**. `max_probe_forward_bytes` SHALL
be 0 for `FAST` and `BALANCED`, and 1 MiB for `THOROUGH`. Custom budgets SHALL
apply their numeric allowance without testing equality with a named preset.

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

- **WHEN** detection uses a preset on a case listed below
- **THEN** it performs the work specified in the corresponding column.

| Case | `BALANCED` | `FAST` | `THOROUGH` (today) |
| --- | --- | --- | --- |
| Ordinary ZIP / gzip / ISO at a known offset | Found | Found | Found (same tiers) |
| MZ stub + junk, no archive magic, `.zip` name | Extension `GUESS`; scan charged ≤ 2 MiB | Extension `GUESS`; scan charged ≤ 256 KiB | Same as `BALANCED` |
| ZIP behind a non-cueing prefix (JPEG + appended ZIP) | Not found | Not found | Not found — no tier looks for a ZIP trailer |
| `zipapp` (`#!` prefix + ZIP) | Not found — shebang is not an executable cue today | Not found | Not found |
| Exhaustive whole-source scan | Never | Never | Never (opt-in later, not by preset alone) |

| Additional pipe reads for a content-probe chain | Disabled; buffered bytes only | Disabled; buffered bytes only | Allowed through 1 MiB, within the read ceiling |

### Requirement: Non-seekable sources degrade explicitly, and are never spooled

Detection SHALL NOT buffer a whole pipe or spool it to a temporary file. Near and far
prefix evidence and cued forward scans SHALL still work through replay buffering; a
probe requiring additional pipe buffer growth SHALL record *not enabled by policy*
when `max_probe_forward_bytes` is zero. With a positive allowance, growth past the
smaller of that allowance, 1 MiB, and the read ceiling SHALL record *budget exhausted*. A positive allowance that cannot cover the
read SHALL record *budget exhausted* rather than attempt the read. Already-buffered
bytes remain available in either case.

#### Scenario: pipe behaviour

- **WHEN** detection reads a pipe listed below
- **THEN** it follows the corresponding capability and buffering policy.

| Case | Expected |
| --- | --- |
| Pipe, default budget, settled before the trailer step (ZIP, gzip) | Prefix tiers run; `unavailable_tiers` empty; no unbounded buffering |
| Pipe, default budget, reaches the trailer step (bzip2, xz or zlib, 512 bytes or more) | Prefix tiers run; tail not read; `trailer` recorded *capability unavailable* (see *receipt reflects the source kind*); no unbounded buffering |
| Detection finds a format whose backend cannot consume the source | `open_archive` raises the capability error rather than opening |
