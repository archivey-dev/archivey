## MODIFIED Requirements

### Requirement: detect_format() returns a FormatInfo

The system SHALL expose:

```python
archivey.detect_format(
    source: str | Path | BinaryIO,
    *,
    config: ArchiveyConfig | None = None,
) -> FormatInfo
```

```python
class DetectionConfidence(Enum):
    CERTAIN = "certain"
    PROBABLE = "probable"
    GUESS = "guess"

@dataclass(frozen=True)
class FormatInfo:
    format: ArchiveFormat
    confidence: DetectionConfidence
    detected_by: Literal["magic", "extension", "content_probe", "sfx_scan", "directory"]
    payload_offset: int = 0
    diagnostics: DiagnosticSummary = DiagnosticSummary.empty()
    cost_receipt: DetectionCostReceipt | None = None   # compare=False; see detection-cost
    unavailable_tiers: tuple[TierSkip, ...] = ()       # compare=False; see detection-cost
    prefixed: bool = False
    payload_end: int | None = None
```

`config=None` → library default. `confidence` = magic / structural probe /
extension-guess. `prefixed` SHALL be `True` when detection found the archive behind bytes
that are not part of it (an executable stub, a `#!` launcher, any other prefix), and it is
the test for a self-extracting or otherwise prefixed archive. `payload_offset` is where to
start reading the archive: never after its first member, and exactly that member when the
detection step saw it. The two are separate facts: a ZIP whose stored offsets count from
the start of the file can be said to start at byte 0, so it MAY report `prefixed=True`
with `payload_offset` 0. `payload_end` is where the archive's region of the source ends
when detection identified something after it: today the start of a PE's Authenticode
certificate table (*Self-extracting (SFX) archives are detected behind an executable
stub*), whatever tier found the archive. `None`, the common case, means the region runs
to the end of the source. `open_archive` passes both bounds to the reader
(`archive-reading`). `cost_receipt` and
`unavailable_tiers` are part of this contract; `detection-cost` defines what they hold.
`FormatInfo` also carries a provisional `corroborated: bool` for `open_archive`'s own use,
which SHALL NOT be part of this contract: its `False` cannot tell an uncorroborated probe
from a result that was not a probe.

A **directory path** SHALL return `FormatInfo(format=DIRECTORY,
confidence=CERTAIN, detected_by="directory")` without reading anything, the same
format `open_archive` reads it as. Its `cost_receipt` SHALL be the zero receipt (one pass, no
bytes read). It SHALL NOT raise `IsADirectoryError` or any
other `OSError`. An empty string is not a directory path, although `Path("")` is
`Path(".")`: `detect_format("")` SHALL raise `ValueError` (`error-handling`).

A **path to a volume of a set** SHALL be detected on the source `open_archive` resolves
for it: any part of a numbered split set (`set.7z.002`, `set.zip.003`, `set.exe.002`) on
the parts joined in order, and a RAR continuation on volume 1. A middle part has no magic
at offset 0, so detecting the named file alone would refuse a path `open_archive` opens.
That resolution runs before detection reads a byte and MAY raise what `open_archive`
raises for the same path: a numbered set with a gap SHALL raise `TruncatedError` naming the
missing part. A lone first part (`set.zip.001` with no other part) SHALL be detected as the
format its bytes show; `open_archive` refuses it as an incomplete set.

**Collectors:**

| Path | Behavior |
| --- | --- |
| Standalone `detect_format` | One finite collector; policy/callback/logging/budget; final summary on `FormatInfo.diagnostics` |
| Inside `open_archive` | Open creates prospective-reader collector + detection watermark, passes that collector into detection. On success the reader owns it — no seed/merge/replay/copy; each retained occurrence charged once. Internal detection-range `FormatInfo.diagnostics` is not retained after handoff; same events remain on the reader's cumulative summary |

#### Scenario: detect / handoff matrix

| Case | Expected |
| --- | --- |
| Standalone detect with magic/extension conflict | `FormatInfo.diagnostics` has exact conflict count + retained detail under default budget |
| Auto-detect inside `open_archive` retains conflict, open succeeds | Reader continues same collector/order/budget; no copied aggregate |
| Magic match | `confidence=CERTAIN`, `detected_by="magic"`, `prefixed=False` |
| RAR, 7z or ZIP found by the SFX scan at offset N | `detected_by="sfx_scan"`, `prefixed=True`, `payload_offset == N` |
| ZIP found from its end record behind a PE stub, offsets counted from the ZIP's start | `prefixed=True`, `payload_offset` = the ZIP's first byte |
| The same, offsets counted from the start of the file | `prefixed=True`, `payload_offset` 0 |
| Signed PE SFX, any tier | `payload_end` = the certificate table's start |
| Unsigned PE SFX, or no PE layout | `payload_end` is `None` |
| Extension-only guess | `confidence=GUESS`, `detected_by="extension"` |
| Directory path | `format=DIRECTORY`, `confidence=CERTAIN`, `detected_by="directory"`; zero `cost_receipt`; no `OSError` |
| Empty string `""` | `ValueError`; the current directory is not detected |
| Any part of a numbered split set, or a RAR continuation | The format, `detected_by` and `payload_offset` `open_archive` reports for the same path |
| Numbered set with a gap (`set.zip.002`, no `set.zip.001`) | `TruncatedError` naming the missing part, from `detect_format` and `open_archive` alike |
| Lone first part (`set.zip.001`, no other part) | The format its bytes show; `open_archive` raises `TruncatedError` |
| Explicit `diagnostic_policy` on detect | IGNORE/COLLECT/RAISE applies to that finite detection |

### Requirement: Self-extracting (SFX) archives are detected behind an executable stub

SFX RAR/7z/ZIP: EXE stub precedes payload. If leading bytes look like executable
(`MZ` / ELF) rather than archive magic, the system SHALL scan for RAR
(`52 61 72 21 1A 07`), 7z (`37 7A BC AF 27 1C`), or ZIP local-header
(`50 4B 03 04`) magic within a bounded forward window equal to the shared
`SFX_MAX` constant (today 2 MiB; same binding as the RAR and 7z SFX scanners)
before running content probes. Match → embedded format
with `payload_offset` = payload start and `detected_by` indicating an SFX scan.
No match → fall through per the differentiation policy from the sibling
requirement, which is graded by cue strength: a strong cue suppresses the content
probes, a weak one does not. "No silent fabricated member" is therefore guaranteed for
a **strong** cue only — see that requirement for the measured reason.

Which magic the scan hunts for SHALL be **backend-declared data**, like every other
detection signal, rather than a table maintained inside the detector. A backend declares
only the magic that can legitimately begin an appended payload: ZIP declares its
local-file header and NOT the end-of-central-directory or spanned markers, which as
needles inside a 2 MiB stub window would claim any executable containing those four
bytes.

Native RAR/7z parsers SHALL accept a start offset (read in place, no copy). ZIP
already locates the EOCD from the tail, so a leading stub is tolerated without a
separate parser scan; detection still SHALL return `ZIP` with `payload_offset`
rather than a stream codec when the ZIP needle matches.

**Overlay start first.** When the source starts with a PE whose section table the
detection prefix holds, its *overlay start* is the end of the furthest section's raw data,
and its *payload end* is the start of an Authenticode certificate table that runs to the
end of the source, or the end of the source when there is none. When the overlay start
lies inside the window, the candidate there SHALL be judged first, with the same
validators. A hit there that its validator returns as `VALID` or `VALID_SHORT` SHALL be
the answer, ahead of any needle before or after it in the window: the exact-end
preference below is a tie-break between needles of unknown standing, and the PE's own
layout outranks it. When nothing at the overlay start is accepted, the scan below runs
unchanged. Every other scan bounded by `SFX_MAX` SHALL apply the same rule — the RAR and
7z parsers' scans and the forward ZIP walk that reads a non-seekable source — so forced
`format=`, seekable or not, opens the same payload. A PE whose layout does not parse SHALL
be scanned as today.

The scan takes the **earliest** matching needle in the window that its format's hit
validator accepts, and resumes past one it rejects. A 7z hit whose declared end falls
short of a known end of source (`HitOutcome.VALID_SHORT`) is kept only as a fallback: the
scan goes on, and a later 7z hit that ends exactly at end of source wins over it, so a
stub that embeds a whole small 7z archive does not hide the real payload after it. With no
such later hit the short one is used, which keeps a 7z followed by trailing data readable.
A held short hit SHALL be displaced only by a later `VALID` hit of the **same** format. A
`VALID` hit of another format SHALL end the scan, and the held short hit SHALL be the
answer: the exact-end preference is a tie-break within one format and never reorders
formats, so the earliest accepted needle still decides between them.

The window bounds where a magic may **start**, not how far its validator reads. A
candidate that starts inside the window SHALL be judged on its whole header, read up to
the smaller of `VALIDATOR_PEEK_MAX` and `max_scan_bytes` past the window end, so under the
presets the same bytes give the same answer at the window end, inside the window, and on
a non-seekable source. A header that does not fit that allowance SHALL be rejected and
`sfx_scan` recorded as *budget exhausted*.

The scan SHALL cap rejected candidates only for a format whose parser runs its own capped
scan (RAR and 7z), and SHALL count them per format, as each of those parsers counts its own
format's. Decoys of one format SHALL NOT spend another's allowance. A format whose reader
runs no such scan SHALL NOT be capped: ZIP already locates the end of central directory
from the tail, so a cap on ZIP candidates would refuse a file that forced `format=ZIP`
opens. With both rules, a file of decoys means the same thing to detection as to a forced
`format=`. After `MAX_VALIDATED_CANDIDATES` (256) rejected candidates of a capped format,
the scan SHALL stop searching for that format's needles, so its later candidates are not
judged, and SHALL record `sfx_scan` as *budget exhausted*, whether or not it answers.

#### Scenario: SFX matrix

| Case | Expected |
| --- | --- |
| `MZ` + 7z magic at offset N | `SEVEN_Z`, `payload_offset == N`; backend opens at N |
| `MZ` + RAR magic at offset N | `RAR`, `payload_offset == N`; backend opens at N |
| `MZ` + ZIP local magic (`PK\x03\x04`) at offset N | `ZIP`, `payload_offset == N`; real ZIP members listed |
| `MZ` + low-entropy filler + RAR/7z/ZIP magic in window | Same as above — **not** `BROTLI` / fabricated single-file member |
| **Strong** executable cue (validated PE / ELF), no RAR/7z/ZIP in window | No content probe runs; extension guess or `FormatDetectionError` — never a fabricated member |
| **Weak** executable cue (bare `MZ` / `\x7fELF`), no RAR/7z/ZIP in window | Content probes run unchanged, so a probe may still claim the stub — the accepted residual, per the sibling requirement and `dev-docs/topics/detection.md` |
| Stub containing a decoy needle the validator rejects | The scan resumes past it and finds the real payload |
| RAR decoy whose header (bad CRC) crosses the window end | Rejected, as at any offset inside the window and on a pipe |
| Real RAR whose main header crosses the window end | `RAR`, `payload_offset` at its marker; receipt within budget |
| A header that crosses the window end by more than a small `max_scan_bytes` allows | Rejected; `sfx_scan` recorded *budget exhausted*; the tier reads at most twice `max_scan_bytes` |
| 256 rejected RAR decoys before the real RAR payload | No `sfx_scan` answer; `sfx_scan` recorded *budget exhausted*; forced `format=RAR` raises `CorruptionError` naming the cap |
| 256 rejected ZIP decoys before a real RAR payload | `RAR` at its marker, as forced `format=RAR` opens it; nothing recorded as cut short |
| 256 rejected ZIP decoys before a real ZIP payload | `ZIP` at its local header, as forced `format=ZIP` opens it; nothing recorded as cut short |
| A window filled with one capped format's decoys | That format's needles are no longer searched after the 256th rejection; the scan does not walk the rest of its decoys |
| Whole valid 7z in the stub, then 256 rejected 7z decoys, then the real 7z | The embedded 7z, as the fallback forced `format=SEVEN_Z` also takes; `sfx_scan` recorded *budget exhausted* |
| Stub containing a whole valid 7z before the real 7z payload | The real payload, which ends at end of source; the embedded one is only a fallback |
| Whole valid 7z in the stub, then a real ZIP payload | `SEVEN_Z` at the stub's 7z: a `VALID` hit of another format does not displace a held short hit |
| A valid 7z followed by trailing bytes, nothing later | That 7z, at its offset |
| Bare brotli / non-executable stream | Unchanged content-probe behaviour |
| Strong cue, no archive in the stub, exactly one of `vol.exe.001` / `vol.7z.001` / `vol.zip.001` beside it | `detect_format` reports that volume's format; `open_archive` (including with `format=` matching that container) opens the set |
| Same stub, but it *does* contain archive magic | The embedded archive; sibling volumes are ignored |
| Two of those first-volume names beside the stub | `UnsupportedFeatureError` naming both |

#### Scenario: overlay start

| Case | Expected |
| --- | --- |
| PE, RAR or 7z starting exactly at the overlay start | That archive, `payload_offset` = overlay start; forced `format=` opens the same offset |
| PE with a valid ZIP local header in a section, a valid RAR at the overlay start | `RAR` at the overlay start, not the earlier ZIP |
| PE with a valid ZIP local header in a section, a valid ZIP at the overlay start, read through forced `format=ZIP` from a pipe | The forward walk lists the ZIP at the overlay start, as detection reports |
| Signed PE, 7z at the overlay start ending where the certificate starts | That 7z (`VALID_SHORT`), accepted at once; the scan does not read on to the window end |
| Unsigned PE, 7z at the overlay start ending 1 KiB before end of source, a second 7z later in the window that ends at end of source | The 7z at the overlay start, through detection and forced `format=SEVEN_Z` alike |
| Bare `MZ` stub with no PE header (no layout) and a 7z followed by trailing data | Unchanged: the short hit is a fallback and the scan reads the window |
| PE with a config block between the last section and the 7z (`7zS.sfx` style) | Nothing accepted at the overlay start; the forward scan finds the 7z as today |
| PE whose ZIP is inside `.rsrc` (Squirrel) | Nothing at the overlay start; the forward scan finds the ZIP as today |
| PE whose section table lies past the detection prefix, or does not parse | No layout; scanned as today |
| ELF or Mach-O stub | Scanned as today |

### Requirement: Detection's access shape is bounded, not only its byte count

Detection SHALL perform **one forward-only pass** over the prefix from the detection
origin. Bytes already in the prefix buffer SHALL NOT be fetched again. The trailer tier,
when it runs, SHALL add one seek towards the end, one read of its block, and one seek
back to the end of the prefix. Those bytes are not kept, so a later tier that reads
them as part of the prefix fetches them again. The PE tail probe (*A ZIP in a PE's overlay
is found from its end record*), when it runs, SHALL add one seek towards the end and one
read of its span, at most two reads of fixed record parts the span does not already hold
(the first central header and the local header it names), and one seek back to the end of
the prefix. No other backward seek re-reads the prefix. The exit restore of a seekable
caller stream is the non-consumption contract.

This holds for every source kind. A network range reader pays for the prefix pass and,
when the trailer runs, one range for that block; a member stream (`ArchiveStream`) is
not asked for the trailer, because a rewind would re-decode, and it decodes the prefix
forward once. That holds whether the member stream reaches detection bare, under a
pass-through buffer, wrapped in the `ArchiveSource` that `open_archive` builds, or as a
volume in a list passed to `open_archive`. A source that is not asked records `trailer`
as *capability unavailable* (detection-cost), unless it is shorter than the 512-byte
block: then there is no block to miss and nothing is recorded. The rule is stated flatly rather than
derived from a cost model because `StreamCapability` cannot distinguish a cheap seek
from an expensive one.

Resolving an exact `payload_offset` through a central-directory walk does not fit this
shape — the directory is reached backwards from the end and points backwards again. Offset
resolution is therefore separable from identification, and no tier does it. A ZIP found
from its end record reports the EOCD-derived base, which needs no walk.

#### Scenario: access-shape matrix

| Case | Forward reads | Seeks toward end | Backward seeks |
| --- | --- | --- | --- |
| gzip at offset 0, seekable stream | 1 pass | 0 | **0** |
| ISO far magic, seekable stream | 1 pass | 0 | **0** |
| Seekable bzip2 or xz larger than the prefix, no `koly` block | 1 pass, then the rest of the file for the inner-TAR probe, which fetches the trailer bytes again | 1 | 1, back to the end of the prefix |
| `koly` hit on a seekable image larger than the prefix | 1 prefix pass; the trailer bytes are fetched once | 1 | 1, back to the end of the prefix |
| Gated PE, ZIP found from its end record, directory inside the span | 1 prefix pass, the span, the local header | 1 | 2: to the local header, back to the end of the prefix |
| Gated PE, directory and local header both before the span | 1 prefix pass, the span, two fixed record parts | 1 | 3: to the central header, to the local header, back to the end of the prefix |
| Non-seekable source, any tier | 1 pass | 0 | **0** |
| Member stream (`ArchiveStream`), bare, buffered, through `open_archive`, or one volume of a list, any tier | 1 pass | 0 | **0** |

The backward-seek column does not count the exit restore of a seekable caller stream.

## ADDED Requirements

### Requirement: A ZIP in a PE's overlay is found from its end record

When the forward scan of *Self-extracting (SFX) archives are detected behind an executable
stub* finds nothing, detection SHALL look for a ZIP end-of-central-directory record before
the payload end, but only when all of these hold: the source starts with a PE whose layout
parses (same definitions as that requirement); the source length is known; the payload end
lies past both the overlay start and the end of the scan window; and the source allows the
read the trailer magic step makes, a cheap seek that restores the handle and does not grow
the prefix. The search SHALL cover the 65 558 bytes ending at the payload end, the same
span the ZIP reader searches, with the same locator. That span ends at the payload end, not
necessarily at end of source, and the part of it the prefix already holds SHALL be taken
from the prefix. A source that does not allow the read SHALL be recorded under `sfx_tail`,
never under `trailer`, so the two tiers' records cannot be confused.

A record found there SHALL be accepted only when all of these hold: both disk numbers are
0 and its two entry counts are equal; `cd_start = eocd − cd_size` and
`base = cd_start − cd_offset` are not negative; the four bytes at `cd_start` are a central
header signature (or `cd_size` is 0 for an empty archive); and the first central header's
local-header offset plus `base` is at or past the overlay start and holds a local header
signature. A record with ZIP64 placeholder values SHALL be declined. Accepted →
`ZIP` / `PROBABLE` / `detected_by="sfx_scan"`, with `payload_offset` = `base`. No read is
made to refine it. `base` is never after any member's local header, so `open_archive`
reads every member from it. It is the ZIP's first byte when the ZIP's offsets count from
its own start, and 0 when they count from the start of the file; `prefixed` is `True`
either way. The reader searches for the end record before the same payload end the probe
used (`format-zip`), so it finds every record the probe accepts. Declined → detection
continues with far magic, as after a scan miss today.

#### Scenario: tail probe matrix

| Case | Expected |
| --- | --- |
| Signed PE, 3 MiB of overlay filler, then a ZIP, then zero padding and a certificate | `ZIP`, `payload_offset` = the ZIP's first byte (its first local header); `open_archive` lists every member |
| Same, unsigned (ZIP ends at end of file) | `ZIP`, as above |
| Same, ZIP written in place (offsets counted from byte 0) | `ZIP`, `payload_offset` 0; `open_archive` lists every member |
| Same, ZIP's central directory not in file order | `ZIP`, `payload_offset` = the ZIP's first byte, before every member; `open_archive` lists every member |
| Same, ZIP followed by a certificate larger than 64 KiB | `ZIP`: the probe's and the reader's searches both end at the payload end; `open_archive` lists every member |
| ZIP written in place, followed by a certificate larger than 64 KiB | `ZIP`, `payload_offset` 0; `open_archive` lists every member |
| PE whose overlay holds only a certificate (an ordinary signed program) | No tail read |
| PE no larger than the scan window | No tail read: the scan covered the file |
| PE carrying `PK\x05\x06` as a string constant near its end (counts or offsets that point nowhere) | Declined |
| PE whose end record is valid but whose first local header lies inside the sections | Declined |
| End record with ZIP64 placeholders | Declined |
| ELF or Mach-O stub with an appended ZIP past the window | Not found, as today |
| Pipe or member stream | No tail read; `sfx_tail` recorded *capability unavailable* |
| `max_scan_bytes` 0 | No tail read; `sfx_tail` recorded *not enabled by policy* |
