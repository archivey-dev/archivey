# Prefixed and embedded archives

An archive does not have to start at byte 0. Something can sit in front of it — an
executable stub, a shell launcher, an unrelated file it was appended to — and the archive
is still a perfectly good archive. This page covers the machinery shared by every format
that can be found that way, and the places where a format's own structure changes the
answer.

The detector as a whole, with its step order, budget and tie rule, is on
[`detection.md`](detection.md); this page is the SFX step in depth. Format pages keep
their own half: [`formats/zip.md`](../formats/zip.md) §3 has ZIP's two offset
conventions, which are ZIP's and nobody else's.

## 1. Shapes in the wild

| Shape | Example | What is in front |
| --- | --- | --- |
| Self-extracting archive | `rar a -sfx`, `7z -sfx7zCon.sfx`, Windows installer stubs | A real executable that unpacks the payload |
| Script launcher | `zipapp` / `.pyz`, pex, shiv, Spring Boot executable JAR, makeself `.run` | A `#!` line and usually a few lines of shell or Python |
| Concatenation / polyglot | `cat stub payload.zip`, a JPEG with a ZIP appended | Anything at all |
| Embedded | An archive inside a firmware or disk image | Anything at all, usually far in |

The first two are meant to be *run*; the last two are not. Nothing in the bytes says which,
so the machinery below reports what it found and does not classify intent.

## 2. Ways to find one

Only the cued forward scan is shipped today.

| Tier | How it works | Bound | Status |
| --- | --- | --- | --- |
| **Tail probe** | Some formats locate themselves from the end, so no search is needed — only the willingness to look. | Set by the format (ZIP: 65 557 bytes) | **Designed, not shipped.** Held out of the default budget pending a seek-cost measurement |
| **Cued forward scan** | Leading bytes look like a prefix → search forward for each backend's declared needle. | `min(size, SFX_MAX)`, `SFX_MAX` = 2 MiB | **Shipped** |
| **Exhaustive scan** | Search the whole source, for a caller who knows they are holding a firmware image. | Caller's `max_scan_bytes` | Designed, not shipped |
| **Prefix analysis** | Do not search at all: read the stub, which for some families states where the payload begins and what made it. | None — one seek to the stated offset | An idea in [`IDEAS.md`](../IDEAS.md) |

**Prefix analysis is not a tier, which is why it is last.** A makeself `.run` is a shell
script that exports `SKIP` (the header's line count) and `COMPRESS`, so the payload offset is
`head -n $SKIP | wc -c` and the compressor is named outright — no window, no needle, and no
false `1f 8b 08` picked up from the script's own text. It also names compressors archivey
cannot read (`bzip3`, `lzo`) instead of reporting a needle miss. But it works only for stub
families somebody taught it, so it can never replace the scan; it can only short-circuit it.
The cost of promoting it is a corpus of current and old installers and a definition of "looks
like makeself" that does not turn into a second shell parser ([`IDEAS.md`](../IDEAS.md)
§Detection).

The scan runs second in the detector's order — near magic → **SFX scan** → far magic →
content probes → extension — and reports `PROBABLE` with `detected_by="sfx_scan"` and a
`payload_offset`.

`SFX_MAX` is shared by four call sites on purpose: the detector, `rar_parser`'s own scan,
`sevenzip_parser`'s, and the forward ZIP walk's (`zip_local_walk`, for a ZIP read from a
stream it cannot seek). The walk keeps its own scan loop because it must put back every
byte after the header it finds, which `scan_for_magic` does not return; it uses the same
window, `VALIDATOR_PEEK_MAX` allowance and validator. Separate bounds drift, and a stub the RAR parser accepts but
the detector does not is a file that opens under `format=RAR` and fails under auto-detect.

**The cue is two-tiered.** `WEAK` is the bare prefix — `MZ`, `\x7fELF`, or `#!`. `STRONG`
means the header structurally parses: a DOS header whose `e_lfanew` actually points at
`PE\0\0`, an ELF identification block whose class, encoding and version are all valid, or a
Mach-O header whose `cputype`/`filetype` or fat arch table parse. A strong cue with no
needle hit suppresses the content probes; a weak one does not.

**The cue does two jobs, and only one of them is about cost.** Deciding whether to spend
the scan window is a cost question (§3). Suppressing the content probes, which only a
`STRONG` cue does, is a correctness one, recorded in
[`format-detection`](../../openspec/specs/format-detection/spec.md) §"Executable-looking
prefixes must not silently become a wrong stream format" and settled by measurement in the
archived `sfx-format-detection` design. The failure that one prevents is not a wrong *error* but
a wrong *success*: a content probe claims a stream codec on a stub, and `open_archive`
returns a fabricated single-file member — `installer.uncompressed` — with no complaint. So
a structurally confirmed executable that contains no archive suppresses the probes
outright: it is not a compressed stream, and saying so costs nothing.

It has to be graded rather than a flat "skip probing executables", because two or four
bytes are not proof. Refusing a probe on a bare `MZ` would reject a genuine Brotli stream
whose first bytes happen to look executable, and the spec forbids fixing that by tightening
the probe instead: measured, a 16× larger prefix moves the false-positive rate 8.27% →
8.13%, and demanding decoded output loses real streams roughly one for one.

Worth knowing what the measurements did **not** show. Real PE binaries do not trip the
Brotli probe at all — 0 of 100 across MSVC, Go's own linker, MinGW-w64 and every `MZ` file
on the survey machine, because the canonical `MZ\x90\x00` DOS-stub prologue fails Brotli's
nibble check (97 of 100 carry `90 00`). The one measured collision between a probe and an
executable is a different probe: a zero-filled Mach-O stub came back `LZMA_ALONE`, since
`cf fa ed fe` passes the LZMA-Alone properties gate. So strong-cue suppression is an
invariant held on principle, not a patch for a common collision — the probes' real
false-positive problem is arbitrary data, tracked as threat-model O10.

Mach-O has no weak tier: its header either parses, giving `STRONG`, or it raises **no cue
at all** and the file is never scanned. It is never `WEAK`, because `ca fe ba be` is also
the Java class-file magic and a weak cue there would put every `.class` file through the
scan.

## 3. Cost is what tiers this, not false positives

Deciding *whether to scan* is about not reading 2 MiB from every file a caller opens — it
is not about keeping wrong answers out, which is the validator's job (§4) and, for the
probes, the `STRONG` tier's (§2). That distinction is easy to lose and was reasoned about
backwards in review, so it is worth stating plainly: **widening the cue is a cost decision;
hit validation is the correctness decision**.

The numbers behind the current gate, measured on a `/usr` tree:

- Widening the cue from "executable" to "prefix-shaped" (adding Mach-O and `#!`) enrolled
  **742 more files against 2 868 already scanned**, about 26% more. The newly enrolled ones
  are mostly small scripts — median 2 959 bytes, one file in 734 large enough to reach the
  window at all — so the whole tree cost **10.3 MiB** more, not the 2 MiB per script the
  bound alone suggests.
**The tail probe is gated the other way round.** Nothing can cue it: the front of a
prefixed ZIP looks like whatever the stub is, and a ZIP whose front *does* say `PK\x03\x04`
was already found by near magic. So it would cost one tail read on every source — free when
it finds a ZIP, since the reader goes on to read the EOCD anyway, and wasted otherwise,
which is most files. What that wasted seek costs on a cold cache or over a network is
unmeasured, and that is the open question. Which entry point the caller used is not:
`open_archive` and `detect_format()` run the same detection and waste the same read.

## 4. Validate the hit, do not trust the magic

Four bytes in a stub are not an archive. Every format that declares a scan needle also
declares a validator, and both the detector and the native parser scans report a hit
only after it passes. Forced `format=RAR` / `format=SEVEN_Z` used to take the first
structural match and open at a decoy; they now call the same validators.

| Format | Needle | Validator |
| --- | --- | --- |
| ZIP | `PK\x03\x04` only | Cheap LFH sanity: version-needed in range, no reserved general-purpose bits, known method id, non-empty name, name+extra inside the source. Rejects `PK\x03\x04` plus the zero-fill an ELF or PE stub pads with. EOCD confirmation is the tail probe's job, not this tier's |
| 7z | `37 7A BC AF 27 1C` | `StartHeaderCRC` over the 20-byte StartHeader, plus `offset + 32 + NextHeaderOffset + NextHeaderSize` landing at EOF |
| RAR | RAR3 and RAR5 markers | The CRC-checked main header that follows the marker |

ZIP's other two magics are deliberately **not** needles;
[`formats/zip.md`](../formats/zip.md) §2.1 has the reasoning, which is ZIP's own. The survey
below is the evidence behind it.

Validators return a `HitOutcome` rather than a boolean, so a later policy can treat a
damaged-but-identified payload as identified without changing any signature. `VALID_SHORT`
is a valid 7z hit whose declared end falls short of the known end of source: the scan keeps
it only as a fallback, so an archive that ends at end of file beats a decoy embedded in the
stub.

**Validation makes a hit trustworthy, not cheap.** It justifies reporting high confidence on
a hit; it does not justify removing the gate.

Evidence that this tier needs validating rather than locating: across **3 320 ELF and PE
files** under `/usr/bin`, `/usr/lib`, `/usr/local` and `/opt`, **zero** carried a real
appended ZIP, and all **six** `PK\x05\x06` tail matches were false positives — `zip`,
`zipnote`, `zipsplit`, `zipcloak`, `libzip.so` and `librevenge-stream.so`, each carrying the
signature as a string constant, every one parsing to nonsense (entry counts 19 280–55 381,
central-directory offsets past EOF).

## 5. Where the formats differ

The mechanism is shared; what a hit *means* is not.

**ZIP locates itself.** Its central directory is found from the end and its entry offsets are
corrected through the EOCD's own known position, so a prefixed ZIP needs no offset from the
detector to be readable. Two consequences follow. It is the only format the tail probe can
serve. And when the forward scan lands on a decoy needle, the reader usually still succeeds,
because it finds the real EOCD from the tail of the slice anyway. The two write conventions
that make its stored offsets differ — and why `payload_offset` is defined as the earliest LFH
rather than as the EOCD adjustment — are on [`formats/zip.md`](../formats/zip.md) §3.

**7z and RAR need the offset.** Their native parsers accept a start offset and read in place
with no copy. The parser scan (`scan_for_magic`) takes the same hit validator the
detector uses, so an invalid decoy is skipped rather than opened; if nothing
validates, the first identified candidate is the origin so a damaged payload still
reaches the parser. A 7z hit whose declared end falls short of the source is graded
`VALID_SHORT`: the scan keeps the first one as a fallback and looks on for a `VALID` hit
that ends exactly at EOF, so a CRC-valid decoy in a stub loses to the real payload
behind it.

**Compressed streams are a different search.** A makeself-style `.run` wraps a compressed
*stream*, not a container, so there is no container magic to find — the needle has to be a
codec header. Those needles are searched under the `#!` cue only, because a stub plus a bare
compressed stream is a real shape for script launchers and not for executable ones.

## 6. Sharp edges

**format** — inherent · **library** — upstream's · **archivey** — ours.

| What you see | Where | More |
| --- | --- | --- |
| A prefixed ZIP behind bytes that fire no cue (a JPEG polyglot, a plain concatenation) is not detected, though `open_archive(..., format=ZIP)` reads it | **archivey** | The tail probe is the tier that would find it (§2) |
| `detected_by="sfx_scan"` on a `zipapp`, a JPEG polyglot, or junk prepended to a tar | **archivey** | The name asserts intent the tier cannot know. `prefix_kind` is the field designed to report what the prefix actually is, and it is not shipped. Resolved 2026-09-25: kept, not renamed; `detected_by` is documented as an open set and `sfx_scan` as covering every prefixed hit |
| A prefixed archive on a non-seekable source may be missed entirely | **format** | The tail probe needs a seek; the forward scan needs a cue in the first bytes |

A defect worth remembering because it shows what the cue gate is really protecting: before
Mach-O was added, a macOS SFX stub matched no cue, and `cf fa ed fe` is *structurally
guaranteed* to parse as a Brotli uncompressed meta-block header. A PE stub and an ELF stub
both opened their real 7z members while the Mach-O one returned `BROTLI` with a single
fabricated `.uncompressed` member. A missing cost gate did not produce a missing answer; it
produced a confidently wrong one.

## 7. Decisions

| Choice | Why | Rejected |
| --- | --- | --- |
| One shared `SFX_MAX` for the detector and the native parsers' scans | Separate bounds drift into a file that opens under `format=` and fails under auto-detect | A bound per call site |
| `scan_for_magic` takes an optional `HitValidator` (same `(peek_more, remaining)` shape as the detector), returns earliest VALID, else earliest VALID_SHORT, else earliest identified, and caps rejected candidates at 256 | Parser scans had no hook, so a decoy ahead of the real payload made forced `format=` fail. Peek is served from the scan window (forward-only; source need not be seekable) | Seeking back to the origin to validate |
| The detector's scan uses the same 256-rejection cap (`MAX_VALIDATED_CANDIDATES`) for RAR and 7z, the formats whose parsers scan (`ReadBackend.SFX_PARSER_SCANS`), counted per format. Once a format is capped the scan stops searching for its needles, and a capped scan records `sfx_scan` as *budget exhausted* even when it answers. ZIP is never capped | Uncapped, a window of RAR decoys each declaring a 60 KB header cost 4-5 s per detection, and a file of decoys meant one thing to detection and another to forced `format=` (DR-23a). Each parser counts only its own format, so a pooled count let 256 ZIP decoys hide a RAR that `format=RAR` opens. The seekable ZIP reader finds the end of central directory from the tail and runs no scan, and the forward walk's scan is bounded by the window alone (its validator reads only the header and computes no CRC), so a ZIP cap refused a file `format=ZIP` lists. The cost: 2 MiB of back-to-back `PK\x03\x04` decoys still takes about 2 s per detection, one validation each, as before the cap existed. Skipping a capped format's hits one by one walked a one-format carpet hit by hit (0.19-0.25 s for 2 MiB of RAR decoys); not searching for its needles takes 0.015 s. A capped scan holding a short 7z hit answers with it, as the 7z parser does, but candidates past the cap were never judged | A budget field charging validator bytes; leaving the detector uncapped because its needle search is linear; one cap pooled across formats; capping ZIP too and accepting that detection refuses what `format=ZIP` opens |
| The window bounds where a magic may *start*; a validator may read `validator_allowance(budget)` past it, the smaller of `VALIDATOR_PEEK_MAX` (132 KiB) and `max_scan_bytes`, charged to the prefix | A view clamped at the window end made RAR accept a header it could not CRC, so the same bytes were `RAR` at the window end, rejected 1 MiB earlier, rejected on a pipe, and then `CorruptionError` at open. With every header in hand, no validator needs a "clamped, not evidence" branch. Scaling with `max_scan_bytes` keeps the budget field a bound (`detection.md` §4.1): a header that does not fit a small budget is rejected and the tier recorded as cut short | Treating a short peek as a clamp when `remaining` covers it; a constant allowance, which let an 8 KiB scan budget read 68 KB |
| Cue is a cost gate; validators are the correctness gate | Keeps two different questions from being answered by one mechanism, which is how the gate got reasoned about as false-positive defence | Treating the cue as the filter and skipping validation |
| Two-tier cue, with `STRONG` suppressing content probes | `MZ` is two bytes; a real Brotli stream may start with it. Only a structurally confirmed executable is strong enough to overrule a probe | One boolean cue |
| Mach-O raises no weak cue | `ca fe ba be` is Java class-file magic; a weak cue would scan every `.class` | Treating the magic as a weak cue like `MZ` |
| Opening an embedded archive is the right default | A caller who opens a file has a reason to think it is an archive; a sweep can filter on the prefix instead | Refusing anything that is not an archive end to end |
| Report what was found, do not classify the stub | The same tier finds an installer, a program and a polyglot; intent is not in the bytes | Deciding whether a file "is" self-extracting |
| Stub-only `vol.exe` follows every 7-Zip first-volume name (`exe.001`, `7z.001`, `zip.001`) | Opening the stub is what a caller does; supporting only the Linux name would make the same producer flag work on one OS and fail on the other | Following `exe.001` only; leaving the stub as `FormatDetectionError` |
| Old-scheme SFX `name.exe` + `name.r00` is volume 1 of that `.rNN` set | Same discovery as `name.rar` + `.r00`; a 7-Zip numbered stub has no `.r00` and still follows `.001` | Treating every `.exe` as maybe-volume (would `iterdir` on random executables) |

## 8. Verify

```bash
./scripts/test.sh tests/test_sfx.py tests/test_sfx_scan.py tests/test_detection.py \
    tests/test_detection_workspace.py
```

Corpus counts in §3 and §4 are measurements, not assertions — their provenance is the
investigation linked in §9, and the machine they were taken on is gone. Everything below is
behaviour a test holds.

| Claim |
| --- |
| One shared `SFX_MAX` across the detector and the native parsers' scans (§2, §7) |
| The forward ZIP walk's scan caps no rejected candidates and judges a header that crosses the window end on its whole length (§2, §7) |
| The scan is bounded, and a magic counts only when wholly inside the window |
| The cue is graded rather than boolean, and `STRONG` means the header structurally parses |
| Mach-O parses or raises no cue at all, so a `.class` file is never scanned |
| A fat Mach-O 64 header is read as `fat_arch_64` (cputype, cpusubtype, 64-bit offset and size, align, reserved) |
| The magic search is linear in the window and finds the same hits, in the same order, as a from-scratch search |
| A `STRONG` cue suppresses the content probes; a `WEAK` one does not, and a real Brotli stream still answers |
| The Mach-O defect in §6 is closed: a stub of each kind opens its real 7z members |
| A shebang non-archive costs at most the window, and detection leaves a non-seekable stream replayable |
| Each format's validator rejects its own decoy under every cue (§4) |
| Magic bytes quoted in script *text* are not a hit |
| The scan continues past a failed validation rather than giving up on the source |
| Forced `format=7z` / `format=RAR` skip an invalid decoy the same way |
| `scan_for_magic` validator: decoy then valid; fallback on reject-all; cap; no-validator unchanged |
| Forced-format scan falls back to a damaged or empty payload so the parser names the damage |
| 7z's declared end is checked against the source length, not the peek window, and costs one 32-byte peek |
| A candidate near the window end is judged on its whole header: a decoy is rejected there as it is inside the window and on a pipe, a real payload is found within budget, and every validator's largest peek fits `VALIDATOR_PEEK_MAX` |
| Detection and forced `format=` stop at the same per-format rejected-candidate cap for RAR and 7z; ZIP decoys never cap the scan, so a real RAR or ZIP after 256 of them is found as the forced format opens it; a capped scan holding a short 7z hit answers with it and records the scan as cut short; a capped format's needles are no longer searched |
| A held short 7z hit is displaced only by a later 7z that ends at end of source; a real ZIP after it does not displace it, since the end-of-source preference never reorders formats |
| Under a small scan budget the validator reads at most `max_scan_bytes` past the window |
| ZIP self-corrects from the tail, so a decoy hit does not move the answer (§5) |
| 7z and RAR are opened *at* the offset, and a format with no stub story refuses one (§5) |
| The shapes in §1 detect end to end: `zipapp`, a shebang concatenation, a real SFX |
| An uncued prefix (JPEG polyglot) is **not** detected — the §6 gap |
| Among CRC-valid 7z hits, one that ends exactly at EOF beats an earlier one that ends short |

**Building fixtures.** Most stubs here are synthetic — `MZ` plus filler, a seven-byte ELF
ident, a hand-built Mach-O header — because the cue only reads the leading bytes and a real
binary would add megabytes for nothing. Where the *payload* has to be real the tests build
one with `py7zr` or read a committed RAR fixture. Real end-to-end SFX artifacts are
generated rather than committed where the tool exists: `7z a -sfx7zCon.sfx` and
`rar a -sfx` both produce one in a few seconds, and both are on CI. PE and Mach-O stubs
cannot be produced on Linux, which is why those two are hand-built rather than generated —
the full stub matrix is task 4.3 of `prefixed-archive-detection`.

## 9. References

- Specs: [`format-detection`](../../openspec/specs/format-detection/spec.md) ·
  [`detection-cost`](../../openspec/specs/detection-cost/spec.md)
- In flight: `openspec/changes/prefixed-archive-detection/` (the four implementation blocks;
  Block 1 ships today; Block 2 and `prefix_kind` were struck on 2026-09-25) · decided against:
  `openspec/changes/archive/2026-09-25-detection-evidence-ledger/`
- Archived: `openspec/changes/archive/2026-08-21-sfx-format-detection/` ·
  `2026-08-31-detection-prefix-workspace/` · `2026-08-30-detection-format-gaps/`
- Investigation: [`archive-format-detection-algorithm.md`](../investigations/archive-format-detection-algorithm.md)
  — evidence classes, the tail-tier cost argument, the corpus counts above
- Code: `internal/sfx.py` (bound, cue, scan, `HitOutcome`) · `internal/detection.py` (tier
  order) · `internal/backends/zip_detect.py`, `internal/backends/sevenzip_detect.py`, `internal/backends/rar_detect.py` ·
  `internal/volumes.py` (sibling discovery)
