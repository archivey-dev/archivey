## Context

The SFX tier (`internal/detection.py` step 2, `internal/sfx.py`) runs when the leading
bytes raise an executable cue. It searches forward up to `min(SFX_MAX, max_scan_bytes)`
(2 MiB) for each backend's validated needle. The cue looks only at the first few bytes:
`_is_pe` checks that `e_lfanew` points at `PE\0\0` and reads nothing past it.

The ZIP tail probe was designed in `prefixed-archive-detection` (Block 2) and struck on
2026-09-25. Its notes ask a reopened tail probe to come as its own additive change, which
this is. `dev-docs/topics/prefixed-archives.md` §2–§3 explain why the probe was held back:
nothing cues it, so it would cost a tail read on every source. `dev-docs/IDEAS.md` carries
a related idea, "Bound the SFX search at the PE overlay".

## Goals / Non-Goals

**Goals:**
- Detect a ZIP appended far behind a PE stub (the install4j shape) without reading the
  tail of any file that cannot hold one.
- Answer a classic RAR / 7z / ZIP SFX from the PE's overlay start, so a decoy needle in
  the stub never competes with the real payload.
- One PE layout helper shared by detection and the RAR / 7z parser scans.

**Non-Goals:**
- ELF and Mach-O layouts. ELF's section header table usually ends the image, so its
  helper would be simple, but there is no real sample. Mach-O lays its segments out
  differently. Both wait for a user case.
- A ZIP inside a PE section past the window (no case seen; Squirrel's sits at 170 KB).
- Undoing installer obfuscation (install4j's XORed block) or naming installer families.
  That is the "prefix analysis" idea and stays in `IDEAS.md`.
- A new end-record search strategy for the ZIP reader. The search gains an upper bound,
  the payload end (§12), and nothing else: the window, the locator and the local-header
  fallback walk stay as they are (`format-zip`, *Report bytes after the end of a ZIP
  archive*).
- A tail probe for non-executables (JPEG + ZIP). That is still the struck Block 2.

## Investigations

Installers examined on 2026-10-26 (Windows downloads, not committed):

| File | Producer | Last section ends | Certificate | Payload | Today |
| --- | --- | --- | --- | --- | --- |
| `7z2601-x64.exe` | 7-Zip SFX | 46 080 | none | 7z at 46 080 | `SEVEN_Z`, found by scan |
| `winrar-x64-722.exe` | WinRAR SFX | 501 760 | 10 448 B at end | RAR at 501 760 | `RAR`, found by scan |
| `GitHubDesktopSetup-x64.exe` | Squirrel | 269 340 160 | 15 648 B at end | ZIP in `.rsrc` at 169 888 | `ZIP`, found by scan |
| `IRPF2026Win64v1.3.exe` | install4j | 690 176 | 10 496 B at end | 34 MB XORed block, then ZIP at 35 536 406 | **missed** |
| `Git-2.56.0.4-64-bit.exe`, `CursorUserSetup-…exe` | Inno Setup 7.0 / 6.4 | 1 395 200 / 944 640 | yes | Inno's own format | refused (correct) |
| `npp.8.9.8.1.Installer.x64.exe` | NSIS | 190 464 | yes | NSIS's own format | refused (correct) |
| `Claude Setup.exe` | (bootstrapper) | 7 188 992 | 10 400 B at end | none | refused (correct) |

- IRPF's end record is at 110 923 018, followed by 224 zero bytes and the certificate.
  `open_archive(format=ZIP)` lists 174 members and warns about the certificate as trailing
  data (`observed_bytes` 225).
- IRPF's 34 MB block, XORed back with `0x88`, holds three install4j JARs and a gzipped
  tar of a Java 17.0.16 runtime. A tail probe does not need any of this; it is recorded
  so nobody repeats the dig.
- The six `PK\x05\x06` false positives counted in `prefixed-archives.md` §4 (`zip`,
  `zipnote`, `zipsplit`, `zipcloak`, `libzip.so`, `librevenge-stream.so`) are ELF, so the
  PE gate excludes them. They also fail the record checks (entry counts 19 280–55 381,
  directory offsets past end of file).
- In both classic SFX installers the payload starts exactly at the overlay start. The
  7-Zip one also carries a 7z signature inside its own `.rdata` (offset 36 704), which
  today's validator has to reject.

## Decisions

### 1. Gate the tail probe on the PE layout, not on an installer allowlist
Probe only a PE whose payload end lies past the overlay start and past the scan window.
An ordinary program or DLL, signed or not, has no such overlay, so it never pays for the
tail read. A file that does pay is a large installer that already paid for a 2 MiB scan,
so the extra 64 KiB is small. **Rejected:** probe on any strong cue (pays on every large
signed program); an install4j marker check (covers only installers someone already looked
at, and depends on a private format); a new `max_tail_bytes` budget field (the gate does
the cost work; a field can come later as an additive change).

### 2. Read the layout from the prefix only
The DOS header, PE header, optional header data directories and section table normally
end within the first 1 KiB, inside `max_prefix_bytes`. The helper takes the prefix bytes
and returns `PeLayout(overlay_start, payload_end | None)`, or `None` when anything is out
of range or past the prefix. The certificate entry (data directory 4) holds a file offset,
not an RVA. It counts only when it starts at or past the overlay start and runs to the end
of the source. Anything else leaves `payload_end` at end of source. **Rejected:** a seek to
read a section table past the prefix (an extra access, for headers no real linker writes).

### 3. A valid hit at the overlay start beats every other needle
The overlay start is where the PE format itself says appended data begins, so it is
stronger evidence than "earliest needle" and than the 7z exact-end tie-break. Both
accepting outcomes count there: `VALID`, and `VALID_SHORT` for a 7z that ends before end
of source, whether a certificate or anything else follows it. This changes one answer: a
PE with a valid payload at its overlay start and another valid needle elsewhere in the
window now gets the overlay payload. It also bounds the scan cost `IDEAS.md` records for
"a 7z SFX with data after the archive", for every PE whose layout parses. A stub with no
parsable PE header (the bare `MZ` stub in
`test_short_7z_hit_scan_cost_is_bounded_by_the_window`) keeps today's rule. Every scan
bounded by `SFX_MAX` takes the same layout and rule: the detector, the RAR and 7z parsers,
and the forward ZIP walk, which reads the prefix before it scans and so has the layout.
`format=` and detection then agree, seekable or not (DR-23a). **Rejected:** treat the
overlay start as a hint only, scanning from 0 first (keeps every decoy in play and saves
nothing); accept only `VALID` there (a signed 7z SFX, the common case, would still read
the whole window); leave the forward ZIP walk on the earliest-needle rule (streaming
`format=ZIP` would open a decoy that detection skips); apply it only past the window (no
gain for the common case).

### 4. Search the span before the certificate, with the reader's locator
The probe calls `zip_parser.locate_classic_record` on a view that ends at `payload_end`.
Decision §12 gives the reader the same end, so the reader's search covers the same span
and finds every record the probe accepts, whatever the certificate's size and whichever
convention the ZIP's offsets use. **Rejected:** search only the last 65 558 bytes of the
file (misses a ZIP behind a large dual signature); leave the reader on its own tail search
and its local-header walk (the walk starts at `payload_offset`, which is the stub for a
ZIP whose offsets count from byte 0, so that file would have to be declined).

### 5. Confirm the record before answering
The checks in the spec cost two small reads: the first central header and the local
header it names. Requiring that local header to be at or past the overlay start rules
out a record whose "archive" would sit inside the program's own sections. A record that
declares no entries is declined: it has neither header to check, so 22 bytes of
`PK\x05\x06` and zeros would pass, and since `payload_offset` is the record's own base
(§10) nothing later would catch it. **Rejected:** read the whole central directory
(megabytes for a big archive); trust the record alone (the six false positives show why
not); accept an empty record (uncorroborated, and an empty ZIP behind a multi-megabyte
overlay is not a payload anyone needs found); require the record to end flush with the
payload end (IRPF has 224 zero bytes between them).

### 6. Report as `sfx_scan`, record as `sfx_tail`
`detected_by` stays `sfx_scan`, which the docs already define as covering every prefixed
hit. Confidence is `PROBABLE`, as for a scan hit. The tier name `sfx_tail` appears only in
`TierSkip` records, so a caller can tell why no tail read happened. **Rejected:** a new
`detected_by` value (it is an open set, but adding one for the same kind of evidence only
splits callers' matches).

### 7. The tail read is the trailer tier's read, ending at a given offset
`PrefixWorkspace.read_tail(length)` returns the last `length` bytes and records its
declines as `trailer`. The probe's span ends at the certificate start, so the method gains
an end offset and the name of the tier a decline is recorded under; the trailer step
passes `trailer` and end of source, the probe passes `sfx_tail` and the payload end. One
method keeps the cheap-seek rule (seek, restore the handle, never grow the prefix) in one
place. It also gains the accounting the spec asks for: bytes taken from the prefix are not
fetched again, and fetched bytes count in `unique_bytes_read`. **Rejected:** `read_at`
(it grows the prefix on an expensive-seek source and records `content_probe_read_at`); a
second tail method (two copies of the cheapness test, DR-23a).

### 8. The cost spec's Purpose note is amended at archive
The `detection-cost` Purpose says a ZIP tail probe "adds its own budget and receipt
fields". Decision §1 decides against a budget field, and the delta defines a tail
allowance instead. Purpose text is not part of a requirement delta, so the archive step
amends it by hand (task 4.4).

### 9. Decline ZIP64 end records in this change
ZIP64 needs the locator and the ZIP64 end record read and checked as well. No installer
seen needs it. A declined record leaves detection where it is today.

### 10. A tail-probe hit reports the EOCD-derived base
**Maintainer decision (davitf, review round 1, K1):** `payload_offset` for a ZIP found
from its end record is `base = (eocd − cd_size) − cd_offset`, with no read made to refine
it, and the field stays an `int`. `dev-docs/formats/zip.md` §3 now defines it as a safe
start that is exact when the evidence shows it: never after the archive's first member,
and exactly that member when the tier that found the archive saw it. The forward scan
sees the earliest local header and reports it; the tail probe sees only the end record
and reports the base.

The value is used, not only shown: `open_archive` hands it to the reader as the place to
start reading (`core.py`), and the ZIP reader cuts the source there. A value after the
first member cuts members off; `base` cannot be after any member, because every member is
at `base` plus a stored offset that is not negative. For a ZIP appended whole (install4j)
it is the ZIP's first byte. For one whose offsets count from the start of the file it is
0, which reads correctly, and which is defensible as the start: the ZIP's own numbers say
it starts there. Decision §11 moves the "was there a prefix?" question off this field.

A base-0 ZIP whose end record a certificate larger than 64 KiB hides from a search that
ends at end of file would not read from 0: the reader's fallback walk would meet the stub.
Decision §12 makes the reader's search end at the payload end, so that file reads too, and
Block 1 lands that before the probe exists.

**Rejected:** the first entry the directory lists (one read, but too late when the
directory is not in file order, which cuts members off); the minimum over the whole
directory (megabytes during detection, for a number that is then only a label);
`int | None` with `None` for "not known" (callers are told to test `payload_offset > 0`,
which raises `TypeError` on `None`, and only in the rare case a test suite does not
reach); a caller flag to ask for the exact value (public surface for a number few read).

### 11. `FormatInfo.prefixed` is the test for a prefixed archive
**Maintainer direction (davitf, review round 1):** stop using `payload_offset > 0` as the
test for a self-extractor; document the base-0 case and add a field if needed. The field
is `prefixed: bool = False`, `True` when detection had to recognise or skip leading bytes
before the archive's own structures, whether or not the archive's stored offsets count
them in. It is defined by the evidence, not by the archive's extent: a ZIP written in place
starts at byte 0 by its own numbers, yet detection still met a stub first, and that is
what a caller asking "is this a self-extractor?" wants. Today that is every `sfx_scan` hit; a later tier that finds a prefixed
archive by other evidence sets it too, which is why it is a field and not
`detected_by == "sfx_scan"`. `detected_by` says which evidence decided and is an open set,
so a caller matching one value would miss a new tier. It is added last in the dataclass,
so positional construction keeps working. It reaches `open_archive` callers through
`reader.format_info`; with `format=` passed there is no detection, and `format_info` stays
`None` as today.

`prefix_kind` / `PrefixKind` (`NONE` / `EXECUTABLE` / `SCRIPT` / `UNKNOWN`) was struck from
`prefixed-archive-detection` on 2026-09-25 because "`payload_offset > 0` already says
prefixed". Decision §10 ends that, so the need is back, but only for the yes/no answer.
**Rejected:** reviving `PrefixKind` (it classifies the prefix, which no caller has asked
for, and a bool can grow into it later); `detected_by == "sfx_scan"` as the documented
test (ties the question to one evidence value of an open set); keeping
`payload_offset > 0` and reporting a nonzero offset for a base-0 ZIP (needs the directory
read §10 rejects, or reports a start the ZIP's own numbers contradict).

### 12. A known payload end bounds the reader, and an identified certificate is silent
**Maintainer decision (davitf, review round 1 follow-up):** detection reports the
certificate table's start as `FormatInfo.payload_end` (`int | None`, `None` meaning the
region runs to the end of the source), `open_archive` passes it to `open_read` beside the
start offset, and the backend behaves as if handed a view of `[start, end)`. A backend
never reads before its start offset to find an end itself: that would break the
"as if a view" promise of `ReadBackend.open_read` and would not work on a stream. Under
forced `format=` the start is 0 and the stub is the backend's own first bytes. Every RAR,
7z and ZIP backend opened at 0 with no end reads those bytes and derives the same end with
the same helper, so both paths agree (DR-23a). For RAR, 7z and the ZIP forward walk these
are bytes their payload scan reads anyway. The seekable ZIP reader locates its archive
from the tail and never reads its start, so it gains one read of its first bytes for
this; without it, forced `format=ZIP` on IRPF would keep warning about the certificate
and fail under `STRICT` while auto-detect opens it.

A scan never accepts a candidate that starts at or past a known payload end. The
certificate table is not parsed, so a needle inside it could pass a validator, and the
payload would then start where its region has already ended. With that rule
`payload_offset < payload_end` always holds, in detection and in the forced path.

With the end known, the ZIP reader's end-record search stops there, and the trailing-data
checks of ZIP, 7z and RAR stop there too: a code-signed installer no longer warns about its
own certificate. This reverses the recorded 7z rule that "a self-extractor's tail (the
certificate table of a code-signed one) is reported too", by the maintainer's call: the
warning is for bytes nobody can explain, and these are explained. A tail between the
archive's end and the certificate is still reported. `unrar` reads the real file, so for
RAR the end bounds archivey's own checks only.

`None` is the common case here (every non-PE and every unsigned file), so code that
forgets it fails on the first ordinary file, unlike the rare-case `None` §10 rejects.
**Rejected:** readers reading the stub before their start offset (breaks the view
contract; impossible on a stream); passing the end through detection only (forced
`format=` would still warn and still miss a hidden end record); keeping the certificate
warning (a warning on every signed installer teaches callers to ignore the diagnostic).

## Risks / Trade-offs

- [The overlay-start rule changes an answer] → Only for a PE with a valid archive at its
  overlay start and another valid needle elsewhere in the window. No such file has been
  seen. The scenario pins the new answer, and every `SFX_MAX` scan follows it.
- [Remote sources pay one extra round trip on a gated PE] → Gated files are installers
  that already cost a 2 MiB read; recorded in `prefixed-archives.md` §3.
- [A crafted PE could point its certificate entry anywhere] → It counts only when it runs
  to end of source and starts at or past the overlay start; otherwise `payload_end` is end
  of file. Every offset is checked against the known length before reading.
- [Existing callers test `payload_offset > 0`] → It stays true for every hit that is not
  a base-0 tail-probe ZIP, and that shape is unlikely this far into a file: offsets counted
  from the file's start come from `zip -A` or a writer emitting the stub itself, and those
  ZIPs sit right after the stub, where the forward scan answers first. The docstring,
  `docs/opening.md` and the changelog point callers at `prefixed` (task 1.7).
- [The local-header walk for a large certificate is slow on a big ZIP] → It reads headers
  only, never member data, and has been the reader's fallback since before this change.

## Open Questions

- **Overlay start past the window.** A RAR / 7z stub larger than 2 MiB is not found today.
  The overlay-start check could reach it in one read, but then the parsers' scans must
  reach it too. Left out until a real file needs it.
