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
- Changing the ZIP reader's end-record search. It already falls back to walking local
  headers when a long tail hides the record (`format-zip`, *Report bytes after the end of
  a ZIP archive*).
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
For a certificate under about 64 KiB this is the reader's own window. For a larger one the
probe finds a record the reader's tail search misses, and the reader then reaches it
through its local-header walk, so detection never promises a file the reader refuses.
**Rejected:** search only the last 65 558 bytes of the file (misses a ZIP behind a large
dual signature); teach the reader the certificate too (a reader change for a speed-up
only; it can follow).

### 5. Confirm the record before answering
The checks in the spec cost two small reads: the first central header and the local
header it names. Requiring that local header to be at or past the overlay start rules
out a record whose "archive" would sit inside the program's own sections. **Rejected:**
read the whole central directory (megabytes for a big archive); trust the record alone
(the six false positives show why not).

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
amends it by hand (task 3.4).

### 9. Decline ZIP64 end records in this change
ZIP64 needs the locator and the ZIP64 end record read and checked as well. No installer
seen needs it. A declined record leaves detection where it is today.

## Risks / Trade-offs

- [The overlay-start rule changes an answer] → Only for a PE with a valid archive at its
  overlay start and another valid needle elsewhere in the window. No such file has been
  seen. The scenario pins the new answer, and every `SFX_MAX` scan follows it.
- [Remote sources pay one extra round trip on a gated PE] → Gated files are installers
  that already cost a 2 MiB read; recorded in `prefixed-archives.md` §3.
- [A crafted PE could point its certificate entry anywhere] → It counts only when it runs
  to end of source and starts at or past the overlay start; otherwise `payload_end` is end
  of file. Every offset is checked against the known length before reading.
- [The local-header walk for a large certificate is slow on a big ZIP] → It reads headers
  only, never member data, and has been the reader's fallback since before this change.

## Open Questions

- **`payload_offset` for a tail-probe hit.** The spec says the first central header's local
  header plus `base`. Every writer seen lists entries in file order, so that is the earliest
  local header, but the ZIP format does not promise it. The alternatives are `base` (0 for
  a ZIP written in place, which hides the stub) or the minimum over the whole central
  directory (exact, but reads all of it during detection). Recommendation: first entry.
- **Overlay start past the window.** A RAR / 7z stub larger than 2 MiB is not found today.
  The overlay-start check could reach it in one read, but then the parsers' scans must
  reach it too. Left out until a real file needs it.
