# Design — salvage, step 1

## Context

Salvage was planned in three steps, from the narrowest to the widest:

| Step | What | Where it stands |
| --- | --- | --- |
| Keep iterating past a damaged member | A member's data error does not end the pass | **Done** for damaged data, in every format (below) |
| A damaged decode keeps its good prefix | The bytes before a decode error do not depend on the read size | This change, §B |
| RAR: go on past a damaged header as `unrar` does | List the members after a header whose CRC fails | This change, §A |
| ZIP local-header walk, TAR resync | Find headers by searching the bytes | Later, opt-in (§Later steps) |

### What already works

Measured on `main` (d4ea424), with `stream_members()` in both access modes:

| Damage | archivey | Reference tool |
| --- | --- | --- |
| One member's data, ZIP / 7z / RAR, solid or not (`tests/fixtures/damaged_member/`) | That member raises from its read; the later members are yielded and read; the pass ends cleanly. In a solid block, the later members of that block raise too | `7z t`, `unrar t`: the same members fail |
| ZIP, one member's local header signature | That member raises `CorruptionError`; the other three read | `unzip -t`: the same |
| ZIP, a central-directory entry's signature or name length | All four members listed from their local headers, then `CorruptionError` | `unzip -t`: lists only the first; 7-Zip: "Headers Error" |
| `archivey test` / `extract` on a damaged RAR member | `2 OK, 1 failed`; extract writes `a.txt` and `c.txt` | `unrar t`: the same |
| **RAR, one FILE header's CRC** | 2 of 6 members, then `CorruptionError` | `unrar lb`: 6 of 6, exit 3 |
| **TAR, one header's checksum** | 1 of 4, then `CorruptionError` | GNU tar: 3 of 4, "Skipping to next header" |

So "keep iterating past a damaged member" needs no new work for data. The rows in
bold are what is left, and both are damage to a member *header*. RAR is in this change.
TAR is in §Later steps, because GNU tar finds the next header by a search.

## A. RAR: go on past a damaged header

### What `unrar` actually does

The `format-rar` spec and `formats/rar.md` §1 say that `unrar` "searches past the
damage". It does not. From the unrar source (`arcread.cpp`, `ReadHeader50` and
`ReadHeader15`; read in 5.80, and the 7.00 behaviour below agrees): on a CRC mismatch it
reports "the file header is corrupt", sets `BrokenHeader`, **parses the damaged header
anyway** ("Report, but attempt to process"), and sets
`NextBlockPos = CurBlockPos + HeadSize + DataSize` from the damaged header's own
fields. Nothing searches. `SearchBlock` only calls `ReadHeader` again until it gets a
header of the type it wants. With encrypted headers it stops (`return 0` when
`Decrypt`).

Measured on unrar 7.00, fixture `basic_nonsolid__.rar` (RAR5), third FILE header
(`subdir/file2.txt`, offset 129):

| Byte damaged | `unrar lb` | `unrar x` |
| --- | --- | --- |
| Last byte of the header | All 6 listed, "subdir/file2.txt - the file header is corrupt", exit 3 | All 6 written; `file2.txt` tests OK (its data CRC is intact) |
| Third byte of the name (`b` to `X`) | All 6 listed, one as `suXdir/file2.txt` | **`suXdir/file2.txt` written**, data CRC OK, exit 3 |
| The header-size vint | 3 listed, then "Corrupt header is found", "Unexpected end of archive" | The same 2 members, then the errors |

The RAR 1.5-4 twin (`basic_nonsolid__rar4.rar`) gives the same results. So `unrar`
trusts the damaged header twice: its sizes say where the next header is, and its other
fields are used to list and extract the member.

### The rule

When a header after MAIN fails its CRC (today: `_RarHeaderCrcError`, recorded in
`RarArchive.damaged`), and it is not taken as a damaged end block:

1. **Find the next position from the damaged header**, as `unrar` does: its start plus
   the header size plus the data size, both read from the damaged bytes (RAR5: the size
   vint and, when the flags say so, the data-size vint; RAR 1.5-4: `HEAD_SIZE`, plus
   `ADD_SIZE` or the FILE header's packed size, including the high 32 bits when the
   flags say so). If a field does not parse, or the position is not after the damaged
   header, stop.
2. **Confirm it**: read one header at that position. It must be inside the volume,
   pass its own CRC, and be a type that can follow MAIN (RAR5: FILE, SERVICE, ENDARC;
   RAR 1.5-4: FILE, NEWSUB, ENDARC and the old sub-block types the walk already accepts).
   Its own fields must parse, as for any header. If it does not pass, stop where the
   walk stops today.
3. **Go on** from that header with the ordinary walk. The damaged header is **not
   listed** (decision 1). Its span (`damaged_at`, `resumed_at`) is recorded.

Each later damaged header gets the same rule. The walk reads each header once, so the
cost grows with the number of headers and the walk makes no extra reads on an intact
archive. A damaged span is retained as a small record. The records are capped as
`_MAX_DAMAGED_SERVICE_HEADERS` caps damaged service headers today, and past the cap only
a count is kept (DR-9).

What ends the pass does not change: a `CorruptionError`, now raised **after the last
member the walk reached**, and naming the first damaged header. This is the path a
damaged end block and a missing middle volume already take (DR-2: "read past the gap.
list everything in all available parts, then raise at the end"). `members()` and
`get()` still raise it. `members_report()` returns every member reached and this error.
`extract_all()` writes every member reached, then raises.

**Volumes.** The walk goes on inside the volume. Whether the walk continues into the
next volume is decided as today, by the last intact member header. With a resumed walk,
that is the real last member, not the member before the damage.

**Encrypted headers.** The walk stops at the damage, as today and as `unrar` does. Even
with the password proven, the next header's IV would come from a size that no CRC
has checked, and `unrar` does not go there either (DR-6, and less code).

**MAIN.** A damaged MAIN header still raises at open. Its flags are needed to read the
rest.

### Why confirm, when `unrar` does not

The confirmation is the only place this design is stricter than `unrar`. It is the
"could the lenient behaviour hide bytes or weaken a check" factor in "When consistency
and the official tool disagree", and it is how DR-2's "reopen if" is met: the walk
trusts the damaged header's sizes only after the next header's CRC has vouched for
them. When the confirmation fails, `unrar` also fails in practice: it parses garbage and
reports "Unexpected end of archive" (the third row above). So the listing matches
`unrar` wherever `unrar` gets a correct result.

The confirmation is one CRC on one header, read at one position. A false
confirmation needs a damaged size field that points at bytes which happen to pass a
CRC: 2⁻³² for RAR5, 2⁻¹⁶ for RAR 1.5-4. The type check and the field checks lower that
further. A search would test a CRC at every byte offset. On a 1 GB RAR5 archive that
expects about 0.25 false headers, which is why a search is not in this step.

### Decisions

**Decision 1 — the member whose header is damaged. Recommendation: skip it.** The walk
uses the damaged header's sizes, which the next header has confirmed, and nothing else
from it. The member is not listed. The diagnostic says where it was and how many bytes
were skipped.

- *Why not list it, as `unrar` does:* its fields have no check. The name, the type,
  the mode, the times and the encryption flags can all be wrong, and the third row
  above shows `unrar x` writing a wrong path. The data CRC does not help. It covers the
  data, not the header, and a header with a wrong name and intact data passes it. DR-1
  ranks a wrong value below a reported absence, and `formats/rar.md` §6 already refuses
  to list a member from an encryption record it could not read for the same reason.
  The "is the tool's result useful" factor does not save it either: the member would
  be listed under a name that may be wrong.
- *What a caller loses:* one member per damaged header. Its bytes are still in the
  archive, and an opt-in salvage mode could later offer it as "unverified" (§Later
  steps).
- *What would change the answer:* a caller who needs the bytes more than the name.
  That is the salvage-mode caller, and it gets an opt-in for it, not a default.

**Decision 2 — `ARCHIVE_DAMAGE_SKIPPED` under `STRICT`. Recommendation: not in
`ARCHIVE_INTEGRITY_CODES`.** `STRICT` then lists the same members and raises the same
`CorruptionError` at the end as the default does.

- `ARCHIVE_INTEGRITY_CODES` holds anomalies that the default would otherwise let pass
  without an error (DR-3: trailing data, a damaged end block). This damage never passes
  without an error, because the pass still raises. Putting the code in would only make
  `STRICT` stop earlier, at the first damaged header, and raise `DiagnosticRaisedError`
  in place of `CorruptionError`. `formats/rar.md` already avoids that substitution
  when a cut and a lesser diagnostic meet.
- A caller who wants to stop at the first damage can use
  `DiagnosticPolicy(raise_on={"archive_damage_skipped"})`.

**Settled by rules, stated so they can be overruled:**

- *The error at the end, not a diagnostic in its place:* DR-2 and the
  missing-middle-volume ruling. A lost member is a refusal-class event (DR-1), so the
  pass raises.
- *On by default, no flag:* `unrar` does it by default (DR-6). DR-8 wants complete
  defaults, and nothing here trusts bytes that no checksum has checked.
- *No search:* DR-2's "reopen if" and the false-header numbers above.

### The solid pass

A solid `stream_members()` pass runs one `unrar p` over the archive and splits the
output by the offsets of the listed members (`RarReader`'s solid pass and its `plan`
hook). `unrar p` also prints the skipped member's bytes, because it trusts the damaged
header, and their length is not known. If the pass went on splitting, every later
member would get the wrong bytes. A later member's CRC would catch them, but only after
the wrong bytes were returned.

So the `plan` hook answers `None` ("serve it as `open()` does") for every payload
member after the first skipped header in that solid stream. Those members are read one
at a time by name, each `unrar` run decoding the solid stream from the start: the
cost that random `open()` on a solid RAR already has (`reader.cost.access_cost`). It is
paid only on a damaged solid archive. The same holds for the `unar` all-entries pass.

**Duplicate names.** When two members share a name, the reader asks `unrar` for one of
them by its position among the members with that name. A skipped header with the same
name, as `unrar` reads it, moves those positions by one. A positional read of a
duplicate name after a skipped header is therefore refused with the skip named in the
error, not guessed. This shape is rare and almost only crafted (DR-5a).

**File copies and links.** A RAR5 file copy or hard link whose source was the skipped
member has no source in the listing. It takes the existing path for a source that is
not listed, and a test pins that it does.

### The diagnostic

```python
DiagnosticCode.ARCHIVE_DAMAGE_SKIPPED = "archive_damage_skipped"

@dataclass(frozen=True)
class DamageSkippedContext(_JsonSafeContext):
    kind: Literal["damage_skipped"] = "damage_skipped"
    archive_name: str | None = None
    format: str = ""
    volume: int | None = None   # 0-based volume index; None for a single file
    damaged_at: int = 0         # offset of the damaged header in its volume
    resumed_at: int = 0         # offset of the header the walk went on from
    what: str = ""              # "member_header" | "service_header" | "header"
```

`what` comes from the damaged header's type byte, which has no check, so it is a hint
and the docs say so. The code is generic, not RAR-specific: the TAR and ZIP steps
reuse it (DR-0). The `CorruptionError` names the first damaged header, as today. The
diagnostics give each skipped span, so a caller sorting a backup corpus can see how
much was lost without parsing messages (DR-13: the error carries one, the diagnostics
carry all).

## B. A damaged decode keeps the same prefix however it is read

### The problem

`_compressed_feed_size(n)` returns `min(n, 1 MiB)` when `n` is over 64 KiB, so that a
whole-member read is one C inflate call. When a decoder call raises, CPython's zlib,
lzma, bz2 and zstd wrappers drop the output of that call. So a large `read(n)` loses up
to 1 MiB of compressed input's worth of good output, and a small read loses less.
The prefix also depends on output budgets: a call asked for at most `n` bytes stops
early and keeps the rest of its input. Where the next call starts depends on `n`, so
the output the failing call drops depends on `n` too.

### Recommendation: fixed feeding

The decoder sees the same sequence of calls whatever the caller does:

- **Input** is fed in slices that end at multiples of 64 KiB of compressed offset,
  counted from the decoder's start. The read from the source may stay large (the 1 MiB
  read is kept, then sliced), and a short source read is topped up to the slice
  boundary or EOF. On a pipe that delivers slowly, a read may then wait for the rest of
  a slice before it returns. Whether the source is already read through a full-count
  reader (so nothing changes) is checked in the first implementation task.
- **Output** per call is capped at 64 KiB whatever `n` is. Output past `n` stays in the
  stream's buffer, which already exists, so a call never holds more than 64 KiB above
  what it holds today.

With both fixed, the call boundaries depend only on the compressed bytes. The prefix
before an error is then the same for `read(1)`, `read(64 KiB)`, `read(1 MiB)` and
`read()`, from a file and from a pipe. On the repro above, every read size should get
what 64 KiB reads get today (7 143 424 bytes; a test pins the number). `gzip -dc` gets
7 176 192. The gap is at most one call's output, and it is the same gap for every
caller.

A seek that restarts the decoder at an index point counts the slices from that point.
The prefix after such a seek can differ from a linear read's prefix. That is DR-4a's
best-effort index trust, and it is not a new difference.

**Cost.** The 1 MiB feed was added so a whole-member ZIP read would be one inflate
call, because the per-call Python overhead was the gap to `zipfile`. A standalone
measurement of raw zlib (21 MB of text, 1.4 MB compressed) gives 20.9 ms with 1 MiB
feeds and 14.8 ms with 64 KiB feeds and 64 KiB output. Raw inflate is not slower in
slices, and the stream's per-call overhead is what the benchmark gate has to measure.
`tasks.md` makes the benchmark run a gate for this PR. If the stream overhead shows,
the slicing loop goes inside `_read_decompressed_chunk`, so one Python-level read
covers many decoder calls.

### Decision 3 — fixed feeding or the exact prefix

**Recommendation: fixed feeding.** It is simple, the same for every codec, and it fixes
the DR-5 complaint completely.

The alternative is to recover the exact prefix: on an error, run the failing call again
from a copy of the decoder state taken before it, in 1 KiB steps. That gets up to one
more call's output (on the repro, close to `gzip -dc`). But only `zlib.decompressobj`
has `copy()`. lzma, bz2, zstd and brotli have no way to copy their state. For them the
exact prefix needs a restart from a seek point. That works on a seekable source only,
and on a plain `.xz` it means decoding the whole prefix again. The result would then
depend on the codec and on the source, and DR-5 is what this section is fixing. A copy
on every call also costs about 5% of raw inflate time on the measurement above.

The exact prefix stays possible later as a DEFLATE-only refinement on top of fixed
feeding, if a salvage caller asks for the last few KB.

### Accelerators

The rapidgzip path must give the same prefix before the same error ("accelerators never
change result or error type"). Its decode is chunked differently, so this is measured,
not assumed (`tasks.md`). If it differs, the choice is between handing the read back
to the in-process decoder at the error (it re-decodes from the last seek point, on the
error path only) and a DR-5a note. That choice goes to the maintainer with the
numbers.

### Scope of the guarantee

It covers `DecompressorStream`, and so every codec member of ZIP and 7z, the
single-file formats, compressed TAR streams and `open_stream`. RAR data comes from
`unrar`, which has its own output. `extract_all` still deletes a partial file, so the
guarantee reaches callers through streams. Keeping partial files belongs to salvage
mode (§Later steps).

## Plugin API

Nothing changes in `archivey.plugins` in this step. A plugin's `walk()` or
`iter_members()` that raises still ends the listing with the members before the damage
kept (`plugin-api` design §2a).

The seam for later is a fourth named method on `PluginContext`, next to the three
member diagnostics:

```python
def damage_skipped(self, damaged_at: int, resumed_at: int, error: CorruptionError) -> None:
    """The walk found damage and resumed past it. Emits ARCHIVE_DAMAGE_SKIPPED and
    keeps ``error``; the adapter raises the first kept error after the walk ends."""
```

It is not added now, because no plugin needs it yet (DR-13). When CPIO or AR learn to
resume (GNU cpio skips junk to the next magic), the method lands with them. The
built-in RAR reader keeps the error the same way through its own `damaged` field.
When TAR gets the rule too, the "keep the first error, raise it after the last member"
logic moves into the base reader, shared by built-ins and the plugin adapter
(DR-23a: these must agree). The sequential shape (1064) needs no change: the adapter
already raises after the members the walk yielded.

## Stability

- The listing change is a behaviour change: the same archive yields more members before
  the same error. It needs the `needs-minor` label and a **Changed** changelog line. It is
  not **Breaking:**, because no call that succeeded now fails and no error type changes.
- `ARCHIVE_DAMAGE_SKIPPED` and `DamageSkippedContext` are new public names. They are
  added to `DiagnosticCodeStr` and the API surface listing.
- Fixed feeding changes which bytes a damaged stream returns before it raises. That is
  a fix (DR-5), and it would fit in a patch release. It ships with the rest in 0.3.0.

## Coordination

The "per-member overhead" PRs (1073 to 1076) change `ArchiveStream` construction,
`tracked_open` and `reader_state`. §B changes `DecompressorStream`'s feed loop, and §A
changes the RAR parser and the solid pass. The only shared file is the benchmark
baseline. §B's benchmark run waits for those PRs to merge, so its before and after
numbers compare the same base.

## Later steps (not in this change)

- **TAR, past a damaged header.** The same rule as RAR fits TAR: take the damaged
  header's size, confirm the next header's checksum, and go on. GNU tar does something
  else. It ignores the damaged header's size and tests each following 512-byte block
  ("Skipping to next header"). Matching GNU tar means a search, so this needs its own
  decision: the confirmed-size rule by default, or GNU tar's block scan as the opt-in.
- **Opt-in salvage mode** (`salvage=True`, `--salvage`). Anything that finds structure
  by searching: ZIP local headers when the central directory is gone, a TAR block scan,
  a RAR header search, a member listed from a damaged header as "unverified", and
  extraction that keeps partial files. All of these trust bytes found by a search, so
  they are an explicit request (DR-10) with its own design.
- **The exact DEFLATE prefix** (Decision 3's alternative).

## Rejected

- **Searching for the next RAR header by CRC at every offset.** See the false-header
  numbers. It also costs one CRC per byte of damaged span.
- **Trusting the damaged sizes without the confirmation (exact `unrar`).** On a damaged
  size field it would parse garbage as headers. Today's stop is better than a garbage
  member.
- **Dropping the 1 MiB feed and doing nothing else.** It fixes the 1 MiB case, but the
  output budget still makes the prefix depend on `n`.
