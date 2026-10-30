# Design: synthetic RAR archives for `unrar`

## Context

### How a read reaches `unrar` today

`dev-docs/formats/rar.md` §2.3 has the full picture. In short: stored members, and
stored encrypted members in one part, are read by archivey itself. Everything else goes
to `unrar p` (or `unar`), and `unrar` gets the **original archive**:

| Read | What `unrar` gets |
| --- | --- |
| `open()` of a member, solid or not | `unrar p -inul -cfg- [-ver] (-p \| -p-) -n./<mask> -- <archive>` |
| A pass (`stream_members()`, `extract_all()`) over a nonsolid archive | The same, once per member |
| A pass over a solid archive | One `unrar p` with no mask, demultiplexed by unpacked sizes |

Four consequences:

1. **Each open walks every header.** `unrar` keeps walking after the first match, because
   a mask can select more members. In a solid archive it also decodes every member after
   the target, and archivey waits for it to exit (the overrun check reads to EOF).
2. **A stream source is copied whole** on the first read `unrar` serves
   (`_ensure_archive_path`), bounded by `SpoolLimits.max_bytes`. A volume set from
   streams is copied whole too, because `unrar` finds the next volume by name.
3. **The member name is a mask.** `rar_unrar.py` ports how `unrar` 7 reads stored names
   and compares masks, so that archivey can skip the other members a mask selects. What
   it cannot model is refused, or goes to `unar` under `auto`: a glob that matches
   earlier members (unless `rar_allow_glob_member_concatenation`), a glob in a directory
   component, a backslash, a NUL, a name `unrar` reads as empty, an earlier 8-bit name
   with no UTF-8 locale, and a selection that depends on the dot rule when the binary
   gives no answer to the probe.
4. **A masked read of a solid member decodes from the archive start**, across solid
   groups (`rar -s<N>`). `unrar` skips to the group only when the name is passed as an
   argument, which archivey cannot do safely (rar.md §2.3, "the member is never
   positional").

### The idea, and why it waited

`rarfile` writes a small temporary RAR holding one member's headers and packed data,
and guards it heavily (never solid, split or encrypted members; never above about 20 MB).
The idea appears in this repo four times:

- `openspec/specs/format-rar/spec.md`, "Support benchmark-gated small-member
  optimization": allowed once benchmarks justify it, output byte-identical to the direct
  path, deferred for the first reader.
- `dev-docs/formats/rar.md` §7, "Can the stream-source copy be made small, rather than
  just moved?": the copy would be one compressed member instead of the whole archive.
  "Unmeasured, and the guards are the hard part: RAR3 and RAR5 need different header
  synthesis." Building it was "considered and deferred", with the remark that the
  machinery for decoding every RAR3 compressed comment in one `unrar` call would share
  the writer. Both are tracked internally.
- `dev-docs/IDEAS.md`, "Decode RAR without `unrar`": the same synthetic archive fed to
  libarchive. `review/archive/2026-07-12-codebase-deep-review/roadmap.md` cut that one
  ("Don't add a second RAR path"). That objection is about a second **decoder**. This
  change keeps `unrar` as the only decoder and changes only what it is given.
- The maintainer on PR 290 (2026-09-04), about `memfd`: "being linux-only makes it a bit
  uncomfortable ... we could do that for memfd files: the limit would then be the
  compressed member size."

It was deferred before 0.2.0 as a performance item on an external-tool path. The
maintainer asked for it now (2026-10-30): faster opens of small members, no whole-archive
spool when streaming, and no wildcard matching problems.

## The synthetic archive

### Layout

Every synthetic archive is one file, one volume, with the members in archive order:

| Part | RAR5 | RAR 1.5-4 |
| --- | --- | --- |
| Signature | `Rar!\x1a\x07\x01\x00` | `Rar!\x1a\x07\x00` (the marker block) |
| MAIN | Type 1, no extra area. Archive flags: `SOLID` (0x04) when the chain has more than one member, else 0 | Type 0x73, 13 bytes. Flags: `MHD_SOLID` (0x08) when the chain has more than one member, else 0 |
| Per member: FILE header | The member's stored header, decrypted if the archive is `-hp`. Name replaced (D2). Header CRC32 recomputed | The stored header, decrypted if `-hp`. Name replaced, `LHD_UNICODE` cleared. `HEAD_CRC` recomputed |
| Per member: data | The packed bytes, verbatim | The packed bytes, verbatim |
| ENDARC | Type 5, flags 0 | Type 0x7B, flags 0x4000, 7 bytes |

**What is copied, and what is made.** Only the MAIN and ENDARC headers are made. Every
FILE header is the archive's own, so every field `unrar` needs to decode the member
comes from the archive unchanged: method or compression info, dictionary size, the
member's own solid flag, host OS, attributes, sizes, CRC32, the RAR5 extra area (hash
record, encryption record, times, owner, version, redirect) and the RAR3 salt and
extended time. A patch changes only:

- the name and its length (D2), and on RAR 1.5-4 the `LHD_UNICODE` flag;
- for a member split across volumes: the split flags are cleared and the packed size is
  the sum of the parts (below);
- the header size and header CRC that follow from those.

**Measured facts that fixed the layout** (`unrar` 7.00, `scripts/exploration/
rar_synthetic_probe.py`):

- **ENDARC is required.** Without it, `unrar` exits 10 and prints nothing.
- **`-ver` is required.** A RAR5 FILE header with a version record (a history row of
  `rar -ver`) is skipped without `-ver`: exit 10, no output. With `-ver` the synthetic
  archive gives each row's bytes. Archivey passes `-ver` on every synthetic read; with
  placeholder names it selects nothing extra.

### What a read puts in it

| Read | Members in the synthetic archive |
| --- | --- |
| Nonsolid member | The member alone |
| Solid member | The **chain**: from the last member at or before the target whose own solid flag is clear, to the target. Every header with packed data in that range goes in, a RAR3 symlink (its target is compressed data) and a stored member included |
| Member split across volumes | One member: the last part's header, split flags cleared, packed size = the sum of the parts, data = the parts joined in order |
| History row (`rar -ver`) | As any other member; `-ver` is passed |
| Encrypted member (`-p`) | As any other member; the header carries the salt or encryption record, and `unrar` gets the password on stdin |
| Header-encrypted archive (`-hp`) | Plain headers: the decrypted FILE headers, a MAIN without the header-encryption flag, no CRYPT header. The data stays encrypted |
| Pass over a nonsolid archive (D3) | A batch of members, one `unrar` run per batch |
| Pass over a solid archive | Each solid stream (`rar -s<N>` group) in turn, as one chain |

The chain start follows what the format means by the per-member solid flag, and what
`unrar` does when it is given a name as an argument: rar.md §2.3 measured that only a
positional name skips to its group in `solid_groups__.rar`. `unar` starts at the same
member (`_unar_solid_runs`). The masked read today decodes from the archive start, which
is a property of the `-n` route, not of the format (§"Matching `unrar`").

A file copy (`FILE_COPY`), a hard link and a symlink need no data from `unrar` and keep
today's routes. A directory with data keeps today's refusal: `unrar` emits nothing for a
directory entry, synthetic or not.

### The `unrar` call

```
unrar p -inul -cfg- -ver (-p | -p-) [-n./m<k>] -- <synthetic>.rar
```

- A one-member archive needs no mask: `unrar p` prints the only member.
- A chain needs the target only: `-n./m<k>`, where `m<k>` is the target's placeholder
  name (D2). `unrar` decodes the members before it and prints only the target. The mask
  is ASCII letters and digits, so no wildcard, dot rule, locale or encoding question can
  come up.
- A batch (D3) has no mask: `unrar` prints every member in order and the pipe is
  demultiplexed by unpacked size. Every member in a batch is a regular file with data,
  so the sizes are exact.

### Where the file lives

A temporary file from `tempfile.mkstemp(suffix=".rar")`, mode 0600, in the system
temporary directory, as today's spool. Not a `memfd`: it is Linux-only, and the
maintainer called that uncomfortable (PR 290). With a synthetic archive the copy is
small, so most of the gain a `memfd` offered is already there.

The file lives as long as the member stream. With `seekable_members=True`, a backward
seek respawns `unrar` on the **same** file; nothing is copied again. Reader close removes
any file left.

### The copy is bounded

Every synthetic copy counts against `SpoolLimits.max_bytes`, for path sources too (DR-9:
reuse an existing limit). It is a copy of archive bytes (packed and, for `-p`,
encrypted data), not of member plaintext, so the `archive-reading` rule "plaintext
member data spooled proportional to member size: forbidden" does not apply to it. The
size is known before the copy, so a copy over the limit is refused before a byte is
written. On a path source, D1 decides what happens instead.

## Measurements

All with RARLAB `unrar` 7.00 on Linux x86-64. Archives written with `rar` 7.00 (RAR5)
and the pinned `rar` 6.23 that `scripts/gen_rar_fixtures.py` fetches (RAR4, `-ma4`).
Script: `scripts/exploration/rar_synthetic_probe.py`.

### Does `unrar` accept it?

Each row compares the bytes `unrar p` prints with the source file. All 36 read
byte-identical with exit 0:

| | plain | `-p` | `-hp` |
| --- | --- | --- | --- |
| RAR4 nonsolid, name kept | ok | ok | ok |
| RAR4 nonsolid, name replaced | ok | ok | ok |
| RAR4 solid group (`-s4`), chain of 3, all printed | ok | ok | ok |
| RAR4 solid group, chain of 3, target only by placeholder mask | ok | ok | ok |
| RAR4 split member (3 volumes) as a synthetic volume set | ok | ok | ok |
| RAR4 split member, parts joined into one volume | ok | ok | ok |
| RAR5, the same six shapes | ok | ok | ok |

Also measured, outside the matrix:

- A solid chain spread over 5 volumes (`rar -s -v50k`), rebuilt as a synthetic volume
  set with placeholder names: the last member reads byte-identical by its mask.
- History rows of `file_version__.rar`: exit 10 with no output without `-ver`; each
  row's own bytes with `-ver`.
- No ENDARC: exit 10, no output.
- The split encrypted RAR5 member joins into one member and decrypts. The fixture notes
  say each part has its own encryption record; the joined read shows the parts form one
  ciphertext under the record of the last part.

### `unrar` alone: masked original against synthetic

3,000 members of 2,000 bytes, `-m3`, median of 3 runs. "Synthetic" includes reading the
member's bytes from the archive, building the file, writing it and running `unrar`.

| Archive | Member | Masked original | Synthetic |
| --- | --- | --- | --- |
| RAR4 nonsolid | first / last | 17.0 / 16.3 ms | 3.3 / 3.0 ms |
| RAR4 nonsolid `-hp` | first / last | 55.7 / 59.0 ms | 20.3 / 17.0 ms |
| RAR4 solid `-s50` | first / last | 46.1 / 38.8 ms | 5.2 / 5.1 ms |
| RAR5 nonsolid | first / last | 10.8 / 9.5 ms | 6.4 / 5.1 ms |
| RAR5 nonsolid `-hp` | first / last | 78.8 / 90.7 ms | 35.2 / 25.4 ms |
| RAR5 solid `-s50` | first / last | 51.2 / 30.1 ms | 5.3 / 6.3 ms |

The first member costs as much as the last: `unrar` walks every header either way. The
`-hp` rows keep a floor in the synthetic column: the data key derivation, which the
member needs anyway.

### Through archivey today (`open()` + `read()` of one 2 KB member, path source)

| Archive | 1,000 members | 10,000 members |
| --- | --- | --- |
| Nonsolid | 6.8 ms | 20.6 ms |
| Solid `-s` (one group), first member | 13.2 ms | 90.2 ms |
| Solid `-s50`, first member | 15.9 ms | 100.1 ms |

`extract_all()` on a nonsolid archive of 250-byte members: 7.48 s for 1,000 members
(7.5 ms each) and 49.5 s for 4,000 (12.4 ms each).

A 1.2 KB member of a 200 MiB archive opened from a `BytesIO`: **1,350 ms**, nearly all
of it the whole-archive copy. The same member from the path: 7.1 ms.

One `unrar p` over a synthetic archive of all 4,000 members of that `extract_all()`
archive (D3): build 0.06 s, `unrar` 0.14 s, 8,000,000 bytes out.

For a large member, the copy is a real cost. A 200 MiB member of random data: `unrar p`
0.48 s, copying the archive with `fsync` 1.05 s. A 16 MiB member of text: `unrar p`
0.34 s, copy 0.24 s. That is why D1 keeps the original for large members of a path
source.

### Expected gains

| Case | Today | With synthetic archives | Basis |
| --- | --- | --- | --- |
| `open()` of a small nonsolid member, 10,000 members | 20.6 ms | about 4-7 ms, flat in member count | measured `unrar` rows, plus about 1 ms of archivey overhead |
| `open()` of the first member, solid `-s`, 10,000 members | 90.2 ms | about 5 ms | chain of one; `unrar` stops after it |
| `open()` of a member in a later `-s<N>` group | decodes the archive up to it | decodes its group | measured `-s50` rows |
| `extract_all()`, nonsolid, 4,000 small members | 49.5 s | about 20 s per-member (no D3), under 1 s plus file writing with D3 | measured spawn and batch rows |
| A small member from a 200 MiB stream source | 1,350 ms and 200 MiB on disk | about 5 ms and the member's packed bytes on disk | estimate from the rows above |
| A pass over a stream source, nonsolid | the whole archive on disk | one member or one batch on disk at a time | design |
| A pass over a stream source, solid | the whole archive on disk | one solid group on disk at a time | design; no gain for a single-group `rar -s` archive |
| Last member of a single-group solid archive | whole decode | the same whole decode, plus the copy | the chain is the archive |

## Integrity and matching `unrar`

### The integrity guarantee (DR-4a)

DR-4a promises a digest check for a member read from start to end with no skipped
bytes. Synthetic archives change where `unrar` reads from, not what archivey checks:

- The digest checked is the one in the FILE header that went into the synthetic
  archive, which is the header archivey listed (below). The fused size-and-digest stage
  on `unrar`'s output is unchanged.
- `stream_members()` stays forward-only and never seekable (DR-10). In a pass, archivey
  reads each member's header and packed bytes in one forward read and writes them to the
  synthetic file; there is no seek inside the source beyond what reaching the member
  already needs (DR-10a).
- A respawn after a backward seek reads the same synthetic file again, so the bytes
  `unrar` decodes cannot change between the two runs.

**Stronger than today in one respect.** Today `unrar` walks the original archive itself,
and archivey predicts what that walk selects. Where the two parsers disagree (a damaged
header that `unrar` treats differently, a QO record, an SFX search, a name `unrar` reads
differently, a file that changed on disk after `open()`), `unrar` can decode a member
archivey did not list. Before writing a synthetic archive, archivey reads the header
again and checks its CRC against the one the listing parsed (for `-hp`, after
decryption). `unrar` then sees one header, and it is that one.

### Matching `unrar` (DR-6)

The bytes are `unrar`'s own: `unrar` still decodes every member, with the archive's own
header fields. What changes is which headers it sees and in what container.

| Question | Today (`-n` mask on the original) | Synthetic | Matches |
| --- | --- | --- | --- |
| Bytes of a nonsolid member | `unrar`'s decode | `unrar`'s decode of the same header and data | yes, 36/36 measured |
| Where a solid read starts | the archive start | the member's solid stream start | `unrar` with a positional name, and `unar` |
| A member with an unknown compression version | refused before the spawn | the same refusal | yes |
| A later member of a solid stream behind an unknown method | refused, and under `unrar` also later groups | refused within its stream only | `unrar` with a positional name, and `unar` |
| Wrong password | exit 11, or exit 2/3 with no output (RAR4) | the same codes from the same header | yes; keep the mapping table of rar.md §2.3 |
| Corrupt data | `unrar`'s exit code, overridden by archivey's digest | the same | yes |

The solid start is the one visible change. For an archive a real tool writes the output
is the same: the encoder resets its state at a member whose solid flag is clear, and
`unrar` does the same when it decodes. Only a crafted archive with a clear flag on a
member whose data still depends on earlier state can decode differently, and its digest
then fails. DR-5a allows a crafted-only shape to differ a little; `unar` already decodes
that way.

The dictionary memory check (`_check_dictionary_memory`) and the `RewindWarning` floor
(`_solid_prefix`) then count the chain, not the archive prefix. Both get smaller.

## Streaming

**A seekable stream source** (`BytesIO`, a remote file object) stops being copied whole.
Each read copies the member, or its chain, and nothing else. A remote source then reads
only the member's bytes (DR-10a, scenario 9 in `dev-docs/scenarios.md`).

**A pass** reads each member's header and data once, forward, and writes them to the
current synthetic file:

- nonsolid: one member per file, or a batch (D3); the file is removed when the batch is
  read;
- solid: one solid stream per file; `unrar` runs when the stream is complete, and the
  file is removed after.

`unrar` cannot read a file that is still being written: it reads to EOF and stops. A
solid stream therefore has to be complete on disk before its `unrar` run starts. For a
single-group archive (`rar -s`) that is the whole archive's packed data, as today, minus
the headers and the members with no data.

**A non-seekable source** (a pipe) is out of scope. `RarReadBackend` refuses it for two
reasons (`_NON_SEEKABLE_REASON`): "the header walk seeks past each member's data, and
unrar reads members from a file on disk". This change removes the second reason. The
first needs a forward header walk at pass time, as TAR has. That is a follow-up.

## Risks

| Risk | Mitigation |
| --- | --- |
| The writer produces a header `unrar` decodes differently, and the member has no digest (RAR5 can omit the CRC) | The writer patches only names, split flags and sizes; every decode field is copied. Tests compare the synthetic read with `unrar p` on the original for every committed RAR fixture and the RAR corpus, byte for byte, before the original route is removed |
| RAR 1.5 and 2.x archives (`UNP_VER` 15-26) use the archive solid flag in ways not measured here | Measure against `rar15-comment.rar`, `rar202-comment-nopsw.rar` and the corpus before the switch; keep the original route for `UNP_VER` < 29 if they differ |
| Other `unrar` versions (6.0 floor, WinRAR 7.23 on Windows CI, 7.30 betas) read the synthetic file differently | The file uses only the basic header types every version reads. Run the probe in CI on each pinned version |
| RAR 1.5-4 split member joined past 4 GiB needs `LHD_LARGE` fields the last part may not have | Insert the high size fields, or keep the original route for that member; the default 1 GiB spool limit refuses such a copy before it matters |
| A RAR5 service header (`STM`, NTFS stream) with packed data inside a solid chain | Include every header with packed data in the chain, not only FILE headers; add a fixture with `rar -os -s` |
| The temp file holds a decrypted `-hp` header: sizes, times, CRC | Placeholder names keep the member name off disk (D2). The file is 0600 and removed when the stream closes. Today's spool of an `-hp` stream source holds the encrypted archive, so this is new, and the security page has to say it |
| A crash leaves temp files | The same as today's spool: reader close and stream close remove them; a killed process leaves them in the temp directory |
| A batch (D3) misaligns when `unrar` prints a wrong number of bytes for a damaged member | A member with a digest fails its check; on any failure or a non-zero exit inside a batch, the rest of the batch is read again one member at a time. Batches take only members with a digest, and one password |
| More disk I/O for a large member of a path source | D1 keeps the original route above a size threshold |

## Decisions for the maintainer

Settled by rules, not asked: the chain starts at the solid stream start (DR-6, measured
`unrar` behaviour for a positional name; DR-5a for the crafted shape); temp file rather
than `memfd` (the 2026-09-04 remark on Linux-only); every copy counts against
`SpoolLimits.max_bytes` (DR-9, reuse an existing limit); a split member is joined
rather than written as a volume set (both measured; one file is simpler); `unar` keeps
its route in this change.

### D1. Which reads go through a synthetic archive?

Copying a member's packed bytes is cheap for a small member and costly for a large one
(a 200 MiB member: 1.05 s to copy, 0.48 s to decode). The mask on the original costs a
full header walk per read, and all the name modelling.

- **A. Every `unrar` read.** All mask code goes: the name model, the dot-rule probe, the
  glob refusal, the `auto` fallback to `unar` for names `unrar` cannot address. A large
  member on a path source pays a copy of its packed bytes, and a member over the spool
  limit (1 GiB by default) is refused where it reads today.
- **B. Every `unrar` read, except a large member of a path source whose name is plain
  (recommended).** "Large" is packed bytes (the whole chain for a solid member) over an
  implementation threshold, starting at 64 MiB. "Plain" has two parts. Once per reader: every
  name in the archive decodes cleanly (valid UTF-8 for RAR5, ASCII for an 8-bit RAR3
  name) and has no `\`, NUL, leading `/`, or empty, `.` or `..` component, so `unrar`
  reads each name as archivey does. Per member: the name is ASCII (no locale question),
  has no `*` or `?` and no component ending in `.` (no dot rule), and no other name
  equals it or starts with it plus `/`, compared without case (Windows `unrar` folds
  case). Such a read keeps today's mask, which then selects the target alone. Real
  archives pass; a crafted one fails and gets the synthetic route. Every other read is synthetic, whatever its size,
  within the spool limit. The name model, dot-rule probe, glob refusal and `unar`
  fallback still go, because no read that needs them takes the mask route.
- **C. Only stream sources and names refused today.** The smallest change. All mask
  code stays, and path sources keep the per-read header walk.

Recommendation: **B.** It gives the small-member speed-up to path sources, removes the
whole-archive copy, and deletes the name machinery, while a multi-gigabyte member of a
file on disk still reads with no copy. It leaves the end code smaller than today with
one simple fallback. A is cleaner still, but turns large reads on a path into copies
and refusals; on a system with `/tmp` in RAM it can use memory the size of the member.

### D2. Do members get placeholder names in the synthetic archive?

- **Yes, `m0`, `m1`, … (recommended).** The mask is always plain ASCII. No locale,
  encoding, wildcard or dot-rule question can come up, and a `-hp` archive's member
  names never reach the disk. Costs a header rewrite (new name length, header size and
  CRC), measured for RAR4 and RAR5.
- **No, the stored name.** The FILE header is copied byte for byte except the split
  fields. A one-member archive needs no mask, but a solid chain needs one, so the name
  model stays for chains.

Recommendation: **placeholder names.** The rewrite is a few lines per format and is
what lets the mask code go.

### D3. Does a pass over a nonsolid archive run one `unrar` per batch of members?

Today a pass opens each member with its own `unrar` (12.4 ms per member at 4,000
members, growing with the count). With synthetic archives each spawn costs 3-6 ms flat.
One synthetic archive of many members, read by one `unrar` and demultiplexed by size,
did 4,000 members in 0.2 s.

- **Yes, in this change (recommended).** Batches hold members with a digest and the
  same password, up to a packed-size cap (an implementation constant, about 64 MiB).
  A failure inside a batch falls back to one member at a time.
- **Later.** Per-member synthetic reads first; batches in a separate change.

Recommendation: **yes.** It turns the slowest RAR case into one of the fastest, and the
solid pass already does the same demultiplexing.

### D4. What happens to `rar_allow_glob_member_concatenation`?

Under B or A, no read builds a mask from a member's name, so the flag no longer changes
anything. It shipped in 0.2.0.

- **Deprecate it (recommended).** Setting it warns for one minor release and does
  nothing; it is removed after (DR-12a). The CHANGELOG says so.
- **Keep it** as a no-op without a warning. A public name with no effect fails DR-13.

Recommendation: **deprecate.**

## Rejected alternatives

- **Piping a synthetic archive to `unrar` on stdin.** `unrar` refuses every
  non-seekable input (rar.md §2.3 table, `rar_unrar_input_matrix.py`).
- **A synthetic volume set for split members.** Measured to work, but it needs a temp
  directory and the set's naming scheme. Joining the parts gives one file and also
  works with `-p` and `-hp`.
- **Feeding the synthetic archive to libarchive.** A second decoder; the roadmap cut it.
- **Generating FILE headers from parsed fields.** Every field `unrar` needs would have
  to be written back correctly, for each RAR version. Copying the stored header keeps
  the fields as the archive has them.
- **Starting `unrar` on a growing synthetic file** so a solid pass could begin before
  its stream is on disk. `unrar` reads to EOF and stops.
- **Keeping the original archive and passing the member positionally.** Measured
  unsafe: a name that starts with `-` or `@` becomes a switch or a list file (rar.md
  §2.3).

## Follow-ups

- Give `unar` the same synthetic file: it would drop `unar`'s own whole-archive copy for
  stream sources and prefixed files.
- Decode every RAR 1.5-4 compressed comment in one `unrar` run, with the comments as
  members of one synthetic archive (tracked internally).
- RAR over non-seekable sources: a forward header walk at pass time.
- Read a directory entry's compressed data by giving `unrar` a FILE header without the
  directory attribute. Today such data is refused (rar.md §2.3); this would deliver it.
