# RAR

Current maintainer truth for the RAR backend. RAR is the only format whose read path
crosses a **process boundary**: archivey parses every header itself and hands member
bytes to a separate `unrar` process. Most of what is peculiar here follows from that.
Registers keep the status — this page states the behaviour and links the row.

## At a glance

| | |
| --- | --- |
| Read | Yes — metadata natively, member data through RARLAB `unrar` or `rar` |
| Write | **Not shipped**, for any format — no `archivey.create`, no writer module ([writing design](../investigations/archive-writing-design.md)) |
| Source | Seekable only, in both access modes |
| Listing cost | `REQUIRES_SCANNING` — a header-to-header walk cached at open (§1). RAR5 with QO: read the copies, skip matching FILE headers on the walk (§1.1) |
| Access cost | `SOLID` for a solid archive, `DIRECT` otherwise. `solid_block_count` is always `None` (§1) |
| Stream capability | `SEEKABLE` — of the source. Member streams are a separate question (§5) |
| Core dependencies | None to list an unencrypted archive. Compressed member data needs RARLAB `unrar` or `rar` **6.0 or later** on `PATH` (§1), or, by default, `unar` 1.10+ when no RARLAB binary is found (§3). Stored encrypted members need `cryptography` instead |
| Optional | `[recommended]` (`cryptography`): header decryption, RAR3/RAR4 and RAR5 alike. BLAKE2sp needs nothing — stdlib `hashlib` |
| Refuses | Non-seekable sources · a non-RARLAB `unrar`/`rar` (no fallback to `7z` / `bsdtar` / `unrar-free`; `unar` when no RARLAB binary is found, unless `rar_decompressor="unrar"`) · with `unar`: encrypted RAR 2.x-4.x data and, in a solid archive, compressed members after it in the same solid stream, a non-ASCII password, a header-encrypted RAR5 volume set, RAR5 solid members after an empty entry, RAR 1.5 compression, a prefixed multi-volume set · a RARLAB binary older than 6.0, or one whose banner version cannot be parsed · a later volume opened without its first · a glob in a directory component, or a backslash in the stored name (unrar path) · a glob-named member whose mask also matches **earlier** members, unless `rar_allow_glob_member_concatenation=True` (under `AUTO`, these and the name refusals go to an accepted `unar` when the read needs no password, the archive is a file with no prefix, and `unar` does not refuse it) · a member whose dictionary, as the chosen program allocates it, is over `DecoderLimits.max_decoder_memory` (`ResourceLimitError`, §7) · writing |

**Two things a reader might expect and will not find.** Nothing amortizes repeated
random reads of a solid archive: there is no `unrar x` anywhere in `src/`, so every
out-of-order solid `open()` is its own whole-archive decode (§2.4). RARLAB `rar`
(the trialware writer) is accepted when `unrar` is missing; `unrar` wins when both
exist. Reads still spawn only `p` (§3).

The 6.0 floor is the **banner probe**, not archive open. Missing or too-old `unrar`
does not fail `open_archive` or stored reads; compressed comments stay
`None` (§1, §2.2). The public `format_availability()` also runs the probe, and reports
RAR `PARTIAL` with the probe's refusal as the `unrar` hint; `check_programs=False`
skips it.

## 1. Shape

Several properties generate most of this page.

```
  [ SFX stub? ]  [ magic ]  [ MAIN ]  [ FILE hdr | packed data ] × n  [ QO? ]  [ ENDARC ]
                     │          │            │
   Rar!\x1a\x07\x00 ─┤          │            └── data_offset ─┐
   Rar!\x1a\x07\x01\x00         │                             │
        version 4 / 5      each header states                 │
                           its own size                       │
  ─────────────────────────────────────────────────────────── │ ───────────────
   archivey's parser reads everything above                    │
                                                    ╔══════════▼═══════════╗
                                                    ║  unrar  (subprocess) ║
                                                    ╚══════════════════════╝
```

| Block | RAR5 type | What it is |
| --- | --- | --- |
| **marker** | — | The magic itself, and the only thing found by position. `Rar!\x1a\x07\x00` is the RAR3 family (7 bytes), `Rar!\x1a\x07\x01\x00` is RAR5 (8) |
| **MAIN** | 1 | One per volume, immediately after the marker. Archive-wide flags — solid, volume, recovery — and, in RAR5, the **volume number** the parser checks the set against. It carries no member data, which is why identifying an archive means parsing this one block (§2.1) |
| **FILE** | 2 | One per member, followed immediately by that member's packed bytes. Name, sizes, mtime, attributes, host OS, CRC32, compression info, and in RAR5 an *extra area* of typed records: the redirect (symlink/hardlink/copy), the hash, the file times, the per-file encryption record, the version number |
| **SERVICE** | 3 | Same layout as FILE, but the payload is archive metadata rather than a member — comments (`CMT`), recovery records, NTFS streams, and the **quick-open record** (`QO`): copies of FILE headers stored after the members (§1.1) |
| **ENCRYPTION** | 4 | Present only in a header-encrypted RAR5, and *first* if so: the KDF count, salt and optional password-check value needed to decrypt every block after it. RAR3 has no equivalent block — it encrypts the header stream directly, which is why it has no check value and why a wrong password there is only visible as a structural failure |
| **ENDARC** | 5 | Terminates the walk. Its flags say whether another volume follows, which is what marks a set as missing its last volume (§2.2) |

RAR3's blocks carry the same *ideas* under a fixed 7-byte header — CRC16, type, flags,
header size — where RAR5 frames everything with variable-length integers and a CRC32.

**The metadata is ours; the bytes are another program's.** The two halves of the format are
documented very differently. RARLAB **publishes the metadata layout** — the RAR 5.0
technote, §9 — so the header parser is written against a specification rather than guessed;
the *compression* is proprietary, documented nowhere, and the UnRAR licence forbids using
its source to re-create a compressor. So archivey parses headers natively while `unrar`
decodes payloads (ADR [0002](../decisions/0002-native-rar-metadata-unrar-data.md), threat-model C1).
Everything about that boundary is a consequence:

- **Listing completes without `unrar`** — names, sizes, timestamps, modes, flags, hashes,
  link targets and header decryption come out of the parser (§2.2). Stored old-style
  comments do too; compressed RAR 1.5-4 comments (RAR 1.5 / 2.x COMMENT subblocks and
  compressed RAR 2.9-4 `CMT` headers) are filled when the binary is available and
  otherwise stay `None`. A stored, unencrypted member is read by slicing
  the source, whatever its solid flag, and a split one by joining its parts, so an
  archive of those reads end to end with no subprocess (§2.3). A stored, encrypted
  member in one part is decrypted from the same slice.
- **`unrar` seeks the archive, so it cannot be piped one** — which is why a stream source
  is copied to a temp file the first time a member cannot be read directly, the whole
  archive. `CostReceipt.notes` states that caveat at open. There is no
  "stream it through" option and never was; the only question a stream source poses is
  *where* the seekable copy lives and *how much* of the archive it holds (§2.3, §7).
- **A member name becomes an argv token**, which makes the name a parsing surface for a
  program that was never told the name is untrusted (§2.3, §4).
- **Two numbers cross back.** `unrar` is run with `-inul` and its stderr goes to
  `DEVNULL`, so its own diagnostic text is discarded: the only signals are the exit code
  and how many bytes arrived. Every RAR data error archivey reports is reconstructed from
  those two.
- **A member stream is a pipe**, so a rewind on a named `unrar` open is a respawn and a
  full re-decode (solid: from the archive start), reported as `STREAM_REWIND_REDECOMPRESSES`
  once the solid prefix plus discarded member progress meets the 1 MiB floor. The unnamed
  ALL-pipe used by `stream_members()` stays forward-only (§2.3, §5). Opening a member of
  a solid archive by name decodes again what an earlier open decoded of its solid prefix
  (the archive's for `unrar`, the member's solid stream for `unar`), which logs one INFO
  record per reader on `archivey.backends` (`_solid_run`); it is not a diagnostic.
- **Identity of the binary costs a process.** `find_rarlab_unrar` looks up `unrar`
  first, then `rar`, runs the candidate with only `-cfg-` (so `~/.unrarrc` cannot inject
  `-idq` and empty the banner), and sniffs the banner.
  Major.minor is parsed from that same text (`UNRAR 6.02` / `UNRAR 7.00` /
  `RAR 7.00`) and cached with the probe — not re-read per member. A `RAR` token
  does not match inside `UNRAR`. Below 6.0, or a RARLAB banner whose version cannot be
  parsed, is still cached as RARLAB (`is_rarlab=True`) and still refused
  (`PackageNotInstalledError` names the floor and the version found). A lookalike
  or too-old `unrar` does not hide a usable `rar`. `shutil.which` re-runs
  on every call — a miss is never frozen, so installing `unrar` into a directory
  already on `PATH` is visible without editing the string. The banner verdict is
  cached for the resolved (absolute) candidate together with its stat identity
  (`st_dev` / `st_ino` / `st_mtime_ns` / `st_size`); a hit, a durable "not RARLAB"
  answer, or a too-old RARLAB answer is reused only while that identity is
  unchanged. A probe that times out (10 s) is cached as "not RARLAB" with a
  `timed_out` mark, so a hung binary costs one timeout per process rather than one per
  member read; the refusal names the binary and says it did not answer, on every lookup.
  The trade is that a one-off slow start stays refused until the binary changes on disk
  or the process restarts. A probe that cannot *run* the binary (`OSError`, e.g.
  `EMFILE`) is not cached. There is one entry per resolved absolute path, so
  alternating two `PATH`s does not re-probe. The lookup does not key cwd or `PATHEXT`.

**Blocks chain forward and each header states its own size.** Without a usable RAR5 `QO`
the walk reads a header, uses its declared size to find the next, and stops at `ENDARC`.
In RAR 1.5-4 a FILE or SUB header's data size is its PACK_SIZE (plus HIGH_PACK_SIZE),
whether or not the header sets LONG_BLOCK (0x8000), as `unrar` reads it; other blocks
have data only with LONG_BLOCK. Skipping nothing when a FILE header cleared the flag
parsed the member's data as headers, so a crafted member could carry extra members that
`unrar` does not list (measured, `unrar` 7.00). So:
reading the structure needs seek, and a non-seekable source is refused in both access modes
(§2.1); the whole member table is built at open — walking every header, or reading `QO`
and skipping the FILE headers it already holds (§1.1) — which is why
`listing_limits.max_members` is applied at parse (`ResourceLimitError`; `None` /
`ListingLimits.UNLIMITED` lifts it) — and
every length is a variable-length integer whose byte count the input chooses, so bounds
have to be on **bytes consumed**, not on the decoded value — the one place that was
violated was a quadratic pre-read loop in front of the capped decoder
([`hostile-input.md`](../../review/archive/2026-07-16-rar-reader/hostile-input.md) F2, fixed);
a member split across a volume boundary is rejoined from continuation *flags*, which needs
an identity check or a crafted flag folds an unrelated member into the previous one (F6,
fixed); and a volume set is *discovered* by naming convention rather than by a recorded
disk number, unlike a spanned ZIP — though discovery is where the resemblance ends. RAR5
records a volume number in MAIN and the parser checks the set against it, refusing a
headless set (`Need first volume`) or an out-of-order one. RAR 1.5-4 MAIN records only
flags; RAR 3.0 and later also write the volume's number into its end block, which the
parser reads only to refuse a lone later volume. For ordering, there the name really is
the whole chain.

**Listing is a walk unless RAR5 `QO` is present.** With no `QO`
(all RAR3/4; small RAR5; `-qo-`; header-encrypted RAR5) the parser starts at MAIN and
visits each header in turn, using the declared packed size to seek over the data to the
next one. That is O(members) seeks — the same shape `ListingCost.REQUIRES_SCANNING` names,
which is what `tar_reader` reports for uncompressed tar, and what RAR reports too: the
value names the work, not when it is paid (here, at open). With a usable `QO`, listing
reads those copies first, seeks back to after MAIN, and skips matching FILE headers on
the walk (§1.1).
A walk whose last skip lands past the end of the file lists what it found and then
reports `TruncatedError` as `members_report().error` (`members()` raises it), as TAR
does for a member whose data runs past the end. **A file that ends part-way through a
plain header is the same**: after the header's first byte and before its last, which
for RAR5 includes its CRC and its size vint, the walk lists the members before that
header and reports `TruncatedError`. Measured 2026-10-01 on unrar 7.00 with
`basic_nonsolid__rar4.rar` cut to 140 or 190 bytes: `unrar` lists the members before the
cut, prints "Unexpected end of archive" and exits nonzero. Until then archivey raised
`CorruptionError` at open ("Unexpected EOF while reading RAR3 block header" or "… header
body", and the RAR5 equivalents) and listed nothing. Only a file that ends before the
header's declared bytes counts as a cut: a declared size that is invalid while the bytes
are present (a RAR3 size below 7, a RAR5 size over 2 MiB, a size vint over 10 bytes)
stays `CorruptionError`. A cut exactly at a header boundary lists the members before
the cut, then warns: RAR5 writers always close a volume with `ENDARC`, so a RAR5 walk
that reaches end of file without one emits `ARCHIVE_EOF_MARKER_MISSING`
(`expected_marker="end_of_archive_block"`, `format="rar"`, `observed_kind="absent"`)
once per archive after the members, naming the volumes that lacked it. That is TAR's
missing-trailer rule: the listing completes, and `DiagnosticPolicy.STRICT` refuses it
after delivery. A volume in a set needs the block too — its flags are what say another
volume follows — so a set whose volumes all end in `ENDARC` emits nothing. RAR 1.5-4 is
left alone: old writers may omit the end block,
so its absence there is not evidence of a cut. **With header encryption (`-hp`) a cut
inside a header is a truncated listing too.** Each header there is a salt (RAR3, 8 bytes)
or IV (RAR5, 16 bytes) and then whole 16-byte cipher blocks, and a writer never stops
part-way through one, so a file that ends after the first byte of a salt or IV and
before the header's last cipher block lists the members before it and then reports
`TruncatedError`, in RAR3 and RAR5 alike. Before, `_HeaderDecryptStream.read` returned
nothing for a short last block, which the walk took as a clean end of file: cutting
1-16 bytes off an `-hp` archive lost its end block and nothing more, and listed as
complete (RAR3) or with only the warning above (RAR5); cutting into the salt or IV was
`CorruptionError` at open, with no listing. A header that decrypts its first block and
then runs out is a cut only once the password is proven, and a header that fails its CRC
or size checks is `CorruptionError` only then. RAR5 proves it with the archive's
password check value. RAR3 has none, so the first encrypted header whose CRC16 matches
proves it: the walk already takes a mismatch there as a wrong password, and the same
test acquits as well as convicts. A set has one password, so `parse_rar_volumes` carries
the proof into each later volume's walk. Before that proof (a RAR5 archive with no check
value, or a cut or a CRC16 mismatch inside the first encrypted RAR3 header of an archive
or set) a wrong key decrypts a garbage size that also reads to the end of the file, or
fails the CRC16, so that stays `EncryptionError("…wrong password?")`, and a password
list moves on to the next candidate. When the read ran out of ciphertext, the message
adds the second reading: "if the password is right, the file ends inside the encrypted
header that starts at byte N, or that header is damaged". It comes second because a
wrong key on a small, whole archive also decrypts a size that runs to the end of the
file and gets the same message. It names damage too because damage in a whole header
garbles the size the same way. A header whose read did not run out of ciphertext (a size
under the minimum, refused inside the read, or a CRC16 mismatch over a whole header) gets
no such clause. The cut wording is one helper, shared with the proven cut's
`TruncatedError`. In a set the clause's offset is within one volume, so the raised error
names that volume, as the returned cut and damage strings do. RAR5 does not take a CRC32
match as proof the way RAR3 takes a CRC16 one: RARLAB's `rar` writes the check value
with `-hp`, so an archive without one is crafted, and the walk keeps one proof per
format rather than add a second that only crafted input reaches. Each RAR3 header has
its own salt, so the proof covers the password and not a later header's key: a damaged
later salt decrypts a garbage header, which is `CorruptionError`, or a cut when its
garbage size runs to the end of the file. The boundary cases keep their plain-walk
meaning: an `-hp` RAR5 that ends exactly where the next IV would start gets the RAR5
warning above, and a skip past the end of the file is the packed-data `TruncatedError`.
An `-hp` RAR3 that ends exactly where the next salt would start is a clean end, as in a
plain RAR3 walk.

**Why a cut exactly between RAR 1.5-4 headers is not reported** (measured 2026-10-01,
unrar 7.00, on `basic_nonsolid__rar4.rar` and `encrypted_header__rar4.rar` cut at every
length). At each header boundary, plain and `-hp` alike, `unrar l` and `unrar t` list
the members before the cut and exit 0; every other cut length fails. Reading does not
catch it either: each member listed is whole, so its read succeeds, and the members
after the cut are never asked for. Since these writers may omit `ENDARC`, no reader can
tell "cut here" from "ended here". archivey follows unrar. Until this was settled the
`-hp` RAR3 case raised `CorruptionError` at open, which refused a file whose members
were all intact when only its 24-byte end block was gone, while the same cut on a plain
RAR3 file listed silently. RAR5 differs only because its writers always close with
`ENDARC`, which is what makes the warning above possible there.

**A damaged `ENDARC` keeps the listing** (maintainer ruling 2026-10-03). When the end
block fails its header CRC, RAR 1.5-4 or RAR5, the walk keeps every member before it
and stops; the members open and read as usual. The reader reports the damage
after the members, as `ARCHIVE_EOF_MARKER_MISSING` (`expected_marker="end_of_archive_block"`,
`observed_kind="nonzero"`, `observed_bytes` the block's offset in its volume,
`expected_bytes` 0), one per damaged volume, so `DiagnosticPolicy.STRICT` refuses
after delivery and `members_report().error` stays `None`. This reuses the missing-block
diagnostic on purpose: the damage is after the last member, where TAR also reports a
bad trailer block as `"nonzero"`. Measured 2026-10-03 on unrar 7.00, one CRC byte of the
end block flipped in `basic_nonsolid__rar4.rar` and `basic_nonsolid__.rar`: `unrar l`
lists all six members and exits 0 (RAR5 also prints "Corrupt header is found"), and
`unrar t` tests every member OK, then prints "Total errors" and exits 3. Before the
ruling archivey raised `CorruptionError: RAR3 ENDARC header CRC mismatch` (or the RAR5
generic header CRC error) at open and listed nothing. The parser records each damaged
volume and the block's offset in `RarArchive.end_block_damaged_volumes`; RAR5 signals
the block through `_RarEndBlockCrcError`, raised by `_read_rar5_block` in place of the
generic CRC error.

*Which header counts as the end block.* The type field is read from the same bytes
whose CRC failed, so it is not proof on its own: one flipped byte turns a MAIN or FILE
header's type into `ENDARC` (RAR5 `5`, RAR3 `0x7b`). A CRC-failed header is taken as
the end block only when its type reads as `ENDARC`, its shape is an end block's (RAR5:
no extra or data area, nothing after the end-of-archive flags; RAR3: no `LONG_BLOCK`
flag, header at most 20 bytes), and nothing but zero bytes follows it, as far as the
trailing-data scan's 1 MiB looks; a non-zero byte past that is unseen, as after an
intact block. A FILE header fails the shape. A MAIN header with no extra and no data
area passes it and is kept out only by the blocks after it, so a damaged one at the end
of the file lists as an empty archive with `ARCHIVE_EOF_MARKER_MISSING`; `rar` 7.00's
MAIN headers carry a locator record, which fails the shape. Anything else is a damaged
header (the rule after this one), including a damaged end block followed by a non-zero
byte. Zeros count as nothing because `rar` pads a volume with them (§2.2, trailing
data), so the same damage gives the same outcome on a padded and an unpadded volume.
What that adds to the window is the tail, not a shape: the damaged MAIN case above now
also holds when only zeros follow it. unrar 7.00 is laxer here: with the second FILE
header's type byte flipped to `ENDARC` in either `basic_nonsolid__` fixture, `unrar l`
lists only `file1.txt` and `unrar t` tests it OK and exits 3, dropping the other five
members. These checks bound accidental damage, not a crafted file, and that is enough:
a RAR 1.5-4 file cut at a block boundary already lists the same prefix with no
diagnostic at all, since writers may omit `ENDARC`, so spoofing a damaged end block
only adds a warning.

*Volume sets.* Once the CRC fails, the block's flags are not data, so the walk does not
read its next-volume flag. `needs_next_volume` is then whatever the volume's member
headers (CRCs intact) said: a member whose data continues chains to the next volume,
exactly as for a volume with no end block. With no continuing member the set ends at
the damaged volume, and later volumes the caller passed are not read; the diagnostic
names the damaged volume, so a strict caller refuses and a lenient one has been told.
A continuing member with no next volume supplied is the usual "Incomplete RAR
multi-volume set" `TruncatedError`. This is stricter than `unrar t` on a set: on
`tinyvol.part1.rar` with a damaged end block, `unrar t` follows the split member into
volume 2 and exits 0 without checking volume 1's end block, while `unrar l` reports
"Corrupt header is found" and exits 3. archivey reports it, as `unrar l` does.

*Encrypted headers.* The same password-proof rule as for a cut applies. A proven key
(RAR5 check value; RAR 1.5-4 an earlier encrypted header whose CRC16 matched) makes a
damaged end block the diagnostic above. Unproven, a CRC mismatch reads the same as a
wrong key, so it stays the wrong-password `EncryptionError`: a RAR 1.5-4 `-hp` archive
whose end block is the first encrypted header (no members), and any RAR5 `-hp` archive
whose encryption record has no check value. A damaged block whose type byte is itself
the damaged byte is not recognised as `ENDARC`, so it falls under the damaged-header
rule below.

*Bytes after an intact end block.* The walk looks up to 1 MiB past the block (past any
data area it declares, as for every other block, and past its AES padding under `-hp`,
as the walk's `data_offset` is a ciphertext offset) and keeps the first non-zero byte's
offset in `RarArchive.trailing_data_volumes`. The reader reports each volume's as
`ARCHIVE_TRAILING_DATA` (`expected_marker="zeros_to_eof"`) after the members, DR-3.
Zeros pass. An end block declaring a data area past the seekable range is
`CorruptionError`, as a FILE header's is. `unrar t` 7.00 exits 0 on such a file; 7-Zip
warns, for zeros too. Measured on the committed `rar` 7.00 sets
(`tests/fixtures/rar/README.md`): a volume that comes out at exactly the `-v` size is
padded with zeros up to it, and one that overshoots carries none. `tinyvol_hp.part1-3`
(`-v900b -hp`, 900 bytes) has 142 zero bytes after its end block and
`tinyvol_cut.part1-3` (`-v1500b`, 1 500 bytes) has 77; `tinyvol`, `tinyvol_m3` and
`tinyvol_cut_solid` overshoot (917, 917, 923 bytes) and have none. So the zero rule is
what keeps an untouched padded set clean. The 9 zero bytes at the end of
`tinyvol_rnn.rar` (RAR 1.5-4) are inside its end block, not after it.

*Ordering with a cut.* When the merged listing is also truncated (a later volume cut),
the reader raises `TruncatedError` before it reaches this diagnostic, as it does for the
missing-block one. That is deliberate: under a strict policy, emitting first would
replace the `TruncatedError` with a `DiagnosticRaisedError` about lesser damage.

**A damaged header after MAIN lists the members before it** (DR-2). Any header after
the main header whose CRC fails, other than one taken as the end block above, ends the
walk of its volume there: the parser records it in `RarArchive.damaged` (walks catch
the private `_RarHeaderCrcError`), and the reader lists the members before it and then
raises `CorruptionError`. This is the path the reader uses for `RarArchive.truncated`,
with `CorruptionError` in place of `TruncatedError`. TAR does the same for a damaged
header after its first member. Before this, the walk raised at open and listed nothing.
Measured on unrar 7.00 with the last byte of the second FILE header flipped in
`basic_nonsolid__rar4.rar` and `basic_nonsolid__.rar`: `unrar lb` lists `file1.txt`,
reports "empty_file.txt - the file header is corrupt", lists the other four members,
and exits 3. archivey stops at the damaged header and does not search for the next one:
the damaged header's size is not data, and a search would trust bytes no CRC has
checked yet. A damaged MAIN header still raises at open, since its flags are needed to
read the rest.

*Fields parsed before the CRC.* RAR 1.5-4 parses a FILE header's fields before the CRC
check, because they give the bytes the CRC covers, so a parse error in a header whose
CRC also fails counts as the same damage. With the fields unparsed the true CRC range is
unknown, so that check uses the whole header, a deliberate approximation: it is exact
except for a header with old comment subblocks (`FILE_COMMENT`), whose CRC stops before
them. A bad declared size, and an invalid field under a matching CRC, still fail the
open.

*Volume sets.* The damaged header's size is not needed to find the next volume: its
first header is at offset 0 of a separate file. So `needs_next_volume` is whatever the
member headers before the damage (CRCs intact) said, as for a damaged end block: a
member whose data continues chains the walk to the next volume, whose members are
listed, and the `CorruptionError` follows the whole listing and names the first damaged
volume. This is the missing-middle-volume ruling (DR-2: "read past the gap. list
everything in all available parts, then raise at the end"), and a damaged end block
then lists the same set whichever of its bytes was hit; only the report differs. In
practice such a header is the volume's end block, since a member that continues is the
volume's last. With no continuing member the set ends at the damaged volume. When the
next volume is also missing, the reader raises the usual `TruncatedError` and its
message names the damaged header as well.

*Encrypted headers.* As for a cut and a damaged end block, this needs the header
password proven. Unproven, a CRC mismatch reads the same as a wrong key, so it stays the
wrong-password `EncryptionError`.

### 1.1 Quick Open (QO)

RAR5 can store a SERVICE named `QO` after the FILE stream (before recovery records and
`ENDARC`). MAIN extra 0x01 is the locator: the distance from MAIN to that SERVICE. Each
QO record is a CRC'd copy of a FILE header plus an offset back to the original header,
so `data_offset` is `QOHeaderPos - Offset + header_size`. The payload is stored bytes
(`compress_type` 0x30); we do not run the unpacker on it. Packed member data is not
stored twice.

```
  MAIN  [CMT?]  FILE | packed   FILE | packed   …   QO   [RR?]  ENDARC
                       ▲                 ▲               ▲
                       not in QO         in QO           └── MAIN locator
```

WinRAR's switch is `-qo-` none, `-qo+` every FILE header, default **AUTO**
(`QOPEN_AUTO`): copies **only for relatively large files**, local headers for the
rest ([`-qo` docs](https://documentation.help/WinRAR/HELPSwQO.htm)). Measured
(RAR 7.00): `rar a -m0` with a 240-byte file and a 10 KiB file wrote a 55-byte QO
containing only the 10 KiB name; `-qo+` wrote all three (including the directory).
`rar a` onto an existing archive **rewrites** QO at the new end with the new member
included — it does not leave FILE after the old QO.

**Listing:**

1. Follow the locator and parse QO into FILE copies keyed by `header_offset`.
   Only the first MAIN of a volume is asked. `unrar` 7.00 accepts a repeated MAIN
   (`unrar lb` lists past it), and each try reads a QO payload of up to 16 MiB, so
   following every MAIN's locator let a crafted archive buy that read again with
   each 17-byte MAIN (13 bytes at the format minimum): measured at about 50 ms of
   parse per extra MAIN (DR-9a).
2. Seek back to after MAIN and walk. `CMT` is a normal SERVICE. When `tell()`
   is a FILE in the map, emit those copies in order and seek to the end of
   the consecutive run (the chain is in memory; one seek). AUTO holes — small
   files QO omitted — are not in the map, so their local headers are parsed.
3. After QO, keep walking — recovery records, `ENDARC`, and any FILE a writer
   left past QO. A QO copy whose `header_offset` the walk never hits is not a
   member: `unrar` too substitutes a copy only for a header it reaches (pinned by
   an `unrar lb` oracle). When the walk ends at an end block read whole, the QO
   header reports such copies as `MEMBER_HEADER_RECORD_SKIPPED` with their count,
   and the listing stays as the walk found it. `rar` writes one copy per header it
   caches, so a leftover copy means a damaged or crafted QO, and a strict policy
   can refuse it. A walk that was cut or stopped at a damaged header leaves copies
   unreached for that reason alone, so it reports nothing. A damaged end block with
   only zeros after it stops nothing, but it already makes the archive corrupt, and
   the claim would rest on a header whose CRC failed, so it reports nothing either.
   The report goes on the damaged-service-header channel (`_qo_unmatched_copies`)
   but stays out of that channel's cap: there is at most one per volume, it
   retains nothing attacker-sized, and the cap's overflow message says each header
   it counts was not read to the end, which is not true of this one.

When `-qo+` copied every FILE, the first FILE after MAIN (or after `CMT`) is
in the map and the chain is one seek to QO. UnRAR (`qopen.cpp`) does the same
work the other way around: it walks FILE headers and substitutes the QO copy
on a hit. We start from QO and skip the hits. The win is seeks, not local CPU:
parsing the copies is a bit slower than a FILE walk on a local disk (per-record
`BytesIO`, two CRCs) and cheaper when the source is high-latency.

Member `-p` encryption does not encrypt the QO SERVICE; the FILE
copies still carry encryption extras, and listing uses them. Header-encrypted
(`-hp`) archives put ENCRYPTION first, so the plaintext QO name is absent and we
skip QO (`hdr_enc is not None`); even after decrypt the copies are IV+ciphertext
and `data_offset` misses AES padding. Packed, split, encrypted, CRC-bad, or
locator-field-0 QO also falls back to walking every FILE header. §6.

Measured on `rar a -qo+` (RAR 7.00): every `RarMemberInfo` field `_to_member`
and the stored-read path use matches the FILE walk, extras included (xtime, hash,
redir, encryption, version, owner). Forced QO is stored even at `-m3`/`-m5`;
RAR 7.00 did not emit a packed QO.

**Two on-disk generations hide behind one magic.** `Rar!\x1a\x07\x00` is the RAR3 family —
which is RAR 1.5, 2.x and 3.x, all one block layout, reported as `format_version == "4"` —
and `Rar!\x1a\x07\x01\x00` is RAR5. They disagree about nearly every metadata question, so
the reader is version-conditional almost everywhere:

| | RAR3 family (`version 4`) | RAR5 (`version 5`) |
| --- | --- | --- |
| Timestamps | DOS wall clock → **naive** `datetime` | Unix/FILETIME → **aware UTC**, sub-second |
| Symlink target | stored as the **member's data** | a **header redirect**, no data stream |
| Symlink digest | a genuine CRC32 of the target string | **none surfaced** — the field covers zero bytes (§2.2) |
| Names | dual fields: a compressed UTF-16 name plus an 8-bit name | one UTF-8 field |
| Data encryption | AES-128-CBC from RAR 3.x on, keyed by 2¹⁸ rounds of WinRAR's variant of SHA-1 (§3); RAR 1.5 and 2.x members use older proprietary ciphers. Only `unrar` decrypts member data. No check value | AES-256-CBC, keyed by PBKDF2-HMAC-SHA256 at `1 << kdf_count` rounds (a `kdf_count` above 24 is refused as corrupt). The encryption record usually carries a 64-bit password check |
| Header encryption | no check value — a wrong password is only visible as a structural failure | `ENCRYPTION` block usually carries a check value |
| Encrypted-member digests | plain | key-**tweaked** MACs when `XENC_TWEAKED` is set (§2.2) |

The absent RAR3 check value is why a wrong header password used to surface as
`CorruptionError` and abort a whole candidate list on the first wrong entry
(F1, fixed — candidate iteration works on RAR3 today, §8).

Storing the target as data also means a RAR3/4 symlink can arrive with its target out
of reach, where a RAR5 redirect never can — the redirect is in the header, which the
reader has already parsed by the time anyone asks. The reader reads those bytes
directly out of the archive (no `unrar` hop, even in a solid archive), decrypts a
stored encrypted target as `open()` would (maintainer decision 2026-10-16, so a
password gives the same listing as a plain archive, as in ZIP and 7z), and declines when
it cannot, emitting `SYMLINK_TARGET_UNAVAILABLE` with the reason rather than leaving
`link_target` silently unset:

| `reason` | When | Archive records a target |
| --- | --- | --- |
| `password_required` | the target is encrypted, stored and in one part, and no password was given | yes |
| `password_or_damage` | the target decrypted under the password fails its CRC32: RAR 2.9-4 has no password check, so a wrong password and damage look the same | yes |
| `target_data_encrypted` | the target is encrypted in a form archivey does not decrypt (compressed, split, RAR 2.0's cipher), or `cryptography` is not installed | yes |
| `target_data_split_across_volumes` | the target is split across volumes and a part was not found (a complete split target is joined and read) | yes |
| `target_data_compressed` | the target is LZ-compressed rather than stored M0 | yes |
| `no_target_data` | an unencrypted member's declared and packed sizes are both zero | no |
| `target_empty` | an encrypted member's sizes are both zero: it goes through the decrypting read, which returns no bytes, and the shared empty-target report names it | no |

The code is in `ARCHIVE_INTEGRITY_CODES`, so a strict `DiagnosticPolicy` refuses such
an archive; a lenient one lists the member as a link with no target. The last column is
what extraction does with it: `no_target_data` and `target_empty` are the archive's own
omission and report `ExtractionStatus.LINK_TARGET_UNAVAILABLE` (`docs/extracting.md`);
the other five are targets the archive carries and this read could not reach, so they
stay per-member failures governed by `OnError`. `password_required` is kept for a target
this read can decrypt, as in the ZIP and 7z readers, so a password really is what is
missing; a target it cannot decrypt is `target_data_encrypted`, because a correct
password does not change that answer.

A target the direct read does reach is checked twice before it is used. Its declared
size must equal its packed size, since a stored target is its packed bytes; a header
that declares more would have the read run into the next header. Then the bytes are held
to the member's data CRC32, since the header CRC does not cover the data. On either
mismatch the read raises `CorruptionError`, and it is reported as ZIP and 7z report a
damaged target (`_report_unreadable_link_target`): by the listing, or by a
`stream_members()` pass when it reaches the link (solid or not; the read goes straight
to the archive, not through the `unrar` pipe), and once only. The link stays
listed with `link_target` unset, `SYMLINK_TARGET_UNAVAILABLE` carries
`reason="target_data_damaged"` (so a strict policy refuses the archive), and opening or
extracting the link raises the fault. A RAR5 redirect needs no such check, since its
target is a header field covered by the header CRC.

The RARLAB writer produces only the encrypted case in practice — it stores every
symlink target M0, which is why `target_data_compressed` has no fixture.

**Solidity is archive-wide and its blocks are invisible.** RAR exposes no per-solid-block
boundaries, so `ArchiveInfo.is_solid` is one flag and `CostReceipt.solid_block_count` is
`None` by construction rather than by omission. Consequences: a whole streaming pass is
**one** `unrar` process whose stdout is an undelimited concatenation of payload members;
splitting that back apart relies entirely on the archive's own declared sizes *and* on
knowing exactly which member kinds `unrar` emits bytes for, which is version-dependent —
get it wrong for one kind and every later member is offset (tracked internally); and a
random open of a solid member is a **fresh whole-archive decode** inside `unrar`, one
process per open, because there is no earlier point to resume from.

## 2. The pipeline here

Each stage: who does the work, what is RAR-specific rather than general, what is refused —
and, for the stage that delegates, what crosses the boundary.

### 2.1 Identify

Two magics at offset 0 and two extensions, `.rar` and `.cbr`. Comic-book aliases
across containers are `.cbr` → RAR, `.cbz` → ZIP, `.cbt` → TAR, `.cb7` → 7z.
Magic still wins; a ZIP named `.cbr` (the usual mislabel) opens as ZIP and emits
`FORMAT_EXTENSION_CONFLICT`. Same for the other aliases. Both magics are also
the scan needles for a prefixed archive, deliberately rather than their shared
`Rar!\x1a\x07` prefix: matching each id separately resolves RAR4 vs RAR5 at the
hit instead of re-reading to disambiguate.

The hit validator (`internal/backends/rar_detect.py`) is the **main header that follows the marker**,
and it is checksummed, which makes it a stronger validator than ZIP's field-range checks:

- **RAR5** — read the first block's declared length (capped at 64 KiB for identity, well
  under the parser's 2 MiB header cap), verify its CRC32, then require the block type to be
  `MAIN` or `ENCRYPTION`. A CRC failure after a plausible header is `DAMAGED`, not
  `NOT_THIS_FORMAT`: the payload was identified and is broken, which a later evidence
  ledger can use.
- **RAR3** — require block type `0x73` (`MAIN`), a header size between the structural
  minimum and 64 KiB, and a matching 16-bit header CRC.

Everything else about finding an archive behind a stub — the cue tiers, the 2 MiB
`SFX_MAX`, why validation is the correctness gate and the cue only a cost gate — is shared
and lives on [`topics/prefixed-archives.md`](../topics/prefixed-archives.md). RAR's own
residue is the two-needle choice above, the CRC-checked validator, and the fact that
`SFX_MAX` is shared with `rar_parser`'s *own* stub scan so the parser and the detector
cannot disagree about how far to look.

A self-extracting **and** split RAR set (`rv.part1.sfx`, `rv.part2.rar`, …) is joined
from any part — the `.sfx` (or `.exe`) first volume shares the `partN` stem with later
`.rar` volumes. 7-Zip's stub-only `vol.exe` (no archive magic) follows the split first
volume beside it, including under `format=`. An old-scheme SFX first volume (`name.exe` /
`name.sfx` beside `.r00`) is discovered the same way as `name.rar` + `.r00` — prefer
`.rar` when both exist. A 7-Zip numbered split (`vol.exe` + `vol.exe.001`, no `.r00`)
is still not an old-scheme set; stub-follow owns that shape.

### 2.2 Open and list

`rar_parser.py` parses RAR5 `QO` copies then walks, skipping FILE headers already
in the map; no `unrar`, no `rarfile`. `reader.get()` and name lookup are served
from that table. FILE headers QO omitted are parsed. §1.1.

**Volumes are resolved before parsing.** `name.partN.rar` (RAR5 and newer RAR4), an SFX
first volume `name.part1.sfx` / `name.part1.exe` beside later `.partN.rar` parts, and
`name.rar` (or an old-scheme SFX `name.exe` / `name.sfx`) + `name.r00`, `name.r01`, …
(older RAR4) are all discovered from any member of the set — the old scheme by walking
names from volume 1 under unrar's rule (one added to the letter's character code, so
`.r99` → `.s00` and `.z99` → `.{00`) until a name is missing, then the rest of the
listing's old-scheme names by number (`rar_volume_number`), taken only when the file starts
with a RAR signature, since the shape also matches Info-ZIP's `backup.z01`. Every old-scheme name, volume 1's included, is matched
case-insensitively from one directory listing, except that an SFX stub is an entry
point only when `<stem>.r00` or `<stem>.R00` exists with the stub's own base spelling
(a fast reject that avoids a listing on every `.exe` open). Of two `.partN` files with one
number in different padding (`q.part2.rar` and a stray `q.part02.rar`) or, on a
case-sensitive filesystem, in different case (`Q.PART2.RAR`), discovery takes the name
opened as spelled, then the one padded like the name unrar
predicts, then that name as spelled, then one spelling the base as the opened name does,
then a `.rar` over an `.exe` / `.sfx`, then the lowest name. That is unrar's rule: it goes
back to volume 1 keeping the opened name's spelling and padding and adds one to the number
for each next name, widening the padding once the number outgrows it (from `q.part1.rar`,
part 10 is `q.part10.rar`, not a stray `q.part010.rar`), so measured on unrar 7.00
`unrar t q.part1.rar` is All OK beside the stray and never opens it, and from `q.part02.rar`
it looks for `q.part03.rar`. It took the first match in directory listing order before, which
read the stray as volume 2. A set renamed to mixed widths (`q.part1`, `q.part02`, `q.part03`)
still joins, where unrar stops at "Cannot find volume q.part2.rar". Headers are then read across the volumes
in order with split members stitched into one logical member.
`ArchiveInfo.is_multivolume` is `True` and `ArchiveInfo.extra["rar.volume_count"]`
carries the count. A set whose last volume present says another follows — a lone
volume 1 among them — lists the members whose headers are in the volumes present and then
raises `TruncatedError` ("expects another volume (volume N is missing)"), the channel a cut
file uses (`RarArchive.truncated`, set by `mark_missing_next_volume`). Members wholly
inside the present volumes read normally; the one that runs into the missing volume is
still `split_after` after the merge and raises `TruncatedError` on read, before any
decompressor runs; `extract_all` writes the members before it and then raises. That is
`unrar t`: every complete member OK, then "Cannot find volume" for the last one (ruled by
davitf, 2026-10-06; this used to refuse at open).

**A gap is a missing volume too** (ruled by davitf, 2026-10-06: "list everything in all
available parts, then raise at the end"; and for a missing volume 1, "we should support
it"). Discovery returns every volume present, and when their names number them with a
gap the reader passes those numbers to `parse_rar_volumes`, which checks each RAR5
volume against its own number, merges nothing across a gap, and records the missing
numbers in `truncated`. The member that ran into the gap keeps `split_after`; the
continuation that opens the volume after it is listed on its own with `split_before`,
as `lsar` lists it, and `unrar` warns "You need to start extraction from a previous
volume" for it. Either flag left on after the merge refuses the read with
`TruncatedError` (`_missing_data_error`), and in a solid archive so does every member
past the gap: `unrar` gives checksum errors for them.

**A member whose packed data the file cuts is refused before `unrar` runs.** The listing
already raises `TruncatedError` for such a file, but `members_report()` and a pass still
list the member, so a read reaches it. `unrar` cannot say why it fails there: it exits 3,
which for an encrypted member with no output is also the RAR4 wrong-password answer
(§5), and the bytes it writes for the gap can fail the digest as corruption before
the exit code is read, which depends on timing. So a member that a
program would decode, and whose data ends past the end of the source, raises
`TruncatedError` from the listing's numbers (`_cut_data_error`), as a missing volume
does. A stored plaintext member archivey slices itself still reads up to the cut and
then raises `TruncatedError`, as TAR, ZIP and ISO members do. A stored encrypted member
reads differently in the two modes: `open()` decrypts it with `cryptography` and reads
up to the cut, but a solid pass hands it to `unrar` and so refuses it before any byte,
since what `unrar` writes for the gap cannot be verified (DR-1). Measured with
`unrar 7.00` on `encryption__.rar` cut to 260 bytes, inside its second member: `unrar t`
prints that member's checksum error and "Unexpected end of archive". Before, the same cut read as
`EncryptionError` (wrong password) or as a digest `CorruptionError`, depending on the
access mode and on timing. A member past a gap is read by
pointing `unrar` at the first volume after the gap (`_unrar_path_for`), the way `unrar`
reads such a set opened there; for that a gapped set is always staged, under names that
keep each volume's number, and so is `unar`'s private directory. Opened from any volume,
the listing is the same. Archive data only volume 1 carries — the comment, an SFX stub —
is absent with it. A lone later volume opened by path is a set missing the rest,
numbered by its name; opened as a stream it has no name, and stays
`UnsupportedFeatureError` ("Need first volume"). A later volume is recognised by RAR5
MAIN's volume number, by the RAR 3.0+ end block's volume number (`EARC_VOLNUMBER`, flag
`0x0008`), or by a first member that continues an earlier volume; the path case catches
that refusal and parses the volume again under its name's number. A RAR 1.5 / 2.x later
volume whose first member starts on its boundary records none of these, so as a stream it
lists as volume 1, as `unrar` lists it. (RAR 3.0+ also sets MAIN flag `0x0100` on volume
1, measured on the RAR 6.24 `tinyvol_rnn` fixtures; its absence does not mark a later
volume, since RAR 1.5 / 2.x predate it.) Explicit sequences are still read as `1..N`. An
explicit sequence of volume *paths* is used as given, with no discovery: headers are read
from those files in that order. For a discovered set and an explicit one alike, `unrar` is
pointed at the first file in place only when its own next-volume rule, run from it, finds
exactly the files parsed and nothing past the last. That rule follows the MAIN header's
naming flag, not the names on disk: an old-scheme set renamed `x.part1.rar`, `x.part2.rar`
is continued from `x.part1.r00`, a file archivey never parsed. Otherwise, on the first read
that needs `unrar`, the files are symlinked — hard-linked where a symlink is
refused — into a temp directory under the set's own names, and copied within
`SpoolLimits` only where neither link works. `unar` always gets such a directory. An old-scheme
set is staged as `.rar`, `.r00` … `.z99` and then on past `z` (`.{00`, `.|00` …), because
unrar's next-volume rule adds one to the letter's character code and never switches to
`partN` for an old-scheme set: measured, unrar 7.00 reads 1 500 volumes named that way,
and stopped at 901 when the 902nd was staged as `partN`. `unar` 1.10 reads 901 old-scheme
volumes whatever their names and calls the member damaged, so a longer set is refused
for it (`UnsupportedFeatureError` naming unrar). Stream
volumes are copied into a temp directory named `…partN.rar` so `unrar` can walk the set
later (P11 again) — and the **names** are the point, not just the seekability: `unrar`
discovers later volumes by filename on disk, so neither a `memfd` nor a byte-concatenation
serves them. Measured on the two-part `tinyvol` fixture, where the whole payload is 1 600
bytes: part 1 on disk beside its sibling gives rc 0 and all 1 600, part 1 as an anonymous
`memfd` gives **rc 3 after 839**, and the two volumes concatenated into one file give the
same **rc 3 after 839** — both stop at the volume-1 boundary.

**Header encryption is native.** A RAR5 or RAR3 header-encrypted archive lists with a
password and `cryptography` installed, with no `unrar` involved. Without a password it is
`EncryptionError`; with a password and no crypto backend, `PackageNotInstalledError`. A
password *list* is iterated correctly on both generations.

**Data encryption is `unrar`'s, and `unrar` takes one password.** A list is therefore
resolved before the spawn. A RAR5 member's encryption record carries the same PswCheck
the header block does, so the reader tries the candidates against it (known-good, then
the list, then the provider, per `archive-reading`) and hands `unrar` the one it accepts.
The winner is cached per salt, KDF cost and check; `rar` writes one salt per run, so an
archive usually costs two key derivations per candidate tried (PswCheck, then HashKey;
three when archivey decrypts a stored member itself), not two per member. The
cost of each derivation is the archive's `kdf_count`, and an archive that salts every
member defeats the cache; `DecoderLimits.max_key_derivation_rounds` bounds the total
(threat-model O18). The tweaked-digest HashKey comes from the
same winner. A pass (`stream_members`, one `unrar p` for the whole archive) and a plain
member of a solid archive use the first RAR5 member's winner. **RAR3/4 data has no check value**, so a candidate list is judged by
decoding, under the shared rule in `password_confirm.attempt_with_confirm`: each candidate
runs a bounded probe (`unrar p` of the member, read to at most 64 KiB, then stopped), a
candidate the probe confirms (a member that fits the prefix, CRC matched) wins at once,
and when several survive, each in order is decoded to the member's CRC. A stored member's
probe is native instead, and so is its read: AES-CBC with the member's key, CRC over the
plaintext (a RAR5 tweaked CRC after `ConvertHashToMAC`), no `unrar` (`_stored_check`). In a non-solid archive each encrypted member is judged on
its own data; a solid archive, and the pass over a whole archive, judge once on the first
encrypted member (solid) or the smallest (non-solid). One distinct password still goes to
`unrar` unjudged, and so does an `-hp` archive's header password. A RAR5 member whose
record has no check value, or whose check fails its own SHA-256 checksum, is handled the
same way in a non-solid archive. In a solid one it takes the solid rule above: the winner
of the first member whose check can judge a candidate, and the decode rule only when no
member has one.

**A partial read of a member no check vouched for emits `ENCRYPTED_MEMBER_UNVERIFIED`**
(`check="no_password_check"`). RAR3/4 data has no check to accept a password on at all:
a wrong one shows up only as `unrar`'s exit code or a digest mismatch (table below), both
at the member's end, and `unrar` streams what the wrong key decoded before either.
Measured on unrar 7.00 with `unrar p -inul -p<wrong>`:

- **Stored:** every wrong password returns the member's full length of garbage, then exit
  3. Measured on a scratch copy of the archivey-dev `encryption_with_symlinks__rar4.rar`
  fixture, whose stored encrypted symlinks were retyped as regular files (the attribute
  word and header CRC16 changed, nothing else); not committed.
- **Compressed:** 63 of 200 wrong passwords (`wrong0`..`wrong199`) returned bytes for the
  14-byte `secret.txt` in `encryption__rar4.rar`, and 55 of 200 for the solid
  `a.txt` in `tests/fixtures/external/rar4_solid_encrypted_libarchive.rar`. The rest
  emit nothing and exit 3. The "a compressed one trips the decompressor first" guess held
  for two thirds of wrong keys, not all: a small member's garbage can decode to a
  plausible LZ or PPMd block.

So a caller who reads a prefix and closes got the wrong key's bytes with no signal, the
ZipCrypto shape. The reader wraps the member stream in the same
`UnverifiedPasswordReadWatch` ZIP and 7z use, on every data path (named `unrar`, `unar`,
and both solid passes). What is not watched: a RAR5 member whose own record carries a
usable PswCheck (64 bits, strong enough to accept a password on), and any member of a
header-encrypted archive, whose headers the password already decrypted past one CRC
after another. A RAR5 member with no usable check of its own is watched, even in a solid
archive whose password another member's check picked; that record is hostile or damaged,
and over-reporting an advisory code costs less than a silent wrong-key prefix. With the
`unar` program the question does not arise for RAR3/4: it refuses that data outright (§3).

A wrong key read **to EOF** on a member that did emit bytes surfaces as
`CorruptionError` (the fused CRC mismatch), not `EncryptionError`: the exit-3-to-
`EncryptionError` row below applies only when nothing came out. That split is unchanged
here.

Each encrypted header is its own AES-CBC message (RAR3: 8-byte salt; RAR5: 16-byte IV)
padded to a 16-byte block. `_HeaderDecryptStream.tell()` is the **ciphertext** cursor,
including that padding — that is the correct `data_offset`, because packed data and the
next header's salt/IV start after the padded ciphertext, not after the logical
`header_size`. Leftover bytes in `_buf` are the unread tail of the last decrypted block.
Mid-header that tail is still-owed plaintext; after `header_size` it is AES padding.
Either way, subtracting `len(_buf)` from `tell()` is wrong: on the committed
`encrypted_header__.rar` / `encrypted_header__rar4.rar` fixtures every FILE
`header_size % 16 != 0`, and that counterfactual fails the parse
(`CorruptionError` / `EncryptionError`). The decrypt stream has no `seek`; packed-data
skips go through the underlying `source` after the wrapper is discarded. CBC *can*
reposition by taking the preceding ciphertext block as the IV — `AesDecryptStream`
does — but the parser never needs it, and this wrapper's `tell` is the ciphertext
cursor rather than a plaintext offset.

The decrypt *stage* (`open_aes_decrypt_stage`) is shared with 7z; the pull stream
(`AesDecryptStream` in `streams/crypto.py`) is not a replacement. That class is
the 7z member-data wrapper: `owns_inner` (default borrow), plaintext `tell`/`seek`,
unbounded `read(-1)`. Header parsing still needs a `tell()` that is archive offset
for both arms of the walk (`header_fd` is either the raw handle or the decrypt
stream) and a wrapper that must not report seekable on an unbounded mid-file
handle. Ownership is no longer a divergence — both borrow. Keep the header stream.

``_HeaderDecryptStream.read`` has no 8 KiB cap. Per-header size is the
caller's: RAR5 refuses `hdrlen > _RAR5_MAX_HEADER` (2 MiB) before the body
read; RAR3 `header_size` is a 16-bit field. A tighter cap here used to reject
a well-formed encrypted header as `EncryptionError("…wrong password?")`.
Unbounded `read(-1)` is still refused. The encrypted wrong-password path
decrypts at most one garbage-sized header (then CRC fails and the walk
rewrites that as `EncryptionError`); that is strictly less work than the
unencrypted walk already allows.

**Names, and `encoding=`.** A RAR5 name is UTF-8, and a RAR 1.5-4 name usually has a
UTF-16 field beside its 8-bit bytes; both decode as stored. A RAR5 name, or a RAR5
redirect target, that is not valid UTF-8 decodes with `surrogateescape`, as a TAR name
does: each bad byte is one U+DC80–U+DCFF character, and extraction escapes it the
shared way (`a%FFq.txt` under `STRICT`/`STANDARD`, the raw byte under `TRUSTED`). It
used to decode with `replace`, so `a\xffq.txt` and `a\xfeq.txt` both listed as
`a\ufffdq.txt` and the second superseded the first. `unrar` 7.00 reads both names as
`a` (it stops at the first bad byte), and each still reads its own bytes, because the
mask is built from the stored bytes (§2.3). A
RAR 1.5-4 name with only the 8-bit bytes records no code page, so it is decoded like an
unflagged ZIP name: strict UTF-8 first, with or without the Unicode flag, then
`encoding=` when the caller passed one, otherwise cp437 for a member whose host is
MS-DOS, OS/2 or Win32 and windows-1252 for any other host (§7 has the evidence). So
`encoding=` applies only to bytes that are not valid UTF-8, as in every format (design
rules, ruled 2026-10-07), and a name without the Unicode flag that took the UTF-8
reading over `encoding=` emits `MEMBER_NAME_ENCODING_INFERRED`, as in ZIP and TAR. The
five bytes windows-1252 leaves undefined decode with `surrogateescape` too, so
`b\x81.txt` and `b\x8d.txt` stay two names. The 8-bit field is never tried as UTF-16LE:
almost any even-length byte string decodes that way, so `caf\xe9.txt` used to list as
`慣琮瑸`. The UTF-16 field decodes with `surrogatepass`, as 7z names do (7z.md §2): a
lone surrogate stays in `name`, and extraction writes it by the cross-format rule in
`safe-extraction` ("Lone surrogates in a member name"). It used to decode with
`replace`, which also left the U+D800–U+DFFF arm of `_fix_rar3_astral_truncation`
unreachable. 7-Zip 23.01 writes such a name as 7z's. `unrar` 7.00 holds the field as
UTF-16 code units, one `wchar_t` each, so a valid pair is two characters to its `-n`
matcher (`-n./pair??.txt` selects `pair` U+1F600 `.txt`, `-n./pair?.txt` does not), and
`unrar x` on Linux writes the name cut at its first surrogate unit (`hi\ud800.txt` →
`hi`); both measured. On POSIX the mask goes out as UTF-8 bytes, which cannot carry a
surrogate unit, so it sends each unit as `?`. A member that mask also selects is handled
like a stored glob's sibling (§2.3): refused by default when it comes earlier, read with
`rar_allow_glob_member_concatenation`, and skipped when it comes later. A unit in a
directory component is refused, since a directory glob cannot be sized. Windows argv is
UTF-16, so there the mask carries a valid pair as it is; a lone unit is still refused
there, as in a RAR5 name (what Windows `unrar` does with one is unmeasured). `raw_name`
is always the stored bytes. A name with no Unicode field goes to `unrar` as its stored
bytes, so how archivey decodes it never changes which member a read returns (§2.3); a
name with one goes as the decoded field, as `unrar` reads it. `USES_ENCODING` is true,
so RAR no longer emits `ENCODING_ARGUMENT_UNUSED`. Comments follow `unrar`: a RAR 2.9-4
`CMT` SERVICE header whose attribute field has bit 0 set (`SUBHEAD_FLAGS_CMT_UNICODE`)
is UTF-16LE, read in whole 2-byte units (an odd trailing byte is dropped, as `unrar`
reads `CmtSize / 2` units) and cut at the first U+0000. Every other RAR 1.5-4 comment
(an unflagged `CMT`, or an old-style COMMENT subblock, stored or compressed) is
8-bit text cut at the first NUL, decoded as strict UTF-8, then with the caller's
`encoding=` when one was passed, then windows-1252. A byte the code page leaves undefined
(five in windows-1252) survives as a lone surrogate (`surrogateescape`). That is the
order and the error handler an 8-bit name uses, and the ones a ZIP comment uses, because
a comment records its code page no more than a name does; only the last fallback differs
from a name's (`unrar`'s windows-1252 rather than the host's OEM code page). It is never
guessed as UTF-16LE, for the reason names are not: an even-length `caf\xe9 ok!` used to
list as CJK. A compressed `CMT` SERVICE header (what `rar` 2.9-6.x writes for a comment
that shrinks, so most real ones) is decoded the way a compressed old-style comment is:
the parser keeps its packed bytes as a `_Rar3Comment` with the header's CRC32 and
unicode bit, the listing budget weighs the larger of its declared size and its packed
bytes, and `_resolve_rar3_comment` wraps the bytes in a one-file archive for the selected
program. The decoded bytes are used only when their CRC32 matches, and then decoded as a
stored `CMT` is. One that declares more than 256 KiB (`RAR3_MAX_COMMENT_SIZE`, the most
`rar` writes), or whose packed data is larger than that, is dropped by the walk without
its bytes being read or weighed; an encrypted or split `CMT` is skipped, stored or
compressed. A `CMT` is read from the span the walk skips after its header, which is its
PACK_SIZE whether or not LONG_BLOCK is set, as `unrar` reads it. So no byte is read both
as comment data and as a later header; a read that could overlap the next headers would
let a stack of 35-byte `CMT` headers each re-read the rest of the archive (DR-9a). A
`CMT` whose PACK_SIZE runs past the end of the file is a cut, with LONG_BLOCK set or
clear, and so is a RAR5 `CMT` whose data does: the comment is not read and stays `None`,
the walk skips its span as it skips any packed data, and the members before it list,
then `TruncatedError` (DR-2). `unrar` 7.00 lists those members and reports "Unexpected
end of archive". Until this was fixed the comment read raised `CorruptionError` out of
the walk at open, which discarded the members already listed. The comment gets no
diagnostic of its own: the archive-level `TruncatedError` already says the file is
damaged, and a withheld comment is one of the things a cut file lacks. That differs from
a damaged service header on an otherwise clean archive, which has no archive-level error
and so carries a diagnostic of its own (§6). A comment the walk reads (its bytes in the
file, within the 256 KiB compressed cap, not encrypted or split) whose packed bytes alone
are over `listing_limits.max_metadata_bytes` is refused with `ResourceLimitError` before
it is read (DR-9); a cut comment is a cut as above, and one the walk skips is not
weighed: a stored comment has no size cap of its own, and the read holds every packed
byte, so a 1 KiB budget used to hold the whole comment before refusing.

**Metadata mapping.** Everything comes out of the native parser; there is no library in
between to blame or to defer to.

| `ArchiveMember` field | Source | Absent when |
| --- | --- | --- |
| `name` | Decoded header name, normalized (backslash is a separator); a file-version row is presented as `path;n`, matching WinRAR and `unrar` | — |
| `raw_name` | Stored name bytes, verbatim — including RAR3's `path;n` bytes, which are not rewritten | — |
| `size` / `compressed_size` | Header sizes; RAR3 `FILE_LARGE` extends both to 64 bits, and the packed skip is extended with them so the walk does not misparse past a >4 GiB member (F5, fixed) | — |
| `modified` | RAR4 DOS time → naive local; RAR5 Unix/FILETIME → aware UTC. A stored value that is not a date (a DOS month of 13, a FILETIME past `datetime`'s range) is `None` plus `MEMBER_TIMESTAMP_INVALID`, as in ZIP, TAR and 7z; it is not clamped to a nearby date. The same rule covers `accessed` and the creation slot | The header carries none, the DOS word is zero (unset, as in ZIP), or the stored value was invalid |
| `accessed` / `created` / `ctime` | RAR5 `0x03` time extra (`HAS_ATIME` / `HAS_CTIME`); RAR3 EXTTIME after mtime (ctime then atime; arctime is unused). Same tz convention as that generation's `modified`. No ZIP-style extra-field precedence. The RARLAB writer emits one time extra; a later extra without `HAS_CTIME` / `HAS_ATIME` does not wipe earlier values. The creation slot is `created` from a birth-time host (Win32, and RAR3 MS-DOS / OS2 / Mac / BeOS) and `ctime` from any other. A Unix RARLAB writer fills the slot from `st_ctime` (inode change), which `created` never holds, so a Unix member's slot is `ctime`, and so is an unknown host's | The extra or slot is absent; `created` also when `host_os` is Unix or unknown |
| `mode` | Unix host: `S_IMODE` of the stored attributes, masked before the C helper so a hostile vint cannot raise `OverflowError` mid-listing | Non-Unix host. A Win32 host puts its attribute word in `windows_attrs`; a FAT, OS/2, Macintosh or BeOS host gets **neither** field |
| `uid` / `gid` / `uname` / `gname` | Owner record from `rar -ow`. RAR5: the file header's owner record (`0x06`): each field its flags announce. RAR 7.00 on Linux stores the names when the system resolves them and the numeric ids otherwise, never both. Names decode as UTF-8 with other bytes kept as lone surrogates. A record too short for what its flags announce is dropped with `MEMBER_HEADER_RECORD_SKIPPED`, like the other optional records. RAR 1.5-4 keeps the owner in a `UOW` service header right after the file (after a split member's last part, in the last volume): its data, between the name and any salt, is the user name and the group name, each ended by a NUL or the data's end, as `unrar`'s `ExtractUnixOwner30` reads it. Data with no NUL gives no owner, as `unrar` applies none, and is reported once as `MEMBER_HEADER_RECORD_SKIPPED` on the file it follows unless another `UOW` header after it names an owner, like the RAR5 record too short for its flags. A `UOW` header with no file before it is ignored without a report: there is no member to own it, and `unrar` applies it to nothing. RAR 6.23 writes names only, and no `UOW` header when there are none | No owner record, or the flag for that field is clear; `uid` / `gid` always on RAR 1.5-4 |
| `create_system` | RAR3 `host_os` 0–5 → FAT / OS2 / Win32 / Unix / Mac / BeOS. RAR5 stores only Windows or Unix and the parser maps those to Win32 / Unix | Never — unknown `host_os` is `CreateSystem.UNKNOWN`. Whether the creation slot is a birth time is decided from `host_os` directly, not from this field |
| `type` | Directory flag; RAR5 `file_redir` gives `HARDLINK` for hard links, `FILE` for a file copy (`rar -oi`, "file reference"; below), `SYMLINK` for Unix/Windows symlinks and junctions (a Windows one also sets `extra["is_reparse_point"]`, and a junction `extra["is_junction"]`). A directory flag over a non-zero unpacked size (`rar` never writes one; unrar's `ReadHeader50` accepts it and its `extract.cpp` directory branch returns before the data) stays a directory and emits `MEMBER_DIRECTORY_DATA_IGNORED` (also for an unpacked size of 0 over a non-empty packed body, which `open()` then refuses as having no data). `open()` slices stored, unencrypted directory data itself; compressed or encrypted directory data raises `UnsupportedFeatureError` before any spawn, since `unrar p` emits nothing for a directory. `stream_members()` yields a stream for the same directories that opens the same way on its first read; in a solid pass it is served outside the `unrar p` pipe and takes no offset there. A Unix-host FIFO, device or socket mode makes `OTHER` only when the unpacked size is 0; with data it is a `FILE` with `MEMBER_SPECIAL_FILE_HAS_DATA` (`unrar` extracts the bytes as a regular file), DR-25. Both carry `extra["special_file_type"]`. `rar` skips such files when archiving, so only a rewritten header produces either | — |
| `link_target` | RAR5: the redirect's target string, at list time; on a file copy, the source's stored path. A Windows symlink or junction (redirect types 2 and 3) holds a Windows path, so it goes through the normalizer ZIP and 7z reparse buffers use (`windows_reparse.normalize_windows_link_target`): `\` becomes `/`, as `unrar`'s `DosSlashToUnix` does, and a leading `\??\` or RAR 5.1's `/??/` is dropped (`\??\C:\Windows` lists as `C:/Windows`, `\??\UNC\srv\share` as `//srv/share`, `..\up\x` as `../up/x`). Extraction refuses a drive or UNC target on every OS (`safe-extraction`); `unrar` on Linux refuses the prefixed ones and `../up/x` and creates `C:/abs/y` as a relative link, measured on 7.00. A Unix symlink (type 1), a hard link and a file copy keep the stored string. RAR4: the member's **data**, read directly when it is stored and unencrypted | An encrypted or compressed RAR4 target with no direct bytes — left unset; listing still succeeds |
| `compression` | Method id → `CompressionMethod`. Stored members report `STORED`; M1–M5 report `CompressionAlgorithm.RAR` with `level` 1–5 (method byte − 0x30). A method byte outside M0–M5 stays `UNKNOWN` with `level` omitted. Unpack version is `extra["rar.extract_version"]`, not `level` | — |
| `hashes` | `crc32` and/or `blake2sp` as bytes | A RAR5 **redirect** (see below), or an encrypted member whose digests are tweaked |
| `is_encrypted` | Per-member encryption flag | — |
| `is_current` | `False` for a file-version history row, `True` for the live revision. Stamped for duplicate names when the walk ends, and members settle (`member_state_final`) when links are resolved: a streaming pass, and a random-access pass over a solid archive with no listing call before it, yield each member with `member_state_final=False` until the pass ends; a pass after `members()` yields settled members. A RAR4 symlink whose target is unread (`read_link_targets=False`) also reads `False` until it is read. No other field changes after a member is yielded, unlike a ZIP read from a pipe ([`zip.md`](zip.md) §2.2.2) | — |
| `extra` | `is_file_copy` on a file copy; `is_junction` on a Windows junction, `is_reparse_point` on a Windows symlink or junction (redirect types 2 and 3) — RAR is the one format that names the kind in a header field, so both are set while listing with nothing read; `rar.file_version` on a history row; `rar.tweaked_crc32` / `rar.tweaked_blake2sp` on a tweaked-digest member; `rar.extract_version` when the FILE header recorded one (stored and compressed) — RAR3 `UNP_VER` as stored (unvalidated), RAR5 reports 50. The RAR5 compression-info version (0 for RAR 5.0 data, 1 for RAR 7.0) is read only to refuse one `unrar` cannot decode, and is deliberately kept internal: `rar.extract_version` stays 50 for both because the `rarfile` parity oracle compares it, and a second key waits for a caller who needs it | — |
| `comment` | RAR3 CMT SERVICE when the solid flag is set (attaches to the preceding member) and RAR 1.5 / 2.x FILE COMMENT subblocks. Stored comments decode natively; compressed ones (old-style or `CMT`) decode through RARLAB `unrar` when available | No member comment block, a RAR5 `CMT` (archive-only, below), a compressed comment without `unrar` / with an invalid CRC, or an encrypted comment (known limitation, §5) |

**Archive comments are `ArchiveInfo.comment`.** RAR5 `CMT` is archive-only — it never
becomes a member comment. It is UTF-8 by the format, so `encoding=` does not apply, and
a byte that is not valid UTF-8 survives as a lone surrogate, as in a RAR5 name. `rar`
7.00 never stores one: it writes a comment file's undecodable byte as U+FFFE followed by
U+E000 plus the byte, which is valid UTF-8, and `unrar l` prints `??` for the pair. RAR3
`CMT` without the solid flag is the archive comment; with it, the preceding member (row
above). RAR 1.5 / 2.x COMMENT subblocks on MAIN are the archive comment. Stored archive
comments decode natively; a compressed one (old-style or `CMT`) without `unrar` stays
`None` and listing still succeeds.

**A RAR5 file copy is a `FILE`.** `rar -oi` stores a second identical file as a
redirect of type 5 (`FILE_COPY`; `unrar lt` says "File reference") naming an earlier
member, with no data of its own: packed size 0, unpacked size the source's, CRC32
`0x00000000`. `unrar x` writes it as an independent file, a copy and not a hard link, so
archivey lists it as `MemberType.FILE` with `extra["is_file_copy"] = True`,
`link_target` set to the stored source path and `link_target_member` set to the source
member. Reading it (`open()`, `stream_members()`, `extract`, on `unrar` and `unar`,
solid or not) returns the source's bytes, verified by the source's digest; `unrar p` with
no member names and `unar` emit nothing for a copy, so the copy has no place in a solid
pass's pipe. A solid pass (`stream_members()`, extraction) keeps each source a later copy
reads as its pipe passes it, read by the caller or not, and serves the copies from that
(`rar_copy_sources.py`): a named open of the source would decode the solid stream again
from its start, so fifty copies of a 1 KiB file behind 100 MiB of solid data decoded
about 5 GiB in 51 decompressor runs, and now decode 100 MiB in one. Up to 8 MiB per pass
is kept in memory (a tuning constant, not a caller limit) and the rest in a temporary
file charged to `SpoolLimits.max_bytes` from the source's first decoded byte until the
pass ends, so a pass that reads nothing writes nothing and the pass's own copy of a
stream source is charged first. A source with no room left, or one the pass does not
emit (a `unar` refusal), falls back to the named open, which is also what `open()` and a
non-solid archive use (there a named open decodes only the source).
Extraction keeps none of the sources it writes from the pass: the pass asks
(`FileCopyPass.keep_source`) at a source's first decoded byte, and the coordinator says
no for a member whose stream it is writing. Each later copy is then copied from that
file, after checking on the opened file that it is still the one written (device, inode,
size and mtime); if not, or if the source was never written, the copy reads its stream,
which serves kept bytes or decodes the source again. A dry run writes empty files, so it
keeps sources as a plain pass does. `stream_members(file_copy_streams=False)` yields
`None` for each copy and the pass keeps nothing. The source is the latest
**earlier** member whose name the target names (archive-root relative, like a hard link
target) and it must be a `FILE`; a copy of a copy stands for the first source. A copy
with no such source still lists, and reading it raises `LinkTargetNotFoundError`; a copy
whose declared size differs from its source's raises `CorruptionError`. A RAR5 hard link
(`rar -oh`, type 4) stays `HARDLINK`.

Two digest rules are worth stating because they look like missing data and are not:

- **A RAR5 redirect surfaces no digest.** A symlink, hard link or file copy keeps its
  target in a header field and stores no data stream, so its CRC32 field covers zero bytes
  and RARLAB writes `crc32(b"") == 0`. That value describes nothing and is identical for
  every redirect in every archive, so a de-duplicating caller reading `member.hashes` would
  see every link as the same content. Measured against the other formats: ZIP `0x2d212004`
  over 9 stored bytes, 7z `0x2b4106af` over 45, TAR none, RAR5 `0x00000000` over **zero**
  ([`rar-corpus-sweep-diagnosis.md`](../investigations/rar-corpus-sweep-diagnosis.md)). The
  rule keys on the *redirect*, never on the member type — **RAR3/4 stores the target as
  member data**, so its CRC32 is a genuine digest and is kept.
  A link member's digest, where one exists, is a digest of the **target string** — the bytes
  the format stores for that member — not of whatever the link resolves to. That is true of
  ZIP and 7z as well, so it is a property of `hashes` rather than of RAR: for a link, the
  field answers "what path is recorded here", not "what content is there". Kept, because the
  value is real and dropping it in one format only would trade this for a worse
  inconsistency; said out loud, because `hashes` otherwise implies content.
- **Tweaked digests are kept out of `hashes`.** With RAR5's tweaked-encryption flag set, the
  stored CRC32 and BLAKE2sp are key-derived MACs (`ConvertHashToMAC`), not checksums of the
  plaintext — the format transforms them precisely so a stored digest is not an oracle for
  guessing encrypted content. Comparing one to a plaintext digest would report corruption on
  a good archive. They are exposed under `extra` and verified by applying the same forward
  transform once a password is available; without one, each emits
  `DIGEST_UNVERIFIABLE(reason="tweaked_checksum")`.

**File-version history is listed, not hidden.** A `-ver` archive's prior revisions appear as
`path;n` with `is_current=False`, the live revision keeps the plain path, and `read("path;1")`
returns that revision's bytes. The `;n` split only fires when the suffix after the last `;`
is one to ten ASCII digits and only when the version flag is set, so an ordinary `a;b.txt`
is not misattributed. `str.isdigit()` alone let `a;²` and a 5 000-digit suffix through to
`int()`, which raised a bare `ValueError` from `open_archive`.

### 2.3 Member data

This is the boundary. Three routes, and which one a member takes is decided entirely from
its header:

| Route | When | Cost |
| --- | --- | --- |
| **Direct slice** — no subprocess | Stored (`-m0`, or `-ms<ext>` inside a solid archive), unencrypted; a member split across volumes has its parts joined | A read of the source range. Measured: reading every member of `basic_nonsolid__.rar` spawns **zero** processes |
| **Decrypted slice** — no subprocess | Stored, encrypted, in one part: RAR 2.9-4 (AES-128, key and IV from the password and the 8-byte header salt) or RAR5 (AES-256, PBKDF2 key, IV from the encryption record); `cryptography` installed | `AesDecryptStream` over the slice of `compress_size` bytes (padded to 16), cut to `file_size`, digest-checked, seekable. Password chosen as for `unrar` (below). A split member is not decrypted here: each part carries its own encryption record (measured, `rar` 7.00), so it goes to the program. Without `cryptography` the program reads it; with neither, the error names both |
| **Named `unrar p`** | Any member the row above does not cover — which in a solid archive is normally all of them, since `rar -s` compresses them | One process per open, and in a solid archive each decodes from the archive start. Concurrent opens do not share that work: three overlapping reads are three live processes and three full decodes. A read the single-live-stream gate refuses costs nothing, the slot being reserved before the spawn (§5). With `seekable_members=True`, a backward `seek()` closes that process; the next `read()` respawns it and skips to the offset. The rewind diagnostic's cost includes the solid prefix, not just the bytes already read from this member |
| **One unnamed `unrar p` pipe** | A streaming pass over a solid archive | One process for the whole pass. Measured on `basic_solid__.rar`: one streaming pass = 1 spawn; opening each of its 4 members = 4 |

The pipe is spawned on the **first read into the pass**, not at pass start, so listing a
solid archive through `stream_members()` — or an extraction whose selector matches nothing —
never starts `unrar` and is never asked for a password.

**A solid archive can mix stored and compressed members.** RAR picks the method per
file: `rar -s -m3 -msbin` compresses most files and stores the `.bin` ones as they are.
A stored member still gets its own solid flag (`file_solid`), which on a compressed
member means "continue from the previous member's decoder state". Its bytes are
plaintext in the archive all the same, so the direct slice reads them and ignores the
flag. `unrar` decodes every compressed member ahead of it to reach those bytes, which is
why a stored member read through `unrar` is charged the window ahead of it (§7,
"A stored member of a solid archive"). `stored_solid_member__.rar` is that shape: a
compressed `first.txt`, then a stored `second.bin` with the flag set.

**The argv is constructed defensively, because the member name is attacker-controlled.**
`unrar p -inul -cfg- [-ver] (-p | -p-) [-n./<member>] -- <archive>`:

- **The archive path follows `--`.** The caller chooses it, and a relative path such as
  `-inul.rar` was otherwise parsed as a switch: `unrar` exited 7 with no output and every
  compressed member read as truncated. `--` is RARLAB's documented end-of-switches marker;
  measured on `unrar` 7.00 and `rar` 7.00. An `@` prefix needs no guard in this position:
  `unrar` reads the first non-switch argument as the archive, and only later file-name
  arguments as list-files (also measured on 7.00).

- **The member is never positional.** It is the value of the `-n` include mask, prefixed
  `./`. Passed positionally, a member literally named `-inul` is parsed by `unrar` as a
  *switch* — which drops the filter, so `unrar` prints **every** member's data concatenated
  and exits 0, and the caller asking for one member receives another's bytes; and a member
  named `@atfile` is parsed as a **list-file**, making `unrar` open an attacker-chosen local
  path. Both were confirmed end to end against committed fixtures
  ([`unrar-boundary.md`](../../review/archive/2026-07-16-rar-reader/unrar-boundary.md) F3).
  A `--` end-of-switches guard fixes the first and **not** the second — `@` expansion still
  happened after `--` — which is why the include mask is the fix: inside `-n`, a leading `-`
  is not a switch, and a value starting with `.` is not a list-file. For a name **without**
  wildcards, `./` also anchors the mask to the exact archive path, though `unrar` still
  selects everything *below* that path (`ab` selects `ab/x`). Once the name contains
  `*` or `?` in the **basename only**, the same mask matches that basename at any depth.
  A glob in a directory component, or a backslash in the name `unrar` reads, is still
  `UnsupportedFeatureError` on the unrar path: Windows `unrar` treats `\` as a separator
  so `-n./a\b_TGT.txt` emits nothing, and a directory glob has not been measured enough
  to demux. POSIX `unrar` reads the `\` of a Windows-host RAR5 name as `_`, so that
  name reads through the `_` mask. On Windows a stored backslash is refused in every
  case, since `unrar` there turns every RAR5 `\` into `_` and that is unmeasured.
- **Which members a mask selects is computed the way `unrar` 7 computes it.**
  `rar_unrar.py` ports the steps from the `unrar` source: how a name is read from the
  header (`UtfToWide` cuts a RAR5 name at its first invalid byte and accepts overlong
  forms; `CharToWide` maps each invalid byte of an 8-bit name to a private-use
  character on Linux; `ConvertFileHeader` turns a Windows-host RAR5 `\` into `_` on
  Unix), how the path is cleaned (`ConvertPath` drops leading `./`, `../` and anything
  up to the last `/../`), and how the mask is compared (`CmpName` with
  `MATCH_WILDSUBPATH`, including the rule that a trailing `.` in the mask may stand for
  nothing). `unrar_member_view` gives the name `unrar` reads, `unrar_mask_view` the
  mask, and `unrar_mask_selects` the comparison.
- **Every read sizes a skip past the members its mask selects before the target**, not
  only a glob read: two members with the same name, two names `unrar` reads alike, and
  a mask that names a directory holding earlier members all emit more than the target.
  `RarReader._unrar_selection` looks the candidates up in an index keyed on each
  member's view (built once per reader), skips their unpacked sizes, and bounds the pipe
  at the target's size when anything else is selected. The mask is refused before the
  spawn when it would not select the target, when `unrar` reads the name as empty
  (`\xff`, overlong `\xc0\x80`) or with no name part, when the name holds a surrogate
  that argv cannot carry, and when an earlier member's name cannot be read the way
  `unrar` reads it on this host (a non-ASCII 8-bit name with no UTF-8 locale, or a
  code point glibc converts past U+10FFFF). A later member that cannot be modelled
  only forces the bounded pipe. Those refusals name `rar_decompressor='unar'`, which
  addresses members by position.
- **`*` and `?` in a member name are `unrar` wildcards, not archivey's.** Masks have **no
  escape** (`[` and `]` are literal; `\` does not escape), so `-n./a*.txt` concatenates
  every matching member in archive order with no headers — including `subdir/aY.txt`.
  `open("a*.txt")` is still an exact-name lookup. Skip the unpacked size of earlier
  payload matches (omitting `-ver` history rows unless the target is one), then stop at
  the target's size so the fused overrun probe does not see the next match. Stored
  members never take this path. A glob confined to the basename, with no `\`, is the
  demuxed set; a glob in a directory component and a backslash stay refused (§5). The
  `rar_allow_glob_member_concatenation` refusal still applies only to a glob name; a
  name with no `*` or `?` that shares its mask with earlier members reads without it.
- **`-ver` is added** when the target is a history row, or when a solid pass contains any
  versioned payload FILE, because the mask excludes history rows otherwise and the demux
  would go out of alignment.
- **The password goes to stdin**, not into argv: the switch is a bare `-p` and the secret is
  written to the child's stdin, so it never appears in `/proc/<pid>/cmdline`. With no
  password the switch is `-p-`, which disables the interactive prompt so `unrar` cannot
  block on stdin. What is written is the first 127 UTF-16 units, the part the native key
  derivation hashes; `unrar` 7.00 cuts a RAR5 password there too (127 characters plus
  100 000 more decrypted). That bound is also what makes writing it all before reading
  stdout safe: a 200 KB password once filled the stdin pipe while `unrar` filled stdout,
  and both processes waited. A password with a line break or a NUL is refused with
  `UnsupportedFeatureError`, because `unrar` ends the password there: measured,
  `"password\x00zz"` decrypts a RAR4 member whose password is `password`.
  A password whose 127-unit cut falls inside a surrogate pair has no UTF-8 form to
  write. On RAR5 it is a wrong password (`EncryptionError`), as on the native path,
  because RAR5 hashes UTF-8. On RAR 1.5-4 the native path hashes the UTF-16 units as
  they are, so it accepts exactly this password and a header CRC can prove it right;
  there the limit is `unrar`'s stdin, and the read raises `UnsupportedFeatureError`.
- **The mask is built from what `unrar` compares against.** An 8-bit RAR3 name (no
  Unicode flag) goes into argv as its **stored bytes**: `unrar` runs both the argv mask
  and the stored name through the C library's multibyte conversion, so the bytes match
  in every locale. Measured on 7.00 with `caf\xe9.txt`: the stored bytes match under
  `C`, `POSIX` and `C.UTF-8`; the UTF-8 of the decoding archivey presents never does.
  Every other name goes in as the UTF-8 of the name **as `unrar` reads it**, not as
  archivey presents it: a RAR5 name cut at a bad byte is masked with the prefix
  (`ab\xffcd.txt` as `ab`), and a RAR3 emoji whose UTF-16 field holds only `U+F600` is
  masked with `U+F600` (measured: the real emoji selects nothing). On POSIX the switch
  is passed as bytes, so the filesystem encoding cannot change it. Windows argv is
  Unicode, so there the text is used in every case.
- **`unrar` runs under a UTF-8 locale.** Its child environment sets `LC_ALL` to the
  first of `C.UTF-8`, `C.utf8`, `en_US.UTF-8`, `en_US.utf8` that the C library loads
  (asked once per process with `newlocale`, which touches no global state). Measured:
  under `LC_ALL=C` a non-ASCII RAR5 name never matches its own mask and the read looked
  truncated. With no UTF-8 locale, a non-ASCII text mask is refused with
  `UnsupportedFeatureError` naming `rar_decompressor='unar'`. Windows keeps its
  environment.
- **A NUL in a member name is refused** before the spawn with `UnsupportedFeatureError`: an
  argument is a C string, so the mask would end at the NUL and could name another member.
  `unar` addresses entries by index and reads such a member.

**A path is required, and a stream source pays for it.** The requirement is stronger than
"prefers a file": `unrar` *seeks* the archive and refuses every non-seekable input. Worth
measuring rather than assuming, because the binary's own switch list invites the opposite
conclusion — `-si[name]` is documented as "Read data from standard input", and it is a
`rar` **compressor** switch that on `unrar` is a command-line error
(`scripts/exploration/rar_unrar_input_matrix.py`, RARLAB unrar 7.00):

| Handed the archive as | |
| --- | --- |
| `unrar p -si` with no path, archive on stdin | **rc 7** — command-line error |
| `unrar p -` | **rc 7** — `-` is not stdin to `unrar` |
| `unrar p /dev/stdin` with a **pipe** behind fd 0 | **rc 2** — fatal, non-seekable |
| `unrar p <a FIFO path>` | **rc 2** — same |
| `unrar p /dev/stdin` with a **seekable file** behind fd 0 | rc 0 |
| `unrar p /proc/self/fd/N`, N an inherited **memfd** | rc 0 |

An anonymous seekable `memfd` is therefore the one door left open, and it does not survive
multi-volume (§2.2); bounding the copy rather than relocating it is §7.

So the first member that cannot be read directly triggers a copy of the **entire archive**
to `tempfile.mkstemp(suffix=".rar")` — mode `0600`, removed on reader close. For a
non-path stream, `CostReceipt.notes` states that caveat **at open** (§7) —
including when only stored members are read and the copy never happens. There is still
no diagnostic. The copy itself is per-member, so a stored member costs nothing and the
next compressed member in the same archive costs a full copy.

**Explicit stream volumes wait for the same trigger.** `_materialize_stream_volumes()`
runs from `_ensure_archive_path()` too, so a list of open volume streams is copied on the
first member read `unrar` has to serve, not at `open()`. The header walk reads the
originals: `parse_rar_volumes` needs each volume as its own stream positioned at its
start, which the concatenation cannot be, so the reader mints one bounded `SharedSource`
view per volume from `ConcatenatedFile.volume_ranges`. A caller who only lists writes
nothing. When the copy does happen it writes the **whole set**, because `unrar` resolves
siblings by name; only its timing changed. It used to run from `RarReader.__init__`,
which cost the two-volume `tinyvol` fixture 1757 bytes at open, 100% of both volumes,
with no `read()` on the reader.

**What crosses back is an exit code and a byte count.** `-inul` suppresses `unrar`'s
messages and its stderr is discarded, so archivey reconstructs every data error from those
two signals:

| Signal | Mapped to | Note |
| --- | --- | --- |
| exit 11 | `EncryptionError` | RARLAB's bad-password code |
| exit 2 or 3, encrypted member, zero bytes out | `EncryptionError` | RAR4 reports a wrong password this way rather than as 11. A genuinely corrupt encrypted member that also emits nothing is mislabelled; the bias is deliberate, since a caller cannot make progress on either without the right password |
| exit 2 or 3 | `CorruptionError` | **Only when archivey has no hash of its own.** A member with a CRC32 or BLAKE2sp is verified here, and that check is authoritative — `unrar`'s code is suppressed to avoid legacy-format false positives |
| exit 10, named open | `CorruptionError` | "no files matched" — **also suppressed** when archivey has a hash, and the read then fails from the fused length check as `TruncatedError` instead, which is the observable difference |
| exit 0 or 1 | pass | |
| negative | pass | archivey terminated the process on an early close |

Mapping runs on the completing (empty) read as well as on close, so a fault surfaces from
`read()` rather than only from `close()`. Independently of the exit code, every RAR member
read is bounded by its declared size and checked against its digest in one fused stage:
over-long is `CorruptionError` at the boundary, short is `TruncatedError`. That is what
covers the members `unrar`'s exit code cannot speak for — a hash-less member, a partial read,
or an empty stream that reaches EOF cleanly.

**Without the binary**, a compressed read, or an encrypted one archivey does not decrypt
(above), raises `PackageNotInstalledError` naming RARLAB `unrar` or `rar` and naming
the lookalikes that are *not* accepted. A RARLAB binary older than 6.0 (or whose banner version cannot be parsed) raises the same
exception at the banner probe, once, cached with the probe, naming the floor and the
version found. Open, listing, and stored reads still succeed: a missing or too-old
binary is caught when resolving compressed comments, and those stay `None`
(§2.2). With the default `rar_decompressor="auto"`, `unar` is used instead when no
RARLAB program is found; `7z` and `unrar-free` never are (§3, threat-model C1).

### 2.4 Extract

Path traversal, symlink escape, name collisions, cross-platform name safety and the
byte/ratio/member caps are the shared extraction spine —
[`safe-extraction`](../../openspec/specs/safe-extraction/spec.md) and
[`threat-model.md`](../threat-model.md). A blocked member does not end the run.

Three things are RAR's own. File-version history rows are skipped by default and recorded
as `SUPERSEDED`, through the spine's existing `is_current=False` behaviour — their `path;n`
names are unique, so the shared last-entry-wins pass leaves them alone. Extracting a solid
archive rides the single streaming pipe rather than opening members one at a time. Repeated
random `open()` of a solid member is a fresh whole-archive decode each time — by design,
not a gap: amortizing via `unrar x` into a temp directory was considered and rejected
because it hides decode work behind later reads (`VISION.md`; §6).

**A RAR5 hard link resolves to an earlier member only, in both modes.**
`unrar` extracts one from what it has already written: when the target comes later it
fails with "You need to unpack the link target first" (exit 9), and a hard link to a
symlink becomes a second name for the symlink on Linux. On macOS `link(2)` follows the
symlink, so `unrar` links its target file there; archivey writes the symlink everywhere,
as GNU tar does. The base reader never looks forward for a hard link's target, so
random access and a streaming pass agree with each other and with `unrar`, as TAR does
(`tar.md`). `unar` differs: it writes every RAR hard link as a
symlink to the target name, which is why a forward one appears to work there.

**A listing cut part-way extracts its prefix, then raises.** `extract_all` writes the
members listed before the damage, runs the hard-link second pass over them, and raises
the listing's own `TruncatedError` or `CorruptionError`, in both modes and under either
`OnError`, with no report — as TAR does and as `unrar x` does on the same cuts. Before
that ruling (davitf, 2026-10-03; §6) a random-access extraction listed first and refused
before writing anything, while a streaming one wrote the prefix.

### 2.5 Write

Not shipped, and not RAR-specific: no format has a writer. RAR would be the least likely
candidate regardless — the compressor is the half of the format nobody outside RARLAB has
reimplemented, and the UnRAR licence forbids using its source to try.

## 3. In the wild

**The format is defined by one vendor's tool, and that tool is not redistributable.** RAR
compression is proprietary with no published decompressor specification; RARLAB `unrar` is
freeware, and the `rar` *writer* is trialware. So the same archivey code path works or
fails depending on what the host has installed, and listing and reading have different
requirements. That asymmetry is the whole reason for the native-metadata split.

**Nothing else on a normal machine is a safe substitute**, which is why the fallback is
refused rather than merely discouraged. RARLAB `rar` (the trialware writer) is the
*same vendor's decompressor under a different name*: Ubuntu's `rar` package Suggests
`unrar` and does not put `unrar` on `PATH`, so `apt install rar` alone used to miss.
On 7.00, `rar p` matched `unrar p` on the extract argv; the finder now accepts a
`RAR x.yy … Alexander Roshal` banner when `unrar` is missing or unusable, still
preferring `unrar`, still spawning only `p`. Windows `Rar.exe` banner is
unmeasured. Measured across the other candidates
([`alternative-rar-decompressors.md`](../investigations/alternative-rar-decompressors.md)):

| Candidate | Verdict |
| --- | --- |
| **`unar` / MacPaw XADMaster** | **Shipped as the second program (default `"auto"` uses it when no RARLAB binary is found), gated** — see the paragraph after this table. Before the gate: **silently wrong**. On a RAR5 **solid** archive containing any empty FILE, reading a *non-empty* member fails — Debian's 1.10.1 SIGSEGVs with 0 bytes, and the newer 1.10.7/1.10.8 lineage (what Homebrew ships) exits **0 with empty output**, on stdout *and* on extract-to-disk. The newer behaviour is the dangerous one, and skipping the empty members in the argv does not help; the solid decoder still walks that slot. Debian's 1.10.1 also drops a compressed RAR5 member when a Huffman lookup peeks past its packed data, solid or not, with exit 0 (a Debian patch, also in Debian's 1.10.8 packages before 1.10.8+ds1-10). `find_unar` runs every `unar` once on such a member and does not use a build that drops it; for a build that passes, the per-member size and digest check still turns a short member into an error, and the solid pass reads a member with no digest through a run of its own. Apart from those it matches `unrar p` on what was measured, which is why it is not closed — see below. [`known-issues.md`](../known-issues.md) |
| **`7z`** | A codec lottery, and short of what this backend needs even when it wins. Ubuntu's `7zip` advertises RAR under *Formats* while the *Codecs* list has no `Rar5` until `7zip-rar` is installed — so it lists and extracts stored members, then says `Unsupported Method` on anything solid or typically compressed. With the plugin the ALL-pipe matches `unrar p` on our fixtures, but it takes the password **on argv**, reports a **missing member as rc=0**, and cannot address **`path;n`** — the three things §2.3, §4 and file-version reads depend on. And it is still a RARLAB-derived non-free codec under another name. Homebrew's `7zz` compiles it out entirely |
| **`bsdtar`** | No solid, no password — and on a stored non-solid fixture, `--to-stdout` wrote **~7 GB** before the probe harness capped it, from an archive of a few KiB |
| **`unrar-free` 0.1.3** | Extract-to-disk only; no stdout at all |

**Update 2026-09-26: `unar` shipped as the second program**
(`ArchiveyConfig.rar_decompressor="unar"`), at the maintainer's request. The gate is
wider than the one proposed below: RAR5 solid members after an empty file *or a
directory*, RAR 1.5 compression, encrypted RAR 2.x-4.x data, non-ASCII passwords and
header-encrypted RAR5 volume sets are refused before `unar` runs; a prefixed single file
is copied first, from where the RAR starts. That copy is bounded by `SpoolLimits` like a
stream source's (maintainer decision 2026-09-28): the size is known for a path, so
`cost.notes` says at open whether it will be refused, and an archive over the limit is
refused before the temp file exists, with `ResourceLimitError` naming
`rar_decompressor='unrar'`, which reads a prefixed archive in place. Encrypted RAR5 data is read with the password on `unar`'s argv
(visible to local users; the maintainer accepted that and asked for it to be
documented), and `"auto"`, the default since the maintainer chose it on 2026-09-26,
picks RARLAB `unrar` when installed, `unar` otherwise, once per reader. So the "never a
probe of `PATH`" line in the reasoning below no longer holds for `unar`. Measurements and the reasons are in
[`alternative-rar-decompressors.md`](../investigations/alternative-rar-decompressors.md)
§2026-09-26 measurements, and the upstream defect in
[`known-issues.md`](../known-issues.md) §MacPaw `unar`; the process layer is
`internal/external/`, the RAR policy `internal/backends/rar_unar.py`. CI's macOS leg now
runs the fixture parity test against the Homebrew bottle. The upstream report is still
not filed. The rest of this paragraph is the 2026-09-01 reasoning.

`7z`, `bsdtar`, `unrar-free` and Homebrew's `7zz` are **closed**. **`unar` is not** — it is
the one candidate still on the table, because Homebrew dropping the `rar` cask made macOS
the hard install (below) and `brew install unar` is easy. Three things would have to happen
before it could ship, and none has: an **early-fail gate** in the backend, refusing
`format == RAR and info.is_solid and any FILE with size == 0` from the native listing alone
before `unar` is ever spawned (gating RAR4 too, conservatively); the fixture matrix run
against a **Homebrew bottle**, since the measurements above are apt and a local build; and
the XADMaster bug **filed upstream**. The gate's predicate is generalized from one fixture
family, and ANTI members and packed-nonzero/unpacked-zero empties are untested — so it may
be under-inclusive. What is not on the table under any of that is a silent fallback: a
second engine would be an explicit opt-in, never a probe of `PATH` (threat-model C1).

**Writing RAR4 needs an old binary.** RAR 7 dropped `-ma4`, so `scripts/gen_rar_fixtures.py`
downloads Ubuntu's rar 6.23 package from archive.ubuntu.com (SHA-256 pinned from Ubuntu's
signed package index; rarlab.com is not reachable from every build environment), unpacks
only the binary into the user cache and uses it purely to build the RAR4 fixtures.
`--only GLOB` writes just the matching fixtures, so new ones can be added without
rewriting the rest.
Any RAR4 archive in the wild today was written by something older than a current WinRAR.

**RAR3 header/file encryption KDF is not stock SHA-1.** WinRAR mutates its SHA-1 block
buffer in place after hashing it. `hashlib.sha1` does not, so `_Rar3Sha1` hashes
correctly and then corrupts a reused `bytearray` seed so the next of the 0x4000×16
rounds matches WinRAR. Seed ≤ 64 bytes (a password of 28 UTF-16 code units plus the
8-byte salt) never hits it. Ported from `rarfile` 4.3 `Rar3Sha1`. The committed `-hp`
fixtures use `header_password` (UTF-16LE plus salt is 38 bytes), so listing them never
reaches the mutation.

**The writer being trialware is also why the corpus fixtures are committed.** The declarative corpus builds each entry
in every format it declares, and eight entries declare `rar`. All eight ran **nowhere**:
building them needs the trialware writer, which CI does not install, so `skip_unless_runnable`
skipped the whole column while the sweep reported green. When the writer was finally installed
and the column run, four of the eight failed, in two shapes — and the instructive part is that the
first diagnosis was wrong. Both shapes looked like stale assertions; one was, and the other
was the assertion finally doing its job and catching a reader bug (the RAR5 redirect digest,
§2.2). With both corrected the suite went from 2 284 passed / 65 skipped to **2 326 / 23** —
42 tests that had previously run nowhere. The archives are now committed under
`tests/fixtures/corpus/rar/` and pinned by a manifest, against the corpus's own
generate-everything design, because the alternative made the test matrix a licensing
decision (ADR [0016](../decisions/0016-committed-rar-corpus-fixtures.md)).

**macOS is the hard install.** Homebrew disabled the `rar` cask over Gatekeeper: RARLAB's
own macOS `unrar` is ad-hoc signed on ARM and unsigned on Intel, with no notarization ticket,
so a quarantined download is blocked. Homebrew core will not ship an `unrar` formula either
— that removal was the licence, in 2020, and is independent of Gatekeeper. Published user
guidance is [`docs/install.md`](../../docs/install.md#getting-rarlab-unrar-or-rar); CI compiles a
pinned RARLAB source tree instead of trusting a third-party tap.

**Old archives are still readable and still surprising.** RAR 1.5 and 2.x archives (extract
version ≤ 20) share the RAR3 block layout, so they list and read; extract version alone is
never a rejection. `rar15-comment.rar` and `rar202-comment-nopsw.rar` are borrowed from
`rarfile`'s own corpus because modern `rar` cannot emit them. RAR3's two name fields are the
other legacy trap: the compressed name is UTF-16, which truncates a non-BMP character to a
single code unit — an emoji arrives as a private-use `U+F600` — and the 8-bit field is
preferred where it recovers the real character, without overriding a private-use character
that is genuinely present in both. `unrar` does no such recovery, so the read mask is the
truncated `U+F600` form (`RarMemberInfo.rar3_unicode_name` keeps it), not the name
archivey lists.

`rarfile`'s full test corpus can be run against the native parser as an oracle by pointing
`ARCHIVEY_RARFILE_TEST_FILES` at its `test/files` directory; it is opt-in and skips by
default.

## 4. Threat surface

RAR-specific only. General extraction and name hazards are §2.4.

- **The member name is an argument to another program.** This is the format's distinguishing
  hazard and the one no other backend has: CWE-88 argument injection reachable by anyone who
  can hand over an archive, with two outcomes — the wrong member's bytes returned at exit 0,
  and an arbitrary local-file read driven by a `@`-prefixed name. Closed by the `-n./`
  include mask; a basename glob with no backslash is demuxed from the parsed member list
  (§2.3). A glob in a directory component, or a backslash `unrar` keeps, is refused
  on the unrar path rather than guessed. Worth remembering how the hole survived a rule written to prevent
  it: the backend did control the argv it intended to build, and the hostile-name axis
  was simply not one anybody had enumerated.
- **Listing is attacker-controlled work with no decompression.** A small file can declare an
  enormous member table; `listing_limits.max_members` bounds the walk at parse
  (`ResourceLimitError`; `ListingLimits.UNLIMITED` disables it). [`threat-model.md`](../threat-model.md) O1.
- **Per-member comments expand after the parse-time bound.** RAR 1.5/2.x FILE `COMM`
  subblocks and compressed RAR 2.9-4 `CMT` headers hold *compressed* bytes at parse, and
  `_resolve_rar3_comment` unpacks each one in the reader once the walk has returned
  (§2.2), so `max_members` never weighs them. A `COMM` subblock is `uint16`-bounded at
  64 KiB, a compressed `CMT` at 256 KiB unpacked and packed (`RAR3_MAX_COMMENT_SIZE`).
  **The sum is bounded:** the header walk weighs each member's comment with its names as it
  appends the member, by the larger of the declared `unpacked_size` (the decode) and the
  packed bytes (what the listing holds until the decode; a header can declare 1 byte over
  256 KiB of them), and before decoding any the reader weighs the final list again with
  the archive comment, raising `ResourceLimitError` past
  `listing_limits.max_metadata_bytes`, so a refused archive spawns nothing. **The spawn
  count is not:** every compressed comment still forks its own `unrar`, and comments that
  each declare a few bytes pass the byte budget, so the process cost remains open —
  decoding all of them in one `unrar` call is tracked internally. The path is inert
  without the binary, which drops comments.
- **RAR3 names are themselves compressed.** The *retained* name bytes are roughly 1:1 with
  header bytes on a successful decode. Before #292 the transient cost was the lever: the
  decoder continued past a failed 8-bit read with `?`, so an empty 8-bit field plus
  RLE-heavy encoding built ~100 characters per input byte — about **11 s of CPU and
  13.5 MB** at the `uint16` `name_size` ceiling — then discarded the buffer before any
  member existed. Closed by `_decode_rar3_unicode_name`: overrun returns `None` and the
  caller falls back to the 8-bit field; every output unit costs a `std_name` or `encdata`
  byte, so amplification is impossible by construction (shipped decode of that ceiling
  vector is microseconds).
- **Variable-length integers are a CPU bomb, not a memory one.** The input chooses how many
  continuation bytes to supply, so a decoder that re-copies its accumulated bytes each
  iteration is quadratic in a length the attacker picks — a few megabytes of `0x80` burned CPU
  proportional to the square of a length the attacker picked, with nothing allocated and
  nothing obviously malformed to reject. Bounding
  the decoded *value* does not help; the bound has to be on bytes consumed. Fixed; the
  mutation and Atheris harnesses would not have found it, because a multi-kilobyte run of one
  byte is not a shape bit-flip mutation produces.
- **The solid pipe is demultiplexed from the archive's own numbers, against a policy that
  is in no field.** A crafted size, or a member kind whose emission behaviour archivey
  models wrongly, shifts every subsequent member. The uncomfortable part is that no stored
  size predicts what `unrar p` prints, and the two generations fail in opposite directions —
  measured on the `symlinks_solid__` pair, where every link emits **zero** bytes:

  | | RAR5 link | RAR4 link |
  | --- | --- | --- |
  | packed size | **0** | 6–12 |
  | unpacked size | 6–12 | 6–12 |
  | bytes `unrar p` emits | 0 | 0 |

  So keying the demux on `packed > 0` is wrong for RAR4 and keying it on `unpacked > 0` is
  wrong for RAR5; the only correct predictor is `unrar`'s own semantic rule — print
  regular-file data, skip directories, links and copies — which `is_payload_file()`
  re-implements. Per-member digest verification is the backstop, so a desync surfaces as a
  checksum failure rather than as silent wrong data. The `__rar4`
  archive is RAR3-family (`-ma4`); only its stored link members declare extract
  version 20 (RAR 2.0). The RARLAB writer stores those targets M0 — it does not
  produce a compressed (LZ-data) RAR3 symlink target, which is why that case is
  not in the fixtures. `FILE_COPY` (RAR5 redirect type 5) is pinned with
  archives `rar -oi` writes at test time. Residual is
  unfixtured existing kinds — Windows symlink, Windows junction — and future kinds
  whose emission `is_payload_file()` gets wrong (tracked internally). A later reader must
  not conclude the current kinds are all pinned.
- **A stream source materializes the archive to disk.** The temp file is `0600` and the temp
  volume directory `0700`, and both are removed on close; the exposure is disk space and
  lifetime, not readability by other users. `CostReceipt.notes` carries the caveat at open
  (§7).
- **The password is kept off the process table** by going to `unrar`'s stdin (§2.3), which is
  otherwise inherent to delegating to a CLI.
- **Encrypted members expose no plaintext digest**, by design of the format rather than by
  our choice — the tweaked MAC exists so the stored value cannot confirm a guess about the
  content (§2.2).

## 5. Sharp edges

*Where it lives*: **format** — inherent, no implementation fixes it · **library** — the
`unrar` binary's behaviour, fixable only upstream or by replacing it · **archivey** — ours.

| What you see | Where it lives | More |
| --- | --- | --- |
| Listing an archive works on a machine where reading it fails | **format** | The compressor is proprietary and its reference tool is non-free, so no distribution installs it by default and no pip extra can ship it (§1, §3). `PackageNotInstalledError` names it and names the lookalikes that will not be accepted |
| `seekable_members=True` on a sequential solid pass is still a pipe | **archivey** | Random `open()` of an `unrar`-backed member respawns the process on a backward seek, the same reopen the other backends use. `stream_members()` is never seekable by design: those handles are a single-pass decode, and seeking would break it. The `seekable_members=True` you declared still holds — it promises what random `open()` can do |
| Reading one member of a solid archive out of order decodes the whole archive, and doing it twice decodes it twice | **format** / **archivey** | No per-block boundaries to resume from (§1), and nothing caches the decode (§2.4). `AccessCost.SOLID` is the signal |
| Handing over **any non-path stream** — a `BytesIO`, a file object, a network-backed reader — may write a full-size copy of the archive to `/tmp`; `cost.notes` says so at open | **archivey** | The RARLAB decompressor needs a path (§1). The copy waits for the first member `unrar` has to read, so listing writes nothing and a stored member (decrypted by archivey, if encrypted) is free; the next member the program has to read, such as a compressed one, is not. Open volume streams behave the same way and copy the whole set (§2.3). Bounding the copy to one member rather than moving it is §7 |
| A corrupt encrypted member can be reported as a wrong password | **library** / **archivey** | `unrar` reports both as exit 2/3 with empty output on RAR4 and exposes no signal to separate them — that half is upstream's. Resolving the ambiguity toward `EncryptionError` is ours and is reversible (§2.3) |
| A 7-Zip SFX stub sitting beside a numbered split (`vol.exe` next to `vol.exe.001` / `vol.7z.001` / `vol.zip.001`) | **archivey** | Opening the stub follows that first volume. The stub is still not a sibling. An old-scheme SFX first volume (`name.exe` + `.r00`) is discovered as volume 1 of that `.rNN` set |
| A RAR on a pipe or socket cannot be opened at all, in either access mode | **format** | Block headers are chained forward but the walk still seeks; nothing is buffered for you (ADR [0010](../decisions/0010-no-silent-buffer-nonseekable.md)) |
| A RAR 1.5-4 name stored only as 8-bit bytes can list in the wrong code page | **format** | The header records none. Archivey guesses strict UTF-8, then cp437 for a DOS or Windows host and windows-1252 otherwise; `encoding=` overrides the guess, as in ZIP. Reading is unaffected (§2.2) |
| Some members raise `UnsupportedFeatureError` on the `unrar` path and read with `rar_decompressor='unar'` | **archivey** | A name `unrar` reads as empty or with no name part, one holding a surrogate, any member after a non-ASCII 8-bit name when no UTF-8 locale is available, and a compressed member whose name has a backslash or a glob in a directory component: `unrar` cannot be told which member is meant, and archivey will not guess (§2.3) |
| Every RAR5 symlink and hard link has no `hashes` entry, where ZIP and 7z have one | **format** | The stored field covers zero bytes, so the only honest answer is no digest (§2.2). RAR3/4 keeps its digest, which is genuine — but note what it covers: the **target string**, not anything the link points at, the same as ZIP's and 7z's (§2.2, §6) |
| Opening several members of a solid archive at once runs one whole-archive decode **per open**, concurrently | **format** / **archivey** | There are no block boundaries to share (§1), so `concurrent_operations=True` makes overlapping reads correct without making them cheap: measured, three open streams are three live `unrar` processes, each decoding from the start, all reaped on close. `AccessCost.SOLID` is the only signal and it does not scale with the number of open streams. Without the flag the second `open()` is refused with `ArchiveyUsageError` and spawns nothing — the live-stream slot is reserved before the member is opened (#293), where it used to be taken after |
| A compressed RAR 1.5 / 2.x old-style comment is `None` without RARLAB `unrar` | **archivey** | Listing and stored old-style comments stay native; the proprietary compressed blob is decoded only when the optional binary is available (§2.2) |
| An encrypted RAR 1.5 / 2.x old-style comment (PASSWORD or SALT flag) is `None`, with or without `unrar` or a password | **archivey** | Known limitation, because it cannot be tested: RARLAB `rar` 7.00 writes no old-style comment subblocks and no repo fixture carries either flag. The parser (`_parse_rar3_old_comment_subblocks`) drops the comment when either flag is set, stored (`M0`) comments included, so nothing is decoded or spawned. `decompress_rar3_blob` repeats the check as a second guard for direct callers: the comment subblock keeps no salt, so the synthetic FILE header it builds could not carry one (§2.2) |
| A member read has no time bound | **archivey** | `open_unrar_p` hands the caller a pipe with no read timeout; the only timeouts are the version probe and the teardown. A wall-clock cap refuses legitimately long members, and an idle or first-byte deadline kills valid solid reads, where `unrar` emits nothing while it decodes the members ahead of the target. Documented rather than bounded for 0.2.0; a caller-supplied timeout was the alternative and was not taken |
| Opening a compressed member whose stored name has a glob in a directory component, or a backslash, raises `UnsupportedFeatureError` | **archivey** | Windows `unrar` treats `\` as a separator so a Linux literal-backslash name emits nothing, and a glob in a directory component has not been measured enough to demux. Basename globs without `\` still demux. `rar_decompressor='unar'` reads these members by position, and the error says so. The matcher is now a port of `unrar`'s own `CmpName` (§2.3), so lifting the directory-glob refusal is a matter of measuring it; [`IDEAS.md`](../IDEAS.md) carries what it would take |
| Opening a glob-named member whose mask also matches **earlier** members raises `UnsupportedFeatureError` | **archivey** | Names like this are almost always constructed. On a nonsolid archive `unrar -n./a*.txt` also decompresses every earlier match — unbounded, and outside `ExtractionLimits`, which do not reach `open()`/`read()`. On a solid archive that decode is already inside `AccessCost.SOLID`, and what the mask adds is only the transfer of bytes archivey then discards — a bounded factor on work the read already owes (§6). Refused either way; `ArchiveyConfig.rar_allow_glob_member_concatenation=True` reads it anyway, and the error names the flag. A glob name matching nothing else is unaffected. A solid `stream_members()` pass builds no mask, so it is unaffected — a **nonsolid** one takes the named route and is refused like any other mode, which is deliberate (§2.3, §6). Under `AUTO` an accepted `unar` reads the member by index instead (`_unar_for_unaddressable`), except for a read that needs a password (`_member_needs_password`: `unar` would show it on its command line) or an archive `unar` would have to copy (a stream, or a prefix) |

## 6. Decisions

| Choice | Why | Rejected |
| --- | --- | --- |
| Native metadata parser; `unrar` for member data only | Listing works with no binary and no `rarfile` dependency, and archivey's cost and streaming model is not bent to another library's | `rarfile`, which couples listing to its own decompressor stack — kept as a test oracle (ADR [0002](../decisions/0002-native-rar-metadata-unrar-data.md)) |
| RARLAB `unrar` **or** `rar`, no silent fallback to other tools | The alternatives are measurably worse in ways a caller cannot see: `unar` returns empty files with a success exit on a whole archive class, `7z` depends on a plugin that may or may not be installed, `bsdtar` writes gigabytes on a stored member. A degraded backend chosen behind the caller's back is the failure mode `PackageNotInstalledError` exists to prevent. Accepting RARLAB `rar` is the same vendor's `p` command, not a second engine | Probing `PATH` the way `rarfile` does (threat-model C1, [`alternative-rar-decompressors.md`](../investigations/alternative-rar-decompressors.md)) |
| Refuse RARLAB `unrar` older than **6.0** at the banner probe | `-n` glob demux and `-ver` were checked from 6.02 up. 5.91 passed those RAR data tests but hangs on an anonymous-fd multi-volume probe that 6.12+ exits 3 on — a path archivey does not use. Floor 6.0 so Debian 12 / Ubuntu 22.04 apt packages work. Parsed from the same identification banner as the RARLAB sniff, cached with the probe, not re-read per member. Open and stored reads do not require it; compressed old-style comments stay `None` | Floor 7.0, which would refuse those distro packages; checking per member; treating a RARLAB banner with no parseable version as 6.0 |
| Pass the member as `-n./<name>`, never positionally | It is the only construction that neutralizes both hostile prefixes; `--` handles the switch case and leaves `@listfile` expansion intact | `--` alone as the member guard; shell quoting (there is no shell — argv is a list). `--` *is* passed, before the archive path, where the only hostile prefix is `-` |
| Honour `seekable_members=True` on named `unrar` by respawning the process | A flag that seeks on stored members and raises on compressed ones is a broken contract, and buffering the decoded member would hide the cost VISION forbids | Buffering the member in memory; teaching `ArchiveStream` to reopen every non-seekable inner (the blast radius is every backend for one pipe) |
| Declare a `RewindWarning` cost floor for the solid prefix | The member stream's `tell()` is only this member; named `unrar` of a solid member re-decodes everything before it. Maxing the predicate against that prefix keeps one diagnostic path | Lowering the global 1 MiB threshold; emitting the diagnostic from the RAR wrapper |
| Pass a basename glob as the `-n./` mask and skip other matches from the parsed list; refuse a glob in a directory component or a backslash | The refusal was the conservative half of this; the list needed to demux a basename glob is already in archive order. Directory-glob and literal-backslash matching is not the matcher we reimplemented, and guessing there reported a valid archive as truncated | Demuxing those names from a guessed skip; treating CRC mismatch as the only safety net |
| Narrow every `*` to `?` in the `-n` mask (`_unrar_mask_for`), and match the result with a fixed-length walk | A member whose stored name contains `*` becomes a glob the moment it is handed to `unrar -n`, so **both operands come from the archive** — the member name is the mask and a sibling is the subject, and a hostile name picks them. Two matchers backtracked exponentially on that. Archivey's spelled `*` as `.*` in a regex: `"a" + "*a"*n + "b.txt"` against `"a"*60 + ".txt"` cost 0.039 s at n=5 and 18.2 s at n=8, about 8x per added `*`, in a name with room for hundreds; a 271-byte two-member archive spent 32.9 s inside `reader.open()` **before `unrar` was spawned**, so no subprocess timeout applied. Replacing it with a two-pointer walk fixed archivey's half and left `unrar` 7.00's own, which has the same defect and is not reachable from here: `unrar p -inul -cfg- -p- '-n./a*a*a*a*a*a*a*a*ab.txt'` alone took 15.6 s against 0.007 s for a plain mask, so the archive still cost 15.6 s end to end. `?` consumes exactly one character (measured against unrar 7.00: it does not match empty, and there is no DOS-style extension case), so substituting it for `*` keeps the mask the same length as the name — the member always still matches itself. It usually narrows the match set; `unrar`'s DOS rule for a `*.` mask means it can also select a name the `*` mask would not (`?.` selects `..`, `*.` does not), which is harmless because the skip is computed from the mask actually passed. With no `*` left, neither matcher has anything to backtrack on: the subprocess went to 0.009 s with byte-identical output, the archive reads end to end in 0.018 s, and the demux matcher collapses to a length check plus a per-character walk, taking the arm-ordering hazard with it (a wildcard arm tested *after* character equality matched a mask `*` against a literal `*` in the name and under-matched — the bug the two-pointer walk shipped with). Narrowing is visible in `wildcard_ver__.rar`: mask `data*` became `data?`, so `data.bin` no longer matches and the pipe carries 8202 bytes instead of 24605. The skip in `_unrar_selection` must be sized against the substituted mask, not the presented name, or it steps past bytes the pipe never carried | Keeping the two-pointer walk, which leaves `unrar`'s 15.6 s untouched; bounding the wildcard count, which fixes both halves but refuses archives that read today; assuming a subprocess timeout covers the `unrar` half, when the cost is inside a process we wait on |
| Refuse a glob member name whose mask also matches earlier members; a config flag is the escape hatch | Names like this are almost always constructed. The read is correct — the skip returns the member's own bytes — but on a nonsolid archive `unrar` has already decompressed everything ahead of it, and nothing bounds that: `ExtractionLimits` stop at extraction. On a solid archive those matching members are already inside the solid prefix `AccessCost.SOLID` advertises, so what the mask adds there is not the decode but only the *emit*; they are refused anyway. Measured before [#371](https://github.com/archivey-dev/archivey/pull/371) landed, when the mask still carried the stored `*`: a 120 KB member named `*.bin` cost 2,000,000 bytes of `data.bin` first on a nonsolid archive, and a member named `*` cost the archive. #371 has since narrowed every `*` to `?` in the mask, so a nonzero prefix now needs a **same-length** sibling agreeing on every literal position — `*.bin` becomes `?.bin` and no longer reaches `data.bin` at all. That narrows the set sharply without bounding the worst case, since one same-length sibling can be any size, so it does not make this refusal redundant: the committed `a*.txt` fixture masks to `a?.txt`, its `aY.txt` sibling is the same length, and the refusal still fires. Reading such a name by default is not worth the DOS risk, and the config flag is what turns it back on. The solid *emit* is a bounded transfer cost on work already owed rather than new work (measurement below), and solid is not carved out: refusing both shapes keeps the modes consistent with each other and keeps one meaning on the config flag. Whether the refusal earns its keep at all is §7 | A diagnostic instead of a refusal, which reports a cost already paid; refusing with no flag, which would reject a real `report*.pdf` beside `report1.pdf`; a byte budget, which is a limit on work already done by the time it trips. Note what this does **not** cover: a name with no sibling it can match has a zero prefix, is not refused, and still reaches `unrar` as a mask. Mask-matching cost is a separate narrowing, which is what #371 is for; neither fix subsumes the other |
| Trust archivey's own digest over `unrar`'s exit code | Two authorities disagreeing about corruption produce false positives on legacy archives; the one that checks the bytes we actually returned wins. Exit codes stay the fallback for members with no hash | Mapping every non-zero exit unconditionally |
| Password on stdin, not in argv | Command-line arguments are world-readable through the process table for the life of the subprocess | `-p<password>`, which is what the CLI documents |
| Both stream shapes copy on first read, not at `open()` | `unrar` needs a path only for member **data**; archivey's own header walk reads whatever bytes it is given, so a list-only caller has no reason to pay for a copy. Measured before the change: the two-volume `tinyvol` fixture wrote 1757 of 1757 bytes at `open()` with no `read()`. Parsing the originals needs each volume as its own stream positioned at its start, which one `ConcatenatedFile` cannot be, so the walk reads one bounded `SharedSource` view per volume — non-owning and under the shared lock, so the caller's stream positions are untouched. The copy still writes the whole volume set when it happens, because `unrar` resolves siblings by name | Keeping the constructor copy and specifying around the inconsistency; copying only the volume holding the member, which `unrar` cannot use; reopening the caller's streams |
| A stream source gets a temp **file**, not a pipe | `unrar` seeks the archive and refuses every non-seekable input, so there is no streaming option to prefer — the only real choices are where the seekable copy lives and how much of the archive it holds (§1) | Piping the archive, or piping a synthesized header plus one member's compressed block — both refused before a byte is read. `rarfile`'s own version of that trick is a small temp *file* for the same reason, and it falls back to a whole-archive temp file exactly where we do |
| Spawn the solid pipe on first read, not at pass start | A pass nobody reads from — listing through `stream_members()`, an extraction whose selector matches nothing — should cost no process and should never prompt for a password | Opening the pipe when the pass begins |
| Solidity is one archive-level flag, `solid_block_count = None` | RAR exposes no block boundaries, so any number would be invented. `None` says "unknown", which is true | Reporting 1, which reads as "one small block" |
| A RAR5 redirect surfaces no digest; RAR3/4's is kept | Keying on the storage shape rather than the member type keeps a genuine digest where one exists and drops a constant that describes nothing. The value dropped is exactly the one a de-duplicating caller would read | Keying on member type, which would have thrown away RAR3/4's real digest; surfacing `crc32(b"")` for symmetry |
| Surface a link member's digest where the format stores one, and say what it covers | It is a real digest of the bytes the format stores for that member — which for a link is the target *string*, not the content it resolves to. ZIP and 7z store and surface exactly the same thing, so dropping RAR3/4's alone would buy consistency inside RAR at the cost of a worse one across formats. The fix for the misreading is documenting the field, not emptying it (§2.2) | Dropping link digests everywhere, which loses information ZIP and 7z genuinely store; keeping them and saying nothing, which leaves `hashes` implying content |
| Commit the RAR corpus archives, pinned by a manifest | Otherwise the corpus's RAR column is a licensing decision and runs on Linux only, while the release headlines a native RAR reader | Installing the trialware writer on CI; reworking digest expectations for a platform dependence that measurement showed does not exist (ADR [0016](../decisions/0016-committed-rar-corpus-fixtures.md)) |
| Read QO, seek back, skip matching FILE headers on the walk | Same table extract uses. Consecutive cached spans chain in memory (one seek per run). AUTO omits small files from QO; those still list from their local headers. `CMT` after MAIN is a normal SERVICE on that walk. Packed QO / `-hp` fall back to a full FILE walk. Wrapping QO for `unrar` at list time would violate listing-without-unrar | Validating QO against a full FILE walk *at list time* (pays the seeks QO exists to avoid). Build-time `use_qo=False` comparison is the standing pin |
| An unknown compression version is `UnsupportedFeatureError` on read, decided from the header | `unrar` 7.00 decodes RAR5 compression-info versions 0 and 1 and RAR 1.5-4 `UNP_VER` 13-29; outside them it prints "Unknown method … You may need a newer version of RAR" and writes nothing, which archivey reported as `TruncatedError` "ended after 0 of N". The data is not short, so this is the lzip-version-0 ruling (#567). Measured on 7.00 with every `UNP_VER` from 0 to 99 on a compressed RAR4 member: below 13 and above 29 is "Unknown method", **36 included**. A value in 13-28 selects an older algorithm, and data written for another one fails its checksum; that stays a checksum error here. A stored member is copied whatever it declares, in `unrar` and here. The check runs in `_open_member` and in both solid-pass plans, so no process is spawned; the `unrar` pass gives the member no room in the pipe, because `unrar p` writes nothing for it. A later compressed member of its solid stream is `UnsupportedFeatureError` too, naming it, with either program, decided from the headers (`solid_after_unknown_compression`): decoding it means decoding the unknown member first. The streams follow the members' solid flags, as `unar_dictionary_costs` walks them, not the archive bit. Under `unrar` the refusal reaches further. `unrar` stops at the unknown member and `unrar p` writes nothing after it, and a read addressed with the `-n` include mask archivey uses decodes a solid archive from its start, so a member in a later solid group (`rar -s<N>`) fails as well. Its message says the include mask is the cause and points to `unar`. Measured on 7.00 with `solid_groups__.rar`; only a name given as an argument skips to its group. With the archive's solid bit cleared, the masked read of `c.txt` reads, so that extension keys on the bit. `unar` reads a later stream: measured on 1.10.1 with `a.txt`'s data garbled, `unar -i` writes `c.txt` and `d.txt` whole and nothing for `b.txt`. So its policy refuses only the stream. The refusals used to be `TruncatedError`, which reported an archive that is not damaged as damaged. A stored member archivey reads itself still reads; in a pass, a refused member is served as `open()` serves it, since the output holds nothing for it | Leaving it to the decompressor's exit; refusing at open, which loses every member that does decode; the set 15/20/26/29/36, which `unrar` does not use |
| The RAR5 extra area is the header's last `extra_size` bytes | `unrar`'s `ProcessExtra50` places it there, and the MAIN locator walk already did. Walking on from the end of the name instead read any bytes between the two as records: measured, a fixture `unrar` lists as a plain file listed here as a symlink. Bytes between the fixed fields and the declared area are skipped, as `unrar` skips them without a word, but they carry `MEMBER_HEADER_RECORD_SKIPPED` here: a conforming writer leaves no room there, so they mean the header is damaged or crafted, and a strict policy refuses it. If a later RAR adds a fixed field this parser does not read, that diagnostic fires on every such header, and the parser is the place to teach it the field. An extra size not smaller than the whole header, its CRC and size vint included, is `CorruptionError`, as `unrar` reports "Corrupt header" for it (it checks `ExtraSize >= HeadSize` when it reads the size; measured on 7.00 at the whole header and one byte under it, which is the band where the body length and the whole header disagree). An area that reaches back over the fixed fields is ignored by `unrar`, which then lists the member from those fields; here it is left unread through the stop reason, so the member carries `MEMBER_HEADER_RECORD_SKIPPED` and is `encryption_unknown` rather than plaintext on the strength of a header that did not say | Walking from the end of the name; refusing the overlap, which `unrar` reads; skipping the gap silently, as `unrar` does, which hides a damaged header from a strict policy |
| `CompressionAlgorithm.RAR` for M1–M5 (`level` 1–5); extract version in `extra["rar.extract_version"]` | The header identifies the algorithm, so `UNKNOWN` claimed we could not tell. `ContainerFormat.RAR` and `CompressionAlgorithm.RAR` are homonyms (container vs codec), not a reason to invent `RAR_COMPRESSION` / `RARLAB` | Putting 15/20/29/50 in `level`; dropping M1–M5 from `level` |
| No `unrar x` tempdir cache for solid random `open()` | `AccessCost.SOLID` and per-open decode are the honest signals; a tempdir extraction amortizes work the caller cannot see or bound, which `VISION.md` rules out | `unrar x` into a managed temp directory to serve later random reads from disk |
| Encrypted-header `tell()` is the ciphertext cursor; leftover `_buf` is AES padding | `data_offset` must skip the padded ciphertext so the next salt/IV is aligned. Subtracting leftover plaintext lands in padding — measured on both `encrypted_header__*.rar` fixtures, where every FILE `header_size % 16 != 0` | Reporting a logical plaintext offset from `tell()` |
| No 8 KiB cap on `_HeaderDecryptStream.read`; callers use the format's own header limit | RAR5 already refuses `hdrlen > _RAR5_MAX_HEADER` (2 MiB) before the body read; RAR3 `header_size` is a uint16. The encrypted wrong-password path decrypts one garbage header then raises `EncryptionError` — strictly less than the unencrypted walk already allows. A tighter cap rejected a legitimate header as wrong-password. Unbounded `read(-1)` stays refused. | Keep 8 KiB and split the error (`CorruptionError` would abort password iteration); a second cap of 2 MiB inside `read` |
| Keep `_HeaderDecryptStream`; share only the AES *stage* with `crypto.py` | The header walk binds `header_fd` to either the raw archive handle or the decrypt stream and calls `.tell()` for `header_offset` / `data_offset` — archive offset, not a ciphertext cursor vs plaintext. The wrapper also sits mid-file unbounded, so `AesDecryptStream` would advertise seekable over the rest of the archive. Both streams borrow (`owns_inner`). A short last block now raises `TruncatedError` on the 7z pull stream; the header stream still never calls `finalize`. | Wrapping headers in `open_aes_decrypt_stream`; replacing `_Readable` with `BinaryIO` / a streamtools base |
| Derive each RAR5 key output (AES key, HashKey, PswCheck) with its own `hashlib.pbkdf2_hmac` run, and charge each to the key-derivation budget | UnRAR reads all three from one PBKDF2 chain at `n`, `n+16` and `n+32` rounds, but `pbkdf2_hmac` returns only a chain's end. Measured at `2**20` rounds on Python 3.13: one `hashlib` run 0.28 s, two runs 0.55 s, a Python loop walking the chain once (precomputed SHA-256 pad states) 0.78 s. So a `-p` read through `unrar` costs two derivations, a stored member archivey decrypts three, and the budget charges what actually runs (maintainer, 2026-10-20) | One Python chain, which halves the charge but makes every encrypted RAR5 read about 40% slower; running the two `hashlib` calls in parallel threads, which halves wall time on two cores but not the work; charging one chain while running two, which lets the budget understate CPU |
| Compressed RAR 1.5-4 comments are budgeted against `max_metadata_bytes` in the reader, before any is decoded, and an over-budget archive raises `ResourceLimitError` | Ruled by davitf (2026-09-19, on #353 F12): the comments expand after the parse, so the parser cannot see them (row below), and `max_metadata_bytes` means retained metadata on every format, so an over-budget listing raises here as it does everywhere. Each comment's `unpacked_size` is in its header and `decompress_rar3_blob` reads no more than that, so the sum is exact and checked up front: a refused archive spawns no `unrar`. A comment whose packed bytes are more than its `unpacked_size` counts those instead, since the listing holds them until the decode: a header can declare 1 byte over 256 KiB of packed data, and 200 such solid `CMT` headers held 52 MB under a 10 KB budget when only the declared size counted. **This bounds bytes, not spawns** — comments declaring a few bytes each still cost one `unrar` apiece; one `unrar` call for every comment is tracked separately (§4). Stored comments, which the parser has already decoded, count in the same total by their length. Since the parse-time byte budget (row below), the member comments are weighed as the walk appends their members, with the names (a RAR 1.5-4 `CMT` comment, which attaches to the member before it, as it attaches). The reader's check then weighs every member of the final list again and adds the archive comment; it recomputes rather than reusing the walk's running total, which is kept per list and misses a comment that reached a member after the member was weighed. The parser reads one by its **packed** size (a RAR5 `CMT` was read by its unpacked size, which put the next header's bytes in the comment) and in 1 MiB pieces, so a size past the end of the file raises `CorruptionError` having held no more than the file, where one read of a declared 1 TiB raised a bare `MemoryError` | Dropping the remaining comments to `None` (silently loses data on honest archives); capping the number of comments decoded; a running total after each decode, which pays the forks before refusing |
| The parser holds each member list to `max_members` and `max_metadata_bytes` as it appends | The table is built at open, so both bounds belong at parse. `max_metadata_bytes` was first left out of the parser on the reasoning that follows, and added once the 2026-10-10 code sweep showed the gap it left (tracked internally): an archive under `max_members` whose names are long keeps them all until registration, up to 64 KiB per RAR 1.5-4 name and 2 MiB per RAR5 header, times `max_members`. `_append_member` now adds `header_metadata_bytes` (name and raw name, RAR5 redirection target, comment, a compressed one by declared or packed size, whichever is larger) to a running total kept on the list (`_MemberList`), the same per-list rule as the count: per volume, then for the merged set, where a split member's later parts merge and are not weighed again. The weight is registration's for the same fields, with the stored name standing for the normalized one, so an archive whose names normalization leaves alone opens under any cap its listing fits. The original reasoning: Measured retained/wire is ~9×, dominated by the fixed `RarMemberInfo` object, which `max_members` already caps **for the members**; a damaged SERVICE header is retained too and is not a member, so it has its own bound (`_MAX_DAMAGED_SERVICE_HEADERS`) rather than being counted here — measured, 200 000 damaged 17-byte SERVICE headers in a 3.4 MB file retained 80 MB under no bound at all, and counting them as members would refuse an archive `unrar` lists; names are within ~4× of the header bytes (RAR3 UCS-4 worst case), typically ~1:1. A parse-time byte budget would guard the minor term, and a fixed header-bytes ceiling would reject archives `ListingLimits` permits — the `_MAX_ARCHIVE_MEMBERS` bug this exists to fix. The one listing path with real expansion is per-member compressed comments, which unpack in the reader after parse, where no parse-time guard can see them (§4) | A parser-local header-bytes constant; one running total shared by every volume, which weighs a split member's name once per volume |
| A malformed **optional** RAR5 extra record drops the record, not the archive | The extra area is a list of optional records, and the walk has always ignored a record type it does not implement. A type it *does* implement but cannot parse is the same amount of missing information, so refusing every member that parsed — over a checksum record — was an inconsistency rather than a posture. `unrar` 7.00 lists such an archive; measured on a one-byte edit to a BLAKE2sp record's `xsize`. Each branch commits its value on its own last statement, so a dropped record leaves its field **absent, never wrong**. Not silent: `MEMBER_HEADER_RECORD_SKIPPED`, which is in `ARCHIVE_INTEGRITY_CODES`, so `DiagnosticPolicy.STRICT` still refuses. **The line is a record's framing against its body** (davitf, on #371): a body the reader cannot parse costs one record and leaves the next record's offset known, so the walk goes on; a size vint it cannot use costs every later record, so the walk stops and says so. Unusable means unreadable, running past the header, or **below one byte** — a body opens with its type vint, so one byte (a type, no payload) is the smallest legal record and a declared size of zero names nothing while still advancing the cursor. That last case is what made one attacker byte cost one retained record. **`unrar` 7.00 is not the oracle here.** Measured on `encryption__.rar` with only the first member's extras corrupted and the second as a control, all four shapes behave alike: `unrar l` exits 0 and lists both members, but the corrupted member loses its encryption marker *and* its timestamp, while the second is untouched. The lost timestamp is the tell — that TIME record sits after the injected junk, so losing it shows unrar abandoned the rest of the extra area rather than skipping one record. It does that even for a record whose framing is sound and whose body merely will not parse (`01 80`), which is where **archivey is now more lenient than unrar**: the next record's offset is known, so we drop that one record and recover the TIME and CRYPT records unrar throws away. Its listing is wrong — plaintext, exit 0 — but not silently wrong end to end: `unrar t` on the same member reports `checksum error` and exits nonzero, because it cannot actually decrypt. So the damage is per-member and surfaces on extraction, which is why the oracle argument covers a malformed record body and stops there. The skip list is also capped (`_MAX_SKIPPED_HEADER_RECORDS`, 16 — arbitrary; the format's own bound is six, one per FILE extra type) for the records that *are* framed correctly, since one of those costs two attacker bytes apiece. It bounds only the expensive path, not record count: 2 MiB of well-formed records of an unimplemented type is a million ignored records in 0.49 s, linear in the input and not amplified. `max_members` cannot see any of this — it is one member. After the cap the extra-area walk stops, reported once via `list_truncated` on the diagnostic's context rather than once per record — a capped listing must not read as a complete one, since how far to trust the member's metadata turns on whether the header was read to the end. CRC-32 on the enclosing header is an integrity check, not an authenticity one; the cap is the hostile-input bound. Same leniency-vs-refusal question [`tar.md`](tar.md) §7 asks about tar's stdlib EOF handling — answered here for one record type, not there | Keeping the refusal; dropping the record silently, which would make the archive look intact; leaving the skip list unbounded |
| The RAR5 **encryption** record stays fatal | The sole exception to the row above. Dropping it leaves `file_encryption` unset, and a member with no encryption parameters is presented as plaintext — a wrong answer rather than a missing one, which is the failure class this library ranks worst. A member whose encryption parameters cannot be read is not a member that can be presented. **A member whose extra-area walk stopped early fails closed and lists as encrypted**, since the walk may have stopped in front of the record and "not encrypted" would be the same wrong answer reached by omission — measured, four crafted prefixes reach it and the cheapest is one byte. That is the one place the no-absent-parameters rule gives way. **"Encrypted" and "could not tell" stay separate inside the backend** (`RarMemberInfo.encryption_unknown`), because they are acted on differently: the fail-closed answer is what the *member* reports, while the archive-level flag stays the aggregate of members *known* to be encrypted. Conflating them let one damaged member report a wholly plaintext archive as encrypted, which also hands the caller's password to every `unrar` spawn for it and relabels an empty read as a wrong password. The cost of failing closed is **one extra pass** over an already-damaged member: a stored member is normally sliced from the source with no binary at all, and a cut-short one is sliced only after its bytes have been checked, because they would be ciphertext presented as plaintext if the record never reached was the encryption record. The first version of this branch routed such a member to `unrar` instead, on the belief that `unrar` settles the question. **It does not**, and that is worth stating because it is the obvious wrong inference. Measured on unrar 7.00 with one `00` byte prepended to each fixture's extra area: `unrar l` drops the encrypted marker, so it reached the same wrong conclusion from the same damaged header. What separated the two runs was **which digest survived**, which is the writer's choice and not ours — RAR5 keeps CRC32 in the fixed header and BLAKE2sp in the extra area, so the cut destroys one and not the other. `blake2sp.rar`'s member carries BLAKE2sp, lost it, and unrar returned the bytes at exit 0 marked unverified (`?`); `encryption__.rar`'s members carry CRC32, kept it, and unrar checked the ciphertext against it, failed, emitted **zero bytes and exited 3** (archivey surfaces that as `TruncatedError`; the undamaged sibling still reads). Had that encrypted member used BLAKE2sp, unrar would have handed back ciphertext at exit 0 with nothing said. So unrar's rule is "return the bytes unless a surviving digest says no", and **archivey holds the same surviving digest**. Ruled by davitf: apply that test here, and refuse when no digest survived — *"I think it matches how we deal with encrypted stored members where we're not sure the password is correct"*, which is the ZipCrypto stored path (`_open_stored_confirmed`). So the bytes are verified against the surviving digest **before** any of them is returned and the member reads on any install, `unrar` or not; with no digest left it is unreadable and the refusal names the **cut-short header**, not the missing package — measured, reporting `PackageNotInstalledError` there named a way out rather than the cause, for a member that reads fine on `main`. The check is up front rather than at EOF for ZipCrypto's reason: nothing in a stored member's framing rejects wrong bytes incrementally, so a caller that stops reading early would never reach the end-of-stream verdict. It costs one extra pass over an already-damaged member and nothing on the happy path. An encrypted member's digests are key-tweaked whenever the writer sets that flag and are the plaintext digest when it does not, so ciphertext matches neither — measured on a stored `-ppassword` fixture, refused, and on the plaintext `-m0` one, read correctly with no binaries on `PATH`. The diagnostic also names which of the four faults ended the walk, since it is the only thing explaining why the member reads as encrypted. **All of that is the sliceable member**; a cut-short member that needs `unrar` (compressed, solid, split, spanned) is decoded by it as before, with any surviving digest checked at end of stream and nothing checking one that has none — unchanged, still reported encrypted, still carrying the diagnostic. **SERVICE headers (`CMT`, `QO`) get the same walk and are not members**, so nothing listed them and nothing reported them: a cut-short `CMT` had its payload sliced and decoded into `ArchiveInfo.comment` with no diagnostic at all, which is the one place the leniency-is-not-silent argument did not hold. Both slice gates now refuse on `encryption_unknown` and the reader emits from `RarArchive.damaged_service_headers`, in every volume — the volume merge is field by field, so a new field is silent past volume 1 until it is added there. That list is retained per damaged header and nothing lists a SERVICE header, so it is capped and the remainder reported as a count (see the `max_members` row). The diagnostics do not call the header a member: it is in no listing, so naming `CMT` as one sent a reader looking for something that is not there and never mentioned the comment it had withheld. Note the walk allows one byte of trailing padding (as rarfile does), so a one-byte extra area is never walked — grafting one to build a repro changes nothing | Skipping it for consistency; listing it as encrypted with absent parameters in the *parsed* case; leaving a cut-short header to answer the question from what it happened to read; letting the fail-closed answer reach the archive-level flag; **routing the member to `unrar`**, which costs it on a core-only install and buys no better answer; refusing outright, which loses a member `main` reads and that its own checksum vouches for; verifying at end of stream, which a partial read never reaches |
| `extract_all` on a listing that ends in damage writes the members listed before it, then raises the listing's error (§2.4) | **Ruled by davitf, 2026-10-03**, for every format: it is what TAR already did, the order `stream_members()` gives, and what `unrar` and 7-Zip do — measured with unrar 7.00 and p7zip 16.02 on cut archives, both write the members before the cut and exit nonzero | Refusing before any write when the listing was walked first, which is what RAR did until then and made the outcome depend on whether the caller had listed; returning an `ExtractionReport` for the prefix alongside the error, which no public shape does today and the ruling did not take — a caller who needs the prefix's names reads `members_report()`, whose members are the prefix the pass was offered |

### Solid glob-emit measurement (2026-09-20)

unrar 7.00, `p -inul -n./`, two-member archive, first member unpacks to 66 MB,
output read in-process and dropped, median of 15. Highly compressible vs
incompressible is that first member.

| Shape | no-glob | with glob mask | factor |
| --- | --- | --- | --- |
| solid, compressible | 0.035 s | 0.109 s | 3.1× |
| solid, incompressible | 0.380 s | 0.432 s | 1.14× |
| nonsolid, same pair | 0.005 s | 0.118 s | 23× |

The solid extra is a transfer cost of roughly 1 ms/MB: `unrar` still decodes
the excluded member (the dictionary needs it) and only skips emitting it.
Nonsolid 23× is decode that would not otherwise happen.

**To re-run it**, since §7 parks the ruling for revisiting. Build a two-member
archive with `rar a -s -m3 arc.rar big.bin target.bin`, where `big.bin` is
66,000,000 bytes and `target.bin` is 65,536 bytes of `os.urandom`; fill
`big.bin` from a repeating string for the compressible row and from
`os.urandom` for the incompressible one, and drop `-s` for the nonsolid row.
Then time `unrar p -inul -n./target.bin arc.rar` against
`unrar p -inul -n./*.bin arc.rar`, reading stdout in-process and discarding it
— a `/dev/null` consumer hides the effect entirely.

Re-run that way on 2026-09-20: 0.053 s → 0.157 s (2.95×), 0.407 s → 0.475 s
(1.17×), and nonsolid 0.006 s → 0.105 s (16.4×). The absolute times and both
solid factors reproduce. The nonsolid factor is a ratio of two sub-10 ms
numbers and swings with load, so read that row as an order of magnitude rather
than as 23 exactly. The original archive is not in `tests/fixtures/` and the
glob name it used was not recorded, so the table above stays the original
measurement and these are a reproduction of it.

## 7. Open questions

Gaps in what *we* know — each would change something here if answered, and none can be
settled by reading more code. Distinct from §5, which is behaviour a caller already sees.

- **Settled (2026-09-29): members `unrar` addresses by a shared or cut name, and how an
  8-bit RAR3 name lists.** Three cases used to go wrong on the `unrar` path. A RAR5 name
  that is not valid UTF-8 could serve a sibling's bytes. Duplicate names failed with
  `CorruptionError`. An 8-bit RAR3 name listed as UTF-16LE (`b"caf\xe9.txt"` as
  `'慣琮瑸'`). The first two are fixed by computing the selection `unrar` makes (§2.3),
  the third by the decoding in §2.2. The measurements
  behind the fix, on Linux with `unrar` 7.00 (`unrar p -inul -n./<mask> -- archive`):

  | Stored name | UTF-8 text as mask | Stored bytes as mask |
  |---|---|---|
  | RAR3/4 8-bit (`caf\xe9.txt`) | fails in every locale | matches in every locale (C, POSIX, C.UTF-8) |
  | RAR5, or RAR3 Unicode-flagged, non-ASCII | matches only under a UTF-8 locale | same bytes, same result |
  | RAR5 invalid UTF-8 (`\xff`, `ab\xffcd.txt`) | fails | fails; `unrar vb` lists the name cut at the first bad byte (`""`, `ab`) |
  | two members with the same name | matches both | matches both |
  | RAR3 emoji, UTF-16 field `emoji_\uf600.txt` | the real emoji fails; `U+F600` matches | — |

  **Code page evidence for the 8-bit listing.** Windows `unrar` reads a RAR 1.5-4 8-bit
  name as the OEM code page (`arcread.cpp`, `ArcCharToWide(..., ACTW_OEM)` then `OemToCharBuffA`), which is what
  WinRAR writes; the Windows CI runner's OEM 437 turns `\xe9` into `Θ`. `unrar` on
  Linux keeps the bytes and maps them to private-use characters (`unrar lb` prints
  `caf\xef\xbf\xbe\xee\x83\xa9.txt`), 7-Zip on Linux prints the raw bytes, and
  `lsar` guesses per archive (windows-1252 for `caf\xe9`, IBM866 or windows-1251 for
  Cyrillic). No tool decodes the field as UTF-16. So archivey takes cp437, the OEM code
  page of the US and western European installs, for DOS, OS/2 and Win32 hosts, and
  windows-1252 for any other host, after strict UTF-8. That guess is wrong for other
  OEM code pages (cp850, cp866, cp932), which is what `encoding=` is for.
- **Open: a per-member fallback to `unar`** for what the `unrar` path still refuses: a
  name `unrar` reads as empty, a surrogate name, a member after a name that cannot be
  modelled, and maybe the refused glob names (the `rar_allow_glob_member_concatenation`
  refusal). The maintainer (2026-09-28): `auto` "is exactly picking the best tool for
  each job", and the C1 rule that `auto` decides once "is not something I remember
  choosing". The fallback would replace the `UnsupportedFeatureError` raised in
  `RarReader._open_member`, and the PR that adds it revisits threat-model C1. Caveats:
  `unar` puts the password on its command line (C1), and `unar` has limits of its own
  on some solid archives (§3). So a fallback can itself refuse, and must say which tool
  refused.
- **Open: a shared plain name reads without the glob-concatenation flag.** The flag
  exists because a glob read makes `unrar` decode earlier members only to discard them.
  A duplicate name, or a mask naming a directory, does the same, and reads without it,
  since the flag's name and documentation are about globs. Whether it should cover
  every shared mask is the maintainer's call.
- **Open: the name model on Windows and macOS is unmeasured.** The selection tests run
  on Linux only.
  - Windows: the case fold is Python's per-character `.upper()` where `unrar` uses
    `CharUpperW`; the mask and the name both get `/` turned into `\` (the mask in
    `CheckArgs`, a change the source dates 2025-09-11, so older Windows builds may
    differ; the name in `ConvertFileHeader`), so the model converts both sides; an
    8-bit name is read through the OEM then ANSI code page, which is
    modelled only for a single-byte OEM, so a DBCS OEM (cp932) can mis-size the skip.
    Precomposition (`FoldStringW`) for a Unix-host name is modelled but unmeasured.
  - macOS: `unrar` reads 8-bit names, and the argv mask, with its own `UtfToWide`
    (`CharToWide` under `_APPLE`), which stops at the first byte that is not UTF-8.
    That is modelled. So an 8-bit name that is not UTF-8 from its first byte (cp1251
    `привет.txt`) is read as empty and refused before the spawn, and `caf\xe9.txt`
    reads through `caf`. macOS CI confirmed the refusal. `_probe_utf8_locale` is
    unverified on macOS/BSD. If it fails there, non-ASCII names are refused rather
    than misread.
  - To build more cases: `tests/test_audit_rar_iso_dir.py` has RAR5/RAR3 header
    rewriters with CRC fix-up (`_rar5_parse`, `_rar5_build`, `_rar3_parse`,
    `_rar3_build`), since `rar` 7.00 cannot write RAR4.
- **Settled (2026-09-30): a RAR dictionary size counts against `DecoderLimits`.** Every
  in-process codec checks the dictionary or window its header declares against
  `max_decoder_memory`, and RAR now does too, although `unrar` or `unar` decodes it in
  another process. The reader checks it before it spawns the program, on a named
  `open()` and on the first read of each member of a solid pass, with
  `check_decoder_memory` and its message. The number counted is what the program that
  will run allocates, so under `rar_decompressor="auto"` it is the rule of the program
  `auto` picked. Maintainer decision (2026-09-30): check it, per program.

  Measured on Linux with `rar`/`unrar` 7.00 and `unar` 1.10.1, peak RSS of the child
  (the Python parent stayed at 41–43 MiB in every case). *small*: a 64 KiB member;
  *crafted*: the same member with its header patched to declare D.

  | D | unrar small | unrar crafted | unar small | unar crafted |
  | --- | --- | --- | --- | --- |
  | 1 MiB | 9 MiB | 9 MiB | 21 MiB | 22 MiB |
  | 256 MiB | 8 MiB | 8 MiB | 20 MiB | 276 MiB |
  | 1 GiB | 8 MiB | 9 MiB | 21 MiB | 1045 MiB |
  | 4 GiB | 9 MiB | 8 MiB | 21 MiB | 1045 MiB |

  | Shape | unrar | unar |
  | --- | --- | --- |
  | Solid, 2 × 64 KiB, first header declares 4 GiB | 9 MiB | 4116 MiB |
  | Solid, 64 KiB + 512 MiB, honest 128 KiB dictionary | 9 MiB | 21 MiB |
  | The same, first header declares 1 GiB | 521 MiB | 1044 MiB |
  | Solid `-s2`: 64 KiB + 300 MB in one stream, then a member that starts a second stream; the first header declares 1 GiB; the second-stream member is read | 308 MiB ¹ | — |
  | Solid `-s2 -md128k`: 2 × 64 KiB in one stream, then 300 MB in a second; the first header declares 1 GiB; the 300 MB member is read | — ¹ | 19 MiB |

  ¹ `unrar` exited 3 (a CRC error) on both patched `-s2` archives. On the first it had
  already decoded the 300 MB; on the second the figure (8 MiB) says nothing, so it is
  left out. The last two rows were measured on 2026-09-30 with `posix_spawn` and
  `wait4`; the rest come from the investigation behind this decision.

  - **`unar` allocates up front and touches every page.** One mapping of the declared
    size, resident even for 64 KiB of output. So the count is the declared size. In a
    solid archive `unar` keeps one dictionary per solid stream (a new stream starts at
    a compressed member without the solid flag), and the count is the largest one
    declared in the stream up to and including the member. Only the stream's first
    declaration was allocated when later ones were patched, so this is an upper bound.
    A member in a later stream does not pay for an earlier one (last row).
  - **`unrar` is lazy and bounded by its output.** For a nonsolid member it reserves
    min(declared, unpacked size), and pages fill only as output is written, so a
    declaration alone costs nothing. The count is min(declared, unpacked size). In a
    solid archive it keeps the largest window it has seen, and it decodes every earlier
    member, across solid streams too (second-to-last row: reading the member of the
    second stream paid for the first). The count is min(largest dictionary declared up to and
    including the member, total unpacked size of those members). That is wider than
    "the member's own stream", on purpose.
  - **A shared `unrar` mask.** A named `unrar` read decodes every member its mask
    selects, in archive order: a glob with `rar_allow_glob_member_concatenation=True`,
    or a duplicate name, which needs no opt-in. The count is the largest among the
    target and the selected members before it (`RarReader._unrar_selection` returns
    it). In a nonsolid archive each earlier match sizes its own window; in a solid one
    the target's count already covers them. A match after the target is not counted:
    the read stops at the target's end, and that member's window fills only as
    `unrar` writes to the pipe.
  - **Not counted.** A stored member, a directory, and a RAR5 redirect (hardlink, file
    copy, symlink), which carry no data to decode (`uses_no_dictionary` in
    `rar_unar.py`; stored headers from `rar -m0` declare 0 anyway). They add nothing to
    the window or the decoded bytes. A RAR3 symlink does count: its target is compressed
    data. A compressed RAR 1.5-4 comment, which `unrar` or `unar` decodes at open:
    RAR3/4 dictionaries top out at 4 MiB (the 3-bit field over a 64 KiB base), and
    `rar -ma4` is gone from rar 7.00.
  - **A stored member of a solid archive.** `rar -s` sets the member's own solid flag
    on it (`file_solid`). The reader slices a stored member itself whatever that flag
    says (since 2026-10-07), so such a member goes to the program only inside a solid
    pass, where the count below applies. Measured 2026-09-30 with a
    300 MB member declaring 1 GiB (patched) ahead of a stored 64 KiB member: `unrar p`
    of the stored member peaked at 314 MiB, the same as reading the 300 MB member
    (309 MiB), so `unrar` decodes the prefix and the stored member counts the window
    ahead of it. `unar -i` of the stored member stayed at 41 MiB, against 1044 MiB for
    the 300 MB member, so under `unar` it counts 0. (Peaks include the 41–47 MiB
    Python parent; `unrar` exited 3 on the patched archives, as in the table.)
  - **Which solid flag.** `unrar` decides from the MAIN header's solid flag
    (`RarArchive.is_solid`), not the member's. With the MAIN flag set and the stored
    member's own flag cleared, `unrar p` still peaked at 314 MiB; with the MAIN flag
    cleared and the member's flag set, it stayed at 47 MiB (the parent). So the
    `unrar` solid walk keys on `is_solid`. `unar` stayed at 47 MiB in all four
    combinations for the stored member.
  - **The refusal message** gives the count and, when the count is capped below it, the
    declared dictionary. When the dictionary was declared by another member (solid, a
    shared mask, a pass) and the member read does not declare that size itself, the
    message names that member, so a caller knows which header to look at. A declarer
    with the same name as the member read (a duplicate) is named by its archive
    index.
  - **Not signalled at open.** Every count is known from the parse, so `ar.cost.notes`
    could say at `open_archive` that a read will be refused, as it does for a
    `SpoolLimits` refusal. Left out: the refusal is per member, and `ar.cost.notes` is
    one open-time caveat for the archive, not a per-member list. A note would have to
    say "some members" or name them, which does not scale.
  - **What honest archives declare.** rar 7.00 declares the data size rounded up to a
    power of two (10 MB → 16 MiB, 300 MB → 512 MiB), so a real archive over-declares by
    at most 2×, and small members declare 128 KiB whatever `-md` says. Under the 2 GiB
    default the check refuses only a member that asks for 4 GiB, which is what `rar`
    writes for `-md4g` on data over 2 GiB, and under `unrar` only when that much data is
    actually decoded.
  - **Above 4 GiB.** RAR 7.0 (algorithm 1) declares up to 64 GiB. `rar -md64g` needs
    more input than the dictionary, and no real 8 GiB+ archive was built; patched
    headers above 4 GiB did not decode (`unrar` exited 1–3, `unar` stayed near 21 MiB).
    The parser sizes them as `unrar` 7.00 does (5 exponent bits plus 1/32 steps), so
    they are refused under the default. Unmeasured beyond that.
  - **Not adopted: `unrar -mdx<n>`.** It makes `unrar` refuse a member whose effective
    window exceeds `n` (a power of two). It would be a second net for `unrar` only;
    `unar`, the tool that touches the whole dictionary, has no equivalent, and its
    refusal (exit 2, "No files to extract") would need mapping to
    `ResourceLimitError`.

  Code: `RarMemberInfo.dictionary_size` (parser), `unar_dictionary_costs` (`rar_unar.py`),
  `_unrar_dictionary_costs` and `RarReader._check_dictionary_memory` (`rar_reader.py`).

- **Does the glob-concatenation refusal earn its keep?** It ships and is decided (§6):
  a member whose stored name is an include mask matching earlier members is refused by
  default, on solid and nonsolid archives alike. The ruling is parked for revisiting
  rather than closed, on two arguments that the measurement in §6 does not dispose of.

  First, **an attacker can choose the archive shape.** The sharp case — decode that would
  not otherwise happen, unbounded in the earlier member's size — is the nonsolid one.
  Make the same archive solid and the amplification the refusal prevents drops to a
  bounded transfer cost, roughly 1 ms/MB (§6). A hostile archive is cheap to rebuild,
  so the refusal raises the cost of one construction rather than closing the
  amplification.

  Second, and sharper: **a solid archive is already the thing the refusal is defending
  against.** An out-of-order `open()` of any solid member decodes every member ahead of
  it, with no glob involved at all — that is §5's own row and what `AccessCost.SOLID`
  exists to advertise. So an attacker wanting a caller to decode a lot for one small read
  does not need a glob name: solidity alone does it, on a name nobody would refuse. The
  glob adds real amplification only on the shape where solidity does not already provide
  it, and that is the one case the refusal closes. Which suggests the real question is
  not about glob names but about whether an unbounded `open()`/`read()` decode should be
  refusable at all — threat-model O1's general gap, where `ExtractionLimits` stop at
  `extract`.

  What holds the ruling up meanwhile is not the threat number: it is that the modes and
  shapes agree with each other, and that one config flag means one thing. What would
  settle it is a decision on the general gap, not more measurement of this case.

- **Can the stream-source copy be made small, rather than just moved?** P11 is closed:
  a non-path stream gets an open-time `CostReceipt.notes` caveat, and the copy is bounded
  by `ArchiveyConfig.spool_limits` (`SpoolLimits.max_bytes`, 1 GiB by default, across a
  whole volume set; refused before writing). What remains is making the copy one
  compressed member via a synthetic single-member archive rather than the whole
  archive. The sibling cost — an
  out-of-order solid `open()` being a whole decode each time — is **already decided**:
  not a diagnostic, because `access_cost` already carries it; whether a once-per-reader
  `warnings.warn` is worth adding is tracked internally.

  Two ideas compose here and only the combination is interesting. A `memfd` is seekable,
  anonymous, freed on close, and `unrar` reads one happily (§1) — but on its own it only
  trades unbounded disk for unbounded RAM, which is the worse of the two for a large
  archive, and it is **Linux-only**, and it cannot serve a volume set because `unrar` needs
  sibling names on disk (§2.2). What makes the size bounded is `rarfile`'s trick: build a
  *synthetic* single-member archive — a marker, a synthesized MAIN, the member's own FILE
  header and packed bytes copied verbatim, a synthesized ENDARC — so the copy is one
  **compressed member** rather than the whole archive. `rarfile` writes that to a small temp
  file and guards it heavily (never for solid, split, or encrypted members, and never above
  ~20 MB); a `memfd` is simply a better container for the same bytes where the platform has
  one. Unmeasured, and the guards are the hard part: RAR3 and RAR5 need different header
  synthesis. [`IDEAS.md`](../IDEAS.md) carries the neighbouring idea — the same synthetic
  archive fed to libarchive instead, to drop the `unrar` requirement entirely. Bounding this
  copy is also what `openspec/changes/bounded-source-spooling` ([PR
  #251](https://github.com/archivey-dev/archivey/pull/251)) would put under one configured limit.
  Building the synthetic archive now was considered and deferred. Tracked internally, and
  worth building alongside the machinery for decoding every RAR3 compressed comment in one
  `unrar` call — one synthetic writer would serve both.

- ~~**Does `ListingCost.INDEXED` mean "cheap" or "already paid"?**~~ Neither: it names
  how the member list is read on the source, so RAR reports `REQUIRES_SCANNING` like TAR
  (maintainer ruling 2026-10-15; general form under DR-10 in
  [`design-rules.md`](../design-rules.md)). Reasons: the receipt says what listing costs,
  and for RAR that is a header walk; a later change may make the walk lazy, as TAR's is.
  The quick-open case is the next question.
- **Should a RAR5 archive whose `QO` covers every header report `INDEXED`?** The record
  saves the seeks (12 reads and 11 seeks instead of 6,011 reads and 3,007 seeks for 3,001
  members), not the parse. The maintainer chose to keep one value for every RAR and leave
  this open (2026-10-16), rather than close it or make the receipt depend on the archive.
- ~~**Should `unar` become an opt-in second engine?**~~ Yes, shipped 2026-09-26 as the
  fallback under the default `"auto"` (§3). It was the one candidate the
  decompressor matrix left open, and Homebrew dropping the `rar` cask is what keeps it open
  (§3). Blocked on three things nobody has done: the fixture matrix against a Homebrew
  bottle rather than apt and a local build, an upstream XADMaster report, and a judgement on
  whether the early-fail gate predicate is under-inclusive — it is generalized from one
  fixture family, and ANTI members and packed-nonzero/unpacked-zero empties are untested.
  None of that is answerable by reading code.
- ~~**What does a partial read of a RAR3/4 member return under a wrong password?**~~
  The wrong key's bytes, measured on unrar 7.00: always for a stored member, and for
  about three wrong passwords in ten on a compressed one, which the guess that the
  decompressor trips first had missed. RAR now emits `ENCRYPTED_MEMBER_UNVERIFIED` on
  that close (§2.2 has the numbers and what is not watched). The stored measurement used
  a retyped scratch copy, since RAR 6.24 was still not downloadable here; a real
  `-ma4 -m0 -p` fixture from it would pin the stored case in CI too.
- **Is the wrong-password-versus-corruption bias measurable, or only plausible?** The exit-2/3
  mapping for an encrypted member that emits nothing assumes wrong passwords vastly outnumber
  corrupt encrypted members. That is a reasonable prior and it is untested: no archive has
  turned up in our corpora where a genuinely corrupt encrypted member produced this shape, so
  the cost of the mislabel is unknown.

## 8. Verify

```bash
./scripts/test.sh tests/test_rar_reader.py tests/test_rar_oracle.py \
    tests/test_rarfile_corpus.py tests/test_volumes.py tests/test_sfx.py
```

About 24 of the ~140 tests those five files hold are `unrar`-gated, and they **skip
quietly**. The parser, detection and SFX tests all still run, so a container without the
binary reports green with the entire data path untested — which is the trap, not the count
(`AGENTS.md` §Session setup).

Two claims here are about the **external binary** rather than about archivey, so no test can
hold them — they are probes instead, re-runnable when a new `unrar` lands:

```bash
python3 scripts/exploration/rar_unrar_input_matrix.py       # §2.3 input modes, §2.2 volumes, §4 emission
python3 scripts/exploration/rar_decompressor_matrix.py      # §3 the decompressor table
```

| Claim |
| --- |
| A member whose packed data the file cuts is `TruncatedError` when `unrar` would decode it, encrypted or not, solid or not, in random access and in a pass; a cut stored plaintext one raises `TruncatedError` too (the bytes before the cut are not asserted) |
| Cost receipt: `DIRECT` for a nonsolid archive, `SOLID` with `solid_block_count is None` for a solid one |
| Listing and stored reads with **no binary on `PATH` at all**, and a compressed read there naming RARLAB `unrar` |
| A stored nonsolid archive is read end to end with zero subprocesses (the §2.3 measurement) |
| The finder rejects a missing or non-RARLAB binary, and the message names the lookalikes |
| A non-RARLAB binary on `PATH` is rejected, and the one we run is RARLAB's 6.0+ |
| Identification parses major.minor from the probe banner; below 6.0 (or unparseable RARLAB) is refused once and cached as RARLAB |
| The finder caches hits and misses for one `PATH`, then re-probes after `PATH` changes or a cached binary vanishes |
| A solid pass spawns `unrar` only on the first read |
| Hostile member names (`-inul`, `@atfile`) read **their own** bytes, RAR4 and RAR5 |
| An archive path starting with `-` or `@` reads its members; `--` sits directly before the path |
| A probe that times out is cached for that binary, the next name is still tried, a replaced binary is re-probed, and every refusal names the timeout |
| A wildcard member name reads its own bytes, including the solid prefix-skip case |
| Listing a stream-volume set writes nothing; the first compressed read writes the whole set once and close removes it |
| A glob name whose mask also matches earlier members is refused; the flag reads it anyway; a glob matching nothing else is untouched; a solid streaming pass is untouched |
| A directory-component glob or a backslash in the stored name is a typed refusal; `-ver` history is omitted from the skip unless the target is a history row |
| Hostile prefixes and glob names become a `-n./` mask; `[]` stays literal in the skip; Windows fold is per-character so `?` stays length-aligned |
| `seekable_members=True` respawns named `unrar` on a backward seek; stored direct-slice does not; default route stays a pipe |
| A solid later-member rewind is loud without lowering the global threshold; a live `unrar` survives close+respawn |
| The password reaches `unrar` on stdin, not in argv |
| A NUL in a password or a member name is a typed refusal; a password past the pipe buffer does not deadlock the spawn |
| An 8-bit RAR3 name is masked with its stored bytes; `unrar` runs under a UTF-8 locale, and without one a non-ASCII name is refused before spawning |
| Each read returns its own member's bytes when the mask selects others: duplicate names (solid and not), a RAR5 name cut at a bad byte, a name `unrar` reads as empty; an earlier unmodellable name refuses later reads |
| The mask selection archivey predicts is the one `unrar` 7.00 makes (Linux) |
| An 8-bit RAR 1.5-4 name lists in its writer's code page, honours `encoding=`, and still reads; RAR5 names ignore `encoding=` |
| An explicit volume list in separate directories reads as given |
| An invalid DOS date or out-of-range FILETIME is `None` plus `MEMBER_TIMESTAMP_INVALID`; a crafted `;n` suffix is not a bare `ValueError` |
| Exit-code mapping: 11, 2/3, 10, hash-present suppression, solid-pipe suppression, negative rc |
| A missing stdout pipe is a typed error, not a `RuntimeError` |
| Header-encrypted listing with a password, and a wrong password as `EncryptionError` on both generations |
| Encrypted member data requires a password |
| A partial read of RAR3/4 encrypted data emits `ENCRYPTED_MEMBER_UNVERIFIED` (named open, seek, solid pass); a read to EOF, a RAR5 member with a PswCheck, and a header-encrypted RAR4 archive do not |
| Tweaked digests kept out of `hashes`, and BLAKE2sp verified / cross-checked against `unrar` |
| RAR5 redirect digests dropped without losing RAR4's genuine ones |
| RAR5 Windows symlink and junction targets list as ZIP's and 7z's do, and a drive or UNC target is refused at extraction |
| A RAR5 name that is not UTF-8, and an 8-bit RAR 1.5-4 name with a byte windows-1252 leaves undefined, list as distinct names, read their own bytes through `unrar`, and extract escaped |
| Solid symlink / hardlink demux does not consume pipe bytes |
| Solid link emission per generation: RAR5 packed 0 / unpacked > 0, RAR4 packed > 0 / unpacked > 0, both emit 0; `is_payload_file()` is False |
| A RAR5 file copy lists as `FILE` with `is_file_copy` and its source, reads and extracts as an independent file (both programs, solid and not); a dangling or wrong-size copy raises; a hard link stays `HARDLINK` |
| A solid pass decodes a file copy's source once for all its copies (both programs; the source read or skipped, extracted or filtered out); kept in the spool past the memory allowance, decoded again when the spool limit has no room; the spool charge starts at the first kept byte, after a stream source's own copy, and ends with the pass; a pass that reads nothing writes nothing; the kept bytes are checked against the source's digest and count toward extraction limits |
| Extraction copies a file copy from its written source and keeps nothing for it (random access and streaming, both programs); a replaced source file falls back to decoding; a dry run keeps sources; `stream_members(file_copy_streams=False)` yields `None` for copies, solid or not, and keeps nothing |
| File-version rows list, read, stay out of `extract_all`, and keep solid demux aligned |
| M0 is `STORED`; M1–M5 is `RAR` with `level` 1–5; unpack version in `extra["rar.extract_version"]` (stored included; RAR3 `UNP_VER` unvalidated, RAR5 reports 50); method bytes outside M0–M5 stay `UNKNOWN` with no `level` |
| Volume sets (`partN` and `.rNN`, including an SFX `.exe`/`.sfx` first volume), stream volumes, a stray `partN` of another padding, and a set with a volume missing at its start, middle or end |
| Stub-only `vol.exe` follows `vol.exe.001` / `vol.7z.001` / `vol.zip.001`; a real SFX is not redirected |
| RAR 1.5 / 2.x list and read; extract version ≤ 20 is not a rejection |
| RAR 1.5 / 2.x archive and member comments match `rarfile`; stored old-style comments need no binary; RAR3 CMT reaches `member.comment`; RAR5 CMT stays archive-only |
| An encrypted old-style comment is `None` and spawns nothing |
| Stored names over `max_metadata_bytes` refuse at open (RAR4, RAR5, and a volume set weighing a split member's name once) |
| Compressed RAR 1.5-4 comments (old-style subblocks and `CMT` headers) over `max_metadata_bytes` (member and archive comments, each weighed by the larger of its declared size and its packed bytes, summed with the names) refuse at open before any decode |
| A compressed RAR 2.9-4 `CMT` comment is decoded by the selected program and `None` without one; its CRC32 and unicode bit are honoured; one declaring more than 256 KiB, or packing more than that, is dropped unread; a SALT-flagged one spawns nothing; its packed bytes count toward the budget when larger than its declared size |
| A `CMT` comment whose data runs past the end of the file, stored or compressed, is a cut: RAR 1.5-4 and RAR5 list the members before it, then `TruncatedError`, and the comment is `None`, as `unrar` lists them; a `CMT` the walk reads (its bytes in the file, within the 256 KiB compressed cap, not encrypted or split) whose packed bytes alone are over `max_metadata_bytes` is refused before it is read |
| RAR3 non-BMP name recovery from the 8-bit field |
| Listing without QO is a header-to-header walk; with QO, FILE headers already in it are not read (§1.1) |
| QO listing matches the FILE-header walk field-for-field |
| QO listing serves stored reads and keeps the archive comment; unreadable QO falls back to the walk |
| QO payload of non-FILE records parses in linear time; overlapping QO spans are refused |
| AUTO still lists small files QO omitted; `rar a` rewrites QO; FILE after QO is still listed |
| A QO copy no header the walk reaches matches is reported on a clean end, refused under `STRICT`, kept past the damaged-service-header cap, not reported after a cut, a damaged header, a damaged end block or without QO, and not listed, as in `unrar` |
| A malformed optional RAR5 extra record drops the record, not the archive; encryption stays fatal; a zeroed extra area does not retain one skip per byte; the extra area is placed by its declared size |
| An unknown compression version is `UnsupportedFeatureError` on read, for both decompressors and the solid pass; a stored member reads. In a solid archive so is a later member of its solid stream, and under `unrar` a later solid group too, worded by cause; `unar` reads a later group; a stored one reads |
| Bounded hostile parsing: the header-size vint, hostile packed sizes, hostile modes, out-of-range timestamps |
| RAR5/RAR3 `accessed`/`created` from the time extra, and `None` when the extra or slot is absent |
| RAR3 compressed-name decode fails closed on overrun; long RLE stays bounded (§4) |
| The >4 GiB RAR3 packed skip, and split-continuation identity checks |
| Member-table ceiling at parse via `listing_limits.max_members` |
| The SFX needle validator, its `DAMAGED` verdict, and a decoy skipped for the real payload |
| Metadata and bytes match `rarfile` on our fixtures and on the corpus |
| Mutation and coverage-guided fuzzing of the header walk |
| `extract_all` over a listing cut part-way writes the members before the cut, then raises the listing's error, in both modes, under either `OnError`, with no report; a selected hard link in the prefix still gets its source's bytes; an entry unmatched in the prefix is not reported; listing limits still refuse before any write |

**Building fixtures.** `uv run python scripts/gen_rar_fixtures.py` regenerates most of
`tests/fixtures/rar/`; it needs the RARLAB `rar` writer, and because RAR 7 dropped `-ma4` it
downloads a checksum-pinned RAR 6.23 into the user cache for the RAR4 variants. The corpus
archives under `tests/fixtures/corpus/rar/` are committed and manifest-pinned instead
(ADR 0016), so the corpus RAR column runs everywhere `unrar` exists. The two RAR 1.5 / 2.0
comment archives are borrowed from `rarfile` and cannot be regenerated. The hostile-argv
fixtures were built by `make_hostile_fixtures.py` in the review folder and pushed by the
maintainer, since the review container had no writer. Live `rar a` tests skip without
the writer — three SFX tests, a multi-volume roundtrip, and the QO listing pins that
need `-qo+` or live AUTO; the gap and what would close it are in
[`tests/fixtures/rar/README.md`](../../tests/fixtures/rar/README.md).

## 9. References

- [RAR 5.0 archive format](https://www.rarlab.com/technote.htm) — RARLAB's own metadata
  reference, and what the RAR5 parser is written against: §1 data types (the vint encoding
  every length uses) · §2 general archive structure (the signature, and the block header
  whose own size field drives the walk) · §3 archive blocks (MAIN, FILE, ENCRYPTION, ENDARC,
  and the FILE extra records — redirect, hash, file times, encryption, version) · §4 service
  headers. It covers **RAR 5.0 only**, naming the RAR 4.x signature once for contrast; older
  technotes are linked from the [Library of Congress RAR entry](https://www.loc.gov/preservation/digital/formats/fdd/fdd000450.shtml).
  The compression algorithms are documented nowhere. The parser here also drew on
  [`rarfile`](https://github.com/markokr/rarfile), on reading the UnRAR source, and on the
  `archivey-dev` `rar-native-metadata-reader` exploration; the RAR3 SHA-1 string-to-key and
  Unicode filename decompression are adapted from `rarfile` 4.3 under the ISC licence
- Specs: [`format-rar`](../../openspec/specs/format-rar/spec.md) ·
  [`access-mode-and-cost`](../../openspec/specs/access-mode-and-cost/spec.md) ·
  [`safe-extraction`](../../openspec/specs/safe-extraction/spec.md) ·
  [`packaging-and-extras`](../../openspec/specs/packaging-and-extras/spec.md)
- Code: `internal/backends/rar_parser.py` (headers, both generations, volumes, header
  crypto) · `rar_reader.py` (member mapping, solid demux, temp materialization, exit
  mapping) · `rar_unrar.py` (binary discovery, argv construction) · `internal/backends/rar_detect.py`
  (SFX hit validator) · `internal/volumes.py` (sibling discovery, shared with 7z and ZIP)
- Decisions: ADR [0002](../decisions/0002-native-rar-metadata-unrar-data.md) (native
  metadata, `unrar` data) · ADR [0016](../decisions/0016-committed-rar-corpus-fixtures.md)
  (committed corpus fixtures) · ADR [0003](../decisions/0003-member-streams-opt-in.md)
  (member streams opt-in) · ADR [0010](../decisions/0010-no-silent-buffer-nonseekable.md)
  (no silent buffering)
- Review: [`2026-07-16-rar-reader`](../../review/archive/2026-07-16-rar-reader/SUMMARY.md)
  — F1–F6 with
  [`unrar-boundary.md`](../../review/archive/2026-07-16-rar-reader/unrar-boundary.md) and
  [`hostile-input.md`](../../review/archive/2026-07-16-rar-reader/hostile-input.md)
- Investigations:
  [`alternative-rar-decompressors.md`](../investigations/alternative-rar-decompressors.md)
  (the decompressor matrix, macOS install) ·
  [`rar-corpus-sweep-diagnosis.md`](../investigations/rar-corpus-sweep-diagnosis.md)
  (why the RAR column ran nowhere; the cross-format symlink digest table)
- Probes: `scripts/exploration/rar_unrar_input_matrix.py` (input modes, volume discovery,
  emission policy) · `scripts/exploration/rar_decompressor_matrix.py` (the §3 table). The
  input-mode and emission questions were first investigated in
  [PR #101](https://github.com/archivey-dev/archivey/pull/101), which was never merged; its
  conclusions are stated here and its measurements are what the first script re-runs, so the
  PR is provenance rather than a live reference
- Registers: [`threat-model.md`](../threat-model.md) O1, C1 · [`known-issues.md`](../known-issues.md)
  (MacPaw `unar` silent-wrong)
- Topic: [`prefixed-archives.md`](../topics/prefixed-archives.md) (the shared SFX machinery)
- User-facing: [`docs/formats.md`](../../docs/formats.md#rar) ·
  [`docs/install.md`](../../docs/install.md#getting-rarlab-unrar-or-rar) ·
  [`docs/formats.md`](../../docs/formats.md)
