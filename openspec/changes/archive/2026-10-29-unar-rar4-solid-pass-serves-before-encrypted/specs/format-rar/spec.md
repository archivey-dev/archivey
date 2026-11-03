## MODIFIED Requirements

### Requirement: Read RAR member data with unar

When `ArchiveyConfig.rar_decompressor` is `unar`, or `auto` with no usable RARLAB
`unrar` or `rar` on `PATH`, the system SHALL read compressed member data by invoking
`unar` 1.10 or later, identified on `PATH` by its `unar -h` banner with the same probe
timeout and stat-keyed cache as RARLAB `unrar`. An identified `unar` SHALL also decode a
small embedded RAR5 archive once, under the same timeout and cache, and SHALL NOT be
used unless it writes that archive's one member exactly and exits 0: Debian and Ubuntu
`unar` packages before 1.10.8+ds1-10 write nothing for such members, and their version
string does not tell them apart. A refused `unar` SHALL count as absent under `auto`,
and the refusal SHALL say what the check saw; it names the Debian patch only for exit 0
with a short member. Stored, unencrypted members SHALL still be read directly, whatever
their own solid flag, including a member split across volumes whose parts were all
found, and a stored, encrypted member in one part SHALL be decrypted by archivey as
under `unrar` (`Use RARLAB unrar only for member data that needs it`). The system MUST
NOT use `unrar` in that mode, and MUST NOT use `unar` in any other mode; a missing,
unidentified or refused `unar` SHALL raise
`PackageNotInstalledError` naming `unar`. `auto` SHALL choose once per reader, when the
archive opens; a read `unar` refuses MUST NOT be retried with `unrar`, and with neither
program present `auto` SHALL raise the `PackageNotInstalledError` that names RARLAB
`unrar` or `rar`. When `auto` chooses `unar`, `ar.cost.notes` SHALL say so at open,
naming the password exposure and the `unrar` setting that avoids it.

The argv SHALL be
`unar -o - -q -nr -k skip [-p <password>] [-i] -- <absolute path> [index …]`:
members named by decimal entry index in parse order, never by stored name. The
password is on the command line because `unar` takes it nowhere else, so other local
users can read it in the process list; the documentation SHALL say so. The native
RAR5 password check SHALL reject a wrong password before `unar` runs where the archive
stores one; otherwise, when `unar` produces no data for a non-empty encrypted member,
the read SHALL raise `EncryptionError`. The
system SHALL refuse with `UnsupportedFeatureError`, before spawning `unar`:

- an encrypted RAR 2.x-4.x member that archivey does not decrypt itself (`unar` 1.10
  returns no data for it, and exits 0, even with the right password), and in a solid
  archive every compressed member its solid stream carries into. A solid pass SHALL
  refuse those members, and also every encrypted RAR 2.x-4.x member that `open()`
  decrypts itself (a stored one in one part: the pass has no native-decrypt branch),
  and read the others, those before the encrypted member included, since `unar -i`
  names entries by index and decodes nothing past the last one named; with encrypted
  RAR 2.x-4.x headers it SHALL refuse every member;
- a member or solid pass that needs a password that is not ASCII, or contains NUL
  (`unar` 1.10 does not decrypt with it);
- every member of a multi-volume RAR5 set with encrypted headers (XADMaster 1.10.8
  returns no data for it, and exits 0);
- in a RAR5 solid archive, a member with data that follows an empty file, a
  directory or a link;
- a compressed member whose extract version is below 20 (RAR 1.5 algorithm);
- any member of a multi-volume set that has a prefix before the RAR.

A solid pass that includes a refused member SHALL name only the readable payload
members, so `unar` never decodes the refused one, and SHALL name at most 4000 of
them to stay inside `ARG_MAX`. A readable member past the 4000th SHALL be refused in
that pass with `UnsupportedFeatureError`; opening it on its own is not affected. A
single archive with a prefix SHALL be copied from the RAR's start before `unar`
reads it, bounded by `ArchiveyConfig.spool_limits` for a path source too, and
`ar.cost.notes` SHALL say so at open, naming the limit or the refusal as for a stream
source. Every
member read through `unar` SHALL be checked against its declared
size and stored digest, because `unar` exits 0 on some failures.

A compressed RAR 1.5-4 comment (a RAR 1.5/2.x old-style COMMENT subblock, or a
RAR 2.9-4 `CMT` SERVICE header that is not stored) SHALL be decoded by the selected
program, so with `unar` selected `unar` decodes it. The decoded text SHALL be used
only when its stored CRC matches (the CRC16 of a COMMENT subblock, the full CRC32 of a
`CMT` header); otherwise, or when the selected program is missing, the comment SHALL be
`None`, as it is with `unrar`. A compressed `CMT` that declares more than 256 KiB, the
most `rar` writes, SHALL be `None` and SHALL NOT be weighed or decoded.

#### Scenario: unar selection matrix

| Case | Expected |
| --- | --- |
| Default config (`auto`), RARLAB `unrar` present, compressed member | `unrar` is spawned; `unar` is not |
| Default config (`auto`), only a `unar` that passes the RAR5 check, compressed member | `unar` is spawned; `ar.cost.notes` says why at open |
| `rar_decompressor="unrar"`, only `unar` present | `PackageNotInstalledError` names RARLAB `unrar` or `rar`; `unar` is not used |
| `rar_decompressor="unar"`, `unar` missing, `unrar` present | `PackageNotInstalledError` names `unar`; `unrar` is not used |
| `rar_decompressor="auto"`, RARLAB `unrar` present | `unrar` is spawned; `unar` is not |
| `rar_decompressor="auto"`, only a `unar` that passes the RAR5 check | `unar` is spawned |
| Only a `unar` that fails the RAR5 check (`tests/test_unar_probe.py`), `auto` or `"unar"` | `auto`: as with neither present; `"unar"`: `PackageNotInstalledError` saying what the check saw |
| `rar_decompressor="auto"`, neither present | `PackageNotInstalledError` names RARLAB `unrar` or `rar` |
| `unar` selected, member name contains `*` | Read by index; no `rar_allow_glob_member_concatenation` needed |
| `unar` selected, encrypted RAR5 member, right password | Read correctly; the password is passed with `-p` |
| `unar` selected, encrypted RAR5 member, wrong password | `EncryptionError` |
| `unar` selected, encrypted RAR 2.x-4.x member, compressed or split | `UnsupportedFeatureError` naming the RAR 2.x-4.x reason |
| `unar` selected, stored encrypted RAR 2.9-4 member in one part, `open()` | Decrypted by archivey; `unar` is not spawned |
| `unar` selected, solid RAR 2.x-4.x pass with an encrypted compressed member | That member and the compressed members after it in its solid stream refused, saying `unar` 1.10 cannot read them and naming `rar_decompressor='unrar'`; the members before it read correctly |
| `unar` selected, solid RAR 2.x-4.x pass with a stored encrypted member in one part, `cryptography` installed | Refused in the pass, though `open()` decrypts it; the members before the first encrypted one are read |
| `unar` selected, solid RAR5 pass where a member's header stopped before encryption was ruled out, empty run | Not `EncryptionError`: the member's fail-closed flag says nothing about the run |
| `unar` selected, non-ASCII password | `UnsupportedFeatureError` naming the password reason |
| `unar` selected, RAR5 volume set with encrypted headers, right password | `UnsupportedFeatureError` |
| `unar` selected, RAR5 solid, empty file first | Members with data after it are refused; listing is not |
| `unar` selected, member before the first empty entry in a RAR5 solid pass | Read correctly from a run that names only readable members |
| `unar` selected, RAR 1.5 compressed member | `UnsupportedFeatureError` |
| `unar` selected, single archive after a 4 KiB prefix | Read from a copy that starts at the RAR; `ar.cost.notes` warns of the copy at open |
| `unar` selected, solid pass with a refused member and more than 4000 readable members | Members past the 4000th refused in the pass; each still opens on its own |
| `unar` selected, compressed RAR 1.5 archive comment | Decoded by `unar` and checked against its CRC16 |
| `unrar` present, RAR 2.9-4 archive comment in a compressed `CMT` SERVICE header | Decoded, checked against its CRC32, and UTF-16LE when `SUBHEAD_FLAGS_CMT_UNICODE` is set |
