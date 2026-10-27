# Alternative RAR decompressors (`unar`, `7z`, `bsdtar`, `unrar-free`)

**Status:** finished evidence. `7z` closed. **`unar` implemented 2026-09-26** as the
opt-in `ArchiveyConfig.rar_decompressor="unar"`, with the early-fail gate widened after
new measurements ([2026-09-26 measurements](#2026-09-26-measurements-behind-the-shipped-gate)
at the end of this page; the live upstream defect is in
[`known-issues.md`](../known-issues.md) §MacPaw `unar`). The body below that section's
heading is the 2026-09-01 evidence as recorded.  
**Date:** 2026-09-01  
**Trigger:** Homebrew disabled the `rar` cask (Gatekeeper / notarization); CI now
compiles RARLAB UnRAR from a pinned GitHub mirror
([PR #276](https://github.com/archivey-dev/archivey/pull/276)). Question: should archivey
accept another CLI for member **data** — first `unar` (easy `brew install`), then
whatever rarfile already wraps?

**Measured on:** Ubuntu noble. RARLAB `unrar` 7.00 (gold). `unar`/`lsar` **v1.10.1**
(Debian `unar 1.10.7+ds1+really1.10.1`); locally built MacPaw `XADMaster` `v1.10.8`
binary reporting **v1.10.7**. `7z` **23.01** from Ubuntu `7zip` (DFSG) **without**
and **with** the `7zip-rar` plugin. `bsdtar` 3.7.2 (libarchive). `unrar-free` 0.1.3.
Fixtures under `tests/fixtures/rar/` plus `rar a -s` probes.

Re-run: `python3 scripts/exploration/rar_decompressor_matrix.py`

Related policy: ADR
[`0002-native-rar-metadata-unrar-data`](../decisions/0002-native-rar-metadata-unrar-data.md),
threat-model **C1**, `src/archivey/internal/backends/rar_unrar.py`.

---

## Verdict

| Candidate | As a RAR **data** backend |
| --- | --- |
| **`unar`** | **Open.** Stdout concat is real. RAR5 solid + any empty FILE SIGSEGVs (apt 1.10.1) or returns **rc=0 empty** (built 1.10.7 / Homebrew's XADMaster 1.10.8) — **including disk extract**. Skipping empties does not help. A listing-only early-fail gate can refuse the affected archives; do not ship a backend until that gate exists and a Homebrew bottle is measured. |
| **`7z e -so`** | **Closed.** Only with the RAR codec actually loaded, and even then a second non-free decompressor. Distro `7zip` lists RAR5 and extracts **stored** (`-m0`) members, then says `Unsupported Method` on solid / typical compressed members. `apt install 7zip-rar` adds `Codecs: Rar5` and then the ALL-pipe matches `unrar p` on `basic_solid__.rar`, encryption, hostile names, volumes. Remaining CLI gaps: no stdin password, missing-member **rc=0**, `path;n` unused, link members can set **rc=2** while the payload concat is still correct. No gain over RARLAB `unrar`. |
| **Homebrew `7-zip` / `7zz`** | **No.** Core formula compiles with `DISABLE_RAR_COMPRESS=1`. Same `Unsupported Method` on solid RAR as Debian `7zip` without `7zip-rar`; Homebrew ships no plugin extra. |
| **`bsdtar`** | **No.** Documents no solid / no password. Solid RAR4: `RAR solid archive support unavailable`. Stored nonsolid: **unbounded stdout** (~7 GB in 8 s) — the matrix now kills at a 2 MiB cap (`rc=125`) rather than skipping the row. |
| **`unrar-free` 0.1.3** | **No.** Extract-to-disk only; no stdout. |
| **Unofficial brew `unrar` taps** | **Not a second engine** — they install RARLAB UnRAR. Usable for users who accept a third-party tap; **not** for CI. |

**macOS install:** published user guidance is `docs/install.md` §Getting RARLAB
unrar — pip users, no repo checkout. First-line is the unofficial Homebrew
tap (bottles from the tap's GHCR, or a compile of the formula's RARLAB
tarball); alternative is a copy-paste source build that does not use the tap.
User docs name `unar` / `7z` once, because `rarfile` accepts them; they are
not substitutes. CI still compiles the pinned UnRAR source. **`7z` as a
second engine is closed** (still non-free). **`unar` stays open** on an
early-fail gate plus an upstream XADMaster report — not as a silent fallback.

---

## What archivey needs

From `rar_unrar.py` / `rar_reader.py` / `format-rar`:

```
  native parser ──► list / sizes / solid flag
                         │
         ┌───────────────┼───────────────┐
         ▼               ▼               ▼
   stored nonsolid  named unrar p   ONE unnamed pipe
   (direct slice)   -n./member      + SolidBlockReader
```

| Need | Why |
| --- | --- |
| Raw payload on **stdout** | Streaming API |
| ALL payload members concatenated in archive order | Solid `stream_members()` |
| Single member by stable identity | Nonsolid / random solid `open()` |
| Dirs / RAR5 redirects omitted from the pipe | Demux size map = `is_payload_file()` |
| Honest non-zero exit on wrong password / missing / fatal | Typed errors |
| Password not forced onto argv | Process-list hygiene (`unrar` bare `-p` + stdin) |
| Safe hostile names (`-inul`, `@…`) | Already hardened via `-n./` |

rarfile’s probe order is `unrar` → `unar` → `7z`/`7zz` → `bsdtar`, with
`7z e -so -bb0` as the 7-Zip cmdline.

---

## `unar`

`unar -o -` concatenates selected members to stdout (no framing). Matches
`unrar p` on the committed fixtures that are stored/nonsolid, solid **without** empty
files, solid RAR4 **with** empty files, volumes, correct-password encryption, hostile
names (by `-i` index). It does not match on every compressed RAR5 member: 1.10.1 drops
some, below.

### Compressed RAR5 member dropped — exit 0

apt 1.10.1 writes nothing for a compressed RAR5 member when a Huffman lookup near its
end peeks past the last packed byte, solid or not, and exits 0 with empty stderr under
`-o -`. About 1–6% of `-m3` members of small random text did this. The 14-byte repro,
with RAR 7.00, is the shortest over `ab` that `rar` compresses and `unar` drops;
`scripts/find_unar_probe_member.py` finds it and explains the condition:

```sh
printf 'aaaaabababbabb' > f.txt
rar a -ma5 t.rar f.txt
unar -o - t.rar | wc -c    # 0; unrar p writes 14
```

Earlier notes said the member's last packed byte uses 6–8 of its bits. That is a
correlation, not the condition: XADMaster peeks as many bits as the longest code in the
table (at most 10) before it decodes a symbol, so the last symbol fails when its code is
shorter than that by more than the last byte's unused bits. Many members with 7 or 8
bits used decode.

The cause is Debian's `CSInputBuffer-bit-string-reading.patch`, applied only to the
Debian/Ubuntu 1.10.1 package: its bit reader raises end of file when fewer bits remain
than a Huffman lookup peeks, though the code it uses is shorter. Built from source
(2026-10-01), upstream 1.10.1, 1.10.7, 1.10.8 and master decode the repro, the fixtures and
300 generated RAR5 archives correctly; the Debian build drops 27 of 300 archives' members,
and the same build without the patch drops none. That patch is also why apt 1.10.1 loses
`FILE1.TXT` in the RAR 1.5 fixture. The empty-member failure below is a separate, upstream
bug and is unrelated.

Which packages carry the patch, from the `debian/patches/series` of each source package in
Ubuntu's archive (2026-10-01): Ubuntu 22.04 (1.10.1-2build11), 24.04
(1.10.7+ds1+really1.10.1-3build1) and 26.04 (1.10.8+ds1-9build1), and Debian 1.10.8+ds1-2
to -9. Debian 1.10.8+ds1-10 (unstable, June 2026) deleted it. Upstream 1.10.8 built with
the patch applied writes 0 bytes for the repro. archivey now runs this repro once per
`unar` binary and does not use one that fails it (`known-issues.md`).

A run of one entry (`-i k`) writes the member exactly or not at all. A run of several
entries of a solid archive loses the dropped member and can go on to lose later ones,
or write stale window bytes for one: the bytes at the dropped member's offset in the
concatenation are then someone else's, and often as many as its declared size. Only
the member's CRC32 or BLAKE2sp tells them apart, so archivey's `unar` solid pass reads a
member with neither through a run of its own. Fixtures: `tests/fixtures/rar/unar_drop*`
and `unar_stale*`. The 1.10.8 lineage was not measured for this.

### Solid RAR5 + empty FILE — stdout **and** disk

Empty members are packed (28 bytes on `basic_solid__.rar`). Skipping them in the
extract argv does not avoid the crash: `unar` still decodes that solid slot.
Empty first / mid / last all fail when reading a **non-empty** member.

| Mode | apt 1.10.1 | built 1.10.7 |
| --- | --- | --- |
| `unar -o -` ALL / `file1.txt` only | **SIGSEGV**, 0 bytes | **rc=0**, 0 bytes |
| extract to a directory | SIGSEGV; 0-byte stubs | rc=1; non-empty files written empty (`Failed! (Unknown error)`) |
| empty member only (`-i 0`) | rc=0, 0 bytes | rc=0, 0 bytes |

**Tempdir fallback does not help.** The bug is the RAR5 solid decoder, not the
stdout writer.

### Homebrew `unar` (installable; bottle not yet measured)

homebrew-core formula
[`unar`](https://github.com/Homebrew/homebrew-core/blob/master/Formula/u/unar.rb)
builds MacPaw **XADMaster v1.10.8** (bottles include `arm64_tahoe`). That is
the silent-empty lineage, not apt's SIGSEGV 1.10.1. Maintainer confirmed
`brew install unar` installs on a Mac. `unar -v` from that Mac, and the
fixture matrix against `unrar p` on a **brew bottle**, have not been run.

Other gaps: wrong data password **rc=0** + empty; named `file.txt` concatenates
all `-ver` revisions; `-inul` parsed as an unar option unless `-i` is used;
password on argv only.

---

## `7z`

### The codec lottery (this is the spike)

Ubuntu `7zip` 23.01 **advertises** `Rar` / `Rar5` under **Formats** in `7z i`.
The **Codecs** list has Copy / LZMA / … and **no** `Rar5` until `7zip-rar` is
installed. Listing (`7z l basic_solid__.rar`) works either way. Data does not.

| `7z e -so` | Distro `7zip` only | After `apt install 7zip-rar` |
| --- | --- | --- |
| Stored `-m0` (basic nonsolid, blake2sp, volumes, corpus `large.rar`) | matches `unrar p` | same |
| Nonsolid `-m3` (fresh `rar a -m3`) | matched here without the plugin | matches |
| Solid RAR5 + empty (`basic_solid__.rar`) | **rc=2, 0 bytes, `Unsupported Method`** | **41 B, match** |
| Solid RAR4 + empty | `Unsupported Method` | match |
| Encrypted compressed (`encryption__.rar` `-m3`) | `Unsupported Method` | match, wrong password **rc=2** |
| Hostile `-m5` names | `Unsupported Method` | match with `-spd` |
| Disk extract of `basic_solid__.rar` | 0-byte files, rc=2 | files + concat match |

`7z i` showing a Rar5 **format** is not an availability probe. A backend would
need `Codecs:` containing `Rar5`, or a trial extract of a compressed (ideally
solid) member.

`7zip-rar` is Ubuntu **multiverse**, same non-free neighbourhood as `unrar`.
It does not magically make RAR “just a pip extra.” On Windows / official 7-Zip
builds the codec is usually bundled; on Debian/Ubuntu it is an extra package;
Homebrew `sevenzip` / `7-zip` bottles exist and **do not** ship the codec (see
Homebrew `7zz` below).

### With the codec loaded — CLI vs `unrar p`

`7z e -so -bb0 -bd -spd -- archive [members…]` (rarfile’s shape plus `-spd`).

| Case | Result vs `unrar p` |
| --- | --- |
| Solid ALL-pipe including empty members | **match** (RAR5 and RAR4) |
| Two named members, argv reversed | concat in **archive order** (good) |
| Nested path `subdir/file2.txt` | match; **basename** `file3.txt` of a nested solid member is **empty** (need the archive path) |
| Missing member | **rc=0**, empty stdout (same hole as `unar`; `unrar` rc=10) |
| File-version ALL | matches `unrar p -ver` (includes history), not default `p` |
| `file.txt` (live) | live bytes only (good) |
| `file.txt;1` | **empty** (no `path;n`) |
| Hostile `-inul` / `@atfile` with `-spd` | match |
| Password | `-ppassword` on **argv**; bare `-p` + stdin is **not** accepted (wrong-password error) |
| Wrong password | rc=2, empty, `ERROR: Wrong password` (honest — better than `unar`) |
| Symlink / hardlink solid | **payload concat matches**, but **rc=2** `Data Error` on the redirect rows. Mapping 7z’s 2 → `CorruptionError` would false-positive a correct pipe. |
| `-bb0 -bd` | stderr empty; stdout stays gold |

---

## `bsdtar` / `unrar-free`

rarfile already warns: no solid, no password, no RARVM filters, no multi-volume.

Measured:

- Solid RAR4: `RAR solid archive support unavailable.`
- Solid RAR5: `Unsupported block header size`.
- **Stored nonsolid** `basic_nonsolid__.rar`: `--to-stdout` wrote **~7 GB** in
  8 s in the first spike. The matrix now caps stdout at 2 MiB (`rc=125`,
  note `output cap exceeded`) instead of skipping the row.
- Encrypted: fails fast (header error), no password switch.
- `unrar-free` 0.1.3: `-x` extract only; `--help` has no stdout option.
  (rarfile’s docs mention a newer libarchive-based unrar-free with stdout; that
  is not what Ubuntu ships.)

---

## Mapping if we ever add a second engine

```
                    stdout concat of payload members
                                    │
              ┌─────────────────────┼─────────────────────┐
              ▼                     ▼                     ▼
           unrar              7z + Rar5 codec           unar
        full, non-free     closed: still a            open: easy brew,
        (what we use)      non-free plugin            listing-only gate
                                                      for solid+empty
              │                     │                     │
              └────── bsdtar / unrar-free ────────────────┘
                     no solid / no stdout / stdout bomb
```

A `7z` opt-in was considered and **closed**: codec probe, argv builder, and
CLI gaps are real work for another non-free codec. `unar` stays open on the
listing-only gate plus an upstream XADMaster report — not as a silent
fallback.

---

## Recommendation

1. **Do not add `unar` in this PR.** Keep it open. Disk extract is not a
   workaround and skipping empty members is not a workaround, but a
   listing-only early-fail gate (`format == RAR and info.is_solid and any
   FILE with size == 0`, also on RAR4) would refuse the known-bad archives
   before spawning `unar`. Blocked on: that gate in a backend, an upstream
   XADMaster report, and a fixture matrix on a Homebrew `unar` bottle.
2. **Do not add `7z`.** Closed. The plugin path works, and is still a
   RARLAB-derived non-free codec under a different package name.
3. **Do not add `bsdtar` / `unrar-free`.**
4. **Do not silently fall back** to whatever is on `PATH` (C1).
5. **macOS install friction:** published `docs/install.md` is for pip users.
   Unofficial Homebrew tap first (trust the tap; bottles or formula source),
   copy-paste rarlab `make` second. CI keeps the pinned source build
   (`scripts/install-rarlab-unrar.sh`).

---

## Homebrew `7zz` (closed)

`brew install 7-zip` (core formula `sevenzip`, also aliased `7zip`) installs
the binary **`7zz`**. Homebrew compiles `CPP/7zip/Bundles/Alone2` with
`DISABLE_RAR_COMPRESS=1`
([`Formula/s/sevenzip.rb`](https://github.com/Homebrew/homebrew-core/blob/master/Formula/s/sevenzip.rb)).
7-Zip's own `DOC/readme.txt`: with that flag, 7-Zip can still **list** a RAR and
extract **stored** members, but cannot decompress compressed / solid RAR.

User measurement (macOS, 2026-09-01): `7zz i` shows no RAR codec; extracting a
solid RAR prints `ERROR: Unsupported Method : <member>` per file. Same lottery
as Ubuntu `7zip` without `7zip-rar`, except Homebrew has **no** `7zip-rar`
plugin package — the non-free codec is stripped at compile time for the same
UnRAR-license reason core dropped `unrar`
([homebrew-core #66609](https://github.com/Homebrew/homebrew-core/pull/66609),
[brew#15395](https://github.com/Homebrew/brew/issues/15395)).

**Not an archivey RAR data backend, and not an easy macOS alternative.**

---

## Unofficial Homebrew `unrar` taps

Not a second decompressor: these formulae compile **RARLAB UnRAR** and install
`unrar`. archivey's finder (`UNRAR` + `Alexander Roshal` / `RARLAB`) will accept
them. The question is trust and whether CI should depend on them.

### `brew install gromgit/new-life/unrar`

Tap: [gromgit/homebrew-new-life](https://github.com/gromgit/homebrew-new-life)
("Resurrecting Homebrew formulae/casks that fell by the wayside"). Suggested in
[Homebrew discussion #3355](https://github.com/orgs/Homebrew/discussions/3355).
User confirmed it produces a working `unrar` on macOS.

Formula `Formula/unrar.rb` as of 2026-09-01 (last bump
[`be584aab`](https://github.com/gromgit/homebrew-new-life/commit/be584aabbe182d561f78c457b37c3c79f65c6229),
2025-07-31):

| Field | Value |
| --- | --- |
| homepage | `https://www.rarlab.com/` |
| url | `https://www.rarlab.com/rar/unrarsrc-7.1.10.tar.gz` |
| sha256 | `72a9ccca146174f41876e8b21ab27e973f039c6d10b13aabcb320e7055b9bb98` |
| install | `make` then `bin.install "unrar"` (plus `libunrar` dylib rename on macOS) |
| livecheck | rarlab.com `rar_add.htm` |
| bottles | `arm64_sequoia`, `arm64_sonoma`, `ventura`, `x86_64_linux` — **no Tahoe**, **no arm64_linux** |
| bottle host | `https://ghcr.io/v2/gromgit/new-life` |

Fetched that rarlab URL on 2026-09-01; sha256 **matches** the formula. The
tarball is UnRAR source (`version.hpp` `RARVER_MAJOR 7` / `RARVER_MINOR 13` —
banner 7.13). This is the old homebrew-core unrar formula, not `unrar-free`.

Maintainer: Adrian Ho ([gromgit](https://github.com/gromgit)), a long-time
Homebrew contributor (commented on the 2020 core unrar-removal PR). Tap created
2020-12, ~2 stars, one primary author. Formula commits are unsigned.

### `carlocab/personal/unrar`

Same shape, older pin (`unrarsrc-7.1.5.tar.gz`), bottles through Sequoia +
Linux. [PR #276](https://github.com/archivey-dev/archivey/pull/276) already rejected
it for CI: personal tap, bottles stop before `macos-latest` (Tahoe).

### Trust

- **Source build path:** official RARLAB tarball, checksummed. Functionally the
  same class as `scripts/install-rarlab-unrar.sh` (different pin: 7.1.10 vs
  7.2.7 / banner 7.23). A user who lets brew compile on a bottle-less OS is
  compiling rarlab.com source locally — that is the more trustworthy of the two
  brew paths.
- **Bottle path:** prebuilt binary from a third-party GHCR namespace. Homebrew
  still verifies the sha256 listed in the formula; the remaining bet is that
  gromgit's GHCR and the formula stay honest.
- **Ruby:** short, matches the historical core formula. No extra download
  scripts.
- **What it is not:** Homebrew-blessed, multi-maintainer, or pinned by us. A
  tap can change the URL tomorrow; CI would inherit that.

### CI decision: do not switch

Keep compiling the pinned `pmachapman/unrar@d861246` commit via
`scripts/install-rarlab-unrar.sh` on macOS. Reasons, same neighbourhood as #276:

1. Bottles lag current GitHub `macos-latest` (Tahoe). A tap job would compile
   from an unpinned-to-us tarball, or fail if the tap/formula disappears.
2. We already have a content-addressed pin and a GHA cache of the **built
   binary**.
3. Linux CI uses distro `unrar`; Windows uses the official SFX. A third-party
   tap would be a macOS-only extra moving part.

A one-off "does the tap's `unrar` pass our RAR tests" job would only restate
that RARLAB UnRAR 7.1.10 works, which the existing suite already covers at
7.00 / 7.23.

### User-facing guidance

Published on `docs/install.md` (pointer from `docs/formats.md`). Audience is pip
installers, not a repo checkout. First-line macOS: unofficial
`gromgit/new-life/unrar` (compiles RARLAB source). Alternative: copy-paste
source build onto PATH. The repo script stays a contributor/CI path
(`setup-dev-env.sh`, `ci.yml`). Lookalikes (`unar`, Homebrew `7zz`) are not
mentioned in user docs. The 2018 rar_add “UnRAR for Mac OS X 64 bit” link is
called out as *not* the current official binary.

---

## Official macOS `unrar` binaries (closed)

Two different files on rarlab.com, easy to mix up.

### `rar_add.htm` — “UnRAR for Mac OS X 64 bit”

`https://www.rarlab.com/rar/unrar_MacOSX_10.13.2_64bit.gz`

- Lives under **Addons contributed by our users**. RARLAB’s footer on that page:
  no support for those non-Windows binaries; official UnRAR for OS X is part of
  the RAR package.
- gzip date **2018-01-30**. Mach-O **x86_64 only**, **no** `LC_CODE_SIGNATURE`,
  min OS 10.13.
- Not a current official binary. Do not send users there.

### `download.htm` — RAR for macOS ARM / x64 (what the Homebrew cask shipped)

Fetched `rarmacos-arm-720.tar.gz` / `rarmacos-x64-720.tar.gz` (cask version
7.20; download.htm currently lists 7.23). Each tarball contains `rar/unrar`.

| Binary | Arch | Code signature |
| --- | --- | --- |
| ARM `unrar` | arm64, min OS 11.0 | **Ad-hoc + linker-signed** (`CS_ADHOC\|CS_LINKER_SIGNED`). SuperBlob has a CodeDirectory only — **no** CMS / notarization ticket. |
| Intel `unrar` | x86_64, min OS 10.9 | **Unsigned** (no `LC_CODE_SIGNATURE`). |

That is why Homebrew marked the `rar` cask `disable! … because: :fails_gatekeeper_check` on 2026-09-01. Gatekeeper assesses **quarantined downloads** (browser, Homebrew casks). It is not “Tahoe refuses every unsigned binary”:

- A **local compile** (unix makefile, or a Homebrew *formula* build) gets an
  ad-hoc signature from the linker and is not quarantined. That is what CI
  does, and what `gromgit/new-life/unrar` does when there is no bottle.
- The **vendor tarball** Apple-silicon `unrar` is already ad-hoc signed, so
  *if it is not quarantined* (e.g. `curl` in Terminal) Tahoe will run it. A
  Safari download or `brew install --cask` sets quarantine and Gatekeeper
  blocks until the user allows it in System Settings. Tahoe also made the old
  CLI quarantine bypasses harder for *apps*; Homebrew will not ship the cask
  regardless.
- Apple silicon still requires *some* signature for arm64; ad-hoc counts.
  Intel Tahoe still runs unsigned x86_64, but that Intel package is still a
  Gatekeeper problem once quarantined.

**Will RARLAB notarize later?** Possible, not something to promise. RAR 7.20
(Feb 2026 tarball) is still ad-hoc on ARM and unsigned on Intel — years after
users hit “developer cannot be verified.” If they Developer ID–sign and
Apple-notarize a future macOS build, Homebrew *could* re-enable the `rar`
**cask**. Homebrew **core** still will not ship an `unrar` *formula*: that
removal was the UnRAR license (2020), independent of Gatekeeper.

**User-docs implication:** pointing at the official macOS *package* is honest
but a worse first-line than compiling source (Gatekeeper prompt, ARM vs Intel
URL, trialware `rar` sitting next to `unrar`). Mention it as “exists, may be
blocked, not the add-ons 2018 link.” Lead pip users at a source compile —
the unofficial formula or a copy-paste `make`.

---

## Open questions (`unar` kept open; `7z` closed)

- File the XADMaster RAR5 solid+empty bug (1.10.1 SIGSEGV vs 1.10.7+ silent
  empty on stdout **and** disk extract). Evidence is in this document and
  `dev-docs/known-issues.md`.
- Run the fixture matrix on a Homebrew `unar` bottle (formula is XADMaster
  1.10.8). Record `unar -v` from that Mac.
- Early-fail gate for a future `unar` backend: native listing only —
  `format == RAR and info.is_solid and any FILE with size == 0`. Gate RAR4
  too (conservative: RAR4 solid+empty reportedly works). The predicate is
  generalized from one fixture family; ANTI members and packed-nonzero /
  unpacked-zero empties are untested, so it may be under-inclusive.
- Do not add a `unar` backend in this PR, and do not point CI at
  `brew install unar` or at `gromgit/new-life/unrar`.

`7z` leftover (not pursuing): ignore rc=2 when every payload member's CRC
verifies (symlink archives)? Too much special-casing for a closed branch.

---

## 2026-09-26 measurements behind the shipped gate

**RAR5 solid after an empty entry, by lineage** (stdout and extract-to-disk alike):

| `unar` lineage | `unar -o -` / disk extract |
| --- | --- |
| Debian `unar 1.10.7+ds1+really1.10.1` | **SIGSEGV**. Output of *earlier* members that `unar` had buffered is lost too (`wildcard_names_solid__.rar`: 8192 of 8202 bytes of member 0) |
| Locally built MacPaw XADMaster `v1.10.8` (banner **v1.10.7**) | **rc=0**, empty output (silent wrong data) |
| homebrew-core formula `unar` (XADMaster **v1.10.8**) | Same 1.10.8 lineage. CI's macOS leg installs it and runs `tests/test_rar_unar.py` against it |

Probes written with `rar a -s -ds -m3`, member order kept: an empty file first or in the
middle fails, an empty file last passes, a directory between members fails
(`wildcard_names_solid__.rar`), directories written last pass. RAR4 passed every shape.
Selecting only the later member does not help: the decoder still walks the earlier slot.

**The gate as shipped.** From the native listing: in a RAR5 solid archive, refuse every
member with data that follows an empty file, a directory, or a link (links are included
without a failing sample, on the same no-data-in-the-stream grounds). The solid pass then
names only the readable members by index, so `unar` never reaches the crash and loses no
buffered output. RAR4 is not gated; the size and digest check on each member is the net.

**Six more `unar` behaviours found on the committed fixtures**, all handled in
`internal/backends/rar_unar.py`:

- **RAR 1.5 compression** (`rar15-comment.rar`, `FILE1.TXT`, method 3 at version 15):
  `unar` writes nothing for the member and exits 0. Refused when a member's extract
  version is below 20 and it is not stored. The same archive's comment blobs carry the
  same method (`extract_version=15`, `compress_type=0x34`), and `unar` 1.10.1 decodes
  them correctly through the one-file RAR `decompress_rar3_blob` builds (archive and both
  member comments). Comments are therefore not gated; the stored CRC16 drops any wrong or
  missing output under either program.
- **A prefix before the RAR** (an SFX stub, or any leading bytes): `unar` reports an
  unknown format. A single prefixed archive is copied from where the RAR starts; a
  prefixed multi-volume set is refused.
- **Volume names follow the header** (`tinyvol_rnn.rar` + `.r00` given as streams):
  `unar` looks for volume 2 only under the scheme the main header names, and read an
  old-style set written to disk as `partN` as volume 1 alone (a short member, caught by
  the size check). Stream volumes are written under the set's own scheme.
- **Encrypted RAR 2.x-4.x data** (`encryption__rar4.rar`, the RAR4 header-encrypted
  fixtures): `unar -p <right password>` writes nothing and exits 0. Refused. Encrypted
  RAR5 data, header-encrypted RAR5 included, decodes correctly with `-p`. A wrong
  password also gives exit 0 and no output, so an empty pipe for a non-empty encrypted
  member is reported as `EncryptionError`; no password at all gives exit 2.
- **A non-ASCII password** does not decrypt RAR5 data (measured with the `rar` writer
  and a password with `é`). Refused. A password starting with `-`, or holding quotes or
  backslashes, works because it is its own argv item.
- **A multi-volume RAR5 set with encrypted headers** (`tinyvol_hp.part1.rar`): Debian's
  1.10.1 decodes it with the right password, but the Homebrew bottle (XADMaster 1.10.8)
  writes nothing and exits 0 (CI's macOS leg). Refused under every version, since the
  finder does not tell 1.10.1 and 1.10.8 apart for this.

Also different from `unrar p`, and handled in the pipe layout rather than refused: an
all-entries run always includes file-version history rows, and a RAR3/4 symlink emits its
stored target as data.
