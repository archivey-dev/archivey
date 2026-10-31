# Feed `unrar` a synthetic archive per read

> **Design draft.** No implementation yet. The maintainer reviews the design and the four
> open decisions in `design.md` §"Decisions for the maintainer" before any code lands.

## Why

Today every `unrar` read hands the program the **original archive** and selects the
member with a `-n` include mask. Three costs follow from that one choice:

- **Each open walks every header.** `unrar` does not stop at the first match, because a
  mask can select more members. Opening one 2 KB member costs 6.8 ms in an archive of
  1,000 members and 20.6 ms in one of 10,000. `extract_all()` on a nonsolid archive opens
  each member this way, so it grows with the square of the member count: 7.5 ms per
  member at 1,000 members, 12.4 ms at 4,000 (49.5 s in total).
- **A stream source is copied whole.** `unrar` needs a seekable file, so the first read
  `unrar` serves copies the entire archive to disk. Reading a 1.2 KB member of a 200 MiB
  archive opened from a `BytesIO` takes 1,350 ms; from a path it takes 7.1 ms.
- **The name is a mask.** About a thousand lines port how `unrar` reads names and masks
  (`UtfToWide`, `CharToWide`, `CmpName`, the dot rule, the locale) so that archivey can
  predict which members a mask selects. Some names still cannot be addressed and are
  refused, or sent to `unar` under `auto`. A public config flag,
  `rar_allow_glob_member_concatenation`, exists only for this.

`rarfile` solved the same problem by writing a small single-member RAR. The idea is
recorded in `dev-docs/formats/rar.md` §7 ("Can the stream-source copy be made small"),
in the `format-rar` spec as the deferred "benchmark-gated small-member optimization", and
was deferred before 0.2.0 with the RAR3 comment batching that would share the writer.

## What Changes

- For a read that `unrar` serves, archivey writes a **synthetic RAR** to a temporary
  file: a signature, a made-up MAIN header, the FILE header of each member the read needs
  (copied from the archive, with the name replaced), their packed bytes copied verbatim,
  and an ENDARC header. `unrar p` reads that file. Measured with `unrar` 7.00: 36 of 36
  shapes read byte-identical (RAR4 and RAR5; plain, `-p` and `-hp`; nonsolid, solid
  groups, split members). See `design.md` §"Measurements".
- A nonsolid member needs only itself. A solid member needs the chain from the start of
  its solid stream, as `unrar` decodes when a name is given as an argument.
- A member split across volumes becomes one whole member: the parts are joined. The
  synthetic archive is never a volume set.
- A header-encrypted (`-hp`) archive gets plain headers in the synthetic file; the data
  stays encrypted and `unrar` still gets the password on stdin.
- Archivey verifies the synthetic header against the listing before it spawns `unrar`, so
  the member `unrar` decodes is the member archivey listed.
- A copy is bounded by `SpoolLimits.max_bytes`, as the whole-archive copy is today.
- Proposed (decisions D1-D4): every `unrar` read goes through a synthetic archive except
  a large member of a path source whose name the mask selects alone; members get
  placeholder names; a pass over a nonsolid archive batches members into one `unrar`
  run; `rar_allow_glob_member_concatenation` is deprecated.

## Impact

- Capabilities: `format-rar` (new requirement for the synthetic archive; the deferred
  small-member requirement is replaced). The mask-related requirements and the
  stream-copy rows of `Serve random access and extraction with bounded explicit temp
  use` change once D1 and D4 are decided (tasks §2).
- Code: `internal/backends/rar_reader.py` (`_open_member_with_program`, the solid pass,
  `_ensure_archive_path`), a new writer module beside `rar_unrar.py`, and removals in
  `rar_unrar.py` (mask model, dot-rule probe) if D1 is B or A.
- Public API: no new names. `ArchiveyConfig.rar_allow_glob_member_concatenation` is
  deprecated (D4).
- Not changed: `unar` reads (a follow-up can give it the same file), listing, the
  natively read stored and decrypted members, and RAR over non-seekable sources (this
  change removes one of the two reasons RAR needs a seekable source; the other is the
  header walk at open).
