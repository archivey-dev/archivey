# Vendored RAR fixtures for the native reader tests

Most archives here are **generated** by:

```bash
uv run python scripts/gen_rar_fixtures.py
```

That script shells out to RARLAB `rar` (and, when the system `rar` is 7.x and
lacks `-ma4`, downloads Ubuntu's rar 6.23 package, checks its pinned SHA-256 and
unpacks the binary into the user cache, solely to write RAR4 fixtures). Re-run the
script after changing member layouts or compression flags, then commit the updated
binaries. To add new fixtures without rewriting the others, pass
`--only 'name*.rar'`.

Multi-volume fixtures:

| Files | Notes |
| --- | --- |
| `tinyvol.part1.rar` / `tinyvol.part2.rar` | RAR5 `-v` / `.partN.rar` naming |
| `tinyvol_m3.part1.rar` / `tinyvol_m3.part2.rar` | RAR5 `-m3 -v900b`; a compressed member split across volumes, which still needs unrar (a stored one is joined natively) |
| `tinyvol_enc.part1.rar` / `tinyvol_enc.part2.rar` | RAR5 `-m0 -v1200b -ppassword`; a stored, encrypted member split across volumes. Each part has its own encryption record, so a program reads it rather than archivey |
| `tinyvol_hp.part1.rar` … `tinyvol_hp.part4.rar` | RAR5 `-m0 -v900b -hpheader_password`; every part repeats one encryption record, so the header key is derived once per set |
| `tinyvol_rnn.rar` / `tinyvol_rnn.r00` | RAR4 `-ma4 -vn` classic `.rar` + `.r00` naming |
| `tinyvol_cut.part1.rar` … `tinyvol_cut.part3.rar` | RAR5 `-m0 -v1500b`, members `a.txt` … `d.txt`; the fourth volume was deleted, so `d.txt` runs into a missing volume |
| `tinyvol_cut_solid.part01.rar` … `tinyvol_cut_solid.part04.rar` | RAR5 `-s -m3 -v900b`, same members; the last volume was deleted |

File-version (`-ver`) fixtures:

| Files | Notes |
| --- | --- |
| `file_version__.rar` | RAR5 nonsolid `-m0 -ver`; three revisions of `file.txt` |
| `file_version__rar4.rar` | RAR4 nonsolid `-ma4 -m0 -ver`; same revisions |
| `file_version_solid__.rar` | RAR5 solid `-s -m3 -ver`; `a.txt` history + `b.txt` |

Encrypted / hash fixtures of note:

| Files | Notes |
| --- | --- |
| `encryption__.rar` | RAR5 `-ppassword`; HASHMAC tweaked CRC32 |
| `encryption_solid__.rar` | RAR5 `-s -m3 -ppassword`; solid *and* encrypted, so one `unrar p` pass needs one password for both members |
| `encryption_blake2sp.rar` | RAR5 `-m0 -htb -ppassword`; HASHMAC tweaked BLAKE2sp |
| `blake2sp.rar` | RAR5 `-m0 -htb`; plaintext BLAKE2sp (no encryption) |
| `encryption_stored__.rar` | RAR5 `-m0 -ppassword`; stored *and* encrypted with the default CRC32, so the digest sits in the fixed FILE header and survives damage to the extra area |
| `encryption_stored_sizes__.rar` | RAR5 `-m0 -ppassword`; stored, encrypted members of 0, 7, 16, 3000 and 3001 bytes, which archivey decrypts itself; the ciphertext is padded to whole 16-byte blocks |
| `encryption_large__rar4.rar` | RAR4 `-ma4 -m3 -ppassword`; two 100 000-byte members, past the 64 KiB password-confirm prefix. Some wrong passwords (`wrong3`) decode the whole member with `unrar`, so only the CRC rejects them |
| `encryption_large_solid__rar4.rar` | Same members, `-s`: one password for the solid stream |
| `encryption_large_stored__rar4.rar` | RAR4 `-ma4 -m0 -ppassword`; one stored 100 000-byte member, which every wrong password decrypts to full length |
| `encryption_stored_sizes__rar4.rar` | RAR4 `-ma4 -m0 -ppassword`; the members of `encryption_stored_sizes__.rar`, AES-128 |
| `symlinks_encrypted__rar4.rar` | RAR4 `-ma4 -m3 -ppassword`; the members of `symlinks_solid__rar4.rar` (not solid), with each symlink's target stored and AES-128 encrypted |

Compressed RAR 2.9-4 archive comments (`-z`). `rar` 6.23 compresses a comment that
shrinks into the `CMT` SERVICE header, so the text repeats twenty times; RAR 7 cannot
write RAR4, so the script uses its fetched rar 6.23:

| Files | Notes |
| --- | --- |
| `comment_compressed__rar4.rar` | RAR4 `-ma4 -m3`, members as `comment__.rar`; the ASCII comment is stored as 8-bit text (`CMT` method `0x33`, unicode bit clear) |
| `comment_compressed_unicode__rar4.rar` | Same, `-scfc` and a comment with `é` and `—`: stored as UTF-16LE with `SUBHEAD_FLAGS_CMT_UNICODE` set |

## Tests that still need the `rar` writer at runtime

CI and macOS `setup-dev-env.sh` install **unrar only** — the writer is trialware
(ADR [0016](../../../dev-docs/decisions/0016-committed-rar-corpus-fixtures.md)).
The corpus RAR column and the fixtures in this directory already run without it.

These tests still shell out to `rar a` and **skip** when the writer is absent.
They are the leftover of that decision, not a new gap from dropping the Homebrew
cask. Linux `setup-dev-env.sh` still `apt-get install`s `rar`, so they run on a
provisioned Linux laptop; they do not run on CI.

| Test | Why it still writes |
| --- | --- |
| `test_sfx.py::test_sfx_rar_behind_a_low_entropy_stub_is_not_brotli` | `rar a` for a payload matching `_FILES` |
| `test_sfx.py::test_a_real_sfx_archive_auto_opens` | `rar a -sfx` — a real ~250 KB stub, not a hand-rolled `MZ` |
| `test_sfx.py::test_auto_open_matches_an_explicitly_sliced_stream[rar]` | same payload as the stub test |
| `test_volumes.py::test_multi_volume_rar_real_roundtrip` | live `rar a -v400b`; listing/read of committed volumes is already covered by `tinyvol*` above |
| `test_rar_reader.py::test_listing_qo_skip_count_does_not_scale_with_member_count` | live `rar a -qo+`; skip count must not grow with member count |
| `test_rar_reader.py::test_qo_listing_stored_read_and_comment` | live `rar a -qo+ -z`; stored slice plus archive comment from the QO table |
| `test_rar_reader.py::test_unreadable_qo_falls_back_to_file_walk` | live `rar a -qo+`, then a flipped QO payload byte |
| `test_rar_reader.py::test_qo_listing_matches_file_walk_live` | live `rar a` shapes vs `use_qo=False` FILE walk |
| `test_rar_reader.py::test_qo_listing_matches_file_walk_with_comment` | live `rar a -qo+ -z`; archive comment field parity |
| `test_audit_rar_iso_dir.py::test_file_copy_with_a_special_mode_keeps_its_kind` | live `rar a -oi:1000` for a real file copy; `::test_file_copy_built_from_a_hardlink_record_keeps_its_kind` covers the same shape on CI from `hardlinks_solid__.rar` |
| `test_rar_trailing_data.py::test_zeros_rar_writes_after_a_non_last_volume_are_silent` | live `rar a -v100k`; the committed `tinyvol_hp` set covers the padded case on CI |

Committing a small SFX payload (and a real `-sfx` stub) the way this directory
already does for volumes would close the gap. Tracked internally.

## Many-member listing fixtures

Structural benchmark gate; CI has `unrar` but not `rar`, so these are committed
rather than built on demand:

| Files | Notes |
| --- | --- |
| `many_list_store__.rar` | RAR5 `-m0 -s -ep1`; 1000 tiny `fNNNNN.txt` members |
| `many_list_store_nonsolid__.rar` | RAR5 `-m0 -s- -ep1`; 256 tiny members |

Wildcard member names (`*` / `?` in the stored path). Windows cannot create these
on disk, so they are committed rather than built in the test. Compressed (`-m3`)
so the read takes the named-`unrar` route; stored members never would.

| Files | Notes |
| --- | --- |
| `wildcard_names__.rar` | RAR5 `-m3`; padded so members compress; add-order `subdir/aY.txt` then `a*.txt` / `aX.txt` / `b?.txt` / `b1.txt` / `only*.dat` |
| `wildcard_names_solid__.rar` | RAR5 `-s -m3`; same members and add order |
| `wildcard_names_one_encrypted__.rar` | RAR5 `-m3`; the nonsolid members, plaintext, then `secret.txt` added with `-ppassword` — the archive has encryption though no glob-named member does |
| `wildcard_names__rar4.rar` | RAR4 `-ma4 -m3`; same members as the nonsolid RAR5 |
| `wildcard_dirglob__.rar` | RAR5 `-m3`; `aaa/x.txt`, `dX/x.txt`, `d*/x.txt` — directory-component glob, refused |
| `wildcard_backslash__.rar` | RAR5 `-m3`; `a/b1.txt` readable; `a\b_TGT.txt` and `a\b*.txt` refused (Windows `unrar` treats `\` as a separator) |
| `wildcard_ver__.rar` | RAR5 `-m3 -ver`; `data.bin` two revisions, `data_TARGET`, `data*` — live glob must skip history |

Seek-respawn (named `unrar p` with `seekable_members=True`):

| Files | Notes |
| --- | --- |
| `seek_respawn_solid__.rar` | RAR5 `-s -m3 -ds`; add-order `prefix.bin` (1 MiB repeating) then `tail.txt`. `-ds` keeps that order so the later-member rewind sees a 1 MiB prefix. The prefix also fills the pipe so a mid-stream seek hits a live process |
| `solid_groups__.rar` | RAR5 `-s2 -m3`; `a.txt` … `d.txt` (840 bytes each) in solid groups of two, so `c.txt` starts a second solid stream (solid flag clear). `tests/test_rar_unknown_compression.py` sets `a.txt` to an unknown compression version |

(`-m0` store archives do not set the solid bit even with `-s`; the flags still
match the regeneration commands in `scripts/gen_rar_fixtures.py`.)

Extended timestamps (`-tsmca`: modification, creation, access). Default `rar a`
stores mtime only; these two are the ones that carry `accessed` / `created`.

| Files | Notes |
| --- | --- |
| `xtime__.rar` | RAR5 `-m0 -tsmca`; one `file.txt`; mtime 2020-01-15 12:00:00 UTC, atime 2021-06-20 18:30:00 UTC. ctime is the build machine's inode-change time and is deliberately not pinned; tests assert presence, not value |
| `xtime__rar4.rar` | RAR4 `-ma4 -m0 -tsmca`; same member and pinned mtime/atime; ctime likewise unpinned |

Members MacPaw `unar` 1.10.1 drops (exit 0, no output): a compressed RAR5 member where
a Huffman lookup peeks past the end of its packed data. Built by `_build_unar_drop` with
RAR 7.00; another `rar` build may compress them so `unar` reads them, so rerun
`scripts/find_unar_probe_member.py` (with `--after hello` for the solid one) and check
`unar -o -` after regenerating.

| Files | Notes |
| --- | --- |
| `unar_drop__.rar` | RAR5 `-m3`; the 14-byte `f.txt` (`aaaaabababbabb`) |
| `unar_drop_solid__.rar` | RAR5 `-s -m3`; `a.txt` (`hello`), then the 7-byte `f.txt` (`ababbaa`) |
| `unar_stale_solid__.rar` | RAR5 `-s -m3`; `a.txt` … `e.txt`. One `unar` run drops `c.txt`, writes stale bytes of `d.txt`'s length and drops `e.txt` |
| `unar_stale_nocrc_solid__.rar` | Same, with `c.txt`'s CRC32 removed from its FILE header (header CRC recomputed), so it has no digest |

## Legacy (not regenerated)

| File | Provenance |
| --- | --- |
| `rar15-comment.rar` | Copied from [markokr/rarfile](https://github.com/markokr/rarfile) `test/files/` (ISC) |
| `rar202-comment-nopsw.rar` | Same |

Modern `rar` cannot emit RAR 1.5 / 2.0; keep these as-is.
