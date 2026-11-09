# External fixtures

Archives and streams produced by **other** tools, committed because we cannot generate
them here. Everything else in `tests/fixtures/` is built at test time; these exist
because the producer is the point.

## `encoding_infozip_jules.zip`

Info-ZIP output whose member names are valid UTF-8 with general-purpose bit 11 *not* set —
the case `tests/test_zip.py::test_unflagged_utf8_name_is_sniffed` exists for. Neither
stdlib `zipfile` nor `7z` writes this combination.

## `aes_ae1_pyzipper036.zip`

A WinZip **AE-1** member (method 99, extra `0x9901` vendor version 1, AES-256, DEFLATE),
password `secret`, one entry `secret.txt`.

Written with `pyzipper` 0.3.6 on 2026-09-03. AE-1 keeps the plaintext CRC in the headers;
AE-2 zeroes it. No tool on the test image writes AE-1 — `7z -mem=AES256` emits AE-2 — so
without this fixture every AE-1 case in `tests/test_zip_aes.py` would be bytes we
assembled and then read back ourselves.

`pyzipper` is not a dependency, and this is not a hostage to its behaviour: it is a
snapshot of what versions 0.3.0 (2019-02) through 0.3.6 (2022-07) emitted for *every* AES
member regardless of size. 0.3.6 was the only release available until 0.4.0 switched the
default to AE-2 on 2026-05-14, and stdlib `zipfile` writes no encryption at all, so a
Python program emitting an AES ZIP in those four years was almost certainly emitting AE-1.
0.4.0 still emits AE-1 under its opt-in `conditionally_include_crc` for members of at
least 20 bytes.

See [`dev-docs/formats/zip.md`](../../../dev-docs/formats/zip.md) §3.

## `lzma_bpo21872/`

Three real LZMA Alone (`.lzma`) streams from the attachments on CPython's BPO-21872,
"LZMA library sometimes fails to decompress a file" — files that stdlib `lzma` used to
decompress *short* while the `xz` utility read them whole. Committed 2026-09-19.

They are a shape nothing on the test image writes: **the declared uncompressed size is
known and there is no end-of-payload marker**, so a decoder has to stop at the size rather
than at a marker. stdlib `FORMAT_ALONE` always writes the unknown-size marker instead, and
`tests/test_single_file.py::test_lzma_alone_size_from_header_when_known` cannot fill the
gap: it patches the size field into stdlib output, and that contradictory header (size
*and* end marker) is rejected as corrupt by some liblzma builds, so it must not be read
back.

| File | Source attachment | Notes |
| --- | --- | --- |
| `22h_ticks_bad.bi5` | `Archive.zip` (2014-06-25) | The original report's failing file. Dukascopy tick data. Also shipped as `14_22h_ticks.bi5` in `more_bad_lzma_files.zip` — byte-identical. |
| `23h_ticks_good.bi5` | `Archive.zip` (2014-06-25) | The control uploaded beside it: same producer, never failed. |
| `failed_file_01.lzma` | `failed_files_more.zip` (2017-12-24) | A later report, different submitter and three years apart. |

CPython fixed this in 3.7 (PR 14048, the `needs_input` handling in the decompress reader),
so all three decode correctly today — `tests/test_single_file.py::test_bpo21872_lzma_alone_samples_decode_whole`
is a regression pin on our own stream layer, which chunks reads differently from
`lzma.open`, not a live bug hunt. The bug was sensitive to where reads landed relative to
internal buffer boundaries, so the test reads each file at several chunk sizes, 8192
among them.

Only three of the nineteen attached files are committed; the rest are the same shape from
the same two sources.

## `junction/`

Two archives of the same Windows tree, one ZIP and one 7z, both written by **7-Zip
26.03 with `-snl`** (store symbolic links as links) on a `windows-latest` GitHub runner
on 2026-09-21. They exist because an NTFS junction cannot be created on Linux or macOS
at all, so nothing here can produce the shape under test.

The tree is a junction and two symlinks beside the directory they point at:

```cmd
mkdir tree\target
echo hello> tree\target\payload.txt
echo plain> tree\regular.txt
cd tree
mklink /J junction_dir target
mklink /D symlink_dir target
mklink symlink_file target\payload.txt
cd ..
7z a -t7z  junction_7zip_snl.7z  tree\* -snl
7z a -tzip junction_7zip_snl.zip tree\* -snl
```

The symlinks are the control: telling a junction from a directory symlink is the whole
job of `extra["is_junction"]`, so a fixture with only a junction in it could not show
whether detection works or merely guesses.

### What they turned out to contain

**7-Zip stores the reparse data buffer for a *file* reparse point and nothing at all for
a *directory* one.** `symlink_file` carries its full 92-byte buffer, tag
`IO_REPARSE_TAG_SYMLINK`, from which the real target decodes. `junction_dir` and
`symlink_dir` carry the `FILE_ATTRIBUTE_REPARSE_POINT` bit (`0x410` with the directory
bit) and zero bytes of content — no reparse data, and no extra field carrying it
either. The 7z and the ZIP agree entry for entry.

**Without `-snl`, 7-Zip follows every link and records no reparse bit at all.** Measured
on the probe's own `zip_default.zip` and `7z_default.7z` (built by the same job, not
committed): `symlink_file` comes back as an ordinary file, `external_attr` `0x20`, holding
the target's 7 bytes; `junction_dir/` and `symlink_dir/` come back as ordinary directories,
`0x10`, with the target's contents copied in under each. So the reparse bit never appears
on a member whose data is something other than a reparse buffer — the flag and the buffer
arrive together or not at all. That is the fact that bounds how far a reader can trust the
bit: archivey still treats it as a candidate and lets the data decide (see
`dev-docs/formats/zip.md` §2.2.1), because nothing in the format obliges another writer to
be as consistent.

A junction is always a directory reparse point. The reparse tag is the only thing that
separates one from a directory symlink, and it lives in the data that was never
written, so **a junction written by 7-Zip cannot be recognised as one** — by archivey,
or by 7-Zip itself on the way back out. `tests/test_windows_reparse.py` pins that as a
measured fact, so a future 7-Zip that starts storing it will fail the test rather than
pass unnoticed.

The other two tools on a stock Windows box do not get that far, which is why neither is
committed here:

- **bsdtar** (`tar.exe`) follows a junction and archives the target's contents through
  it, while converting Windows symlinks into ordinary Unix symlinks (`create_system` 3,
  mode `0o120666`) that archivey already reads.
- **`Compress-Archive`** follows everything, storing even a file symlink as a regular
  file holding the target's bytes.

See [`dev-docs/formats/zip.md`](../../../dev-docs/formats/zip.md) for how the reader
uses this.

## `rar4_solid_encrypted_libarchive.rar`

libarchive's `test_read_format_rar4_solid_encrypted.rar` (from the `.uu` in
`libarchive/test/`, commit `9dc6678c`, BSD-2-Clause), decoded and committed 2026-09-27.
A solid RAR 2.9 (`-ma4`) archive, `-m3`, of four 18-byte members `a.txt`..`d.txt`
("This is from a.txt" and so on), every one encrypted with the password `password`.
`rar` 7 cannot write RAR4, and it is the only solid RAR3/4 encrypted archive in the
tree.

Under the wrong password `wrong0`, `unrar` 7.00 decodes `a.txt` into 18 garbage bytes
and streams them before its CRC fails (exit 3): the shape
`tests/test_encrypted_member_unverified.py` needs for the solid pass. About one wrong
password in four does that on this member; the rest emit nothing. See
[`dev-docs/formats/rar.md`](../../../dev-docs/formats/rar.md) §2.2.

## `lzop/`

`.lzo` files written by `lzop` 1.04 with LZO library 2.10 (Ubuntu 24.04 package),
committed 2026-10-30, since no tool on the test image writes the format. The inputs are
rebuilt in `tests/test_lzop.py`, each with mtime 2024-03-01 12:00 UTC and mode 0644:

- `text.txt.lzo`: `lzop` (LZO1X-1, Adler-32), 12 000 numbered lines in two blocks.
- `text-9-crc32.txt.lzo`: the same input with `lzop -9 --crc32` (LZO1X-999, CRC-32).
- `random.bin.lzo`: 20 000 random bytes, which lzop stores uncompressed.
- `empty.lzo`: an empty file: a header and the end block.
- `two-files.lzo`: `lzop -c a.txt b.txt`, two lzop files back to back.
- `files.tar.lzo`: a USTAR archive of `dir/one.txt` and `dir/two.txt`.

## `bzip3/`

Four `.bz3` files written by the **`bzip3` 1.4.0** tool (Ubuntu 24.04's `bzip3`
package) on 2026-11-07, with `bzip3 -e -k -c`. No other common tool writes the format.
`tests/test_bzip3.py` reads them beside files the `bzip3` package's `BZ3Compressor`
writes.

| File | Made from | Notes |
| --- | --- | --- |
| `tiny.txt.bz3` | `hi\n` | one literal block (BWT index -1) |
| `empty.txt.bz3` | an empty file | the 9-byte header and no block |
| `lines.txt.bz3` | 30 000 lines `%07d the quick brown fox jumps over the lazy dog\n` | `-b 1`: two blocks, 1 MiB and 511 424 bytes |
| `files.tar.bz3` | a GNU tar of `tiny.txt` and an empty `empty.txt` | 16 MiB block size (the default) |

## `xar_bsdtar/`

Five XAR archives written by **bsdtar 3.7.2** (libarchive) on 2026-11-07, one per
`--options xar:compression=` value: `none.xar`, `gzip.xar`, `bzip2.xar`, `lzma.xar`
and `xz.xar`. Each holds the same tree, every time stamp 2024-03-01 12:00 UTC:

- `b.txt` (mode 0640): 1 500 words drawn from eight, a line of about 8 KB.
- `dir/` and `dir/a.txt` (`hello\n`).
- `link`, a symlink to `dir/a.txt`.
- `hard.txt`, a hard link to `dir/a.txt`. bsdtar keeps the data on `dir/a.txt`
  (`<type link="original">`) and writes `hard.txt` after it.
- a file whose name on disk was `caf\xe9.txt`. bsdtar could not convert the byte to
  UTF-8, wrote U+FFFD in its place and stored the name base64-encoded
  (`<name enctype="base64">`), so it reads back as `caf�.txt`.

Made with `bsdtar --format xar --options xar:compression=<c> -cf <c>.xar b.txt dir link
hard.txt 'caf'$'\xe9''.txt'`. 7-Zip cannot list them. `tests/test_xar.py` reads them
beside the archives `tests/xar_util.py` writes.

## `cab_libarchive/`

Four cabinets written by Microsoft's **`makecab.exe`**, copied from libarchive's test
suite (`libarchive/test/test_read_format_cab_*.cab.uu`, decoded; libarchive is
BSD-2-Clause) on 2026-11-07. No tool on the test image writes LZX, and the other two
show what Microsoft's own writer does with stored and MSZIP folders, so
`tests/test_cab.py` reads them beside the cabinets `tests/cab_util.py` writes.

| File | Folder | Notes |
| --- | --- | --- |
| `test_read_format_cab_1.cab` | stored | `empty`, `dir1/file1`, `dir2/file2` |
| `test_read_format_cab_2.cab` | MSZIP | the same, and `zero` (33 000 zero bytes, two blocks) |
| `test_read_format_cab_3.cab` | LZX | as `_2` |
| `test_read_format_cab_filename_cp932.cab` | MSZIP | two names in cp932 (`表だよ/漢字.txt`, `表だよ/一覧表.txt`) |

How they were made is in libarchive's `test_read_format_cab.c` (`mkcab1` to `mkcab3`).

## `lha_lhasa/`

Twenty-two LHA archives from lhasa's test suite (`test/archives/<tool>/<file>`, renamed
`<tool>_<file>`; lhasa commit `75ed835`, v0.6.0), copied on 2026-11-09. Each was written
by the tool its directory names, most on the system it ran on; no tool on the test image
writes LHA, so `tests/test_lha.py` reads them beside the archives `tests/lha_util.py`
writes. Their expected bytes are what lhasa 0.4.0 extracts.

| Tool | Files | What they hold |
| --- | --- | --- |
| LHa for UNIX 1.14i | `lha_unix114i_*` | `-lh5-` level 0, `-lh6-` level 1, `-lh7-` level 2; symlinks; directories with Unix modes |
| LHA for OS/2 2.08 | `lha_os2_208_*` | level 3, `-lh5-` and directories |
| UNLHA32.DLL 2.67a | `unlha32_h2_lhx.lzh` | `-lhx-` |
| LHARK-A 0.4d | `lhark04d_lh7.lzh` | LHARK's `-lh7-`, read as `-lk7-` |
| LArc 3.33 | `larc333_lz4.lzs` | `-lz4-` (stored) |
| PMARC2 (MSX-DOS) | `pmarc2_pm0.pma` | `-pm0-` (stored), no time |
| LhA 1.22 (Amiga) | `lha_amiga_122_*` | `-lh4-`, `-lh1-`, a file in subdirectories |
| LHarc 1.13 | `lharc113_lh1.lzh` | `-lh1-` |
| LArc 3.33 | `larc333_lz5.lzs`, `larc333_initial.lzs` | `-lz5-`; one crafted to copy the whole starting ring (`initial.bin`), with no end byte |
| By hand (lhasa's `lz5-to-lzs` script) | `generated_lzs.lzs` | `-lzs-`, with no end byte |
| OS-9/68k LHA 2.01 | `lha_osk_201_h2_lh0.lzh` | the level-2 header two bytes longer than its size; OS-9 permissions |
| MorphOS LhA 2.7.17 | `morphos_lha_2717_h2_metadata.lzh` | a `0x71` comment record, skipped |
| LH/2 2.22 (OS/2) | `lh2_222_eas.lzh` | mixed levels 0 and 1, OS/2 extended attributes as a file |

lhasa is under the ISC license:

> Copyright (c) 2011-2025, Simon Howard
>
> Permission to use, copy, modify, and/or distribute this software for any purpose with
> or without fee is hereby granted, provided that the above copyright notice and this
> permission notice appear in all copies.
>
> THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES WITH REGARD
> TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS. IN NO
> EVENT SHALL THE AUTHOR BE LIABLE FOR ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL
> DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER
> IN AN ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF OR IN
> CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
