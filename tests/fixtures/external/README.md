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
