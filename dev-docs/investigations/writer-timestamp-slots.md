# Writer timestamp slots — which time ZIP, 7z and TAR writers store as "creation"

**Status:** measured 2026-09-25 on GitHub-hosted runners (`ubuntu-latest`,
`macos-latest` arm64 on macOS 26, `windows-latest` on Windows Server 2025), CI run
[36161789865](https://github.com/archivey-dev/archivey/actions/runs/36161789865); the TAR
rows come from run
[36172269114](https://github.com/archivey-dev/archivey/actions/runs/36172269114). The method
is the script, not the numbers in this page. It settles which ZIP, 7z and TAR readers may
put a stored creation time in `Member.created`.

## Question

`Member.created` holds a birth time or nothing. It never holds `st_ctime`, the Unix
inode change time. ZIP's NTFS extra field (`0x000A`), the third time of ZIP's Extended
Timestamp (`0x5455`), 7z's `CTime` property and libarchive's PAX
`LIBARCHIVE.creationtime` are each documented as a creation time. But Unix has no
portable birth time, so a Unix writer may put `st_ctime` there. The reader must know
which writers do that, and how to recognise their archives.

## Re-run

```bash
uv run python scripts/exploration/probe_writer_timestamps.py
```

The script runs on one OS. The matrix runs in CI with the `Writer timestamp probe`
workflow (`.github/workflows/writer-timestamps.yml`): start it from the Actions tab, or
change the probe in a PR. Each job's summary holds its report, and the archives are
uploaded as artifacts.

Method: the script creates `f.txt`, waits, sets its mtime and atime to 2033 and 2034,
waits, then runs `chmod`. That gives four different source times: birth, ctime (the
chmod, 8 s after birth), mtime and atime. The mtime and atime are in the future on
purpose. On APFS, setting an mtime earlier than the birth time moves the birth time
back to it. Under Linux `relatime`, reading a file whose atime is not newer than its
mtime refreshes the atime. Windows has no inode change time, so there are only three
source times. Each writer archives the file. The script then parses the raw fields and
labels each stored time with the source time it matches (within 1 s).

## Results

"—" means the writer stored no time in that slot. "n/a" means the writer or the
option does not exist there.

### ZIP

| Writer | OS | "version made by" host | NTFS creation | UT third time | archivey |
|---|---|---|---|---|---|
| 7-Zip 23.01 (`7z`, `7za`), default | Linux | 3 Unix | — | — | no time |
| 7-Zip 23.01, `-mtc=on` | Linux | 3 Unix | **ctime** | — | `ctime` |
| 7-Zip 26.03 (`7zz`), default | macOS | 3 Unix | — | — | no time |
| 7-Zip 26.03, `-mtc=on` | macOS | 3 Unix | **ctime** | — | `ctime` |
| p7zip 17.05 (`7z`, `7za`), default | macOS | 3 Unix | **ctime** | — | `ctime` |
| 7-Zip 26.03, default | Windows | 0 FAT | — | — | no time |
| 7-Zip 26.03, `-mtc=on` | Windows | 0 FAT | birth | — | `created` |
| Info-ZIP 3.0 | Linux, macOS | 3 Unix | — | — (flags `0x03`) | no time |
| Info-ZIP 3.0 | Windows | 0 FAT | — | birth, local header only | no time (see below) |
| libarchive 3.7.2 (`bsdtar`) | Linux | 3 Unix | — | **ctime**, central and local | `ctime` |
| libarchive (`/usr/bin/tar`) | macOS | 3 Unix | — | **ctime**, local header only | no time |
| libarchive (`System32\tar.exe`) | Windows | **3 Unix** | — | birth, local header only | no time |
| `ditto -c -k` (Finder "Compress") | macOS | 3 Unix | — | — (`0x5855`: atime, mtime) | no time |
| `Compress-Archive`, PowerShell 5.1 and 7 | Windows | 0 FAT | — | — (DOS time only) | no time |
| Explorer "Compressed folder" (Shell `CopyHere`) | Windows | 0 FAT | — | — (DOS time only) | no time |

p7zip 17.05 rejects `-mtc=on -mta=on` for ZIP (`E_INVALIDARG`), but it already stores
all three NTFS times by default.

### 7z

| Writer | OS | Attributes | `CTime` | archivey |
|---|---|---|---|---|
| 7-Zip 23.01 / 26.03, p7zip 17.05, default | Linux, macOS | `0x81a08020` (Unix mode) | — | no time |
| 7-Zip 23.01 / 26.03, p7zip 17.05, `-mtc=on` | Linux, macOS | `0x81a08020` (Unix mode) | **ctime** | `ctime` |
| 7-Zip 26.03, default | Windows | `0x00000020` | — | no time |
| 7-Zip 26.03, `-mtc=on` | Windows | `0x00000020` | birth | `created` |
| libarchive (`bsdtar --format 7zip`) | Linux, macOS | `0x81a08020` (Unix mode) | **ctime** | `ctime` |
| libarchive (`tar.exe --format 7zip`) | Windows | **`0x81b68020` (Unix mode)** | birth | `ctime` |

### TAR (PAX)

Added in a later run,
[36172269114](https://github.com/archivey-dev/archivey/actions/runs/36172269114), with the
same method. GNU tar is not on the Windows runner.

| Writer | OS | PAX `ctime` | PAX `LIBARCHIVE.creationtime` | archivey |
|---|---|---|---|---|
| libarchive 3.7.2 (`bsdtar --format pax`) | Linux | ctime | — | `ctime` |
| libarchive (`/usr/bin/tar --format pax`) | macOS | ctime | **birth** | `created` and `ctime` |
| libarchive (`System32\tar.exe --format pax`) | Windows | **birth** | birth | `created`, and `ctime` holds the birth time too |
| GNU tar (`--format=pax`) | Linux, macOS | ctime | — | `ctime` |

libarchive writes `LIBARCHIVE.creationtime` wherever it can read a birth time: APFS and
NTFS, but not ext4 on Linux, where libarchive 3.7.2 does not use `statx`. On Windows it
also fills the PAX `ctime` with the birth time, because Windows has no inode change
time.

## Conclusions

1. **The field does not decide the meaning. The writer's OS does.** Every Linux and
   macOS writer that fills a creation slot fills it with `st_ctime`. That holds for the
   NTFS field, the UT third time and 7z `CTime`. Every Windows writer fills the slot
   with the birth time. So a rule based on the field alone, where the NTFS field means
   `created` and the UT third time means ctime, is wrong for 7-Zip on Unix in one
   direction and for Info-ZIP on Windows in the other.
2. **macOS writers store `st_ctime` in the ZIP and 7z slots, not the birth time they
   have.** 7-Zip 26.03, p7zip and libarchive all do this on macOS, although APFS keeps
   a birth time. So host 3 correctly means "not a birth time" for every macOS ZIP and 7z
   writer measured. The exception is libarchive's PAX TAR, which writes the APFS birth
   time as `LIBARCHIVE.creationtime`, beside `st_ctime` in the PAX `ctime`.
3. **The header's host marks the writer's OS, with one exception.** 7-Zip, p7zip and
   Info-ZIP stamp their real OS: host 3 and a Unix mode on Linux and macOS, FAT/`0x20`
   on Windows. libarchive on Windows stamps itself Unix in both formats (host 3 and
   mode `0x81b6`), yet stores the birth time. The reader rule sends it to
   `ctime`. That loses a birth time but never reports `st_ctime` as
   `created`, which is the direction the rule is built to fail in.
4. **Most creation times come from an opt-in.** Current 7-Zip stores no creation time
   in either format unless you pass `-mtc=on`. The Windows built-ins (`Compress-Archive`,
   Explorer) and `ditto` never store one. The one default writer that does is p7zip 17
   (ZIP). A `created` from a ZIP or 7z member is rare in practice. `ctime` is more
   common.
5. **Some creation times live only in the local header.** Info-ZIP on Windows, and
   libarchive on macOS and Windows, write the UT flags `0x07` (or `0x01`) in the
   central directory but keep the third time only in the local header, as the
   Info-ZIP extra-field note allows. archivey lists from the central directory, so it
   does not see those times. For Info-ZIP on Windows that is a birth time that
   `created` misses. Reading local headers during listing costs one seek per member.
   It is not done today.

6. **`ctime` is what the archive stored, not a guarantee.** libarchive on Windows puts
   the birth time in the PAX `ctime`, in the ZIP UT third time and in 7z `CTime`, so its
   members can carry a birth time in `ctime`. `created` never carries `st_ctime`,
   which is the promise the readers keep.

## What the readers do

- **ZIP** (`zip_reader._zip_created`): a creation time from host FAT, OS/2, NTFS or
  VFAT is `created`. From any other host, unknown included, it goes to
  `ctime`. The UT third time wins over NTFS when both are present.
- **TAR** (`tar_reader`): PAX `ctime` is `ctime`; libarchive's
  `LIBARCHIVE.creationtime` is `created`.
- **7z** (`sevenzip_reader._unix_mode`): a Unix file type (`S_IFMT` bits) in
  the attributes' high word marks a Unix writer, so `CTime` goes to
  `ctime`. Otherwise `CTime` is `created`. A special file type counts only with the
  `0x8000` bit, since Windows `STRICTLY_SEQUENTIAL` reads as `S_IFCHR`.

The two outcomes the rule accepts are listed above: libarchive-on-Windows birth times
go to `ctime`, and local-header-only UT times are not read. Neither outcome puts
`st_ctime` in `created`.

## Raw output

The three reports from the run above, exactly as the script printed them. That run
predates `ArchiveMember.ctime`: the "archivey reads" lines show the per-format `extra`
keys (`zip.ctime`, `7z.ctime`) that the field replaced.

### Linux

```text
# Writer timestamp probe on Linux 6.17.0-1022-azure (x86_64)

Source file f.txt:
- birth: 2026-09-25 16:36:57 (birth)
- mtime: 2033-02-03 04:05:06 (mtime)
- atime: 2034-03-04 05:06:07 (atime)
- ctime: 2026-09-25 16:37:05 (ctime)

## 7z zip default
version: 7-Zip 23.01 (x64) : Copyright (c) 1999-2023 Igor Pavlov : 2023-06-20
- member: f.txt
- create_system: 3
- create_version: 63
- external_attr: 0x81a08020
- dos_time: 2033-02-03 04:05:06
- central ntfs.mtime: 2033-02-03 04:05:06 (mtime)
- central ntfs.atime: None
- central ntfs.ctime: None
- archivey reads: {'created': 'None'}

## 7z 7z default
version: 7-Zip 23.01 (x64) : Copyright (c) 1999-2023 Igor Pavlov : 2023-06-20
- member: f.txt
- attributes: 0x81a08020
- unix_mode: 0o100640
- CTime: None
- ATime: None
- MTime: 2033-02-03 04:05:06 (mtime)
- archivey reads: {'created': 'None'}

## 7z zip -mtc=on -mta=on
version: 7-Zip 23.01 (x64) : Copyright (c) 1999-2023 Igor Pavlov : 2023-06-20
- member: f.txt
- create_system: 3
- create_version: 63
- external_attr: 0x81a08020
- dos_time: 2033-02-03 04:05:06
- central ntfs.mtime: 2033-02-03 04:05:06 (mtime)
- central ntfs.atime: 2034-03-04 05:06:07 (atime)
- central ntfs.ctime: 2026-09-25 16:37:05 (ctime)
- archivey reads: {'created': 'None', 'zip.ctime': '2026-09-25 16:37:05.783961+00:00'}

## 7z 7z -mtc=on -mta=on
version: 7-Zip 23.01 (x64) : Copyright (c) 1999-2023 Igor Pavlov : 2023-06-20
- member: f.txt
- attributes: 0x81a08020
- unix_mode: 0o100640
- CTime: 2026-09-25 16:37:05 (ctime)
- ATime: 2034-03-04 05:06:07 (atime)
- MTime: 2033-02-03 04:05:06 (mtime)
- archivey reads: {'created': 'None', '7z.ctime': '2026-09-25 16:37:05.783961+00:00'}

## 7za zip default
version: 7-Zip (a) 23.01 (x64) : Copyright (c) 1999-2023 Igor Pavlov : 2023-06-20
- member: f.txt
- create_system: 3
- create_version: 63
- external_attr: 0x81a08020
- dos_time: 2033-02-03 04:05:06
- central ntfs.mtime: 2033-02-03 04:05:06 (mtime)
- central ntfs.atime: None
- central ntfs.ctime: None
- archivey reads: {'created': 'None'}

## 7za 7z default
version: 7-Zip (a) 23.01 (x64) : Copyright (c) 1999-2023 Igor Pavlov : 2023-06-20
- member: f.txt
- attributes: 0x81a08020
- unix_mode: 0o100640
- CTime: None
- ATime: None
- MTime: 2033-02-03 04:05:06 (mtime)
- archivey reads: {'created': 'None'}

## 7za zip -mtc=on -mta=on
version: 7-Zip (a) 23.01 (x64) : Copyright (c) 1999-2023 Igor Pavlov : 2023-06-20
- member: f.txt
- create_system: 3
- create_version: 63
- external_attr: 0x81a08020
- dos_time: 2033-02-03 04:05:06
- central ntfs.mtime: 2033-02-03 04:05:06 (mtime)
- central ntfs.atime: 2034-03-04 05:06:07 (atime)
- central ntfs.ctime: 2026-09-25 16:37:05 (ctime)
- archivey reads: {'created': 'None', 'zip.ctime': '2026-09-25 16:37:05.783961+00:00'}

## 7za 7z -mtc=on -mta=on
version: 7-Zip (a) 23.01 (x64) : Copyright (c) 1999-2023 Igor Pavlov : 2023-06-20
- member: f.txt
- attributes: 0x81a08020
- unix_mode: 0o100640
- CTime: 2026-09-25 16:37:05 (ctime)
- ATime: 2034-03-04 05:06:07 (atime)
- MTime: 2033-02-03 04:05:06 (mtime)
- archivey reads: {'created': 'None', '7z.ctime': '2026-09-25 16:37:05.783961+00:00'}

## Info-ZIP zip
- member: f.txt
- create_system: 3
- create_version: 30
- external_attr: 0x81a00000
- dos_time: 2033-02-03 04:05:06
- central ut.flags: 0x03
- central ut.mtime: 2033-02-03 04:05:06 (mtime)
- central other extras: 0x7875
- local ut.flags: 0x03
- local ut.mtime: 2033-02-03 04:05:06 (mtime)
- local ut.atime: 2034-03-04 05:06:07 (atime)
- local other extras: 0x7875
- archivey reads: {'created': 'None'}

## bsdtar/libarchive zip
- member: f.txt
- create_system: 3
- create_version: 20
- external_attr: 0x81a00000
- dos_time: 2033-02-03 04:05:06
- central ut.flags: 0x07
- central ut.mtime: 2033-02-03 04:05:06 (mtime)
- central ut.atime: 2034-03-04 05:06:07 (atime)
- central ut.ctime: 2026-09-25 16:37:05 (ctime)
- central other extras: 0x7875
- local ut.flags: 0x07
- local ut.mtime: 2033-02-03 04:05:06 (mtime)
- local ut.atime: 2034-03-04 05:06:07 (atime)
- local ut.ctime: 2026-09-25 16:37:05 (ctime)
- local other extras: 0x7875
- archivey reads: {'created': 'None', 'zip.ctime': '2026-09-25 16:37:05+00:00'}

## bsdtar/libarchive 7zip
- member: f.txt
- attributes: 0x81a08020
- unix_mode: 0o100640
- CTime: 2026-09-25 16:37:05 (ctime)
- ATime: 2034-03-04 05:06:07 (atime)
- MTime: 2033-02-03 04:05:06 (mtime)
- archivey reads: {'created': 'None', '7z.ctime': '2026-09-25 16:37:05.783961+00:00'}
```

### macOS

```text
# Writer timestamp probe on Darwin 25.6.0 (arm64)

Source file f.txt:
- birth: 2026-09-25 16:36:21 (birth)
- mtime: 2033-02-03 04:05:06 (mtime)
- atime: 2034-03-04 05:06:07 (atime)
- ctime: 2026-09-25 16:36:29 (ctime)

## 7zz zip default
version: 7-Zip (z) 26.03 (arm64) : Copyright (c) 1999-2026 Igor Pavlov : 2026-09-03
- member: f.txt
- create_system: 3
- create_version: 63
- external_attr: 0x81a08020
- dos_time: 2033-02-03 04:05:06
- central ntfs.mtime: 2033-02-03 04:05:06 (mtime)
- central ntfs.atime: None
- central ntfs.ctime: None
- archivey reads: {'created': 'None'}

## 7zz 7z default
version: 7-Zip (z) 26.03 (arm64) : Copyright (c) 1999-2026 Igor Pavlov : 2026-09-03
- member: f.txt
- attributes: 0x81a08020
- unix_mode: 0o100640
- CTime: None
- ATime: None
- MTime: 2033-02-03 04:05:06 (mtime)
- archivey reads: {'created': 'None'}

## 7zz zip -mtc=on -mta=on
version: 7-Zip (z) 26.03 (arm64) : Copyright (c) 1999-2026 Igor Pavlov : 2026-09-03
- member: f.txt
- create_system: 3
- create_version: 63
- external_attr: 0x81a08020
- dos_time: 2033-02-03 04:05:06
- central ntfs.mtime: 2033-02-03 04:05:06 (mtime)
- central ntfs.atime: 2034-03-04 05:06:07 (atime)
- central ntfs.ctime: 2026-09-25 16:36:29 (ctime)
- archivey reads: {'created': 'None', 'zip.ctime': '2026-09-25 16:36:29.236391+00:00'}

## 7zz 7z -mtc=on -mta=on
version: 7-Zip (z) 26.03 (arm64) : Copyright (c) 1999-2026 Igor Pavlov : 2026-09-03
- member: f.txt
- attributes: 0x81a08020
- unix_mode: 0o100640
- CTime: 2026-09-25 16:36:29 (ctime)
- ATime: 2034-03-04 05:06:07 (atime)
- MTime: 2033-02-03 04:05:06 (mtime)
- archivey reads: {'created': 'None', '7z.ctime': '2026-09-25 16:36:29.236391+00:00'}

## 7z zip default
version: 7-Zip [64] 17.05 : Copyright (c) 1999-2021 Igor Pavlov : 2017-08-28
- member: f.txt
- create_system: 3
- create_version: 63
- external_attr: 0x81a08020
- dos_time: 2033-02-03 04:05:06
- central ntfs.mtime: 2033-02-03 04:05:06 (mtime)
- central ntfs.atime: 2034-03-04 05:06:07 (atime)
- central ntfs.ctime: 2026-09-25 16:36:29 (ctime)
- archivey reads: {'created': 'None', 'zip.ctime': '2026-09-25 16:36:29+00:00'}

## 7z 7z default
version: 7-Zip [64] 17.05 : Copyright (c) 1999-2021 Igor Pavlov : 2017-08-28
- member: f.txt
- attributes: 0x81a08020
- unix_mode: 0o100640
- CTime: None
- ATime: None
- MTime: 2033-02-03 04:05:06 (mtime)
- archivey reads: {'created': 'None'}

## 7z zip -mtc=on -mta=on
failed: exit 2: System ERROR:
E_INVALIDARG

## 7z 7z -mtc=on -mta=on
version: 7-Zip [64] 17.05 : Copyright (c) 1999-2021 Igor Pavlov : 2017-08-28
- member: f.txt
- attributes: 0x81a08020
- unix_mode: 0o100640
- CTime: 2026-09-25 16:36:29 (ctime)
- ATime: 2034-03-04 05:06:07 (atime)
- MTime: 2033-02-03 04:05:06 (mtime)
- archivey reads: {'created': 'None', '7z.ctime': '2026-09-25 16:36:29+00:00'}

## 7za zip default
version: 7-Zip (a) [64] 17.05 : Copyright (c) 1999-2021 Igor Pavlov : 2017-08-28
- member: f.txt
- create_system: 3
- create_version: 63
- external_attr: 0x81a08020
- dos_time: 2033-02-03 04:05:06
- central ntfs.mtime: 2033-02-03 04:05:06 (mtime)
- central ntfs.atime: 2034-03-04 05:06:07 (atime)
- central ntfs.ctime: 2026-09-25 16:36:29 (ctime)
- archivey reads: {'created': 'None', 'zip.ctime': '2026-09-25 16:36:29+00:00'}

## 7za 7z default
version: 7-Zip (a) [64] 17.05 : Copyright (c) 1999-2021 Igor Pavlov : 2017-08-28
- member: f.txt
- attributes: 0x81a08020
- unix_mode: 0o100640
- CTime: None
- ATime: None
- MTime: 2033-02-03 04:05:06 (mtime)
- archivey reads: {'created': 'None'}

## 7za zip -mtc=on -mta=on
failed: exit 2: System ERROR:
E_INVALIDARG

## 7za 7z -mtc=on -mta=on
version: 7-Zip (a) [64] 17.05 : Copyright (c) 1999-2021 Igor Pavlov : 2017-08-28
- member: f.txt
- attributes: 0x81a08020
- unix_mode: 0o100640
- CTime: 2026-09-25 16:36:29 (ctime)
- ATime: 2034-03-04 05:06:07 (atime)
- MTime: 2033-02-03 04:05:06 (mtime)
- archivey reads: {'created': 'None', '7z.ctime': '2026-09-25 16:36:29+00:00'}

## Info-ZIP zip
- member: f.txt
- create_system: 3
- create_version: 30
- external_attr: 0x81a00000
- dos_time: 2033-02-03 04:05:06
- central ut.flags: 0x03
- central ut.mtime: 2033-02-03 04:05:06 (mtime)
- central other extras: 0x7875
- local ut.flags: 0x03
- local ut.mtime: 2033-02-03 04:05:06 (mtime)
- local ut.atime: 2034-03-04 05:06:07 (atime)
- local other extras: 0x7875
- archivey reads: {'created': 'None'}

## bsdtar/libarchive zip
- member: f.txt
- create_system: 3
- create_version: 20
- external_attr: 0x81a00000
- dos_time: 2033-02-03 04:05:06
- central other extras: 0x7875
- central ut.flags: 0x01
- central ut.mtime: 2033-02-03 04:05:06 (mtime)
- local other extras: 0x7875
- local ut.flags: 0x07
- local ut.mtime: 2033-02-03 04:05:06 (mtime)
- local ut.atime: 2034-03-04 05:06:07 (atime)
- local ut.ctime: 2026-09-25 16:36:29 (ctime)
- archivey reads: {'created': 'None'}

## bsdtar/libarchive 7zip
- member: f.txt
- attributes: 0x81a08020
- unix_mode: 0o100640
- CTime: 2026-09-25 16:36:29 (ctime)
- ATime: 2034-03-04 05:06:07 (atime)
- MTime: 2033-02-03 04:05:06 (mtime)
- archivey reads: {'created': 'None', '7z.ctime': '2026-09-25 16:36:29.236391+00:00'}

## ditto -c -k (Finder Compress)
- member: f.txt
- create_system: 3
- create_version: 21
- external_attr: 0x81a04000
- dos_time: 2033-02-03 04:05:06
- central ux-old.atime: 2034-03-04 05:06:07 (atime)
- central ux-old.mtime: 2033-02-03 04:05:06 (mtime)
- local ux-old.atime: 2034-03-04 05:06:07 (atime)
- local ux-old.mtime: 2033-02-03 04:05:06 (mtime)
- archivey reads: {'created': 'None'}
```

### Windows

```text
# Writer timestamp probe on Windows 2025Server (AMD64)

Source file f.txt:
- birth: 2026-09-25 16:36:31 (birth)
- mtime: 2033-02-03 04:05:06 (mtime)
- atime: 2034-03-04 05:06:07 (atime)
- ctime: -

## 7z zip default
version: 7-Zip 26.03 (x64) : Copyright (c) 1999-2026 Igor Pavlov : 2026-09-03
- member: f.txt
- create_system: 0
- create_version: 63
- external_attr: 0x00000020
- dos_time: 2033-02-03 04:05:06
- central ntfs.mtime: 2033-02-03 04:05:06 (mtime)
- central ntfs.atime: None
- central ntfs.ctime: None
- archivey reads: {'created': 'None'}

## 7z 7z default
version: 7-Zip 26.03 (x64) : Copyright (c) 1999-2026 Igor Pavlov : 2026-09-03
- member: f.txt
- attributes: 0x00000020
- unix_mode: None
- CTime: None
- ATime: None
- MTime: 2033-02-03 04:05:06 (mtime)
- archivey reads: {'created': 'None'}

## 7z zip -mtc=on -mta=on
version: 7-Zip 26.03 (x64) : Copyright (c) 1999-2026 Igor Pavlov : 2026-09-03
- member: f.txt
- create_system: 0
- create_version: 63
- external_attr: 0x00000020
- dos_time: 2033-02-03 04:05:06
- central ntfs.mtime: 2033-02-03 04:05:06 (mtime)
- central ntfs.atime: 2034-03-04 05:06:07 (atime)
- central ntfs.ctime: 2026-09-25 16:36:31 (birth)
- archivey reads: {'created': '2026-09-25 16:36:31.512405+00:00'}

## 7z 7z -mtc=on -mta=on
version: 7-Zip 26.03 (x64) : Copyright (c) 1999-2026 Igor Pavlov : 2026-09-03
- member: f.txt
- attributes: 0x00000020
- unix_mode: None
- CTime: 2026-09-25 16:36:31 (birth)
- ATime: 2034-03-04 05:06:07 (atime)
- MTime: 2033-02-03 04:05:06 (mtime)
- archivey reads: {'created': '2026-09-25 16:36:31.512405+00:00'}

## 7z.exe zip default
version: 7-Zip 26.03 (x64) : Copyright (c) 1999-2026 Igor Pavlov : 2026-09-03
- member: f.txt
- create_system: 0
- create_version: 63
- external_attr: 0x00000020
- dos_time: 2033-02-03 04:05:06
- central ntfs.mtime: 2033-02-03 04:05:06 (mtime)
- central ntfs.atime: None
- central ntfs.ctime: None
- archivey reads: {'created': 'None'}

## 7z.exe 7z default
version: 7-Zip 26.03 (x64) : Copyright (c) 1999-2026 Igor Pavlov : 2026-09-03
- member: f.txt
- attributes: 0x00000020
- unix_mode: None
- CTime: None
- ATime: None
- MTime: 2033-02-03 04:05:06 (mtime)
- archivey reads: {'created': 'None'}

## 7z.exe zip -mtc=on -mta=on
version: 7-Zip 26.03 (x64) : Copyright (c) 1999-2026 Igor Pavlov : 2026-09-03
- member: f.txt
- create_system: 0
- create_version: 63
- external_attr: 0x00000020
- dos_time: 2033-02-03 04:05:06
- central ntfs.mtime: 2033-02-03 04:05:06 (mtime)
- central ntfs.atime: 2034-03-04 05:06:07 (atime)
- central ntfs.ctime: 2026-09-25 16:36:31 (birth)
- archivey reads: {'created': '2026-09-25 16:36:31.512405+00:00'}

## 7z.exe 7z -mtc=on -mta=on
version: 7-Zip 26.03 (x64) : Copyright (c) 1999-2026 Igor Pavlov : 2026-09-03
- member: f.txt
- attributes: 0x00000020
- unix_mode: None
- CTime: 2026-09-25 16:36:31 (birth)
- ATime: 2034-03-04 05:06:07 (atime)
- MTime: 2033-02-03 04:05:06 (mtime)
- archivey reads: {'created': '2026-09-25 16:36:31.512405+00:00'}

## Info-ZIP zip
- member: f.txt
- create_system: 0
- create_version: 30
- external_attr: 0x00000020
- dos_time: 2033-02-03 04:05:06
- central other extras: 0x4453
- central ut.flags: 0x07
- central ut.mtime: 2033-02-03 04:05:06 (mtime)
- local other extras: 0x4453
- local ut.flags: 0x07
- local ut.mtime: 2033-02-03 04:05:06 (mtime)
- local ut.atime: 2034-03-04 05:06:07 (atime)
- local ut.ctime: 2026-09-25 16:36:31 (birth)
- archivey reads: {'created': 'None'}

## bsdtar/libarchive zip
- member: f.txt
- create_system: 3
- create_version: 20
- external_attr: 0x81b60000
- dos_time: 2033-02-03 04:05:06
- central other extras: 0x7875
- central ut.flags: 0x01
- central ut.mtime: 2033-02-03 04:05:06 (mtime)
- local other extras: 0x7875
- local ut.flags: 0x07
- local ut.mtime: 2033-02-03 04:05:06 (mtime)
- local ut.atime: 2034-03-04 05:06:07 (atime)
- local ut.ctime: 2026-09-25 16:36:31 (birth)
- archivey reads: {'created': 'None'}

## bsdtar/libarchive 7zip
- member: f.txt
- attributes: 0x81b68020
- unix_mode: 0o100666
- CTime: 2026-09-25 16:36:31 (birth)
- ATime: 2034-03-04 05:06:07 (atime)
- MTime: 2033-02-03 04:05:06 (mtime)
- archivey reads: {'created': 'None', '7z.ctime': '2026-09-25 16:36:31.512405+00:00'}

## Compress-Archive (powershell)
- member: f.txt
- create_system: 0
- create_version: 20
- external_attr: 0x00000000
- dos_time: 2033-02-03 04:05:06
- archivey reads: {'created': 'None'}

## Compress-Archive (pwsh)
- member: f.txt
- create_system: 0
- create_version: 20
- external_attr: 0x00000000
- dos_time: 2033-02-03 04:05:06
- archivey reads: {'created': 'None'}

## Explorer Shell.Application CopyHere
- member: f.txt
- create_system: 0
- create_version: 20
- external_attr: 0x00000020
- dos_time: 2033-02-03 04:05:06
- archivey reads: {'created': 'None'}
```
