# Capability declaration vs behaviour — measured

**Status:** living measurement, not a fix. First run 2026-09-05 on
`0c0a71c`; this file tracks the re-run on 2026-09-17 (`origin/main` plus
this PR). The method is the script, not the numbers in this page.

**Note (2026-09-26):** `reader.member_streams` no longer exists — the property was
removed at the 0.2.0 API freeze along with `MemberStreams` leaving the public surface.
The snippets below that read it are as run on 2026-09-17; the script now reads the
reader's private `_member_streams` field, and the "UNTYPED" finding about the attribute
being off the ABC is moot (there is no attribute).

**Note (2026-09-26, `stream_members()` never seeks):** a `stream_members()` handle is
now forward-only on every format, with or without `seekable_members=True`
(`archive-reading` spec). The `stream_members_seekable` check enforces that: a pass
handle that reports `seekable() True` or accepts `seek(0)` is `DELIVERED-NOT-DECLARED`.
It used to record the flag and return `OK` whatever it saw. The snapshot was
regenerated on 2026-09-26 and also takes in verdicts that had already moved on
`main`: zip-aes `seekable_opt_in` is `OK` on all three rows (WinZip AES members seek
since #480), and the single-file `listing_cost` rows other than gz are `OK`
(listing now records `seeks=1 decomp=1`). The tables and the "Violations"
section below are still the 2026-09-17 run; read the JSON for current verdicts.

**Note (2026-10-17):** `concurrent_members=True` was renamed `concurrent_operations=True`.
The predicates below and the script use the new name; the 2026-09-17 run used the old one.

## Re-run

```bash
uv run --no-sync python scripts/investigations/exploration/capability_declaration_sweep.py
uv run --no-sync python scripts/investigations/exploration/capability_declaration_sweep.py --compare
```

`--compare` diffs **verdicts** against
[`capability-declaration-vs-behaviour.json`](capability-declaration-vs-behaviour.json).
Seek-count drift prints as `NUMERIC` and is not a failure. After a real
behaviour change, update this page, then:

```bash
uv run --no-sync python scripts/investigations/exploration/capability_declaration_sweep.py --write-snapshot
```

The script draws rows from `tests.sample_archives.CORPUS` /
`corpus_archive_path` / `skip_unless_runnable`. New `FORMAT_KEYS` and the
`encrypted*` / `large` / `compressed` / `sevenzip-stored` extras are picked
up without editing an enrolment list. A skip is `UNTESTED`, never `OK`.
Registry formats with no corpus key are `UNTESTED-NO-CORPUS`.

Five rows **must run** (`REQUIRED_RAN` in the script): `encrypted`/`encrypted-mixed`
rar, `compressed` rar, and `encrypted`/`encrypted-mixed` zip-aes. A skip or a
stored-only `compressed` rar exits non-zero and refuses `--write-snapshot`.
That is the 2026-09-05 blind spot: `basic`/`large` rar are STORED and never
reach unrar. Packed `compressed` exists now; encryption is still required
because it is a different unrar path. The script does not xfail holes.

Triggered by `dev-docs/formats/rar.md`: `seekable_members=True` on RAR,
`reader.member_streams` reported `SEEKABLE`, the member stream was a pipe.
That is one field. The sweep asks how many others lie the same way.

## This run

| Thing | Value |
| --- | --- |
| Date | 2026-09-17 |
| Tree | `bf2f52db55b3` (this branch, rebased on `origin/main`) |
| Python | 3.11.16 |
| `rar` | RAR 7.00 trial |
| `unrar` | UNRAR 7.00 freeware |
| `7z` | 7-Zip 23.01 |
| `zip` | Info-ZIP |
| `skip_unless_runnable` | nothing skipped (42 corpus rows) |

## What moved since 2026-09-05

The first run is not the current state. Between `0c0a71c` and this rebase:

- `MemberStreams.SEEKABLE` is now a **guarantee**, not a request mask
  (`types.py`). It covers `open()` only; since 2026-09-26 a
  `stream_members()` yield never seeks (see the note at the top).
- `#299` enrolled the corpus in `tests/test_member_stream_contract.py`,
  including RAR / encrypted 7z / zip-aes. WinZip AES members are
  `xfail(strict=True, reason="decrypting stream wrapper does not seek")`.
- `#342` made encrypted 7z members seek (AES-CBC restart). The 2026-09-05
  7z SEEKABLE failures are gone.
- Corpus gained `compressed` (RAR, actually packed) and `sevenzip-stored`.
  The first run’s “corpus rar is stored, so basic looks fine” trap has a
  packed row now; it seeks.

Still true: zip-aes `open()` streams under `seekable_members=True` report
`seekable() is False`. Encrypted RAR and packed RAR no longer do.

## Predicates (in the script)

**A. `reader.member_streams`** (concrete reader; still not on `ArchiveReader`)

- `seekable_members=True` → every FILE from `open()` has `seekable() is True`
  and backward / mid-stream seek rereads the same bytes. Per-member
  disagreement inside one archive is a fail even if some members pass.
- `concurrent_operations=True` → two overlapping `open()` calls both read.
- Default → `seekable()` is False and `seek()` raises; a second live
  `open()` raises `ConcurrentAccessError`.
- `stream_members()` under `seekable_members=True` → every FILE handle has
  `seekable() is False` and `seek(0)` raises (2026-09-26 rule; before, it was
  recorded, not required).

**B. `reader.cost` vs `reader.io_stats()`** (fresh open, `enable_measurement`,
listing before any payload `open()`)

- `INDEXED` + `source_seek_count == 0` → `MEASUREMENT-HOLE`, not a pass.
- `REQUIRES_DECOMPRESSION` + listing `bytes_decompressed == 0` and
  `consumed in (0, None)` → hole.
- `REQUIRES_SCANNING` + seeks == 0 → hole (directory walk is not a seek).
- `DIRECT` last-member Δdecomp ≥ total payload on a multi-file archive → lie.
- `SOLID` last-member Δdecomp ≈ last size only → hole (the wrap counted the
  opened member, not skipped prefix). 7z folder decode showing Δdecomp =
  total is a real confirmation.

**C. `reader.info`**

- `member_count is int` → equals `len(list(members()))`. `None` is allowed
  (tar / dir / iso still return `None` at open, and still after listing).
- `is_solid` agrees with `access_cost is SOLID`.
- `is_encrypted` is header-level per the docstring, not per-member.
- `is_multivolume` False on this corpus (no multi-volume row).

**D. Lifetime** — after `reader.close()`, `read` on a stream from `open()` or
`stream_members()` raises. Default and `seekable_members=True`.

Verdicts: `OK` / `DECLARED-NOT-DELIVERED` / `DELIVERED-NOT-DECLARED` /
`UNTESTED` / `UNTESTED-NO-CORPUS` / `MEASUREMENT-HOLE` / `ERROR`.

## Registry formats with no corpus key

`UNTESTED-NO-CORPUS`, not passing. All `FormatSupport.FULL` here.

| Format | Extension |
| --- | --- |
| `ArchiveFormat.LZMA_ALONE` | `lzma` |
| `ArchiveFormat.Z` | `Z` |
| TAR + LZMA_ALONE | `tar.lzma` |
| TAR + UNIX_COMPRESS | `tar.Z` |

## Matrix — member streams (this run)

Default second-open and non-seekable held on every row. Concurrent overlapping
`open()` held on every row. No `DELIVERED-NOT-DECLARED` on the stream flags.
Lifetime held on all 42 rows.

`SEEKABLE` (opt-in `open()`):

| Format | Entry | Verdict |
| --- | --- | --- |
| zip (store / deflate / ZipCrypto) | basic, large, encrypted* | OK |
| tar, tar.* | basic (+ large tar.gz / tar.zst) | OK |
| dir, iso, iso-joliet | basic | OK |
| 7z | basic, large, sevenzip-stored, encrypted, mixed, header | OK |
| rar | basic, large, compressed, encrypted, mixed | OK |
| single-file* | single-file / gz-meta | OK |
| zip-aes | encrypted | **DECLARED-NOT-DELIVERED** (both members False) |
| zip-aes | encrypted-mixed, encrypted-multi | **DECLARED-NOT-DELIVERED** (plaintext True, AES False) |

`reader.member_streams` still has the SEEKABLE bit on the failing zip-aes
rows. `_wrap_member_stream` is still `declared ∧ is_seekable(inner)`. The
WinZip AES decrypt wrapper is the inner that is not seekable. ZipCrypto
uses a decryptor that is.

`stream_members()` under the same flag, as run on 2026-09-17: zip-aes AES
members reported `seekable() True` on the sequential yield and encrypted 7z
reported False, because nothing then required either. Since 2026-09-26 every
pass handle reports False, on every row, and the check fails on a True.

## Matrix — cost / info (numbers from this run)

Listing after `open` + `members()`, no payload. `consumed` is
`compressed_bytes_consumed`.

| Format | Entry | listing | seeks | access | last Δdecomp / last / total | is_encrypted | member_count |
| --- | --- | --- | --- | --- | --- | --- | --- |
| zip | basic | INDEXED | 7 | DIRECT | 12 / 12 / 41 | F | 6=6 |
| zip | large | INDEXED | 7 | DIRECT | 64014 / 64014 / 192042 | F | 3=3 |
| zip, zip-aes | encrypted* | INDEXED | 7 | DIRECT | ≈ last | **F** (members True) | match |
| 7z | basic | INDEXED | 4 | SOLID | **41 / 16 / 41** | F | 7=7 |
| 7z | large | INDEXED | 4 | SOLID | **192042 / 64014 / 192042** | F | 3=3 |
| 7z | encrypted, mixed | INDEXED | 4 | SOLID | Δdecomp = total | **T** (folder, not header) | match |
| 7z | encrypted-header | INDEXED | 4 | SOLID | Δdecomp = total | T (header) | match |
| rar | basic | INDEXED | **0** | DIRECT | 12 / 12 / 41 | F | 6=6 |
| rar | compressed | INDEXED | **0** | DIRECT | 8400 / 8400 / 16592 | F | 2=2 |
| rar | encrypted, mixed | INDEXED | **0** | DIRECT | ≈ last | **T** (per-member only) | match |
| tar | basic | REQUIRES_SCANNING | 3 | DIRECT | 12 / 12 / 41 | F | **None** (listed 6) |
| tar.gz etc | basic | REQUIRES_DECOMPRESSION | **0** | SOLID | 12 / 12 / 41 | F | **None** (listed 6) |
| dir | basic | REQUIRES_SCANNING | **0** | DIRECT | 16 / 16 / 41 | F | **None** (listed 7) |
| iso | basic | INDEXED | 28 | DIRECT | 16 / 16 / 41 | F | **None** (listed 7) |
| iso-joliet | basic | INDEXED | 25 | DIRECT | 16 / 16 / 41 | F | None |
| single-file gz | single-file | INDEXED | 1 | DIRECT | ≈ size | F | 1=1 |

`is_multivolume` False on every row. Source Path is SEEKABLE on every row.
Pipe + `streaming=True`: tar* and single-file → `FORWARD_ONLY`; zip / 7z /
rar / iso raise `StreamNotSeekableError` (no `CostReceipt`). Directory is
not piped.

Cost verdicts worth a name:

| Claim | Format | Verdict |
| --- | --- | --- |
| INDEXED (seeks not ∝ N) | zip, 7z | OK (zip 7 seeks on 3 and 6 members; 7z 4 seeks on 1, 3, 7) |
| INDEXED | iso / iso-joliet | OK against the enum’s own example; 25–28 seeks on a 7-member image is a tree walk. `member_count` stays None after listing. |
| INDEXED | rar | **MEASUREMENT-HOLE** (`source_seek_count=0`). The enum docstring already admits RAR walks every header at open. Unfalsifiable here. |
| REQUIRES_DECOMPRESSION | compressed tar | **MEASUREMENT-HOLE**. Path to the codec; `consumed=None`; listing `bytes_decompressed` stays 0. |
| REQUIRES_SCANNING | dir | **MEASUREMENT-HOLE** (`os.walk` is not a seek). |
| SOLID last-member | 7z | OK (`Δdecomp = total`) |
| SOLID last-member | compressed tar | **MEASUREMENT-HOLE** (`Δdecomp ≈ last size`) |
| `is_encrypted` header-only | zip / zip-aes | OK (archive False, members True) |
| `is_encrypted` header-only | 7z encrypted (no `-mhe`) | docstring vs code: True because `has_encrypted_folders` |
| `is_encrypted` header-only | rar encrypted / mixed | docstring vs code: True because `any(m.is_encrypted)` |
| `is_encrypted` header-only | 7z encrypted-header | OK (True) |

## Violations

### 1. SEEKABLE declared, zip-aes inner is not seekable — DECLARED-NOT-DELIVERED

The only remaining SEEKABLE lie on this corpus. Already pinned:
`test_corpus_seekable_members_seek_and_reread` xfails the password-bearing
zip-aes members (`strict=True`). Mixed / multi still disagree inside one
archive (`plain.txt` / `not_secret.txt` True, AES members False).

**Minimal repro:**

```bash
cd /workspace && uv run --no-sync python -c '
from pathlib import Path
import tempfile
from archivey import open_archive
from tests.sample_archives import CORPUS, corpus_archive_path
e = next(x for x in CORPUS if x.id == "encrypted-mixed")
p = corpus_archive_path(e, "zip-aes", Path(tempfile.mkdtemp()))
with open_archive(p, password=e.passwords, seekable_members=True) as r:
    print("declared", r.member_streams)
    for m in r.members():
        if not m.is_file: continue
        f = r.open(m)
        print(m.name, "enc", m.is_encrypted, "seekable", f.seekable())
        f.close()
'
```

Encrypted RAR / packed RAR / encrypted 7z: same shape now prints all True.

### 2. `ArchiveInfo.is_encrypted` vs its docstring — still a conflict

Docstring: "Header-level encryption (7z, RAR5) — not per-member encryption".

| Row | Archive `is_encrypted` | What is actually encrypted |
| --- | --- | --- |
| zip / zip-aes encrypted* | False | per-member only — matches docstring |
| 7z encrypted-header | True | header (`-mhe`) — matches |
| 7z encrypted / mixed | True | folders; not header. Code: `is_header_encrypted or has_encrypted_folders` |
| rar encrypted / mixed | True | per-member passwords. Code: `has_header_encryption or any(m.is_encrypted)` |

**Minimal repro:**

```bash
cd /workspace && uv run --no-sync python -c '
from pathlib import Path
import tempfile
from archivey import open_archive
from tests.sample_archives import CORPUS, corpus_archive_path
e = next(x for x in CORPUS if x.id == "encrypted")
for key in ("zip", "rar", "7z"):
    p = corpus_archive_path(e, key, Path(tempfile.mkdtemp())/key)
    with open_archive(p, password=list(e.passwords)) as r:
        print(key, "archive", r.info.is_encrypted,
              "members", [m.name for m in r.members() if m.is_encrypted])
'
```

Output here: `zip archive False`; `rar archive True`; `7z archive True`.

### 3. MEASUREMENT-HOLE — `io_stats` still cannot see some of the work

`enable_measurement()` was on. `io_stats` was never `None`. The holes are
zeros that do not mean "no work":

- **RAR listing INDEXED:** `source_seek_count=0` on stored, packed, and
  encrypted rows. Cannot check the handbook’s "41 seeks on 40 members".
- **dir REQUIRES_SCANNING:** seeks=0.
- **compressed tar REQUIRES_DECOMPRESSION / SOLID:** listing decomp=0,
  `consumed=None`. Last-member Δdecomp equals last size.
- **`compressed_bytes_consumed`:** `None` on every Path open. Documented.
  Useless for these predicates on `open_archive(path)`.
- **single-file bz2/xz/zst/lz4/lz/zz/br listing:** INDEXED with seeks=0
  (gz is 1). Same Path-without-wrap hole; N=1 so it is not a header walk.

### 4. UNTYPED / UNDECLARED

- **`member_streams` is not on `ArchiveReader`.** `dir(ArchiveReader)` has
  `cost`, `info`, `stream_members`, not `member_streams`. The type’s own
  docstring still says it is reachable at runtime but not part of the typed
  public contract. Callers who branch on it are using an untyped field.
  After `#299` the field is a guarantee for `open()`, not a request mask —
  but only if you can see it.
- **No per-member stream capability.** zip-aes mixed still disagrees
  member-by-member with no diagnostic. The archive-level flag cannot be
  true when stored and piped members share one reader.
- **`stream_members()` vs `open()` seekability** is settled as of 2026-09-26:
  a pass handle never seeks, and only `open()` under `seekable_members=True`
  does.

No `DELIVERED-NOT-DECLARED` hits. No `ERROR`. No skipped corpus rows.

## xfail now vs needs a decision

**Already pinned** (`xfail(strict=True)` in
`test_corpus_seekable_members_seek_and_reread`,
`tests/test_member_stream_contract.py:240`): zip-aes decrypt-wrapper
members. Strict so the day the wrapper seeks, the xfail burns. Do not add
a second pin in this sweep; the contract suite is the tripwire.

**Do not pin again (closed on this tree):** RAR-via-unrar SEEKABLE,
encrypted 7z SEEKABLE. The 2026-09-05 recommendation to xfail those rows
landed as real tests, not xfails, and they pass.

**Do not xfail the measurement holes.** An xfail there would assert
behaviour nobody measured:

- RAR listing `source_seek_count=0`
- dir listing seeks
- compressed-tar listing (`REQUIRES_DECOMPRESSION` with decomp=0 /
  `consumed=None`)
- `compressed_bytes_consumed` always `None` on a Path open

**Decision first** (either side is a coherent product):

- **`is_encrypted` on the archive.** Keep the docstring (header only: zip
  is the model, RAR/7z folder-or-member bits are wrong) or keep the code
  (any encryption: rewrite the docstring). Do not xfail until that is
  picked.
- **RAR `listing_cost=INDEXED`.** The enum docstring already special-cases
  it. Either leave that or move RAR to `REQUIRES_SCANNING`. Measurement
  cannot settle it until seeks (or bytes read) are visible.
- **ISO `INDEXED` + `member_count=None` + 28 seeks.** Internally consistent
  with "tree lives in the header region" / "counting requires a walk".
  Only a problem if INDEXED is supposed to mean ZIP-like O(1) central
  directory.

## What callers already rely on with no capability field

- Branching on `reader.member_streams` (untyped).
- "This member’s stream is a pipe vs a slice" — only discoverable by
  `seekable()` after `open()`.
- ZipCrypto vs AES on ZIP (same `ArchiveFormat.ZIP`, different stream
  reality). Still the live split.
- Solid open-order cost vs `CONCURRENT` (orthogonal; this run did not
  contradict it).

## Counts (this run, 42 rows × checks)

| Kind | Count (distinct issues, not cells) |
| --- | --- |
| DECLARED-NOT-DELIVERED | 2 (zip-aes SEEKABLE; `is_encrypted` vs header-only docstring) |
| DELIVERED-NOT-DECLARED | 0 |
| MEASUREMENT-HOLE | RAR listing seeks; dir listing; compressed-tar listing/SOLID; Path `consumed=None`; most single-file listing seeks |
| UNTYPED | 2 (`member_streams` off the ABC; no per-member stream cap) |
| UNTESTED-NO-CORPUS | 4 (`lzma`, `Z`, `tar.lzma`, `tar.Z`) |
| UNTESTED (skip) | 0 |
| ERROR | 0 |

SEEKABLE DECLARED-NOT-DELIVERED **cells**: 3 (`encrypted` / `encrypted-mixed`
/ `encrypted-multi` zip-aes). Down from 8 on 2026-09-05.

`is_encrypted` DECLARED-NOT-DELIVERED **cells**: 4 (`encrypted`/`encrypted-mixed`
× rar/7z). Header-encrypted 7z is OK.

## 2026-09-05 run (superseded numbers)

On `0c0a71c`, corpus rar `basic`/`large` were stored and sought; encrypted
RAR and zip-aes and encrypted 7z did not. The handbook `tplain.rar`
failure was compressed non-solid, which the corpus did not then include.
That run also counted 8 SEEKABLE failing rows and called RAR INDEXED a
hole. The method lived in `/tmp` and died with the session. Use the script
above, not that dump.
