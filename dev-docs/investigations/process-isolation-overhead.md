# Process isolation overhead

What `process_isolation` and the rapidgzip child cost today. The handbook page that
explains the mechanism is [`topics/process-isolation.md`](../topics/process-isolation.md);
it carries no numbers and links here.

Every figure on this page comes from two committed scripts, run on main at `9fc54b31` on
2026-10-27. To refresh the page, run them again and replace the tables:

```bash
uv run --no-sync python scripts/bench_process_isolation.py   # §1
uv run --no-sync python scripts/bench_accelerator_reads.py   # §2 to §4
```

**What the numbers are.** Wall times for the cases named in each table, on one host: a
4-core Xeon 2.1 GHz (KVM), Linux, CPython 3.11.17, rapidgzip 0.16.0. Each case runs in a
fresh interpreter: one warm-up read, then the fastest of three. The payload is random words
and numbers, which gzip compresses about two to one. Other data, other sizes, another
access pattern or another machine give other numbers, so the text below says what each
cost depends on and quotes a figure only with its case. On the 1 MiB rows, columns that
should match differ by a few ms between runs, which is up to about 70% of a 4 ms row;
on the larger rows, by up to about 15%. Treat a smaller difference as noise.

## Summary

- **The default isolates only PPMd.** `KNOWN_CRASHES` times the same as `NONE` on every
  gzip, bzip2, xz, zstd, ZIP and LZMA2 row (§1). PPMd pays a fixed cost per decoder, so
  what it adds depends on how many decoders an archive needs: a non-solid 7z needs one per
  member, a solid one a single decoder for the folder.
- **`NATIVE_DECODERS` adds a copy through a pipe** for every byte of output, and a fixed
  cost per decoder (§1). Its relative cost is largest where the decoder itself is fast
  (zstd) or the members are small and many, and smallest for slow decoders (bzip2, xz).
- **A rapidgzip child has a fixed start cost**, about 35 ms on this host for a 1 MiB
  `.gz` (§2). Within one open archive the child is reused, so a further ZIP member pays a
  smaller per-member cost, not the start again. Whether the accelerator pays for a full
  read depends on whether its parallel decode saves more than that start: in these runs it
  did for the 64 MiB `.gz`, the 32 MiB ZIP member and `.tar.gz`, and the 16 MiB `.bz2`
  files, and not for 1 MiB of either.
- **`AUTO` uses rapidgzip for a large sequential DEFLATE read too**, on Linux and macOS,
  from 16 MiB compressed at 3:1 or less (§2). Below that, and for bzip2, a read without
  declared seeking stays on the standard library.
- **The end check of a ZIP or 7z DEFLATE member decodes only the tail** after rapidgzip's
  newest resume point (§3), so a full read through the child no longer pays a second
  decode of the whole member.
- **After seeks, the gap depends on the seek pattern and the member size** (§4). A seek
  back without the accelerator decodes from the member's start, so it costs more the
  larger the member and the further the target; rapidgzip restarts from its own index.
  Forward-only seeks cost little either way.

## 1. Isolation, accelerators off

`scripts/bench_process_isolation.py`: each archive read in full with `stream_members()`,
`use_rapidgzip` and `use_indexed_bzip2` set to `OFF`. Times in ms, and the ratio to
`NONE`.

| archive | `NONE` | `KNOWN_CRASHES` (default) | `NATIVE_DECODERS` |
|---|---:|---:|---:|
| `01M.gz` | 8 | 9 (1.05x) | 10 (1.22x) |
| `16M.gz` | 109 | 114 (1.05x) | 177 (1.63x) |
| `64M.gz` | 437 | 445 (1.02x) | 616 (1.41x) |
| `01M.zst` | 4 | 7 (1.68x) | 8 (2.01x) |
| `16M.zst` | 26 | 27 (1.01x) | 97 (3.66x) |
| `64M.zst` | 95 | 93 (0.98x) | 295 (3.10x) |
| `01M.bz2` | 87 | 89 (1.02x) | 91 (1.05x) |
| `16M.bz2` | 753 | 742 (0.99x) | 820 (1.09x) |
| `01M.xz` | 23 | 22 (0.98x) | 25 (1.08x) |
| `16M.xz` | 304 | 311 (1.02x) | 384 (1.26x) |
| `deflate-1x-8M.zip` | 55 | 57 (1.03x) | 107 (1.94x) |
| `deflate-1024x-8M.zip` | 219 | 222 (1.01x) | 768 (3.50x) |
| `lzma2-nonsolid-1024x4K.7z` | 418 | 443 (1.06x) | 982 (2.35x) |
| `lzma2-solid-1024x4K.7z` | 135 | 133 (0.98x) | 321 (2.37x) |
| `ppmd-nonsolid-1024x4K.7z` | 1,145 | 2,533 (2.21x) | 2,548 (2.23x) |
| `ppmd-solid-1024x4K.7z` | 992 | 1,242 (1.25x) | 1,282 (1.29x) |

The script's derived figures: the extra time of the many-decoder archive over its
one-decoder pair, per extra decoder, and a solid folder's extra time per member read. A
"control" row is a codec the setting leaves in this process, so its figure is the noise.

| setting | ZIP deflate, per decoder | 7z LZMA2, per decoder | 7z PPMd, per decoder | LZMA2 solid, per member | PPMd solid, per member |
|---|---:|---:|---:|---:|---:|
| `KNOWN_CRASHES` | 0.00 ms (control) | 0.03 ms (control) | 1.11 ms | 0.00 ms (control) | 0.24 ms |
| `NATIVE_DECODERS` | 0.49 ms | 0.37 ms | 1.09 ms | 0.18 ms | 0.28 ms |

How to read it:

- **`KNOWN_CRASHES` against `NONE`.** The same within noise on every row but PPMd: the
  default runs nothing else in a child. (The `01M.zst` gap is 3 ms on a 4 ms row.)
- **`NATIVE_DECODERS`, per MiB.** On the `.gz` rows (1 to 64 MiB) the time grows by about
  7 ms per MiB under `NONE` and about 9.5 under `NATIVE_DECODERS`; the difference is the
  copy. The copy costs about the same per MiB whatever the codec, so the ratio it gives
  depends on how fast the codec decodes on its own: large for zstd, small for bzip2 and xz.
- **Per decoder.** A decoder in a child pays a fixed cost to set up, so the ratio depends on
  the number of decoders as much as on the data: compare the 1-member and 1024-member ZIP
  rows, which hold the same 8 MiB.
- **PPMd** runs in a child under the default and pays its per-decoder cost there. The two
  1024 × 4 KiB archives show the range: one decoder per member when non-solid, one for
  the folder when solid.

## 2. The accelerators, full reads

`scripts/bench_accelerator_reads.py`, part 1: each archive read to the end of every
member under `KNOWN_CRASHES`. `stdlib` is the standard-library module alone; `OFF` sets
both accelerators `OFF`; `AUTO` is the default config. `OFF` and `AUTO` read with
`stream_members()`. `AUTO seek` and `ON seek` open the archive with
`seekable_members=True` and read each member through `open()`; `ON` forces both
accelerators on. Fastest of three, ms.

| archive | stdlib | `OFF` | `AUTO` | `AUTO seek` | `ON seek` |
|---|---:|---:|---:|---:|---:|
| `01M.gz` | 7 | 9 | 9 | 8 | 41 |
| `16M.gz` | 116 | 110 | 126 | 111 | 97 |
| `64M.gz` | 446 | 432 | 189 | 154 | 158 |
| `01M.bz2` | 42 | 91 | 88 | 89 | 132 |
| `16M.bz2` | 711 | 766 | 770 | 281 | 264 |
| `deflate-1x-32M.zip` | 186 | 228 | 147 | 127 | 126 |
| `deflate-16x-32M.zip` | 199 | 218 | 223 | 224 | 411 |
| `deflate-256x-32M.zip` | 213 | 237 | 244 | 242 | 1,020 |
| `bzip2-1x-16M.zip` | 706 | 721 | 743 | 259 | 252 |
| `1x-32M.tar.gz` | 212 | 231 | 131 | 214 | 219 |
| `1024x-32M.tar.gz` | 256 | 328 | 241 | 570 | 610 |
| `1x-16M.tar.bz2` | 740 | 801 | 795 | 456 | 432 |

The script's derived figures:

| figure | value |
|---|---:|
| One rapidgzip stream beyond the standard library (`01M.gz`, `ON seek` minus `stdlib`) | 35 ms |
| Each further ZIP member under `OFF` (deflate, 1 to 256 members at 32 MiB) | 0.04 ms |
| Each further ZIP member under `ON seek`, one child reused for the archive | 3.50 ms |

How to read it:

- **`AUTO` without seeking starts a child only for a large DEFLATE stream that pays**:
  on Linux and macOS, at least 16 MiB compressed and 3:1 or less (gzip.md §2.3). Here
  that is the `64M.gz`, the single 32 MiB ZIP member and both `.tar.gz` rows; every
  other row follows `OFF`. bzip2 has no sequential route.
- **`AUTO seek` starts a child only above the size threshold** (16 MiB compressed for
  DEFLATE, 1 MiB for bzip2), so it follows `OFF` below it and `ON seek` above it. Which
  rows cross the threshold depends on how well the data compresses, not on its size.
- **Whether a full read gains from the child** is a trade between the fixed start (and,
  for ZIP, the per-member cost) and the time the parallel decode saves, which grows with
  the size of the data and with the number of cores. In these runs the large `.gz`,
  `.bz2`, `.tar.bz2`, `.tar.gz`, ZIP bzip2 and single ZIP DEFLATE member rows gained; the
  1 MiB rows and the many-member ZIP rows lost.
- **Not traced.** The `.tar.gz` of 1024 members reads slower with seeking allowed, under
  `AUTO` and `ON` alike, than sequentially, though a sequential `AUTO` read of the same
  file through the child is faster than `OFF`. A 1 MiB `.bz2` under `OFF` is slower than
  the standard library with no child involved.

## 3. One large ZIP DEFLATE member, full read

`scripts/bench_accelerator_reads.py`, part 2: one 40 MiB DEFLATE member, opened with
`seekable_members=True`, so `AUTO` reads it through the rapidgzip child.

| measurement | ms |
|---|---:|
| Full read, `AUTO` (rapidgzip child) | 147 |
| Full read, `OFF` (standard-library zlib) | 278 |
| `AUTO`: open and first byte | 72 |
| A plain `zlib` decode of the member's raw data | 242 |

ZIP and 7z set `refuse_input_after_end`, so when rapidgzip's output ends, the parent
checks where the DEFLATE stream ends and whether bytes follow it (`_hands_over_at_end`,
then `deflate_resume.stream_end`, in `zlib_codec.py`). It decodes with zlib from
rapidgzip's newest resume point, not from offset 0, so the check costs a decode of the
tail, not of the member, and does not grow with the member's size. The plain zlib row is
what a decode of the whole member would cost; the full `AUTO` read takes less than that.

## 4. Reads after seeks

`scripts/bench_accelerator_reads.py`, part 3: one DEFLATE member in a ZIP, opened with
`seekable_members=True`, then 20 reads of 64 KiB, each after a seek. The 20 offsets are
spread evenly over the member and visited in three orders: ascending (every seek goes
forward), descending (after the first, every seek goes back), and shuffled. The time
starts after the open and the first byte. `OFF` is the standard library; `ON` forces the
rapidgzip child, which `AUTO` would use only from 16 MiB compressed. Fastest of three, ms.

| member | ascending, `OFF` | ascending, `ON` | descending, `OFF` | descending, `ON` | shuffled, `OFF` | shuffled, `ON` |
|---|---:|---:|---:|---:|---:|---:|
| 4 MiB | 27 | 12 | 237 | 14 | 155 | 29 |
| 16 MiB | 100 | 26 | 929 | 41 | 597 | 20 |
| 64 MiB | 413 | 73 | 3,796 | 231 | 2,477 | 127 |

How to read it:

- **`OFF` pays for the distance it decodes.** A forward seek decodes from where the stream
  is to the target; a seek back decodes again from the member's start. So ascending order
  costs about one decode of the member, and descending order about one decode per read,
  growing with the member's size. A shuffled order sits between.
- **`ON` restarts from the nearest point of rapidgzip's index**, so a read after any seek
  costs a decode of about one index chunk plus the request through the child. It grows
  far less with the member's size or the order.
- **The ratio between the two is not a property of rapidgzip.** It depends on how far back
  the seeks go, how many there are, how large the member is and how much is read after
  each. A caller who reads a member front to back with a few forward skips sees the
  ascending column; a caller who jumps around a large member sees the other two.
