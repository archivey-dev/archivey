# Process isolation overhead

What `process_isolation` and the rapidgzip child cost today. The handbook page that
explains the mechanism is [`topics/process-isolation.md`](../topics/process-isolation.md);
it carries no numbers and links here.

Every figure on this page comes from two committed scripts, run on main at `f347a2a0` on
2026-10-24. To refresh the page, run them again and replace the tables:

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
should match differ by up to about 25% between runs; treat a smaller difference as noise.

## Summary

- **The default isolates only PPMd.** `KNOWN_CRASHES` times the same as `NONE` on every
  gzip, bzip2, xz, zstd, ZIP and LZMA2 row (§1). PPMd pays a fixed cost per decoder, so
  what it adds depends on how many decoders an archive needs: a non-solid 7z needs one per
  member, a solid one a single decoder for the folder.
- **`NATIVE_DECODERS` adds a copy through a pipe** for every byte of output, and a fixed
  cost per decoder (§1). Its relative cost is largest where the decoder itself is fast
  (zstd) or the members are small and many, and smallest for slow decoders (bzip2, xz).
- **A rapidgzip child has a fixed start cost**, about 36 ms on this host for a 1 MiB
  `.gz` (§2). Within one open archive the child is reused, so a further ZIP member pays a
  smaller per-member cost, not the start again. Whether the accelerator pays for a full
  read depends on whether its parallel decode saves more than that start: in these runs it
  did for the 64 MiB `.gz` and the 16 MiB `.bz2` files, and not for 1 MiB of either.
- **A full read of a ZIP or 7z DEFLATE member through rapidgzip pays a second, serial
  zlib decode** for the end check (§3). For the 40 MiB member measured, that decode alone
  took longer than the whole gap between the two reads.
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
| `01M.gz` | 7 | 8 (1.17x) | 14 (1.87x) |
| `16M.gz` | 120 | 146 (1.22x) | 191 (1.59x) |
| `64M.gz` | 454 | 475 (1.05x) | 678 (1.49x) |
| `01M.zst` | 5 | 5 (1.09x) | 9 (2.08x) |
| `16M.zst` | 28 | 28 (1.02x) | 108 (3.90x) |
| `64M.zst` | 111 | 106 (0.95x) | 342 (3.07x) |
| `01M.bz2` | 90 | 112 (1.24x) | 98 (1.08x) |
| `16M.bz2` | 812 | 804 (0.99x) | 950 (1.17x) |
| `01M.xz` | 28 | 32 (1.13x) | 31 (1.08x) |
| `16M.xz` | 345 | 327 (0.95x) | 404 (1.17x) |
| `deflate-1x-8M.zip` | 56 | 54 (0.97x) | 112 (1.98x) |
| `deflate-1024x-8M.zip` | 224 | 229 (1.02x) | 1,096 (4.88x) |
| `lzma2-nonsolid-1024x4K.7z` | 449 | 425 (0.95x) | 1,196 (2.66x) |
| `lzma2-solid-1024x4K.7z` | 151 | 157 (1.03x) | 378 (2.50x) |
| `ppmd-nonsolid-1024x4K.7z` | 1,491 | 2,783 (1.87x) | 2,943 (1.97x) |
| `ppmd-solid-1024x4K.7z` | 1,125 | 1,350 (1.20x) | 1,301 (1.16x) |

The script's derived figures: the extra time of the many-decoder archive over its
one-decoder pair, per extra decoder, and a solid folder's extra time per member read. A
"control" row is a codec the setting leaves in this process, so its figure is the noise.

| setting | ZIP deflate, per decoder | 7z LZMA2, per decoder | 7z PPMd, per decoder | LZMA2 solid, per member | PPMd solid, per member |
|---|---:|---:|---:|---:|---:|
| `KNOWN_CRASHES` | 0.01 ms (control) | -0.03 ms (control) | 1.04 ms | 0.01 ms (control) | 0.22 ms |
| `NATIVE_DECODERS` | 0.80 ms | 0.51 ms | 1.25 ms | 0.22 ms | 0.17 ms |

How to read it:

- **`KNOWN_CRASHES` against `NONE`.** The same within noise on every row but PPMd: the
  default runs nothing else in a child.
- **`NATIVE_DECODERS`, per MiB.** On the `.gz` rows (1 to 64 MiB) the time grows by about
  7 ms per MiB under `NONE` and about 10.5 under `NATIVE_DECODERS`; the difference is the
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
| `01M.gz` | 7 | 9 | 10 | 9 | 43 |
| `16M.gz` | 110 | 115 | 112 | 112 | 96 |
| `64M.gz` | 466 | 455 | 451 | 181 | 195 |
| `01M.bz2` | 48 | 113 | 92 | 90 | 137 |
| `16M.bz2` | 781 | 740 | 813 | 305 | 294 |
| `deflate-1x-32M.zip` | 188 | 237 | 238 | 343 | 358 |
| `deflate-16x-32M.zip` | 215 | 244 | 265 | 231 | 485 |
| `deflate-256x-32M.zip` | 250 | 259 | 269 | 252 | 1,229 |
| `bzip2-1x-16M.zip` | 758 | 767 | 794 | 256 | 273 |
| `1x-32M.tar.gz` | 221 | 249 | 249 | 246 | 247 |
| `1024x-32M.tar.gz` | 262 | 336 | 330 | 683 | 644 |
| `1x-16M.tar.bz2` | 790 | 764 | 850 | 494 | 543 |

The script's derived figures:

| figure | value |
|---|---:|
| One rapidgzip stream beyond the standard library (`01M.gz`, `ON seek` minus `stdlib`) | 36 ms |
| Each further ZIP member under `OFF` (deflate, 1 to 256 members at 32 MiB) | 0.09 ms |
| Each further ZIP member under `ON seek`, one child reused for the archive | 3.42 ms |

How to read it:

- **`AUTO` without seeking is `OFF`.** `AUTO` uses an accelerator only where seeking is
  declared, so a `stream_members()` read never starts a child.
- **`AUTO seek` starts a child only above the size threshold** (16 MiB compressed for
  DEFLATE, 1 MiB for bzip2), so it follows `OFF` below it and `ON seek` above it. Which
  rows cross the threshold depends on how well the data compresses, not on its size.
- **Whether a full read gains from the child** is a trade between the fixed start (and,
  for ZIP, the per-member cost) and the time the parallel decode saves, which grows with
  the size of the data and with the number of cores. In these runs the large `.gz`,
  `.bz2`, `.tar.bz2` and ZIP bzip2 rows gained; the 1 MiB rows and the many-member ZIP
  rows lost; the ZIP DEFLATE member lost for the reason in §3.
- **Not traced.** The `.tar.gz` of 1024 members reads slower with seeking allowed, under
  `AUTO` and `ON` alike, than sequentially. A 1 MiB `.bz2` under `OFF` is slower than the
  standard library with no child involved.

## 3. One large ZIP DEFLATE member, full read

`scripts/bench_accelerator_reads.py`, part 2: one 40 MiB DEFLATE member, opened with
`seekable_members=True`, so `AUTO` reads it through the rapidgzip child.

| measurement | ms |
|---|---:|
| Full read, `AUTO` (rapidgzip child) | 396 |
| Full read, `OFF` (standard-library zlib) | 297 |
| `AUTO`: open and first byte | 90 |
| A plain `zlib` decode of the member's raw data | 263 |

ZIP and 7z set `refuse_input_after_end`, so when rapidgzip's output ends, the parent finds
where the DEFLATE stream ends and whether bytes follow it by decoding the member again
with zlib from offset 0 (`_hands_over_at_end`, then `deflate_resume.stream_end`, in
`zlib_codec.py`). That decode is serial and grows with the member, so it takes about what
the plain zlib row shows; for this member, more than the whole gap between `AUTO` and
`OFF`. `.gz` and `.tar.gz` do not pay it.

## 4. Reads after seeks

`scripts/bench_accelerator_reads.py`, part 3: one DEFLATE member in a ZIP, opened with
`seekable_members=True`, then 20 reads of 64 KiB, each after a seek. The 20 offsets are
spread evenly over the member and visited in three orders: ascending (every seek goes
forward), descending (after the first, every seek goes back), and shuffled. The time
starts after the open and the first byte. `OFF` is the standard library; `ON` forces the
rapidgzip child, which `AUTO` would use only from 16 MiB compressed. Fastest of three, ms.

| member | ascending, `OFF` | ascending, `ON` | descending, `OFF` | descending, `ON` | shuffled, `OFF` | shuffled, `ON` |
|---|---:|---:|---:|---:|---:|---:|
| 4 MiB | 27 | 14 | 254 | 20 | 168 | 29 |
| 16 MiB | 104 | 32 | 1,032 | 43 | 684 | 20 |
| 64 MiB | 425 | 82 | 3,903 | 286 | 2,701 | 160 |

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
