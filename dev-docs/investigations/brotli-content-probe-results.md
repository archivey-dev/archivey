# Brotli content probe — investigation results

**Brief:** `dev-docs/investigations/brotli-content-probe-brief.md` (lands with PR #254)
**Registered as:** `dev-docs/threat-model.md` O10 (from #254)
**Date:** 2026-08-19
**Status:** complete. No production code changed — the brief asks for findings plus, if
warranted, an OpenSpec proposal. A proposal is warranted; §7 says what it should contain.

**Environment.** `main` @ `d43375f`, CPython 3.11.15, `Brotli` 1.2.0 (the C extension),
glibc 2.39, Linux 6.18.5. Measurement scripts are reproduced inline in §8; every number
below was produced by them in this environment.

---

## TL;DR

The ~8% is **not** decoder looseness or a tuning failure. It is one specific,
fully-explained feature of RFC 7932: **a non-last *uncompressed* meta-block**. Its header
is four bytes with only ~15 constrained bits, and everything after it is literal output.
Roughly 6.4% of random data parses as one, and the decoder then happily copies bytes until
the bounded prefix runs out. A metadata meta-block (declared skip length, no output) adds
most of the rest. Analytic prediction **8.10%**, measured **8.16%** — the model is closed.

Three consequences, each measured:

1. **Probe tuning cannot work, and now there is a reason why.** Both accepting paths
   declare a length and emit no evidence; a bigger prefix just gets more literal bytes
   copied, and demanding output is the same test the uncompressed path already passes.
2. **The information the probe is missing is the file size.** Both paths declare a byte
   count that a complete valid file *must* physically contain. Checking the declaration
   against the file cuts random-data false positives **25×** (4 KiB files) with **zero**
   false negatives on 150 real streams — 56 of which take the uncompressed path themselves.
   Following the declared chain across meta-blocks does better still, and is the only
   variant that helps files ≥ 16 MiB.
3. **The impact is narrower than P12/O10 record, but the *reach* is wider.** Across 364
   false positives, **not one** ended in a silent success: the listing is wrong, and a full
   read always raises. But two qualifications matter (§5.1). It is not confined to
   high-entropy blobs — **3.5% of 39 859 files under `/usr`** are claimed, dominated by the
   Doxygen opener `/**\n`, and `/usr/include/lzma.h` detects as `BROTLI`. And "the read
   raises" is about the *terminal exception*: a read can hand back **65 536 bytes** of
   fabricated output — verbatim slices of the input — before the error arrives, so a caller
   streaming to disk has already written garbage. The genuinely silent case still needs
   crafted input, and crafted input really is valid Brotli, so no probe can refuse it (§3).

Also settled: **`MZ` is a legal Brotli stream prefix** — §3 builds one and round-trips it
through the reference decoder. But **`MZ` followed by a *valid DOS header* is not**, and
provably so (§3.1): a valid `e_cblp` is arithmetically disjoint from what Brotli's MLEN
encoding requires at those byte positions. Real PE files are already rejected — **0/100**,
across four toolchains and every `MZ` file on this machine — and the `MZ` + `\x90`×4094
fixture is accepted only because its filler is *not* what a DOS header looks like. That
explains why #254's cue split is safe, but it does **not** justify loosening the STRONG
test to `e_cblp` — a Linux EFI kernel image breaks every DOS-field rule and only the
existing `e_lfanew` test survives (§3.1, §7). §7 measures
today's `e_lfanew` → `PE\0\0` rule at ~2⁻⁵² against `e_cblp`'s 2⁻⁷. **`\x7fELF` is likewise
impossible**, deterministically — one of **54 first bytes that can never begin a valid
Brotli stream**. And the peer probes are clean: zlib and LZMA Alone take **0/20 000**
random blobs each, so this is Brotli's problem alone.

---

## 1. Why `MZ` + `\x90`×4094 decodes (brief Q1)

Walk `4D 5A 90 90` as RFC 7932 reads it — LSB-first within each byte (§1.5):

| bits | field | value |
| --- | --- | --- |
| byte 0 bit 0 | "WBITS > 16" | 1 |
| byte 0 bits 1–3 | `n` | 6 → **WBITS = 17 + 6 = 23** |
| byte 0 bit 4 | `ISLAST` | **0** |
| byte 0 bits 5–6 | `MNIBBLES` code | 2 → **6 nibbles**, so MLEN is 24 bits |
| byte 0 bit 7 … byte 3 bit 6 | `MLEN` − 1 | 2 171 060 → **MLEN = 2 171 061** |
| byte 3 bit 7 | `ISUNCOMPRESSED` | **1** |

That lands exactly on a byte boundary at byte 4, so the zero-padding rule is vacuous. The
meta-block is a **non-last uncompressed block of 2 171 061 bytes**, and the decoder's job
from there is `memcpy`. Given a 256-byte prefix it emits `256 − 4 = 252` bytes and stops
because the input ran out — which is precisely the observed 252, and why it is not a
truncation *error*: the decoder is mid-block and content with that.

The contrast pair in the brief isolates two different rules, not one:

| prefix | what changes | verdict |
| --- | --- | --- |
| `MZ` + `\x90`… | as above | **accepted** — uncompressed meta-block |
| `MZ` + `\x00`… | MLEN's top nibble becomes 0 | rejected — with `MNIBBLES > 4` the most significant nibble must be non-zero (`EXUBERANT_NIBBLE`) |
| `MZ` + `A`… | MLEN is fine, but byte 3 bit 7 is 0 | rejected — `ISUNCOMPRESSED = 0`, so it must parse Huffman tables, and does not |

So `\x90` is not incidental filler. `0x90` supplies both the non-zero top MLEN nibble and
the set `ISUNCOMPRESSED` bit; `0x00` fails the first test and `0x41` fails the second.

For the whole 8%, the same reasoning generalises into a header parser
(§8, `hdr.py`) that classifies a prefix without decoding it. Over 200 000 random
300-byte blobs, every class it calls invalid is accepted **0%** of the time by the real
decoder, and acceptance concentrates in exactly two classes:

| first meta-block parses as | share of blobs | of those, probe accepts | contribution to the 8.16% |
| --- | --- | --- | --- |
| **uncompressed** | 6.46% | 99.84% | **6.45%** (79% of hits) |
| **metadata** (declared skip) | 3.31% | 51.35% | **1.70%** (21% of hits) |
| compressed (Huffman body) | 35.62% | 0.02% | 0.006% |
| empty-last (`ISLAST`+`ISLASTEMPTY`) | 3.15% | **0.00%** | — |
| structurally invalid (5 rules) | 51.46% | 0.00% | — |

Two details worth keeping:

- **The metadata path only half-works**, because after the declared skip the decoder parses
  the *next* meta-block header and usually fails there. That is the same chain the gate in
  §4 walks deliberately.
- **Empty-last is valid Brotli that never passes.** `b"\x06"` alone decodes to `b""`, but
  `b"\x06" + anything` is rejected: **the decoder refuses trailing bytes after a stream
  ends.** So the decoder already enforces whole-file consistency at the *end* of a stream —
  it simply never reaches the end, because the accepting paths declare lengths far beyond
  the prefix. That asymmetry is the whole bug, and §4 is its fix.

## 2. The rate, derived (brief Q2)

The header is a small deterministic tree, so the acceptance probability on uniform random
input can be computed exactly rather than sampled (§8, `m5_analytic.py`):

| first meta-block parses as | analytic | measured (200k blobs) |
| --- | --- | --- |
| uncompressed | 6.4187% | 6.46% |
| metadata | 3.2895% | 3.31% |
| empty-last | 3.1357% | 3.15% |
| compressed | 35.6567% | 35.62% |
| reserved WBITS | 0.7812% | 0.74% |
| **predicted probe acceptance** | **8.10%** | **8.16%** |

**How many bits are actually constrained?** For the dominant path: 1–7 bits of WBITS (of
which exactly one 7-bit pattern is reserved — 1/128), `ISLAST` = 0, a 2-bit `MNIBBLES`,
a 4-bit non-zero top nibble when `MNIBBLES > 4`, `ISUNCOMPRESSED` = 1, and however many
padding bits reach the byte boundary. That is **about 15 constrained bits out of the
32 consumed** — and 17 of those 32 are MLEN payload that constrains nothing. `2⁻⁴` from
the two flag bits and the code, times the nibble and padding factors, is the 6.4%.

**Is the rate an artifact of short accidental streams?** No — it is the opposite. The
brief wondered whether demanding decoded output helps because accidental streams are
short. They are not short; they are *unbounded*. The uncompressed path emits `prefix − 4`
bytes, so it satisfies "produced output" trivially and satisfies "≥ 512 bytes" as soon as
the prefix is ≥ 516. That is exactly why the brief's own table shows a 4096-byte prefix
with a ≥512-byte demand still sitting at 8.13%: the bigger prefix hands the same path
more bytes to copy. Requiring output measures the wrong thing — every FP here is a
*declaration*, and declarations cost the forger nothing.

## 3. Can a legal Brotli stream begin with `MZ`? (brief Q3)

**Yes — constructively.** `MZ\x90\x90` is a complete, well-formed header for a non-last
uncompressed meta-block of 2 171 061 bytes. Append that many literal bytes and a
one-byte empty-last meta-block (`\x03`) and you have a 2 171 066-byte file that the
reference decoder accepts and that round-trips exactly:

```
stream = b"MZ\x90\x90" + payload + b"\x03"        # payload = 2_171_061 bytes
brotli.decompress(stream) == payload              # True
```

So the SFX change's decision to leave a bare `MZ` prefix able to reach the content probes
is correct, and **cannot** be tightened to a strong cue on legality grounds. `MZ` proves
nothing in either direction.

The weaker "would a real encoder ever emit it?" question is more constrained but does not
rescue the cue. `M` = `0x4D` forces WBITS = 23 (low nibble `0xD`) *and* `ISLAST` = 0 *and*
`MNIBBLES` = 6, i.e. an `lgwin=23` stream whose first meta-block is 1–16 MiB; `Z` then
pins MLEN ≡ 181 (mod 512). The reference encoder does emit `0xD` low nibbles at
`lgwin=23` (it is deterministic in `lgwin`: `0x1`/`0x3` at 10, `0xB` at 22, `0xD` at 23,
`0xF` at 24), but across the multi-meta-block inputs tried here it chose `ISLAST=1` or
5-nibble lengths, so no encoder-produced `MZ` turned up. That is a statement about
encoder heuristics, not about legality — and detection must accept legal streams, not
merely fashionable ones.

**`\x7fELF` is a different story.** `0x7F` forces WBITS = 24, then `ISLAST` = 1,
`ISLASTEMPTY` = 1 — the stream ends inside byte 0 — and the remaining bits must be zero
padding. Bit 6 of `0x7F` is 1, so it is **deterministically invalid, for every possible
continuation**. That is the mechanism behind the brief's 0/887 ELF binaries: not a
statistical near-miss, a structural impossibility.

Generalising that: exactly **54 of 256 first bytes can never begin a valid Brotli
stream** — 52 by the empty-last padding rule and 2 (`0x11`, `0x91`) by the reserved WBITS
pattern. Verified over 216 000 trials with random tails: zero acceptances.

```
0e 11 16 1e 26 2e 36 3e 46 4e 56 5e 66 6e 73 75 76 77 79 7b 7d 7e 7f 86 8e 91 96 9e a6 ae
b3 b5 b6 b7 b9 bb bd be bf c6 ce d6 de e6 ee f3 f5 f6 f7 f9 fb fd fe ff
```

Note `0x7f` (ELF) and `0xff` are both in it; `0x4d` (`M`) and `0x23` (`#!`) are not.

### 3.1 Where the `\x90` filler came from, and why `e_cblp` closes the case

`MZ` + `\x90`×4094 is `_STUB` in `tests/test_sfx.py` (#254), and its own comment calls it
"deliberately the *synthetic* one". `\x90` is x86 `NOP` — filler chosen to look like code,
not copied from a real executable. It matters more than a fixture choice usually would,
because **`\x90` is exactly what makes it decode**: §1 showed byte 3 supplies both the
non-zero MLEN top nibble and the set `ISUNCOMPRESSED` bit.

A real PE does not look like that. Every PE DOS header begins `4D 5A 90 00` — byte 2 is
`0x90` (that is `e_cblp` = 144, bytes-on-last-page), but **byte 3 is `0x00`**. The header
shape alone is enough: `MZ\x90\x00…` fails on `EXUBERANT_NIBBLE`.

That is not one linker's habit. Across **100 distinct `MZ` binaries** — MSVC (distlib
launchers, plus `.pyd`/`.dll` from the numpy, Pillow, lxml, cffi, cryptography, msgpack and
PyYAML Windows wheels), **Go's own internal linker**, **MinGW-w64's GNU `ld`**, and every
`MZ` file found on this machine — bytes 2–3 are `90 00` in **97/100** and the Brotli probe
claims **0/100**. Most toolchains embed the same canonical "This program cannot be run in
DOS mode" stub, which is why the prologue looks universal.

**It is not universal, and the three exceptions matter** (they are what §7 turns on):

| binary | bytes 0–3 | `e_cblp` | `e_lfanew` | sig | Brotli |
| --- | --- | --- | --- | --- | --- |
| `vmlinuz-4.15.0-47-generic` (Linux EFI stub) | `4d 5a ea 07` | **2026** | **130** | `PE\0\0` | rejected |
| `ripgrep.node` (x64-win32) | `4d 5a 78 00` | 120 | 120 | `PE\0\0` | rejected |
| `jansi.dll` (arm64) | `4d 5a 78 00` | 120 | 120 | `PE\0\0` | rejected |

The kernel image is the instructive one: an EFI-bootable `bzImage` is a valid PE whose
"DOS header" is not a stub at all but real x86 boot code, so `e_cblp` is 2026 (well over
the 512 sanity limit), `e_lfanew` is 130 (not even 4-byte aligned), and bytes 2–3 are
neither `90 00` nor anything conventional. It is still a perfectly valid PE, and the
`e_lfanew` → `PE\0\0` test still identifies it.

The Brotli probe rejects all 100 regardless — including the kernel image, whose `e_cblp` of
2026 is still below the 2048 threshold §3.1 derives, though only by 22. No binary in the
corpus reaches the Brotli-legal zone.

That generalises into a provable rule, which is the useful part:

> For a prefix starting `MZ`, byte 0 = `0x4D` pins `MNIBBLES` to code 2 (six nibbles), so
> MLEN's most significant nibble is **byte 3 bits 3–6** and must be non-zero. Hence a legal
> Brotli stream beginning `MZ` requires **byte 3 ≥ 0x08**, i.e. **`e_cblp` ≥ 2048**.
> `e_cblp ≤ 512` forces byte 3 ≤ 2. **The two conditions cannot both hold.**

Verified exhaustively over all 65 536 `(byte2, byte3)` pairs: **0 overlap**. So validating
`e_cblp` in the SFX executable cue costs *nothing* in Brotli detection — it cannot reject a
stream the probe could legitimately want, because no such stream exists. And it is a sharp
discriminator: only 513/65 536 = 0.78% of random 2-byte values satisfy `e_cblp ≤ 512`
(measured 0.90% on 20 000 random `MZ`-prefixed blobs).

This also puts a number on how exposed the SFX path specifically is. Random data *forced*
to start with `MZ` is accepted by the Brotli probe **47.19%** of the time — not 8% — because
`M` pins WBITS = 23, `ISLAST` = 0 and `MNIBBLES` = 6 all at once, which is a far more
favourable configuration than average. The `MZ` prefix makes the collision six times more
likely, and `e_cblp` removes it entirely.

The residual honesty: the Windows loader ignores every DOS header field except `e_lfanew`
and the `MZ` magic, so a hand-built PE *may* carry a nonsense `e_cblp` and still run. The
rule above is sound in the direction that matters (valid `e_cblp` ⇒ not Brotli); it is not a
guarantee that every loadable PE has one. Real linker output does, which is what an SFX stub
is.

## 4. Is there a cheap structural pre-gate? (brief Q4)

**Yes, and it is a good one.** Not a first-byte table — that is free but only worth 21% —
but the observation that both accepting paths *declare a byte count*:

> An uncompressed meta-block declares MLEN raw bytes that must physically follow it. A
> metadata meta-block declares MSKIPLEN bytes likewise. For a **complete** file,
> `header_bytes + declared_length ≤ file_size` is therefore an invariant, not a heuristic.

Random data has no such obligation, and the numbers follow:

| file size | probe today | + first-block framing check | + full chain walk |
| --- | --- | --- | --- |
| 4 KiB | 8.09% | **0.325%** (25×) | **0.050%** (162×) |
| 64 KiB | 8.38% | 4.16% (2×) | **1.55%** (5.4×) |
| 1 MiB | 6.75% | 3.75% (2×) | **1.45%** (4.7×) |
| 16 MiB | 8.33% | 8.33% (1×) | **2.00%** (4.2×) |

**False negatives on 150 real Brotli streams** (payloads from empty to 1 MiB, qualities
0/1/5/9/11, `lgwin` 10/22/24): **0 for both variants.** That is not luck — 56 of those 150
genuinely start with an uncompressed meta-block (every `one-byte`, `text-small`,
`random-4k` and `random-1m` case), and every one satisfies the invariant by construction.
The check is sound by definition, and the corpus confirms the definition was read right.

The **chain walk** is the stronger form. Uncompressed and metadata meta-blocks are
byte-aligned and self-describing, so the *next* header's offset is known exactly without
decompressing anything: parse, jump, parse again, stop at the first compressed meta-block
(whose length is only knowable by Huffman-decoding it) or at the declared end. Cost is one
~24-byte read per link, capped; for a real Brotli file whose first meta-block is compressed
— 79 of the 150 — the walk stops immediately, having read four bytes. It is also the only
variant that does anything for files ≥ 16 MiB, where MLEN's 2²⁴ ceiling makes the
single-block check vacuous.

Both need the file size, which the probe signature `content_probe(prefix: bytes) -> bool`
does not carry. Detection can supply it: `os.path.getsize` for a `Path`, `seek(0, 2)`
relative to the start position for a seekable stream, and for anything else the peek itself
— `_peek_prefix` returns short when the file is shorter than the request, so any file below
`DETECTION_LIMIT` (4096) already reveals its exact size. Only a non-seekable stream longer
than the peek has no size, and there the gate degrades to today's behaviour.

For completeness, the tuning variants re-measured on one shared corpus (20 000 random 4 KiB
blobs, 1200 system binaries, 150 real streams):

| policy | random FP | binary FP | real misses |
| --- | --- | --- | --- |
| 256B prefix, any outcome (today) | 8.19% | 0/1200 | 0/150 |
| 256B prefix, ≥1 byte out | 6.50% | 0/1200 | 24/150 |
| 256B prefix, ≥512 bytes out | 0.00% | 0/1200 | 90/150 |
| 4096B prefix, any outcome | 7.94% | 0/1200 | 0/150 |
| 4096B prefix, ≥512 bytes out | 6.33% | 0/1200 | 45/150 |
| **256B prefix + framing gate** | **0.33%** | 0/1200 | **0/150** |
| **4096B prefix + framing gate** | **0.07%** | 0/1200 | **0/150** |

(The ≥512-byte rows differ from the brief's, which counted a truncation as a hit regardless
of how much came out; here the byte count is required outright. Both agree on the
conclusion, and on the direction of every trade.)

### 4.1 A gate that looks attractive and is not: restricting WBITS

WBITS is the obvious candidate, because its encoding is lopsided. The 15 legal values are
*not* equiprobable in random data — WBITS = 16 is a **one-bit** encoding, so it takes half
of all random prefixes, while 18–24 take four bits each:

| WBITS | encoding | share of random data |
| --- | --- | --- |
| 16 | 1 bit | **50.0%** |
| 18–24 | 4 bits | ~6.2% each |
| 10–15, 17 | 7 bits | ~0.8% each |
| (reserved) | 7 bits | 0.78% |

So a whitelist bites hard. Restricting the probe to WBITS = 22 — the reference encoder's
default — takes random-data FP from **8.30% to 0.79%**, a 10.5× cut.

**But the encoder emits whatever it is asked for, and real files use the full range.**
Measured across quality × `lgwin` × payload: at quality ≥ 2 the encoder emits *exactly* the
requested `lgwin`, all 15 values 10–24 reachable; quality 0 and 1 clamp anything below 18 up
to 18. Nothing narrows it. And the wild confirms it — every real Brotli stream I could find
on this machine, verified by decompressing it:

| source | WBITS |
| --- | --- |
| `/usr/share/javascript/underscore/underscore.min.js.br` | **15** |
| `…/underscore.min.js.map.br` | **16** |
| 4 WOFF2 fonts (Font Awesome) | **19** |
| 8 WOFF2 fonts (Lato, Roboto Slab, Fraunces) | **22** |

The two `.br` files — the exact format the brief insists must keep working — use 15 and 16.
The `brotli` CLI shrinks the window toward the input size, so small-window streams are the
*normal* case for small files; only the Python binding's `lgwin=22` default keeps 22 common.
Whitelisting even the union observed here, {15, 16, 19, 22}, is worth just **2.1×** (8.30% →
4.00%) because it has to admit 16 — the one value that is half of all random data.

| whitelist | random FP | reduction | rejects |
| --- | --- | --- | --- |
| {22} only | 0.79% | 10.5× | both real `.br` files, 4/12 fonts |
| {15, 16, 19, 22} ("observed" — **already stale**) | 4.00% | 2.1× | Fira Sans (18) and Source Code Pro / Source Serif 4 (21) — see below |
| {16…24} | 8.15% | 1.0× | the `.br` file at WBITS 15 |

**The middle row is the point, and it did not survive one independent run.** A reviewer
surveyed 213 real WOFF2 streams on a different machine and found **22** (171), **16** (34),
**21** (6, hashed rust-docs Source Code Pro / Source Serif 4) and **18** (2, Fira Sans).
Adding my own `.br` files and fonts, the observed union across two machines is now
**{15, 16, 18, 19, 21, 22}** — six of the fifteen legal values, from two small samples that
disagreed with each other on first contact.

That is the strongest form of this argument. An "observed union" whitelist is not a
conservative choice that merely fails to pay; it is a rule whose false-negative set is
whatever the next machine happens to ship, and the very first attempt to reproduce it found
real fonts it would reject.

So WBITS whitelisting is the wrong shape of lever: the variants that pay are unsound
(they reject files archivey claims to support), and the variant that is safe barely pays.
The framing check in §4 gets 25–162× while being *sound* — it cannot reject a valid complete
file, because the property it tests is one such a file must have. Not recommended.

## 5. What actually happens on a false positive

Worth pinning down before choosing a policy, because it changes what "silent wrong answer"
means here. Across 364 false positives at 4 KiB, 64 KiB and 256 KiB:

| stage | outcome |
| --- | --- |
| `detect_format` | `ArchiveFormat.BROTLI`, confidence `PROBABLE`, `detected_by="content_probe"` |
| `open_archive(...).members()` | succeeds — **one** fabricated member |
| reading that member | **fails every time**: `TruncatedError` 97.5%, `CorruptionError` 2.5% |

Zero silent successes. That follows from §1: the accepting paths declare lengths the file
cannot honour, so the read runs off the end. It also means the user-visible defect is
sharper than "fabricated data" — it is **the wrong error**. A file that should have raised
`FormatDetectionError` ("unrecognized format") instead raises `TruncatedError (…,
format=BROTLI)`, which blames the file for being truncated and names a format it never was.

Two other pieces of the realistic picture:

- **Executables are not at risk.** 0/1200 system binaries and the brief's 0/887 ELF
  binaries — and for ELF, §3 shows it is outright impossible.
- **Ordinary text files very much are.** An earlier draft of this section claimed
  "structured files are not at risk" from 0/950 repo files. That was an artifact of which
  file types got scanned (`.py`, `.md`, `.json`, `.toml`). A wider sweep — 39 859 files
  under `/usr`, via `scripts/investigations/exploration/brotli_probe_field_survey.py` — finds **1377
  accepted (3.5%)**, and they are not high-entropy at all:

  | first 4 bytes | what it is | count |
  | --- | --- | --- |
  | `/**\n` | Doxygen / Javadoc comment opener | **375** |
  | `let ` | JavaScript / TypeScript | 17 |
  | `-- \n` | SQL / Lua / Haskell comment | 3 |
  | `## \n` | Markdown / shell comment | 2 |

  `/usr/include/lzma.h` and `/usr/include/yaml.h` both come back from `detect_format` as
  `ArchiveFormat.BROTLI`. The reason is exact rather than lucky: `2f 2a 2a 0a` gives
  WBITS = 24 (`/` = `0x2F`), `ISLAST` = 0, `MNIBBLES` code 1 (five nibbles), a non-zero top
  MLEN nibble, `ISUNCOMPRESSED` = 1 from bit 3 of `\n`, and — the part that makes it work —
  bits 4–7 of `0x0A` are all zero, satisfying the pad-to-byte-boundary rule. **A newline as
  the fourth byte is what completes the header**, which is why a comment opener followed by
  a line break is such a reliable hit.

  So the accepting bit patterns do *not* need entropy. They need one of a family of
  four-byte openers, and `/**\n` is among the most common in existence. The family is
  wider than this table: an independent scan of a different Linux image found
  `/*!\n` (34), `// \n` (30), `AUTO` (27), `#\n#\t` (21), `LINK` (20) *ahead of* `/**\n`
  (18), and §7.2 adds `---\r\n` from Windows. Read the table as "whichever comment-plus-
  line-break openers this filesystem happens to contain", not as a fixed top four.

  The gates hold up on exactly this data: of the 1377, the first-block framing check
  rejects **1316**, the chain walk rejects **1363**, and only **14** survive both.
- **High-entropy *bodies* are.** Reading real compressed/media files from an offset (so the
  container header is gone, i.e. a headerless blob) gives 1.5–2.6% acceptance, and
  cryptographic random gives 8.05% — indistinguishable from uniform random, and cut to
  0.40% by the framing gate. So the exposed case is exactly "an opaque high-entropy blob
  with no magic", which is also the case where a clean `FormatDetectionError` is the most
  useful answer.

### 5.1 The residual is not just lucky fits — and "every read failed" undersells it

Two corrections from an independent replication, both reproduced here.

**The residual has named format families in it.** At 4 KiB, 0.325% of random blobs survive
(40 uncompressed, 24 metadata, 1 compressed per 20 000) with declared lengths that happen to
fit. But on real filesystems the survivors are systematic, because some container magics
*are* a valid uncompressed meta-block header with a small declared length:

| magic | what it is | parses as | survives the gate when |
| --- | --- | --- | --- |
| `D0 CF 11 E0 A1 B1 1A E1` | OLE / Compound File Binary — `.doc`, `.xls`, `.ppt`, `.msi`, `.vsmacros` | WBITS 16, **MLEN 7422**, header 3 bytes | file ≥ 7425 bytes — i.e. **always**, in practice |
| `64 86 …` | COFF object (`IMAGE_FILE_MACHINE_AMD64`), e.g. Go's `race_windows.syso` | uncompressed, small MLEN | routinely |

The OLE case is the sharp one: those 8 bytes are *constant*, so the declared length is
always 7422 and **every CFB file above 7425 bytes passes both the framing check and the
chain walk**. Verified on this machine —
`detect_format("/usr/share/cmake-3.28/Templates/CMakeVSMacros1.vsmacros")` returns
`BROTLI` / `PROBABLE` / `content_probe`, and the chain walk stops at the first compressed
header and returns cannot-disprove. The gate is still the right primary fix (it cut 207 → 3
on the reviewer's 79 926-file scan, and it rejects the Mach-O files §7.2 shows the probe
accepts today) — but the residual is *Microsoft Compound Files and COFF objects*, not
opaque blobs, and it should be tested with those fixtures rather than a random blob whose
MLEN happens to fit.

**A read can deliver fabricated bytes before it fails.** §5's table says every read failed,
which is true of the terminal exception and misleading about what the caller gets. Measured
here on a file whose first uncompressed meta-block declares 163 846 bytes and fits:

```
read delivered 65536 bytes, then CorruptionError
those bytes are a verbatim slice of the input file: True
```

The reviewer measured the same shape on real files — 126 976 bytes from `race_windows.syso`
before `CorruptionError`, 5020 of 5024 from a Mach-O before `TruncatedError`. So a caller
streaming to disk has already written a chunk of garbage when the error arrives. `.vsmacros`
happens to deliver 0 bytes (the decoder fails inside the same fill), so this depends on
where the failure lands relative to the buffer — which is exactly why "no silent wrong
answer" is the wrong summary. **P12 / O10 should say: the listing is wrong, a full read
raises, and a prefix of fabricated bytes may already have been produced.**

## 6. Do the peer probes share the problem? (brief Q6)

No. Measured identically — 20 000 random 4 KiB blobs and 1200 system binaries:

| codec | random 4 KiB FP | system-binary FP |
| --- | --- | --- |
| `lzma_alone` | **0.000%** | 0/1200 |
| `zlib` | **0.000%** | 0/1200 |
| `brotli` | 8.190% | 0/1200 |

The two are clean for different reasons, and only one of them is the header gate:

- **zlib** is gated by construction — `_ZLIB_HEADERS` admits 4 of 65 536 two-byte prefixes
  (0.006%) before any decode, and the decode then has to succeed too.
- **LZMA Alone**'s gate is weak: every properties byte ≤ 224 is a valid `(lc, lp, pb)`
  triple, so ~88% of random data passes `_alone_header_plausible` and reaches the decoder.
  It scores 0 anyway because the LZMA decoder is *intrinsically* strict — there is no
  "copy the rest verbatim" escape hatch in its bitstream. Brotli's uncompressed meta-block
  is that escape hatch.

So the fix belongs in Brotli, not at the probe layer generally. The transferable lesson is
narrower: a probe is only as strong as the weakest thing the format lets a stream *declare*
without proving.

### 6.1 LZMA Alone is not quite zero — and its residual has the same shape

"0/20 000" is right for uniform random (re-measured: 0 at 4 KiB × 20 000 *and* 0 at 64 KiB
× 4 000), but it is not the whole picture. Over **40 000 real files**, the LZMA Alone probe
accepts **4** — 0.010%:

| file | contents | size |
| --- | --- | --- |
| `cryptography.egg-info/top_level.txt` | `cryptography\n` | **13** |
| `cryptography-41.0.7.dist-info/top_level.txt` | `cryptography\n` | **13** |
| `launchpadlib-1.11.0.egg-info/top_level.txt` | `launchpadlib\n` | **13** |
| `/usr/lib/php/packaging` | `deb.sury.org\n` | **13** |

Every one is **exactly 13 bytes — the Alone header size**. The whole file is consumed as a
header, the decoder immediately runs out of input, and `TruncatedError` counts as
acceptance. The first byte just has to be ≤ 224 to pass the properties gate, which any
lowercase letter is.

**The fix is the same shape as the Brotli framing gate**: a real `.lzma` is 13 header bytes
*plus* range-coder payload, so a file that is only the header cannot be one. Requiring
`file_size > 13` removes **4 of 4**, leaving zero real-world residual. Same principle —
check the declared framing against what the source can actually hold.

Two footnotes. The Alone properties gate does almost nothing (~88% of random data passes
it), so the *decoder* is the real filter — unlike zlib, where the gate does the work. And
`cf fa ed fe` passes the Alone gate too (`0xcf` = 207 ≤ 224), which is why the zero-filled
Mach-O stub in §7.2 came back `LZMA_ALONE` rather than `BROTLI`.

### 6.2 Compressed-first is ~1000× stronger evidence than uncompressed-first

Raised by the maintainer: should an uncompressed first meta-block carry less confidence
than a compressed one, on the reasoning that real streams are mostly compressed? Measured,
and the gap is larger than the question assumed.

**Random data, by first-meta-block class** (20 000 × 4 KiB):

| first block | share of random data | accepted | share of all false positives | acceptance *within* the class |
| --- | --- | --- | --- | --- |
| compressed | 35.78% | **1** | 0.1% | **0.014%** |
| uncompressed | 6.69% | 1338 | **80.7%** | **~100%** |
| metadata | 3.21% | 320 | 19.3% | ~50% |

**Real streams in the wild: 25 of 25 are compressed-first** — both `.br` files and 23 WOFF2
payloads. Not one uncompressed.

But uncompressed-first is not *invalid*, and that is the cost. The reference encoder emits
it exactly when the payload is incompressible — verified across qualities:

| payload | first meta-block |
| --- | --- |
| text, 1 KiB and 1 MiB | compressed at every quality |
| random, 4 KiB and 1 MiB | **uncompressed** at every quality |
| 12 bytes | mixed |

So a genuine `.br` of already-compressed data *is* uncompressed-first. Downgrading the
class would mis-rank those — though in practice they carry the `.br` extension, which the
§7 rule already treats as corroboration.

**And the MLEN answer, which is the part that matters.** For a real uncompressed-first
stream, MLEN is the payload size and the declared end lands one byte short of EOF:

| payload | MLEN | file | declared end |
| --- | --- | --- | --- |
| 4 096 B random | 4 096 | 4 100 | 4 099 |
| 65 536 B random | 65 536 | 65 540 | 65 539 |
| 1 048 576 B random | 1 048 576 | 1 048 581 | 1 048 580 |

For random data accepted as Brotli (1 282 uncompressed-first hits): MLEN median **236 929**,
max **16 715 621**, against a 4 KiB file — and **96.7% declare more than the file holds**.

That is the whole finding in one line: **the confidence split and the framing gate are
measuring the same thing, and the gate measures it better.** "Uncompressed-first" is a
proxy for "probably fabricated"; "the declared length overruns the source" is the direct
test, and it keeps the 3.3% of genuine incompressible streams the proxy would penalise.

Where the split still adds something is the *residual*: everything that survives the gate
is uncompressed or metadata (§5.1), never compressed. So a probe-only hit whose first block
is **compressed** is ~1000× better evidence than one that is not, and could reasonably keep
`PROBABLE` where the rest drops to `GUESS`. That is a refinement of §7's Brotli-only
`GUESS` rule, not a replacement for the gate.

## 7. What detection should do (brief Q5)

The brief listed four options. With the measurements in, three of them are worse than the
option the measurements produced.

**Recommended — add the structural gate; leave the probe itself alone.** Gate the Brotli
probe on the framing invariant of §4, chain-walk form, using the file size where detection
can get it and falling back to today's behaviour where it cannot. It is sound rather than
heuristic (a complete valid file cannot fail it), it costs a bounded number of small reads
and no decompression, it is 4×–162× depending on file size, and it measured **0/150** false
negatives on a corpus deliberately stocked with the streams most likely to trip it. Bare
`.br` files keep working — that is what the 0/150 means, and it is the constraint the brief
puts above the others.

### 7.1 Should the probe run at all? (raised by the maintainer)

Given §5 — ordinary `.h` files detecting as Brotli — the fair question is whether content
probing should be off by default, gated on an archive-like extension, or merely documented.
Three measurements decide it.

**What disabling would actually cost is small.** With the Brotli probe forced off, `.br`
files are *still* detected, by the extension guess at step 4 — at `GUESS` instead of
`PROBABLE`. So disabling loses only **extensionless** raw Brotli. And raw Brotli is rare:
on this system, **2 `.br` files against 1797 `.gz`**, ~900:1. Both `.br` files are Ubuntu's
`libjs-underscore` pre-compressed web assets, sitting beside the original and a `.gz` twin
— which is what raw Brotli in the wild *is*: static assets a web server sends with
`Content-Encoding: br`, and they always carry the extension.

**What extension-gating would achieve is large.** 0 of 400 sampled false positives carried
a known archive extension, so corroboration would remove all of them.

**But both contradict the founding use case.** `VISION.md` is explicit:

> *"index and deduplicate decades of messy backups — old downloads with **wrong
> extensions**…"* … *"**Identification must be evidence-based.** Wrong extensions are
> normal; magic-first detection with honest confidence reporting is a feature, not
> plumbing."*

A Brotli stream named `.dat` in a backup corpus is precisely what archivey exists to
identify. Gating discovery on the extension removes that; disabling by default removes it
and *also* makes a real `.br` file report less confidence than the bytes can support. The
same "this format is rare, stop looking for it" argument would apply to LZMA Alone, which
is equally magic-less and equally rare — but whose probe costs 0% false positives. Turning
Brotli's discovery off rather than fixing Brotli's probe treats the symptom.

**The defect is what the probe claims, not that it runs.** `detect_format` reports
`/usr/include/lzma.h` as `BROTLI` at **`PROBABLE`** confidence. Under the same
honest-confidence principle, that is the bug. So:

| lever | verdict |
| --- | --- |
| structural gate (§4) | **do it** — sound, no policy change, 1377 → 14 on real data |
| extension as a *confidence input* | **do it** — probe + `.br` → `PROBABLE`; probe alone → `GUESS` |
| honest error on probe-only results | **do it** — this is where the user-visible harm is |
| extension as a *hard gate* | no — contradicts "wrong extensions are normal" |
| off by default | no — same, and it under-reports confirmed `.br` files |
| config knob to disable | not now — at 0.035% it does not earn the API surface, docs and test matrix; if one is ever wanted, make it a general "content probes off" strictness setting, not a Brotli special case |
| documentation warning | subsumed — a `GUESS` verdict and an honest error *are* the warning, delivered where the user is |

The gate is what makes this affordable: it takes the real-world rate from 3.5% of files
under `/usr` to **14 / 39 859 = 0.035%**, a 100× cut, without giving up discovery.

**Deferred, deliberately: extension-first ordering.** Content probes run at step 2, before
the extension guess at step 4, so a probe result preempts the extension entirely — a file
named `x.lzma` whose bytes trip the Brotli probe is reported as Brotli and never reaches
its own extension. The maintainer's suggestion is to invert this: try the formats matching
the extension first, and fall back to the rest only on a miss or when there is no filename.
That is strictly better than either the status quo or a hard extension gate — it uses the
extension as a *priority order* rather than a filter, so wrong-extension files still get
identified. It is also a larger structural change to `_detect_format_body` that touches
every format, not just Brotli, and it should land as its own change rather than riding
along with the probe fix.

On the brief's four:

| option | verdict |
| --- | --- |
| require `.br` extension corroboration; report `GUESS` otherwise | **Rejected.** It breaks detection of correctly-formed extensionless `.br` streams — the format's whole problem is that content is all there is. The gate gets a bigger win without giving that up. |
| demand more of the decoded bytes (reach a meta-block boundary) | **Rejected as primary.** §2: the uncompressed path *is* a meta-block in progress and emits as much as you ask for. Every output-demanding variant trades FP for FN roughly one-for-one (24–90 misses of 150). |
| fail loudly when a single-file result rests only on a content probe | **Worth doing, separately, and narrowly.** Not as a refusal — that would break `.br` — but the `PROBABLE`/`content_probe` provenance is already on `FormatInfo` and is currently discarded downstream. §5 shows the wrong-error problem is the real user-visible harm; a read failure on a probe-only single-file result should say "this may not be a Brotli file" rather than "file is truncated". |
| accept the rate and document it | **Superseded.** It was the right call while probe tuning looked like the only lever. It is not the only lever. |

**Separately, for the SFX cue (#254).** An earlier draft of this section proposed promoting
the `MZ` cue to STRONG on a valid `e_cblp`, *independently* of the `e_lfanew` → `PE\0\0`
follow-through. **That was wrong, and measuring the alternatives is what shows it.** Over
200 000 random `MZ`-prefixed blobs:

| candidate STRONG rule | real `MZ` binaries | random `MZ` FP | analytic bound |
| --- | --- | --- | --- |
| `e_cblp ≤ 512` | 99/100 ✗ | **0.7695%** | 513/2¹⁶ = 0.783% |
| bytes 2–3 == `90 00` | 97/100 ✗ | 0.0025% | 1/2¹⁶ = 0.0015% |
| `e_lfanew` → `PE\0\0` (**today's rule**) | **100/100** | **0.0000%** | ~2⁻⁵² |
| — with `e_lfanew ≤ 1024` | **100/100** | 0.0000% | ~2⁻⁵⁴ |
| — with `e_lfanew ≤ 1024`, 8-byte aligned | 99/100 ✗ | 0.0000% | ~2⁻⁵⁷ |
| `e_lfanew` → `PE`/`NE`/`LE`/`LX` | 100/100 | 0.0000% | ~2⁻⁵⁰ |

Every rule built from DOS header *fields* loses real binaries; the spec-grounded one loses
none. And it wins on false positives by a margin nothing else approaches: `e_lfanew` is four
random bytes that must land inside the prefix (~2⁻²⁰) *and* address four more specific bytes
(2⁻³²). Swapping in `e_cblp` would have made the cue roughly **10¹³ times looser** *and*
rejected the kernel image. Even the tightened `90 00` form is 2⁻¹⁶ against 2⁻⁵², and loses
three binaries. So:

- **Keep `e_lfanew` → `PE\0\0` as the STRONG rule.** Do not add `e_cblp` as an alternative
  path to STRONG. Retracted.
- **Bounding `e_lfanew` looked safe here and is not — see §7.2.** A Windows survey of
  12 887 PE binaries found a maximum of **11 648**, so the cap below rejects a real
  binary. Kept as written because the reasoning about *why* one might want a bound still
  holds; the conclusion is superseded. Observed values across the original 100 binaries
  are just ten distinct numbers spanning **120…280**:

  | `e_lfanew` | 120 | 128 | 130 | 232 | 240 | 248 | 256 | 264 | 272 | 280 |
  | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
  | count | 2 | 36 | 1 | 2 | 6 | 14 | 12 | 10 | 10 | 7 |

  Go and MinGW emit 128 exactly; MSVC varies 128–280 as its Rich header grows. A cap of
  **1024** keeps 100/100 with ~3.6× headroom over the observed maximum. But the FP gain is
  ~2⁻⁵² → ~2⁻⁵⁴ — invisible, because the 2⁻³² signature match dominates and the range term
  was already the smaller factor. The real reason to cap it is **bounding the read**: the
  `_is_pe` helper from `sfx-format-detection` (`src/archivey/internal/sfx.py:100`, on `main`
  since #254 merged) allows `e_lfanew` anywhere up to `len(prefix) - 4`, so resolving
  the check can require the whole 4096-byte prefix; a 1 KiB cap makes the cue answerable
  from 1 KiB and keeps it answerable if `DETECTION_LIMIT` ever grows. Treat it as hygiene,
  not as detection strength.
- **Do not require alignment.** It is the tempting next step and it is wrong: the Linux EFI
  kernel image sits at `e_lfanew` = 130, not even 4-byte aligned, and is a valid PE. The PE
  format recommends alignment; it does not require it, and real files exercise the
  difference.
- **Optionally widen the accepted signature to `NE`/`LE`/`LX`** alongside `PE`. Still
  0.0000% measured, still ~2⁻⁵⁰ analytically, and it covers 16-bit Windows and OS/2 SFX
  stubs that the `PE`-only test rejects. Caveat: no such stub was available to test here —
  every one of the 53 `MZ` files on this machine is a `PE` — so this is reasoning from the
  format, not from a corpus.
- **`e_cblp`'s real value is explanatory, not operational.** It is what *proves* real
  executables can never collide with the Brotli probe, which is precisely the assurance
  #254's weak/strong split was asserting from outcomes. As a runtime check it would only be
  a micro-optimisation (two bytes, no `e_lfanew` read) and is not worth the code.
- **Narrowing STRONG to bytes 2–3 == `90 00`** is tighter than `e_cblp ≤ 512`, but it is a
  toolchain convention rather than a format requirement, and the corpus catches it out:
  97/100, missing the kernel image and both 120-byte-stub binaries. A genuine DOS-era `MZ`
  binary carries `e_cblp` = filesize mod 512, i.e. effectively arbitrary. Since the
  `e_lfanew` test is both tighter *and* grounded in the PE spec, `90 00` has no role.
- The `MZ` + `\x90`×4094 fixture should be labelled for what §3.1 shows it is: not a stub
  with unlucky filler, but a byte sequence whose filler is *specifically* what a DOS header
  never contains. It is a fine regression test; it is not evidence about real executables,
  and #254's design notes read as though it were.

**Scope note for the proposal.** Any of this moves normative text in
`openspec/specs/format-detection/spec.md` (the probe requirements) and touches the
`content_probe(prefix) -> bool` signature, since the gate needs a size the probe cannot
currently see. The brief is explicit that this must land as an OpenSpec change rather than
in passing, and that remains right. The proposal should cover: the framing invariant as a
normative requirement, the size-availability fallback (including the non-seekable case),
the `content_probe` signature change and what it means for the other probes, and the
error-message provenance item above. On that signature: zlib genuinely does not need the
length, but **LZMA Alone does** — §6.1 found its entire real-world false-positive set is
files that are exactly its 13-byte header, which the same invariant rejects.

The residual (§5) does not close and should stay registered. P12/O10 want rewording, but to
**three** clauses rather than the two this note originally proposed: the listing is wrong,
a full read raises, and a prefix of fabricated bytes may already have been produced.
"Silent wrong answer" is overstated; so is "misleading listing and misattributed read
error", which §5.1 measured as missing the 65 536 bytes delivered before the exception.

**One thing that will not close, ever.** A crafted file *is* a valid Brotli stream — §3
builds a 2 MB one starting with `MZ`. Brotli has no magic, so "this file is simultaneously
valid Brotli and something else" is a property of the format, not a defect in the probe.
No gate proposed here changes that, and none should claim to.

## 7.2 Field survey: what other operating systems say

Everything above §7.1 was measured on one Linux container. `scripts/investigations/exploration/
brotli_probe_field_survey.py` was run on GitHub's Windows, macOS and Linux images via a
temporary workflow (`.github/workflows/brotli-field-survey.yml`), ~59 000 files each:

| image | files | PE | probe hits | framing gate rejects | chain walk rejects | survive both |
| --- | --- | --- | --- | --- | --- | --- |
| `windows-latest` (Server 2025) | 59 202 | 12 887 | 318 (0.54%) | 259 | 306 | **12** (0.020%) |
| `windows-2022` | 59 176 | — | — | — | — | **14** |
| `macos-latest` (ARM64) | 59 800 | 934 | 672 (1.12%) | 659 | 670 | **2** (0.0033%) |

Three platforms, ~178 000 files: the residual after the chain walk stays at 0.003–0.02%,
consistent with the 0.035% measured on `/usr` locally. **The gate's effectiveness is not a
Linux artifact.** Four findings change the text above.

**1. The `e_lfanew ≤ 1024` cap in §7 is dead.** 12 887 Windows PE binaries — 129× the
corpus §3.1 rests on — give a maximum of **11 648**, 11× the value the cap was sized
against, and one binary exceeds 1024:

| `e_lfanew` | 64 | 120 | 128 | 168–360 | 11648 |
| --- | --- | --- | --- | --- | --- |
| count | 20 | 34 | 3304 | 9528 | **1** |

That binary is **`C:\Windows\System32\tcblaunch.exe`** (11 560 on `windows-2022`), the
Trusted Computing Base launcher — and its DOS header is entirely ordinary, `4d 5a 90 00`
with `e_cblp` = 144. So the giant `e_lfanew` is not correlated with any other oddity that
might have been used to except it.

`rule_lfanew_le_1024` scores 12 886/12 887. The spec-grounded `e_lfanew` → `PE\0\0` test
is still 12 887/12 887. So the cap is not the free tightening §7 called it; it is another
field-derived rule that loses a real binary, and the only reason to want it — bounding the
read — has to be weighed against that. Recommend: keep it out of the *correctness* rule;
if a bound is wanted for read-size reasons, treat exceeding it as "cannot confirm cheaply",
not as "not an executable".

**2. Windows DOS stubs come in three shapes, not one**, and the exceptions are whole
product families rather than strays:

| bytes 0–3 | `e_cblp` | `e_lfanew` | count | what they are |
| --- | --- | --- | --- | --- |
| `4d 5a 90 00` | 144 | 128–360 | 12 833 | the canonical stub |
| `4d 5a 78 00` | 120 | 120 | 34 | Edge WebView (`vulkan-1.dll`, `vk_swiftshader.dll`, `telclient.dll`, …) and the .NET Android SDK's `aapt2.exe` |
| `4d 5a 00 00` | **0** | **64** | 20 | `C:\Windows\System32\WinMetadata\*.winmd` — WinRT/ECMA-335 metadata assemblies, **no DOS stub at all**: the PE header starts immediately after the 64-byte DOS header |

§3.1's "`90 00` in 97/100" was optimistic about a convention that managed assemblies and
two separate Microsoft product teams already break.

**3. 64-bit Mach-O is structurally *guaranteed* to pass the probe.** macOS returned **200
Mach-O hits**, and the reason is exact rather than statistical: `cf fa ed fe`
(`MH_MAGIC_64`, little-endian) parses as WBITS 24, `ISLAST` 0, `MNIBBLES` code 2,
non-zero top MLEN nibble, `ISUNCOMPRESSED` = 1, zero padding — a complete uncompressed
meta-block header. The other Mach-O magics (`ce fa ed fe`, both big-endian forms, and the
fat `ca fe ba be`) are all rejected. This is the exact mirror of ELF, which §3 shows is
*impossible*.

It matters beyond this investigation: archivey's `executable_cue` handles `MZ` and ELF
only, so **a macOS SFX stub gets no cue at all *and* is claimed by a content probe** —
the `sfx-format-detection` defect, on a platform that change never considered. The framing
gate rescues it (a Mach-O's MLEN comes from its `cputype` field — 16 636 918 for arm64 —
which no ordinary binary can honour), but the missing cue is worth registering separately.

**Confirmed from the other direction, and the two halves compose badly.**
`sfx-format-detection` reached the same gap independently at `34db1b0`, from a CI failure:
its ELF-cue test sampled `/usr/bin/env`, which is Mach-O on macOS, so both macOS legs went
red. That change now pins the gap with `test_a_mach_o_binary_is_not_a_cue_today` and a
`design.md` note — and it independently hit the same `0xcafebabe` Java-class-file collision
that bit the survey script in §7.2. Two encounters from two directions make that a real
footgun rather than a quirk.

But its note says a Mach-O stub *"still falls through to the content probes"*, and §7.2
says the probes always accept `cf fa ed fe`. Together that is not a fall-through, it is a
**reliable misdetection**. Reproduced end-to-end against `34db1b0` itself:

| stub | cue | `detect_format` | `open_archive` |
| --- | --- | --- | --- |
| PE + 7z | `STRONG` | `SEVEN_Z`, `off=8132` | real members |
| ELF + 7z | `STRONG` | `SEVEN_Z`, `off=8192` | real members |
| **Mach-O + 7z** | **`NONE`** | **`BROTLI`** | **one fabricated `.uncompressed` member** |

So the silent-wrong-answer defect the change exists to close is **fully intact on macOS**
after it lands. Two refinements to the claim, both measured:

- **It is structural, not probabilistic.** Whether `cf fa ed fe` parses as an uncompressed
  meta-block depends only on those four bytes — WBITS 24, `ISLAST` 0, six nibbles, non-zero
  top nibble from `0xFE`, `ISUNCOMPRESSED` from its bit 7, zero padding. Every thin 64-bit
  little-endian Mach-O qualifies, whatever its `cputype`.
- **Brotli is not the only claimant.** With a realistic arm64 header the answer is
  `BROTLI`; with a zero-filled stub, LZMA Alone's probe bites first and the answer is
  `LZMA_ALONE`. Both fabricate a single `.uncompressed` member, so the user-visible defect
  is identical — the Mach-O fall-through lands on *whichever* content probe accepts first.
  A universal (`ca fe ba be`) stub is rejected by both and fails loudly with
  `FormatDetectionError`, so a **thin** arm64 stub is the silent case and a fat one is not.

Widening the cue is a spec change, which is why `sfx-format-detection` deliberately did not
do it. `prefixed-archive-detection` (PR #257) is where it lands.

*A correction to my own tooling, recorded because it would otherwise have become a claim
in this document:* the survey script first reported "Mach-O: 66" on **Windows**, which is
not a thing. Mach-O fat binaries and Java `.class` files share the magic `ca fe ba be`,
and the script split them on "is the next `u32` small?" — but a Java 8 class reads
`00 00 00 34` = 52, which is small. Those 51 files were Java classes. The fix splits on
field layout instead (Java has `minor_version` then `major_version`, and major has been
≥ 45 since JDK 1.1; Mach-O has a single `nfat_arch`). The 200 macOS hits are unaffected —
they are `cf fa ed fe`, verified against the reference decoder independently.

**4. `---\r\n` joins `/**\n`.** 50 Windows hits are Narrator Braille rule files opening with
the YAML document separator. Same mechanism: byte 3 is `0x0D`. The general rule is that
byte 3 must land in **`0x09`–`0x0F`** — tab, LF, VT, FF, CR — with bit 3 set (giving
`ISUNCOMPRESSED`) and bits 4–7 clear (satisfying the padding rule). It is necessary but not
sufficient: bytes 0–2 must also produce a non-zero top MLEN nibble, so `abc\t` is rejected
while `/**\n`, `---\r\n`, `-- \n` and `## \n` are accepted. Windows' hit mix is `.txt` 89,
`.rst` 82, `.yaml` 50, `.nls` 45; macOS's is `.h` 117, no-extension 117, `.yml` 114,
`.md` 90, `.o` 77.

### 7.3 Scope: the target is SFX stubs, not every PE

**Maintainer ruling (2026-08-19), and it narrows most of §3.1 and §7.2.** archivey does not
need to classify arbitrary executables. The executable cue exists for one job: recognising
the **stub in front of a self-extracting archive**. That is a far more restrictive
population than "every `MZ` file on a Windows install", and the corner cases this
investigation kept finding are mostly *outside* it:

| counterexample | what it is | an SFX stub? |
| --- | --- | --- |
| `vmlinuz-4.15` (`e_cblp` 2026, `e_lfanew` 130 unaligned) | Linux EFI kernel image | no |
| `WinMetadata\*.winmd` (`e_cblp` 0, no DOS stub) | WinRT/ECMA-335 metadata assemblies | no |
| `tcblaunch.exe` (`e_lfanew` 11 648) | Windows Trusted Computing Base launcher | no |
| Edge WebView DLLs, `aapt2.exe` (120-byte stub) | ordinary shipped binaries | no |

So the "every field-derived rule loses a real binary" result in §7 is *true as stated about
all PEs*, and **over-strong as an argument about SFX cues**. A rule that mishandles a Linux
kernel image or a `.winmd` costs archivey nothing, because neither will ever be handed to it
as a self-extracting archive. The conclusion that survives the narrowing is weaker but still
holds: the `e_lfanew` → `PE\0\0` test is both the cheapest and the most robust of the
candidates, and nothing measured here argues for replacing it. What does *not* survive is
using these counterexamples to rule out a bounded `e_lfanew`.

The one artifact in the corpus that genuinely *is* SFX-shaped is instructive: **distlib's
`t32`/`t64`/`w32`/`w64` launchers**, which `pip` concatenates with a ZIP payload to make an
executable — exactly the stub-plus-archive shape. Those sit at `e_lfanew` 240–280, well
inside any plausible bound.

**What this leaves open, deliberately.** There is no real SFX corpus here. The maintainer's
plan is to generate stubs with current *and* old tools (WinRAR, 7-Zip, InstallShield-era
installers) and to pull from old installation archives and media images — which is the only
way to learn what a 1990s NE/LE self-extractor actually looks like. Until then, treat §3.1
and §7.2's executable-header conclusions as *bounds on the general PE population*, and do
not let their corner cases veto a cue design aimed at stubs. Recorded as a follow-up in
`brotli-probe-framing-gate/tasks.md` §5.

**Caveats.** CI images are stocked by GitHub's imaging, not by a user's install history:
no consumer installers, no packed or DRM'd binaries, no third-party signed EXEs. They are a
better sample than one container, not a sample of the wild. Intel macOS went unsampled —
`macos-13` never scheduled (Intel runners are effectively unavailable) and was dropped from
the matrix. The Windows `e_lfanew` maximum is the number most likely to move again.

## 8. Reproducing

Scripts are self-contained; run them against `main` with the repo venv. The header parser
they share (`hdr.py`) is ~130 lines and implements only WBITS plus the first meta-block
header — everything that reaches a Huffman body is reported as undecided and handed to the
real decoder.

```python
# The whole finding in six lines.
import brotli
from archivey.internal.streams.codecs import _BY_STREAM_FORMAT
from archivey.types import StreamFormat

codec = _BY_STREAM_FORMAT[StreamFormat.BROTLI]
assert codec.content_probe(b"MZ" + b"\x90" * 4094)          # accepted
assert len(brotli.Decompressor().process(b"MZ" + b"\x90" * 254)) == 256 - 4
# ... because MZ\x90\x90 is a 4-byte header for an uncompressed meta-block of 2_171_061
# bytes, and the decoder just copies. Give it the bytes it asked for and it is a real file:
payload = bytes((i * 7 + 11) % 256 for i in range(2_171_061))
assert brotli.decompress(b"MZ\x90\x90" + payload + b"\x03") == payload
```

| script | what it produces |
| --- | --- |
| `hdr.py` | the RFC 7932 header parser used by everything below |
| `m1_validate.py` | §1's classification table; also the check that every class the parser calls invalid is accepted 0% by the real decoder |
| `m2_overrun.py`, `m6_residual.py` | §4's framing check, and §5's residual breakdown |
| `m3_variants.py` | §4's policy table (FP/FN across all probe variants) |
| `m4_prefixes.py` | §3: the `MZ` construction, encoder reachability, the 54 impossible first bytes |
| `m5_analytic.py` | §2's analytic derivation |
| `m7_chain.py` | §4's chain walk across file sizes |
| `m9_impact.py`, `m10_realworld.py` | §5: listing-vs-reading outcomes, and the real-file negatives |
| `m11_mz.py` | §3.1: real PE headers, and the exhaustive `e_cblp` disjointness check |
| `m13_dos.py`, `m15_full.py` | §3.1/§7: the 100-binary DOS-header survey and the STRONG-rule comparison (builds its own Go and MinGW PEs, pulls MSVC-built `.pyd`s from Windows wheels, and sweeps the machine for `MZ` files) |
| `m14_lfanew.py` | §7: the `e_lfanew` distribution and what bounding it is worth |
| `m12_wbits.py` | §4.1: emitted vs. requested `lgwin`, and the WBITS whitelist trade |

Scripts live in the session scratchpad, not the repo — they are measurement one-offs, and
the numbers they produced are recorded above. The two that would be worth keeping if the
proposal lands are `hdr.py` and `m3_variants.py`, as the seed of a regression test that the
gate's false-negative count stays at zero.

### The one script that *is* in the repo

`scripts/investigations/exploration/brotli_probe_field_survey.py` packages the header parser and every
survey above into one stdlib-only, read-only, Python 3.8+ file that runs on a bare system
interpreter — no venv, no archivey. It exists because three conclusions here rest on
corpora that one Linux container cannot make representative:

| what it collects | why this document needs it |
| --- | --- |
| PE/DOS fields + every candidate cue rule's verdict | §7's ranking turns on `e_lfanew`'s maximum (280 here, from 100 binaries with no installers, packers or signed EXEs) |
| WBITS of every `.br` file and WOFF2 payload found | §4.1 rejects WBITS whitelisting on 2 `.br` files and 12 fonts |
| header class of every file, + both gates' verdicts | §5's real-world false-positive rate — already corrected once by this script |
| Mach-O count | archivey's cue handles `MZ` and ELF only; a macOS SFX stub gets no cue at all |

Running it on Linux is what turned up the `/**\n` result in §5. Windows and macOS runs are
the ones still missing.

## 11. Residual after `probe-completeness-gate` (2026-08-25)

Re-ran `scripts/investigations/exploration/probe_residual_census.py` on this image after shipping
completeness + the chain walk, **and again after raising the completeness output drain
from 256 bytes to 64 KiB** (review F4; link cap 8, non-seekable `read_at` max offset
1 MiB unchanged):

| | count | share of tree |
| --- | --- | --- |
| files scanned | 150 623 | — |
| content-probe claims | 30 | — |
| genuine streams | 1 | — |
| **fabricated** | **29** | **0.019%** |

The previous post-gate census on this image (256-byte drain) was 30 / 147 601 (0.020%).
The larger drain rejects a few more fully-visible truncations before the walk; the tree
also grew slightly between runs. Compare with the post-first-block census on a smaller
tree: 128 fabricated (0.193%). Of the 29 survivors, 26 carry no `format_unconfirmed`
signal (PROBABLE Alone / compressed-first Brotli) — that is
`probe-provenance-unconfirmed`'s remaining argument. OLE/CFB and COFF above the prefix
still survive both rules by construction.

## 12. Residual after `probe-provenance-unconfirmed` (2026-08-25)

After keying `format_unconfirmed` / `PROBE_FORMAT_UNCONFIRMED` on probe-only provenance
(rather than `GUESS` confidence), the fabrication *count* is unchanged — this change does
not reject claims — but the honesty channel covers every uncorroborated probe hit.
Re-ran `scripts/investigations/exploration/probe_residual_census.py` on this image (default roots,
147 601 files):

| | count |
| --- | --- |
| content-probe claims | 30 |
| genuine streams | 1 |
| fabricated | 29 (0.020%) |
| probe-only fabrications (stamp on failure) | **29** |
| probe-only fabrications with **no** signal | **0** |

Confidence values are untouched; the previously-silent `PROBABLE` Alone / compressed-first
Brotli failures now stamp exactly as the `GUESS` class already did.

## Refs

- `src/archivey/internal/streams/codecs.py` — `_PROBE_PREFIX`, `_decodes_sample`,
  `BrotliCodec.content_probe`, `_ZLIB_HEADERS`, `_alone_header_plausible`
- `src/archivey/internal/streams/brotli_framing.py` — first-block gate + `chain_proves_invalid`
- `src/archivey/internal/detection.py` — `_peek_prefix`, `_make_probe_read_at`,
  `DetectionConfidence`, and where a probe result becomes the answer
- `src/archivey/internal/streams/peekable.py` — `DETECTION_LIMIT = 4096`
- `openspec/specs/format-detection/spec.md` — the normative probe requirements
- RFC 7932 §1.5 (bit order), §9.1 (WBITS), §9.2 (meta-block header)
