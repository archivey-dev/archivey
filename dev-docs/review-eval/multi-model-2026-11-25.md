# Multi-model PR reviews, 2026-11-18 to 11-25

The evidence behind [review-loop.md §Second-model
reviews](../review-loop.md#second-model-reviews) and the verdict rule in
`code-review-skill` §4. AG = Antigravity.

Source: `get_reviews` bodies on 17 PRs (finding
index lines only; inline threads not re-read). Reach classes:

- **hostile-bytes**: an archive's bytes trigger it. Always real (threat model).
- **normal-use**: ordinary calls, ordinary threading, real file-likes, real platforms.
- **caller-misuse**: the caller's own code does something odd: a callback that re-enters
  the reader, retries after its own callback raised, `__index__` objects, GC finalizer
  timing, Windows 8.3 names plus hard links under TRUSTED.
- **fix-introduced**: created by an earlier round's fix (or a merge) on the same PR.

## Per PR

| PR | Opus rnds | Codex rnds | AG rnds | Notable |
|---|---|---|---|---|
| 1833 concurrency 1 | 4 | 4 | 1 | Codex C1 🔴 callback re-entry (caller-misuse, but AssertionError/walk motion) took 3 Codex rounds of variants (extraction cb -> link-resolution cb -> logging handler); ended only when the internal window stopped granting anything (structural fix). Opus K1/K4 same class. AG: 2 nits-ish. |
| 1834 concurrency 2 | 3 | 5 | 3 | Real: C1-C3 close vs running calls, C8/C9 races, A2 `closed` wrong, A3 error type, C10. Caller-misuse: C2 (info after failed open from callback), C7, A1 (callback closes sibling -> deadlock), C11/C14 (GC finalizer). Fix-introduced: A5 (from A2 fix), C12 (from C10 fix), C13 + its recheck (from C11 fix). No Opus round between external rounds 11:06-14:05Z. |
| 1830 plan | 3 | 3 | 3 | Design moved twice mid-review (davi rulings); many findings were text kept in sync with the moving design. |
| 1826 plan | 0 | 1 | 1 | Codex C1-C6 (policy/trust, pilot) vs AG A1-A12 (fit against code: kernels, string collisions, detection). Overlap about 1-2 of 18. Best evidence the models look differently. |
| 1806 LZX | 2 | 0 | 1 | AG A1 🔴 real bypass (set_output_size after realign error) that Opus missed after 1200 fuzz cases. PR then closed for the 1825 trim. |
| 1825 codecs trim | 1 | 0 | 1 | Both conditional on nits. The fast path working. |
| 1809 codecs args | 2 | 1 | 0 | Codex C1-C7 all direct-package-caller arg parity (caller-misuse). PR closed by the trim: rounds spent on code that was cut. |
| 1783 kernel API | 1 | 3 | 0 | Opus conditional on 7 doc/nit items. Codex C1 🔴 (.Z bad codes at EOF hidden), C2 (BCJ2 errors lost), C3 (LZX pad byte): real, normal-use/hostile-bytes. C14, C15->C22 fix-introduced. C4-C6, C11, C19 polished standalone API later trimmed. |
| 1728 pipe=True | 1 (💬) | 3 | 0 | Opus 💬 Comment with 3 🟡 incl. K3 functional -> loop stopped, no Opus fix round. Codex C3 🔴 (remote change dropped, walk reports success), C1, C2, C11, C12 real normal-use. C14 merge-introduced. |
| 1782 placements refactor | 4 | 3 | 0 | Opus K1 🔴 (hard link + caller symlink). Codex CX1 Windows short names (caller-misuse/platform corner), CX2 real (file replaced by dir), CX3 perf whose fix introduced CX6. |
| 1757 callback stop | 5 | 2 | 1 | +Cursor. Every external finding is one class: the caller's on_source_read raises, the caller retries (caller-misuse). 13+ findings over 9 reviews. |
| 1829 follow-up | 1 | 0 | 0 | Clean. |
| 1794 DMG tables | 2 | 3 | 0 | Codex CX1 real design point (shared tracker), CX3 merge conflict. |
| 1816 LZFSE child | 1 | 0 | 0 | +Cursor. Clean. |
| 1756 salvage base | 2 | 3 | 0 | +Cursor G1-G9. Codex C1/C2 real minor. |
| 1767-1770 salvage | 5/5/2/3 | 0 | 0 | Opus alone, measured hostile-bytes resource bugs (real). Fix-introduced: 1767 K6 🔴, 1768 K5/K6/K9, 1769 K3, 1770 K9/K10. Still open: design decisions (#1760/#1765, K6) never ruled. |

Earlier audit (11-22, 1711/1715/1759/1779/1744): Codex 35 findings, 14 real bugs, real
bug in 4 of 5 PRs; 1715 CX4 took 4 rounds of narrower variants.

## What the numbers say

1. **First looks by a second model pay; rechecks mostly re-review fixes.** Codex's first
   look found a real, non-misuse bug Opus had passed on 1783, 1728, 1794, 1834, 1782,
   1756 (6 of 8 implementation PRs; 1757 and 1809 were misuse-only). AG's first look
   found one on 1806 and 1834. External rechecks (round 2+) found mainly fix-introduced
   bugs and narrower misuse variants.
2. **Fixes create the tail.** About 20 later-round findings in the sample were caused by
   an earlier fix or merge. Opus fix rounds catch these well and cheaply (salvage PRs),
   but on 1834 the fixes went straight back to Codex/AG with no Opus round between.
3. **Point fixes to a class keep failing.** 1833 C1 (4 rounds), 1834 C1/C11/C13, 1757
   C3, 1767 K2 (4 rounds), 1715 CX4 (4 rounds). Each ended when the invariant was
   enforced in one place.
4. **Models are complementary, not ranked.** Opus measures (bombs, fuzzing, timing) and
   is strongest on hostile bytes. Codex traces contracts statically (errors,
   diagnostics, budgets, locks) and finds silent wrong results. AG checks claims against
   the code and catches spec/doc drift; on 1806 it found what Opus's fuzzing did not.
   Opus also shares the implementer's model family, so its blind spots correlate with
   the author's.
5. **Review spent on undecided or later-cut code**: 1806, 1809, parts of 1783 (trimmed
   by 1825); 1767-1770 (5 rounds each, design still unruled); 1830 (design changed twice
   mid-review).
6. **💬 Comment hid work**: 1728 R1, 1830 R1/R3, 1782 R4 each carried 🟡 findings, and 💬
   stops the loop like an approval, so the fixes were never re-read by Opus.
7. **Codex posting**: the skill never says the reviewer posts its own review (§6 says "a
   second agent posts this review"), so Codex answers in chat.
