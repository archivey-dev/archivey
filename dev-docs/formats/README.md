# Format and topic handbook

Living pages, rewritten in place: what archivey does for one format, or for one
cross-cutting topic, and why. Read the page for the format or topic you are changing; the
specs under `openspec/specs/` stay the machine-checkable contract.

**Create a page when a change needs one**, not before: `dev-docs/formats/<format>.md` or
`dev-docs/topics/<topic>.md`, **in that same PR**. Do not add empty pages or directories.
For a format or topic that has no page yet, point briefs at
[`code-map.md`](../code-map.md), the threat model, and the best ADR or investigation.

## The pages

Formats:

- [`zip.md`](zip.md) — the first page, and the worked example for the shape below.
- [`rar.md`](rar.md) — the only format whose read path runs an external program.
- [`7z.md`](7z.md) — the format whose header is a decode program.
- [`tar.md`](tar.md) — no index, archivey's own header walker, and how archivey decides
  why a walk ended.
- [`iso.md`](iso.md) — a filesystem read through a library written to author it.
- [`dmg.md`](dmg.md) — a UDIF image, recognised by the `koly` block and refused.
- [`single-file.md`](single-file.md) — the stream codecs as one-member archives, with a
  page per codec: [gzip](gzip.md), [bzip2](bzip2.md), [xz, lzip and LZMA Alone](xz.md),
  [zstd and LZ4](zstd-lz4.md), [Brotli](brotli.md), [`.Z`](unix-compress.md).
- [`directory.md`](directory.md) — a live tree behind the archive API, read at walk time
  and again at open.

Topics:

- [`detection.md`](../topics/detection.md) — how a source's format is decided, in what
  order, and at what cost.
- [`prefixed-archives.md`](../topics/prefixed-archives.md) — archives that do not start
  at byte 0.
- [`stream-ownership.md`](../topics/stream-ownership.md) — which wrapper closes its
  inner.
- [`exception-handlers.md`](../topics/exception-handlers.md) — when a blind
  `except Exception` is right in `src/`, and which shape it takes.
- [`process-isolation.md`](../topics/process-isolation.md) — which native decoders run
  in a child process, how the children are reused, and what a caller sees when one dies.

## Format page structure

Settled by writing [`zip.md`](zip.md) first and taking the shape the material actually
had. Sections are numbered so a brief can cite `zip.md` §2.3.

| Section | Holds |
| --- | --- |
| **At a glance** | Support, costs, dependencies, refusals. Also **anything a reader would reasonably expect and will not find** — a capability the user docs imply, a guarantee the code does not actually enforce, an optimization the shape of the format suggests and nobody built. State it as behaviour, not as a spec delta: the specs are being phased out as a claim-bearing surface, so "the spec says X and we do Y" dates badly where "we do Y" does not |
| **1. Shape** | The two to four structural properties that generate everything else, each with its consequences attached in the same breath. Not a spec reproduction; the altitude specs skip |
| **2. The pipeline here** | Fixed subsections — identify · open and list · member data · extract · write. Each says *who does the work*, *what is format-specific rather than general*, and *what is refused*. "Nothing here is format-specific" is a legitimate and useful answer. Member-metadata mapping lives under *open and list*. A stage that hands work to a **separate process** answers a fourth question — *what crosses the boundary*, in both directions — because none of the first three reach it: [`rar.md`](rar.md) §2.3 is argv construction one way and an exit code plus a byte count the other, and that is the page |
| **3. In the wild** | Variants, producers and what they get wrong, files that are secretly this format, corpus evidence with its provenance |
| **4. Threat surface** | Format-specific attack surface only; link the [`threat-model.md`](../threat-model.md) property or non-guarantee section |
| **5. Sharp edges** | *Symptoms someone observes*, each tagged **format** (inherent) / **library** (upstream or replace the library) / **archivey** (ours), so a reader can stop thinking about what they cannot fix. Details and fix plans stay behind the register link. **One table, not two**: a reader arrives with a symptom and does not yet know whether it is a bug or the format, so the tag sorts each row after they have found it rather than making them pick the right list first |
| **6. Decisions** | Choice → why → rejected alternative. Light bullets, not ADRs |
| **7. Open questions** | What we do not know and cannot settle by reading the code — each with what it would change and what would answer it. When there is nothing honest to put in it, keep the heading with one line saying none are open, so the numbers of §8 and §9 stay what briefs cite |
| **8. Verify** | The command that runs this format's tests, and how to build or regenerate its fixtures. No list of the tests that pin each claim: tests are found by their folder and file name |
| **9. References** | External spec sections *with numbers*, our investigations, upstream issues |

Four rules the shape depends on:

- **Never separate a structural fact from its consequence.** The strongest grouping force
  in the ZIP material was causal — one property generated eight downstream behaviours. A
  separate "consequences" section breaks the chain and makes the reader re-derive it.
- **No performance numbers.** They are the most volatile thing on the page and they rot
  into a fourth disagreeing source. Verify carries the command instead.
- **Behaviour here, status behind the link.** The page says what a caller sees and how
  fixable it is; `known-issues.md` keeps live defects, and the format's threat surface
  links the `threat-model.md` design.
- **State the rule, not the tests that pin it.** A page names no test paths or test
  names, in §8 or anywhere else: tests are found by their folder and file name, so a list
  is a second copy that drifts. This replaces the test links that step 1 of
  [`discussions/2026-09-specs-to-handbook-and-tests.md`](../discussions/2026-09-specs-to-handbook-and-tests.md)
  asked for.

Stream formats (brotli, lzma, …) get one page each and may need a different shape; take
this as the starting point, not a template to satisfy.

## Topic pages

Topic pages are **not** format pages with the nouns swapped, and
[`prefixed-archives.md`](../topics/prefixed-archives.md) — written alongside `zip.md` and
shaped by it — came out looser: shapes in the wild, the mechanism and its tiers, the cost
argument, *where the formats differ*, sharp edges, decisions, references. Take the
conventions rather than the section list: the where-it-lives tags, no performance
numbers, status behind the register link.

The split that matters is the same one in both directions. **A format page keeps what the
format's own structure decides; the topic page keeps the shared machinery.** For prefixed
archives that put the cue set, the scan bound, the budget tiers and the validation argument
on the topic page, and left ZIP with its needle, its validator and its two offset
conventions — because those follow from ZIP locating itself from the end, and no other
format has them.

A topic page may name format behaviour freely where that is what explains the mechanism;
what it must not do is restate a format page or a register. The reverse is also true — a
format page links the topic and keeps the residue, which is why the pipeline subsections in
§2 are where those links naturally sit.

**Docs with code:** if a PR makes a handbook or published-doc **claim false**, update that
page in the **same PR**. Do not mint a new ADR or OpenSpec essay just to record the
change of mind.
