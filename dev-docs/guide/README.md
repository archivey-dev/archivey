# Archivey from the inside

A guided tour of how archivey works, for someone who knows Python but not this codebase,
and not the archive formats either. It explains the moving parts in plain words, says
where each one lives, and says why it is built that way. It goes deep into the
architecture. It stays out of the byte-level parsing of each format and the insides of
each decompressor: those are in the format handbooks.

If you remember one thing, make it this picture:

```
 what the caller passes          what archivey builds from it
 ─────────────────────           ────────────────────────────
 a path, a stream, a URL   ──►   ArchiveSource        (one object for every kind of source)
                                     │
                                     ▼
                                 detect_format()      (which format is this?)
                                     │
                                     ▼
                                 a reader             (one per format, on a shared base class)
                                     │  lists members once, hands out the same objects
                                     ▼
                                 ArchiveMember        (name, type, size, times, links…)
                                     │  reader.open(member)
                                     ▼
                                 ArchiveStream        (the member's bytes, decoded as you read,
                                                       checked against the stored checksum)
```

Every format goes through the same five boxes. The differences between ZIP, TAR, 7z
and the rest are inside the reader box and the stream box. Everything else (limits,
name checks, link handling, extraction, diagnostics) is written once and shared.

## The pages

Read them in order the first time. Each page starts with a short "in one minute"
summary, so you can skim and come back.

| Page | What it answers |
| --- | --- |
| [1. Vocabulary](01-vocabulary.md) | The words the code and the docs use everywhere, and which ones mean something different from what you would guess |
| [2. Where things live](02-where-things-live.md) | The source tree, one directory at a time: what each part is for, which files are big and why, and the two boundaries that matter |
| [3. The life of one `open_archive` call](03-life-of-an-open.md) | One call followed from the caller's argument to the first decoded byte, with the function that does each step |
| [4. Readers and the member list](04-readers-and-members.md) | The shared base class, the one member list per reader, walks and passes, link resolution, and what keeps two operations from stepping on each other |
| [5. Formats and plugins](05-formats-and-plugins.md) | The two ways a format is written (the internal tier and the `archivey.formats` interface), how formats register, and how a caller turns readers on and off |
| [6. Streams and codecs](06-streams-and-codecs.md) | How member bytes are produced: slices, the codec registry, the seekable decoder engine, the public stream that checks checksums, accelerators and child processes |
| [7. Pipes, files and the compromises between them](07-pipes-and-files.md) | Why the API has `streaming=`, `seekable_members=` and `concurrent_operations=`, what each format can do from a pipe, and every place the code had to bend |
| [8. Security](08-security.md) | The layers that keep a hostile archive from writing outside the destination, eating all memory or crashing the process, and where the guarantees stop |
| [9. Errors, diagnostics and verification](09-errors-and-diagnostics.md) | How a library's exception becomes an archivey exception, what a diagnostic is, and how "this member checked out" is decided |
| [10. Decisions and why](10-decisions.md) | The maintainer's principles and the big decisions, each with its reason and where it is recorded |
| [11. Bugs that taught us something](11-bugs-and-lessons.md) | The bugs worth remembering, what caused each one, and the rule it left behind |
| [12. Non-obvious choices](12-non-obvious-choices.md) | A "wait, why…?" list: the things that look wrong or over-built until you know the reason |

## How this guide overlaps with the other docs

This guide is an entry point, not a new source of truth. Each rule it mentions has one
home somewhere else, and the guide links to it. When this guide and the home of a rule
disagree, the home wins, and the guide is the one to fix.

| Doc | What it owns | What the guide does with it |
| --- | --- | --- |
| [`docs/how-it-works.md`](../../docs/how-it-works.md) | The user's view of detection, parsing and decoding, in a few pages | The guide starts where that page stops: it names the classes and files, and explains the parts users never see |
| [`code-map.md`](../code-map.md) | "I must change X; which file do I open?" | The guide explains what the files are for and how they fit; the code map stays the task → file index |
| [`design-rules.md`](../design-rules.md) | The maintainer's rules (DR-0 to DR-25), each with its rulings | [Page 10](10-decisions.md) tells the story behind the main ones and cites the DR number; it does not restate the rule text |
| [`decisions/`](../decisions/index.md) (ADRs) | Rare repo-wide decisions | Cited where a page relies on one |
| [`threat-model.md`](../threat-model.md) | Every defended property, accepted risk and open gap | [Page 8](08-security.md) is a map of the security layers that points into it |
| [`formats/`](../formats/README.md) handbook pages | What is true for one format: its layout, its quirks, its decisions | The guide stays format-neutral and uses formats only as examples |
| [`topics/`](../formats/README.md) pages | Deep dives: [detection](../topics/detection.md), [stream ownership](../topics/stream-ownership.md), [verification](../topics/verification.md), [process isolation](../topics/process-isolation.md), [prefixed archives](../topics/prefixed-archives.md), [exception handlers](../topics/exception-handlers.md) | The guide gives the short version and links to the topic page for the rest |
| [`docs/adding-a-format.md`](../../docs/adding-a-format.md) | How to write a format against `archivey.formats` | [Page 5](05-formats-and-plugins.md) explains what happens on archivey's side of that interface |
| `openspec/specs/` and `openspec/changes/archive/` | The behaviour contract, and the design of each past change | Cited for the "why" of a design; the guide does not restate requirements |
| [`known-issues.md`](../known-issues.md) | Live defects, ours and upstream | [Page 11](11-bugs-and-lessons.md) covers fixed bugs and their lessons; live ones stay there |

What only the guide has: the explanation of how the pieces fit together, in one place,
in plain language. That is also the rule for what to add here later. If a fact is about
one format, it goes on that format's handbook page. If it is a rule, it goes to the doc
that owns rules. If it explains how two parts of the code relate, it can go here.

## Keeping it true

- **Names, not line numbers.** The guide names files, classes and functions, never line
  numbers, so a refactor that keeps the names keeps the guide right.
- **Check before you trust.** Like every doc, this one can drift. When a sentence here is
  the reason you are not worried about something, read the code it names first
  ([page 11](11-bugs-and-lessons.md#a-doc-claimed-something-could-not-happen) has the
  bug that taught us this).
- **Update it in the PR that changes the picture.** A PR that moves a boundary, renames a
  layer or changes how a pass works updates the page that describes it.
