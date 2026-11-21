# Archive writing: the deferred design

**Status: not current truth.** Nothing here is implemented. There is no
`archivey.create`, no `ArchiveWriter`, and no writer module in `src/`.

This is the `archive-writing` capability spec as it stood before
`2026-09-02-retire-archive-writing-specs` removed it, plus the two per-format write
requirements that went with it. It was written as a contract for work that never
started, so it sat in `openspec/specs/` claiming a shipped surface — the same defect as
`format-zip`'s streaming-write requirement, at capability scale.

It is kept because the analysis is real and would otherwise be redone from scratch:
the `CompressionSpec` resolution matrix, the `add_members` conversion semantics, and the
`add_file` naming argument are all decisions someone reached once. Treat it as a
starting point for the writing phase's own exploration, not as a design to implement.
This page is the home for the writing work until an OpenSpec change takes it over. The
conversion design draft, which answers the entry gate below and replaces the
`add_bytes` / `add_stream` / `add_file` split, is
[`archive-conversion-design.md`](archive-conversion-design.md).
Writing is not a 1.0 requirement (`VISION.md`). The planned scope is an `ArchiveWriter`
ABC, ZIP and TAR writers (including compressed-tar output such as `w:zst`),
`CompressionSpec`, and streaming conversion (`tar.gz` to `zip` and back) with bounded
memory. §Before re-specifying below is the entry gate for that change.

## The writer surface as specified

```python
archivey.create(
    dest: str | Path | BinaryIO,
    format: ArchiveFormat,
    *,
    compression: CompressionSpec | None = None,
    password: str | bytes | None = None,
    encoding: str = "utf-8",
) -> ArchiveWriter
```

`format` was required — no inference from the destination name. `compression` set a
writer default that per-entry values override. `password` enabled encryption where the
target format supports it. `encoding` covered legacy non-Unicode path fields.
`ArchiveWriter` was a context manager finalizing on exit (ZIP writes its central
directory there).

Four ways to add an entry, deliberately named apart:

```python
def add_file(self, source: str | Path, *, name: str | None = None,
             recursive: bool = True, compression: CompressionSpec | None = None) -> None
def add_bytes(self, data: bytes | bytearray, name: str, *, modified: datetime | None = None,
              mode: int | None = None, compression: CompressionSpec | None = None) -> None
def add_stream(self, stream: BinaryIO, name: str, *, size: int | None = None,
               modified: datetime | None = None, mode: int | None = None,
               compression: CompressionSpec | None = None) -> None
def add_member(self, member: ArchiveMember, data: BinaryIO) -> None
```

`add_file` was named that way on purpose: a bare `add()` taking a path is ambiguous
against `add_bytes` / `add_stream` / `add_member`, and the ambiguity is worst in the
case that matters (a `str` that could be a path or content). With `recursive=True` a
directory source adds its whole tree; `name` overrides the archive-internal path.
`add_stream` streams without materializing the source, and `size` is optional but may be
required by formats that must write a size before the data. `add_member` copies the
member's representable metadata and reads bytes from `data`.

## Streaming conversion

```python
def add_members(self, source: ArchiveReader | Iterable[tuple[ArchiveMember, BinaryIO | None]],
                *, filter: MemberFilter | None = None) -> None
```

The point of the design. It accepts a reader directly or the pair iterable
`stream_members()` already yields, so converting an archive never requires materializing
a member list and handing it back to the writer.

The division of labour was explicit: **reader-side selection** happens through
`stream_members(members=...)`, **writer-side transformation** through `filter`, the same
`Callable[[ArchiveMember], ArchiveMember | None]` extraction uses. Returning `None`
skips the member.

The subtle rule, and the one most likely to be got wrong on a reimplementation: the
filter applies to a transient `.replace()` copy used for the written entry's identity,
while the original mutable member and its stream continue through the backend. That is
what keeps late-bound field updates (sizes and CRC arriving after the data) visible to
the caller — see [`formats/zip.md`](../formats/zip.md) §1 for why those fields are late
in the first place.

The rest of the conversion contract: consume sources sequentially; drive a reader
through `stream_members()` internally; respect solid-archive bounded-memory semantics;
pipe member data in chunks with a 1 MiB default; translate metadata directly; skip
member types the target format cannot represent with a `logging.WARNING` rather than an
exception; never buffer the whole archive. Per-member format-internal buffering was
allowed where the format forces it — a ZIP local header needing the CRC before the data
is the named case.

## The `CompressionSpec` model

```python
class CompressionLevel(Enum):
    STORE = "store"
    FAST = "fast"
    DEFAULT = "default"
    MAX = "max"

@dataclass
class CompressionSpec:
    algo: CompressionAlgorithm | None = None      # None = backend auto-selects
    level: int | CompressionLevel = CompressionLevel.DEFAULT

CompressionSpec.STORED       = CompressionSpec(algo=CompressionAlgorithm.STORED)
CompressionSpec.DEFLATE      = CompressionSpec(algo=CompressionAlgorithm.DEFLATE, level=6)
CompressionSpec.DEFLATE_MAX  = CompressionSpec(algo=CompressionAlgorithm.DEFLATE,
                                               level=CompressionLevel.MAX)
CompressionSpec.LZMA         = CompressionSpec(algo=CompressionAlgorithm.LZMA2,
                                               level=CompressionLevel.DEFAULT)
```

`algo` reuses `CompressionAlgorithm` from the read-side data model rather than minting a
writer enum. `level` is either numeric or a format-agnostic symbolic level, because a
caller who wants "as small as possible" should not have to know that ZIP's maximum is 9
and LZMA's is different.

Resolution:

| `algo` | `level` | Behaviour |
| --- | --- | --- |
| `None` | `STORE` / `FAST` / `DEFAULT` / `MAX` | Backend picks a format-appropriate available algorithm for that effort; `STORE` selects `STORED` |
| `None` | numeric | Format default algorithm at that level, or the algorithm the level implies |
| set | `STORE` | Resolves to `STORED`, with a `logging.WARNING` for the contradiction |
| set | `FAST` / `DEFAULT` / `MAX` | That algorithm, symbolic level mapped to the nearest concrete one |
| set | numeric | That algorithm at that level; out of range raises `ValueError` and is **not** clamped |

`compression=None` anywhere equals `CompressionSpec(algo=None, level=DEFAULT)`.

**No silent substitution.** An explicit `algo` whose backend is missing, or that the
target format cannot represent, fails fast at `create()` or at the first `add_*` that
would use it — `PackageNotInstalledError` or `UnsupportedFeatureError`. Degrading to the
format default would write an archive the caller did not ask for. With `algo=None` the
backend chooses, because then the caller expressed no preference to violate.

## The per-format write requirements that went with it

**ZIP — streaming write via data descriptors.** Set general-purpose flag `0x8`, write
placeholder CRC and sizes in the local file header, stream the data, then append the
real CRC-32 and both sizes after it. The size need not be known in advance, which is
what makes a non-seekable destination possible. Removed in
`2026-09-02-drop-unshipped-write-claims`; the read-path half of the same format fact is
on [`formats/zip.md`](../formats/zip.md) §1.

**TAR — streaming write.** "The backend SHALL support writing TAR archives, including
streaming writes", with the scenario "member data is written in archive order without
requiring a seekable destination". TAR needs no trailer fixup, so this is nearly free
for the format.

**Testing — round trip per writable format.** `create → extract → compare` for every
writable format, matching content and metadata within the format's documented timestamp
and permission limits, with ZIP and TAR rows and a rule that a new writable format adds
its row before being considered supported. Worth reinstating verbatim when there is a
writer to test.

## Never resolved

Two questions the spec left open:

- **Per-entry `compression` on stream-compressed containers.** For `tar.gz` / `tar.zst`
  the codec is a property of the outer stream, so a per-entry algorithm is meaningless.
  Error or warn-and-ignore? The leaning was `ValueError` on an explicit per-entry algo,
  with the writer-level `CompressionSpec` selecting the outer codec.
- **`password=` on a format whose writer cannot encrypt.** Stdlib `zipfile` cannot write
  encryption at all, so this must fail at `create()` rather than at the first member. The
  open part is the error type (`UnsupportedFeatureError` vs `UnsupportedOperationError`)
  and whether a `SUPPORTS_PASSWORD`-style field on the write backend should enforce it
  centrally, mirroring the read side.

## Before re-specifying

Two explorations are the entry gate for a writing spec, both because they shape the API
and are expensive to retrofit:

- **Reproducible output** — `SOURCE_DATE_EPOCH`, stable member ordering, normalized
  metadata. `IDEAS.md` calls this the build-tool adoption wedge.
- **The metadata-fidelity boundary** — xattrs, ACLs, resource forks. Read-side promotion
  is additive and can wait; write-side fidelity has to be a day-one decision because it
  shapes `add_member` and the round-trip contract. Threat model C3.

Neither is addressed anywhere above, which is the strongest argument for treating this
document as a starting point rather than a plan.

## References

- Removed by `openspec/changes/archive/2026-09-02-retire-archive-writing-specs/` and
  `2026-09-02-drop-unshipped-write-claims/`
- [`IDEAS.md`](../IDEAS.md) §Writing
- [`history/PLAN.md`](../history/PLAN.md) §Phase 9, the pre-0.2.0 roadmap entry this page replaces
- [`threat-model.md`](../threat-model.md) C3 (metadata fidelity)
- [`history/ARCHITECTURE.md`](../history/ARCHITECTURE.md) §5.4 — why writing is create-only
  and ZIP append is refused
