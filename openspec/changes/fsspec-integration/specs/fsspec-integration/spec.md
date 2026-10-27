# fsspec integration

## ADDED Requirements

### Requirement: Remote sources are read through a bounded fetch planner

For an `fsspec.core.OpenFile` source (`archive-reading`), the `ArchiveSource` SHALL read
every byte through the file system's range reads (`cat_file`, or `cat_ranges` for
batched fetches), with fsspec's own file cache unused, and SHALL decide each fetch's
start and length itself:

| Rule | Behaviour |
| --- | --- |
| Sequential run | The first two reads of a run fetch what they ask for, and at least a fixed minimum fetch size (64 KiB). From the third read that continues the last fetch, each fetch doubles, up to a fixed maximum fetch size |
| Short forward gap | A forward seek no longer than `ArchiveyConfig.max_read_through` (an `int`, default 1 MiB; a negative value, a `bool`, a float or `None` raises `ArchiveyUsageError` when the config is built) continues the run instead of starting a new request |
| Jump | A backward seek, or a longer forward one, starts a new run at the minimum fetch size |
| Backend range hint | A span the backend declares it will read next is fetched in one request, up to the maximum fetch size, then continued as a run |
| Known spans of a whole-archive pass | Merged across gaps of at most `max_read_through`, and fetched with `cat_ranges` in groups whose total is at most the pass's maximum fetch; the next group is fetched once the previous one is consumed |

The fetched bytes one reader holds SHALL be bounded by a fixed constant that depends
neither on the archive nor on the number of volumes or open member streams: every source
the reader opens SHALL share one pool, and when more sequential runs are active than the
pool holds at the maximum fetch, the maximum fetch SHALL shrink so the pool bound holds.
When more runs are active than the pool holds at the minimum fetch, each further run
SHALL read unbuffered, one fetch of exactly the requested bytes per read with nothing
kept, until a window frees, so the bound holds at any number of streams. No byte SHALL
reach the reader except through those range reads: the planner opens no file object.
Hints SHALL change only how bytes are fetched, never which bytes a read returns, and SHALL
do nothing on a local source. The source facts are those of `archive-reading` §"The source
facts of an OpenFile".

The ZIP, 7z and ISO backends SHALL hint the index they read at open and each member's
stored span before reading it. The RAR backend SHALL hint each header position during
its listing walk.

#### Scenario: ceilings that follow from the format

Range requests exclude the size request. `F` is the maximum fetch in effect for the run.
The remote benchmark axis (`testing-contract`) checks these on every case; counts not
listed are held by its baseline.

| Archive | List | List and read one member |
| --- | --- | --- |
| ZIP, central directory within the last 64 KiB and the member within `F` | ≤ 2 requests | ≤ 3 requests |
| 7z, non-solid, header and member each within `F` | ≤ 2 requests | ≤ 3 requests |
| 7z, solid | ≤ 2 requests | bytes fetched ≤ (member end − folder start) + `F` |
| ISO, member within `F` | baseline | list + 1 request |
| RAR5, TAR, compressed TAR | bytes fetched ≤ archive size + `F` | the same; a compressed RAR member also spools the archive |

#### Scenario: concurrent streams share the pool

| Case | Expected |
| --- | --- |
| Eight threads read eight members of one remote ZIP | Each read returns its member's bytes; the pool bound holds; each fetch is at most pool / 8 |
| More concurrent member streams than the pool holds at the minimum fetch | Each read returns its member's bytes; the pool bound holds; the streams past the limit fetch once per read |
| `extract_all()` over a remote non-solid ZIP far larger than the pool | Fetched bytes held at any time stay within the pool bound |
| A remote 7z in 50 volumes read end to end | The pool bound holds for the reader, not per volume |

### Requirement: A changed remote object is caught or reported

When the source's file system can pin a version of the object, the planner SHALL pin the
version seen at open. When it forwards request headers and the object has an `ETag`, the
planner SHALL send `If-Match` with it on every fetch. When neither is possible, the reader
SHALL record `SOURCE_CHANGE_UNDETECTABLE` (`diagnostics`) at open, saying that a
replacement of the same length cannot be detected, and the planner SHALL compare the total
size on each fetch whose response reports it. A file system for which archivey does not
implement version pinning or header forwarding SHALL be treated as offering neither. A change that is detected SHALL raise; it MUST NOT return bytes of the new
object as bytes of the archive.

#### Scenario: changed object

| Case | Expected |
| --- | --- |
| Versioned store, object replaced mid-read | Reads continue from the pinned version |
| HTTP with `ETag`, object replaced mid-read | The next fetch raises |
| No version, no `ETag` | `SOURCE_CHANGE_UNDETECTABLE` at open; a length change raises `SourceChangedError` on the next fetch |
| `DiagnosticPolicy.STRICT`, no version, no `ETag` | Opens; the diagnostic is collected, not raised |

### Requirement: Multi-volume discovery over fsspec

When the source is one `OpenFile` of a multi-volume set, sibling discovery SHALL list the
parent directory through the source's file system once and SHALL apply the same naming
rules as local discovery (`archive-reading` §Multi-volume), giving the same set for the
same names. Each discovered volume SHALL be opened as its own `OpenFile` source. A file
system that cannot list a directory SHALL be treated as having no siblings.

#### Scenario: fsspec volume discovery

| Case | Expected |
| --- | --- |
| `memory://d/x.7z.001` with `x.7z.002`, `x.7z.003` beside it | One reader over all three; one `ls` of `memory://d` |
| `memory://d/q.part1.rar` with `q.part2.rar` and `q.part02.rar` | The same choice of part 2 as local discovery |
| HTTP first volume, server cannot list | Opens as a lone first volume, as a local lone volume does |

### Requirement: ArchiveyFileSystem exposes an archive as a read-only fsspec file system

`archivey.fsspec.ArchiveyFileSystem` SHALL subclass
`fsspec.archive.AbstractArchiveFileSystem` with protocol `archivey`:

```python
ArchiveyFileSystem(
    fo: str | os.PathLike | fsspec.core.OpenFile | BinaryIO,
    *,
    target_protocol: str | None = None,
    target_options: dict | None = None,
    format: ArchiveFormat | str | None = None,
    password: PasswordInput = None,
    encoding: str | None = None,
    config: ArchiveyConfig | None = None,
    policy: ExtractionPolicy | ExtractionPolicyStr = ExtractionPolicy.STRICT,
    **kwargs,
)
```

A `str` `fo` SHALL be opened with `fsspec.open(fo, protocol=target_protocol,
**(target_options or {}))`, so chained URLs (`archivey://m::s3://b/a.7z`) work. The
archive SHALL be opened once per instance, with `seekable_members=True` and
`concurrent_operations=True`. The reader SHALL be available as `fs.reader`. Unlike a
`str` passed to `open_archive()`, a `str` `fo` reaches whatever protocol it names.

The class SHALL set `cachable = False`, and the instance SHALL own its reader: `close()`,
and leaving `with ArchiveyFileSystem(...)`, SHALL close it, and collecting an instance
with no open member streams SHALL close it too.

The tree SHALL be the name view of `extract_all(dest, policy=policy)`: each path SHALL be
the relative path that policy's name transform gives the member, a duplicate name SHALL
show its current entry (`ArchiveMember.is_current`), and directories implied by member
paths SHALL exist. A member the policy refuses SHALL be absent, with the refusal recorded
on `fs.reader.diagnostics`. Behaviour that depends on a destination (`overwrite=`, existing
files, case-insensitive collisions) and `filter=` are outside the tree.

| Operation | Behaviour |
| --- | --- |
| `info(path)` | `name`, `size` (declared size, or `None`), `type` (`"file"`, `"directory"` or `"other"`), `mtime` (POSIX seconds) when known, and `member` (the `ArchiveMember`) |
| `ls`, `find`, `glob`, `walk` | From the tree above; no member data read |
| `open(path, "rb")` | A seekable member stream; backward seeks MAY re-decode (loud-slow-rewind) |
| A link that resolves to a member | Listed as the target's type with `islink: True` and `destination`; opens the target |
| A link that resolves to nothing | Listed as `"other"`; `open` raises `FileNotFoundError` |
| Missing path | `FileNotFoundError` |
| `open` on a directory | `IsADirectoryError` |
| Any write method, or a mode other than `"rb"` | `NotImplementedError` |
| A damaged member | archivey's own error from `read()`, unchanged |

An instance SHALL pickle as its constructor arguments and reopen the archive when
unpickled, when `fo` is a `str`, `PathLike` or `OpenFile` and the archivey arguments
pickle. A file-object `fo` SHALL raise `TypeError` on pickling, naming the reason.

#### Scenario: fsspec consumers

| Case | Expected |
| --- | --- |
| `pandas.read_csv("archivey://d/t.csv::memory://a.7z")` | Same frame as from the extracted file |
| `pyarrow.parquet.read_table` on a member through the file system | Same table as from the extracted file |
| A ZIP with members `a/../../x`, `/etc/y` and `a/b` twice, default `policy` (`STRICT`) | Tree holds `a/b` (current entry); `a/../../x` and `/etc/y` absent, each with a diagnostic |
| The same ZIP, `policy="standard"` | Tree also holds `etc/y` |
| 10 000 distinct `archivey://m::memory://a{n}.zip` URLs opened and every reference dropped | No reader stays open |
| `pickle.loads(pickle.dumps(fs))` with a URL `fo` | A working file system over the same archive |
| Two threads read two members at once | Both read their members' bytes |
