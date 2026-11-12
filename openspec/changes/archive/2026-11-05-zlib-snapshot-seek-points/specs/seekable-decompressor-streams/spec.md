## ADDED Requirements

### Requirement: gzip decodes record zlib snapshot points

On declared seek demand, the standard library engine SHALL record a seek point inside a
gzip member about every MiB of output, whose state is a `zlib` `decompressobj.copy()`
taken between two feeds. A decode resumed from one MUST still check the member's CRC-32
and ISIZE, which the copy carries. A decompressor in a decoder child has no `copy()` and
records none.

#### Scenario: snapshot matrix

- **WHEN** a gzip stream is read and seeks back
- **THEN** it behaves as below

| Case | Expected |
| --- | --- |
| One-member gzip, read forward with seek demand, then seek back | Resumes at the nearest snapshot before the target |
| Trailer CRC-32 damaged, seek back to a snapshot and read on | `CorruptionError` at the end of the member |
| Stream opened without seek demand | No snapshots |

### Requirement: Snapshot points have a memory cap

Snapshot points SHALL hold at most 32 MiB in one stream. Past that, only they are
thinned, to half of it, by doubling their spacing, later ones keep that spacing, and no
diagnostic is reported. A snapshot closer than half its spacing to a point the stream
holds SHALL NOT be recorded.

#### Scenario: snapshot cap matrix

- **WHEN** snapshots accumulate in one stream
- **THEN** they are kept as below

| Case | Expected |
| --- | --- |
| A second pass over a span already read | No snapshot within half the spacing of one held |
| Snapshots past 32 MiB | Thinned to half of it, spacing doubled; no diagnostic |

## MODIFIED Requirements

### Requirement: rapidgzip is the only gzip and bzip2 accelerator

The system SHALL use `rapidgzip` as the only optional accelerator library for
both gzip and bzip2: gzip through `rapidgzip.RapidgzipFile`, bzip2 through
`rapidgzip.IndexedBzip2File`. It MUST NOT import the standalone `indexed_bzip2`
package because loading both C++ cores in one process can corrupt the heap on
macOS. `use_indexed_bzip2` remains the bzip2 configuration flag but selects the
rapidgzip-bundled decoder.

When rapidgzip is unavailable or disabled, gzip and bzip2 SHALL use stdlib
decoders; backward seek is serviced by re-decompressing from the start, or for gzip
from the nearest member start, BGZF block start or zlib snapshot it knows (§"gzip member
starts are seek points", §"BGZF members are walked without decoding", §"gzip decodes
record zlib snapshot points"), and MUST not degrade silently.

The system MUST NOT run any rapidgzip decoder in the caller's process. The bzip2 decoder
SHALL run in a child process with the same rules as the DEFLATE family's (next
requirement): the child opens a path source itself, a stream source stays in the caller's
process, a child that dies on the data is a verdict the standard library takes over from,
and where no child can be started `AUTO` decodes with the stdlib backend, logging one
warning per process that names `use_indexed_bzip2=OFF`, and `ON` raises
`ResourceUnavailableError`. No crash of that decoder has been seen; it is isolated as a precaution,
because it comes from the same library as the DEFLATE decoder, whose crashes cannot always be
avoided. A maintainer script SHALL run each rapidgzip decoder
in-process on damaged input in a watched process and report every crash by its
signature, so that whether the isolation is still needed stays measurable.

#### Scenario: accelerator matrix

| Case | Expected |
| --- | --- |
| `use_rapidgzip` enabled and package installed | gzip seeks without full re-decompression |
| `use_indexed_bzip2` enabled and rapidgzip installed | bzip2 uses `rapidgzip.IndexedBzip2File` in a child process; the caller's process imports neither rapidgzip nor standalone `indexed_bzip2` |
| `use_indexed_bzip2=AUTO`, no child process can start | stdlib decoder; one warning per process naming `use_indexed_bzip2=OFF` |
| `use_indexed_bzip2=ON`, no child process can start | `ResourceUnavailableError`; never decoded in-process |
| rapidgzip absent or flag `OFF` | stdlib decoder; backward seek re-decompresses from the start, or from a known gzip member start or snapshot, and warns when it re-decodes past the threshold |
