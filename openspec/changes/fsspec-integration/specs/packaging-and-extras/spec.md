# packaging-and-extras — the fsspec entry point

## ADDED Requirements

### Requirement: The base package registers the archivey fsspec protocol

The base distribution SHALL declare the entry point
`[project.entry-points."fsspec.specs"] archivey = "archivey.fsspec:ArchiveyFileSystem"`,
so fsspec resolves the `archivey` protocol without the caller importing archivey.

fsspec SHALL NOT be a runtime dependency of the base package, and SHALL NOT be added to
any extra: every caller who reads remote archives already installs a file system package
(`s3fs`, `gcsfs`, `adlfs`) that depends on fsspec. `archivey.fsspec` SHALL import fsspec
at module import, so a missing fsspec raises the interpreter's own `ModuleNotFoundError`
for `fsspec`. It is not a `PackageNotInstalledError`, whose hint names an extra, and no
extra provides fsspec. No other archivey module SHALL import fsspec.

#### Scenario: fsspec packaging matrix

| Case | Expected |
| --- | --- |
| `pip install archivey`, fsspec not installed, `import archivey` | Works; no fsspec import |
| fsspec not installed, `import archivey.fsspec` | `ModuleNotFoundError` for `fsspec` |
| fsspec installed, `fsspec.filesystem("archivey", fo=...)` without importing archivey | Resolves `ArchiveyFileSystem` through the entry point |
| Any extra, `[all]` included | Does not pull in fsspec |
