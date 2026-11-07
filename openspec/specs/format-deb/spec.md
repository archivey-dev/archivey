# Debian Package Support

## Purpose

Debian binary packages (`.deb`, `.udeb`, `.ddeb`) are read through the unified
`ArchiveReader` API as the files they install, the control files under `DEBIAN/`. The
reader is a built-in written against `archivey.formats` and reads the package's two tars
through the nested-archive hook (`ReaderContext.open_nested`). The format handbook is
`dev-docs/formats/deb.md`.

## Related specs

| Spec | Relationship |
| --- | --- |
| `format-ar` | The outer layer; `format=ArchiveFormat.AR` reads it raw |
| `format-tar` | The reader for the control and data tars |
| `format-plugins` | `ForwardStream.take` and `ReaderContext.open_nested` |
| `archive-data-model` | `ArchiveInfo.extra` keys `deb.package`, `deb.version`, `deb.architecture`; `HashAlgorithm.MD5` |

## Requirements

### Requirement: Read a Debian package as the files it installs

The deb backend SHALL read an ar archive whose first member is `debian-binary` in one
forward pass, from a file, a seekable stream or a pipe (`streaming=True`), reading its
control and data tars through `ReaderContext.open_nested`. It SHALL list the data tar's
members under their own names and the control tar's under `DEBIAN/`, as `dpkg-deb -R`
unpacks them, and SHALL NOT list `debian-binary`. `format=ArchiveFormat.AR` SHALL read
the ar layer instead. `ArchiveInfo.format_version` SHALL be the `debian-binary` version,
and `ArchiveInfo.extra` SHALL carry `deb.package`, `deb.version` and `deb.architecture`
from the control file's first paragraph.

#### Scenario: a package written by dpkg-deb

| Case | Expected |
| --- | --- |
| `hello-xz.deb` read from a pipe | `DEBIAN/control`, `DEBIAN/md5sums`, `DEBIAN/postinst`, then the data files, each read with its bytes; `format_version == "2.0"`; `extra["deb.package"] == "hello"` |
| The same file with `format=ArchiveFormat.AR` | `debian-binary`, `control.tar.xz`, `data.tar.xz` |

### Requirement: Check each installed file against md5sums

The deb backend SHALL give each data `FILE` that `DEBIAN/md5sums` lists its MD5 in
`member.hashes[HashAlgorithm.MD5]`, and a full read SHALL raise `CorruptionError` when
the data does not match. A line that is not an MD5 and a name SHALL be skipped.

#### Scenario: md5sums

| Case | Expected |
| --- | --- |
| A file whose bytes match its line | `verified == Verification.CHECKSUM` after a full read |
| A file whose line holds another file's digest | `CorruptionError` when the read reaches its end |
| A line with 32 non-hex characters | Skipped; the file it names has no digest |

### Requirement: Refuse what dpkg-deb refuses

The deb backend SHALL raise `UnsupportedFeatureError` for a format version whose major
number is not 2, `CorruptionError` when `debian-binary` is not the first member, when the
control tar does not follow it, or when a member whose name does not start with `_` sits
before the data tar. It SHALL skip `_` members and read nothing after the data tar. The
control file and `md5sums`, held whole, SHALL together count against
`ListingLimits.max_metadata_bytes`.

#### Scenario: refusals

| Case | Expected |
| --- | --- |
| `debian-binary` holds `3.0` | `UnsupportedFeatureError` |
| A `_gpgorigin` member between the tars | Skipped; the package reads |
| An `extra` member between the tars | `CorruptionError` |
| `max_metadata_bytes` smaller than the control file and md5sums | `ResourceLimitError` |

