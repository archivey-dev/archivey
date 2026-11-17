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
from the control file's first paragraph once the listing or iteration has read the
control tar, on any source.

#### Scenario: a package written by dpkg-deb

| Case | Expected |
| --- | --- |
| `hello-xz.deb` read from a pipe | `DEBIAN/control`, `DEBIAN/md5sums`, `DEBIAN/postinst`, then the data files, each read with its bytes; `format_version == "2.0"`; `extra["deb.package"] == "hello"` |
| The same file with `format=ArchiveFormat.AR` | `debian-binary`, `control.tar.xz`, `data.tar.xz` |
| A seekable package before `members()` | `extra` empty, `format_version == "2.0"`; the `deb.*` keys after it |

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
before the data tar. It SHALL raise `CorruptionError`, with the member's name in
`member_name`, for a data-tar member whose path, with its root dropped, its `..`
resolved and `/` and `\` both read as separators, has a first segment that equals
`DEBIAN` once both are folded as the extraction collision key folds a name (NFC,
case-folded, a trailing dot or space trimmed), and for a data-tar hard link whose target
does by the same test. It SHALL raise `CorruptionError` in the same way for a
control-tar member, or hard link target, whose `DEBIAN/`-prefixed path, read the same
way but not folded, does not have exactly `DEBIAN` as its first segment. `dpkg-deb -R`
refuses these packages: it will not unpack the control tar into a `DEBIAN` path that the
data tar made, and GNU tar refuses a `..` name. Reading `\` as a separator, dropping a
drive root and folding the data side are stricter than `dpkg-deb -R`, so that no
extraction rewrite and no filesystem moves a member from one tar's tree into the
other's. It SHALL skip `_` members and read nothing after the data tar. `debian-binary`,
the control file and `md5sums`, held whole, SHALL together count against
`ListingLimits.max_metadata_bytes`, each checked by its declared size before it is read.

#### Scenario: refusals

| Case | Expected |
| --- | --- |
| `debian-binary` holds `3.0` | `UnsupportedFeatureError` |
| A `_gpgorigin` member between the tars | Skipped; the package reads |
| An `extra` member between the tars | `CorruptionError` |
| `max_metadata_bytes` smaller than the control file and md5sums | `ResourceLimitError` naming the bytes held in all |
| A `debian-binary` header declaring 9 999 999 999 bytes | `ResourceLimitError` before the member is read |
| A data tar holding `./DEBIAN/control`, `/DEBIAN/x`, `./DEBIAN/` or a `DEBIAN` symlink | `CorruptionError` naming that member, when the listing reaches it |
| A data hard link to `DEBIAN/control` | `CorruptionError` naming the link and its target |
| A data tar holding `usr\..\DEBIAN/postinst`, `C:/DEBIAN/control`, `DEBIAN./postinst`, `DEBIAN /postinst` or `debian/postinst` | `CorruptionError`, stricter than `dpkg-deb -R` |
| A control tar holding `../usr/x` | `CorruptionError` naming `DEBIAN/../usr/x` |
| A control hard link to `../usr/a` | `CorruptionError` naming the link and its target |
| A control tar holding `../debian/x` or `../DEBIAN./x` | `CorruptionError`: the control side is not folded |
| A data tar holding `debianx/x`, `usr/DEBIAN/x`, or a symlink to `../DEBIAN/control` | Listed and read |

