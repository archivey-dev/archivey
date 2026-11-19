## ADDED Requirements

### Requirement: List an installer package's payloads as their files

A macOS installer package (`.pkg`) or Xcode archive (`.xip`) SHALL be read as
`ArchiveFormat.PKG`: the XAR members, with each `Payload` and `Scripts` (at the top, or
in a top-level component folder) and a top-level `Content` replaced by the files of the
CPIO it holds, compressed with gzip or pbzx or not at all, listed under a folder of the
member's name (`app.pkg/Payload/...`), as `pkgutil --expand-full` unpacks it. A payload
that holds no CPIO SHALL be listed as it is. The listing SHALL check each expanded
payload's XAR checksum and raise `CorruptionError` when it fails. A payload file, or a
hard link's target, that extracts outside its folder SHALL raise `CorruptionError`.
`format=ArchiveFormat.XAR` SHALL list the XAR members as they are. Detection SHALL
answer `PKG` for XAR magic when the name ends in `.pkg`, `.mpkg` or `.xip`, or, for any
name but `.xar`, when the start of the table of contents names a `Distribution` or
`PackageInfo`, or a `Content` and a `Metadata`. The cost receipt SHALL say the listing
requires scanning and access is solid.

#### Scenario: Installer packages

| Case | Expected |
| --- | --- |
| A product archive with a pbzx Payload and a gzip Scripts | `Distribution`, `app.pkg/Bom`, `app.pkg/PackageInfo`, `app.pkg/Payload/...`, `app.pkg/Scripts/postinstall` |
| The same with `format=ArchiveFormat.XAR` | `app.pkg/Payload` and `app.pkg/Scripts` as files |
| A `.xip` | `Content/...` and `Metadata` |
| A payload byte changed in a stored chunk | `CorruptionError` naming the checksum, at listing |
| A payload file named `../Bom` | `CorruptionError` |
| A nameless XAR whose TOC holds `a.txt` and `Payload` only | `ArchiveFormat.XAR` |
