## MODIFIED Requirements

### Requirement: Report bytes after a RAR end-of-archive block

After an intact end-of-archive block and any data area it declares, the walk SHALL
look at most 1 MiB further in that volume, and no further than the payload end
(`archive-reading`, *Honour detection payload_offset at open*): a code-signed
self-extractor's certificate table is identified, not data after the archive, and SHALL
raise no diagnostic. A non-zero byte in the part it looks at SHALL emit one
`ARCHIVE_TRAILING_DATA` per volume after the members (`format="rar"`,
`expected_marker="zeros_to_eof"`, `observed_kind="nonzero"`, `observed_bytes` the
offset of that byte past the end block). It is a warning by default and raises under
`DiagnosticPolicy.STRICT` (DR-3). Zero bytes after the block SHALL be silent, and a
byte at 1 MiB or more past it goes unseen. With encrypted headers the block ends after
its AES padding. In a set the message names the volume. A damaged end block is taken
for one only when nothing but zeros follows it (previous requirement), so this check
does not apply to it, and a RAR 1.5-4 archive with no end block has nothing after its
last header to check. `unrar` 7.00 says nothing about these bytes. 7-Zip 23.01 warns
"There are data after the end of archive" for any tail, zeros included; archivey keeps
an all-zero tail silent, because `rar` pads volumes with zeros.

#### Scenario: RAR trailing bytes

| Case | Default policy | `STRICT` |
| --- | --- | --- |
| RAR 1.5-4 or RAR5, headers plain or encrypted, ending at the end block | Nothing | Opens |
| 4 KiB of zeros after the end block | Nothing | Opens |
| `b"JUNK"` after the end block, or after zeros within 1 MiB | `ARCHIVE_TRAILING_DATA`, `observed_bytes` = zeros skipped | `DiagnosticRaisedError` |
| `b"JUNK"` after volume 1 of a set | Full listing; one `ARCHIVE_TRAILING_DATA` naming volume 1 | `DiagnosticRaisedError` |
| Non-zero byte at 1 MiB or more past the end block | Nothing | Opens |
| Signed PE SFX (WinRAR's installer): end block, certificate (`payload_end` known) | Nothing | Opens |
| Signed PE SFX: end block, `b"JUNK"`, certificate | `ARCHIVE_TRAILING_DATA` for `JUNK`; nothing for the certificate | `DiagnosticRaisedError` |

