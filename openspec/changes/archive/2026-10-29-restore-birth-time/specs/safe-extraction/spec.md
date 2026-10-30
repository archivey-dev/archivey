## ADDED Requirements

### Requirement: Extraction restores member times where the system allows it

When extraction sets a file's or a folder's modification time from
`ArchiveMember.modified` (for a file once it is written, for a folder in the deferred
pass of "Policy-Specific Metadata Transforms"), it SHALL also set its birth time from
`ArchiveMember.created` on systems that let a program set one: Windows (`SetFileTime`)
and macOS (`setattrlist`). The birth time SHALL be set after the modification time,
because macOS moves a birth time later than a new modification time back to it. A file's
birth time SHALL be set on the temporary file before the rename that lands it, which
keeps it (measured on Windows, where tunnelling does not apply to a rename).
`ArchiveMember.ctime` SHALL NOT be used for either.
Both SHALL be best effort, under every extraction policy: a member with no stored time
keeps the time it was written, and a time the system refuses or cannot represent SHALL
NOT fail the member.

#### Scenario: member time matrix

| Case | Expected |
| --- | --- |
| A file and a folder with `created` and `modified`, on Windows or macOS | Both times on disk |
| The same on Linux | The modification time; the birth time is when it was written |
| A member with `created = None` | No birth time call |
| On Windows, a file with `created` extracted over an existing file | The member's birth time, not the replaced file's |
| The system refuses the birth time | The member is extracted; no error |
