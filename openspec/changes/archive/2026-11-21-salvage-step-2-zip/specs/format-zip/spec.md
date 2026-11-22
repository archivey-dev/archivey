# format-zip — salvage step 2 delta

## ADDED Requirements

### Requirement: A forward read SHALL go past a local header whose signature alone is damaged

In a forward read, when the four bytes after a member's data are not a ZIP signature,
the walk SHALL read them as a local header when the other 26 bytes pass the checks the
detector makes on a local header, bit 3 is clear, and the four bytes where that
header's data ends are a signature that may follow a member (a local header, a central
directory header, an end record, or the archive extra data record), with the header
and data no longer than 4 MiB. The member SHALL be listed, and every read of it SHALL
raise `CorruptionError` ("Bad magic number for file header"), as a read of the same
member from a file does; the walk SHALL go on to the members after it, and the central
directory at the end SHALL check it as any other member. Otherwise the walk SHALL stop
there as before. This does not apply before the first member.

#### Scenario: a damaged local signature from a pipe

- **WHEN** the signature of the third of five local headers is damaged and the
  archive is read from a pipe
- **THEN** all five members are listed, the third one's read raises `CorruptionError`,
  the other four read, and the pass ends with no error, as from a file
