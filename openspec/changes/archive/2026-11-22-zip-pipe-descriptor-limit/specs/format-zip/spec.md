# format-zip — pipe follow after a data-descriptor member delta

## MODIFIED Requirements

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
there as before. This does not apply before the first member. It applies only when the
member before the damaged header records its sizes in its local header (bit 3 clear):
after a member whose sizes are in a data descriptor, the walk accepts that descriptor only
when an intact signature follows it (for a STORED member this is also how it finds the
data's end), so it SHALL stop at that member as before, and the pipe lists less than a
file does.

#### Scenario: a damaged local signature from a pipe

- **WHEN** the signature of the third of five local headers is damaged and the
  archive is read from a pipe
- **THEN** all five members are listed, the third one's read raises `CorruptionError`,
  the other four read, and the pass ends with no error, as from a file

#### Scenario: a damaged local signature after a data-descriptor member, from a pipe

- **WHEN** the signature of the third of five local headers is damaged, the second
  member keeps its sizes in a data descriptor (bit 3 set, as `zip -` writes to stdout),
  and the archive is read from a pipe
- **THEN** the pass ends at the second member with an error, as it did before this
  rule (`UnsupportedFeatureError` for a STORED member, `CorruptionError` "no data
  descriptor after member #1" for a compressed one); a file read still lists all five
