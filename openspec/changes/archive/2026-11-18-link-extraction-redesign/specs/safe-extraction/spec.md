## ADDED Requirements

### Requirement: A held-back hard link is a placeholder file until its source is read

When a selected HARDLINK's source has no written copy on disk and the source is
re-readable, the system SHALL create an empty regular file at the link's destination at
the link's place in archive order, through the same collision, overwrite-policy and
parent steps as a FILE member, and report the link there. Later HARDLINKs to the same
source SHALL be hard links to that file. After the pass, the system SHALL read the
source once and move its bytes onto each name that still holds the placeholder (the same
device and inode), then apply the link's metadata. A name a later member replaced is not
written. If the source is refused by its recorded size or reading it fails, every
surviving name of that source SHALL be removed and its result revised to `FAILED`, as
one failure group.

#### Scenario: a later member meets a held link as a made one

- **WHEN** an archive holds `file src`, `hard d/h -> src`, `file d`, with `src`
  excluded, under any overwrite policy
- **THEN** the results, result paths and files on disk are the ones the same archive
  gives with `src` selected

### Requirement: No member is written under a symlink this run created

The system SHALL refuse, with `FilterRejectionError`, a member whose parent path reaches
a symlink that this extraction created, under every extraction policy and overwrite
policy, in both access modes. A symlink that was in the destination before the run SHALL
be followed as before. A member at the symlink's own name SHALL meet the overwrite
policy.

#### Scenario: a file under the archive's own symlink

- **WHEN** an archive holds `dir e/`, `sym s -> e`, `file s/x`
- **THEN** `s/x` is `BLOCKED` and nothing is written at `e/x`
