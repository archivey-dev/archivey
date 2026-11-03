# archive-data-model — verification level redesign delta

## ADDED Requirements

### Requirement: ArchiveMember carries its verification level

`ArchiveMember` SHALL expose `verified` and `verifiable`, of type
`archivey.Verification`, with the meanings the `compressed-streams` verification
requirement gives them, applied to this entry's data in this archive.

- From the listing, a member that is not encrypted SHALL start at `verified ==
  UNLOCKED`, and an encrypted member whose password is not yet confirmed at `NONE`.
- `verifiable` is known from the listing. It MAY settle once, at the member's first
  open, which is the first time any stream of that member opens its data (a password
  watch that only appears then can lower it). After that it SHALL NOT fall.
- `verified` SHALL only rise. The reader SHALL raise it in place from every read that
  proves more: a stream of the member, a listing pass that decodes the data, and a
  check that spans members once it passes. A raise SHALL be a monotonic maximum taken
  under a per-reader leaf lock held only for the compare-and-store (never across I/O
  or a callback), so concurrent raises cannot lower it.
- `verified` and `verifiable` SHALL be excluded from equality, like `hashes`,
  `diagnostics` and `extra`. `member_state_final` SHALL NOT cover them, as it does not
  cover `diagnostics`: they MAY still rise after it is `True`.
- A `replace()` copy keeps the values it was copied with and SHALL NOT follow later
  raises.

#### Scenario: member level matrix

| Case | Expected |
| --- | --- |
| ZIP member with a CRC, before any read | `verified` is `UNLOCKED`; `verifiable` is `CHECKSUM` |
| Same member after a stream read it to the end | `verified` is `CHECKSUM` |
| Same member compared with a copy taken before the read | equal |
| `member_state_final` is `True`, then a stream reads the member to the end | `verified` rises to `CHECKSUM` |
| Two threads read two members of one 7z folder (folder CRC only) under `concurrent_operations=True` | both members end at `CHECKSUM`; neither level is ever seen to fall |
| 7z AES member in a folder with no CRC, before and after its first open | `verifiable` may settle to `NONE` at the first open and stays there |
