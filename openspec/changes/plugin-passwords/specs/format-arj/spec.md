## MODIFIED Requirements

### Requirement: Refuse what the ARJ reader cannot read

The backend SHALL raise `CorruptionError` for a header without `60 EA`, a basic header
over 2600 bytes or under its fixed part, a basic or extended header that fails its
CRC-32, a name with no NUL, a second main header, a Unix special header cut short, and a
member whose data fails its CRC-32 when the member is not garbled or its password was
`CONFIRMED`. A garbled member read under an `INCONCLUSIVE` password (one password, no
full check) whose data fails its CRC-32 or its decoder SHALL raise the
wrong-password-or-damage `EncryptionError` instead. It SHALL raise `TruncatedError` for
a file that ends inside a header or a member's data, garbled or not. A member split
across volumes, a method past 4, and a garbled member of an archive whose main header
names the GOST cipher (encryption version 2 or later) SHALL raise
`UnsupportedFeatureError` when read.

#### Scenario: ARJ refusals

| Case | Expected |
| --- | --- |
| A header byte changed | `CorruptionError` (CRC) |
| A member's data changed | `CorruptionError` |
| The file cut inside a member | `TruncatedError` |
| A garbled member, encryption version 2 | Listed, `is_encrypted`; `UnsupportedFeatureError` on read |
| Volume flag `0x04` or `0x08` | `UnsupportedFeatureError` on read |
| Method 9 | Listed as `UNKNOWN`; `UnsupportedFeatureError` on read |

## ADDED Requirements

### Requirement: Read garbled members with the caller's password

A garbled member (flag `0x01`) of an archive with encryption version 0 or 1 SHALL be
listed with `is_encrypted` and read with the caller's `password=` through a
`NeedsPassword` request (`format-plugins`). The garble XORs each stored byte, counted
from the member's first stored byte, with a password byte plus the header's modifier
(byte 7), modulo 256, the password repeating. The check SHALL say `INCONCLUSIVE` for any
non-empty password, since nothing before the data tells a wrong one; the full check
SHALL decode the member to its CRC-32 in bounded chunks and say `REJECTED` on a mismatch
or a decoder failure over the complete stored bytes, `CONFIRMED` on a match over at
least 4 bytes, and `INCONCLUSIVE` on a match over fewer. A source that fails or ends
inside the stored bytes SHALL raise its own error. Under an unconfirmed password, a
decoder failure while the caller reads SHALL raise the wrong-password-or-damage
`EncryptionError`. `ReaderArchiveInfo.is_encrypted` SHALL stay false: the listing is not
garbled.

#### Scenario: Garbled ARJ members

| Case | Expected |
| --- | --- |
| `password="secret"`, the right one | The member reads; its CRC-32 is checked |
| No password | `EncryptionError`, "pass password= to read it" |
| `password=["wrong", "secret"]` | Both pass the check; the full check rejects `wrong`; the member reads |
| `password="wrong"` alone, no provider | The read raises the wrong-password-or-damage `EncryptionError` |
| `password=["a", "b"]` | Both rejected by the full check: the wrong-password-or-damage `EncryptionError` |
| Provider only, two members, one password, `extract_all()` | The provider is asked for the first member only; the CRC-32 confirms and promotes the answer |
| Provider only, `stream_members()`, the first member skipped | The provider is asked only for the member read |
