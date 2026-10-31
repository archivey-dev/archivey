## ADDED Requirements

### Requirement: A file cut inside its signature is truncated

A ZIP, 7z or RAR source that holds only a non-empty start of its format's signature
SHALL raise `TruncatedError`, not "Not a … archive": the bytes that are there match the
format and the file ends, so it was most likely cut short. Only a signature at the start
of the source counts, since a self-extracting stub in front of one can hold any bytes.

#### Scenario: cut signatures

| Case | Expected |
| --- | --- |
| `x.zip` holding `PK\x03` | `TruncatedError`, from a file and from a forward-only read |
| `x.7z` holding the first 5 bytes of the 7z signature | `TruncatedError` |
| `x.rar` holding `Rar!\x1a\x07` (the RAR4 and RAR5 signatures share it) | `TruncatedError` |
| `x.zip` holding `PKx` | `CorruptionError`, not `TruncatedError` |
| `x.zip` holding a stub, then `PK\x03` | `CorruptionError`, not `TruncatedError` |
