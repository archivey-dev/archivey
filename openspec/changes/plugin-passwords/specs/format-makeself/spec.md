## MODIFIED Requirements

### Requirement: Check every digest the header states

For each payload the backend SHALL compute every digest the header states for it (the
POSIX `cksum` CRC, MD5, SHA-256) over the stored bytes while reading, and compare them
at the payload's end. Each file of a payload with a stated digest SHALL have
`verifiable=CHECKSUM`; a match SHALL raise each to `verified=CHECKSUM`; a mismatch SHALL
raise `CorruptionError` from the walk and make each a failure of `verify_all()`.

An encrypted payload's digests cover its ciphertext, and the decrypted files are right
only under the right key, which the openssl check (the compressor's magic or a TAR
header) does not confirm. For its files a mismatch SHALL still raise and make each a
failure of `verify_all()`, but the digests SHALL NOT set `verifiable=CHECKSUM` nor raise
`verified`: those come from the files' own reads.

#### Scenario: digests

| Case | Expected |
| --- | --- |
| An unchanged fixture | `verify_all()` empty; every file `CHECKSUM` |
| One byte of an uncompressed payload changed | Listing raises; `verify_all()` returns every file of that payload |
| An unchanged `--ssl-encrypt` fixture, uncompressed TAR, right password | `verify_all()` empty; no file `CHECKSUM` |
