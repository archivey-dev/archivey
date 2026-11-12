# format-7z — AES tail key check delta

> As archived on 2026-11-05: the requirement below is the one applied to
> `openspec/specs/format-7z/spec.md`, which had moved on since this change was drafted.

## MODIFIED Requirements

### Requirement: Decrypt AES-encrypted 7z with archive-reading passwords

The system SHALL read AES-256-encrypted 7z folders and header-encrypted archives
when a valid password and crypto backend are available. Header encryption SHALL
decrypt the end header before listing; without a password the system raises
`EncryptionError`, and with no crypto backend it raises `PackageNotInstalledError`.
Any archive or folder encryption SHALL set `ArchiveInfo.is_encrypted` to `True`.

Passwords SHALL use the `archive-reading` candidate model: known-good successes
for this reader, remaining static candidates, then provider requests. Header
requests use `member is None`; folder/member requests identify the member being
decrypted where possible. Members in different encrypted folders MAY use different
passwords in one open or one `stream_members()` pass. Key derivation SHALL use the
7z SHA-256 scheme (UTF-16LE password, salt, `1 << NumCyclesPower` rounds with the
documented `0x3F` no-hash sentinel) via a 7z-local helper that feeds `AesParams` into
the shared crypto stage — not a generic crypto-surface KDF. `NumCyclesPower` values
other than `0x3F` SHALL be accepted only when `≤ 24`; values 25–62 SHALL raise
`UnsupportedFeatureError` (matching 7-Zip’s decoder clamp), not
`EncryptionError`.

Because 7z AES carries no password check value in the format, wrong-password detection
relies on a derived cheap key check, integrity anchors and codec rejection, applied as
the `archive-reading` confirmation ladder. The reader SHALL cache derived keys by
`(password, salt, cycles)` and try known-good passwords first.

**Cheap key check (tail padding).** Where the AES coder decrypts the folder's only pack
stream, that stream is CBC over a plaintext padded to a 16-byte boundary, and the
coder's declared output length gives the unpadded length, so `pack_size - unpack_size`
tail bytes are padding. 7-Zip and py7zr pad with zeros. Where the pack stream is a whole
number of blocks and the padding is **4 to 15 bytes**, the reader SHALL decrypt the
final CBC block from the last two ciphertext blocks (the coder's IV and the only block,
for a one-block stream), without decoding the folder, and treat an all-zero padding
tail as `CONFIRMED`. A wrong key passes it at most once in 2³², so it proves the key as
an anchor does: the folder's members are not watched for an unconfirmed password, and
their verification level starts at `UNLOCKED`. A non-zero tail SHALL NOT reject the
candidate: the padding value is a writer convention, not a format guarantee, so the
ladder goes on to the anchor. Below 4 bytes the check SHALL NOT run, in either
direction. An AES coder that declares more output than its pack stream holds SHALL
raise `CorruptionError` before any candidate is tried: AES-CBC never outputs more than
it reads, and the short decrypt would otherwise read as a wrong password under the
correct one.

**Integrity anchor.** Confirmation SHALL stop at the earliest sufficient anchor rather
than decoding the folder: per-member CRCs are consulted in substream order, and the plan
terminates once CRC-verified bytes reach 4. A folder digest SHALL be used only when it is
the earliest such anchor — a folder carrying both a digest and per-member CRCs SHALL
anchor on the members. If that anchor sits past `PASSWORD_CONFIRM_PREFIX_BYTES` and the chain
has a rejecting codec, the plan SHALL NOT walk it (codec rejection settles a wrong
key). If the chain has no rejecting codec, the plan SHALL walk it anyway.

**Codec rejection.** A chain rejects iff a decompressor measured to fail on random AES
output decodes the AES output, directly or through other coders. A decompressor that
decodes before the AES coder sees the same bytes whatever the key and does not count. Measured as rejecting: LZMA1, LZMA2, BZip2, Deflate, Deflate64,
Zstandard and LZ4. Measured as non-rejecting: Brotli (about one random input in twenty
decodes a full 64 KiB prefix) and PPMd. Filters (Delta, BCJ) never reject —
`MethodKind.LZMA_FAMILY` includes Delta and is the wrong predicate. A codec not measured
is non-rejecting. A rejecting chain with no reachable anchor decodes a bounded plaintext prefix
and treats a survivor as `INCONCLUSIVE`. A non-rejecting chain follows the
`archive-reading` rule: walk a late CRC; with no CRC at all, do not invent an
unbounded decode.

When an encrypted folder has **no** folder digest and a member has **no** CRC
(format-legal for store/copy), the system SHALL still return decoded bytes (best-effort,
matching 7-Zip) and SHALL emit `DIGEST_UNVERIFIABLE` with
`DigestContext.reason="no_integrity_anchor"` — it MUST NOT imply the decryption was
authenticated. A tail-padding confirmation SHALL NOT suppress it: that check attests the
key, not the data. The reader SHALL NOT decode such a folder merely to discover that nothing
can be checked — several candidates do not change that. After decoding a
header-encrypted `kEncodedHeader`, a parsed result with zero file records SHALL raise
`EncryptionError` (legitimate writers never encrypt an empty header) so a wrong password
cannot open as a silent empty listing.

#### Scenario: encryption matrix

| Case | Expected |
| --- | --- |
| Header-encrypted archive, no password/provider result | `EncryptionError` before listing |
| Header-encrypted archive, valid password + crypto | Header is decrypted natively; members list; `is_encrypted` true |
| Encrypted folders with different passwords | Each folder uses its matching candidate in random access or one streaming pass |
| Sole wrong password, integrity anchor present (folder digest and/or member CRC) or compressed codec rejects garbage | `EncryptionError`/`CorruptionError`; no incorrect data handed to the caller as success |
| Header-encrypted archive, wrong password decodes to zero file records | `EncryptionError` (never a silent empty listing) |
| Encrypted store/copy member, no folder digest, no member CRC, any password | Bytes returned; `DIGEST_UNVERIFIABLE` (`reason="no_integrity_anchor"`) emitted |
| `NumCyclesPower` 25–62 | `UnsupportedFeatureError` (not remapped to wrong-password) |
| Repeated salt/cycles/password | Derived key cache avoids repeated key derivation |
| Sole wrong password, LZMA2, CRC at 200 MiB | `EncryptionError` at open (codec rejects in the prefix; no 200 MiB read) |
| Correct password, LZMA2, CRC at 200 MiB, AES tail check not confirming, `read(1)` then close | `INCONCLUSIVE`; `ENCRYPTED_MEMBER_UNVERIFIED` |
| Correct password, LZMA2, CRC at 200 MiB, zero AES tail padding of 4 bytes or more, `read(1)` then close | `CONFIRMED` on the tail; no diagnostic |
| Sole wrong password, store/copy, CRC at 200 MiB | Walk to the CRC; `EncryptionError` at open |
| Correct password, store/copy, CRC at 200 MiB, `read(1)` then close | No diagnostic (anchor confirmed) |
| Sole wrong password, store/copy, no CRC at all | Accepted at open; surfaces on the caller's read; `ENCRYPTED_MEMBER_UNVERIFIED` on an abandoned partial read |
| Store/copy, no CRC, two candidates, AES tail padding under 4 bytes or not zero | First candidate; `DIGEST_UNVERIFIABLE`; confirmation ≤ budget |
| No integrity anchor, several candidates, zero AES tail padding of 4 bytes or more | The candidate whose tail is zero is chosen; `DIGEST_UNVERIFIABLE` still emitted |
| AES tail padding of 4 to 15 bytes, all zero for one candidate | `CONFIRMED` with no folder decode |
| AES tail padding non-zero for every candidate | No candidate dropped; the ladder goes on to the anchor |
| AES tail padding under 4 bytes, or a pack stream that is not a whole number of blocks | Check skipped; the ladder starts at the anchor |
| AES coder declares more output than its pack stream holds | `CorruptionError` before any candidate, not a wrong password |
| Ambiguous candidates, store/copy folder, only CRC at folder end | Unbounded pass; the candidate matching the CRC wins |
| AES → Delta → Copy or AES → BCJ → Copy | Treated as non-rejecting (the filter does not reject random input) |
| Rejecting chain, packed input past 1 MiB before the prefix is decoded | Input capped at `PASSWORD_CONFIRM_MAX_INPUT_BYTES`; running out of it is `INCONCLUSIVE`, not a rejection |
| Solid folder, first member 4 KiB, folder 200 MiB | Confirmation decodes the first member only |
| Folder carrying both a folder digest and per-member CRCs | Anchors on the earliest member CRC, not the folder digest |
| LZMA2 decoded before AES, member CRC past the prefix, candidates `wrong` then `right` | Non-rejecting chain: the CRC is walked, `wrong` is rejected, `right` is used |
