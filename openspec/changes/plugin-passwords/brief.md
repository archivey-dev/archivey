# plugin-passwords — let a plugin format read encrypted members

**Status:** Design. The maintainer ruled open questions 1-11 on 2026-11-21 (design.md
§Open questions). No code until the maintainer
has reviewed and merged this design. Additive: no current call changes. Target: 0.6.0
(before DMG encryption).

**Why it matters:** `password=` never reaches a plugin. Three readers need it: makeself
(already decrypts, through the private `ReaderContext._passwords`), DMG (encrypted
images, planned), and ARJ (garbled members are refused today only for this reason). A
plugin that replaces the ZIP, 7z or RAR reader cannot read an encrypted member either.
Most new formats are meant to use the plugin interface, so the password path belongs in
it.

**What it does:**

- `FormatHandler.supports_password` declares that a format can be encrypted, so a
  concrete `password=` given for it is no longer reported as unused.
- A plugin hands archivey a
  `NeedsPassword(what, check, *, full_check=None, member=None, then=None)` request for
  one encrypted unit (a member, a payload, a whole image): `open` and `open_member`
  return it, and `walk` and `iter_members` yield it. archivey runs its whole password
  loop while no plugin code is running, then calls `then(data, verdict)` or sends
  `(data, verdict)` back into the walk. The loop is the built-in one: candidates in
  order, the password that worked tried first next time, the provider asked only after
  the list runs out, its repeats skipped. The plugin writes only `check(password)`,
  which returns what the password unlocked (the key it needs later) with a
  `PasswordConfirmVerdict`: `REJECTED`, `INCONCLUSIVE` or `CONFIRMED` (the enum the
  built-in readers already use, made public). design.md D1 has worked examples.
- archivey raises the errors, so every format says the same thing: `EncryptionError`
  "… is encrypted: pass password= to read it" when no password was given, and the
  wrong-password `EncryptionError` "Wrong password for …" when every one failed.
- An optional `full_check` decides between several `INCONCLUSIVE` passwords (ARJ garble:
  decode the member and check its CRC-32). A checksum failure under a password that won
  unconfirmed says "wrong password or damaged data", as ZipCrypto does.
- `ReaderContext.charge_key_derivation(rounds)` charges archive-declared key derivation
  to `DecoderLimits.max_key_derivation_rounds` before it runs.
- `ReaderArchiveInfo.is_encrypted`, and members listed with `is_encrypted=True`, report
  encryption the way the built-in readers do.
- The verdict travels with the data it covers: `unlocked` on `MemberRecord`,
  `MemberSpan` and `MemberData` (design.md D7).

**After it lands:** makeself moves off `_passwords` (and starts marking its encrypted
members), ARJ reads garbled members, and the DMG spec §6B uses `NeedsPassword` instead
of the private hook.
