# plugin-passwords — let a plugin format read encrypted members

**Status:** Design only. The public names and behaviour below are recommendations; the
maintainer rules on them one question at a time (design.md §Open questions). No code
until then. Additive: no current call changes. Target: 0.6.0 (before DMG encryption).

**Why it matters:** `password=` never reaches a plugin. Three readers need it: makeself
(already decrypts, through the private `ReaderContext._passwords`), DMG (encrypted
images, planned), and ARJ (garbled members are refused today only for this reason). A
plugin that replaces the ZIP, 7z or RAR reader cannot read an encrypted member either.
Most new formats are meant to use the plugin interface, so the password path belongs in
it.

**What it does:**

- `FormatHandler.supports_password` declares that a format can be encrypted, so a
  `password=` given for it is no longer reported as unused.
- `ReaderContext.unlock(what, check, member=None)` runs archivey's whole password loop
  for one encrypted unit (a member, a payload, a whole image): candidates in order, the
  password that worked tried first next time, the provider asked only after the list
  runs out, its repeats skipped. The plugin writes only `check(password)`, which returns
  what the password unlocked, or `None` when it is wrong.
- archivey raises the errors, so every format says the same thing: `EncryptionError`
  "… is encrypted: pass password= to read it" when no password was given, and the
  wrong-password `EncryptionError` "Wrong password for …" when every one failed.
- `unconfirmed(result)` lets a format with no password check (ARJ garble) accept a
  password that only the member's checksum can confirm; a checksum failure under it then
  says "wrong password or damaged data", as ZipCrypto does.
- `ReaderContext.charge_key_derivation(rounds)` charges archive-declared key derivation
  to `DecoderLimits.max_key_derivation_rounds` before it runs.
- `ReaderArchiveInfo.is_encrypted`, and members listed with `is_encrypted=True`, report
  encryption the way the built-in readers do.

**After it lands:** makeself moves off `_passwords` (and starts marking its encrypted
members), ARJ reads garbled members, and the DMG spec §6B uses `unlock` instead of the
private hook.
