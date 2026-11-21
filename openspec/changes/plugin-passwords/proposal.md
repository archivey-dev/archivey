## Why

`password=` reaches only the built-in readers. The plugin interface lists passwords as
left out of its first version (`archivey/formats.py` module docstring, `docs/adding-a-format.md`
§replacement readers). Built-in readers on the interface work around it through the
private `ReaderContext._passwords` (makeself's openssl payloads), or refuse (ARJ garbled
members). DMG encrypted images (plan §6B) would be a third private user. A plugin replacing
ZIP, 7z or RAR cannot read an encrypted member at all.

## What Changes

- New public names in `archivey.formats` (each needs the maintainer's ruling):
  `FormatHandler.supports_password`, `ReaderContext.unlock()`, `unconfirmed()`,
  `ReaderContext.charge_key_derivation()`, `ReaderArchiveInfo.is_encrypted`.
- The adapter passes the caller's `password=` to every plugin whose handler sets
  `supports_password`, including a replacement reader.
- archivey builds the missing-password and wrong-password `EncryptionError`s for a plugin
  from the `what` text it passes.
- Follow-up PRs: makeself on `unlock` (drops `_passwords`), ARJ garble decryption, DMG.

## Capabilities

### Modified Capabilities

- `format-plugins`: a plugin can declare encryption and unlock encrypted units.

## Impact

- Public API: additive names above, all in the provisional `archivey.formats` module.
- No change for callers of `open_archive()`: the same `password=` forms reach plugins.
- `ReaderContext._passwords` is removed once makeself moves (it was never public).
- Docs: `docs/adding-a-format.md` gains a passwords section (written by the docs session).
