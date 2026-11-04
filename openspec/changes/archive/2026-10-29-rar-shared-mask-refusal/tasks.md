## 1. Refuse every mask that selects earlier members

- [x] 1.1 `RarReader._unrar_spawner_by_name`: the refusal no longer requires a glob mask
- [x] 1.2 Message says "also selects" for a non-glob name
- [x] 1.3 Tests: duplicate name refused by default (solid and not), read by `unar` under
  `auto`; the shared-mask tests opt in with the flag
- [x] 1.4 Config, user docs, handbook and threat model
