## 1. Build

- [x] 1.1 `sfx.pe_headers`, `PeHeaders`, `PeSection`; `pe_layout` on top of them
- [x] 1.2 `pe_resources.ProgramResources`: lazy, bounded resource-table read
- [x] 1.3 `open_read(program_resources=…)`: passed by `open_archive` to SFX backends, rejected by the rest
- [x] 1.4 ZIP, 7z and RAR trailing-data checks consult it; RAR's `TrailingData`

## 2. Verify

- [x] 2.1 `tests/test_resource_sfx.py`: detected and forced, signed and unsigned, `STRICT`, padding, junk inside the resource, appended archive, table edge cases
- [x] 2.2 By hand: GitHub Desktop opens with no warning, auto and forced; IRPF, WinRAR, 7-Zip unchanged
