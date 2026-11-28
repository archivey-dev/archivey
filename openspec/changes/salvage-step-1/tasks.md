# Tasks — salvage step 1

No code until the maintainer has reviewed the design. One implementation PR, labelled
`needs-minor`.

## 0. Design review

- [x] 0.1 Maintainer decisions recorded in the design with their date (2026-11-07:
      list flagged, `MEMBER_HEADER_DAMAGED`, `STRICT` refuses the member, one/two
      confirming headers, chains up to 8; 2026-11-05: fixed feeding).
- [ ] 0.2 Maintainer review of this design.

## 1. RAR: resume past a damaged header

- [ ] 1.1 Fixtures: generate damaged copies of `basic_nonsolid__.rar`,
      `basic_nonsolid__rar4.rar` and a solid RAR5 in the test, from committed fixtures
      (header end byte, name byte, data CRC field, size vint, type byte set to `ENDARC`,
      SERVICE, MAIN and `CRYPT`, plain and solid for SERVICE; the 3rd and 5th headers
      damaged; the 3rd and 4th damaged; nine in a row; a RAR 1.5-4 whose damaged size
      lands on a header passing CRC16 while the next does not; a solid RAR5 with a
      digest-less member after the damage, crafted as `tests/test_rar_undecodable_names.py`
      does), and pin `unrar lb` / `unrar t` on each, and `lsar` where the design
      measured it, in a test that skips without the program (DR-24).
- [ ] 1.2 `rar_parser.py`: in both walks, on a damaged header after MAIN, follow its
      sizes (and a chain of up to 8 damaged headers), confirm the header after the chain
      (RAR5 one header, RAR 1.5-4 two), list each FILE-typed damaged header as a member
      marked damaged with its offset, skip a SERVICE-typed one into
      `damaged_service_headers`; never past a damaged header that does not parse in full
      or whose type reads as anything but FILE or SERVICE. Encrypted headers do not
      resume.
- [ ] 1.3 `MEMBER_HEADER_DAMAGED`, `MemberHeaderDamageContext`, `DiagnosticCodeStr`,
      `ARCHIVE_INTEGRITY_CODES`, the diagnostics catalogue row and the API surface
      listing.
- [ ] 1.4 `rar_reader.py`: emit the code on every read, open, stream and extraction of a
      flagged member, before its bytes, never at listing. After a SERVICE-typed damaged
      header with data in a solid stream, a member with no stored digest raises
      `CorruptionError`; after a listed damaged member, it emits `DIGEST_UNVERIFIABLE`
      (`reason="after_damaged_header"`).
- [ ] 1.5 `rar_synthetic.py`: a flagged member's synthetic header is built from its
      stored fields with a fresh CRC; check that the writer does not refuse it, and that
      `unrar` output matches the original archive's.
- [ ] 1.6 Tests: the `format-rar` damaged-header matrix in both access modes,
      `members_report()`, `extract_all()` (writes every reached member, the damaged one
      under its stored name, then raises), `STRICT` (that member refused, the others
      read), `archivey test` and `archivey list` output, a file copy or hard link whose
      source is the damaged member, a two-volume set, `rar_decompressor="unar"` after
      the damage, and a duplicate name across the damage.
- [ ] 1.7 `formats/rar.md` §1: replace "unrar searches past the damage" with what the
      source and the measurements show, and add the resume rule and its reasons.
      `docs/errors-and-diagnostics.md`: the new code. `dev-docs/design-rules.md` DR-1:
      the salvage rule and the damaged-encryption-flag exception, with their date.

## 2. Close

- [ ] 2.1 `dev-docs/IDEAS.md` "Salvage mode": say that confirmed RAR resume shipped and
      list what is left (TAR, the search mode).
- [ ] 2.2 Archive this change (`openspec archive salvage-step-1 --yes`).
