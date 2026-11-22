# format-ar — salvage mode delta

## ADDED Requirements

### Requirement: Salvage mode searches past damage for the next ar header

With `salvage=True`, where the walk ends on damage, it SHALL search forward at 2-byte
steps for a 60-byte header that ends in `` `\n ``, whose size and mode fields parse and
whose date, uid and gid fields hold only digits and spaces. A found member SHALL be
listed with `MEMBER_FOUND_BY_SCAN`; confirmed when the header after its (2-byte padded)
data passes or the archive ends there. A GNU `/n` name whose name table was lost SHALL
keep its raw name with `"name"` in `unchecked`; a found `//` table SHALL name the
members after it.

#### Scenario: ar header search

| Case | Expected |
| --- | --- |
| GNU ar with a zeroed region over one header | Every member after it, flagged |
| Long-name table inside the damage | Later members keep `/n` names, `"name"` unchecked |
