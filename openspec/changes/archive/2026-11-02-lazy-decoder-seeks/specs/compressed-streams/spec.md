## ADDED Requirements

### Requirement: A decoder seek decodes at the next read

A `DecompressorStream` seek that would decode to reach its target (a seek back, or
forward past the buffered output) SHALL record the target and decode nothing. The next
`read`, `read_ahead`, `readinto` or `readall` SHALL decode to the target first, from
the nearest seek point, and then read on. A seek that a later seek replaces, or that no
read follows, SHALL decode nothing. `tell()` SHALL return the target at once, and
`SEEK_CUR` SHALL count from it. A seek within the buffered output, to the decoder's
position, or at or past a size already known SHALL move at once, since it decodes
nothing. `SEEK_END` needs the size: a seek to it SHALL find the size as before, and an
error it meets SHALL raise from that seek.

An error in the bytes before the target (a truncation, damage, a report the collector
escalates) SHALL raise from the read that decodes them, before it returns any byte,
and leave `tell()` at the target. After a decode error the stream keeps it, as after
any read that raised: later reads raise it again, and a seek restarts the decoder at
the next read. Any other error (the source's own seek failing) SHALL keep the target,
so the next read tries again.

#### Scenario: lazy decoder seeks

| Case | Expected |
| --- | --- |
| Seek back to 100 after a full read, no read after | No decoder restart, no decode; `tell()` is 100 |
| Seek, a `SEEK_CUR` seek, another seek, then a read | One restart at most, for the last target; the read returns its bytes |
| Seek past a truncation | `seek` returns the target; the next read raises `TruncatedError`, and so does the read after it; `seek(0)` and a read return the start |
| Seek past damage in the gap | `seek` returns the target; the next read raises `CorruptionError`; `tell()` is still the target |
| Forward seek past the last seek point on an index the decoder builds (BGZF walk) | The seek walks nothing; the read after it walks to the target |
| `seek(0, SEEK_END)` with no known size | Decodes to the end at the seek, from the last seek point past the decoder; a cut stream raises there |
