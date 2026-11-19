## ADDED Requirements

### Requirement: encoding="auto" guesses the codec of legacy names

`open_archive(encoding=...)` SHALL accept `"auto"` besides a codec name. Under `"auto"`,
a format that reads `encoding=` SHALL decode a stored name that is not valid UTF-8, and
that the format gives no other encoding signal for, with a guessed CJK codec: one of
`cp932`, `euc_jp`, `gbk`, `big5` or `cp949`. When no codec is guessed, or the guessed
codec cannot decode that name, the name SHALL decode as it does with `encoding=None`.
Valid UTF-8 and a format's own encoding signal (the ZIP UTF-8 flag or Unicode Path
field, an ISO Rock Ridge name's Joliet twin) SHALL win over the guess. A Latin code page
SHALL never be guessed.

The guess for a name SHALL depend only on the distinct stored member names that are not
valid UTF-8, in the order the reader meets them, up to and including that name, and on
at most the first 256 of them. Text that is not a member name (link targets, comments,
user and group names) SHALL NOT change the guess. Each distinct stored byte string, and
each directory prefix of a name, SHALL decode to one text for the life of the reader.

The same archive bytes SHALL give the same names under any `max_members`, in any order
of calls, and under `streaming=True` and `streaming=False`. The one exception is a ZIP
whose central directory lists entries in another order than its local headers, where the
names met before the guess is frozen MAY differ between the two modes.

A name decoded with a guessed codec SHALL report `MEMBER_NAME_ENCODING_INFERRED`, with
`inferred_encoding` set to the guess and `declared_encoding` set to the codec the name
would otherwise have had. On a format that does not read `encoding=`, `"auto"` SHALL
report `ENCODING_ARGUMENT_UNUSED`, as any other value does.

#### Scenario: auto matrix

| Case | Expected |
| --- | --- |
| ZIP, unflagged cp932 names, `encoding="auto"` | Names in Japanese; `MEMBER_NAME_ENCODING_INFERRED` with `inferred_encoding="cp932"`, `declared_encoding="cp437"` |
| TAR, GBK names, `encoding="auto"`, `streaming=True` and `streaming=False` | The same names in both modes |
| Archive whose first legacy name is ambiguous alone and whose later names are clearly Big5 | First name decodes as with `encoding=None`; later names in Big5 |
| Big5 directory entry ambiguous alone, then its children | The children's directory part is the directory entry's text; one tree |
| cp932 archive with one name cut inside its last character | The other names in cp932; the cut name in cp932 with its last byte escaped |
| cp437 German or French names, `encoding="auto"` | Names as with `encoding=None`; no `MEMBER_NAME_ENCODING_INFERRED` |
| Name that is valid UTF-8 | UTF-8, whatever the guess for the other names |
| ISO Rock Ridge name not UTF-8, Joliet twin present | The Joliet name; the name adds nothing to the guess |
| `max_members=2` on an archive with 10 cp949 names | The 2 listed names equal the first 2 names of an unlimited listing |
| ZIP whose central directory order differs from its local headers' | Names may differ between modes before the guess is frozen |
| `encoding="auto"` under `DiagnosticPolicy.STRICT`, a name guessed | Refused, as any inferred name is |
| `encoding="auto"` on a format that does not read `encoding=` | Opens; `ENCODING_ARGUMENT_UNUSED`; names unchanged |
