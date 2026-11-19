## ADDED Requirements

### Requirement: encoding="auto" guesses the codec of legacy names

`open_archive(encoding=...)` SHALL accept `"auto"` besides a codec name. Under `"auto"`,
a format that reads `encoding=` SHALL decode a stored name that is not valid UTF-8, and
that the format gives no other encoding signal for, with a guessed CJK codec: one of
`cp932`, `euc_jp`, `gbk`, `big5` or `cp949`. When no codec is guessed, or the guessed
codec cannot strictly decode that name, the name SHALL decode as it does with
`encoding=None`. Valid UTF-8 and a format's own encoding signal (such as the ZIP UTF-8
flag or Unicode Path field) SHALL win over the guess, as they win over an explicit
codec. A Latin code page SHALL never be guessed.

The guess for a name SHALL depend only on the distinct stored member names that are not
valid UTF-8, in the order the reader meets them, up to and including that name, and on
at most the first 256 of them. Each distinct stored byte string SHALL decode to one text
for the life of the reader. So the same archive bytes SHALL give the same names under
`streaming=True` and `streaming=False`, under any `max_members`, and in any order of
calls.

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
| cp437 German or French names, `encoding="auto"` | Names as with `encoding=None`; no `MEMBER_NAME_ENCODING_INFERRED` |
| Name that is valid UTF-8 | UTF-8, whatever the guess for the other names |
| `max_members=2` on an archive with 10 cp949 names | The 2 listed names equal the first 2 names of an unlimited listing |
| `encoding="auto"` under `DiagnosticPolicy.STRICT`, a name guessed | Refused, as any inferred name is |
| `encoding="auto"` on a format that does not read `encoding=` | Opens; `ENCODING_ARGUMENT_UNUSED`; names unchanged |
