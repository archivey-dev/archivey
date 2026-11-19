## ADDED Requirements

### Requirement: ReaderContext applies encoding="auto" for a plugin

`ReaderContext` SHALL offer two decoders for stored bytes:

```python
ReaderContext.decode_name(raw: bytes) -> str  # a member name
ReaderContext.decode_text(raw: bytes) -> str  # any other stored text
```

Without `"auto"` they SHALL decode the same way: valid UTF-8, else `encoding=`, else
UTF-8 with `surrogateescape`. Under `encoding="auto"` both SHALL decode the way the
built-in formats do (archive-reading, "encoding="auto" guesses the codec of legacy
names"), sharing one guess per reader. Only `decode_name` SHALL add its bytes to the
evidence the guess is made from. `ReaderContext.encoding` SHALL be `None` under
`"auto"`, so a plugin that decodes with it never receives `"auto"` as a codec name.

#### Scenario: plugin under auto

| Case | Expected |
| --- | --- |
| Plugin calls `ctx.decode_name()` on cp932 bytes, `encoding="auto"` | Japanese text; `MEMBER_NAME_ENCODING_INFERRED` on that member |
| Plugin calls `ctx.decode_text()` on a link target or comment, `encoding="auto"` | Decoded with the current guess; the guess is unchanged |
| Plugin reads `ctx.encoding`, `encoding="auto"` | `None` |
| Plugin reads `ctx.encoding`, `encoding="cp932"` | `"cp932"`, as today |
