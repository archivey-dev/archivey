## ADDED Requirements

### Requirement: ReaderContext applies encoding="auto" for a plugin

`ReaderContext` SHALL offer two decoders for stored bytes:

```python
ReaderContext.decode_name(raw: bytes) -> str  # a member name
ReaderContext.decode_text(raw: bytes) -> str  # any other stored text
ReaderContext.decode_name_and_target(
    raw: bytes, separator: bytes
) -> tuple[str, str | None]  # a member name and a link target in one field
```

`decode_name_and_target` SHALL split `raw` at the first `separator` that falls at a
character boundary of the codec the field decodes with, and SHALL return the name part
and the target part, or `None` for the target when there is no such separator.

Without `"auto"` they SHALL decode the same way: valid UTF-8, else `encoding=`, else
UTF-8 with `surrogateescape`. Under `encoding="auto"` both SHALL decode the way the
built-in formats do (archive-reading, "encoding="auto" guesses the codec of legacy
names"), sharing one guess per reader. Only `decode_name` SHALL add its bytes to the
evidence the guess is made from, and only the name part of `decode_name_and_target`.
`decode_text` SHALL decode with the guess as of the last `decode_name` call, so a plugin
SHALL call it for a member's text while it parses that member. Called from
`archive_info()`, it SHALL use no guess. `decode_text` SHALL read the names already
decoded, so a link target that names a member met earlier gets that member's text, and
SHALL NOT fix the text of any bytes. `ReaderContext.encoding` SHALL be `None` under
`"auto"`, so a plugin that decodes with it never receives `"auto"` as a codec name.

#### Scenario: plugin under auto

| Case | Expected |
| --- | --- |
| Plugin calls `ctx.decode_name()` on cp932 bytes, `encoding="auto"` | Japanese text; `MEMBER_NAME_ENCODING_INFERRED` on that member |
| Plugin calls `ctx.decode_text()` on a link target or comment while parsing a member, `encoding="auto"` | Decoded with the guess as of that member; the guess is unchanged |
| Plugin calls `ctx.decode_text()` from `archive_info()`, `encoding="auto"` | Decoded as without `"auto"`, whenever `info` is read |
| Plugin calls `ctx.decode_text()` before `ctx.decode_name()` on the same bytes | `decode_name` returns what it would have returned without the earlier `decode_text` |
| LHA `ポ\|target` field in cp932, `decode_name_and_target(raw, b"\|")` under `encoding="auto"` | Name `ポ`, target `target`; only `ポ` adds evidence |
| Plugin reads `ctx.encoding`, `encoding="auto"` | `None` |
| Plugin reads `ctx.encoding`, `encoding="cp932"` | `"cp932"`, as today |
