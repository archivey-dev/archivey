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
SHALL NOT fix the text of any bytes.

Under `"auto"`, archivey SHALL make a plugin's directory members wait as the built-in
formats do, with no new call from the plugin. A directory member whose `name` is the
text `decode_name` returned for its `raw_name`, or that text with `\` turned into `/`,
SHALL be held, charged against the listing limits, and listed before a listing cap
raises. When its wait ends, it SHALL take the text that the member ending the wait gives
its prefix, when that member lies under it, and otherwise the decode of `raw_name` with
the guess that member's name was decoded with. Two `decode_name` calls on the same
bytes SHALL return the same text, except that a directory that waited decodes to its
listed text from its listing on. Any other directory member SHALL keep the plugin's
name. `ReaderContext.encoding` SHALL be `None` under
`"auto"`, so a plugin that decodes with it never receives `"auto"` as a codec name.

#### Scenario: plugin under auto

| Case | Expected |
| --- | --- |
| Plugin calls `ctx.decode_name()` on cp932 bytes, `encoding="auto"` | Japanese text; `MEMBER_NAME_ENCODING_INFERRED` on that member |
| Plugin calls `ctx.decode_text()` on a link target or comment while parsing a member, `encoding="auto"` | Decoded with the guess as of that member; the guess is unchanged |
| Plugin calls `ctx.decode_text()` from `archive_info()`, `encoding="auto"` | Decoded as without `"auto"`, whenever `info` is read |
| Plugin calls `ctx.decode_text()` before `ctx.decode_name()` on the same bytes | `decode_name` returns what it would have returned without the earlier `decode_text` |
| LHA `ポ\|target` field in cp932, `decode_name_and_target(raw, b"\|")` under `encoding="auto"` | Name `ポ`, target `target`; only `ポ` adds evidence |
| cpio plugin-shaped reader, Big5 `新/` then `新/報告書.txt`, `encoding="auto"` | The directory waits; both names start with `新/` |
| Plugin yields a directory whose name it joined from parts, `encoding="auto"` | The plugin's name, with no wait |
| XAR: Big5 `新/`, then `新/報告書.txt` and `新/會議記錄.txt`, children joined from the parent's first text | One tree: the directory takes the children's prefix text |
| CAB: cp932 `資.txt` as record 0, eight cp932 names, `資.txt` again as record 9 | Both records decode to one text; the repeated-name handling runs |
| Plugin yields 6 directories in a row, `ListingLimits(max_members=5)` | 5 directories listed, then `ResourceLimitError` |
| Plugin reads `ctx.encoding`, `encoding="auto"` | `None` |
| Plugin reads `ctx.encoding`, `encoding="cp932"` | `"cp932"`, as today |
