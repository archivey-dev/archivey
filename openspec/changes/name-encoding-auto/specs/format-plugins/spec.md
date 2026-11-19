## ADDED Requirements

### Requirement: ReaderContext applies encoding="auto" for a plugin

Under `encoding="auto"`, `ReaderContext.decode_name(raw)` SHALL decode `raw` the way the
built-in formats do under `"auto"` (see archive-reading, "encoding="auto" guesses the
codec of legacy names"), sharing one guess per reader. Each call to `decode_name` SHALL
count as meeting a member name. `ReaderContext.encoding` SHALL be `None` under `"auto"`,
so a plugin that decodes with it gets the no-hint behaviour and never receives `"auto"`
as a codec name.

#### Scenario: plugin under auto

| Case | Expected |
| --- | --- |
| Plugin calls `ctx.decode_name()` on cp932 bytes, `encoding="auto"` | Japanese text; `MEMBER_NAME_ENCODING_INFERRED` on that member |
| Plugin reads `ctx.encoding`, `encoding="auto"` | `None` |
| Plugin reads `ctx.encoding`, `encoding="cp932"` | `"cp932"`, as today |
