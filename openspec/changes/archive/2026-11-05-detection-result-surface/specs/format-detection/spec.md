## ADDED Requirements

### Requirement: A previously produced detection result can be handed to open

`open_archive()` and `open_stream()` SHALL accept a `detection=` argument carrying a result
produced by `detect_format()`, and SHALL skip detection when given one.

```python
result = detect_format(source)
if result.confidence is not DetectionConfidence.CERTAIN:
    ...                                  # the caller's own policy
reader = open_archive(source, detection=result)
```

Three properties, each a constraint rather than a convenience:

- **It is not `format=`.** `format=` is an override: it skips detection and suppresses
  `format_unconfirmed` because the caller took responsibility. `detection=` replays a result
  **archivey itself** produced, so the reader's `format_info` and its `format_unconfirmed`
  behaviour are exactly what a self-detecting open would have given. Routing a detection
  result through `format=` silently launders a guess into a trusted assertion.
- **The result names the source it came from.** A result handed to a *different* source SHALL
  raise rather than open the wrong bytes as the wrong format. This is a typo-catcher, **not**
  a security boundary: a path can change on disk between the two calls, and `detection=`
  inherits exactly the time-of-check-to-time-of-use window today's detect-then-open pattern
  already has.
- **On a non-seekable source it is the only way to look before opening.** Detection has
  already consumed the prefix and a second detection cannot re-read it. The replay buffer
  must therefore travel with the result, so on such a source the result is **not** a pure
  value object: it carries or references the buffered bytes and its lifetime is tied to the
  source's.

`format=` SHALL continue to perform **no detection I/O of any kind**. That contract — do
exactly what I said and no work I did not ask for — is what makes it usable as an escape
hatch.

#### Scenario: handoff matrix

| Case | Expected |
| --- | --- |
| `detect_format` then `open_archive(source, detection=result)` | Detection runs once; `reader.format_info` equals the standalone result |
| A `GUESS` result handed through `detection=`, read fails | Stamped `format_unconfirmed`, exactly as a self-detecting open would |
| The same result handed through `format=` instead | Not stamped — which is why the two are different parameters |
| A result from a different source | Raises; no open attempted |
| Non-seekable source, `detection=` with its replay buffer | Opens without a second read of the prefix |
| Non-seekable source, `detection=` whose buffer was released | Raises rather than re-reading bytes that are gone |
| Both `format=` and `detection=` given | Usage error — two different claims about the same question |
