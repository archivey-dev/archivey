# detection-result-surface — hand a detection result to open

**Status:** Parked, not part of 0.2.0 (2026-10-07). Cut down on 2026-09-25 after the evidence-ledger change was decided against. The reader keeping its `FormatInfo` and `archivey info` detecting once have shipped; what remains is the `detection=` handoff. Not needed for 0.2.0. Additive, no break. Effort: medium.

**Why it matters:** A caller who wants to look before opening calls detect format, then open archive, and pays for detection twice. On a pipe it cannot do that at all, because the first detection consumed the bytes the second one needs.

**What it does:** Open archive and open stream accept the result detect format already produced and skip detection. It is a separate parameter from the format argument on purpose: the format argument is the caller vouching for the format, so a read failure is not flagged as unconfirmed; a handed-over result is archivey's own guess, so the flag behaves exactly as if the open had detected. On a non-seekable source the result carries the bytes detection buffered, so its lifetime is tied to the source.

**Your call later:** Whether the result carries a source token that catches handing it to the wrong source, and what it is. It is a typo-catcher, not an integrity check.

**Bottom line:** Small convenience on files, the only way to inspect-then-open on a pipe.
