## ADDED Requirements

### Requirement: Caller code runs on the calling thread

Archivey SHALL call a function the caller passed (`on_diagnostic`, `on_progress`,
a password provider, a `members=` selector function, a `filter=` function) on the
thread whose call into archivey needs it, before that call returns, except while
the garbage collector closes a stream or pass the caller left open. Archivey SHALL
NOT call caller code from a thread it started.

#### Scenario: callback thread matrix

| Call, made on a worker thread | Callback | Runs on |
|---|---|---|
| `members()` on a ZIP whose name is normalized | `on_diagnostic` | the worker |
| `extract_all(filter=f, on_progress=p)` | `f`, `p` | the worker |

#### Scenario: shared member list

Under `concurrent_operations=True`, the thread that builds the member list runs the
functions that listing calls; the threads waiting for it do not.

#### Scenario: work done elsewhere

Whatever decodes the data (an accelerator, a decoder in a child process, an external
program), its reports come back to the calling thread, which runs the caller's
functions: a backward seek in a `.gz` stream decoded in a child under
`ProcessIsolation.NATIVE_DECODERS` reports `STREAM_REWIND_REDECOMPRESSES` to
`on_diagnostic` on the thread that seeked.

#### Scenario: a stream the collector closes

A member stream or `stream_members()` pass the caller drops without closing is
closed when Python frees it, on whatever thread frees it: usually the one that drops the
last reference, or for a reference cycle the one where the garbage collector runs. A
diagnostic that close reports (`ENCRYPTED_MEMBER_UNVERIFIED` for a partly read ZipCrypto
member) reaches `on_diagnostic` on that thread.
