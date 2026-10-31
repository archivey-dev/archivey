## MODIFIED Requirements

### Requirement: Bounded-memory sequential streaming via stream_members

```python
def stream_members(
    self,
    members: MemberSelector | None = None,
    *,
    file_copy_streams: bool = True,
) -> MemberPass[tuple[ArchiveMember, ArchiveStream | None]]: ...
```

Yields `(member, stream)` in archive order with bounded memory. Solid blocks
decompress progressively (never buffered whole); peak = decoder working set + one
in-flight chunk. Non-file members yield `None`, except a directory that declares data
(see "stream_members yields a stream for exactly the members open() reads").

`file_copy_streams=False` SHALL also yield `None` for a `FILE` member that the archive
stores as a copy of an earlier member (`extra["is_file_copy"]`; only `format-rar` has
them), and the pass SHALL keep nothing for such copies. The copy's bytes and digests are
those of its source, `link_target_member`. The default yields the copy's bytes. A value
that is not a `bool` SHALL raise `ArchiveyUsageError` at the call.

`members` is a selector (names/identities or predicate), not a transform. Streams
are lazy: unselected/unread members are not opened/decompressed and do not request
passwords. Yields the original mutable `ArchiveMember` so late-bound fields stay
visible. A yielded stream whose deferred open fails on its first read (a wrong password,
an unsupported method) SHALL raise that error again on every later read, as a content
verdict is raised again (same type and arguments, first raise as its cause), and SHALL
NOT try the open again.

Symlink targets stored as member data (ZIP, 7z, RAR3/4) are the one exception, and only
while `read_link_targets` is `True` (see "Link targets stored as member data are read
only when configured"). A pass that finalizes then reads every such target, selected or
not, so the complete report matches random access. That read MAY decompress data the
caller did not select and MAY consult the password provider. On 7z it decodes the link's
folder up to the link, within the budget of `format-7z` "A 7z folder is decoded at most
once for its link targets". With `read_link_targets=False` the promise holds without
exception.

Yielded streams are iterator-owned and valid only until advance: the iterator SHALL
close/invalidate the previous stream before the next yield. MUST NOT retain a
growing decompressed-block cache until reader close. On solid archives, random
`open()` may re-decode from block start; the cost is silent, and callers are
directed to `stream_members()` by `reader.cost.access_cost` and by the `open()` /
`read()` docstrings rather than by a runtime warning.

A member's data error (a digest mismatch, a corrupt or cut-short compressed stream) SHALL
be raised from that member's stream read and SHALL NOT end the pass, whether or not the
caller read that stream: the pass SHALL yield the members after it whenever the walk of
the archive's structure can reach them, and SHALL end without raising. Members after the
damage in the same solid block fail too, each from its own read, as `7z t` and `unrar t`
fail them; a later solid block reads cleanly. Random `open()` / `read()` give each member
the same outcome; on a solid block `open()` decodes from the block start up to the member,
so the error MAY be raised from `open()` instead of the first read. A format that stores
no member checksum (ISO, TAR) returns damaged bytes with no error. Of the damage cases,
only damage to the archive's structure that stops the walk makes the pass itself raise
(DR-2): a TAR cut inside a member, a compressed TAR whose stream fails, a ZIP read from a
pipe whose local-header walk loses its place. The members after that point are not
yielded; resyncing past such damage is out of scope. (The pass also raises for reasons
other than damage, such as `ListingLimits` or a diagnostic set to raise.)

A `stream_members()` invocation is an exclusive one-pass/data-path operation in
both modes. It SHALL NOT overlap random `open()`, materialization, another
iteration/data pass, unrelated extraction, or reader close. On a reader opened with
`concurrent_operations=True`, random `open()` / `read()` / `get()` / `members()`,
iteration, further `stream_members()` passes and `extract_all()` MAY run beside it, on
every format (`reader-concurrency`, "Random-access calls beside a pass"). An
`extract_all()` owner MAY invoke it as a child pass and MAY read/close the yielded
child stream. Unrelated overlap SHALL raise `ArchiveyUsageError` at the later op and
leave the active pass/stream valid. (Unlike random `open()`, whose independently
owned streams may coexist when `CONCURRENT` is declared — see `reader-concurrency`.)

Reader close is the one exception, and only while the pass is suspended at a yield
(the caller holds the iterator and is not inside a `next()` call). `close()` and
`with`-exit then close the reader, as `zipfile.ZipFile.close()` does with member
handles open, in this order: the backend's pass is wound down (its last yielded
stream closed, then its pass-scoped resources such as a solid block or an `unrar`
pipe released), then any other member stream still open is closed, and only then is
the archive torn down. Resuming that iterator SHALL raise `ArchiveyUsageError`. A
pass that is executing (inside `next()`, e.g. a selector on another thread) still
makes `close()` raise (maintainer's ruling, 2026-10-10).

The returned `MemberPass` SHALL be an iterator of `(member, stream)` pairs that also has
`close()` and works as a context manager whose exit calls `close()`. Closing a pass
SHALL end it at once, as closing a generator does: the last yielded stream is closed and
the pass releases the reader. Closing does not give a streaming reader a second pass:
`__iter__`, `stream_members()` and `extract_all()` still raise, and `members_report()`
finishes the interrupted walk. Closing an ended or closed pass SHALL do nothing, and
advancing a closed pass SHALL end the iteration. Closing a pass that is executing
(another thread inside `next()`, or a selector closing its own pass) SHALL raise
`ArchiveyUsageError` and leave the pass running, as `reader.close()` does; a
`ValueError` the pass itself raises on close SHALL reach the caller unchanged. A plain
`for` loop over a pass SHALL behave as before.

#### Scenario: stream_members matrix

| Case | Expected |
| --- | --- |
| Yielded file stream emits diagnostic before advance | Stream + reader snapshots share one retained occurrence |
| Selector excludes member / stream unread | No open/decompress; no data-path diagnostic. With `read_link_targets=True`, a data-stored symlink target is still read at finalization (see the exception above) |
| Solid archive | Progressive decode; peak = decompressor state + one chunk |
| `stream_members(lambda m: m.name.endswith(".txt"))` | Only `.txt`; unselected never opened, except data-stored symlink targets when `read_link_targets=True`; original mutable members |
| Fully read stream, then inspect member | Late-bound fields (e.g. size/CRC) visible on same object |
| Advance after one yield | Prior stream closed/invalidated first |
| Random `open()` during active pass | `ArchiveyUsageError`; pass remains usable. Under `concurrent_operations=True`: admitted |
| Close/abandon partial generator | Current stream closed; pass ownership released once |
| `reader.close()` / `with`-exit while the pass is suspended at a yield | Reader closed; yielded stream closed; next `next()` → `ArchiveyUsageError`; a body exception propagates unchanged |
| `reader.close()` while the pass is executing (another thread inside `next()`) | `ArchiveyUsageError`; reader stays open; pass remains usable |
| Random `open()` into solid block | Re-decode from block start + skip; no diagnostic, no warning — discoverable via `reader.cost.access_cost` and the `open()` docstring |
| Unencrypted solid 7z, selector excludes a symlink, pass to the end (default config), either access mode | The link's target is resolved; its folder is decoded up to the link once |
| Pass to the end without `members()`, either access mode, over a ZIP, 7z, RAR4 or RAR5 holding symlinks (default config) | Each yielded symlink ends with the same `link_target` a `members()` call would set, unset where that read cannot produce one |
| Encrypted solid 7z `[a.txt, link, b.txt]`, `read_link_targets=False`, `stream_members(lambda m: False)` to the end | Nothing decoded; provider never consulted; `link_target` unset; no `SYMLINK_TARGET_UNAVAILABLE` |
| `stream_members(file_copy_streams=False)`, RAR5 file copy | The copy is yielded with stream `None`; its source with its bytes |
| `stream_members(file_copy_streams=0)` | `ArchiveyUsageError` at the call |
| One member's data damaged, non-solid ZIP (from a file or a pipe), 7z or RAR, either mode, its stream read or not | That member's read raises `CorruptionError`; every later member is yielded and reads correctly; the pass ends without raising |
| Same, solid 7z with one folder or solid RAR | The damaged member and the later ones in its block raise from their reads; the pass ends without raising |
| Same, solid 7z with two folders, damage in the first | Only the damaged member raises; the second folder reads correctly |
| Same, ISO or plain TAR | No error; the damaged bytes are returned; later members read correctly |
| Archive structure damaged (TAR cut inside a member, compressed TAR stream fails, pipe ZIP local header lost) | Members before the damage yielded; then the pass raises and ends |
