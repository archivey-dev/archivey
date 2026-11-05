# format-rar — file-copy source release delta

## MODIFIED Requirements

### Requirement: Serve a solid pass's file copies from the source it decoded

A solid `stream_members()` pass, and the extraction built on it, SHALL keep the bytes of
each member that a later RAR5 file copy (`rar -oi`) in the pass reads, as its pipe passes
them, whether the caller reads that member or skips it, under `unrar` and `unar`. It
SHALL serve the copies from the kept bytes, so a kept source is decoded once for all its
copies. Kept bytes SHALL pass the source's digest check and declared size as the pipe's
own bytes do, and SHALL count toward extraction limits once per copy.

The pass SHALL keep up to 8 MiB of sources in memory. This constant is a tuning value: it
SHALL NOT refuse a read or change the bytes a read returns, and it is not a field of
`ArchiveyConfig`. A source past it SHALL go to a temporary file charged to
`SpoolLimits.max_bytes` (`archive-reading`). The file SHALL be created, and the source
charged, only when the source's first byte is decoded, so a pass that reads nothing writes
nothing and any copy of the archive source the pass needs is charged before the kept
source. Once the pass has reached the member after a source's last copy, it SHALL let
the source go: its memory is freed, and when no source in the temporary file is still
waiting for a copy, the file is deleted and its charge given back, so a later source
starts a new one. The pass SHALL NOT change the order it yields members in for this.
Whatever is still kept SHALL be let go when the pass ends. A source the limit has no room
for SHALL NOT be kept, and its copies SHALL read the source with a named open, as
`open()` does; that SHALL NOT raise `ResourceLimitError`. A source that the pass does not
emit (a `unar` refusal) SHALL fall back the same way.

Extraction SHALL NOT have the pass keep a source that it is writing to disk from the
pass's stream. It SHALL write each later copy of that source by copying the file it
wrote, when that file is still the one it wrote (same device, inode, size and
modification time, checked on the opened file) and the copy declares the source's size.
Those bytes SHALL count toward extraction limits as the copy's own, as bytes read from
the pass do. They need no second digest check: the source's write passed them through
the source's digest and size checks, and a write that failed them records no identity for
the copy to check against, so the copy falls back to the pass. Otherwise (a selector or filter dropped the source, its write failed, a
later member took its path, or the file changed) the copy SHALL be read from the pass:
from the kept bytes when the extraction did not write the source, and with a named open
when it did. A dry run writes empty files, so it SHALL keep sources as `stream_members()`
does.

`stream_members(file_copy_streams=False)` SHALL yield every file copy with a `None`
stream, solid or not, and a solid pass SHALL then keep no source.

#### Scenario: kept file-copy source matrix

| Case | Expected |
| --- | --- |
| Solid pass, source read, copies read | One decompressor run; every copy reads the source's bytes |
| Solid pass, source skipped, copies read | One decompressor run; the pass moves through the source and keeps it |
| `extract_all()` with a filter that drops the source | One decompressor run; the copies are written |
| Source over 8 MiB, no member read, stream source | Nothing is written: no temporary file, no copy of the archive |
| Source over the memory constant, within `SpoolLimits.max_bytes` | Kept in the temporary file; one decompressor run |
| Two passes on one reader, room for the source once | Each pass keeps it; one decompressor run per pass |
| Two sources, each followed by its copy, then a member; room in the limit for one source | Each is kept in turn; the first is let go after its copy; one decompressor run |
| Stream source, first member a source; the archive copy and the source each fit the limit, not both | The archive copy is made; the source is not kept; each copy decodes it again; no `ResourceLimitError` |
| `SpoolLimits.max_bytes=0`, path source, source over the memory constant | Not kept; each copy decodes it again; nothing is refused |
| Kept bytes that do not match the source's digest | `CorruptionError` on the copy's read |
| `max_extracted_bytes` below the total with copies | `ResourceLimitError`; each copy counts its bytes |
| `extract_all()`, source written from the pass, `SpoolLimits.max_bytes=0`, source over the memory constant | One decompressor run; nothing kept; each copy copied from the source's file |
| `extract_all()`, `streaming=True`, source written | The same: one decompressor run; each copy copied from the source's file |
| `extract_all()`, the source's file replaced before its copies are written | Each copy gets the source's bytes from the archive, not the replacement's; it decodes the source again |
| `extract_all(dry_run=True)` | Sources kept; one decompressor run |
| `stream_members(file_copy_streams=False)`, solid, under `unrar` and `unar` | Copies yielded with `None`; nothing kept; one decompressor run |
| `stream_members(file_copy_streams=False)`, nonsolid | Copies yielded with `None` |
