## 1. Code

- [x] 1.1 `ArchiveStream` in `archivey.reader` becomes a base class with the public stream surface and no constructor; the stream class moves to `ArchiveStreamImpl` in `archivey.internal.streams.archive_stream`, which backends and `open_codec_stream` build directly
- [x] 1.2 `MemberPass` becomes a base class; the reader builds `MemberPassImpl` (`archivey.internal.member_pass`)
- [x] 1.3 Calling either base directly warns and builds the internal subclass, until 0.4.0
- [x] 1.4 With no public class left under `internal`, `archivey/__init__.py` pins only functions

## 2. Tests and docs

- [x] 2.1 `tests/test_deprecated_constructors.py` pins the warnings and that the reader's own paths emit none; other tests build the internal classes
- [x] 2.2 `dev-docs/api-surface.txt` regenerated
- [x] 2.3 `openspec validate --strict reader-built-streams-and-passes`, then archive
