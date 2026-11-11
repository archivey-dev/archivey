"""The formats this package adds to archivey, read through libarchive."""

from __future__ import annotations

import errno as errno_codes
import io
from collections.abc import Callable, Iterator
from datetime import UTC, datetime
from typing import Any, ClassVar, TypeVar

from archivey import (
    ArchiveFormat,
    ArchiveMember,
    CorruptionError,
    MemberType,
    PluginContainer,
    ProcessIsolation,
    ResourceUnavailableError,
    StreamFormat,
    TruncatedError,
    UnsupportedFeatureError,
)
from archivey.exceptions import ArchiveyError
from archivey.formats import (
    ForwardStream,
    Magic,
    MemberSpan,
    ReaderArchiveInfo,
    ReaderContext,
    SequentialFormatHandler,
    SequentialReader,
)
from archivey_libarchive import _client
from archivey_libarchive._libarchive import (
    AE_IFDIR,
    AE_IFLNK,
    AE_IFREG,
    LibarchiveError,
    LibraryUnavailable,
    load,
)


class LibarchiveContainer(PluginContainer):
    """The containers this package adds."""

    LHA = "lha"


LHA = ArchiveFormat(LibarchiveContainer.LHA, StreamFormat.UNCOMPRESSED)

_READ_SIZE = 1 << 20

_T = TypeVar("_T")


def translate(exc: LibarchiveError) -> ArchiveyError:
    """A libarchive failure as archivey's error. libarchive gives a message and an
    errno, not a kind, so the kind is read from the message. archivey adds the format
    and the archive to the message."""
    message = f"libarchive: {exc.message}"
    lowered = exc.message.lower()
    if exc.errno == errno_codes.ENOMEM:
        return ResourceUnavailableError(message)
    if "truncated" in lowered or "unexpected end" in lowered:
        return TruncatedError(message)
    if "unsupported" in lowered or "not supported" in lowered:
        return UnsupportedFeatureError(message)
    return CorruptionError(message)


def _died(exc: _client.ChildDied) -> ArchiveyError:
    if exc.killed:
        return ResourceUnavailableError(str(exc))
    return CorruptionError(f"{exc}, reading this archive")


def _time(seconds: object, nsec: object) -> datetime | None:
    if not isinstance(seconds, int):
        return None
    try:
        stamp = datetime.fromtimestamp(seconds, UTC)
    except (OverflowError, ValueError, OSError):
        return None
    if isinstance(nsec, int) and 0 < nsec < 1_000_000_000:
        stamp = stamp.replace(microsecond=nsec // 1000)
    return stamp


def _dos_time(stamp: object) -> datetime | None:
    """A DOS date and time as the naive local time it records."""
    if not isinstance(stamp, int):
        return None
    t, d = stamp & 0xFFFF, stamp >> 16
    try:
        return datetime(
            ((d >> 9) & 0x7F) + 1980,
            (d >> 5) & 0x0F,
            d & 0x1F,
            (t >> 11) & 0x1F,
            (t >> 5) & 0x3F,
            (t << 1) & 0x3E,
        )
    except ValueError:
        return None


def _int(value: object) -> int | None:
    return value if isinstance(value, int) and value >= 0 else None


def _text(value: object) -> str | None:
    if not isinstance(value, bytes) or not value:
        return None
    return value.decode("utf-8", "surrogateescape")


class _EntryData(io.RawIOBase):
    """One entry's data, read from the session until the walk moves on."""

    def __init__(
        self, call: Callable[[Callable[[], bytes]], bytes], session: _client.AnySession
    ) -> None:
        super().__init__()
        self._call = call
        self._session = session
        self._done = False

    def readable(self) -> bool:
        return True

    def readinto(self, buffer: Any, /) -> int:
        n = min(len(buffer), _READ_SIZE)
        if self._done or n == 0:
            return 0
        data = self._call(lambda: self._session.read(n))
        if not data:
            self._done = True
            return 0
        buffer[: len(data)] = data
        return len(data)


class _LibarchiveReader(SequentialReader):
    fmt: ClassVar[str]
    checks_crc: ClassVar[bool]

    def __init__(self, context: ReaderContext) -> None:
        self._context = context
        isolation = context.config.process_isolation
        self._open_session: Callable[
            [str, Callable[[int], bytes], str | None], _client.AnySession
        ] = (
            _client.in_process_session
            if isolation is ProcessIsolation.NONE
            else _client.child_session
        )

    def archive_info(self) -> ReaderArchiveInfo:
        # libarchive reads forward only: a member out of order walks again from the
        # start, as a solid archive does.
        return ReaderArchiveInfo(is_solid=True)

    def _call(self, fn: Callable[[], _T]) -> _T:
        try:
            return fn()
        except LibarchiveError as exc:
            raise translate(exc) from None
        except _client.ChildDied as exc:
            raise _died(exc) from None
        except _client.ChildUnavailable as exc:
            raise ResourceUnavailableError(
                f"{exc}; set process_isolation=ProcessIsolation.NONE to read "
                "it in this process"
            ) from None

    def _stored(self, converted: bytes) -> bytes:
        """The name's stored bytes, as near as they can be had. With ``encoding=``,
        libarchive decoded every name with it (``hdrcharset``), a name that was valid
        UTF-8 too; encoding back gives the stored bytes, so that valid UTF-8 still
        wins in :meth:`ReaderContext.decode_name`, as in every format."""
        encoding = self._context.encoding
        if encoding is None:
            return converted
        try:
            return converted.decode("utf-8").encode(encoding)
        except (UnicodeError, LookupError):
            return converted

    def _member(self, header: dict[str, object]) -> ArchiveMember:
        converted = header.get("path")
        if not isinstance(converted, bytes) or not converted:
            raise CorruptionError("libarchive gave an entry with no name")
        raw = self._stored(converted)
        warning = header.get("warning")
        if warning:
            raise CorruptionError(f"libarchive: {warning}")
        filetype = header.get("filetype")
        size = _int(header.get("size"))
        link_target = None
        hardlink = header.get("hardlink")
        if isinstance(hardlink, bytes) and hardlink:
            kind = MemberType.HARDLINK
            link_target = self._context.decode_name(self._stored(hardlink))
            size = None
        elif filetype == AE_IFDIR:
            kind, size = MemberType.DIRECTORY, None
        elif filetype == AE_IFLNK:
            kind, size = MemberType.SYMLINK, None
            link_target = _text(header.get("symlink"))
        elif filetype == AE_IFREG:
            kind = MemberType.FILE
        else:
            kind, size = MemberType.OTHER, None
        perm = header.get("perm")
        mode = perm & 0o7777 if isinstance(perm, int) else None
        uid, gid = _int(header.get("uid")), _int(header.get("gid"))
        # When an LHA header stores no Unix mode or owner, libarchive makes them up
        # (0666 or 0777 less the DOS read-only bit; uid and gid 0): those are unknown.
        if header.get("lha_mode_stored") is False:
            mode = None
        if header.get("lha_owner_stored") is False:
            uid = gid = None
        if header.get("mtime_is_dos"):
            # Levels 0 and 1 store a DOS local time, which libarchive read in this
            # host's time zone: report the wall-clock time, naive, as ZIP does.
            modified = _dos_time(header.get("lha_dos_time"))
        else:
            modified = _time(header.get("mtime"), header.get("mtime_nsec"))
        return ArchiveMember(
            type=kind,
            name=self._context.decode_name(raw),
            raw_name=raw,
            size=size,
            modified=modified,
            mode=mode,
            uid=uid,
            gid=gid,
            uname=_text(header.get("uname")),
            gname=_text(header.get("gname")),
            link_target=link_target,
            is_encrypted=bool(header.get("encrypted")),
        )

    def walk(self, stream: ForwardStream) -> Iterator[MemberSpan]:
        session = self._call(
            lambda: self._open_session(self.fmt, stream.read, self._context.encoding)
        )
        try:
            while True:
                header = self._call(session.next_header)
                if header is None:
                    return
                member = self._member(header)
                if member.type is not MemberType.FILE:
                    yield MemberSpan(member)
                    continue
                data = _EntryData(self._call, session)
                yield MemberSpan(member, data=data, checked=self.checks_crc)
        finally:
            session.close()


class LhaReader(_LibarchiveReader):
    fmt = "lha"
    # libarchive checks each member's CRC-16 at the end of its data, and reports a
    # mismatch as a warning, which the session raises.
    checks_crc = True


def _require_library() -> None:
    try:
        load()
    except LibraryUnavailable as exc:
        raise UnsupportedFeatureError(str(exc)) from None


# Every LHA header level has its method id, such as ``-lh5-``, at offset 2.
_LHA_METHODS = (
    b"-lh0-",
    b"-lh1-",
    b"-lh2-",
    b"-lh3-",
    b"-lh4-",
    b"-lh5-",
    b"-lh6-",
    b"-lh7-",
    b"-lhd-",
    b"-lzs-",
    b"-lz4-",
    b"-lz5-",
)


class LhaHandler(SequentialFormatHandler):
    """LHA (LZH) archives, through libarchive."""

    format = LHA
    extensions = (".lzh", ".lha")
    magic = tuple(Magic(2, method) for method in _LHA_METHODS)
    uses_encoding = True

    def open_sequential(self, context: ReaderContext) -> SequentialReader:
        _require_library()
        return LhaReader(context)


HANDLERS = (LhaHandler,)
