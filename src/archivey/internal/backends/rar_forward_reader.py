"""Read a RAR archive front to back from a source that cannot seek.

:class:`RarForwardReader` serves ``stream_members()`` and ``extract_all()`` over a
single-volume RAR read from a pipe or socket. It never holds the archive:

1. At open it walks the headers up to the first member (``MAIN``, ``ENCRYPTION``, an
   archive comment), so the version, the solid flag and the header password are known
   and a volume of a set is refused there.
2. A pass writes the members as rolling volumes (``rar_rolling``) as the walk reaches
   them, and one ``unrar p -vp`` run decodes them all. Its output is cut by member
   size, as the seekable reader's solid pass cuts it (``RarReader._drive_solid_pass``).
3. A member is listed once its header and data are in a volume and the walk has read
   the next header, which may still add to it (a RAR 1.5-4 owner or file comment), or
   when a volume that ends inside it is written. Only a member larger than a volume is
   split. A member listed the second way gets what that next header adds in place,
   before the pass ends; it is not final until then.

Volume 1 is written on the caller's thread; ``unrar`` starts on the first member read,
or when the listing needs a member past volume 1. Then the thread that answers
``unrar``'s volume prompts writes the next volumes, and the walk runs on it; listed
members reach the caller's thread through a queue. While the caller waits for the next
member, it reads past ``unrar``'s output of the members it has had, so ``unrar`` is
never stuck on a full pipe while the walk waits for its next volume prompt.

What a pipe cannot do, and the pass refuses instead: read a member whose output does not
line up (a member of unknown size, a wrong password, an unknown compression version in a
solid archive) or any member after it, read a RAR5 file copy (its source bytes were not
kept), and give each member its own password from several candidates. The design is
tracked internally; ``openspec/changes/archive/2026-11-14-rar-pipe-reader`` holds it.
"""

from __future__ import annotations

import io
import queue
import subprocess
import threading
import zlib
from collections.abc import Callable, Iterable, Iterator
from pathlib import Path
from typing import BinaryIO, Literal, cast

from archivey.config import RarDecompressor
from archivey.cost import AccessCost, CostReceipt, ListingCost, StreamCapability
from archivey.exceptions import (
    ArchiveyError,
    CorruptionError,
    EncryptionError,
    ReadError,
    StreamNotSeekableError,
    TruncatedError,
    UnsupportedFeatureError,
)
from archivey.formats import ArchiveFormat
from archivey.internal.backends.rar_copy_sources import FileCopySources
from archivey.internal.backends.rar_forward import ForwardSource, ForwardSpan
from archivey.internal.backends.rar_parser import (
    ForwardMember,
    ForwardWalk,
    RarArchive,
    RarMemberInfo,
    _Rar3Comment,
    open_forward_walk,
    public_walk_errors,
)
from archivey.internal.backends.rar_reader import (
    _NO_DICTIONARY,
    RarReader,
    _DictionaryCost,
    _larger_cost,
    _psw_check_usable,
    _rolling_volume_bytes,
    _RollingUnrarStream,
    _share_unknown_copy_size,
    _size_left_unknown,
)
from archivey.internal.backends.rar_rolling import (
    RollingVolumes,
    SourceReadError,
    VolumeFeeder,
    start_rolling_unrar,
)
from archivey.internal.backends.rar_synthetic import SyntheticMember, has_packed_data
from archivey.internal.backends.rar_unar import uses_no_dictionary
from archivey.internal.backends.rar_unrar import open_unrar_p
from archivey.internal.file_copy_pass import DEFAULT_FILE_COPY_PASS, FileCopyPass
from archivey.internal.hashing import crc32_digest
from archivey.internal.naming import resolve_link_target_name
from archivey.internal.overrides import override
from archivey.internal.password import _PasswordCandidatesExhausted
from archivey.internal.pe_resources import ProgramResources
from archivey.internal.source import ArchiveSource
from archivey.internal.streams.archive_stream import (
    ArchiveStreamImpl,
    MemberStreamParts,
)
from archivey.internal.streams.crypto import note_crypto_use
from archivey.internal.streams.streamtools import DelegatingStream, SolidBlockReader
from archivey.internal.streams.streamtools.shared import SharedSource, SharedView
from archivey.terminal import quoted
from archivey.types import (
    ArchiveInfo,
    ArchiveInfoExtra,
    ArchiveMember,
    HashAlgorithm,
    MemberType,
)

#: The longest RAR 1.5-4 symlink target a pass keeps from the source, which is
#: that member's data. A longer one is reported as unreadable.
_LINK_TARGET_BYTES = 64 << 10
# How long the caller's thread waits for the next member before it checks that the
# thread writing the volumes is still alive.
_WAIT_SECONDS = 0.1

_ROLLING_FIX = (
    "Use a seekable source (a file, or the stream read into a BytesIO), or install "
    "RARLAB unrar 7.00 or later."
)


class _Closed(ReadError):
    """The reader was closed while a volume was being written; the walk ends."""

    def __init__(self) -> None:
        super().__init__("The RAR reader was closed during its pass")


class _End:
    """The walk is over: ``error`` is what stopped it, if anything did."""

    def __init__(self, error: BaseException | None) -> None:
        self.error = error


class _HeldBytes(SharedSource):
    """The ``SharedSource`` a forward reader has: the few member data spans the walk
    kept (a RAR 1.5-4 symlink's target), by offset. Any other span is refused."""

    def __init__(self, held: dict[int, bytes]) -> None:
        super().__init__(io.BytesIO())
        self._held = held

    @property
    @override
    def size(self) -> int | None:
        return None

    @override
    def view(self, start: int, length: int | None = None) -> SharedView:
        data = self._held.get(start)
        if data is None:
            raise StreamNotSeekableError(
                "A RAR archive read from a non-seekable source keeps no member data "
                "to read again; read the member as the pass reaches it."
            )
        return SharedSource(io.BytesIO(data)).view(0, length)

    @override
    def close(self) -> None:
        self._held.clear()
        super().close()


class _ForwardVolumes(RollingVolumes):
    """Rolling volumes that tell the pass when each one is written."""

    def __init__(
        self,
        version: int,
        members: Iterable[SyntheticMember],
        *,
        solid: bool,
        volume_bytes: int,
        on_written: Callable[[bool], None],
    ) -> None:
        super().__init__(version, members, solid=solid, volume_bytes=volume_bytes)
        self._on_written = on_written

    @override
    def write_next(self) -> Path:
        path = super().write_next()
        self._on_written(self.splitting)
        return path


class _PaddedSpan:
    """A member's packed bytes from the forward source. When the source ends first,
    it reads zeros for the rest of the volume being written, so that volume is still
    written and the members before it there still decode; the member is marked cut.
    A read for a later volume raises ``cut_error``: padding the rest of a declared
    size the archive chooses would cost time in proportion to it, for no member."""

    def __init__(
        self,
        span: ForwardSpan,
        size: int,
        on_cut: Callable[[], None],
        stopping: Callable[[], bool],
        volume: Callable[[], int],
        cut_error: Callable[[], ArchiveyError],
    ):
        self._span = span
        self._left = size
        self._on_cut = on_cut
        self._stopping = stopping
        self._volume = volume
        self._cut_error = cut_error
        # The volume being written when the source ended, once it has.
        self._cut_in: int | None = None

    def read(self, n: int = -1) -> bytes:
        if n < 0 or n > self._left:
            n = self._left
        if n <= 0:
            return b""
        if self._stopping():
            raise _Closed()
        if self._cut_in is not None and self._volume() != self._cut_in:
            raise self._cut_error()
        data = b"" if self._cut_in is not None else self._span.read(n)
        if not data:
            if self._cut_in is None:
                self._cut_in = self._volume()
                self._on_cut()
            data = bytes(n)
        self._left -= len(data)
        return data

    def close(self) -> None:
        self._span.close()


class _LineCheck:
    """Whether a member's slice of the pass's output is the member's output, by its
    CRC32. Used after an earlier member failed its check: its output may have had
    another length than its header says, and then this slice starts in the wrong
    place."""

    def __init__(
        self,
        size: int,
        matches: Callable[[bytes], bool],
        on_match: Callable[[], None],
        on_mismatch: Callable[[], ArchiveyError],
    ) -> None:
        self._left = size
        self._crc = 0
        self._matches = matches
        self._on_match = on_match
        self._on_mismatch = on_mismatch
        # ``None`` until the slice ends, then whether it matched.
        self._matched: bool | None = None

    def update(self, data: bytes) -> None:
        """Take the bytes of one read of ``n`` > 0 bytes: none at the end. Every
        read from the one that ends a slice that does not match raises."""
        if self._matched is None:
            self._crc = zlib.crc32(data, self._crc)
            self._left -= len(data)
            if data and self._left > 0:
                return
            self._matched = self._left == 0 and self._matches(crc32_digest(self._crc))
            if self._matched:
                self._on_match()
        if not self._matched:
            raise self._on_mismatch()


class _ForwardMemberStream(DelegatingStream):
    """Check the real source after each read, before padding can pass verification,
    and, with ``line``, that the slice is the member's output."""

    readinto_passthrough = False

    def __init__(
        self,
        inner: BinaryIO,
        check_cut: Callable[[], None],
        line: _LineCheck | None = None,
    ) -> None:
        self._check_cut = check_cut
        self._line = line
        super().__init__(inner)

    @override
    def read(self, n: int = -1, /) -> bytes:
        data = super().read(n)
        if n != 0:
            # _PaddedSpan marks the cut before returning any padding, so this
            # check sees the mark before padded bytes can reach the verifier.
            self._check_cut()
            if self._line is not None:
                # Before the verifier gets the last bytes: a slice from the wrong
                # place is refused as such, not reported as damage to this member.
                self._line.update(data)
        return data


class _ForwardPass:
    """One pass: the walk feeding the rolling volumes, and the members it lists."""

    def __init__(self, reader: RarForwardReader) -> None:
        self._reader = reader
        #: The archive's source, which the feeder thread reads.
        self.source = reader._source
        self.queue: queue.SimpleQueue[ForwardMember | _End] = queue.SimpleQueue()
        self._held: ForwardMember | None = None
        #: The members the walk released before it read the header after them
        #: (``_release_early``), by ``id`` of the parsed member.
        self.early: set[int] = set()
        #: Held by the caller while it builds a member released early, and by the
        #: walk while it reads the header after that member, which may write into
        #: it. The walk never waits for the caller to list the member: the caller
        #: may be inside the read of an earlier member, waiting for output that
        #: ``unrar`` writes only once the walk's thread has written its next volume.
        self.building = threading.Lock()
        #: Set when the reader closes: the walk stops at its next read of the source.
        self.stopping = False
        #: The error the feeder stopped ``unrar`` with when the source ended inside a
        #: member and the volume the cut is in was written (``_PaddedSpan``).
        self.cut_stop: ArchiveyError | None = None
        self._charge = _rolling_volume_bytes(reader._config.spool_limits)
        self._released = False
        self.stream: _RollingUnrarStream | None = None
        self.pipe: Callable[[], SolidBlockReader] | None = None
        archive = reader._archive
        with reader._materialize_lock:
            if not reader._reserve_synthetic(
                self._charge,
                reader._archive_name or "",
                "one rolling volume of a RAR archive read from a non-seekable source",
                fallback=False,
            ):
                raise AssertionError("a refused spool charge check_fits let through")
        try:
            self.volumes = _ForwardVolumes(
                archive.version,
                self._entries(),
                solid=archive.is_solid,
                volume_bytes=self._charge,
                on_written=self._release_early,
            )
        except BaseException:
            self._release()
            raise

    # -- the thread that writes volumes ------------------------------------------

    def _release_held(self) -> None:
        held, self._held = self._held, None
        if held is not None:
            self.queue.put(held)

    def _release_early(self, splitting: bool) -> None:
        """A volume is written. When it ends inside the member the walk holds, list
        that member now, before the walk reads the header after it: ``unrar`` writes
        the member's output from this volume before it asks for the next one, and
        the caller must be able to read it. A member whose data starts in the next
        volume stays held. A record in that next header (a RAR 1.5-4 ``UOW`` owner
        or ``CMT`` comment) then reaches a member already listed, and is written
        into it (``RarForwardReader._add_late_records``)."""
        held = self._held
        if not splitting or held is None:
            return
        self.early.add(id(held.member))
        self._release_held()

    def stop(self) -> None:
        """Stop the walk at its next read of the source."""
        self.stopping = True

    def _entries(self) -> Iterator[SyntheticMember]:
        """The synthetic members of the volumes, made as the walk reaches them."""
        reader = self._reader
        position = 0
        found = reader._take_first()
        try:
            while found is not None:
                if self.stopping:
                    raise _Closed()
                self._release_held()
                self._held = found
                entry = reader._forward_entry(found, position)
                if entry is not None:
                    position += 1
                    yield entry
                if id(found.member) in self.early:
                    # The caller may be building that member now.
                    with self.building:
                        found = reader._next_found()
                else:
                    found = reader._next_found()
        except Exception as exc:  # noqa: BLE001 - handed to the listing
            # The volume being written ends here, so the members already in it are
            # still decoded; the listing raises this after them, and so does the
            # read of the member the walk held, whose data it was reading.
            reader._fwalk_error = exc
            self._release_held()
            self.queue.put(_End(exc))
            return
        self._release_held()
        self.queue.put(_End(None))

    # -- the caller's thread ------------------------------------------------------

    def spawn(self) -> BinaryIO:
        """Start ``unrar`` on volume 1 (written now when it is not yet)."""
        reader = self._reader
        password = reader._archive_data_password()
        proc, stdout, feeder = start_rolling_unrar(
            self.volumes,
            password=password,
            member=None,
            version_control=True,
            rar5=reader._archive.version == 5,
            program=reader._unrar_program,
            usage=reader._usage,
            opener=open_unrar_p,
        )
        self.stream = _ForwardUnrarStream(
            self,
            stdout,
            proc,
            feeder,
            self.volumes,
            self._release,
            named_member=False,
            # Every member is verified on its own, as in the seekable pass.
            has_verifiable_hash=True,
            encrypted=password is not None,
        )
        return self.stream

    def next_found(self) -> ForwardMember | _End:
        """The next member the walk lists, or the end of the walk."""
        while True:
            try:
                return self.queue.get_nowait()
            except queue.Empty:
                pass
            if self.stream is None:
                if self.volumes.count == 0:
                    try:
                        self.volumes.write_next()
                    except SourceReadError as exc:
                        raise exc.cause from None
                    except OSError as exc:
                        raise ReadError(
                            f"Could not write the first RAR volume for unrar: {exc}"
                        ) from exc
                    continue
                # The walk needs volume 2, which waits for unrar to finish volume 1.
                assert self.pipe is not None
                self.pipe()
                continue
            self._drain()
            try:
                return self.queue.get(timeout=_WAIT_SECONDS)
            except queue.Empty:
                pass
            feeder = self.stream.feeder
            if not feeder.running:
                try:
                    return self.queue.get_nowait()
                except queue.Empty:
                    pass
                error = feeder.error
                if error is not None:
                    raise error
                raise ReadError(
                    "unrar stopped before the RAR archive's headers were all read"
                )

    def _drain(self) -> None:
        """Read past ``unrar``'s output of the members the caller has had."""
        assert self.pipe is not None
        solid = self.pipe()
        target = self._reader._pipe_end
        if target is None:
            # The output no longer lines up: nothing in it is read any more.
            try:
                solid.skip_to(1 << 62)
            except ArchiveyError:
                pass
            return
        solid.skip_to(target)

    def _release(self) -> None:
        if self._released:
            return
        self._released = True
        reader = self._reader
        with reader._materialize_lock:
            reader._spool_budget(None).release(self._charge)

    def close(self) -> None:
        """Remove the volumes when ``unrar`` never started: its stream owns them
        otherwise."""
        self.stop()
        if self.stream is None:
            try:
                self.volumes.close()
            finally:
                self._release()


class _ForwardUnrarStream(_RollingUnrarStream):
    """The pass's ``unrar`` output. Its close stops the walk first, and waits only
    briefly for the thread: that thread reads the caller's source, which may have
    stopped sending, so it removes the volumes itself once its read returns."""

    _FEEDER_WAIT = 1.0

    def __init__(
        self,
        fpass: _ForwardPass,
        stdout: BinaryIO,
        proc: subprocess.Popen[bytes],
        feeder: VolumeFeeder,
        volumes: RollingVolumes,
        release: Callable[[], None],
        **kwargs: bool,
    ) -> None:
        self._fpass = fpass
        source = fpass.source
        super().__init__(
            stdout,
            proc,
            feeder,
            volumes,
            release,
            on_read=None if source is None else source.flush_progress,
            **kwargs,
        )

    @override
    def _raise_for_returncode(self, rc: int) -> None:
        stop = self._fpass.cut_stop
        if stop is not None and self.feeder.error is stop:
            # The output ends after the volume the source cut is in. A read of the
            # cut member that reaches that end raises the member's own error
            # (``check_cut``, after the read returns), and the listing raises this
            # one after the members before it, so this read has nothing to add.
            return
        if isinstance(self.feeder.error, _Closed):
            # Only ``close`` stops the walk. The thread saw that stop while it wrote
            # a volume and killed ``unrar`` before ``close`` could terminate it, so
            # the close itself is all that happened: nothing to report.
            return
        super()._raise_for_returncode(rc)

    @override
    def close(self) -> None:
        self._fpass.stop()
        if not self.closed:
            # ``unrar`` may be waiting for the answer to a volume prompt that the
            # thread, blocked on the source, has not sent. It does not stop for a
            # terminate signal there, but it exits at the end of its input.
            stdin = self._proc.stdin
            if stdin is not None:
                try:
                    stdin.close()
                except (OSError, ValueError):
                    pass
        super().close()


class RarForwardReader(RarReader):
    """Reads a single-volume RAR front to back from a source that cannot seek.

    Only ``pipe=True`` reaches it (``open_archive`` refuses such a source in every other
    mode). The module docstring describes the pass.
    """

    # The member list exists only once the walk has passed every member.
    _MEMBER_LIST_UPFRONT = False

    @override
    def _open_archive(
        self,
        source: ArchiveSource,
        *,
        start_offset: int,
        end_offset: int | None,
        program_resources: ProgramResources | None,
    ) -> None:
        # ``end_offset`` is never set for a source that cannot seek (detection cannot
        # tell where such a stream ends in the object a size counts from), and a PE
        # program's resources are read from a seekable one only.
        del end_offset, program_resources
        self._origin = 0
        self._end = None
        self._program_tail = False
        self._unar_runs = None
        self._members_by_raw = None
        self._unmeasurable = set()
        self._unar_policy = None
        self._solid_after_unknown = {}
        self._members: list[ArchiveMember] = []
        self._dictionary_costs = {}
        self._behind_encryption = set()
        self._archive_has_encryption = False
        self._cost_notes = ()
        # Member data the walk kept, by offset (``_HeldBytes``), and the members whose
        # data the source cut short, by ``id`` of the parsed member.
        self._held_data: dict[int, bytes] = {}
        self._cut: set[int] = set()
        # The members written to the volumes, by ``id`` of the parsed member.
        self._fed: set[int] = set()
        # Why the members from here on are not in the volumes, once one stopped them.
        self._data_end: str | None = None
        # What stopped the walk, set before the member it held is listed.
        self._fwalk_error: Exception | None = None
        # Per-pass state, filled as members are listed (``_list_member``).
        self._pass_costs: dict[int, _DictionaryCost] = {}
        self._window = self._decoded = 0
        self._declarer = -1
        self._peak = _NO_DICTIONARY
        self._seen_encrypted = False
        self._seen_file = False
        self._latest: dict[str, ArchiveMember] = {}
        # Where the output of the members placed so far ends; ``None`` once it no
        # longer lines up.
        self._pipe_end: int | None = 0
        # The member whose failed read leaves ``_pipe_end`` in doubt, until a member
        # placed after it is read whole and matches its CRC32 (``_LineCheck``).
        self._pipe_doubt: str | None = None
        # How to check the CRC32 of each member placed while in doubt, by ``id`` of
        # the parsed member.
        self._line_checks: dict[int, Callable[[bytes], bool]] = {}
        self._pass_password: str | None | Literal[False] = False
        self._fpass: _ForwardPass | None = None
        self._fwalk_done = False
        self._refuse_without_rolling()
        self._fsource = ForwardSource(source)
        self._shared = _HeldBytes(self._held_data)
        if start_offset:
            # The detector found a stub: read past it, so offsets stay the file's.
            self._fsource.seek(start_offset)
            if (
                self._fsource.tell() < start_offset
                or self._fsource.read_at(start_offset, 1) == b""
            ):
                raise TruncatedError(
                    "RAR stream ends inside the stub in front of the archive",
                    archive_name=self._archive_name,
                    source_format=ArchiveFormat.RAR,
                )
        self._fwalk_start = start_offset
        self._archive, self._unrar_password = self._open_walk()
        if self._archive.is_volume:
            raise StreamNotSeekableError(
                "A RAR volume set cannot be read as a pipe: a pipe carries one "
                "stream, and the set's other volumes are separate files. Open the "
                "first volume by its path, without pipe=True.",
                archive_name=self._archive_name,
                source_format=ArchiveFormat.RAR,
            )
        if self._archive.has_header_encryption:
            note_crypto_use(self._usage)
        self._archive_has_encryption = self._archive.has_header_encryption
        self._comment = self._resolve_rar3_comment(self._archive.comment)

    def _refuse_without_rolling(self) -> None:
        if self._decompressor is not RarDecompressor.UNRAR:
            raise StreamNotSeekableError(
                "A RAR archive is read from a non-seekable source only by RARLAB unrar, "
                f"and rar_decompressor is {self._decompressor.name}. {_ROLLING_FIX}",
                archive_name=self._archive_name,
                source_format=ArchiveFormat.RAR,
            )
        if not self._rolling_ok():
            raise StreamNotSeekableError(
                "A RAR archive is read from a non-seekable source only by RARLAB unrar "
                "7.00 or later, which reads it as volumes written as the stream "
                f"arrives, and none was found. {_ROLLING_FIX}",
                archive_name=self._archive_name,
                source_format=ArchiveFormat.RAR,
            )

    def _open_walk(self) -> tuple[RarArchive, str | None]:
        """The walk opened with the header password the candidates hold, if any, and
        the password to hand ``unrar`` (as :meth:`RarReader._parse_archive`)."""
        try:
            try:
                archive = self._start_walk(None)
            except EncryptionError:
                if not self._passwords.has_passwords():
                    raise
                archive = self._passwords.attempt(None, self._start_walk)
        except _PasswordCandidatesExhausted as exc:
            message = (
                exc.last_error.message
                if exc.last_error is not None
                else "Password required to decrypt RAR headers"
            )
            raise EncryptionError(message) from exc
        return archive, self._first_candidate_str()

    def _start_walk(self, password: bytes | None) -> RarArchive:
        """Open the walk at the archive's start and read up to its first member.

        A header password is tried by starting again: the walk has read no more than
        its first headers, which the forward source still holds.
        """
        source = self._fsource
        try:
            source.seek(self._fwalk_start)
        except io.UnsupportedOperation as exc:
            raise UnsupportedFeatureError(
                "The RAR header password candidates cannot be tried again on a "
                "non-seekable source; pass the one password.",
                archive_name=self._archive_name,
                source_format=ArchiveFormat.RAR,
            ) from exc
        _version, walk = open_forward_walk(
            source,
            password=password,
            kdf_cache=self._kdf_cache,
            excluded=self._excluded,
            max_members=self._config.listing_limits.max_members,
            max_metadata_bytes=self._config.listing_limits.max_metadata_bytes,
            name_encoding=self._encoding,
        )
        gen = public_walk_errors(walk.walk())
        first = next(gen, None)
        self._fwalk: ForwardWalk = walk
        self._fwalk_gen = gen
        self._first: ForwardMember | None = first
        return walk.result()

    # -- the walk, on the thread that runs it ----------------------------------------

    def _take_first(self) -> ForwardMember | None:
        first, self._first = self._first, None
        if first is not None:
            self._on_found(first)
        return first

    def _next_found(self) -> ForwardMember | None:
        found = next(self._fwalk_gen, None)
        if found is not None:
            self._on_found(found)
        return found

    def _on_found(self, found: ForwardMember) -> None:
        """What the walk does at each member before its data is read."""
        raw = found.member
        archive = self._archive
        if archive.version == 4 and archive.is_solid and not raw.is_directory:
            # ``_settle_rar15_solid``, member by member.
            version = raw.extract_version
            if self._seen_file and version is not None and version <= 15:
                raw.file_solid = True
            self._seen_file = True
        if (
            raw.is_symlink
            and raw.file_redir is None
            and raw.is_stored
            and 0 < found.data_size <= _LINK_TARGET_BYTES
        ):
            # A RAR 1.5-4 symlink's target is its data: kept for
            # ``_ensure_link_target``.
            data = self._fsource.read_at(found.data_offset, found.data_size)
            if len(data) == found.data_size:
                self._held_data[found.data_offset] = data

    def _forward_entry(
        self, found: ForwardMember, position: int
    ) -> SyntheticMember | None:
        """``found`` as the ``position``-th member of the volumes, or ``None`` when it
        is not written to them."""
        raw = found.member
        if self._data_end is not None or not has_packed_data(raw):
            return None
        if raw.unknown_compression_version() is not None:
            # ``unrar`` stops at it; in a solid archive nothing after it decodes.
            if self._archive.is_solid:
                self._data_end = (
                    f"the member {quoted(raw.filename)} before it is compressed with "
                    "an unknown RAR version, and unrar decodes nothing after it in a "
                    "solid archive"
                )
            return None
        if _size_left_unknown(raw) and raw.is_payload_file():
            self._data_end = (
                f"the member {quoted(raw.filename)} before it has no size in its "
                "header, so the pass cannot tell where its output ends"
            )
            return None
        if self._archive.version != 5 and raw.compress_size >= 1 << 32:
            self._data_end = (
                f"the member {quoted(raw.filename)} before it is too large for a "
                "RAR 1.5-4 synthetic volume header"
            )
            return None
        if not self._fsource.holds(found.data_offset, found.data_size):
            # The source ends inside its data (the forward source reads ahead up to
            # its keep size to tell): not written, and the walk ends after it.
            self._cut.add(id(raw))
            return None
        entry = self._synthetic_entry(raw.filename, raw, position)
        if entry is not None:
            self._fed.add(id(raw))
        return entry

    @override
    def _read_source_at(self, offset: int, size: int) -> bytes:
        return self._fsource.read_at(offset, size)

    @override
    def _entry_data(self, raw: RarMemberInfo) -> list[tuple[BinaryIO, int]]:
        cut = self._cut
        fpass = self._fpass
        assert fpass is not None  # only a pass writes volumes
        span = ForwardSpan(self._fsource, raw.data_offset, raw.compress_size)

        def cut_error() -> TruncatedError:
            # Ends the pass: the feeder stops ``unrar`` with it, and the listing
            # raises it once the members before are given.
            error = TruncatedError(
                "RAR archive is truncated: the stream ends inside the packed data "
                f"of {quoted(raw.filename)}.",
                archive_name=self._archive_name,
                source_format=ArchiveFormat.RAR,
            )
            fpass.cut_stop = error
            return error

        padded = _PaddedSpan(
            span,
            raw.compress_size,
            lambda: cut.add(id(raw)),
            lambda: fpass.stopping,
            # The volumes written so far: the one being written is the next.
            lambda: fpass.volumes.count,
            cut_error,
        )
        return [(cast("BinaryIO", padded), raw.compress_size)]

    # -- listing, on the caller's thread --------------------------------------------

    @override
    def _iter_members(self) -> Iterator[ArchiveMember]:
        fpass = self._fpass
        if fpass is None:
            yield from self._iter_members_without_data()
            return
        # The member listed last when the pass released it early, with what its
        # parsed header held when the member was built from it:
        # ``(member, owner, comment, skipped records)``.
        early: (
            tuple[
                ArchiveMember, object, object, tuple[tuple[str, int | None, str], ...]
            ]
            | None
        ) = None
        while True:
            item = fpass.next_found()
            if early is not None:
                # The walk has read every header up to ``item``.
                self._add_late_records(*early)
                early = None
            if isinstance(item, _End):
                self._finish_walk(item.error)
                return
            raw = item.member
            if id(raw) not in fpass.early:
                yield self._list_member(item)
                continue
            with fpass.building:
                # The walk reads the header after ``raw`` only outside this block,
                # so the member and the snapshot both show what ``raw`` holds here.
                # A header the walk read before is in both; one it reads after is
                # what ``_add_late_records`` adds.
                member = self._list_member(item)
                early = (member, raw.owner, raw.comment, raw.skipped_header_records)
            yield member

    def _add_late_records(
        self,
        member: ArchiveMember,
        owner: object,
        comment: object,
        skipped: tuple[tuple[str, int | None, str], ...],
    ) -> None:
        """Write into ``member`` what a RAR 1.5-4 ``UOW`` or ``CMT`` header read
        after it was listed adds; ``owner``, ``comment`` and ``skipped`` are what its
        parsed header held when the member was built.

        The member is not final yet (``member_state_final``), so it gets the owner
        and comment a seekable read lists, and a ``UOW`` header that named no owner
        is reported as it is there (``_emit_skipped_records``).
        """
        raw = member._raw
        assert isinstance(raw, RarMemberInfo)
        new_owner = raw.owner
        if new_owner is not owner and new_owner is not None:
            member.uid = new_owner.uid
            member.gid = new_owner.gid
            member.uname = new_owner.uname
            member.gname = new_owner.gname
        if raw.comment is not comment and raw.comment is not None:
            resolved = self._resolve_rar3_comment(raw.comment)
            assert not isinstance(resolved, _Rar3Comment)
            raw.comment = resolved
            member.comment = resolved
        records = raw.skipped_header_records
        if records is not skipped:
            added = tuple(r for r in records if r not in skipped)
            if added:
                self._emit_skipped_records(added, member.name, member, member.member_id)

    def _iter_members_without_data(self) -> Iterator[ArchiveMember]:
        """The listing when no pass reads data: the walk skips each member's data.

        A member is listed once the walk has read the next header, which may still
        add to it, as in a pass.
        """
        try:
            held = self._take_first()
            while held is not None:
                found = self._next_found()
                yield self._list_member(held)
                held = found
        except ArchiveyError as exc:
            self._finish_walk(exc)
            return
        self._finish_walk(None)

    def _finish_walk(self, error: BaseException | None) -> None:
        self._fwalk_done = True
        if error is not None:
            raise error
        archive = self._fwalk.result()
        comment = archive.comment
        archive.comment = (
            self._comment
            if comment is self._archive.comment
            else self._resolve_rar3_comment(comment)
        )
        self._archive = archive
        self._after_last_member()
        self._emit_service_header_diagnostics()

    def _list_member(self, found: ForwardMember) -> ArchiveMember:
        """The member the walk found, typed and priced, as it is listed."""
        raw = found.member
        # The walk adds nothing to ``raw`` while it is built: a member released
        # early is built under ``_ForwardPass.building``, any other is behind the walk.
        raw.comment = self._resolve_rar3_comment(raw.comment)
        if self._archive.is_solid and self._seen_encrypted:
            self._behind_encryption.add(id(raw))
        if raw.is_encrypted or raw.encryption_unknown:
            self._seen_encrypted = True
            self._archive_has_encryption = self._archive_has_encryption or (
                raw.is_encrypted
            )
        member = self._to_member(raw, len(self._members))
        self._members.append(member)
        self._link_file_copy(member)
        self._price(member, raw)
        return member

    def _link_file_copy(self, member: ArchiveMember) -> None:
        """``_resolve_file_copies`` for one member: only earlier members count."""
        raw = member._raw
        assert isinstance(raw, RarMemberInfo)
        if raw.is_file_copy() and member.link_target:
            target_name = resolve_link_target_name(
                member.name, member.link_target, MemberType.HARDLINK, within_root=True
            )
            source = self._latest.get(target_name) if target_name is not None else None
            if source is not None and source.type is MemberType.FILE:
                source_raw = source._raw
                assert isinstance(source_raw, RarMemberInfo)
                member.link_target_member = (
                    source.link_target_member if source_raw.is_file_copy() else source
                )
                _share_unknown_copy_size(member, member.link_target_member)
        self._latest[member.name] = member

    def _price(self, member: ArchiveMember, raw: RarMemberInfo) -> None:
        """The member's dictionary cost in the one ``unrar`` run of the pass
        (``_unrar_dictionary_costs`` and ``_pass_dictionary_costs``, member by
        member)."""
        index = len(self._members) - 1
        if not self._archive.is_solid:
            cost = (
                _NO_DICTIONARY
                if uses_no_dictionary(raw)
                else _DictionaryCost(
                    min(raw.dictionary_size, raw.file_size), raw.dictionary_size, index
                )
            )
        else:
            if not uses_no_dictionary(raw):
                if raw.dictionary_size > self._window or self._declarer < 0:
                    self._window, self._declarer = raw.dictionary_size, index
                self._decoded += raw.file_size
            cost = _DictionaryCost(
                min(self._window, self._decoded), self._window, self._declarer
            )
        self._dictionary_costs[id(member)] = cost
        self._peak = _larger_cost(self._peak, cost)
        self._pass_costs[id(member)] = self._peak

    # -- the pass ----------------------------------------------------------------

    @override
    def _iter_with_data(
        self, copies: FileCopyPass = DEFAULT_FILE_COPY_PASS
    ) -> Iterator[tuple[ArchiveMember, ArchiveStreamImpl | None]]:
        fpass = _ForwardPass(self)
        self._fpass = fpass

        def _on_pipe(pipe: Callable[[], SolidBlockReader]) -> None:
            fpass.pipe = pipe

        try:
            yield from self._drive_solid_pass(
                copies,
                fpass.spawn,
                self._plan,
                costs=self._pass_costs,
                on_pipe=_on_pipe,
                wrap_member=self._wrap_forward_member,
                on_member_error=self._on_member_error,
            )
        finally:
            fpass.close()

    def _plan(
        self, member: ArchiveMember, raw: RarMemberInfo, size: int | None, _: bool
    ) -> int | Callable[[], BinaryIO] | None:
        """Where ``member``'s output is in the pass, or the refusal its read raises."""

        def refuse(error: Exception) -> Callable[[], BinaryIO]:
            def _refused() -> BinaryIO:
                raise error

            return _refused

        if id(raw) in self._cut:
            error = self._cut_error(member)
            self._pipe_end = None
            return refuse(error)
        unknown_version = raw.unknown_compression_version()
        if unknown_version is not None:
            return refuse(self._unknown_compression_error(member, unknown_version))
        if has_packed_data(raw) and id(raw) not in self._fed:
            if self._fwalk_error is not None and self._data_end is None:
                return refuse(self._fwalk_error)
            return refuse(
                self._not_fed_error(
                    member, self._data_end or "its data was not read into the pass"
                )
            )
        refusal = self._password_refusal(member, raw)
        if refusal is not None:
            self._pipe_end = None
            return refuse(refusal)
        if self._pipe_end is None:
            return refuse(
                self._not_fed_error(
                    member,
                    "the pass's output stopped lining up at an earlier member, which "
                    "raised its own error",
                )
            )
        offset = self._pipe_end
        if self._can_direct_read(raw):
            mismatch = self._stored_sizes_error(member, raw)
            if mismatch is not None:
                # Refused as the seekable reader refuses it. ``unrar`` copies a
                # stored member up to the smaller of its two sizes, so the output
                # after it starts there.
                self._pipe_end = offset + min(raw.compress_size, raw.file_size)
                return refuse(mismatch)
        # An empty slice has no output to place wrongly, and it matches its CRC32
        # wherever it starts, so it is read with no check and leaves the doubt set.
        if self._pipe_doubt is not None and size != 0:
            matches = self._crc32_check(member)
            if matches is None:
                self._pipe_end = None
                return refuse(self._out_of_line_error(member, self._pipe_doubt))
            self._line_checks[id(raw)] = matches
        assert size is not None  # a member of unknown size stops the volumes
        self._pipe_end = offset + size
        return offset

    def _crc32_check(self, member: ArchiveMember) -> Callable[[bytes], bool] | None:
        """Whether a CRC32 digest of ``member``'s output is the one its header holds,
        or ``None`` when the header holds no CRC32 the pass can compare."""
        hashes, _, transforms, _ = self._payload_verify_args(member)
        expected = (hashes or {}).get(HashAlgorithm.CRC32)
        if expected is None:
            return None
        transform = (transforms or {}).get(HashAlgorithm.CRC32)
        return lambda digest: (
            (transform(digest) if transform is not None else digest) == expected
        )

    def _out_of_line_error(
        self, member: ArchiveMember, doubt: str
    ) -> UnsupportedFeatureError:
        return self._not_fed_error(
            member,
            f"the member {quoted(doubt)} before it failed its check, so its output "
            "may have another length than its header says, and the pass cannot tell "
            "where this member's output starts",
        )

    def _on_member_error(self, member: ArchiveMember, error: ArchiveyError) -> None:
        """A member placed in the output failed its read. A damaged compressed or
        encrypted member can decode to another length than its header says, and then
        every later member's output starts somewhere else. Each member with output
        placed after it is checked against its CRC32 (``_LineCheck``) until one
        matches; one that does not, or that has no CRC32, is refused, and so is every
        member after it. A plain stored member's output is a copy of its packed bytes,
        so its length is known even when its digest fails."""
        raw = member._raw
        assert isinstance(raw, RarMemberInfo)
        if (
            isinstance(error, CorruptionError)
            and not self._can_direct_read(raw)
            and self._pipe_end is not None
        ):
            self._pipe_doubt = member.name

    def _wrap_forward_member(self, member: ArchiveMember, stream: BinaryIO) -> BinaryIO:
        """Keep a late source cut from verifying through a synthetic member slice."""
        raw = member._raw
        assert isinstance(raw, RarMemberInfo)

        def check_cut() -> None:
            if id(raw) in self._cut:
                self._pipe_end = None
                raise self._cut_error(member)

        matches = self._line_checks.pop(id(raw), None)
        line = None
        if matches is not None:
            doubt = self._pipe_doubt
            assert doubt is not None and member.size is not None

            def on_match() -> None:
                self._pipe_doubt = None

            def on_mismatch() -> ArchiveyError:
                self._pipe_end = None
                return self._out_of_line_error(member, doubt)

            line = _LineCheck(member.size, matches, on_match, on_mismatch)
        return _ForwardMemberStream(stream, check_cut, line)

    def _password_refusal(
        self, member: ArchiveMember, raw: RarMemberInfo
    ) -> ArchiveyError | None:
        """Why ``member`` cannot be read with the pass's one password, or ``None``."""
        if not (raw.is_encrypted or raw.encryption_unknown):
            return None
        if self._archive.has_header_encryption:
            return None
        try:
            spawn_password = self._archive_data_password()
            enc = raw.file_encryption
            if enc is not None and _psw_check_usable(enc):
                needed = self._checked_data_password(enc, member)
            elif self._passwords.is_ambiguous():
                return UnsupportedFeatureError(
                    f"RAR member {quoted(member.name)} is encrypted with no password "
                    "check value, and a pass from a non-seekable source cannot try "
                    "several passwords on it; pass the one password.",
                    archive_name=self._archive_name,
                    member_name=member.name,
                    source_format=ArchiveFormat.RAR,
                )
            else:
                needed = spawn_password
        except ArchiveyError as exc:
            return exc
        if needed == spawn_password:
            return None
        return UnsupportedFeatureError(
            f"RAR member {quoted(member.name)} needs a different password from the one "
            "unrar was started with for this pass, and a pass from a non-seekable "
            "source runs one unrar; pass the one password the archive uses.",
            archive_name=self._archive_name,
            member_name=member.name,
            source_format=ArchiveFormat.RAR,
        )

    @override
    def _archive_data_password(self) -> str | None:
        """The one password of the pass's ``unrar``, chosen once.

        The header password of an ``-hp`` archive; else the one candidate; else, from
        several, the one the first member listed with a PswCheck accepts. A list with
        no such member yet gives ``unrar`` none, and an encrypted member later is
        refused (:meth:`_password_refusal`).
        """
        chosen = self._pass_password
        if chosen is not False:
            return chosen
        chosen = None
        if self._passwords.has_passwords():
            if (
                self._archive.has_header_encryption
                or not self._passwords.is_ambiguous()
            ):
                chosen = self._unrar_password
            else:
                member = next(
                    (
                        m
                        for m in self._members
                        if isinstance(m._raw, RarMemberInfo)
                        and m._raw.file_encryption is not None
                        and _psw_check_usable(m._raw.file_encryption)
                    ),
                    None,
                )
                if member is not None:
                    raw = member._raw
                    assert isinstance(raw, RarMemberInfo)
                    assert raw.file_encryption is not None
                    chosen = self._checked_data_password(raw.file_encryption, member)
        self._pass_password = chosen
        return chosen

    @override
    def _unrar_data_password(self) -> str | None:
        # Whether a later member is encrypted is not known when unrar starts.
        return self._unrar_password

    def _cut_error(self, member: ArchiveMember) -> TruncatedError:
        return TruncatedError(
            f"RAR member {quoted(member.name)} is cut short: the stream ends inside "
            "its packed data.",
            archive_name=self._archive_name,
            member_name=member.name,
            source_format=ArchiveFormat.RAR,
        )

    def _not_fed_error(
        self, member: ArchiveMember, why: str
    ) -> UnsupportedFeatureError:
        return UnsupportedFeatureError(
            f"RAR member {quoted(member.name)} cannot be read from a non-seekable "
            f"source: {why}.",
            archive_name=self._archive_name,
            member_name=member.name,
            source_format=ArchiveFormat.RAR,
        )

    @override
    def _cut_data_error(
        self, member: ArchiveMember, info: RarMemberInfo
    ) -> TruncatedError | None:
        return self._cut_error(member) if id(info) in self._cut else None

    @override
    def _file_copy_sources(self, copies: FileCopyPass) -> FileCopySources | None:
        # The sources' bytes are not kept: which later members copy them is not known.
        return None

    @override
    def _pass_file_copy_stream(
        self,
        member: ArchiveMember,
        sources: FileCopySources | None,
        advance_past: Callable[[int], object],
        pass_costs: dict[int, _DictionaryCost],
    ) -> ArchiveStreamImpl:
        error = UnsupportedFeatureError(
            f"RAR member {quoted(member.name)} is a copy of an earlier member, whose "
            "bytes a pass from a non-seekable source does not keep.",
            archive_name=self._archive_name,
            member_name=member.name,
            source_format=ArchiveFormat.RAR,
        )

        def _refused() -> BinaryIO:
            raise error

        return self._wrap_member_stream(
            member.name,
            _refused,
            size=member.size,
            track_output=False,
            seekable=False,
        )

    @override
    def _open_member(self, member: ArchiveMember) -> MemberStreamParts:
        raw = member._raw
        assert isinstance(raw, RarMemberInfo)
        why = self._data_end or (
            "the pass's output does not hold it, and the source cannot be read again"
        )
        raise self._not_fed_error(member, why)

    # -- archive facts -------------------------------------------------------------

    @override
    def _cost_receipt(self) -> CostReceipt:
        return CostReceipt(
            listing_cost=ListingCost.REQUIRES_SCANNING,
            access_cost=AccessCost.SOLID
            if self._archive.is_solid
            else AccessCost.DIRECT,
            stream_capability=StreamCapability.FORWARD_ONLY,
            solid_block_count=None,
            notes=self._cost_notes,
        )

    @override
    def _get_archive_info(self) -> ArchiveInfo:
        comment = self._comment
        assert not isinstance(comment, _Rar3Comment)
        return ArchiveInfo(
            format=ArchiveFormat.RAR,
            format_version=str(self._archive.version),
            is_solid=self._archive.is_solid,
            member_count=len(self._members) if self._fwalk_done else None,
            comment=comment,
            is_encrypted=self._archive_has_encryption,
            is_multivolume=False,
            cost=self._cost_receipt(),
            extra=ArchiveInfoExtra({"rar.volume_count": 1}),
        )

    @override
    def _close_archive(self) -> None:
        fpass, self._fpass = self._fpass, None
        if fpass is not None:
            fpass.close()
        super()._close_archive()


__all__ = ["RarForwardReader"]
