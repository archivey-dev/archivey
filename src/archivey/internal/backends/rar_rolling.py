"""Feed ``unrar`` a synthetic RAR archive as volumes written one at a time.

A synthetic archive (:mod:`rar_synthetic`) is one file that holds every byte a read
needs. For a large member of a stream source that copy is the whole member, and over
``SpoolLimits.max_bytes`` it is refused. Here the same members are written as a volume
set instead, and only one volume is on disk at a time:

1. Volume 1 is written and ``unrar p -vp`` starts on it.
2. Under ``-vp``, ``unrar`` prints ``Insert disk with <next volume>`` on stderr before
   it opens each next volume, and reads one line from stdin. At that point it holds
   no volume open.
3. A feeder thread waits for that prompt, removes the volume ``unrar`` has finished,
   writes the next one and answers with an empty line (the default, *Continue*).

``unrar`` never reads an earlier volume again. rarlab keeps "``-vp`` always prompts,
even when the next volume exists" on purpose, for programs that write volumes as they
go (``volume.cpp``, comment of 2022). Measured on ``unrar`` 7.00: RAR 1.5-4 and RAR5,
plain, solid and encrypted, split at any byte (inside an AES block too), decode byte
for byte as the original. Measured cost: 0.14 ms a volume switch.

Each volume is a valid RAR volume: the MAIN header says it is a volume (RAR5: and its
number), a member that goes on in the next volume is split there (split-after, then
split-before), and ENDARC says whether a volume follows. A part that is not a member's
last carries no checksum: ``unrar`` checks a split part's packed bytes only against a
checksum the part's header holds (``MergeArchive``: a RAR5 hash of type none, or a
RAR 1.5-4 CRC of ``0xFFFFFFFF``, always matches). The last part keeps the member's own
header, with its digest of the unpacked data, which ``unrar`` and archivey check.

The design: tracked internally; the probe that measured it is in the project's
investigation notes.
"""

from __future__ import annotations

import io
import os
import re
import shutil
import struct
import subprocess
import tempfile
import threading
import zlib
from collections.abc import Callable, Iterable, Iterator
from pathlib import Path
from typing import BinaryIO, cast

from archivey.exceptions import (
    ArchiveyError,
    ReadError,
    ResourceLimitError,
    TruncatedError,
    exception_detail,
)
from archivey.internal.backends.rar_parser import load_vint
from archivey.internal.backends.rar_synthetic import (
    _RAR3_ENDARC,
    _RAR3_ENDARC_FLAGS,
    _RAR3_FILE_LARGE,
    _RAR3_FIXED,
    _RAR3_HIGH,
    _RAR3_MAIN,
    _RAR3_MAIN_SOLID,
    _RAR5_ENDARC,
    _RAR5_FILE_HAS_CRC32,
    _RAR5_FILE_HAS_MTIME,
    _RAR5_FLAG_DATA,
    _RAR5_FLAG_EXTRA,
    _RAR5_FLAG_SPLIT,
    _RAR5_MAIN,
    _RAR5_MAIN_SOLID,
    SyntheticMember,
    _rar3_block,
    _rar5_block,
    _vint,
    signature,
)
from archivey.internal.backends.rar_unrar import (
    open_unrar_p,
)
from archivey.internal.external.cli import terminate_process
from archivey.internal.resource_usage import ResourceUsageRecorder

# RAR5 MAIN archive flags and ENDARC flag (``headers5.hpp``).
_RAR5_MAIN_VOLUME = 0x0001
_RAR5_MAIN_VOLNUMBER = 0x0002
_RAR5_ENDARC_NEXT_VOLUME = 0x0001
_RAR5_SPLIT_BEFORE = 0x0008
_RAR5_SPLIT_AFTER = 0x0010
_RAR5_EXTRA_HASH = 2
# RAR 1.5-4 MAIN flags (MHD_VOLUME, MHD_NEWNUMBERING, MHD_FIRSTVOLUME), FILE split
# flags and ENDARC next-volume flag (``headers.hpp``).
_RAR3_MAIN_VOLUME = 0x0001
_RAR3_MAIN_NEWNUMBERING = 0x0010
_RAR3_MAIN_FIRSTVOLUME = 0x0100
_RAR3_SPLIT_BEFORE = 0x0001
_RAR3_SPLIT_AFTER = 0x0002
_RAR3_ENDARC_NEXT_VOLUME = 0x0001
# A RAR 1.5-4 FILE_CRC that ``unrar`` does not check a split part against.
_RAR3_NO_PART_CRC = 0xFFFFFFFF
# HEAD_CRC, HEAD_TYPE, HEAD_FLAGS, HEAD_SIZE, PACK_SIZE, UNP_SIZE, HOST_OS: FILE_CRC
# is at this offset of a RAR 1.5-4 FILE header.
_RAR3_FILE_CRC_AT = 16

#: The fewest packed bytes in one part of a split member (:class:`RollingVolumes`).
MIN_PART_BYTES = 1 << 20

_COPY_CHUNK = 1 << 20
_STDERR_TAIL = 4096
# The width of a volume number in a volume name. ``unrar`` increments the number
# in place, keeping the width (``NextVolumeName``), so every name is known ahead.
_NUMBER_WIDTH = 6
# Any other ``unrar`` question shows its answers as ``[R]etry, [A]bort``: a letter in
# brackets. It stops unrar, whose default answer to a read error is *Retry*.
_QUESTION = re.compile(rb"\[[^\]\s]\]")


def volume_name(number: int) -> str:
    """The file name of volume ``number`` (1 for the first) of a rolling set."""
    return f"v.part{number:0{_NUMBER_WIDTH}d}.rar"


def main_volume_header(version: int, *, solid: bool, index: int) -> bytes:
    """The MAIN header of volume ``index`` (0 for the first) of a set."""
    if version == 5:
        flags = _RAR5_MAIN_VOLUME | (_RAR5_MAIN_SOLID if solid else 0)
        if index:
            flags |= _RAR5_MAIN_VOLNUMBER
        body = _vint(_RAR5_MAIN) + _vint(0) + _vint(flags)
        if index:
            body += _vint(index)
        return _rar5_block(body)
    flags = _RAR3_MAIN_VOLUME | _RAR3_MAIN_NEWNUMBERING
    if solid:
        flags |= _RAR3_MAIN_SOLID
    if not index:
        flags |= _RAR3_MAIN_FIRSTVOLUME
    return _rar3_block(_RAR3_MAIN, flags, b"\x00" * 6)


def end_volume_header(version: int, *, more: bool) -> bytes:
    """An ENDARC header; ``more`` says another volume follows."""
    if version == 5:
        flags = _RAR5_ENDARC_NEXT_VOLUME if more else 0
        return _rar5_block(_vint(_RAR5_ENDARC) + _vint(0) + _vint(flags))
    flags = _RAR3_ENDARC_FLAGS | (_RAR3_ENDARC_NEXT_VOLUME if more else 0)
    return _rar3_block(_RAR3_ENDARC, flags, b"")


def part_header(
    version: int, header: bytes, *, data_size: int, before: bool, after: bool
) -> bytes:
    """``header``, a synthetic member header (:func:`rar_synthetic.patch_header`), for
    one part of the member: ``data_size`` packed bytes, split ``before`` and/or
    ``after`` this part.

    A part with ``after`` set is not the member's last, and its checksum is taken
    out (module docstring); the last part keeps the member's digest.
    """
    if version == 5:
        return _part_rar5(header, data_size, before, after)
    return _part_rar3(header, data_size, before, after)


def _part_rar5(raw: bytes, data_size: int, before: bool, after: bool) -> bytes:
    _, q = load_vint(raw, 4)
    kind, q = load_vint(raw, q)
    hflags, q = load_vint(raw, q)
    extra_size = 0
    if hflags & _RAR5_FLAG_EXTRA:
        extra_size, q = load_vint(raw, q)
    if hflags & _RAR5_FLAG_DATA:
        _, q = load_vint(raw, q)
    extra_at = len(raw) - extra_size
    fields = raw[q:extra_at]
    extra = raw[extra_at:]
    if after:
        fields = _rar5_fields_without_crc(fields)
        extra = _rar5_extra_without_hash(extra)
    flags = hflags & ~(_RAR5_FLAG_SPLIT | _RAR5_FLAG_EXTRA | _RAR5_FLAG_DATA)
    if before:
        flags |= _RAR5_SPLIT_BEFORE
    if after:
        flags |= _RAR5_SPLIT_AFTER
    if extra:
        flags |= _RAR5_FLAG_EXTRA
    if data_size:
        flags |= _RAR5_FLAG_DATA
    head = _vint(kind) + _vint(flags)
    if extra:
        head += _vint(len(extra))
    if data_size:
        head += _vint(data_size)
    return _rar5_block(head + fields + extra)


def _rar5_fields_without_crc(fields: bytes) -> bytes:
    """A RAR5 FILE header's fields with the data CRC32 and its flag taken out."""
    fflags, q = load_vint(fields, 0)
    if not fflags & _RAR5_FILE_HAS_CRC32:
        return fields
    _, q = load_vint(fields, q)  # unpacked size
    _, q = load_vint(fields, q)  # attributes
    if fflags & _RAR5_FILE_HAS_MTIME:
        q += 4
    _, rest = load_vint(fields, 0)
    return _vint(fflags & ~_RAR5_FILE_HAS_CRC32) + fields[rest:q] + fields[q + 4 :]


def _rar5_extra_without_hash(extra: bytes) -> bytes:
    """A RAR5 extra area with its hash record (BLAKE2sp) taken out."""
    out = bytearray()
    q = 0
    while q < len(extra):
        size, body = load_vint(extra, q)
        end = body + size
        kind, _ = load_vint(extra, body)
        if kind != _RAR5_EXTRA_HASH:
            out += extra[q:end]
        q = end
    return bytes(out)


def _part_rar3(raw: bytes, data_size: int, before: bool, after: bool) -> bytes:
    header = bytearray(raw)
    fixed = _RAR3_FIXED.unpack_from(header)
    flags = fixed[2] & ~(_RAR3_SPLIT_BEFORE | _RAR3_SPLIT_AFTER)
    if before:
        flags |= _RAR3_SPLIT_BEFORE
    if after:
        flags |= _RAR3_SPLIT_AFTER
        struct.pack_into("<L", header, _RAR3_FILE_CRC_AT, _RAR3_NO_PART_CRC)
    struct.pack_into("<H", header, 3, flags)
    struct.pack_into("<L", header, 7, data_size & 0xFFFFFFFF)
    if flags & _RAR3_FILE_LARGE:
        high_unp = _RAR3_HIGH.unpack_from(header, _RAR3_FIXED.size)[1]
        _RAR3_HIGH.pack_into(header, _RAR3_FIXED.size, data_size >> 32, high_unp)
    struct.pack_into("<H", header, 5, len(header))
    struct.pack_into("<H", header, 0, zlib.crc32(header[2:]) & 0xFFFF)
    return bytes(header)


class _Pending:
    """The member being written: its header and the data streams left to copy."""

    def __init__(self, member: SyntheticMember) -> None:
        self.header = member.header
        self.left = member.data_size
        self.written = 0
        self._parts = list(member.data())
        self._index = 0
        self._part_left = self._parts[0][1] if self._parts else 0

    def copy(self, size: int, dst: BinaryIO) -> None:
        """Copy the next ``size`` bytes of the member's data to ``dst``."""
        while size > 0:
            while self._part_left == 0:
                self._index += 1
                self._part_left = self._parts[self._index][1]
            stream = self._parts[self._index][0]
            chunk = stream.read(min(size, self._part_left, _COPY_CHUNK))
            if not chunk:
                raise TruncatedError(
                    f"RAR member data ends {self.left} bytes before its packed size"
                )
            dst.write(chunk)
            size -= len(chunk)
            self._part_left -= len(chunk)
            self.left -= len(chunk)
            self.written += len(chunk)

    def close(self) -> None:
        for stream, _ in self._parts:
            stream.close()


class RollingVolumes:
    """A synthetic RAR archive written as volumes, one on disk at a time.

    ``members`` are taken in order, as they are needed: a member's ``data`` is
    called when its first byte is written, and each stream is closed when the
    member is done (or on :meth:`close`). The files live in a private temporary
    directory that :meth:`close` removes.

    No volume holds more than ``volume_bytes``. Each part of a split member holds
    at least ``min_part_bytes`` packed bytes (by default a quarter of a volume, at
    most :data:`MIN_PART_BYTES`); a member too small for two such parts is never
    split, and starts the next volume when it does not fit. A member that does not
    fit an empty volume that way raises ``ResourceLimitError``. ``unrar`` needs both:

    - One read of its decoder takes bytes from one part only (``UnpRead``: it asks
      for the next volume only when a read finds the part empty). A decoder that
      looks ahead past what it holds then decodes past a short part's end, and the
      member fails its digest check (measured: RAR 1.5-4 solid parts of 1 byte).
    - ``unrar`` compares a member's digest with the header of the part its decoder
      stopped in, and a part split after holds no valid digest (``extract.cpp``).
      A decoder reads only what it needs, so the last part must hold data it
      needs: a RAR 1.5-4 empty member's packed bytes are never read at all.
    """

    def __init__(
        self,
        version: int,
        members: Iterable[SyntheticMember],
        *,
        solid: bool,
        volume_bytes: int,
        min_part_bytes: int | None = None,
        directory: str | None = None,
    ) -> None:
        self.version = version
        self.solid = solid
        self.volume_bytes = volume_bytes
        self.min_part_bytes = (
            max(1, min(MIN_PART_BYTES, volume_bytes // 4))
            if min_part_bytes is None
            else min_part_bytes
        )
        self._members: Iterator[SyntheticMember] = iter(members)
        self._next: SyntheticMember | None = None
        self._pending: _Pending | None = None
        self._finished = False
        self._closed = False
        self.dir = Path(tempfile.mkdtemp(prefix="archivey-rar-", dir=directory))
        #: Volumes written so far; the last one is on disk.
        self.count = 0
        #: The largest volume written, in bytes.
        self.peak = 0
        if self.volume_bytes < 1:
            raise ValueError("a volume holds at least one byte")

    @property
    def finished(self) -> bool:
        """Whether the last volume has been written."""
        return self._finished

    def path(self, number: int) -> Path:
        return self.dir / volume_name(number)

    def _peek(self) -> SyntheticMember | None:
        if self._next is None:
            self._next = next(self._members, None)
        return self._next

    def write_next(self) -> Path:
        """Remove the volume on disk, write the next one, and return its path."""
        if self._closed:
            raise ValueError("rolling volumes are closed")
        if self._finished:
            raise ValueError("every volume has been written")
        if self.count:
            self.path(self.count).unlink(missing_ok=True)
        index = self.count
        path = self.path(index + 1)
        version = self.version
        end_size = len(end_volume_header(version, more=False))
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | _O_BINARY, 0o600)
        with os.fdopen(fd, "wb") as f:
            f.write(signature(version))
            f.write(main_volume_header(version, solid=self.solid, index=index))
            used = f.tell() + end_size
            empty = True
            more = True
            while True:
                pending = self._pending
                if pending is None:
                    member = self._peek()
                    if member is None:
                        more = False
                        break
                    self._next = None
                    pending = self._pending = _Pending(member)
                room = self.volume_bytes - used
                head = len(pending.header)
                left = pending.left
                least = self.min_part_bytes
                if head + left <= room:
                    size = left
                else:
                    # Too small to split, or too little room for a part here.
                    size = 0 if left < 2 * least else min(room - head, left - least)
                    if size < least:
                        if not empty:
                            break  # it starts the next volume
                        raise ResourceLimitError(
                            f"A RAR member's header ({head} bytes) and "
                            f"{min(left, least)} bytes of its data do not fit one "
                            f"volume of {self.volume_bytes} bytes; the volume size "
                            "follows SpoolLimits.max_bytes, so raise the limit."
                        )
                last = size == left
                f.write(
                    part_header(
                        version,
                        pending.header,
                        data_size=size,
                        before=pending.written > 0,
                        after=not last,
                    )
                )
                pending.copy(size, f)
                used += head + size
                empty = False
                if not last:
                    break
                pending.close()
                self._pending = None
            f.write(end_volume_header(version, more=more))
            size = f.tell()
        self.count += 1
        self.peak = max(self.peak, size)
        self._finished = not more
        return path

    def close(self) -> None:
        """Close the streams still open and remove the directory. Safe to call
        more than once."""
        if self._closed:
            return
        self._closed = True
        try:
            if self._pending is not None:
                self._pending.close()
                self._pending = None
        finally:
            shutil.rmtree(self.dir, ignore_errors=True)


_O_BINARY = getattr(os, "O_BINARY", 0)


class VolumeFeeder:
    """Answer ``unrar -vp``'s next-volume prompts from a thread, writing each volume.

    The thread reads ``unrar``'s stderr. When the name of the volume after the one on
    disk appears there, whatever words surround it, it writes that volume
    (:meth:`RollingVolumes.write_next`) and answers with an empty line; after the last
    volume it closes stdin, so any later question ends ``unrar`` (it exits on end of
    input). Any other question (a bracketed answer letter without the expected name)
    stops ``unrar``: its default answer to a read error is *Retry*, which would ask
    again forever.

    A failure while writing a volume (the source ends early, a disk error) stops
    ``unrar`` too, and is kept in :attr:`error` for the reader to raise in place of
    the exit status. A thread is needed because Windows cannot poll a pipe.
    """

    def __init__(self, proc: subprocess.Popen[bytes], volumes: RollingVolumes) -> None:
        assert proc.stderr is not None and proc.stdin is not None
        self._proc = proc
        self._volumes = volumes
        #: Why the feeder stopped ``unrar``, if it did.
        self.error: ArchiveyError | None = None
        #: The last bytes ``unrar`` wrote on stderr, for a diagnosis.
        self.stderr_tail = b""
        self._thread = threading.Thread(
            target=self._run, name="archivey-unrar-volumes", daemon=True
        )
        self._thread.start()

    def _expected(self) -> bytes:
        return volume_name(self._volumes.count + 1).encode("ascii")

    def _run(self) -> None:
        proc = self._proc
        # A buffered reader (``Popen`` with a buffer size), so ``read1`` returns
        # what the pipe holds without waiting for more.
        stderr = cast("io.BufferedReader", proc.stderr)
        stdin = proc.stdin
        assert stderr is not None and stdin is not None
        seen = b""
        # After an answer, the rest of the prompt's line (the later answer letters)
        # may still arrive. Every message and question starts a new line.
        rest_of_prompt = False
        try:
            if self._volumes.finished:
                stdin.close()
            while True:
                chunk = stderr.read1(_STDERR_TAIL)
                if not chunk:
                    return
                self.stderr_tail = (self.stderr_tail + chunk)[-_STDERR_TAIL:]
                if rest_of_prompt:
                    newline = chunk.find(b"\n")
                    if newline < 0:
                        continue
                    chunk = chunk[newline:]
                    rest_of_prompt = False
                seen = (seen + chunk)[-_STDERR_TAIL:]
                if self._volumes.finished:
                    continue
                expected = self._expected()
                # The name alone is the prompt: with ``-idq`` unrar prints the next
                # volume's name only when it asks for it, and a translated unrar
                # may word the question and its answer letters differently.
                if expected in seen:
                    try:
                        self._volumes.write_next()
                    except ArchiveyError as exc:
                        self._stop(exc)
                        return
                    except OSError as exc:
                        self._stop(
                            ReadError(
                                f"Could not write the next RAR volume for unrar: {exc}"
                            )
                        )
                        return
                    seen = b""
                    rest_of_prompt = True
                    try:
                        stdin.write(b"\n")
                        stdin.flush()
                        if self._volumes.finished:
                            stdin.close()
                    except (BrokenPipeError, OSError):
                        return  # unrar exited; its status says why
                elif _QUESTION.search(seen):
                    self._stop(
                        ReadError(
                            "unrar asked a question archivey does not answer while "
                            "reading rolling RAR volumes: "
                            + seen.decode("utf-8", "replace").strip()
                        )
                    )
                    return
        except BaseException as exc:  # noqa: BLE001 - reported through error
            if self.error is None:
                self._stop(
                    ReadError(
                        "The RAR volume feeder failed: "
                        + exception_detail(exc, with_type=True)
                    )
                )
        finally:
            try:
                stderr.close()
            except OSError:
                pass

    def _stop(self, error: ArchiveyError) -> None:
        self.error = error
        try:
            self._proc.kill()
        except OSError:
            pass

    def join(self, timeout: float | None = None) -> None:
        self._thread.join(timeout)


def start_rolling_unrar(
    volumes: RollingVolumes,
    *,
    password: str | bytes | None,
    member: str | None,
    version_control: bool,
    rar5: bool,
    program: str | None = None,
    usage: ResourceUsageRecorder | None = None,
    opener: Callable[..., tuple[subprocess.Popen[bytes], BinaryIO]] = open_unrar_p,
) -> tuple[subprocess.Popen[bytes], BinaryIO, VolumeFeeder]:
    """Write the first volume of ``volumes`` and start ``unrar p -vp`` on it, with a
    :class:`VolumeFeeder` that writes the rest. The other arguments are
    :func:`~archivey.internal.backends.rar_unrar.open_unrar_p`'s; ``opener`` is
    that function, or the caller's name for it.

    The caller owns the process (stop it, then :meth:`VolumeFeeder.join`) and closes
    ``volumes`` after it.
    """
    first = volumes.write_next()
    proc, stdout = opener(
        first,
        password=password,
        member=member,
        version_control=version_control,
        rar5=rar5,
        program=program,
        usage=usage,
        volume_pause=True,
    )
    try:
        feeder = VolumeFeeder(proc, volumes)
    except BaseException:
        try:
            stdout.close()
        finally:
            terminate_process(proc)
        raise
    return proc, stdout, feeder
