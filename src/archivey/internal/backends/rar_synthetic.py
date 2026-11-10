"""Build a small synthetic RAR archive for ``unrar`` from a member's own headers.

``unrar`` reads only a seekable file and selects members by an include mask. Given the
original archive, it walks every header for each read, and a stream source must be
copied to disk whole. A synthetic archive holds only what one read needs:

- the RAR signature and a MAIN header made here;
- for each member the read needs, in archive order, its **stored** FILE (or SERVICE)
  header, decrypted when the archive's headers are encrypted, with only the name, the
  split flags and the packed size changed, and its packed bytes copied verbatim;
- an ENDARC header made here.

Every field ``unrar`` decodes with (method, dictionary, the member's own solid flag,
host OS, sizes, CRC, the RAR5 extra area, the RAR 1.5-4 salt and extended time) is the
archive's own. Members are named ``m0``, ``m1``, …, so a mask is plain ASCII and no
stored name reaches the disk or ``unrar``.

The design and the measurements are in ``openspec/changes/rar-synthetic-archives``.
This module only builds bytes and files; which reads use it is the reader's choice.
"""

from __future__ import annotations

import os
import struct
import tempfile
import zlib
from collections.abc import Callable, Iterable
from dataclasses import dataclass
from pathlib import Path
from typing import BinaryIO

from archivey.exceptions import CorruptionError, TruncatedError
from archivey.internal.backends.rar_parser import (
    RAR5_ID,
    RAR_ID,
    RarArchive,
    RarKdfCache,
    RarMemberInfo,
    _parse_rar3_ext_time,
    load_vint,
)
from archivey.internal.excluded_libraries import OptionalLibrary
from archivey.internal.streams.crypto import AesParams, open_aes_decrypt_stage

# RAR 1.5-4 block types and flags (``arcread.cpp`` / ``headers.hpp``).
_RAR3_MAIN = 0x73
_RAR3_FILE = 0x74
_RAR3_SUB = 0x7A
_RAR3_ENDARC = 0x7B
_RAR3_MAIN_SOLID = 0x0008
_RAR3_FILE_SPLIT = 0x0003
_RAR3_FILE_COMMENT = 0x0008
_RAR3_FILE_SALT = 0x0400
_RAR3_FILE_EXTTIME = 0x1000
_RAR3_FILE_LARGE = 0x0100
_RAR3_FILE_UNICODE = 0x0200
_RAR3_LONG_BLOCK = 0x8000
_RAR3_ENDARC_FLAGS = 0x4000  # EARC_NEXT_VOLUME clear; ``rar`` always sets 0x4000
# HEAD_CRC, HEAD_TYPE, HEAD_FLAGS, HEAD_SIZE, PACK_SIZE, UNP_SIZE, HOST_OS, FILE_CRC,
# FTIME, UNP_VER, METHOD, NAME_SIZE, ATTR: the name starts after these.
_RAR3_FIXED = struct.Struct("<HBHHLLBLLBBHL")
_RAR3_HIGH = struct.Struct("<LL")

# RAR5 block types and flags.
_RAR5_MAIN = 1
_RAR5_FILE = 2
_RAR5_SERVICE = 3
_RAR5_ENDARC = 5
_RAR5_FLAG_EXTRA = 0x01
_RAR5_FLAG_DATA = 0x02
_RAR5_FLAG_SPLIT = 0x18
_RAR5_MAIN_SOLID = 0x04
_RAR5_FILE_HAS_MTIME = 0x02
_RAR5_FILE_HAS_CRC32 = 0x04

_AES_BLOCK = 16
_COPY_CHUNK = 1 << 20


class SyntheticUnsupported(Exception):
    """This member cannot be put in a synthetic archive; the caller keeps its route.

    Not an :class:`~archivey.exceptions.ArchiveyError`: it never reaches a caller.
    The one case is a RAR 1.5-4 member joined from parts past 4 GiB whose
    last header has no 64-bit size fields.
    """


def placeholder_name(index: int) -> str:
    """The name the member at ``index`` in a synthetic archive gets: ``m<index>``."""
    return f"m{index}"


def _vint(value: int) -> bytes:
    """A RAR5 variable-length integer: 7 bits a byte, low bits first, the top bit
    set on every byte but the last."""
    out = bytearray()
    while True:
        byte = value & 0x7F
        value >>= 7
        if not value:
            out.append(byte)
            return bytes(out)
        out.append(byte | 0x80)


def _rar5_block(body: bytes) -> bytes:
    """CRC32, header-size vint, then ``body`` (which starts at the header type)."""
    sized = _vint(len(body)) + body
    return struct.pack("<I", zlib.crc32(sized)) + sized


def _rar3_block(kind: int, flags: int, rest: bytes) -> bytes:
    """CRC16, type, flags and header size, then ``rest`` (the fields after them)."""
    body = struct.pack("<BHH", kind, flags, 7 + len(rest)) + rest
    return struct.pack("<H", zlib.crc32(body) & 0xFFFF) + body


def signature(version: int) -> bytes:
    return RAR5_ID if version == 5 else RAR_ID


def main_header(version: int, *, solid: bool) -> bytes:
    """A MAIN header: no volume, no comment, no header encryption, no locator.

    The two shapes are the same size whatever ``solid`` is, so a synthetic file can
    set the flag in place when a second member joins the first.
    """
    if version == 5:
        return _rar5_block(
            _vint(_RAR5_MAIN) + _vint(0) + _vint(_RAR5_MAIN_SOLID if solid else 0)
        )
    return _rar3_block(_RAR3_MAIN, _RAR3_MAIN_SOLID if solid else 0, b"\x00" * 6)


def end_header(version: int) -> bytes:
    """An ENDARC header with no next volume. ``unrar`` 7.00 exits 10 without one."""
    if version == 5:
        return _rar5_block(_vint(_RAR5_ENDARC) + _vint(0) + _vint(0))
    return _rar3_block(_RAR3_ENDARC, _RAR3_ENDARC_FLAGS, b"")


# --------------------------------------------------------------------------- headers


@dataclass(frozen=True, slots=True)
class StoredHeader:
    """One FILE or SERVICE header as stored, in plaintext, and the fields it holds.

    ``raw`` starts at the header CRC: RAR5 ``CRC32``, RAR 1.5-4 ``HEAD_CRC``.
    """

    version: int
    raw: bytes
    kind: int
    data_size: int
    unpacked_size: int
    crc32: int | None
    split: bool


def _decrypt(
    ciphertext: bytes, key: bytes, iv: bytes, excluded: frozenset[OptionalLibrary]
) -> bytes:
    return open_aes_decrypt_stage(AesParams(key=key, iv=iv), excluded=excluded).update(
        ciphertext
    )


def _read_exact(read_at: Callable[[int, int], bytes], offset: int, size: int) -> bytes:
    data = read_at(offset, size)
    if len(data) != size:
        raise TruncatedError(
            f"The RAR header at offset {offset} ends early: {len(data)} of {size} "
            "bytes are there."
        )
    return data


@dataclass(frozen=True)
class HeaderKeys:
    """The header keys of an ``-hp`` archive: its header password, derived through
    the reader's KDF cache, so a key the listing derived is not derived again."""

    cache: RarKdfCache
    password: str

    def rar5(self, salt: bytes, kdf_count: int) -> bytes:
        return self.cache.rar5(self.password, salt, 1 << kdf_count)

    def rar3(self, salt: bytes) -> tuple[bytes, bytes]:
        """RAR 1.5-4 ``(key, iv)``."""
        return self.cache.rar3(self.password, salt)


def read_stored_header(
    read_at: Callable[[int, int], bytes],
    archive: RarArchive,
    *,
    volume_index: int,
    offset: int,
    size: int,
    header_keys: HeaderKeys | None = None,
    excluded: frozenset[OptionalLibrary],
) -> StoredHeader:
    """Read the header at ``offset`` (``size`` bytes, the walk's ``header_size``) again
    and parse it.

    ``read_at(offset, n)`` reads ``n`` bytes of the concatenated volume space.
    For a header-encrypted archive ``offset`` is the first ciphertext byte, right after
    the header's RAR 1.5-4 salt or RAR5 IV, as the walk records it, and
    ``header_keys`` derives the key (RAR5 with the volume's KDF count, from
    :attr:`RarArchive.rar5_header_crypt`). A header whose own CRC fails raises
    :class:`CorruptionError`.
    """
    if archive.has_header_encryption:
        if header_keys is None:
            raise ValueError("an encrypted header needs header_keys")
        padded = -(-size // _AES_BLOCK) * _AES_BLOCK
        if archive.version == 5:
            crypt = archive.rar5_header_crypt.get(volume_index)
            if crypt is None:
                raise CorruptionError(
                    f"No header-encryption record for RAR volume {volume_index + 1}"
                )
            salt, kdf_count = crypt
            iv = _read_exact(read_at, offset - _AES_BLOCK, _AES_BLOCK)
            key = header_keys.rar5(salt, kdf_count)
        else:
            salt = _read_exact(read_at, offset - 8, 8)
            key, iv = header_keys.rar3(salt)
        raw = _decrypt(_read_exact(read_at, offset, padded), key, iv, excluded)[:size]
    else:
        raw = _read_exact(read_at, offset, size)
    return parse_stored_header(archive.version, raw, offset=offset)


def parse_stored_header(version: int, raw: bytes, *, offset: int = 0) -> StoredHeader:
    """Parse the fields :func:`patch_header` and the listing check need from ``raw``."""
    try:
        if version == 5:
            return _fields_rar5(raw, offset)
        return _fields_rar3(raw, offset)
    except (struct.error, IndexError) as exc:
        raise CorruptionError(
            f"The RAR header at offset {offset} is cut short"
        ) from exc


def _fields_rar5(raw: bytes, offset: int) -> StoredHeader:
    (crc,) = struct.unpack_from("<I", raw)
    if crc != zlib.crc32(memoryview(raw)[4:]):
        raise CorruptionError(f"RAR5 header CRC mismatch at offset {offset}")
    _, q = load_vint(raw, 4)
    kind, q = load_vint(raw, q)
    hflags, q = load_vint(raw, q)
    if hflags & _RAR5_FLAG_EXTRA:
        _, q = load_vint(raw, q)
    data_size = 0
    if hflags & _RAR5_FLAG_DATA:
        data_size, q = load_vint(raw, q)
    if kind not in (_RAR5_FILE, _RAR5_SERVICE):
        raise CorruptionError(
            f"The RAR5 header at offset {offset} is not a file header (type {kind})"
        )
    fflags, q = load_vint(raw, q)
    unpacked, q = load_vint(raw, q)
    crc32 = None
    _, q = load_vint(raw, q)  # attributes
    if fflags & _RAR5_FILE_HAS_MTIME:
        q += 4
    if fflags & _RAR5_FILE_HAS_CRC32:
        (crc32,) = struct.unpack_from("<I", raw, q)
    return StoredHeader(
        version=5,
        raw=raw,
        kind=kind,
        data_size=data_size,
        unpacked_size=unpacked,
        crc32=crc32,
        split=bool(hflags & _RAR5_FLAG_SPLIT),
    )


def _fields_rar3(raw: bytes, offset: int) -> StoredHeader:
    fixed = _RAR3_FIXED.unpack_from(raw)
    crc, kind, flags, hsize, pack, unp, _host, fcrc = fixed[:8]
    if kind not in (_RAR3_FILE, _RAR3_SUB) or not flags & _RAR3_LONG_BLOCK:
        raise CorruptionError(
            f"The RAR header at offset {offset} is not a file header (type {kind:#x})"
        )
    covered = _rar3_fields_end(raw) if kind == _RAR3_FILE else len(raw)
    if hsize != len(raw) or crc != zlib.crc32(memoryview(raw)[2:covered]) & 0xFFFF:
        raise CorruptionError(f"RAR header CRC mismatch at offset {offset}")
    if flags & _RAR3_FILE_LARGE:
        high_pack, high_unp = _RAR3_HIGH.unpack_from(raw, _RAR3_FIXED.size)
        pack |= high_pack << 32
        unp |= high_unp << 32
    return StoredHeader(
        version=4,
        raw=raw,
        kind=kind,
        data_size=pack,
        unpacked_size=unp,
        crc32=fcrc,
        split=bool(flags & _RAR3_FILE_SPLIT),
    )


def _rar3_fields_end(raw: bytes) -> int:
    """Where a RAR 1.5-4 FILE header's fields end, and its CRC16 coverage with them.

    A RAR 1.5-2.x header with ``LHD_COMMENT`` holds comment subblocks after the fields,
    outside the CRC (``_parse_rar3_file_header``); in every other header this is the
    header's end.
    """
    flags = struct.unpack_from("<H", raw, 3)[0]
    pos = _RAR3_FIXED.size + (_RAR3_HIGH.size if flags & _RAR3_FILE_LARGE else 0)
    pos += struct.unpack_from("<H", raw, 26)[0]
    if flags & _RAR3_FILE_SALT:
        pos += 8
    if flags & _RAR3_FILE_EXTTIME:
        pos = _parse_rar3_ext_time(raw, pos, None)[3]
    if pos > len(raw):
        raise CorruptionError("The RAR header's fields run past its end")
    return pos


def check_against_listing(
    header: StoredHeader, member: RarMemberInfo, *, part_size: int
) -> None:
    """Raise :class:`CorruptionError` when ``header`` is not the one the listing read.

    The bytes ``unrar`` decodes must be the member archivey listed (a file that
    changed on disk after ``open()``, or a quick-open copy that disagrees with the
    header it stands for). ``part_size`` is the packed size of the part this header
    describes: the whole member, or the last part of a joined one.
    """
    mismatch: list[str] = []
    if header.data_size != part_size:
        mismatch.append("packed size")
    if not member.size_unknown and header.unpacked_size != member.file_size:
        mismatch.append("size")
    if member.crc32 is not None and header.crc32 != member.crc32:
        mismatch.append("CRC32")
    if mismatch:
        raise CorruptionError(
            "The RAR header read again for this member does not match the listing "
            f"({', '.join(mismatch)} differ): the archive changed after it was opened, "
            "or two copies of the header disagree."
        )


def patch_header(
    header: StoredHeader, *, name: str, data_size: int, join: bool
) -> bytes:
    """``header`` with name ``name``, packed size ``data_size`` and, for a member
    joined from parts (``join``), its split flags cleared. Every other field is kept.

    A SERVICE header keeps its name: ``unrar`` tells ``CMT``, ``STM`` and ``QO`` apart
    by it.
    """
    service = header.kind == (_RAR5_SERVICE if header.version == 5 else _RAR3_SUB)
    encoded = None if service else name.encode("ascii")
    if header.version == 5:
        return _patch_rar5(header.raw, encoded, data_size, join)
    return _patch_rar3(header.raw, encoded, data_size, join)


def _patch_rar5(raw: bytes, name: bytes | None, data_size: int, join: bool) -> bytes:
    _, q = load_vint(raw, 4)
    kind, q = load_vint(raw, q)
    hflags, q = load_vint(raw, q)
    extra_size = None
    if hflags & _RAR5_FLAG_EXTRA:
        extra_size, q = load_vint(raw, q)
    if hflags & _RAR5_FLAG_DATA:
        _, q = load_vint(raw, q)
    fields_at = q
    fflags, q = load_vint(raw, q)
    _, q = load_vint(raw, q)  # unpacked size
    _, q = load_vint(raw, q)  # attributes
    if fflags & _RAR5_FILE_HAS_MTIME:
        q += 4
    if fflags & _RAR5_FILE_HAS_CRC32:
        q += 4
    _, q = load_vint(raw, q)  # compression info
    _, q = load_vint(raw, q)  # host OS
    name_at = q
    nlen, q = load_vint(raw, q)
    name_end = q + nlen
    if name_end > len(raw):
        raise CorruptionError("The RAR5 header's name runs past its end")
    if name is None:
        name = raw[q:name_end]
    new_flags = (hflags & ~_RAR5_FLAG_SPLIT) if join else hflags
    if data_size:
        new_flags |= _RAR5_FLAG_DATA
    head = _vint(kind) + _vint(new_flags)
    if extra_size is not None:
        head += _vint(extra_size)
    if new_flags & _RAR5_FLAG_DATA:
        head += _vint(data_size)
    body = (
        head
        + raw[fields_at:name_at]
        + _vint(len(name))
        + name
        + raw[name_end:]  # the extra area: the header's last ``extra_size`` bytes
    )
    return _rar5_block(body)


def _patch_rar3(raw: bytes, name: bytes | None, data_size: int, join: bool) -> bytes:
    fixed = list(_RAR3_FIXED.unpack_from(raw))
    flags = fixed[2]
    name_at = _RAR3_FIXED.size
    high = b""
    if flags & _RAR3_FILE_LARGE:
        high_unp = _RAR3_HIGH.unpack_from(raw, name_at)[1]
        high = _RAR3_HIGH.pack(data_size >> 32, high_unp)
        name_at += _RAR3_HIGH.size
    elif data_size >> 32:
        raise SyntheticUnsupported(
            "a RAR 1.5-4 member joined past 4 GiB with no 64-bit size fields"
        )
    old_name_size = fixed[11]
    # A FILE header's old comment subblocks are left out: ``unrar p`` does not read
    # them, and they sit outside the CRC this header gets.
    end = _rar3_fields_end(raw) if fixed[1] == _RAR3_FILE else len(raw)
    if fixed[1] == _RAR3_FILE:
        flags &= ~_RAR3_FILE_COMMENT
    tail = raw[name_at + old_name_size : end]
    if name is None:
        name = raw[name_at : name_at + old_name_size]
    else:
        flags &= ~_RAR3_FILE_UNICODE  # a plain 8-bit name, with no Unicode part
    if join:
        flags &= ~_RAR3_FILE_SPLIT
    fixed[2] = flags
    fixed[4] = data_size & 0xFFFFFFFF
    fixed[11] = len(name)
    # HEAD_CRC, HEAD_TYPE, HEAD_FLAGS and HEAD_SIZE are rewritten by _rar3_block.
    rest = _RAR3_FIXED.pack(*fixed)[7:] + high + name + tail
    return _rar3_block(fixed[1], flags, rest)


# ------------------------------------------------------------------------------ file


@dataclass(frozen=True, slots=True)
class SyntheticMember:
    """One member to append: its patched header and the packed bytes after it.

    ``data`` returns the streams to copy, in order, each with its size, and
    ``data_size`` is their total. :meth:`SyntheticArchive.append` closes every
    stream ``data`` returns, the ones a failed copy leaves unread included.
    """

    header: bytes
    data: Callable[[], Iterable[tuple[BinaryIO, int]]]
    data_size: int

    @property
    def size(self) -> int:
        return len(self.header) + self.data_size


class SyntheticArchive:
    """A synthetic RAR file on disk that members are appended to, in archive order.

    The file always ends with an ENDARC header: :meth:`append` writes the new members
    over the old ENDARC and a new one after them, so nothing already in the file is
    copied again. ``solid`` says the members form one solid chain; the MAIN header's
    solid flag is then set once the file holds more than one member. The file is
    created with mode 0600 (``mkstemp``; on POSIX) and removed by :meth:`close`.

    No handle stays open between calls. ``unrar`` on Windows opens its archive with
    read sharing only, so a write handle held here would make it fail to open the
    file (exit 6).
    """

    def __init__(
        self, version: int, *, solid: bool = False, directory: str | None = None
    ) -> None:
        self.version = version
        self.solid = solid
        self._main_at = len(signature(version))
        fd, name = tempfile.mkstemp(
            prefix="archivey-rar-", suffix=".rar", dir=directory
        )
        self.path = Path(name)
        self._closed = False
        try:
            with os.fdopen(fd, "wb") as f:
                f.write(signature(version))
                f.write(main_header(version, solid=False))
                self._end_at = f.tell()
                f.write(end_header(version))
        except BaseException:
            self.close()
            raise
        self.count = 0
        #: Bytes in the file, ENDARC included.
        self.size = self._end_at + len(end_header(version))

    @staticmethod
    def overhead(version: int) -> int:
        """Bytes of an empty synthetic file: signature, MAIN and ENDARC."""
        return (
            len(signature(version))
            + len(main_header(version, solid=False))
            + len(end_header(version))
        )

    def append(self, members: Iterable[SyntheticMember]) -> None:
        """Write ``members`` after the ones already in the file, then a new ENDARC.

        A stream that ends before its declared size raises :class:`TruncatedError`;
        the file then still ends with the old ENDARC, so it is what it was. Streams
        that add up to other than the member's ``data_size`` are a caller bug and
        raise ``ValueError``, the file again left as it was.
        """
        if self._closed:
            raise ValueError("synthetic archive is closed")
        added = 0
        end = self._end_at
        with self.path.open("r+b") as f:
            f.seek(self._end_at)
            try:
                for member in members:
                    f.write(member.header)
                    _copy_all(member.data(), f)
                    end += member.size
                    if f.tell() != end:
                        raise ValueError(
                            "synthetic RAR member data does not add up to its "
                            f"declared {member.data_size} bytes"
                        )
                    added += 1
                f.write(end_header(self.version))
                f.truncate()
            except BaseException:
                f.seek(self._end_at)
                f.write(end_header(self.version))
                f.truncate()
                raise
            if self.solid and self.count < 2 <= self.count + added:
                # ``unrar`` keeps the decoder's state from one member to the next
                # only in an archive whose MAIN header says it is solid; otherwise
                # it does not decode the chain's earlier members, and the target
                # decodes against an empty window (13 solid fixture sets fail).
                f.seek(self._main_at)
                f.write(main_header(self.version, solid=True))
        self.count += added
        self._end_at = end
        self.size = end + len(end_header(self.version))

    def close(self) -> None:
        """Remove the file. Safe to call more than once."""
        if not self._closed:
            self._closed = True
            self.path.unlink(missing_ok=True)


def _copy_all(parts: Iterable[tuple[BinaryIO, int]], dst: BinaryIO) -> None:
    """Copy each ``(stream, size)`` of ``parts`` exactly, and close every stream."""
    pending = list(parts)
    try:
        for stream, size in pending:
            remaining = size
            while remaining > 0:
                chunk = stream.read(min(remaining, _COPY_CHUNK))
                if not chunk:
                    raise TruncatedError(
                        f"RAR member data ends {remaining} bytes before its packed size"
                    )
                dst.write(chunk)
                remaining -= len(chunk)
    finally:
        for stream, _ in pending:
            stream.close()


# --------------------------------------------------------------------------- planning


def member_headers(
    member: RarMemberInfo,
) -> tuple[tuple[int, int, int], int, bool]:
    """Where the header to copy for ``member`` is, its part's packed size, and
    whether the member is joined from parts.

    A member in one part copies its own header. A member split across volumes
    copies its last part's header, which carries the whole member's digest and
    encryption record (``_merge_split_member``).
    """
    if member.last_part_header is not None and member.data_parts:
        return member.last_part_header, member.data_parts[-1][1], True
    return (
        (member.volume_index, member.header_offset, member.header_size),
        member.compress_size,
        False,
    )


def placeholder_mask(position: int, info: RarMemberInfo, version: int) -> str:
    """The ``-n`` mask that selects the ``position``-th member of a synthetic archive.

    With ``-ver``, ``unrar`` names a RAR5 history row ``m<k>;<n>`` from its version
    record, so the mask carries the suffix. A RAR 1.5-4 row keeps its ``;n`` in the
    stored name, which the placeholder replaces, so it is plain ``m<k>`` there.
    """
    name = placeholder_name(position)
    if version == 5 and info.is_file_version_history():
        return f"{name};{info.file_version}"
    return name


def has_packed_data(info: RarMemberInfo) -> bool:
    """Whether ``info`` goes into a synthetic archive: a member with packed data.

    A RAR 1.5-4 symlink counts: its target is compressed data, and in a solid stream
    later members depend on it. A directory and a file copy do not.
    """
    return info.compress_size > 0 and not info.is_directory and not info.is_file_copy()


def solid_chain(members: list[RarMemberInfo], target: int) -> range:
    """Indices of ``members`` a solid read of ``members[target]`` must decode.

    From the last member at or before the target whose own solid flag is clear (the
    start of its solid stream), to the target. ``unrar`` starts there when it is
    given the name as an argument, and so does ``unar``.
    """
    start = target
    while start > 0 and members[start].file_solid:
        start -= 1
    return range(start, target + 1)
