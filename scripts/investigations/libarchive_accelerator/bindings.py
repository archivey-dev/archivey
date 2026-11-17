"""ctypes bindings to the system libarchive, for decoding one synthetic entry as a stream.

libarchive has no public API for a bare codec: its LZX, LZH, ZipCrypto and LZW
decoders sit behind its CAB, LHA, ZIP and ``compress`` readers. So each accelerated
codec builds a one-entry container around the coded bytes (``wrappers.py``) and this
module reads that entry, pulling the container's bytes from a Python iterator through
libarchive's read callback. Nothing here reads the whole input first.

Investigation code (``dev-docs/investigations/libarchive-accelerator.md``), not used by
archivey.
"""

from __future__ import annotations

import ctypes
import ctypes.util
from collections.abc import Iterator
from typing import Any, Self

ARCHIVE_EOF = 1
ARCHIVE_OK = 0
ARCHIVE_WARN = -20
ARCHIVE_FAILED = -25
ARCHIVE_FATAL = -30

_READ_CALLBACK = ctypes.CFUNCTYPE(
    ctypes.c_ssize_t, ctypes.c_void_p, ctypes.c_void_p, ctypes.POINTER(ctypes.c_void_p)
)


class LibarchiveError(Exception):
    """A libarchive call failed, or a wrapper's own check did."""

    def __init__(self, code: int, message: str) -> None:
        super().__init__(f"{code}: {message}")
        self.code = code
        self.message = message


def _load() -> ctypes.CDLL:
    name = ctypes.util.find_library("archive") or "libarchive.so.13"
    lib = ctypes.CDLL(name)
    vp, cp, i = ctypes.c_void_p, ctypes.c_char_p, ctypes.c_int
    sigs: dict[str, tuple[Any, list[Any]]] = {
        "archive_version_number": (i, []),
        "archive_version_details": (cp, []),
        "archive_read_new": (vp, []),
        "archive_read_free": (i, [vp]),
        "archive_read_open": (i, [vp, vp, vp, _READ_CALLBACK, vp]),
        "archive_read_open_memory": (i, [vp, cp, ctypes.c_size_t]),
        "archive_read_next_header": (i, [vp, ctypes.POINTER(vp)]),
        "archive_read_data": (ctypes.c_ssize_t, [vp, vp, ctypes.c_size_t]),
        "archive_read_data_block": (
            i,
            [
                vp,
                ctypes.POINTER(vp),
                ctypes.POINTER(ctypes.c_size_t),
                ctypes.POINTER(ctypes.c_int64),
            ],
        ),
        "archive_error_string": (cp, [vp]),
        "archive_read_add_passphrase": (i, [vp, cp]),
        "archive_read_set_options": (i, [vp, cp]),
    }
    for fmt in ("raw", "cab", "lha", "zip_streamable", "7zip"):
        sigs[f"archive_read_support_format_{fmt}"] = (i, [vp])
    sigs["archive_read_support_filter_compress"] = (i, [vp])
    for fname, (res, args) in sigs.items():
        fn = getattr(lib, fname)
        fn.restype, fn.argtypes = res, args
    return lib


lib = _load()


def version() -> str:
    return lib.archive_version_details().decode()


class EntryStream:
    """Read the first entry of a container that ``chunks`` yields, as decoded bytes.

    ``fmt`` names a libarchive format reader (``cab``, ``lha``, ``zip_streamable``,
    ``raw``), ``filters`` the filters to enable. ``ignore_final_warning`` turns an
    ``ARCHIVE_WARN`` at the end of the entry into a normal end. The LHA wrapper uses it:
    it writes a CRC-16 of zero, because the member's CRC is the reader's check, not the
    codec's, and libarchive reports the mismatch as that warning.

    Close the stream (``with``, or :func:`decode_all`): it holds a libarchive handle.
    """

    def __init__(
        self,
        chunks: Iterator[bytes],
        fmt: str,
        *,
        filters: tuple[str, ...] = (),
        passphrase: bytes | None = None,
        options: str | None = None,
        ignore_final_warning: bool = False,
    ) -> None:
        self._chunks = chunks
        self._keep: ctypes.Array[ctypes.c_char] | None = (
            None  # the chunk libarchive holds
        )
        self._callback = _READ_CALLBACK(self._read)
        self._callback_error: BaseException | None = None
        self._ignore_final_warning = ignore_final_warning
        self._done = False
        self._block, self._size, self._offset = (
            ctypes.c_void_p(),
            ctypes.c_size_t(),
            ctypes.c_int64(),
        )
        self._a = lib.archive_read_new()
        try:
            getattr(lib, f"archive_read_support_format_{fmt}")(self._a)
            for f in filters:
                getattr(lib, f"archive_read_support_filter_{f}")(self._a)
            if passphrase is not None:
                lib.archive_read_add_passphrase(self._a, passphrase)
            if options:
                self._check(lib.archive_read_set_options(self._a, options.encode()))
            self._check(
                lib.archive_read_open(self._a, None, None, self._callback, None)
            )
            entry = ctypes.c_void_p()
            r = lib.archive_read_next_header(self._a, ctypes.byref(entry))
            if r not in (ARCHIVE_OK, ARCHIVE_WARN):
                self._check(r)
        except BaseException:
            self.close()
            raise

    def _read(self, _a: int, _data: int, out: Any) -> int:
        try:
            chunk = next(self._chunks, b"")
        except BaseException as exc:  # noqa: BLE001 - re-raised by _check after the C call
            self._callback_error = exc
            return -1
        self._keep = ctypes.create_string_buffer(chunk, len(chunk))
        out[0] = ctypes.cast(self._keep, ctypes.c_void_p)
        return len(chunk)

    def _message(self) -> str:
        msg = lib.archive_error_string(self._a)
        return msg.decode("utf-8", "replace") if msg else ""

    def _check(self, r: int) -> None:
        if self._callback_error is not None:
            raise self._callback_error
        if r < ARCHIVE_OK:
            raise LibarchiveError(r, self._message())

    def read(self) -> bytes:
        """The next block libarchive decoded; ``b""`` at the end of the entry.

        Block by block (``archive_read_data_block``), not ``archive_read_data``: the
        latter copies the last block and then returns the end check's warning in place
        of its count, so with ``ignore_final_warning`` the last block would be lost.
        """
        while not self._done:
            r = lib.archive_read_data_block(
                self._a,
                ctypes.byref(self._block),
                ctypes.byref(self._size),
                ctypes.byref(self._offset),
            )
            if r == ARCHIVE_OK:
                if self._size.value:  # an empty block is skipped
                    return ctypes.string_at(self._block, self._size.value)
            elif r == ARCHIVE_EOF or (r == ARCHIVE_WARN and self._ignore_final_warning):
                # A failed end check (CRC) comes on its own call, after the data.
                self._done = True
            else:
                self._check(r)
                raise AssertionError(f"libarchive returned {r}")
        return b""

    def read_all(self) -> bytes:
        out = []
        while chunk := self.read():
            out.append(chunk)
        return b"".join(out)

    def close(self) -> None:
        if self._a:
            lib.archive_read_free(self._a)
            self._a = None

    def __enter__(self) -> Self:
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()


def decode_all(stream: EntryStream) -> bytes:
    """All of ``stream``'s bytes, closing it."""
    with stream:
        return stream.read_all()


def decode_archive(blob: bytes, fmt: str) -> bytes:
    """Every entry of an archive held in memory, concatenated.

    For the whole-archive timings only: 7z needs a seekable source, which the
    callback reader above does not offer.
    """
    a = lib.archive_read_new()
    try:
        getattr(lib, f"archive_read_support_format_{fmt}")(a)
        if lib.archive_read_open_memory(a, blob, len(blob)) != ARCHIVE_OK:
            raise LibarchiveError(ARCHIVE_FATAL, "open failed")
        buf = ctypes.create_string_buffer(1 << 16)
        out = []
        entry = ctypes.c_void_p()
        while lib.archive_read_next_header(a, ctypes.byref(entry)) == ARCHIVE_OK:
            while (n := lib.archive_read_data(a, buf, len(buf))) > 0:
                out.append(buf.raw[:n])
            if n < 0:
                raise LibarchiveError(int(n), "read failed")
        return b"".join(out)
    finally:
        lib.archive_read_free(a)
