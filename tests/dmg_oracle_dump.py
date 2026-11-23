"""Print what another DMG reader finds in an image, as JSON, for tests/test_dmg_oracles.py.

usage: python dmg_oracle_dump.py {dpp,libyal} IMAGE

Output:
``{"ok": true, "entries": {path: ["file", sha256] | ["dir"] | ["symlink", target]}}``,
or ``{"ok": false, "error": "..."}`` when the reader refuses the image. A path that one
reader lists but cannot read is ``["error", message]``. Paths are NFC, ``/``-separated,
without a leading ``/``. The test runs this in a subprocess because both readers are
native code (a crash or an abort must not take pytest down, and importing them on a
free-threaded build may turn the GIL back on).
"""

from __future__ import annotations

import hashlib
import json
import struct
import sys
import unicodedata
from typing import Any


def _name(path: str) -> str:
    return unicodedata.normalize("NFC", path.strip("/"))


def _dpp(image: str) -> dict[str, list[str]]:
    import dpp

    entries: dict[str, list[str]] = {}
    with dpp.open(image) as pipeline:
        fs = pipeline.filesystem(mode="in_memory")
        stack = ["/"]
        while stack:
            folder = stack.pop()
            try:
                listed = fs.list_directory(folder)
            except Exception as exc:  # noqa: BLE001 - recorded for the test
                entries[_name(folder)] = ["error", str(exc)]
                continue
            for entry in listed:
                path = folder.rstrip("/") + "/" + entry.name
                kind = str(entry.kind).lower()
                if "dir" in kind:
                    entries[_name(path)] = ["dir"]
                    stack.append(path)
                    continue
                try:
                    data = fs.read_file(path)
                except Exception as exc:  # noqa: BLE001
                    entries[_name(path)] = ["error", str(exc)]
                    continue
                if "link" in kind or "sym" in kind:
                    entries[_name(path)] = [
                        "symlink",
                        data.decode("utf-8", "surrogateescape"),
                    ]
                else:
                    entries[_name(path)] = ["file", hashlib.sha256(data).hexdigest()]
    return entries


class _Window:
    """A file object over part of a pymodi handle: one partition of the disk."""

    def __init__(
        self, handle: Any, start: int, size: int
    ) -> None:  # pymodi has no stubs
        self._handle, self._start, self._size, self._pos = handle, start, size, 0

    def read(self, n: int = -1) -> bytes:
        if n is None or n < 0:
            n = self._size - self._pos
        n = max(0, min(n, self._size - self._pos))
        self._handle.seek(self._start + self._pos)
        data = self._handle.read(n)
        self._pos += len(data)
        return data

    def seek(self, offset: int, whence: int = 0) -> int:
        base = (0, self._pos, self._size)[whence]
        self._pos = base + offset
        return self._pos

    def tell(self) -> int:
        return self._pos

    def get_size(self) -> int:
        return self._size


def _volumes(handle) -> list[tuple[int, int]]:
    """(offset, size) of each partition: GPT, Apple Partition Map, or the whole disk."""
    handle.seek(0)
    head = handle.read(4096)
    if head[512:520] == b"EFI PART":
        (table_lba,) = struct.unpack_from("<Q", head, 512 + 72)
        count, entry_size = struct.unpack_from("<II", head, 512 + 80)
        handle.seek(table_lba * 512)
        table = handle.read(count * entry_size)
        found = []
        for i in range(count):
            entry = table[i * entry_size : (i + 1) * entry_size]
            if entry[:16] != bytes(16):
                first, last = struct.unpack_from("<QQ", entry, 32)
                found.append((first * 512, (last - first + 1) * 512))
        return found
    if head[512:514] == b"PM":
        (count,) = struct.unpack_from(">I", head, 512 + 4)
        found = []
        for i in range(count):
            handle.seek(512 * (1 + i))
            entry = handle.read(512)
            start, length = struct.unpack_from(">II", entry, 8)
            if b"Apple_HFS" in entry[48:80] or b"Apple_APFS" in entry[48:80]:
                found.append((start * 512, length * 512))
        return found
    return [(0, handle.get_media_size())]


def _libyal(image: str) -> dict[str, list[str]]:
    import pyfsapfs
    import pyfshfs
    import pymodi

    handle = pymodi.handle()
    handle.open(image)
    entries: dict[str, list[str]] = {}
    for start, size in _volumes(handle):
        handle.seek(start)
        head = handle.read(1100)
        if head[32:36] == b"NXSB":
            container = pyfsapfs.container()
            container.open_file_object(_Window(handle, start, size))
            for i in range(container.number_of_volumes):
                _walk(container.get_volume(i).get_root_directory(), "", entries)
        elif head[1024:1026] in (b"H+", b"HX"):
            volume = pyfshfs.volume()
            volume.open_file_object(_Window(handle, start, size))
            _walk(volume.get_root_directory(), "", entries)
    return entries


def _walk(folder, prefix: str, entries: dict[str, list[str]]) -> None:
    for entry in folder.sub_file_entries:
        path = prefix + "/" + entry.name
        try:
            target = entry.get_symbolic_link_target()
            if target:
                entries[_name(path)] = ["symlink", target]
                continue
            if (entry.file_mode or 0) & 0o170000 == 0o040000:
                entries[_name(path)] = ["dir"]
                _walk(entry, path, entries)
                continue
            data = entry.read_buffer(entry.size) if entry.size else b""
        except Exception as exc:  # noqa: BLE001
            entries[_name(path)] = ["error", str(exc)]
            continue
        entries[_name(path)] = ["file", hashlib.sha256(data).hexdigest()]


def main() -> None:
    reader, image = sys.argv[1], sys.argv[2]
    try:
        out = {"ok": True, "entries": {"dpp": _dpp, "libyal": _libyal}[reader](image)}
    except Exception as exc:  # noqa: BLE001
        out = {"ok": False, "error": f"{type(exc).__name__}: {exc}"}
    print(json.dumps(out))


if __name__ == "__main__":
    main()
