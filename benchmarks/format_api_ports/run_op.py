"""Run one operation on one archive with a chosen reader, for callgrind or a timer.

    python -m benchmarks.format_api_ports.run_op ARCHIVE READER OP [REPEAT]

READER is ``builtin`` or a port name (``zip``, ...); OP is ``open``, ``list``,
``stream``, ``read`` or ``extract``.
"""

from __future__ import annotations

import importlib
import shutil
import sys
import tempfile
import time

import archivey

PORTS = {
    "zip": ("benchmarks.format_api_ports.zip_indexed", "ZIP_PORT"),
    "zipseq": ("benchmarks.format_api_ports.zip_sequential", "ZIP_SEQ_PORT"),
    "7z": ("benchmarks.format_api_ports.sevenzip_indexed", "SEVENZIP_PORT"),
}


def run(path: str, reader: str, op: str) -> None:
    fmt = None
    if reader != "builtin":
        module, name = PORTS[reader]
        fmt = getattr(importlib.import_module(module), name)
    src: object = path
    if op == "pipe":
        src = open(path, "rb")  # noqa: SIM115
        import io

        src = io.BufferedReader(_Unseekable(src))
    kw = {"streaming": True} if op == "pipe" else {}
    with archivey.open_archive(src, format=fmt, **kw) as r:
        if op == "open":
            return
        if op == "list":
            r.members()
        elif op in ("stream", "pipe"):
            for _m, s in r.stream_members():
                if s is not None:
                    s.read()
        elif op == "read":
            for m in r.members():
                if m.type is archivey.MemberType.FILE:
                    r.read(m)
        elif op == "extract":
            d = tempfile.mkdtemp()
            try:
                r.extract_all(d)
            finally:
                shutil.rmtree(d)


class _Unseekable:
    def __init__(self, f):
        self._f = f
        self.closed = False

    def readable(self):
        return True

    def seekable(self):
        return False

    def readinto(self, b):
        return self._f.readinto(b)

    def close(self):
        self._f.close()
        self.closed = True

    def flush(self):
        pass


if __name__ == "__main__":
    path, reader, op = sys.argv[1:4]
    repeat = int(sys.argv[4]) if len(sys.argv) > 4 else 1
    t = time.perf_counter()
    for _ in range(repeat):
        run(path, reader, op)
    if repeat > 1:
        print(f"{(time.perf_counter() - t) / repeat * 1e3:.2f} ms")
