"""Probe which decmpfs type 10 layout macOS reads (DMG plan, open question in §7).

Builds one image with a type 10 file per candidate resource-fork layout, attaches it
read-only, and reads each file through the kernel. Prints one line per layout.
macOS only. Temporary: run from the dmg-macos workflow on a branch.
"""

from __future__ import annotations

import struct
import subprocess
import sys
import tempfile
from pathlib import Path

_REPO = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(_REPO))
sys.path.insert(0, str(Path(__file__).resolve().parent))


def _offset_table(chunks: list[bytes]) -> bytes:
    offsets = [4 * (len(chunks) + 1)]
    for c in chunks:
        offsets.append(offsets[-1] + len(c))
    return struct.pack(f"<{len(offsets)}I", *offsets) + b"".join(chunks)


def _cmpf_fork(chunks: list[bytes]) -> bytes:
    table = struct.pack("<I", len(chunks))
    off = 4 + 8 * len(chunks)
    body = bytearray()
    for c in chunks:
        table += struct.pack("<II", off, len(c))
        off += len(c)
        body += c
    payload = table + body
    rsrc_data = struct.pack(">I", len(payload)) + payload
    rmap = (
        bytes(24)
        + struct.pack(">HHH", 0x1C, 0x32, 0)
        + b"cmpf"
        + struct.pack(">HHhH", 0, 0x0A, 1, 0xFFFF)
        + bytes(8)
    )
    head = struct.pack(">IIII", 0x100, 0x100 + len(rsrc_data), len(rsrc_data), len(rmap))
    return head + bytes(0x100 - 16) + rsrc_data + rmap


LAYOUTS = {
    "offsets raw": lambda b: _offset_table(b),
    "offsets 0xCC": lambda b: _offset_table([b"\xcc" + x for x in b]),
    "offsets 0xFF": lambda b: _offset_table([b"\xff" + x for x in b]),
    "offsets 0x06": lambda b: _offset_table([b"\x06" + x for x in b]),
    "cmpf raw": lambda b: _cmpf_fork(b),
    "cmpf 0xCC": lambda b: _cmpf_fork([b"\xcc" + x for x in b]),
    "cmpf 0xFF": lambda b: _cmpf_fork([b"\xff" + x for x in b]),
}


def main() -> int:
    from dmg_macos_check import _attached

    from tests import dmg_build as d

    datas = {
        name: (f"{name}\n".encode() * 9000)[: 70_000 + i]
        for i, name in enumerate(LAYOUTS)
    }
    by_data = {v: k for k, v in datas.items()}
    real = d._decmpfs

    def patched(kind: int, data: bytes) -> tuple[bytes, bytes]:
        if kind == 10 and data in by_data:
            blocks = [
                data[i : i + d.DECMPFS_BLOCK]
                for i in range(0, len(data), d.DECMPFS_BLOCK)
            ]
            header = b"fpmc" + struct.pack("<IQ", 10, len(data))
            return header, LAYOUTS[by_data[data]](blocks)
        return real(kind, data)

    d._decmpfs = patched
    nodes = [
        d.Node(f"v{i}.txt", data=data, compression=10)
        for i, data in enumerate(datas.values())
    ]
    nodes.append(d.Node("t4.txt", data=b"control\n" * 9000, compression=4))
    image = d.dmg_of(nodes, hfs_options={"name": "Vol"})
    with tempfile.TemporaryDirectory() as tmp:
        path = Path(tmp) / "probe.dmg"
        path.write_bytes(image)
        print(subprocess.run(["hdiutil", "verify", str(path)], capture_output=True,
                             text=True).returncode, "hdiutil verify")
        with _attached(path, mount=True) as (_, root):
            assert root is not None
            for i, (name, data) in enumerate(datas.items()):
                try:
                    got = (root / f"v{i}.txt").read_bytes()
                    print(f"{name}: {'MATCH' if got == data else f'differs ({len(got)})'}")
                except OSError as exc:
                    print(f"{name}: {exc.strerror}")
            control = (root / "t4.txt").read_bytes() == b"control\n" * 9000
            print(f"type 4 control: {'MATCH' if control else 'differs'}")
            ls = subprocess.run(["ls", "-lO", str(root)], capture_output=True, text=True)
            print(ls.stdout)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
