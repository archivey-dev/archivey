"""Build and demonstrate R1 or R2. Run with archivey installed and RARLAB on PATH."""

from __future__ import annotations

import io
import struct
import subprocess
import sys
import tempfile
import zlib
from pathlib import Path

from archivey import ArchiveyConfig, SpoolLimits, open_archive


class Pipe(io.BytesIO):
    """A source advertised as non-seekable, with no usable seek operation."""

    def seekable(self) -> bool:
        return False

    def seek(self, *_args: object, **_kwargs: object) -> int:
        raise io.UnsupportedOperation("pipe")


def vint(value: int) -> bytes:
    out = bytearray()
    while value >= 128:
        out.append((value & 127) | 128)
        value >>= 7
    out.append(value)
    return bytes(out)


def block(body: bytes) -> bytes:
    framed = vint(len(body)) + body
    return struct.pack("<I", zlib.crc32(framed)) + framed


def padded_rar(payload: bytes) -> bytes:
    fields = (
        vint(4)  # CRC32 present
        + vint(len(payload))
        + vint(0o100644)
        + struct.pack("<I", zlib.crc32(payload))
        + b"\x00\x01\x01a"  # stored, Unix, one-byte name
    )
    return (
        b"Rar!\x1a\x07\x01\x00"
        + block(b"\x01\x00\x00")
        + block(b"\x02\x03\x01" + vint(len(payload)) + fields + b"\x00")
        + payload
        + block(b"\x05\x00\x00")
    )


def show_read(label: str, raw: bytes, *, pipe: bool, limit: int | None) -> None:
    source = Pipe(raw) if pipe else io.BytesIO(raw)
    config = ArchiveyConfig(spool_limits=SpoolLimits(max_bytes=limit))
    try:
        with open_archive(source, streaming=True, config=config) as reader:
            members = reader.stream_members()
            member, stream = next(members)
            assert stream is not None
            data = stream.read()
            print(
                f"{label}: read {member.name}: {len(data)} bytes; all zero={not any(data)}"
            )
            # Stop after this member, as a consumer of stream_members() may do.
            members.close()
    except Exception as exc:  # noqa: BLE001 - show the public outcome
        print(f"{label}: {type(exc).__name__}: {exc}")


def main() -> None:
    finding = sys.argv[1]
    with tempfile.TemporaryDirectory(prefix="archivey-rar-repro-") as temp:
        root = Path(temp)
        if finding in ("R1", "R1-default", "R1-blake"):
            large = finding != "R1"
            (root / "zeros").write_bytes(bytes((24 if large else 6) << 20))
            subprocess.run(
                ["rar", "a", "-cfg-", "-idq", "-ma5", "-m0"]
                + (["-htb"] if finding == "R1-blake" else [])
                + ["a.rar", "zeros"],
                cwd=root,
                check=True,
                capture_output=True,
            )
            raw = (root / "a.rar").read_bytes()[: (20 if large else 5) << 20]
            limit = None if large else 2 << 20
        elif finding == "R2":
            raw = padded_rar(bytes(range(251)) * 40)
            limit = 4000
        else:
            raise SystemExit("Choose R1, R1-default, R1-blake or R2")
        path = root / "input.rar"
        path.write_bytes(raw)
        oracle = subprocess.run(
            ["unrar", "t", "-cfg-", "-inul", str(path)],
            check=False,
            capture_output=True,
        )
        print(f"unrar t: exit {oracle.returncode}")
        show_read("seekable", raw, pipe=False, limit=limit)
        if finding == "R2":
            show_read("pipe, default limit", raw, pipe=True, limit=None)
        show_read(
            "pipe, default limit" if limit is None else "pipe, reduced limit",
            raw,
            pipe=True,
            limit=limit,
        )


if __name__ == "__main__":
    main()
