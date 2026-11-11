"""Compare how XAR readers treat a member whose heap data holds more than one stream.

Builds one-file XAR archives whose member is stored as one stream, two streams, or one
stream followed by junk or zero padding, for each XAR encoding (gzip/zlib, bzip2, LZMA
Alone, xz). Each archive declares either the size and SHA-1 of every stream's output or
of the first stream's output only. Then it extracts every archive with:

- Apple's ``xar`` (``/usr/bin/xar`` on macOS, the official reader),
- ``bsdtar`` (libarchive; ``/usr/bin/tar`` on macOS),
- archivey (``AcceleratorMode.OFF``).

and prints a Markdown table: whether the tool succeeded and what it wrote ("A" = the
first stream's output, "A+B" = both streams', "-" = nothing). Each tool runs in a
subprocess with a timeout, since a reader may loop on bad input.

Usage::

    uv run python scripts/investigations/xar_multistream_oracle.py [--out results.md]

Tools that are not installed are reported as "n/a". The XAR handbook entry
(``dev-docs/formats/xar.md`` §2) records what this found.
"""

from __future__ import annotations

import argparse
import bz2
import hashlib
import lzma
import shutil
import struct
import subprocess
import sys
import tempfile
import zlib
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path

HEADER = struct.Struct(">4sHHQQI")
TIMEOUT = 30

A = b"first stream " * 400
B = b"second stream " * 300

ENCODINGS: dict[str, tuple[str, Callable[[bytes], bytes]]] = {
    "gzip": ("application/x-gzip", zlib.compress),
    "bzip2": ("application/x-bzip2", bz2.compress),
    "lzma": ("application/x-lzma", lambda d: lzma.compress(d, lzma.FORMAT_ALONE)),
    "xz": ("application/x-xz", lzma.compress),
}


@dataclass(frozen=True)
class Case:
    encoding: str
    name: str
    stored: bytes
    declared: bytes


def cases() -> list[Case]:
    out: list[Case] = []
    for encoding, (_, encode) in ENCODINGS.items():
        a, b = encode(A), encode(B)
        out += [
            Case(encoding, "one stream (control)", a, A),
            Case(encoding, "two streams, declares A+B", a + b, A + B),
            Case(encoding, "two streams, declares A", a + b, A),
            Case(encoding, "A + junk bytes", a + b"junkjunk", A),
            Case(encoding, "A + 4 zero bytes", a + b"\0" * 4, A),
        ]
        if encoding == "xz":
            out.append(
                Case(
                    encoding, "A + 4 zeros + B, declares A+B", a + b"\0" * 4 + b, A + B
                )
            )
    return out


def build(case: Case) -> bytes:
    """A XAR of one file ``a``, as Apple's xar writes one: SHA-1 TOC checksum first in
    the heap, then the member data with archived and extracted SHA-1 checksums."""
    style = ENCODINGS[case.encoding][0]
    toc_ck = 20
    toc = (
        '<?xml version="1.0" encoding="UTF-8"?>\n<xar><toc>'
        '<checksum style="sha1"><offset>0</offset><size>20</size></checksum>'
        '<file id="1"><name>a</name><type>file</type><mode>0644</mode>'
        f"<data><length>{len(case.stored)}</length><offset>{toc_ck}</offset>"
        f'<size>{len(case.declared)}</size><encoding style="{style}"/>'
        f'<archived-checksum style="sha1">{hashlib.sha1(case.stored).hexdigest()}'
        "</archived-checksum>"
        f'<extracted-checksum style="sha1">{hashlib.sha1(case.declared).hexdigest()}'
        "</extracted-checksum></data></file></toc></xar>"
    ).encode()
    stored_toc = zlib.compress(toc)
    header = HEADER.pack(b"xar!", HEADER.size, 1, len(stored_toc), len(toc), 1)
    return header + stored_toc + hashlib.sha1(stored_toc).digest() + case.stored


def describe(path: Path) -> str:
    if not path.is_file():
        return "-"
    data = path.read_bytes()
    if data == A:
        return "A"
    if data == A + B:
        return "A+B"
    if data and A.startswith(data):
        return f"part of A ({len(data)} B)"
    return f"other ({len(data)} B)"


def run(cmd: list[str], cwd: Path) -> tuple[str, str]:
    try:
        proc = subprocess.run(
            cmd, cwd=cwd, capture_output=True, text=True, timeout=TIMEOUT, check=False
        )
    except subprocess.TimeoutExpired:
        return "TIMEOUT", ""
    message = (proc.stderr or proc.stdout).strip().splitlines()
    status = "ok" if proc.returncode == 0 else f"rc={proc.returncode}"
    if not message:
        return status, ""
    last = message[-1]
    head, _, rest = last.partition(": ")
    if rest and head.endswith(("Error", "Exception")):
        last = f"{head.rsplit('.', 1)[-1]}: {rest}"
    return status, last[:90]


ARCHIVEY = """
import sys
from pathlib import Path
from archivey import open_archive
from archivey.config import AcceleratorMode, ArchiveyConfig
config = ArchiveyConfig(use_rapidgzip=AcceleratorMode.OFF, use_indexed_bzip2=AcceleratorMode.OFF)
with open_archive(sys.argv[1], config=config) as reader:
    data = reader.read("a")
Path(sys.argv[2]).write_bytes(data)
"""


def tools() -> dict[str, Callable[[Path, Path], list[str]] | None]:
    xar = shutil.which("xar")
    bsdtar = shutil.which("bsdtar") or (
        "/usr/bin/tar" if sys.platform == "darwin" else None
    )
    return {
        "xar": (lambda arc, out: [xar, "-xf", str(arc), "-C", str(out)])
        if xar
        else None,
        "bsdtar": (lambda arc, out: [bsdtar, "-xf", str(arc), "-C", str(out)])
        if bsdtar
        else None,
        "archivey": lambda arc, out: [
            sys.executable,
            "-c",
            ARCHIVEY,
            str(arc),
            str(out / "a"),
        ],
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--out", type=Path, help="also write the table here")
    args = parser.parse_args()

    found = tools()
    lines = [
        "| encoding | case | " + " | ".join(found) + " |",
        "|---|---|" + "---|" * len(found),
    ]
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        for index, case in enumerate(cases()):
            archive = root / f"case{index}.xar"
            archive.write_bytes(build(case))
            cells = []
            for name, make in found.items():
                if make is None:
                    cells.append("n/a")
                    continue
                out = root / f"out{index}-{name}"
                out.mkdir()
                status, message = run(make(archive, out), root)
                cell = f"{status}, wrote {describe(out / 'a')}"
                if message and status != "ok":
                    cell += f" ({message.replace('|', '/')})"
                cells.append(cell)
            lines.append(
                f"| {case.encoding} | {case.name} | " + " | ".join(cells) + " |"
            )
    versions = []
    for name, cmd in (
        ("xar", ["xar", "--version"]),
        ("bsdtar", ["bsdtar", "--version"]),
    ):
        if shutil.which(cmd[0]):
            versions.append(f"{name}: {run(cmd, Path.cwd())[1] or '?'}")
    table = "\n".join([f"Tools: {'; '.join(versions) or 'none found'}", "", *lines])
    print(table)
    if args.out:
        args.out.write_text(table + "\n", encoding="utf-8")


if __name__ == "__main__":
    main()
