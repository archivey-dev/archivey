"""Probe archivey's model of Windows ``unrar``'s 8-bit name reading under a DBCS OEM.

Windows ``unrar`` reads a RAR 1.5-4 name stored only as 8-bit bytes through the system
OEM code page, then the ANSI one (``ArcCharToWide`` with ``ACTW_OEM``), and archivey
reproduces that with the same two calls to build the ``-n`` mask. It was measured
only under OEM 437. Under a double-byte OEM code page such as 932 (Japanese), a lead
byte joins the next byte into one character, so a trail byte of ``0x5c`` is not a
``\\`` and a lone lead byte has no partner.

The probe renames the first member of ``tests/fixtures/rar/hostile_argv__rar4.rar``
(the bytes of a compressed member stay the same) to names chosen for those cases, with
a Windows host byte as WinRAR writes and with the fixture's Unix one, and reads each
with archivey through ``unrar``, by ``read()`` and in ``stream_members()``. Each row
says whether the read returned the member's own bytes, was refused, or failed. It
exits 1 when a read returns wrong bytes or fails with anything but a refusal.

Run by ``.github/workflows/rar-windows-links-probe.yml`` inside a Windows container
whose OEM and ANSI code pages are set to 932, and on the runner itself (437) as the
control. Needs ``pytest`` importable (the RAR 1.5-4 header rewriters live in the
tests).
"""

from __future__ import annotations

import ctypes
import json
import sys
import tempfile
from pathlib import Path

_ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(_ROOT))
_FIXTURE = _ROOT / "tests/fixtures/rar/hostile_argv__rar4.rar"

# Shift-JIS (cp932) names. A trail byte of 0x5c is the classic DBCS trap.
_NAMES = {
    "hyou (95 5c)": b"\x95\x5c.txt",
    "so (83 5c) then dir-like": b"\x83\x5cx.txt",
    "tesuto": b"\x83e\x83X\x83g.txt",
    "half-width ka (b6)": b"\xb6.txt",
    "lone lead byte (83 2e)": b"a\x83.txt",
    "lead byte at end": b"ab\x83",
    "ascii control": b"plain.txt",
}


def _renamed(name: bytes, host: int | None) -> bytes:
    from tests.test_audit_rar_iso_dir import _rar3_build, _rar3_parse, _rar3_rename

    blocks = _rar3_parse(_FIXTURE.read_bytes())
    block = next(b for b in blocks if b["type"] == 0x74)
    _rar3_rename(block, name)
    if host is not None:
        block["header"][15] = host
    return _rar3_build(blocks)


def _code_pages() -> dict[str, int | None]:
    if sys.platform != "win32":
        return {"oem": None, "ansi": None}
    k = ctypes.windll.kernel32
    return {"oem": k.GetOEMCP(), "ansi": k.GetACP()}


def main() -> int:
    from archivey import ArchiveyConfig, open_archive
    from archivey.exceptions import UnsupportedFeatureError

    config = ArchiveyConfig(rar_decompressor="unrar")
    with open_archive(_FIXTURE, config=config) as reader:
        first = reader.members()[0]
        expected = reader.read(first)
    rows = []
    bad = 0
    with tempfile.TemporaryDirectory() as tmp:
        for label, name in _NAMES.items():
            for host_label, host in (("windows host", 2), ("unix host", None)):
                path = Path(tmp) / "renamed.rar"
                path.write_bytes(_renamed(name, host))
                row: dict[str, object] = {
                    "case": label,
                    "host": host_label,
                    "stored": name.hex(" "),
                }
                try:
                    with open_archive(path, config=config) as reader:
                        member = reader.members()[0]
                        row["listed"] = member.name
                        try:
                            got = reader.read(member)
                            row["read"] = "own bytes" if got == expected else "WRONG"
                        except UnsupportedFeatureError as exc:
                            row["read"] = f"refused: {exc}"
                    with open_archive(path, config=config) as reader:
                        for m, stream in reader.stream_members():
                            if m.member_id == member.member_id and stream is not None:
                                data = stream.read()
                                row["stream"] = (
                                    "own bytes" if data == expected else "WRONG"
                                )
                except Exception as exc:  # noqa: BLE001 - a probe reports everything
                    row["error"] = f"{type(exc).__name__}: {exc}"
                if (
                    row.get("read") == "WRONG"
                    or row.get("stream") == "WRONG"
                    or "error" in row
                ):
                    bad += 1
                rows.append(row)
    print(json.dumps({"code_pages": _code_pages(), "rows": rows}, indent=1))
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main())
