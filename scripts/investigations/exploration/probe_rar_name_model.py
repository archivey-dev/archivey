"""Probe archivey's model of which members an ``unrar -n`` mask selects, on this OS.

A named ``unrar p`` pipes every payload member its ``-n`` mask selects, so archivey
predicts that selection (``unrar_member_view``, ``unrar_mask_selects``) to size the
skip before its target. ``tests/test_rar_unrar_names.py`` compares the prediction
with ``unrar`` on Linux only, because its expected views are Linux's. This probe
makes the same comparison with whatever the model says on the OS it runs on, so it
measures the Windows and macOS branches too.

Archives (stored members, each payload ``<NNN>`` so a wrong member shows):

- the RAR5 names of the tests, plus names for Windows' case fold and its
  precomposition of a Unix-host name;
- the RAR 1.5-4 8-bit names of the tests, with a Unix and with a Windows host byte;
- Shift-JIS (cp932) 8-bit names, both hosts, for a double-byte OEM code page.

For each archive it passes every member's own mask (``unrar_member_argument``, what
the reader sends) and a few globs, and compares the members ``unrar`` prints with the
ones the model predicts. It then reads every member with archivey through ``unrar``
and checks it gets its own bytes or a refusal. It exits 1 on any difference.

Run by ``.github/workflows/rar-name-model-probe.yml`` on Linux (the control),
macOS and Windows, and inside a Windows container whose code pages are 932.
Needs ``pytest`` importable (the archive builders live in the tests).
"""

from __future__ import annotations

import json
import struct
import sys
import tempfile
import zlib
from pathlib import Path

_ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(_ROOT))

# RAR5 names for the Windows-only steps: CharUpperW's case fold and FoldStringW's
# precomposition of a Unix-host name (host 1 here is the tests' "Unix").
_RAR5_EXTRA: list[tuple[bytes, int]] = [
    ("e\u0301.txt".encode(), 1),  # decomposed: FoldStringW precomposes it
    ("\u00e9.txt".encode(), 1),  # precomposed
    ("É.TXT".encode(), 1),
    ("ı.txt".encode(), 1),
    (b"I.txt", 1),
    ("straße".encode(), 1),
    (b"STRASSE", 1),
    ("Ω.txt".encode(), 1),
    ("ω.txt".encode(), 1),
]
_RAR5_GLOBS = ["ab.", "ab...", "a?", "?", "??", "a?b", "d/ab", "\u00e9", "x/../ab"]
_RAR5_GLOBS += ["E\u0301.TXT", "?.txt", "STRASSE", "i.txt"]

# Shift-JIS names. A trail byte of 0x5c is the classic DBCS trap.
_DBCS_NAMES: list[bytes] = [
    b"\x95\x5c.txt",
    b"\x83\x5cx.txt",
    b"\x83e\x83X\x83g.txt",
    b"\xb6.txt",
    b"a\x83.txt",
    b"ab\x83",
    b"\x95\x5c",
    b"plain.txt",
]
_RAR3_GLOBS = ["café.txt", "caf", "d", "?.txt", "??.txt", "a?.txt"]


def _payload(index: int) -> bytes:
    return f"<{index:03d}>".encode()


def _build_rar3(path: Path, names: list[tuple[bytes, int]]) -> Path:
    """Stored, nonsolid RAR 2.9 members with 8-bit names and the given host bytes."""
    from tests.test_audit_rar_iso_dir import _fixture, _rar3_build, _rar3_parse

    blocks = _rar3_parse(_fixture("hostile_argv__rar4.rar").read_bytes())
    template = next(block for block in blocks if block["type"] == 0x74)
    head = [block for block in blocks if block["type"] == 0x73]
    tail = [block for block in blocks if block["type"] == 0x7B]
    files = []
    for index, (name, host) in enumerate(names):
        data = _payload(index)
        header = bytearray(template["header"])
        flags = struct.unpack_from("<H", header, 3)[0]
        old_len = struct.unpack_from("<H", header, 26)[0]
        offset = 32 + (8 if flags & 0x100 else 0)
        header[offset : offset + old_len] = name
        struct.pack_into("<H", header, 26, len(name))
        struct.pack_into("<H", header, 3, flags & ~0x02F0)
        struct.pack_into("<II", header, 7, len(data), len(data))
        header[15] = host
        struct.pack_into("<I", header, 16, zlib.crc32(data))
        header[25] = 0x30
        struct.pack_into("<H", header, 5, len(header))
        files.append({"type": 0x74, "header": header, "data": data})
    path.write_bytes(_rar3_build(head + files + tail))
    return path


def _compare(
    archive: Path, views: list[str | None], masks: list[str | bytes]
) -> tuple[list[dict[str, object]], dict[str, list[int]]]:
    """Return the mismatching masks and, for every mask, the members it left unknown.

    A mask whose every member is unknown compared nothing; it is reported as a
    mismatch, so a probe where the comparison fails open does not pass.
    """
    from archivey.internal.backends.rar_unrar import (
        UnrarSelectionUnknown,
        unrar_dot_rule,
        unrar_mask_is_usable,
        unrar_mask_selects,
        unrar_mask_view,
    )
    from tests.test_rar_unrar_names import _unrar_selects

    dot_rule = unrar_dot_rule()
    rows = []
    unknowns: dict[str, list[int]] = {}
    for mask in dict.fromkeys(masks):
        if isinstance(mask, str) and any("\ud800" <= c <= "\udfff" for c in mask):
            continue
        mask_view = unrar_mask_view(mask)
        if mask_view is None or not unrar_mask_is_usable(mask_view):
            continue
        expected: list[int] = []
        unknown: list[int] = []
        for index, view in enumerate(views):
            if view is None:
                continue
            try:
                if unrar_mask_selects(mask_view, view, dot_rule=bool(dot_rule)):
                    expected.append(index)
            except UnrarSelectionUnknown:
                # unrar's answer depends on memory past the name; reported, not
                # compared, and the reader refuses such a read.
                unknown.append(index)
        label = mask.hex(" ") if isinstance(mask, bytes) else mask
        if unknown:
            unknowns[label] = unknown
        known = sum(view is not None for view in views)
        if known and len(unknown) == known:
            rows.append({"mask": label, "model": "every member unknown"})
            continue
        try:
            actual: object = _unrar_selects(archive, mask, len(views))
        except AssertionError as exc:
            actual = f"unparsed: {exc}"
        if isinstance(actual, list):
            actual = [index for index in actual if index not in unknown]
        if actual != expected:
            rows.append(
                {
                    "mask": label,
                    "model": expected,
                    "unrar": actual,
                    "unknown": unknown,
                }
            )
    return rows, unknowns


def _read_all(archive: Path) -> dict[str, list[object]]:
    from archivey import ArchiveyConfig, open_archive
    from archivey.exceptions import UnsupportedFeatureError

    config = ArchiveyConfig(
        rar_decompressor="unrar", rar_allow_glob_member_concatenation=True
    )
    out: dict[str, list[object]] = {"read": [], "refused": [], "wrong": []}
    with open_archive(archive, config=config) as reader:
        for index, member in enumerate(reader.members()):
            try:
                data = reader.read(member)
            except UnsupportedFeatureError:
                out["refused"].append(index)
                continue
            except Exception as exc:  # noqa: BLE001 - a probe reports everything
                out["wrong"].append([index, f"{type(exc).__name__}: {exc}"])
                continue
            if data == _payload(index):
                out["read"].append(index)
            else:
                out["wrong"].append([index, data[:20].decode("latin-1")])
    return out


def _code_pages() -> dict[str, int | None]:
    if sys.platform != "win32":
        return {"oem": None, "ansi": None}
    import ctypes

    k = ctypes.windll.kernel32  # type: ignore[attr-defined]
    return {"oem": k.GetOEMCP(), "ansi": k.GetACP()}


def _code_page_mismatch(pages: dict[str, int | None]) -> bool:
    """True when ``ARCHIVEY_PROBE_CODE_PAGE`` names a page the OEM or ANSI page is not.

    The cp932 container job sets it, so a container left on its default code pages
    fails instead of passing as the runner's control. ``chcp`` is the console page
    and says nothing about ``GetOEMCP``.
    """
    import os

    want = os.environ.get("ARCHIVEY_PROBE_CODE_PAGE")
    if not want:
        return False
    if pages["oem"] != int(want) or pages["ansi"] != int(want):
        print(f"CODE PAGE MISMATCH: want {want}, got {pages}")
        return True
    return False


def main() -> int:
    from archivey.internal.backends.rar_reader import RarReader
    from archivey.internal.backends.rar_unrar import (
        unrar_dot_rule,
        unrar_member_argument,
        unrar_member_view,
    )
    from tests.test_rar_unrar_names import _RAR3_NAMES, _RAR5_NAMES, _build_rar5

    # Stored members would be sliced without unrar; send every read through it.
    RarReader._is_directly_sliceable = lambda self, info: False  # type: ignore[method-assign]

    report: dict[str, object] = {
        "platform": sys.platform,
        "code_pages": _code_pages(),
        "dot_rule": unrar_dot_rule(),
        "archives": {},
    }
    archives = report["archives"]
    assert isinstance(archives, dict)
    bad = 0
    with tempfile.TemporaryDirectory() as tmp:
        tmp_path = Path(tmp)
        rar5_names = _RAR5_NAMES + _RAR5_EXTRA
        sets: list[tuple[str, bool, list[tuple[bytes, int]], list[str]]] = [
            ("rar5", True, rar5_names, _RAR5_GLOBS),
            ("rar3 unix host", False, [(n, 3) for n in _RAR3_NAMES], _RAR3_GLOBS),
            ("rar3 windows host", False, [(n, 2) for n in _RAR3_NAMES], _RAR3_GLOBS),
            ("dbcs unix host", False, [(n, 3) for n in _DBCS_NAMES], _RAR3_GLOBS),
            ("dbcs windows host", False, [(n, 2) for n in _DBCS_NAMES], _RAR3_GLOBS),
        ]
        for label, rar5, names, globs in sets:
            sub = tmp_path / label.replace(" ", "_")
            sub.mkdir()
            if rar5:
                archive = _build_rar5(sub, names)
            else:
                archive = _build_rar3(sub / "names3.rar", names)
            views = [
                unrar_member_view(
                    rar5=rar5,
                    stored=name,
                    rar3_unicode_name=None,
                    # RAR5 host: 0 Windows, 1 Unix in the tests' list; views use 2/3.
                    host_os=(2 if host == 0 else 3) if rar5 else host,
                    file_version=None,
                )
                for name, host in names
            ]
            masks: list[str | bytes] = []
            for (name, _host), view in zip(names, views, strict=True):
                argument = unrar_member_argument(view, name, stored_is_8bit=not rar5)
                if argument:
                    masks.append(argument)
            masks += globs
            mismatches, unknowns = _compare(archive, views, masks)
            reads = _read_all(archive)
            bad += len(mismatches) + len(reads["wrong"])
            archives[label] = {
                "views": views,
                "masks_compared": len(dict.fromkeys(masks)),
                "mismatches": mismatches,
                "unknown": unknowns,
                **reads,
            }
    print(json.dumps(report, indent=1))
    pages = report["code_pages"]
    assert isinstance(pages, dict)
    bad += _code_page_mismatch(pages)
    print(f"RESULT: {bad} difference(s)")
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main())
