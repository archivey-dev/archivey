"""Probe how ``unrar`` emits Windows symlink and junction members in a solid pass.

A solid ``stream_members()`` pass splits one ``unrar p`` output stream back into
members, counting only the members ``is_payload_file()`` says ``unrar`` prints. Windows
symlinks and junctions (RAR5 redirect types 2 and 3) had no fixtures, so that rule was
unmeasured for them. A wrong guess shifts every later member's bytes.

Two modes:

``build`` (Windows only) makes a tree with a file symlink, a directory symlink and a
junction between regular files, and archives it with WinRAR's ``rar -ol`` (solid and
not). Each archive is also printed as base64 between markers, so a run log carries it.

``check`` (any OS) reads each archive with the RARLAB ``unrar`` on PATH and with
archivey, and reports, per member: the type archivey lists, whether
``is_payload_file()`` counts it, and the bytes ``unrar p`` prints for it alone. It then
compares the whole-archive ``unrar p`` length with the sum archivey counts, and every
``stream_members()`` stream with ``open()``. It exits 1 on any mismatch.

Run by ``.github/workflows/rar-windows-links-probe.yml``; results feed
``dev-docs/formats/rar.md``.
"""

from __future__ import annotations

import argparse
import base64
import json
import os
import shutil
import subprocess
import sys
from pathlib import Path

# Distinct, compressible text per member, so a shifted demux reads the wrong bytes
# rather than bytes that happen to match.
_FILES = {
    "a_first.txt": "first " * 400,
    "sub/b_inside.txt": "inside " * 300,
    "z_last.txt": "last " * 500,
}
# Added by a second ``rar a``, which appends it after every member already in the
# archive. ``rar`` stores directories, directory links and junctions after the files
# of one run, so without this no data would follow them in the solid stream and a
# miscount there would go unseen.
_APPENDED = {"zz_after.txt": "after " * 450}


def _build(rar: str, out: Path) -> None:
    if os.name != "nt":
        sys.exit("build runs on Windows only: junctions and Windows links need it")
    # rar runs in the tree, so the archive path must not be relative to here.
    out = out.resolve()
    tree = out / "tree"
    if tree.exists():
        shutil.rmtree(tree)
    tree.mkdir(parents=True)
    for name, text in _FILES.items():
        path = tree / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding="ascii")
    os.symlink("a_first.txt", tree / "l_file_link.txt")
    os.symlink("sub", tree / "m_dir_link", target_is_directory=True)
    os.symlink(str(tree / "a_first.txt"), tree / "n_abs_file_link.txt")
    subprocess.run(
        ["cmd", "/c", "mklink", "/J", "o_junction", "sub"], cwd=tree, check=True
    )
    order = [
        "a_first.txt",
        "l_file_link.txt",
        "m_dir_link",
        "n_abs_file_link.txt",
        "o_junction",
        "sub",
        "z_last.txt",
    ]
    variants = {
        "winlinks_solid__.rar": ["-ma5", "-s", "-m3", "-ol"],
        "winlinks_nonsolid__.rar": ["-ma5", "-m3", "-ol"],
    }
    for name, flags in variants.items():
        archive = out / name
        archive.unlink(missing_ok=True)
        subprocess.run(
            [rar, "a", "-r", *flags, str(archive), *order],
            cwd=tree,
            check=True,
        )
        for appended, text in _APPENDED.items():
            (tree / appended).write_text(text, encoding="ascii")
            subprocess.run(
                [rar, "a", *flags, str(archive), appended], cwd=tree, check=True
            )
            (tree / appended).unlink()
        listing = subprocess.run(
            [rar, "lt", str(archive)], capture_output=True, check=True
        ).stdout.decode("utf-8", "replace")
        print(f"===== rar lt {name} =====\n{listing}")
        data = archive.read_bytes()
        print(f"===== BEGIN {name} {len(data)} =====")
        print(base64.b64encode(data).decode())
        print(f"===== END {name} =====")


def _unrar_p(archive: Path, member: str | None = None) -> bytes:
    args = ["unrar", "p", "-inul", "-cfg-", "-p-", str(archive)]
    if member is not None:
        args.append(member)
    return subprocess.run(args, check=False, capture_output=True, timeout=60).stdout


def _check(archives: list[Path]) -> int:
    from archivey import ArchiveyConfig, open_archive

    config = ArchiveyConfig(rar_decompressor="unrar")
    failures = 0
    report: list[dict[str, object]] = []
    for archive in archives:
        whole = _unrar_p(archive)
        rows = []
        counted = 0
        with open_archive(archive, config=config) as reader:
            members = reader.members()
            for m in members:
                raw = m._raw
                payload = bool(raw.is_payload_file())  # type: ignore[union-attr]
                if payload:
                    counted += m.size or 0
                # A directory name selects its contents too, so it says nothing here.
                alone = (
                    None
                    if m.type.name == "DIRECTORY"
                    else len(_unrar_p(archive, m.name.replace("/", os.sep)))
                )
                rows.append(
                    {
                        "name": m.name,
                        "type": m.type.name,
                        "size": m.size,
                        "link_target": m.link_target,
                        "junction": m.extra.get("is_junction"),
                        "reparse": m.extra.get("is_reparse_point"),
                        "redir": getattr(raw, "file_redir", None) and raw.file_redir[0],  # type: ignore[union-attr]
                        "payload": payload,
                        "unrar_p_alone": alone,
                    }
                )
                if not payload and alone:
                    failures += 1
                    print(
                        f"MISMATCH {archive.name}: {m.name} not counted, prints {alone}"
                    )
            by_open: dict[str, bytes] = {}
            for m, row in zip(members, rows, strict=True):
                if row["payload"]:
                    try:
                        with reader.open(m) as f:
                            by_open[m.name] = f.read()
                    except Exception as exc:  # noqa: BLE001 - a probe reports everything
                        by_open[m.name] = f"<{type(exc).__name__}: {exc}>".encode()
        streamed: dict[str, bytes] = {}
        stream_error = None
        try:
            with open_archive(archive, config=config) as reader:
                for m, stream in reader.stream_members():
                    if stream is not None and m.name in by_open:
                        streamed[m.name] = stream.read()
        except Exception as exc:  # noqa: BLE001
            stream_error = f"{type(exc).__name__}: {exc}"
            failures += 1
        for name, data in by_open.items():
            if streamed.get(name) != data and stream_error is None:
                failures += 1
                print(
                    f"MISMATCH {archive.name}: stream_members bytes differ for {name}"
                )
        if len(whole) != counted:
            failures += 1
            print(
                f"MISMATCH {archive.name}: unrar p printed {len(whole)}, "
                f"archivey counts {counted}"
            )
        report.append(
            {
                "archive": archive.name,
                "unrar_p_total": len(whole),
                "archivey_counted": counted,
                "stream_error": stream_error,
                "members": rows,
            }
        )
    print(json.dumps(report, indent=1, default=str))
    return 1 if failures else 0


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="mode", required=True)
    b = sub.add_parser("build")
    b.add_argument("--rar", required=True)
    b.add_argument("--out", type=Path, required=True)
    c = sub.add_parser("check")
    c.add_argument("archives", nargs="+", type=Path)
    args = parser.parse_args()
    if args.mode == "build":
        _build(args.rar, args.out)
        return 0
    return _check(args.archives)


if __name__ == "__main__":
    sys.exit(main())
