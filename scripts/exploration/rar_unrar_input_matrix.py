"""What can RARLAB ``unrar`` accept as its *archive* input, and what does it emit?

Supporting ``dev-docs/formats/rar.md`` §1 (the process boundary) and §2.3.

Four questions, all about the boundary rather than about RAR itself:

1. **Can the archive arrive on a pipe?** ``unrar --help`` advertises ``-si``, which
   invites the idea of streaming the archive in and so avoiding archivey's
   whole-archive temp copy for a non-path source. It does not work, and the reason
   closes the whole family: ``unrar`` *seeks* the archive.
2. **Is an anonymous seekable fd enough?** A ``memfd`` is seekable and never appears
   in the filesystem, so it would trade disk for RAM.
3. **Does that survive multi-volume?** ``unrar`` discovers later volumes by *name*,
   which an anonymous fd cannot provide — and volumes do not concatenate.
4. **Which members does ``unrar p`` emit bytes for?** The solid ALL-pipe demux is
   sliced by declared sizes, so it has to model that policy exactly. Neither the
   packed nor the unpacked size predicts it, and RAR3 and RAR5 disagree in opposite
   directions.

Stdlib-only; RARLAB ``unrar`` is required and everything else is skipped. Every
child gets ``stdin`` set explicitly, ``start_new_session=True``, a timeout, and a
stdout byte cap.

    python3 scripts/exploration/rar_unrar_input_matrix.py
    python3 scripts/exploration/rar_unrar_input_matrix.py --json /tmp/input.json
"""

from __future__ import annotations

import argparse
import json
import os
import shutil
import signal
import subprocess
import sys
import tempfile
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
FIX = REPO / "tests" / "fixtures" / "rar"
TIMEOUT = 8
MAX_STDOUT = 2 * 1024 * 1024


def _unrar() -> str | None:
    path = shutil.which("unrar")
    if path is None:
        return None
    banner = subprocess.run([path], capture_output=True, timeout=TIMEOUT, check=False)
    text = (banner.stdout + banner.stderr).decode("utf-8", "replace")
    if "UNRAR" not in text:
        return None
    if "Alexander Roshal" not in text and "RARLAB" not in text:
        return None
    return path


def _banner_version(unrar: str) -> str:
    out = subprocess.run([unrar], capture_output=True, timeout=TIMEOUT, check=False)
    first = (out.stdout + out.stderr).decode("utf-8", "replace").strip().splitlines()
    return first[0].strip() if first else "?"


def _run(argv: list[str], *, stdin, pass_fds: tuple[int, ...] = ()) -> dict:
    """Run ``argv``, capping stdout. Returns rc plus how many bytes came back."""
    try:
        proc = subprocess.Popen(
            argv,
            stdin=stdin,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            start_new_session=True,
            pass_fds=pass_fds,
        )
    except OSError as exc:
        return {"rc": None, "bytes": 0, "note": f"spawn failed: {exc}"}
    try:
        out, err = proc.communicate(timeout=TIMEOUT)
    except subprocess.TimeoutExpired:
        proc.kill()
        out, err = proc.communicate()
        return {"rc": "timeout", "bytes": len(out), "note": ""}
    note = err.decode("utf-8", "replace").strip().splitlines()
    return {
        "rc": proc.returncode,
        "bytes": len(out[:MAX_STDOUT]),
        "note": note[-1][:70] if note else "",
    }


# --- 1 + 2: how the archive can be handed over --------------------------------------


def input_modes(unrar: str, archive: Path) -> list[dict]:
    rows: list[dict] = []
    data = archive.read_bytes()

    def piped(argv_tail: list[str]) -> dict:
        """Run with ``data`` on the child's stdin through a real pipe."""
        r, w = os.pipe()
        try:
            os.write(w, data)
        except OSError:
            pass  # archive larger than the pipe buffer; the probe fails earlier anyway
        os.close(w)
        try:
            return _run([unrar, "p", "-inul", "-p-", *argv_tail], stdin=r)
        finally:
            os.close(r)

    # -si with no archive path: the "read the archive from stdin" reading of the switch.
    # (Passing -si *and* a path proves nothing — unrar just reads the path.)
    rows.append({"mode": "unrar p -si, no path (pipe on stdin)", **piped(["-si"])})
    rows.append({"mode": "unrar p - (pipe on stdin)", **piped(["-"])})
    rows.append(
        {"mode": "unrar p /dev/stdin, stdin is a PIPE", **piped(["/dev/stdin"])}
    )

    with archive.open("rb") as handle:
        rows.append(
            {
                "mode": "unrar p /dev/stdin, stdin is a SEEKABLE file",
                **_run([unrar, "p", "-inul", "-p-", "/dev/stdin"], stdin=handle),
            }
        )

    with tempfile.TemporaryDirectory() as td:
        fifo = Path(td) / "archive.fifo"
        os.mkfifo(fifo)
        pid = os.fork()
        if pid == 0:  # child: keep the FIFO writable so unrar can open it
            # Opening a FIFO for writing blocks until a reader appears, and an unrar
            # that refuses the path outright never becomes one — so bound the wait
            # rather than hanging the probe.
            signal.alarm(TIMEOUT)
            try:
                with fifo.open("wb") as sink:
                    sink.write(data)
            except (OSError, InterruptedError):
                pass
            os._exit(0)
        try:
            rows.append(
                {
                    "mode": "unrar p <FIFO path>",
                    **_run(
                        [unrar, "p", "-inul", "-p-", str(fifo)],
                        stdin=subprocess.DEVNULL,
                    ),
                }
            )
        finally:
            os.waitpid(pid, 0)

    fd = os.memfd_create("archive.rar")
    try:
        os.write(fd, data)
        os.lseek(fd, 0, os.SEEK_SET)
        os.set_inheritable(fd, True)
        rows.append(
            {
                "mode": "unrar p /proc/self/fd/N, N is an inherited MEMFD",
                **_run(
                    [unrar, "p", "-inul", "-p-", f"/proc/self/fd/{fd}"],
                    stdin=subprocess.DEVNULL,
                    pass_fds=(fd,),
                ),
            }
        )
    finally:
        os.close(fd)
    return rows


# --- 3: multi-volume ----------------------------------------------------------------


def volume_modes(unrar: str, parts: list[Path]) -> list[dict]:
    rows: list[dict] = []
    whole = sum(len(p.read_bytes()) for p in parts)

    rows.append(
        {
            "mode": f"unrar p <part1 on disk, {len(parts)} named siblings present>",
            **_run(
                [unrar, "p", "-inul", "-p-", str(parts[0])], stdin=subprocess.DEVNULL
            ),
        }
    )

    fd = os.memfd_create("part1.rar")
    try:
        os.write(fd, parts[0].read_bytes())
        os.lseek(fd, 0, os.SEEK_SET)
        os.set_inheritable(fd, True)
        rows.append(
            {
                "mode": "unrar p <part1 as a MEMFD: no sibling name to discover>",
                **_run(
                    [unrar, "p", "-inul", "-p-", f"/proc/self/fd/{fd}"],
                    stdin=subprocess.DEVNULL,
                    pass_fds=(fd,),
                ),
            }
        )
    finally:
        os.close(fd)

    with tempfile.TemporaryDirectory() as td:
        joined = Path(td) / "joined.rar"
        joined.write_bytes(b"".join(p.read_bytes() for p in parts))
        rows.append(
            {
                "mode": f"unrar p <volumes byte-concatenated, {whole} B>",
                **_run(
                    [unrar, "p", "-inul", "-p-", str(joined)],
                    stdin=subprocess.DEVNULL,
                ),
            }
        )
    return rows


# --- 4: which members does `unrar p` emit bytes for? --------------------------------


def emission_policy(unrar: str, archive: Path) -> list[dict]:
    """Per member: stored packed/unpacked size vs bytes ``unrar p`` actually emits."""
    sys.path.insert(0, str(REPO / "src"))
    from archivey.internal.backends.rar_parser import parse_rar_archive

    with archive.open("rb") as handle:
        parsed = parse_rar_archive(handle)

    rows: list[dict] = []
    for member in parsed.members:
        emitted = _run(
            [unrar, "p", "-inul", "-p-", f"-n./{member.filename}", str(archive)],
            stdin=subprocess.DEVNULL,
        )
        kind = "dir" if member.is_directory else "link" if member.is_symlink else "file"
        rows.append(
            {
                "member": member.filename,
                "kind": kind,
                "packed": member.compress_size,
                "unpacked": member.file_size,
                "emitted": emitted["bytes"],
                "rc": emitted["rc"],
            }
        )
    return rows


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--json", type=Path, help="also write the rows as JSON")
    args = parser.parse_args()

    unrar = _unrar()
    if unrar is None:
        print("RARLAB unrar not on PATH — nothing to measure.")
        return 0
    if not FIX.is_dir():
        print(f"missing fixtures: {FIX}")
        return 1

    print(f"unrar: {unrar}  ({_banner_version(unrar)})")
    report: dict[str, list[dict]] = {}

    print("\n== 1+2. how the archive is handed over (basic_nonsolid__.rar)")
    print("   rc 0 = read it; anything else = refused. Only seekable inputs work.")
    rows = input_modes(unrar, FIX / "basic_nonsolid__.rar")
    report["input_modes"] = rows
    for row in rows:
        print(
            f"   {row['mode']:<52} rc={row['rc']!s:>7}  {row['bytes']:>5} B  {row['note']}"
        )

    print("\n== 3. multi-volume (tinyvol.part1.rar + part2)")
    print(
        "   unrar finds later volumes by FILENAME, so an anonymous fd cannot serve them."
    )
    parts = [FIX / "tinyvol.part1.rar", FIX / "tinyvol.part2.rar"]
    if all(p.is_file() for p in parts):
        rows = volume_modes(unrar, parts)
        report["volume_modes"] = rows
        for row in rows:
            print(f"   {row['mode']:<62} rc={row['rc']!s:>7}  {row['bytes']:>5} B")
    else:
        print("   fixtures missing — skipped")

    print(
        "\n== 4. emission policy: does any stored size predict what `unrar p` prints?"
    )
    for name in ("symlinks_solid__.rar", "symlinks_solid__rar4.rar"):
        path = FIX / name
        if not path.is_file():
            continue
        print(f"   -- {name}")
        rows = emission_policy(unrar, path)
        report[f"emission:{name}"] = rows
        for row in rows:
            print(
                f"      {row['member']:<28} {row['kind']:<5} "
                f"packed={row['packed']:>4} unpacked={row['unpacked']:>4} "
                f"emitted={row['emitted']:>4}"
            )

    if args.json:
        args.json.write_text(json.dumps(report, indent=2), encoding="utf-8")
        print(f"\nwrote {args.json}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
