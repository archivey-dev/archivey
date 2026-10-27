"""Compare RAR decompressor CLIs against RARLAB ``unrar p``.

Supporting ``dev-docs/investigations/alternative-rar-decompressors.md``.

Stdlib-only. Missing tools are skipped. Every child gets ``stdin=DEVNULL``,
``start_new_session=True``, a timeout, and a stdout byte cap so a firehose
cannot fill RAM (``bsdtar --to-stdout`` on stored nonsolid wrote ~7 GB in 8 s).

    python3 scripts/exploration/rar_decompressor_matrix.py
    python3 scripts/exploration/rar_decompressor_matrix.py --json /tmp/matrix.json
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
import threading
from pathlib import Path
from typing import IO

REPO = Path(__file__).resolve().parents[2]
FIX = REPO / "tests" / "fixtures" / "rar"
TIMEOUT = 8
# Largest legitimate gold in this matrix is a few KiB. A few MiB is generous.
MAX_STDOUT = 2 * 1024 * 1024
MAX_STDERR = 64 * 1024


def _sig(rc: int) -> str:
    if rc < 0:
        try:
            return signal.Signals(-rc).name
        except ValueError:
            return str(rc)
    return str(rc)


def _kill(proc: subprocess.Popen[bytes]) -> None:
    try:
        os.killpg(proc.pid, signal.SIGKILL)
    except (ProcessLookupError, PermissionError, OSError):
        proc.kill()


def _run(cmd: list[str], *, timeout: int = TIMEOUT) -> tuple[int, bytes, bytes]:
    """Run ``cmd``; kill on timeout or once stdout exceeds ``MAX_STDOUT``."""
    try:
        proc = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            stdin=subprocess.DEVNULL,
            start_new_session=True,
        )
    except FileNotFoundError:
        return 127, b"", b"not found"

    out_chunks: list[bytes] = []
    err_chunks: list[bytes] = []
    cap_hit = threading.Event()

    def _drain(
        pipe: IO[bytes], chunks: list[bytes], limit: int, *, is_stdout: bool
    ) -> None:
        n = 0
        while True:
            data = pipe.read(65536)
            if not data:
                return
            # Cap only when the child exceeds the budget, not when it lands
            # exactly on it (a legitimate 2 MiB payload would be a match).
            if n + len(data) > limit:
                chunks.append(data[: limit - n])
                if is_stdout:
                    cap_hit.set()
                    _kill(proc)
                    return
                n = limit
                continue
            chunks.append(data)
            n += len(data)

    assert proc.stdout is not None and proc.stderr is not None
    t_out = threading.Thread(
        target=_drain,
        args=(proc.stdout, out_chunks, MAX_STDOUT),
        kwargs={"is_stdout": True},
    )
    t_err = threading.Thread(
        target=_drain,
        args=(proc.stderr, err_chunks, MAX_STDERR),
        kwargs={"is_stdout": False},
    )
    t_out.start()
    t_err.start()
    try:
        proc.wait(timeout=timeout)
        rc = proc.returncode if proc.returncode is not None else 1
    except subprocess.TimeoutExpired:
        _kill(proc)
        proc.wait()
        rc = 124
    t_out.join()
    t_err.join()
    if proc.stdout is not None:
        proc.stdout.close()
    if proc.stderr is not None:
        proc.stderr.close()
    out = b"".join(out_chunks)
    err = b"".join(err_chunks)
    if cap_hit.is_set() and rc != 124:
        return 125, out, b"output cap exceeded"
    if rc == 124:
        return 124, out, b"timeout"
    return rc, out, err


def _unrar_p(
    archive: Path,
    *,
    password: str | None = None,
    member: str | None = None,
    ver: bool = False,
) -> tuple[int, bytes]:
    cmd = ["unrar", "p", "-inul"]
    if ver:
        cmd.append("-ver")
    cmd.append(f"-p{password}" if password else "-p-")
    if member is not None:
        cmd.append("-n./" + member)
    cmd.append(str(archive))
    rc, out, _err = _run(cmd)
    return rc, out


def _gold(
    archive: Path,
    *,
    password: str | None = None,
    member: str | None = None,
    ver: bool = False,
) -> bytes | None:
    """Return gold stdout, or None when unrar itself failed (never match against that)."""
    rc, out = _unrar_p(archive, password=password, member=member, ver=ver)
    return out if rc == 0 else None


def _unar(
    archive: Path, *members: str, password: str | None = None
) -> tuple[int, bytes, bytes]:
    cmd = ["unar", "-o", "-", "-q", "-D"]
    if password is not None:
        cmd.extend(["-p", password])
    cmd.append(str(archive))
    cmd.extend(members)
    return _run(cmd)


def _seven(
    archive: Path, *members: str, password: str | None = None
) -> tuple[int, bytes, bytes]:
    cmd = [
        "7z",
        "e",
        "-so",
        "-bb0",
        "-bd",
        "-p" + (password or ""),
        "-spd",
        "--",
        str(archive),
        *members,
    ]
    return _run(cmd)


def _row(
    case: str, tool: str, rc: int, out: bytes, gold: bytes | None, note: str = ""
) -> dict:
    return {
        "case": case,
        "tool": tool,
        "rc": rc,
        "rc_label": _sig(rc),
        "out_len": len(out),
        "gold_len": None if gold is None else len(gold),
        "match": None if gold is None else out == gold,
        "note": note,
    }


def _print(rows: list[dict]) -> None:
    print(f"{'case':36} {'tool':8} {'rc':10} {'len':6} {'gold':6} match  note")
    for r in rows:
        m = r["match"]
        ms = "—" if m is None else ("yes" if m else "NO")
        g = "—" if r["gold_len"] is None else str(r["gold_len"])
        print(
            f"{r['case']:36} {r['tool']:8} {r['rc_label']:10} "
            f"{r['out_len']!s:6} {g:6} {ms:5} {r['note']}"
        )


def _tail(err: bytes) -> str:
    if not err:
        return ""
    return err.decode("utf-8", "replace").strip().split("\n")[-1][:70]


def collect() -> list[dict]:
    rows: list[dict] = []
    have = {
        n: shutil.which(n) is not None
        for n in ("unrar", "unar", "7z", "bsdtar", "unrar-free")
    }
    print("tools:", ", ".join(f"{k}={'yes' if v else 'no'}" for k, v in have.items()))
    if not have["unrar"]:
        print("RARLAB unrar missing; cannot build gold.", file=sys.stderr)
        return rows

    codec_rar5 = False
    if have["7z"]:
        _rc, out, err = _run(["7z", "i"])
        text = (out + err).decode("utf-8", "replace")
        in_codecs = False
        for line in text.splitlines():
            if line.startswith("Codecs:"):
                in_codecs = True
                continue
            # 7z i order is Libs → Formats → Codecs → Hashers. Formats never
            # follows Codecs; Hashers does.
            if in_codecs and line.startswith("Hashers:"):
                break
            if in_codecs and "Rar5" in line.split():
                codec_rar5 = True
        banner = next((ln for ln in text.splitlines() if ln.startswith("7-Zip")), "")
        rows.append(
            _row(
                "7z_codec_rar5",
                "7z",
                0 if codec_rar5 else 1,
                b"",
                None,
                f"{banner}; Codecs Rar5={codec_rar5}",
            )
        )

    if have["unrar-free"]:
        _rc, out, err = _run(["unrar-free", "--help"])
        help_txt = (out + err).decode("utf-8", "replace").lower()
        rows.append(
            _row(
                "unrar-free:stdout?",
                "unrar-free",
                _rc,
                b"",
                None,
                "stdout in --help"
                if "stdout" in help_txt
                else "extract-only (no stdout)",
            )
        )

    archives = {
        "nonsolid": FIX / "basic_nonsolid__.rar",
        "solid5+empty": FIX / "basic_solid__.rar",
        "solid4+empty": FIX / "basic_solid__rar4.rar",
        "filever": FIX / "file_version__.rar",
        "hardlinks_s": FIX / "hardlinks_solid__.rar",
        "vol": FIX / "tinyvol.part1.rar",
        "hostile": FIX / "hostile_argv__.rar",
        "enc": FIX / "encryption__.rar",
    }

    plaintext = (
        "nonsolid",
        "solid5+empty",
        "solid4+empty",
        "filever",
        "hardlinks_s",
        "vol",
        "hostile",
    )
    for key in plaintext:
        path = archives[key]
        gold = _gold(path)
        gold_ver = _gold(path, ver=True)
        probes: list[tuple[str, tuple[int, bytes, bytes]]] = []
        if have["unar"]:
            probes.append(("unar", _unar(path)))
        if have["7z"]:
            probes.append(("7z", _seven(path)))
        if have["bsdtar"]:
            probes.append(
                ("bsdtar", _run(["bsdtar", "-x", "--to-stdout", "-f", str(path)]))
            )
        for tool, (rc, out, err) in probes:
            note = ""
            if gold is None:
                note = "gold failed"
            elif gold_ver is not None and out == gold_ver and out != gold:
                note = "matches unrar -ver"
            elif rc == 125:
                note = "output cap exceeded"
            elif rc:
                note = _tail(err)
            rows.append(_row(f"all:{key}", tool, rc, out, gold, note))

    path = archives["enc"]
    gold = _gold(path, password="password")
    if have["unar"]:
        rc, out, err = _unar(path, password="password")
        rows.append(_row("pwd_ok:enc", "unar", rc, out, gold, _tail(err)))
        rc, out, err = _unar(path, password="wrong")
        # Do not gold b"" — every failure (including crash) would match=yes.
        rows.append(
            _row(
                "pwd_wrong:enc",
                "unar",
                rc,
                out,
                None,
                f"empty={out == b''} rc={_sig(rc)}",
            )
        )
    if have["7z"]:
        rc, out, err = _seven(path, password="password")
        rows.append(_row("pwd_ok:enc", "7z", rc, out, gold, _tail(err)))
        rc, out, err = _seven(path, password="wrong")
        low = (err + out).decode("utf-8", "replace").lower()
        if not codec_rar5:
            note = "n/a: no Rar5 codec; " + _tail(err)
        elif "wrong password" in low:
            note = "wrong-password"
        else:
            note = _tail(err)
        rows.append(_row("pwd_wrong:enc", "7z", rc, out, None, note))

    path = archives["nonsolid"]
    for member in ("file1.txt", "subdir/file2.txt"):
        gold = _gold(path, member=member)
        if have["7z"]:
            rc, out, err = _seven(path, member)
            rows.append(_row(f"named:{member}", "7z", rc, out, gold))
        if have["unar"]:
            rc, out, err = _unar(path, member)
            rows.append(_row(f"named:{member}", "unar", rc, out, gold))

    path = archives["solid5+empty"]
    gold = _gold(path)
    if have["unar"]:
        rc, out, err = _unar(path, "file1.txt")
        rows.append(_row("solid_skip_empty", "unar", rc, out, gold, "file1 only"))
        with tempfile.TemporaryDirectory() as td:
            rc, _o, err = _run(["unar", "-q", "-D", "-o", td, str(path)])
            files = {
                p.relative_to(td).as_posix(): p.stat().st_size
                for p in Path(td).rglob("*")
                if p.is_file()
            }
            rows.append(
                _row(
                    "unar_disk:solid5+empty",
                    "unar",
                    rc,
                    b"",
                    None,
                    f"files={files}",
                )
            )
    if have["7z"]:
        rc, out, err = _seven(
            path, "file1.txt", "subdir/file2.txt", "implicit_subdir/file3.txt"
        )
        rows.append(_row("solid_skip_empty", "7z", rc, out, gold, "non-empty names"))
        gold_last = _gold(path, member="implicit_subdir/file3.txt")
        rc, out, err = _seven(path, "implicit_subdir/file3.txt")
        rows.append(_row("solid_named:last", "7z", rc, out, gold_last))

    path = archives["hostile"]
    for name in ("canary.txt", "-inul", "@atfile"):
        gold = _gold(path, member=name)
        if have["7z"]:
            rc, out, err = _seven(path, name)
            rows.append(_row(f"hostile:{name}", "7z", rc, out, gold, _tail(err)))
        if have["unar"]:
            rc, out, err = _unar(path, name)
            rows.append(
                _row(f"hostile:{name}", "unar", rc, out, gold, _tail(out + err))
            )

    return rows


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--json", type=Path, help="Write the row list as JSON")
    args = parser.parse_args()
    os.chdir(REPO)
    rows = collect()
    print()
    _print(rows)
    mismatches = [r for r in rows if r["match"] is False]
    print(f"\n{len(rows)} rows, {len(mismatches)} mismatches vs unrar gold")
    if args.json:
        args.json.parent.mkdir(parents=True, exist_ok=True)
        args.json.write_text(json.dumps(rows, indent=2) + "\n", encoding="utf-8")
        print(f"wrote {args.json}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
