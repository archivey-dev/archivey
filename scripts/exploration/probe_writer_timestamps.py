"""Record which file time each archiver stores in its "creation time" slots.

ZIP's NTFS extra field (0x000A), 7z's CTime property and libarchive's PAX
``LIBARCHIVE.creationtime`` are documented as a creation (birth) time, but a Unix
writer has no portable birth time and may store st_ctime (inode change time) there
instead. archivey's ``Member.created`` must hold a birth time or nothing, so the
readers need to know which writers do what. This script measures it on whatever OS
it runs on; the CI workflow
``.github/workflows/writer-timestamps.yml`` runs it on Linux, macOS and Windows.
Results and conclusions: ``dev-docs/investigations/writer-timestamp-slots.md``.

Method: create ``f.txt``, wait, set its mtime/atime to fixed 2033/2034 values, wait,
then chmod it. On Unix that leaves four distinct source times: birth (creation),
ctime (the chmod, seconds after birth), mtime and atime. Windows has no inode
change time, so only three. Each writer that is
installed archives the file; the script then parses the raw time fields out of every
archive and labels each stored time with the source time it matches.

Usage: ``python scripts/exploration/probe_writer_timestamps.py [--out DIR] [--json FILE]``.
Needs archivey importable (for the 7z header parser) and nothing else; writers that
are not installed are reported as skipped.
"""

from __future__ import annotations

import argparse
import datetime as dt
import json
import os
import platform
import shutil
import stat
import struct
import subprocess
import sys
import tempfile
import time
import zipfile
from pathlib import Path

_GAP_SECONDS = 4
# Both in the future, on purpose. APFS moves the birth time back to any earlier
# mtime that utime sets, which would make birth and mtime indistinguishable. And
# Linux relatime refreshes an atime that is not newer than mtime on every read, so
# atime goes after mtime and stays where the probe put it.
_MTIME = dt.datetime(2033, 2, 3, 4, 5, 6, tzinfo=dt.UTC).timestamp()
_ATIME = dt.datetime(2034, 3, 4, 5, 6, 7, tzinfo=dt.UTC).timestamp()
_FILETIME_EPOCH_OFFSET = 116444736000000000  # 100 ns ticks from 1601 to 1970


# --------------------------------------------------------------------------- source


def _birth_time(path: Path, st: os.stat_result) -> float | None:
    birth = getattr(st, "st_birthtime", None)
    if birth:
        return float(birth)
    if sys.platform.startswith("linux"):
        out = subprocess.run(
            ["stat", "-c", "%W", str(path)], capture_output=True, text=True, check=False
        ).stdout.strip()
        if out and out not in {"0", "-", "?"}:
            return float(out)
    return None


def make_source(root: Path) -> dict[str, float | None]:
    payload = root / "payload"
    payload.mkdir()
    target = payload / "f.txt"
    target.write_bytes(b"archivey writer timestamp probe\n")
    time.sleep(_GAP_SECONDS)
    os.utime(target, (_ATIME, _MTIME))
    time.sleep(_GAP_SECONDS)
    os.chmod(target, stat.S_IRUSR | stat.S_IWUSR | stat.S_IRGRP)
    time.sleep(_GAP_SECONDS)
    st = target.stat()
    times: dict[str, float | None] = {
        "birth": _birth_time(target, st),
        "mtime": st.st_mtime,
        "atime": st.st_atime,
    }
    # On Windows, st_ctime was the creation time before 3.12 and is deprecated since;
    # there is no inode change time to compare against.
    times["ctime"] = None if os.name == "nt" else st.st_ctime
    return times


def label(ts: float | None, source: dict[str, float | None]) -> str:
    if ts is None:
        return "-"
    hits = [
        name
        for name, value in source.items()
        if value is not None and abs(value - ts) <= 1.0
    ]
    when = dt.datetime.fromtimestamp(ts, dt.UTC).strftime("%Y-%m-%d %H:%M:%S")
    return f"{when} ({'/'.join(hits) if hits else 'no match'})"


# --------------------------------------------------------------------------- writers


def _which(*names: str) -> str | None:
    for name in names:
        found = shutil.which(name)
        if found:
            return found
    return None


def writers(payload: Path) -> list[tuple[str, str, list[str] | None, Path]]:
    """(label, kind, argv or None if unavailable, cwd). Output path is appended."""
    out: list[tuple[str, str, list[str] | None, Path]] = []
    sevens = []
    for binary in ("7zz", "7z", "7za"):
        path = _which(binary)
        if path and path not in [p for _, p in sevens]:
            sevens.append((binary, path))
    if os.name == "nt":
        default = Path(r"C:\Program Files\7-Zip\7z.exe")
        if default.exists() and str(default) not in [p for _, p in sevens]:
            sevens.append(("7z.exe", str(default)))
    for name, path in sevens:
        for variant, flags in (
            ("default", []),
            ("-mtc=on -mta=on", ["-mtc=on", "-mta=on"]),
        ):
            out.append(
                (f"{name} zip {variant}", "zip", [path, "a", "-tzip", *flags], payload)
            )
            out.append(
                (f"{name} 7z {variant}", "7z", [path, "a", "-t7z", *flags], payload)
            )
    if not sevens:
        out.append(("7-Zip", "zip", None, payload))

    info_zip = _which("zip")
    out.append(("Info-ZIP zip", "zip", [info_zip, "-q"] if info_zip else None, payload))

    bsdtar = _which("bsdtar")
    if bsdtar is None and sys.platform == "darwin":
        bsdtar = "/usr/bin/tar"
    if os.name == "nt":
        system_tar = (
            Path(os.environ.get("SystemRoot", r"C:\Windows")) / "System32" / "tar.exe"
        )
        bsdtar = str(system_tar) if system_tar.exists() else None
    for fmt in ("zip", "7zip", "pax"):
        kind = {"7zip": "7z", "pax": "tar"}.get(fmt, "zip")
        argv = [bsdtar, "--format", fmt, "-cf"] if bsdtar else None
        out.append((f"bsdtar/libarchive {fmt}", kind, argv, payload))

    # GNU tar (Linux, and gtar where installed) writes PAX atime/ctime with
    # --format=pax, never a birth time.
    gnu_tar = _which("gtar") or (
        _which("tar") if sys.platform.startswith("linux") else None
    )
    out.append(
        (
            "GNU tar --format=pax",
            "tar",
            [gnu_tar, "--format=pax", "-cf"] if gnu_tar else None,
            payload,
        )
    )

    if sys.platform == "darwin":
        out.append(
            ("ditto -c -k (Finder Compress)", "zip", ["ditto", "-c", "-k"], payload)
        )
    if os.name == "nt":
        for shell in ("powershell", "pwsh"):
            exe = _which(shell)
            out.append(
                (f"Compress-Archive ({shell})", "zip", [exe] if exe else None, payload)
            )
        exe = _which("powershell")
        out.append(
            (
                "Explorer Shell.Application CopyHere",
                "zip",
                [exe] if exe else None,
                payload,
            )
        )
    return out


def run_writer(name: str, argv: list[str], cwd: Path, dest: Path) -> str | None:
    """Return an error string, or None on success."""
    member = "f.txt"
    if name.startswith("ditto"):
        cmd = [*argv, member, str(dest)]
    elif name.startswith("Compress-Archive"):
        cmd = [
            argv[0], "-NoProfile", "-Command",
            f"Compress-Archive -Path '{cwd / member}' -DestinationPath '{dest}'",
        ]  # fmt: skip
    elif name.startswith("Explorer"):
        # An empty ZIP (22-byte EOCD) that the shell namespace then fills. CopyHere is
        # asynchronous, so poll until the item shows up and the file stops growing.
        script = f"""
$zip = '{dest}'
[IO.File]::WriteAllBytes($zip, [byte[]](80,75,5,6 + (,0 * 18)))
$shell = New-Object -ComObject Shell.Application
$shell.NameSpace($zip).CopyHere('{cwd / member}', 0x14)
for ($i = 0; $i -lt 60; $i++) {{
  Start-Sleep -Milliseconds 500
  if ($shell.NameSpace($zip).Items().Count -ge 1) {{ Start-Sleep 2; break }}
}}
"""
        cmd = [argv[0], "-NoProfile", "-Command", script]
    else:
        cmd = [*argv, str(dest), member]
    proc = subprocess.run(cmd, cwd=cwd, capture_output=True, text=True, check=False)
    if proc.returncode != 0 or not dest.exists():
        return f"exit {proc.returncode}: {(proc.stderr or proc.stdout).strip()[:300]}"
    return None


# --------------------------------------------------------------------------- ZIP


def _filetime(ticks: int) -> float | None:
    if ticks == 0:
        return None
    return (ticks - _FILETIME_EPOCH_OFFSET) / 10_000_000


def _extras(blob: bytes) -> list[tuple[int, bytes]]:
    fields = []
    pos = 0
    while pos + 4 <= len(blob):
        tag, size = struct.unpack_from("<HH", blob, pos)
        fields.append((tag, blob[pos + 4 : pos + 4 + size]))
        pos += 4 + size
    return fields


def _decode_extras(blob: bytes) -> dict[str, float | None | str]:
    found: dict[str, float | None | str] = {}
    for tag, data in _extras(blob):
        if tag == 0x000A and len(data) >= 4:
            pos = 4
            while pos + 4 <= len(data):
                attr_tag, attr_size = struct.unpack_from("<HH", data, pos)
                body = data[pos + 4 : pos + 4 + attr_size]
                if attr_tag == 1 and len(body) >= 24:
                    m, a, c = struct.unpack_from("<QQQ", body)
                    found["ntfs.mtime"] = _filetime(m)
                    found["ntfs.atime"] = _filetime(a)
                    found["ntfs.ctime"] = _filetime(c)
                pos += 4 + attr_size
        elif tag == 0x5455 and data:
            flags = data[0]
            found["ut.flags"] = f"0x{flags:02x}"
            pos = 1
            for bit, key in ((1, "ut.mtime"), (2, "ut.atime"), (4, "ut.ctime")):
                if flags & bit and pos + 4 <= len(data):
                    found[key] = float(struct.unpack_from("<i", data, pos)[0])
                    pos += 4
        elif tag == 0x5855 and len(data) >= 8:
            a, m = struct.unpack_from("<II", data)
            found["ux-old.atime"] = float(a)
            found["ux-old.mtime"] = float(m)
        else:
            found.setdefault("other extras", "")
            found["other extras"] = f"{found['other extras']} 0x{tag:04x}".strip()
    return found


def inspect_zip(path: Path) -> dict[str, object]:
    with zipfile.ZipFile(path) as zf:
        info = next(
            i for i in zf.infolist() if i.filename.rstrip("/").endswith("f.txt")
        )
        raw = path.read_bytes()
    offset = info.header_offset
    name_len, extra_len = struct.unpack_from("<HH", raw, offset + 26)
    local_extra = raw[offset + 30 + name_len : offset + 30 + name_len + extra_len]
    return {
        "member": info.filename,
        "create_system": info.create_system,
        "create_version": info.create_version,
        "external_attr": f"0x{info.external_attr:08x}",
        "dos_time": dt.datetime(*info.date_time).strftime("%Y-%m-%d %H:%M:%S"),
        "central": _decode_extras(info.extra),
        "local": _decode_extras(local_extra),
    }


# --------------------------------------------------------------------------- TAR


def inspect_tar(path: Path) -> dict[str, object]:
    import tarfile

    with tarfile.open(path) as tf:
        info = next(m for m in tf.getmembers() if m.name.endswith("f.txt"))
    fields: dict[str, object] = {"member": info.name, "mtime": float(info.mtime)}
    for key, value in sorted(info.pax_headers.items()):
        if "time" in key.lower():
            try:
                fields[f"pax {key}"] = float(value)
            except ValueError:
                fields[f"pax {key}"] = value
    return fields


# --------------------------------------------------------------------------- 7z


def inspect_7z(path: Path) -> dict[str, object]:
    import archivey

    with archivey.open_archive(path) as reader:
        record = next(r for r in reader._archive.files if r.filename.endswith("f.txt"))
    attrs = record.attributes
    return {
        "member": record.filename,
        "attributes": None if attrs is None else f"0x{attrs:08x}",
        "unix_mode": None if attrs is None or not attrs & 0x8000 else oct(attrs >> 16),
        "CTime": None
        if record.creation_time is None
        else _filetime(record.creation_time),
        "ATime": None
        if record.last_access_time is None
        else _filetime(record.last_access_time),
        "MTime": None
        if record.last_write_time is None
        else _filetime(record.last_write_time),
    }


def archivey_view(path: Path) -> dict[str, str]:
    import archivey

    try:
        with archivey.open_archive(path) as reader:
            member = next(m for m in reader.members() if m.name.endswith("f.txt"))
            return {"created": str(member.created), "ctime": str(member.ctime)}
    except Exception as exc:  # noqa: BLE001 - report, never abort the probe
        return {"error": f"{type(exc).__name__}: {exc}"}


# --------------------------------------------------------------------------- report


def _render(value: object, source: dict[str, float | None]) -> str:
    if isinstance(value, float):
        return label(value, source)
    return str(value)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--out", type=Path, help="keep the archives in this directory")
    parser.add_argument("--json", type=Path, help="also write raw results as JSON")
    args = parser.parse_args()

    root = Path(tempfile.mkdtemp(prefix="archivey-ts-probe-"))
    source = make_source(root)
    payload = root / "payload"
    out_dir = (args.out or root / "out").resolve()
    out_dir.mkdir(parents=True, exist_ok=True)

    host = f"{platform.system()} {platform.release()} ({platform.machine()})"
    print(f"# Writer timestamp probe on {host}\n")
    print("Source file f.txt:")
    for key, value in source.items():
        when = "-" if value is None else label(value, {key: value})
        print(f"- {key}: {when}")
    print()

    results = {"host": host, "source": source, "writers": []}
    for index, (name, kind, argv, cwd) in enumerate(writers(payload)):
        print(f"## {name}")
        entry: dict[str, object] = {"writer": name, "kind": kind}
        if argv is None or argv[0] is None:
            print("skipped: not installed\n")
            entry["skipped"] = "not installed"
            results["writers"].append(entry)
            continue
        dest = out_dir / f"{index:02d}.{kind}"
        error = run_writer(name, argv, cwd, dest)
        if error:
            print(f"failed: {error}\n")
            entry["failed"] = error
            results["writers"].append(entry)
            continue
        if name.startswith(("7z", "7za", "7zz")):
            version = (
                subprocess.run([argv[0]], capture_output=True, text=True, check=False)
                .stdout.strip()
                .splitlines()
            )
            entry["version"] = next((v for v in version if "7-Zip" in v), "")
            print(f"version: {entry['version']}")
        try:
            inspect = {"zip": inspect_zip, "7z": inspect_7z, "tar": inspect_tar}[kind]
            fields = inspect(dest)
        except Exception as exc:  # noqa: BLE001 - report, never abort the probe
            fields = {"parse error": f"{type(exc).__name__}: {exc}"}
        entry["fields"] = fields
        entry["archivey"] = archivey_view(dest)
        for key, value in fields.items():
            if isinstance(value, dict):
                for sub, subval in value.items():
                    print(f"- {key} {sub}: {_render(subval, source)}")
            else:
                print(f"- {key}: {_render(value, source)}")
        print(f"- archivey reads: {entry['archivey']}\n")
        results["writers"].append(entry)

    if args.json:
        args.json.write_text(json.dumps(results, indent=2, default=str))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
