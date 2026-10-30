"""Does ``unrar`` read a synthetic RAR built from one member's headers and data?

Supporting ``openspec/changes/rar-synthetic-archives``. Instead of handing ``unrar``
the original archive and a ``-n`` include mask, archivey would write a small RAR
holding only what the read needs: a signature, a made-up MAIN header, the member's
own FILE header (patched), its packed bytes copied verbatim, and an ENDARC header.
This script checks that ``unrar`` accepts every shape the design relies on, and
times the read against today's masked read of the original.

Two parts:

1. **Correctness matrix.** For RAR4 (``rar -ma4``) and RAR5, plain, ``-p`` and
   ``-hp``: one nonsolid member, the same with its name replaced, the chain of a
   solid group, a split member as a synthetic volume set, and a split member
   joined into one volume. Each row compares ``unrar p`` output with the source
   file bytes.
2. **Timing.** Opening the last member of a nonsolid archive of many small files,
   by mask on the original versus a synthetic archive (build + write + ``unrar``),
   and the same for the last member of a grouped solid archive (``rar -s<N>``).

Needs RARLAB ``rar`` and ``unrar`` on PATH, and runs inside the repo venv because
header decryption reuses archivey's KDF helpers (``-hp`` rows need
``cryptography``):

    uv run python scripts/exploration/rar_synthetic_probe.py
    uv run python scripts/exploration/rar_synthetic_probe.py --files 5000 --json /tmp/s.json
"""

from __future__ import annotations

import argparse
import functools
import json
import os
import random
import shutil
import statistics
import struct
import subprocess
import sys
import tempfile
import time
import zlib
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path

from archivey.internal.backends.rar_parser import _rar3_s2k, _rar5_s2k, load_vint

TIMEOUT = 120
PASSWORD = "synthetic-pw"
RAR5_SIG = b"Rar!\x1a\x07\x01\x00"
RAR4_SIG = b"Rar!\x1a\x07\x00"


# --------------------------------------------------------------------------- walk


@dataclass
class Block:
    """One header as plaintext bytes, plus where its data area sits in the file."""

    kind: int
    flags: int
    raw: bytes  # plaintext header: RAR5 from CRC32 on, RAR4 from HEAD_CRC on
    data_offset: int
    data_size: int
    name: bytes = b""
    split_before: bool = False
    split_after: bool = False
    solid: bool = False
    # RAR5: offset of the name-length vint inside ``raw``; RAR4: of the name.
    name_at: int = 0
    extra: dict[str, int] = field(default_factory=dict)


def _vint(value: int) -> bytes:
    out = bytearray()
    while True:
        byte = value & 0x7F
        value >>= 7
        if value:
            out.append(byte | 0x80)
        else:
            out.append(byte)
            return bytes(out)


def _aes_cbc_decrypt(key: bytes, iv: bytes, data: bytes) -> bytes:
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

    dec = Cipher(algorithms.AES(key), modes.CBC(iv)).decryptor()
    return dec.update(data) + dec.finalize()


def walk_rar5(data: bytes, password: str | None) -> list[Block]:
    assert data.startswith(RAR5_SIG), "probe archives have no SFX stub"
    pos = len(RAR5_SIG)
    key: bytes | None = None
    blocks: list[Block] = []
    while pos < len(data):
        if key is not None:
            iv = data[pos : pos + 16]
            first = _aes_cbc_decrypt(key, iv, data[pos + 16 : pos + 32])
            size, p = load_vint(first, 4)
            total = p + size
            padded = -(-total // 16) * 16
            raw = _aes_cbc_decrypt(key, iv, data[pos + 16 : pos + 16 + padded])[:total]
            pos += 16 + padded
        else:
            size, p = load_vint(data, pos + 4)
            raw = data[pos : p + size]
            pos = p + size
        assert zlib.crc32(raw[4:]) == struct.unpack_from("<I", raw)[0], "header CRC"
        _, q = load_vint(raw, 4)
        kind, q = load_vint(raw, q)
        hflags, q = load_vint(raw, q)
        if hflags & 1:
            _, q = load_vint(raw, q)
        data_size = 0
        if hflags & 2:
            data_size, q = load_vint(raw, q)
        block = Block(kind, hflags, raw, pos, data_size)
        if kind == 4:  # CRYPT: version, flags, kdf count, salt
            _, q = load_vint(raw, q)
            _, q = load_vint(raw, q)
            count = raw[q]
            salt = raw[q + 1 : q + 17]
            assert password is not None
            key = _rar5_s2k(password, salt, 1 << count)
        elif kind in (2, 3):
            fflags, q = load_vint(raw, q)
            _, q = load_vint(raw, q)  # unpacked size
            _, q = load_vint(raw, q)  # attributes
            if fflags & 2:
                q += 4
            if fflags & 4:
                q += 4
            comp, q = load_vint(raw, q)
            _, q = load_vint(raw, q)  # host os
            block.name_at = q
            nlen, q = load_vint(raw, q)
            block.name = raw[q : q + nlen]
            block.solid = bool(comp & 0x40)
            block.split_before = bool(hflags & 0x08)
            block.split_after = bool(hflags & 0x10)
        blocks.append(block)
        pos += data_size
        if kind == 5:
            break
    return blocks


_RAR3_KEYS: dict[bytes, tuple[bytes, bytes]] = {}


def walk_rar4(data: bytes, password: str | None) -> list[Block]:
    assert data.startswith(RAR4_SIG), "probe archives have no SFX stub"
    pos = len(RAR4_SIG)
    encrypted = False
    blocks: list[Block] = []
    while pos + 7 <= len(data):
        if encrypted:
            assert password is not None
            salt = data[pos : pos + 8]
            if salt not in _RAR3_KEYS:
                _RAR3_KEYS[salt] = _rar3_s2k(password, salt)
            key, iv = _RAR3_KEYS[salt]
            first = _aes_cbc_decrypt(key, iv, data[pos + 8 : pos + 24])
            size = struct.unpack_from("<H", first, 5)[0]
            padded = -(-size // 16) * 16
            raw = _aes_cbc_decrypt(key, iv, data[pos + 8 : pos + 8 + padded])[:size]
            pos += 8 + padded
        else:
            size = struct.unpack_from("<H", data, pos + 5)[0]
            raw = data[pos : pos + size]
            pos += size
        crc, kind, flags, _ = struct.unpack_from("<HBHH", raw)
        data_size = 0
        if kind == 0x74 or flags & 0x8000:
            data_size = struct.unpack_from("<I", raw, 7)[0]
            if kind == 0x74 and flags & 0x100:
                data_size |= struct.unpack_from("<I", raw, 32)[0] << 32
        block = Block(kind, flags, raw, pos, data_size)
        if kind == 0x73:
            encrypted = bool(flags & 0x80)
        elif kind == 0x74:
            assert zlib.crc32(raw[2:]) & 0xFFFF == crc, "header CRC"
            nsize = struct.unpack_from("<H", raw, 26)[0]
            at = 32 + (8 if flags & 0x100 else 0)
            block.name_at = at
            block.name = raw[at : at + nsize]
            block.solid = bool(flags & 0x10)
            block.split_before = bool(flags & 0x01)
            block.split_after = bool(flags & 0x02)
        blocks.append(block)
        pos += data_size
        if kind == 0x7B:
            break
    return blocks


def walk(path: Path, version: int, password: str | None) -> list[Block]:
    data = path.read_bytes()
    return walk_rar5(data, password) if version == 5 else walk_rar4(data, password)


# ---------------------------------------------------------------------- synthesis


def rar5_block(body: bytes) -> bytes:
    """CRC32 + header-size vint + ``body`` (body starts at the header type)."""
    sized = _vint(len(body)) + body
    return struct.pack("<I", zlib.crc32(sized)) + sized


def rar5_main(*, solid: bool = False, volume: int | None = None) -> bytes:
    aflags = (4 if solid else 0) | (1 if volume is not None else 0)
    tail = b""
    if volume is not None and volume > 0:
        aflags |= 2
        tail = _vint(volume)
    return rar5_block(_vint(1) + _vint(0) + _vint(aflags) + tail)


def rar5_end(*, more_volumes: bool = False) -> bytes:
    return rar5_block(_vint(5) + _vint(0) + _vint(1 if more_volumes else 0))


def rar5_patch_file(
    block: Block,
    *,
    name: bytes | None = None,
    clear_split: bool = False,
    data_size: int | None = None,
) -> bytes:
    """Re-emit a RAR5 FILE header with a new name, split flags or data size."""
    raw = block.raw
    _, q = load_vint(raw, 4)
    kind, q = load_vint(raw, q)
    hflags, q = load_vint(raw, q)
    extra_size = None
    if hflags & 1:
        extra_size, q = load_vint(raw, q)
    old_data_size = 0
    if hflags & 2:
        old_data_size, q = load_vint(raw, q)
    fields_at = q
    nlen, q = load_vint(raw, block.name_at)
    name_end = q + nlen
    new_flags = hflags & ~0x18 if clear_split else hflags
    head = _vint(kind) + _vint(new_flags)
    if extra_size is not None:
        head += _vint(extra_size)
    if hflags & 2:
        head += _vint(old_data_size if data_size is None else data_size)
    use_name = block.name if name is None else name
    body = (
        head
        + raw[fields_at : block.name_at]
        + _vint(len(use_name))
        + use_name
        + raw[name_end:]
    )
    return rar5_block(body)


def rar4_block(kind: int, flags: int, rest: bytes) -> bytes:
    size = 7 + len(rest)
    body = struct.pack("<BHH", kind, flags, size) + rest
    return struct.pack("<H", zlib.crc32(body) & 0xFFFF) + body


def rar4_main(*, solid: bool = False, volume: int | None = None) -> bytes:
    flags = 0x08 if solid else 0
    if volume is not None:
        flags |= 0x0001 | 0x0010 | (0x0100 if volume == 0 else 0)
    return rar4_block(0x73, flags, b"\x00" * 6)


def rar4_end(*, more_volumes: bool = False, volume: int | None = None) -> bytes:
    if volume is None:
        return rar4_block(0x7B, 0x4000, b"")
    flags = 0x4000 | 0x0008 | (0x0001 if more_volumes else 0)
    return rar4_block(0x7B, flags, struct.pack("<IH", 0, volume))


def rar4_patch_file(
    block: Block,
    *,
    name: bytes | None = None,
    clear_split: bool = False,
    data_size: int | None = None,
) -> bytes:
    raw = bytearray(block.raw)
    flags = struct.unpack_from("<H", raw, 3)[0]
    if clear_split:
        flags &= ~0x03
    if data_size is not None:
        struct.pack_into("<I", raw, 7, data_size & 0xFFFFFFFF)
        if flags & 0x100:
            struct.pack_into("<I", raw, 32, data_size >> 32)
        else:
            assert data_size < 1 << 32
    nsize = len(block.name)
    tail = bytes(raw[block.name_at + nsize :])
    use_name = block.name if name is None else name
    if name is not None:
        flags &= ~0x200  # plain 8-bit name, no Unicode part
    struct.pack_into("<H", raw, 26, len(use_name))
    rest = bytes(raw[7 : block.name_at]) + use_name + tail
    return rar4_block(0x74, flags, rest)


@dataclass
class Synth:
    version: int

    def sig(self) -> bytes:
        return RAR5_SIG if self.version == 5 else RAR4_SIG

    def main(self, **kw: object) -> bytes:
        return rar5_main(**kw) if self.version == 5 else rar4_main(**kw)  # type: ignore[arg-type]

    def end(self, **kw: object) -> bytes:
        if self.version == 5:
            kw.pop("volume", None)
            return rar5_end(**kw)  # type: ignore[arg-type]
        return rar4_end(**kw)  # type: ignore[arg-type]

    def patch(self, block: Block, **kw: object) -> bytes:
        if self.version == 5:
            return rar5_patch_file(block, **kw)  # type: ignore[arg-type]
        return rar4_patch_file(block, **kw)  # type: ignore[arg-type]

    def is_file(self, block: Block) -> bool:
        return block.kind == (2 if self.version == 5 else 0x74)


def build_single(
    src: bytes, synth: Synth, chain: list[Block], *, rename: bool, solid: bool
) -> bytes:
    """Signature, MAIN, the chain's FILE headers and data, ENDARC."""
    out = bytearray(synth.sig() + synth.main(solid=solid))
    for i, block in enumerate(chain):
        name = f"m{i}".encode() if rename else None
        out += synth.patch(block, name=name)
        out += src[block.data_offset : block.data_offset + block.data_size]
    out += synth.end()
    return bytes(out)


# -------------------------------------------------------------------------- runs


def run_unrar(
    archive: Path, *, password: str | None, mask: str | None = None
) -> tuple[int, bytes, float]:
    argv = ["unrar", "p", "-inul", "-cfg-", f"-p{password}" if password else "-p-"]
    if mask is not None:
        argv.append(f"-n./{mask}")
    argv += ["--", str(archive)]
    t0 = time.perf_counter()
    proc = subprocess.run(
        argv,
        check=False,
        stdin=subprocess.DEVNULL,
        capture_output=True,
        timeout=TIMEOUT,
    )
    return proc.returncode, proc.stdout, time.perf_counter() - t0


def make_tree(root: Path, count: int, size: int, seed: int) -> list[Path]:
    rng = random.Random(seed)
    words = [bytes(rng.choice(b"abcdefghij ") for _ in range(8)) for _ in range(64)]
    paths = []
    for i in range(count):
        p = root / f"d{i % 7}" / f"file-{i:05d}.txt"
        p.parent.mkdir(parents=True, exist_ok=True)
        body = b"".join(rng.choice(words) for _ in range(size // 8))[:size]
        p.write_bytes(body + str(i).encode())
        paths.append(p)
    return paths


RAR4_WRITER = ["rar"]


def rar(args: list[str], cwd: Path) -> None:
    binary = RAR4_WRITER[0] if "-ma4" in args else "rar"
    args = [a for a in args if a != "-ma4" or binary != "rar"]
    subprocess.run(
        [binary, "a", "-idq", "-ep1", *args],
        cwd=cwd,
        check=True,
        stdin=subprocess.DEVNULL,
        timeout=TIMEOUT,
    )


def files_of(blocks: list[Block], synth: Synth) -> list[Block]:
    return [b for b in blocks if synth.is_file(b)]


def correctness(work: Path) -> list[dict[str, object]]:
    rows: list[dict[str, object]] = []
    tree = work / "tree"
    files = make_tree(tree, 12, 3000, seed=1)
    big = work / "big.bin"
    big.write_bytes(random.Random(2).randbytes(150_000))
    expected = {p.name: p.read_bytes() for p in [*files, big]}

    def record(case: str, rc: int, out: bytes, want: bytes) -> None:
        rows.append({"case": case, "rc": rc, "ok": rc == 0 and out == want})

    for version in (4, 5):
        synth = Synth(version)
        fmt = ["-ma4"] if version == 4 else ["-ma5"]
        for enc, enc_args, pw in (
            ("plain", [], None),
            ("-p", [f"-p{PASSWORD}"], PASSWORD),
            ("-hp", [f"-hp{PASSWORD}"], PASSWORD),
        ):
            tag = f"rar{version} {enc}"
            # One nonsolid member, name kept and name replaced.
            arc = work / f"ns{version}{enc}.rar"
            rar([*fmt, *enc_args, "-m3", str(arc), *map(str, files)], work)
            src = arc.read_bytes()
            fblocks = files_of(walk(arc, version, pw), synth)
            target = fblocks[-1]
            want = expected[os.path.basename(target.name.decode("latin-1"))]
            for rename in (False, True):
                syn = work / "s.rar"
                syn.write_bytes(
                    build_single(src, synth, [target], rename=rename, solid=False)
                )
                rc, out, _ = run_unrar(syn, password=pw)
                record(
                    f"{tag} nonsolid {'renamed' if rename else 'verbatim'}",
                    rc,
                    out,
                    want,
                )
            # Solid groups of 4: the chain from the group start to the target.
            arc = work / f"sg{version}{enc}.rar"
            rar([*fmt, *enc_args, "-m3", "-s4", str(arc), *map(str, files)], work)
            src = arc.read_bytes()
            fblocks = files_of(walk(arc, version, pw), synth)
            t = len(fblocks) - 2
            start = max(i for i in range(t + 1) if not fblocks[i].solid)
            chain = fblocks[start : t + 1]
            want = b"".join(
                expected[os.path.basename(b.name.decode("latin-1"))] for b in chain
            )
            syn = work / "s.rar"
            syn.write_bytes(build_single(src, synth, chain, rename=True, solid=True))
            rc, out, _ = run_unrar(syn, password=pw)
            record(
                f"{tag} solid group chain ({len(chain)} members, all emitted)",
                rc,
                out,
                want,
            )
            # Same chain, only the target emitted: mask on the replaced name.
            rc, out, _ = run_unrar(syn, password=pw, mask=f"m{len(chain) - 1}")
            record(
                f"{tag} solid group chain, target only by replaced name",
                rc,
                out,
                expected[os.path.basename(chain[-1].name.decode("latin-1"))],
            )
            # Split member: a three-volume set holding one large stored-ish file.
            voldir = work / f"v{version}{enc}"
            voldir.mkdir()
            rar(
                [*fmt, *enc_args, "-m1", "-v60k", str(voldir / "set.rar"), str(big)],
                work,
            )
            vols = sorted(voldir.iterdir(), key=lambda p: (len(p.name), p.name))
            parts: list[tuple[bytes, Block]] = []
            for vol in vols:
                vsrc = vol.read_bytes()
                parts += [(vsrc, b) for b in files_of(walk(vol, version, pw), synth)]
            # (a) synthetic volume set, one part per volume, headers verbatim.
            sdir = work / f"sv{version}{enc}"
            sdir.mkdir()
            for i, (vsrc, block) in enumerate(parts):
                last = i == len(parts) - 1
                name = sdir / f"x.part{i + 1}.rar"
                body = synth.sig() + synth.main(volume=i)
                body += synth.patch(block, name=b"m0")
                body += vsrc[block.data_offset : block.data_offset + block.data_size]
                body += synth.end(more_volumes=not last, volume=i)
                name.write_bytes(body)
            rc, out, _ = run_unrar(sdir / "x.part1.rar", password=pw)
            record(
                f"{tag} split member as synthetic volume set",
                rc,
                out,
                expected["big.bin"],
            )
            # (b) parts joined into one volume, last part's header, split flags cleared.
            joined = b"".join(
                v[b.data_offset : b.data_offset + b.data_size] for v, b in parts
            )
            last_block = parts[-1][1]
            body = synth.sig() + synth.main()
            body += synth.patch(
                last_block, name=b"m0", clear_split=True, data_size=len(joined)
            )
            body += joined + synth.end()
            syn = work / "j.rar"
            syn.write_bytes(body)
            rc, out, _ = run_unrar(syn, password=pw)
            record(
                f"{tag} split member joined into one volume",
                rc,
                out,
                expected["big.bin"],
            )
    return rows


def _median_time(fn: Callable[[], float], repeat: int) -> float:
    return statistics.median(fn() for _ in range(repeat))


def _chain(blocks: list[Block], idx: int, *, solid: bool) -> list[Block]:
    start = idx
    if solid:
        start = max(i for i in range(idx + 1) if not blocks[i].solid)
    return blocks[start : idx + 1]


def _time_masked(arc: Path, password: str | None, name: str) -> float:
    rc, _, dt = run_unrar(arc, password=password, mask=name)
    assert rc == 0, rc
    return dt


def _time_synthetic(
    work: Path, arc: Path, password: str | None, synth: Synth, chain: list[Block]
) -> float:
    t0 = time.perf_counter()
    with arc.open("rb") as fh:
        # Only the chain's bytes are read, as a stream source would be.
        need = []
        for b in chain:
            fh.seek(b.data_offset)
            need.append(fh.read(b.data_size))
    out = bytearray(synth.sig() + synth.main(solid=len(chain) > 1))
    for i, (b, d) in enumerate(zip(chain, need, strict=True)):
        out += synth.patch(b, name=f"m{i}".encode()) + d
    out += synth.end()
    fd, tmp = tempfile.mkstemp(suffix=".rar", dir=work)
    with os.fdopen(fd, "wb") as fh:
        fh.write(out)
    mask = f"m{len(chain) - 1}" if len(chain) > 1 else None
    rc, _, _ = run_unrar(Path(tmp), password=password, mask=mask)
    os.unlink(tmp)
    assert rc == 0, rc
    return time.perf_counter() - t0


def timing(work: Path, count: int, repeat: int) -> list[dict[str, object]]:
    rows: list[dict[str, object]] = []
    tree = work / "ttree"
    files = make_tree(tree, count, 2000, seed=3)
    listfile = work / "list.txt"
    listfile.write_text("\n".join(str(p) for p in files))
    for version in (4, 5):
        synth = Synth(version)
        fmt = ["-ma4"] if version == 4 else ["-ma5"]
        for label, extra, pw in (
            ("nonsolid", [], None),
            ("nonsolid -hp", [f"-hp{PASSWORD}"], PASSWORD),
            ("solid -s50", ["-s50"], None),
        ):
            arc = work / f"t{version}{label.replace(' ', '')}.rar"
            rar([*fmt, *extra, "-m3", str(arc), f"@{listfile}"], work)
            blocks = files_of(walk(arc, version, pw), synth)
            src_size = arc.stat().st_size
            for which, idx in (("first", 0), ("last", len(blocks) - 1)):
                name = blocks[idx].name.decode("utf-8").replace("\\", "/")

                masked = functools.partial(_time_masked, arc, pw, name)
                synthetic = functools.partial(
                    _time_synthetic,
                    work,
                    arc,
                    pw,
                    synth,
                    _chain(blocks, idx, solid=label.startswith("solid")),
                )

                rows.append(
                    {
                        "format": f"rar{version}",
                        "archive": label,
                        "members": len(blocks),
                        "archive_bytes": src_size,
                        "member": which,
                        "masked_s": round(_median_time(masked, repeat), 4),
                        "synthetic_s": round(_median_time(synthetic, repeat), 4),
                    }
                )
    return rows


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    parser.add_argument("--files", type=int, default=3000)
    parser.add_argument("--repeat", type=int, default=5)
    parser.add_argument("--json", type=Path)
    parser.add_argument("--skip-timing", action="store_true")
    parser.add_argument(
        "--rar4",
        type=Path,
        default=Path.home() / ".cache/archivey/rar-gen/rar-6.23-ubuntu/rar",
        help="a rar that still writes -ma4 (scripts/gen_rar_fixtures.py fetches one)",
    )
    args = parser.parse_args()
    if not args.rar4.is_file():
        print(f"{args.rar4} missing; run scripts/gen_rar_fixtures.py once to fetch it")
        return 0
    RAR4_WRITER[0] = str(args.rar4)
    for tool in ("rar", "unrar"):
        if shutil.which(tool) is None:
            print(f"{tool} not on PATH; nothing to do")
            return 0
    report: dict[str, object] = {
        "unrar": subprocess.run(["unrar"], capture_output=True, check=False)
        .stdout.decode("latin-1")
        .strip()
        .splitlines()[0]
    }
    with tempfile.TemporaryDirectory(prefix="rar-synth-") as tmp:
        work = Path(tmp)
        report["correctness"] = rows = correctness(work)
        for row in rows:
            print(f"{'ok  ' if row['ok'] else 'FAIL'} rc={row['rc']:<3} {row['case']}")
        if not args.skip_timing:
            report["timing"] = trows = timing(work, args.files, args.repeat)
            for row in trows:
                print(
                    f"{row['format']} {row['archive']:<13} {row['members']} members, "
                    f"{row['member']:<5} masked {row['masked_s']:.4f}s "
                    f"synthetic {row['synthetic_s']:.4f}s"
                )
    if args.json:
        args.json.write_text(json.dumps(report, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
