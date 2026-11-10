"""Time archivey's Python decoders against libarchive behind the synthetic wrappers.

Part 1, kernels: each row decodes the same coded bytes both ways, fed in 64 KiB
chunks, checks that the outputs are equal, and prints the best of three for each side.
The libarchive column includes the wrapper, the read callback and the copy out of
libarchive's buffer, which an accelerator in archivey would pay too.

Part 2, whole archives (only when ``7zz`` is on ``PATH``): 7z and ZIP archives whose
time goes mostly to codecs that are already in C (LZMA, PPMd), read end to end by
archivey and by libarchive, to show what a wrapper around their filters could gain.

    uv run python scripts/investigations/libarchive_accelerator/bench.py

Needs the system libarchive (``libarchive.so.13``) and ``ncompress``. The input is the
running interpreter's standard library source, so the absolute times depend on the
Python build; the page names the one measured. Investigation code;
``dev-docs/investigations/libarchive-accelerator.md`` quotes the output.
"""

from __future__ import annotations

import io
import platform
import shutil
import subprocess
import sys
import sysconfig
import tempfile
import time
from collections.abc import Callable, Iterator
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
sys.path.insert(0, str(HERE.parents[2] / "tests"))

import ncompress  # noqa: E402
import wrappers  # noqa: E402
from bindings import decode_all, decode_archive, version  # noqa: E402
from cab_util import CabFolder, _folder_blocks  # noqa: E402
from lha_util import compress as lzh_compress  # noqa: E402
from zipcrypto import _encrypt  # noqa: E402

import archivey  # noqa: E402
from archivey.internal.backends.zipcrypto import ZipCryptoKeys  # noqa: E402
from archivey.internal.streams.codecs.lzh_decoder import LzhDecoder  # noqa: E402
from archivey.internal.streams.codecs.lzx_decoder import FRAME_SIZE, LzxDecoder  # noqa: E402

CHUNK = 1 << 16


def corpus(size: int) -> bytes:
    out = bytearray()
    for p in sorted(Path(sysconfig.get_paths()["stdlib"]).rglob("*.py")):
        out += p.read_bytes()
        if len(out) >= size:
            break
    return bytes(out[:size])


def chunked(data: bytes) -> Iterator[bytes]:
    for i in range(0, len(data), CHUNK):
        yield data[i : i + CHUNK]


def best(fn: Callable[[], bytes], n: int = 3) -> tuple[float, bytes]:
    times, out = [], b""
    for _ in range(n):
        t = time.perf_counter()
        out = fn()
        times.append(time.perf_counter() - t)
    return min(times), out


def row(label: str, python: Callable[[], bytes], la: Callable[[], bytes]) -> None:
    tp, a = best(python)
    tl, b = best(la)
    assert a == b, label
    mb = len(a) / 1e6
    print(
        f"{label:34} {tp * 1000:8.0f} ms {tl * 1000:8.0f} ms {tp / tl:6.1f}x"
        f"   ({mb:.1f} MB out, libarchive {mb / tl:.0f} MB/s)"
    )


def lzx_python(payloads: list[bytes], bits: int, n: int) -> bytes:
    feed = iter(payloads)
    dec = LzxDecoder(bits, lambda: next(feed, None))
    out = []
    while n:
        frame = dec.decode_frame(min(FRAME_SIZE, n))
        out.append(frame)
        n -= len(frame)
    return b"".join(out)


def lzh_python(method: str, comp: bytes, n: int) -> bytes:
    feed = chunked(comp)
    dec = LzhDecoder(method, n, lambda: next(feed, None))
    out = []
    while chunk := dec.read(CHUNK):
        out.append(chunk)
    return b"".join(out)


def kernels(text: bytes) -> None:
    print(f"{'kernel':34} {'python':>11} {'libarchive':>11} {'speed-up':>7}")
    z = ncompress.compress(text)

    def py_z() -> bytes:
        with archivey.open_stream(io.BytesIO(z)) as s:
            return s.read()

    row(
        ".Z (LZW), 11 MB text",
        py_z,
        lambda: decode_all(wrappers.unix_compress(chunked(z))),
    )

    pw = b"pw"
    enc = _encrypt(pw, 0x5A, text)
    header12, cipher = enc[:12], enc[12:]

    def py_zc() -> bytes:
        keys = ZipCryptoKeys(pw)
        keys.decrypt(header12)
        return b"".join(keys.decrypt(c) for c in chunked(cipher))

    row(
        "ZipCrypto decrypt, 11 MB",
        py_zc,
        lambda: decode_all(
            wrappers.zipcrypto_decrypt(header12, chunked(cipher), len(cipher), pw, 0x5A)
        ),
    )

    small = text[: 4 << 20]
    for bits in (16, 21):
        blocks = _folder_blocks(CabFolder(method="lzx", window_bits=bits), small)
        payloads = [p for p, _ in blocks]
        sizes = [(len(p), d) for p, d in blocks]
        row(
            f"LZX {bits}-bit window, 4 MB text",
            lambda payloads=payloads, bits=bits: lzx_python(payloads, bits, len(small)),
            lambda payloads=payloads, sizes=sizes, bits=bits: decode_all(
                wrappers.lzx_folder(iter(payloads), sizes, bits)
            ),
        )

    mib = text[: 1 << 20]
    for method in ("-lh5-", "-lh7-"):
        comp = lzh_compress(mib, method)
        row(
            f"LZH {method}, 1 MiB text",
            lambda comp=comp, method=method: lzh_python(method, comp, len(mib)),
            lambda comp=comp, method=method: b"".join(
                wrappers.lzh(method, chunked(comp), len(comp), len(mib))
            ),
        )


def archivey_read(path: Path) -> bytes:
    out = []
    with archivey.open_archive(path) as r:
        for m in r.members():
            if m.is_file:
                with r.open(m) as s:
                    out.append(s.read())
    return b"".join(out)


def whole_archives(text: bytes) -> None:
    if shutil.which("7zz") is None:
        print("\n(whole archives skipped: no 7zz)")
        return
    print(f"\n{'whole archive':34} {'archivey':>11} {'libarchive':>11} {'speed-up':>7}")
    lib = max(
        Path("/usr/lib/x86_64-linux-gnu").glob("*.so*"), key=lambda p: p.stat().st_size
    )
    exe = (lib.read_bytes() * 16)[: 16 << 20]
    cases = [
        ("7z ARM64 + LZMA2, 16 MB", "7zip", exe, ["-mf=ARM64", "-m0=lzma2"]),
        (
            "7z BCJ2 + LZMA, 16 MB",
            "7zip",
            exe,
            [
                "-m0=BCJ2",
                "-m1=LZMA",
                "-m2=LZMA",
                "-m3=LZMA",
                "-mb0:1",
                "-mb0s1:2",
                "-mb0s2:3",
            ],
        ),
        ("7z PPMd, 11 MB text", "7zip", text, ["-m0=PPMd"]),
        ("ZIP PPMd8, 11 MB text", "zip_streamable", text, ["-tzip", "-mm=PPMd"]),
    ]
    with tempfile.TemporaryDirectory() as tmp:
        src = Path(tmp, "data.bin")
        for label, fmt, data, args in cases:
            src.write_bytes(data)
            out = Path(tmp, "a.7z" if fmt == "7zip" else "a.zip")
            out.unlink(missing_ok=True)
            subprocess.run(
                ["7zz", "a", "-bd", "-bso0", "-mx=1", *args, str(out), str(src)],
                check=True,
            )
            blob = out.read_bytes()
            row(
                label,
                lambda out=out: archivey_read(out),
                lambda blob=blob, fmt=fmt: decode_archive(blob, fmt),
            )


def main() -> None:
    print(version(), "|", platform.python_implementation(), platform.python_version())
    text = corpus(12 << 20)
    kernels(text)
    whole_archives(text)


if __name__ == "__main__":
    main()
