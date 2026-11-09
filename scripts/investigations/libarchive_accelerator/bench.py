"""Time archivey's Python decoders against libarchive behind the synthetic wrappers.

Each row decodes the same coded bytes both ways, fed in 64 KiB chunks, checks that the
outputs are equal, and prints the best of three. The libarchive column includes the
wrapper, the read callback and the copy out of libarchive's buffer, which an accelerator
in archivey would pay too.

    uv run python scripts/investigations/libarchive_accelerator/bench.py

Needs the system libarchive (``libarchive.so.13``) and ``ncompress``. Investigation
code; ``dev-docs/investigations/libarchive-accelerator.md`` quotes the output.
"""

from __future__ import annotations

import io
import sys
import sysconfig
import time
from collections.abc import Callable, Iterator
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
sys.path.insert(0, str(HERE.parents[2] / "tests"))

import ncompress  # noqa: E402
import wrappers  # noqa: E402
from bindings import version  # noqa: E402
from cab_util import CabFolder, _folder_blocks  # noqa: E402
from zipcrypto import _encrypt  # noqa: E402

import archivey  # noqa: E402
from archivey.internal.backends.zipcrypto import ZipCryptoKeys  # noqa: E402
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


def row(
    label: str, python: Callable[[], bytes], la: Callable[[], bytes], n: int
) -> None:
    tp, a = best(python, n)
    tl, b = best(la, 3)
    assert a == b, label
    mb = len(a) / 1e6
    print(
        f"{label:34} {tp * 1000:8.0f} ms {tl * 1000:8.0f} ms {tp / tl:6.1f}x"
        f"   ({mb:.1f} MB out, libarchive {mb / tl:.0f} MB/s)"
    )


def main() -> None:
    print(version())
    print(f"{'kernel':34} {'python':>11} {'libarchive':>11} {'speed-up':>7}")
    text = corpus(12 << 20)

    # .Z
    z = ncompress.compress(text)

    def py_z() -> bytes:
        with archivey.open_stream(io.BytesIO(z)) as s:
            return s.read()

    row(
        ".Z (LZW), 11 MB text",
        py_z,
        lambda: wrappers.unix_compress(chunked(z)).read_all(),
        1,
    )

    # ZipCrypto, decryption only
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
        lambda: wrappers.zipcrypto_decrypt(
            header12, chunked(cipher), len(cipher), pw, 0x5A
        ).read_all(),
        1,
    )

    # LZX, one CAB folder
    for bits in (16, 21):
        small = text[: 4 << 20]
        blocks = _folder_blocks(CabFolder(method="lzx", window_bits=bits), small)
        payloads = [p for p, _ in blocks]
        sizes = [(len(p), d) for p, d in blocks]

        def py_lzx(
            payloads: list[bytes] = payloads, bits: int = bits, n: int = len(small)
        ) -> bytes:
            feed = iter(payloads)
            dec = LzxDecoder(bits, lambda: next(feed, None))
            out, left = [], n
            while left:
                frame = dec.decode_frame(min(FRAME_SIZE, left))
                out.append(frame)
                left -= len(frame)
            return b"".join(out)

        row(
            f"LZX {bits}-bit window, 4 MB text",
            py_lzx,
            lambda payloads=payloads, sizes=sizes, bits=bits: wrappers.lzx_folder(
                iter(payloads), sizes, bits
            ).read_all(),
            1,
        )


if __name__ == "__main__":
    main()
