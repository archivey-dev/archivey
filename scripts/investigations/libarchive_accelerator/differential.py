"""Differential test: archivey's Python decoders against libarchive on damaged input.

An accelerator must give the same bytes or the same refusal as the decoder it replaces
(DR-5). This feeds both the same clean and damaged streams (bit flips, replaced bytes,
cuts) and counts the outcomes. ``cabextract``, when installed, is a third opinion for
LZX, since archivey's LZX decoder follows libmspack.

    uv run python scripts/investigations/libarchive_accelerator/differential.py [N] [SEED]

Investigation code; ``dev-docs/investigations/libarchive-accelerator.md`` quotes the
output.
"""

from __future__ import annotations

import collections
import io
import logging
import random
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
sys.path.insert(0, str(HERE.parents[2] / "tests"))

import ncompress  # noqa: E402
import wrappers  # noqa: E402
from bench import corpus  # noqa: E402
from bindings import LibarchiveError  # noqa: E402
from cab_util import CabFolder, _folder_blocks  # noqa: E402
from zipcrypto import _encrypt  # noqa: E402

import archivey  # noqa: E402
from archivey.exceptions import ArchiveyError  # noqa: E402
from archivey.internal.backends.zipcrypto import ZipCryptoKeys  # noqa: E402
from archivey.internal.streams.codecs.lzx_decoder import FRAME_SIZE, LzxDecoder  # noqa: E402

logging.disable(logging.CRITICAL)
N = int(sys.argv[1]) if len(sys.argv) > 1 else 500
rng = random.Random(int(sys.argv[2]) if len(sys.argv) > 2 else 1)
TEXT = corpus(4 << 20)
Outcome = tuple[str, bytes | str]


def sample() -> bytes:
    n = rng.choice([1000, 20000, 70000])
    o = rng.randrange(len(TEXT) - n)
    return TEXT[o : o + n]


def damage(data: bytes, start: int = 0) -> tuple[bytes, str]:
    kind = rng.choice(["flip", "flip", "bytes", "cut"])
    b = bytearray(data)
    if kind == "cut":
        return bytes(b[: rng.randrange(start, len(b))]), kind
    if kind == "flip":
        for _ in range(rng.randint(1, 3)):
            p = rng.randrange(start, len(b))
            b[p] ^= 1 << rng.randrange(8)
        return bytes(b), kind
    p, n = rng.randrange(start, len(b)), rng.randint(1, 8)
    b[p : p + n] = rng.randbytes(n)
    return bytes(b), kind


def run(fn) -> Outcome:
    try:
        return "ok", fn()
    except (ArchiveyError, LibarchiveError) as e:
        return "refused", f"{type(e).__name__}: {e}"[:110]


def compare(a: Outcome, b: Outcome) -> str:
    if a[0] == b[0] == "ok":
        return "same bytes" if a[1] == b[1] else "BOTH ACCEPT, DIFFERENT BYTES"
    if a[0] == b[0] == "refused":
        return "both refuse"
    return (
        "archivey accepts, libarchive refuses"
        if a[0] == "ok"
        else "ARCHIVEY REFUSES, LIBARCHIVE ACCEPTS"
    )


def report(name: str, stats: collections.Counter, examples: dict) -> None:
    print(f"\n== {name}: {sum(stats.values())} streams")
    for (kind, verdict), count in sorted(stats.items()):
        print(f"  {kind:6} {verdict:40} {count}")
    for verdict, ex in examples.items():
        print(f"  e.g. {verdict}:")
        for e in ex:
            print(f"     {e}")


def unix_compress() -> None:
    stats: collections.Counter = collections.Counter()
    examples: dict = collections.defaultdict(list)
    for i in range(N):
        clean = ncompress.compress(sample())
        z, kind = (clean, "clean") if i % 10 == 0 else damage(clean, 3)

        def py(z: bytes = z) -> bytes:
            with archivey.open_stream(io.BytesIO(z)) as s:
                return s.read()

        a = run(py)
        b = run(lambda z=z: wrappers.unix_compress(iter([z])).read_all())
        verdict = compare(a, b)
        stats[(kind, verdict)] += 1
        if verdict not in ("same bytes", "both refuse") and len(examples[verdict]) < 2:
            examples[verdict].append(
                (
                    kind,
                    a[1] if a[0] == "refused" else "ok",
                    b[1] if b[0] == "refused" else "ok",
                )
            )
    report(".Z (LZW)", stats, examples)


def cabextract(cab: bytes) -> str:
    with tempfile.TemporaryDirectory() as t:
        Path(t, "x.cab").write_bytes(cab)
        r = subprocess.run(
            ["cabextract", "-q", "-d", f"{t}/o", f"{t}/x.cab"],
            capture_output=True,
            check=False,
        )
        return "ok" if r.returncode == 0 else "refused"


def lzx() -> None:
    stats: collections.Counter = collections.Counter()
    examples: dict = collections.defaultdict(list)
    third: collections.Counter = collections.Counter()
    have_cabextract = shutil.which("cabextract") is not None
    for i in range(N):
        data, bits = sample(), rng.choice([15, 16, 21])
        blocks = [
            p
            for p, _ in _folder_blocks(CabFolder(method="lzx", window_bits=bits), data)
        ]
        kind = "clean"
        if i % 10:
            j = rng.randrange(len(blocks))
            blocks[j], kind = damage(blocks[j])
        decoded = [
            min(FRAME_SIZE, len(data) - k) for k in range(0, len(data), FRAME_SIZE)
        ]
        sizes = [(len(p), d) for p, d in zip(blocks, decoded, strict=True)]

        def py(
            blocks: list[bytes] = blocks, bits: int = bits, n: int = len(data)
        ) -> bytes:
            feed = iter(blocks)
            dec = LzxDecoder(bits, lambda: next(feed, None))
            out = []
            while n:
                frame = dec.decode_frame(min(FRAME_SIZE, n))
                out.append(frame)
                n -= len(frame)
            return b"".join(out)

        a = run(py)
        b = run(
            lambda blocks=blocks, sizes=sizes, bits=bits: wrappers.lzx_folder(
                iter(blocks), sizes, bits
            ).read_all()
        )
        verdict = compare(a, b)
        stats[(kind, verdict)] += 1
        if verdict not in ("same bytes", "both refuse") and len(examples[verdict]) < 2:
            examples[verdict].append(
                (
                    kind,
                    a[1] if a[0] == "refused" else "ok",
                    b[1] if b[0] == "refused" else "ok",
                )
            )
        if have_cabextract and a[0] != b[0]:
            cab = b"".join(wrappers.lzx_folder_bytes(blocks, sizes, bits))
            third[(verdict, f"cabextract {cabextract(cab)}")] += 1
        if a[0] == "ok" and a[1] != data:
            third[
                ("archivey: wrong bytes, no error (no checksums)", "libarchive " + b[0])
            ] += 1
    report("LZX (one CAB folder, no block checksums)", stats, examples)
    for k, v in sorted(third.items()):
        print(f"  {k[0]:46} {k[1]:20} {v}")


def zipcrypto() -> None:
    """Decryption has no failure mode: any bytes decrypt. The check is equal output.

    libarchive takes the passphrase as a C string, so a password with a NUL byte
    cannot reach it; those are counted apart.
    """
    same = nul = 0
    for _ in range(N // 5):
        pw = rng.randbytes(rng.randint(1, 12))
        data = rng.randbytes(rng.randint(0, 50000))
        enc = (
            _encrypt(pw, 0x33, data) if rng.random() < 0.5 else rng.randbytes(12) + data
        )
        header12, cipher = enc[:12], enc[12:]
        keys = ZipCryptoKeys(pw)
        check = keys.decrypt(header12)[11]
        a = keys.decrypt(cipher)
        if b"\0" in pw:
            nul += 1
            continue
        b = wrappers.zipcrypto_decrypt(
            header12, iter([cipher]), len(cipher), pw, check
        ).read_all()
        same += a == b
    print(
        f"\n== ZipCrypto decrypt: {same} of {N // 5 - nul} random streams give equal bytes"
        f" ({nul} passwords with a NUL byte skipped: libarchive cannot take them)"
    )


if __name__ == "__main__":
    unix_compress()
    lzx()
    zipcrypto()
