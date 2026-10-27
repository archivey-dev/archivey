"""Measure how quickly stdlib ZIP codecs reject wrong-key / random input.

Used to evidence-back the ZipCrypto multi-password confirmation bound
(``openspec/changes/zip-multipassword-disambiguation``).

What we measure
---------------
For each of DEFLATE (raw, ZIP-style ``wbits=-15``), BZIP2, and ZIP-framed LZMA:

1. **Uniform random streams** — feed ``os.urandom`` through the decompressor and
   record how many *compressed* bytes were consumed and how many *decompressed*
   bytes were produced before the codec raised.
2. **Wrong-key ZipCrypto** — encrypt a valid compressed payload with the right
   password, decrypt with a colliding wrong password (verification byte matches),
   and measure the same. This is the real confirmation path.

BZIP2 note
----------
A valid bzip2 block can be up to ~900 KiB of compressed input. Random input almost
never has a valid ``BZh[1-9]`` magic, so rejection is usually immediate; the
interesting tail is streams that accidentally look like a header. We also probe
"almost-magic" prefixes to see worst-case consumption.

Run from repo root::

    uv run --no-sync python scripts/exploration/zipcrypto_codec_rejection.py
"""

from __future__ import annotations

import argparse
import bz2
import io
import lzma
import os
import statistics
import struct
import sys
import zipfile
import zlib
from dataclasses import dataclass
from pathlib import Path

# Allow importing tests.zipcrypto without installing the package as editable tests.
_REPO = Path(__file__).resolve().parents[2]
if str(_REPO) not in sys.path:
    sys.path.insert(0, str(_REPO))

from tests.zipcrypto import _Keys, build_zipcrypto_zip  # noqa: E402


@dataclass(frozen=True)
class RejectionSample:
    compressed_consumed: int
    decompressed_produced: int
    error_type: str
    error_msg: str


def _summarize(samples: list[RejectionSample], label: str) -> None:
    if not samples:
        print(f"  {label}: no samples")
        return
    cc = [s.compressed_consumed for s in samples]
    dp = [s.decompressed_produced for s in samples]
    print(f"  {label} (n={len(samples)})")
    print(
        f"    compressed consumed:  min={min(cc)}  p50={statistics.median(cc):.0f}  "
        f"p95={_percentile(cc, 95):.0f}  max={max(cc)}"
    )
    print(
        f"    decompressed produced: min={min(dp)}  p50={statistics.median(dp):.0f}  "
        f"p95={_percentile(dp, 95):.0f}  max={max(dp)}"
    )
    # Error-type histogram
    hist: dict[str, int] = {}
    for s in samples:
        hist[s.error_type] = hist.get(s.error_type, 0) + 1
    print(f"    errors: {hist}")


def _percentile(values: list[int], pct: float) -> float:
    ordered = sorted(values)
    if not ordered:
        return 0.0
    idx = min(len(ordered) - 1, round((pct / 100.0) * (len(ordered) - 1)))
    return float(ordered[idx])


# ---------------------------------------------------------------------------
# Direct codec probes (no ZIP framing)
# ---------------------------------------------------------------------------


def reject_deflate(data: bytes, *, max_out: int = 2 * 1024 * 1024) -> RejectionSample:
    """Feed raw DEFLATE bytes; return consumption at first error or max_out."""
    dec = zlib.decompressobj(-15)  # ZIP raw deflate
    produced = 0
    consumed = 0
    try:
        # Feed in small chunks so we can see early rejection.
        for i in range(0, len(data), 64):
            chunk = data[i : i + 64]
            out = dec.decompress(chunk, max_out - produced)
            produced += len(out)
            consumed += len(chunk) - len(dec.unconsumed_tail)
            if produced >= max_out:
                return RejectionSample(
                    consumed,
                    produced,
                    "max_out",
                    "hit decompressed bound without error",
                )
            if dec.eof:
                return RejectionSample(
                    consumed, produced, "eof_ok", "stream ended cleanly (false accept)"
                )
        # Flush remaining
        out = dec.flush()
        produced += len(out)
        return RejectionSample(
            consumed, produced, "flush_ok", "flush succeeded (false accept)"
        )
    except zlib.error as exc:
        # After error, unconsumed_tail holds unused input; consumed is approximate.
        unused = len(dec.unconsumed_tail)
        # zlib doesn't expose a precise "bytes accepted" counter; approximate from
        # how far we got through ``data`` minus unused tail.
        approx = min(len(data), consumed + 64) - unused
        return RejectionSample(
            max(0, approx), produced, type(exc).__name__, str(exc)[:80]
        )


def reject_bzip2(data: bytes, *, max_out: int = 2 * 1024 * 1024) -> RejectionSample:
    dec = bz2.BZ2Decompressor()
    produced = 0
    consumed = 0
    try:
        for i in range(0, len(data), 64):
            chunk = data[i : i + 64]
            out = dec.decompress(chunk, max_out - produced)
            produced += len(out)
            # BZ2Decompressor has no unconsumed_tail until eof; need_input means all
            # of chunk was accepted (or buffered internally).
            consumed = i + len(chunk)
            if produced >= max_out:
                return RejectionSample(
                    consumed,
                    produced,
                    "max_out",
                    "hit decompressed bound without error",
                )
            if dec.eof:
                return RejectionSample(
                    consumed, produced, "eof_ok", "stream ended cleanly (false accept)"
                )
        return RejectionSample(
            consumed, produced, "need_more", "no error after all input"
        )
    except OSError as exc:
        return RejectionSample(consumed, produced, type(exc).__name__, str(exc)[:80])
    except Exception as exc:  # noqa: BLE001 — exploration: record any failure mode
        return RejectionSample(consumed, produced, type(exc).__name__, str(exc)[:80])


def reject_lzma_raw_zip(
    data: bytes, *, max_out: int = 2 * 1024 * 1024
) -> RejectionSample:
    """ZIP LZMA framing: 2-byte version + 2-byte props size + props + raw LZMA.

    ``zipfile`` uses this layout. For random data we try the same path zipfile would:
    if the header is unreadable we count that as early rejection; otherwise we feed
    the remainder to ``LZMADecompressor(FORMAT_RAW, filters=...)``.
    """
    if len(data) < 4:
        return RejectionSample(len(data), 0, "short", "shorter than ZIP LZMA header")
    _ver, props_size = struct.unpack("<HH", data[:4])
    consumed = 4
    if props_size <= 0 or props_size > 256 or 4 + props_size > len(data):
        # zipfile would fail constructing the decompressor / reading props.
        return RejectionSample(
            min(len(data), 4 + max(props_size, 0)),
            0,
            "bad_props_header",
            f"props_size={props_size}",
        )
    props = data[4 : 4 + props_size]
    consumed = 4 + props_size
    rest = data[consumed:]
    try:
        # Mirror zipfile.LZMADecompressor: FILTER_LZMA1 with encoded properties.
        filters = [{"id": lzma.FILTER_LZMA1, "properties": props}]
        dec = lzma.LZMADecompressor(lzma.FORMAT_RAW, filters=filters)
    except (lzma.LZMAError, ValueError) as exc:
        return RejectionSample(consumed, 0, type(exc).__name__, str(exc)[:80])

    produced = 0
    try:
        for i in range(0, len(rest), 64):
            chunk = rest[i : i + 64]
            out = dec.decompress(chunk, max_out - produced)
            produced += len(out)
            unused = len(dec.unused_data)
            consumed = 4 + props_size + i + len(chunk) - unused
            if produced >= max_out:
                return RejectionSample(
                    consumed,
                    produced,
                    "max_out",
                    "hit decompressed bound without error",
                )
            if dec.eof:
                return RejectionSample(
                    consumed, produced, "eof_ok", "stream ended cleanly (false accept)"
                )
        return RejectionSample(
            consumed, produced, "need_more", "no error after all input"
        )
    except lzma.LZMAError as exc:
        return RejectionSample(consumed, produced, type(exc).__name__, str(exc)[:80])


# ---------------------------------------------------------------------------
# Through zipfile (the real confirmation path)
# ---------------------------------------------------------------------------


def reject_via_zipfile(
    blob: bytes, name: str, password: bytes, *, max_out: int = 2 * 1024 * 1024
) -> RejectionSample:
    """Open an encrypted member with ``password`` and read until error or ``max_out``."""
    produced = 0
    try:
        with zipfile.ZipFile(io.BytesIO(blob)) as zf, zf.open(name, pwd=password) as fh:
            while produced < max_out:
                chunk = fh.read(64 * 1024)
                if not chunk:
                    return RejectionSample(
                        -1,  # zipfile doesn't expose ciphertext cursor
                        produced,
                        "eof_ok",
                        "member read completed (CRC passed — false accept risk)",
                    )
                produced += len(chunk)
            return RejectionSample(
                -1, produced, "max_out", "hit decompressed bound without error"
            )
    except Exception as exc:  # noqa: BLE001 — record whatever zipfile/codec raises
        return RejectionSample(-1, produced, type(exc).__name__, str(exc)[:100])


def _wrong_key_ciphertext(password: bytes, payload: bytes) -> bytes:
    """Decrypt ``payload`` (incl. 12-byte header) with a wrong password's keystream.

    ``payload`` is the encrypted member body as stored in the ZIP (header + ciphertext).
    We re-derive by encrypting known plaintext is awkward; instead callers pass the
    encrypted bytes from a built archive and we XOR with a wrong key's keystream after
    consuming the header the same way ZipCrypto does.
    """
    # Actually: to get wrong-key *plaintext* (what the decompressor sees), decrypt with
    # the wrong password.
    keys = _Keys(password)
    out = bytearray()
    for i, cipher_byte in enumerate(payload):
        plain = cipher_byte ^ keys.keystream_byte()
        if i >= 12:
            out.append(plain)
        keys.update(plain)
    return bytes(out)


def _encrypted_member_body(blob: bytes) -> bytes:
    name_len, extra_len = struct.unpack_from("<HH", blob, 26)
    # Local file header is 30 + name + extra; encrypted body follows.
    start = 30 + name_len + extra_len
    # Compressed size is at offset 18.
    comp_size = struct.unpack_from("<I", blob, 18)[0]
    return blob[start : start + comp_size]


def run_random_trials(n: int, stream_size: int) -> None:
    print(f"\n=== Uniform random streams (n={n}, each {stream_size} bytes) ===")
    for name, fn in (
        ("DEFLATE raw", reject_deflate),
        ("BZIP2", reject_bzip2),
        ("LZMA ZIP-framed", reject_lzma_raw_zip),
    ):
        samples = [fn(os.urandom(stream_size)) for _ in range(n)]
        _summarize(samples, name)
        survivors = [
            s
            for s in samples
            if s.error_type in {"max_out", "eof_ok", "flush_ok", "need_more"}
        ]
        if survivors:
            print(f"    WARNING: {len(survivors)} streams did not error within bound")
            for s in survivors[:5]:
                print(f"      {s}")


def run_almost_magic_bzip2(n: int, stream_size: int) -> None:
    """Force a plausible bzip2 magic, then random — worst-case header acceptance."""
    print(f"\n=== BZIP2 with forced magic BZh9 + random (n={n}) ===")
    samples = []
    for _ in range(n):
        data = b"BZh9" + os.urandom(stream_size - 4)
        samples.append(reject_bzip2(data))
    _summarize(samples, "BZIP2 almost-magic")
    survivors = [
        s for s in samples if s.error_type in {"max_out", "eof_ok", "need_more"}
    ]
    if survivors:
        print(f"    WARNING: {len(survivors)} streams survived")
        for s in survivors[:5]:
            print(f"      {s}")


def run_wrong_key_zipfile(n_collisions: int, plaintext_size: int) -> None:
    print(
        f"\n=== Wrong-key via zipfile "
        f"(plaintext ~{plaintext_size} bytes, {n_collisions} collisions/codec) ==="
    )
    # Highly compressible so compressed members stay modest; size is decompressed.
    plaintext = (
        b"The quick brown fox jumps over the lazy dog.\n" * (plaintext_size // 45 + 1)
    )[:plaintext_size]
    right = b"correct-password-for-probe"
    name = "probe.bin"
    for compression, label in (
        (zipfile.ZIP_DEFLATED, "DEFLATE"),
        (zipfile.ZIP_BZIP2, "BZIP2"),
        (zipfile.ZIP_LZMA, "LZMA"),
        (zipfile.ZIP_STORED, "STORED"),
    ):
        blob = build_zipcrypto_zip(
            right, name.encode(), plaintext, compression=compression
        )
        samples: list[RejectionSample] = []
        # Collect several colliding wrong passwords and measure each.
        try:
            collisions = []
            # find_check_byte_collisions reads the whole member; for large plaintext
            # that is slow. Use a small search helper inline for open-only collision.
            import io as _io

            with zipfile.ZipFile(_io.BytesIO(blob)) as zf:
                info = zf.getinfo(name)
                for i in range(50_000):
                    wrong = f"collide-{i}".encode()
                    if wrong == right:
                        continue
                    try:
                        h = zf.open(info, pwd=wrong)
                    except RuntimeError:
                        continue
                    h.close()
                    collisions.append(wrong)
                    if len(collisions) >= n_collisions:
                        break
            if len(collisions) < n_collisions:
                print(f"  {label}: only found {len(collisions)} collisions, skipping")
                continue
        except Exception as exc:  # noqa: BLE001
            print(f"  {label}: collision search failed: {exc}")
            continue

        for wrong in collisions:
            samples.append(reject_via_zipfile(blob, name, wrong))
        _summarize(samples, f"{label} wrong-key zipfile.read")

        # Also measure direct codec on wrong-key decrypted ciphertext (compressed path).
        if compression != zipfile.ZIP_STORED:
            body = _encrypted_member_body(blob)
            direct_samples = []
            for wrong in collisions:
                garbage = _wrong_key_ciphertext(wrong, body)
                if compression == zipfile.ZIP_DEFLATED:
                    direct_samples.append(reject_deflate(garbage))
                elif compression == zipfile.ZIP_BZIP2:
                    direct_samples.append(reject_bzip2(garbage))
                else:
                    direct_samples.append(reject_lzma_raw_zip(garbage))
            _summarize(direct_samples, f"{label} wrong-key direct codec")


def run_how_much_to_read_for_certainty(
    n: int, stream_size: int, read_sizes: list[int]
) -> None:
    """For each candidate confirmation read size, how often does random input still
    not error after reading that many *decompressed* bytes?"""
    print("\n=== Certainty vs decompressed-read budget (random input) ===")
    for name, fn in (
        ("DEFLATE", reject_deflate),
        ("BZIP2", reject_bzip2),
        ("LZMA", reject_lzma_raw_zip),
    ):
        print(f"  {name}:")
        for budget in read_sizes:
            survivors = 0
            max_cc = 0
            for _ in range(n):
                s = fn(os.urandom(stream_size), max_out=budget)
                max_cc = max(max_cc, s.compressed_consumed)
                if s.error_type in {"max_out", "eof_ok", "flush_ok", "need_more"}:
                    survivors += 1
            print(
                f"    budget={budget:>8} B  survivors={survivors}/{n}  "
                f"max_compressed_seen={max_cc}"
            )


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("-n", type=int, default=2000, help="random trials per codec")
    parser.add_argument(
        "--stream-size", type=int, default=2 * 1024 * 1024, help="random stream size"
    )
    parser.add_argument(
        "--collisions", type=int, default=20, help="wrong-key collisions per codec"
    )
    parser.add_argument(
        "--plaintext-size",
        type=int,
        default=256 * 1024,
        help="plaintext size for wrong-key zipfile trials",
    )
    args = parser.parse_args()

    run_random_trials(args.n, args.stream_size)
    run_almost_magic_bzip2(min(args.n, 500), args.stream_size)
    run_how_much_to_read_for_certainty(
        n=min(args.n, 1000),
        stream_size=args.stream_size,
        read_sizes=[64, 256, 1024, 4096, 64 * 1024, 256 * 1024, 1024 * 1024],
    )
    run_wrong_key_zipfile(args.collisions, args.plaintext_size)


if __name__ == "__main__":
    main()
