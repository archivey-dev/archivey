"""Differential Atheris fuzzing of the two raw Snappy backends under archivey's framing.

usage: python fuzz.py {raw,framed} SECONDS WORKDIR [libFuzzer args...]

``raw``: one input is a raw block. Each backend (through ``decode_raw_chunk``, so with
the 64 KiB length check) is compared with Google Snappy and a strict Python decoder:
acceptance and bytes must agree. ``framed``: one input is a framed stream. Each backend
is driven two ways (whole input and 64 KiB reads; 7-byte reads with 13-byte reads of
output) and compared with the reference framing around Google Snappy: outcome kind and
bytes must agree.

A disagreement is saved under WORKDIR/findings/<target>/<signature>/ and the run goes
on. A native crash stops the process; libFuzzer then writes ``crash-*`` into WORKDIR.
"""

# Each lambda here is called at once, inside its loop iteration.

from __future__ import annotations

import hashlib
import sys
from pathlib import Path

import atheris

with atheris.instrument_imports(["archivey", "common"]):
    sys.path.insert(0, str(Path(__file__).parent))
    import common as C

TARGET, SECONDS, WORK = sys.argv[1], int(sys.argv[2]), Path(sys.argv[3])
FINDINGS = WORK / "findings" / TARGET
FINDINGS.mkdir(parents=True, exist_ok=True)
CORPUS = WORK / "corpus" / TARGET
CORPUS.mkdir(parents=True, exist_ok=True)
_seen: set[str] = set()


def _norm(result: tuple[str, object]) -> tuple[str, object]:
    kind, value = result
    if kind == "ok":
        return kind, hashlib.sha256(value).hexdigest()[:16]  # type: ignore[arg-type]
    return kind, None


def _record(data: bytes, results: dict[str, tuple[str, object]]) -> None:
    shape = sorted((k, v[0]) for k, v in results.items())
    sig = hashlib.sha256(repr(shape).encode()).hexdigest()[:12]
    folder = FINDINGS / sig
    folder.mkdir(exist_ok=True)
    count = len(list(folder.glob("input-*.bin")))
    if count < 5:
        (folder / f"input-{count}.bin").write_bytes(data)
        (folder / "outcomes.txt").write_text(
            "\n".join(f"{k}: {v}" for k, v in sorted(results.items())) + "\n"
        )
    if sig not in _seen:
        _seen.add(sig)
        print(f"FINDING {TARGET} {sig}: {shape}", flush=True)


def raw_one(data: bytes) -> None:
    results = {
        name: C.outcome(lambda d=dec: C.decode_raw_chunk(d, data))
        for name, dec in C.DECODERS.items()
    }
    results["python-strict"] = C.outcome(lambda: C.python_raw(data))
    results["google"] = C.outcome(lambda: C.google_raw(data))
    norm = {k: _norm(v) for k, v in results.items()}
    # Refusal reasons differ by design; acceptance and bytes must not.
    if len({(k2, v2 if k2 == "ok" else None) for k2, v2 in norm.values()}) != 1:
        _record(data, norm)


def framed_one(data: bytes) -> None:
    results: dict[str, tuple[str, object]] = {}
    for name in C.BACKEND_NAMES:
        results[f"{name}/bulk"] = C.outcome(lambda n=name: C.decode_with(n, data))
        results[f"{name}/drip"] = C.outcome(
            lambda n=name: C.decode_with(n, data, step=7, max_length=13)
        )
    results["reference"] = C.outcome(lambda: C.reference_framed(data))
    norm = {k: _norm(v) for k, v in results.items()}
    if len(set(norm.values())) != 1:
        _record(data, norm)


def _seeds() -> list[bytes]:
    out = []
    pay = C.payloads(3000)
    for p in pay.values():
        if TARGET == "raw":
            out.append(C.google_compress_raw(p))
        else:
            for produce in C.producers().values():
                out.append(produce(p))
    if TARGET == "framed":
        repros = Path(__file__).parents[1] / "snappy_compress_utils" / "repros"
        out += [f.read_bytes() for f in sorted(repros.glob("*.sz"))]
    return out


if __name__ == "__main__":
    for i, seed in enumerate(_seeds()):
        (CORPUS / f"seed-{i}").write_bytes(seed)
    one = raw_one if TARGET == "raw" else framed_one
    atheris.Setup(
        [
            sys.argv[0],
            str(CORPUS),
            f"-max_total_time={SECONDS}",
            "-max_len=200000",
            "-rss_limit_mb=2048",
            f"-artifact_prefix={WORK}/",
            *sys.argv[4:],
        ],
        one,
    )
    atheris.Fuzz()
