"""Non-gating TAR/ISO lock baseline (wall time under concurrent opens).

Records representative wall-clock samples for concurrent member opens under
``concurrent_operations=True``. There is **no** pass/fail threshold — re-run before any
performance claim and compare before/after with the same recipe.

Example::

    uv run --extra all python benchmarks/tar_iso_lock_baseline.py

Sample run (2026-07-11, Linux x86_64, CPython 3.11, illustrative only)::

    ZIP ref     n=8 workers  wall≈0.005s
    plain TAR   n=8 workers  wall≈0.002s
    .tar.gz     n=8 workers  wall≈0.003s
    ISO         n=4 workers  wall≈0.001s   (skipped if pycdlib absent)
"""

from __future__ import annotations

import io
import tarfile
import tempfile
import threading
import time
import zipfile
from pathlib import Path

from archivey import open_archive


def _make_tar(
    path: Path, *, compressed: bool, n: int = 8, payload: bytes = b"x" * 4096
) -> None:
    mode = "w:gz" if compressed else "w"
    with tarfile.open(path, mode) as tf:
        for i in range(n):
            data = payload + f"-{i}".encode()
            info = tarfile.TarInfo(name=f"f{i}.txt")
            info.size = len(data)
            tf.addfile(info, io.BytesIO(data))


def _fan_out_wall(path: Path) -> float:
    with open_archive(path, concurrent_operations=True) as reader:
        names = [m.name for m in reader.members() if m.is_file]
        barrier = threading.Barrier(len(names))

        def worker(name: str) -> None:
            barrier.wait(timeout=10)
            with reader.open(name) as stream:
                stream.read()

        threads = [threading.Thread(target=worker, args=(n,)) for n in names]
        t0 = time.perf_counter()
        for t in threads:
            t.start()
        for t in threads:
            t.join(timeout=60)
        return time.perf_counter() - t0


def _maybe_iso(path: Path, n: int = 4) -> float | None:
    try:
        import pycdlib
    except ImportError:
        return None
    iso = pycdlib.PyCdlib()
    iso.new(interchange_level=1)
    for i in range(n):
        data = (b"y" * 4096) + f"-{i}".encode()
        iso.add_fp(io.BytesIO(data), len(data), f"/F{i}.TXT;1")
    iso.write(str(path))
    iso.close()
    return _fan_out_wall(path)


def main() -> None:
    with tempfile.TemporaryDirectory() as td:
        root = Path(td)
        plain = root / "a.tar"
        gz = root / "a.tar.gz"
        _make_tar(plain, compressed=False)
        _make_tar(gz, compressed=True)
        # ZIP included as a non-locked reference shape (stdlib zipfile coordination).
        zpath = root / "a.zip"
        with zipfile.ZipFile(zpath, "w") as zf:
            for i in range(8):
                zf.writestr(f"f{i}.txt", (b"z" * 4096) + f"-{i}".encode())

        print(f"ZIP ref     n=8 workers  wall={_fan_out_wall(zpath):.4f}s")
        print(f"plain TAR   n=8 workers  wall={_fan_out_wall(plain):.4f}s")
        print(f".tar.gz     n=8 workers  wall={_fan_out_wall(gz):.4f}s")
        iso_wall = _maybe_iso(root / "a.iso")
        if iso_wall is None:
            print("ISO         skipped (pycdlib not installed)")
        else:
            print(f"ISO         n=4 workers  wall={iso_wall:.4f}s")
        print(
            "Note: wall time only; lock wait/hold requires instrumentation. "
            "No CI threshold — informational baseline."
        )


if __name__ == "__main__":
    main()
