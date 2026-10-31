"""The decoder worker script, as a file: what it may import, and how it starts.

Every decoder child runs ``decoder_worker.py`` as a script (``python -P``), rapidgzip's
included (it hands over to ``rapidgzip_worker.py``). The parent imports the same file
for its constants. Neither may import ``archivey`` or a codec library at module level.
"""

from __future__ import annotations

import subprocess
import sys
import textwrap

from archivey.internal.streams.codecs import decoder_child


def _run(probe: str) -> str:
    proc = subprocess.run(
        [sys.executable, "-P", "-c", probe],
        capture_output=True,
        text=True,
        timeout=60,
        check=False,
    )
    assert proc.returncode == 0, proc.stderr
    return proc.stdout.strip()


def _modules_added_by(code: str) -> set[str]:
    probe = textwrap.dedent(
        f"""
        import sys
        before = set(sys.modules)
        {code}
        new = sorted(set(sys.modules) - before - {{"w"}})
        print(",".join(new))
        """
    )
    return {m for m in _run(probe).split(",") if m}


def test_loading_the_worker_imports_nothing_new() -> None:
    """At module level the worker imports a few small standard-library modules and no
    codec library or ``archivey``, so each child imports only its own codec. What those
    modules pull in differs by build (free-threaded Python preloads less), so the
    allowance is what importing them directly adds in the same interpreter."""
    worker = str(decoder_child.WORKER)
    new = _modules_added_by(
        "import importlib.util; "
        f"spec = importlib.util.spec_from_file_location('w', {worker!r}); "
        "spec.loader.exec_module(importlib.util.module_from_spec(spec))"
    )
    allowed = _modules_added_by(
        "import importlib.util, __future__, marshal, signal, struct, enum"
    )
    assert new <= allowed, sorted(new - allowed)
    assert not {m for m in new if m.split(".")[0] in {"archivey", "pyppmd"}}


def test_loading_the_rapidgzip_worker_imports_no_archivey() -> None:
    """The child loads ``rapidgzip_worker.py`` by path with ``decoder_worker`` as
    ``__main__``. An ``archivey`` import there loads the whole library into every
    child, which ran unnoticed because the child's interpreter can import it."""
    worker = str(decoder_child.WORKER)
    rapidgzip = str(decoder_child.WORKER.with_name("rapidgzip_worker.py"))
    new = _modules_added_by(
        "import importlib.util; "
        f"d = importlib.util.spec_from_file_location('d', {worker!r}); "
        "dw = importlib.util.module_from_spec(d); d.loader.exec_module(dw); "
        "sys.modules['__main__'] = dw; "
        f"r = importlib.util.spec_from_file_location('r', {rapidgzip!r}); "
        "r.loader.exec_module(importlib.util.module_from_spec(r))"
    )
    assert not {m for m in new if m.split(".")[0] in {"archivey", "rapidgzip"}}, new


def test_turning_off_core_dumps_survives_a_python_without_ctypes() -> None:
    """A Python built without ``_ctypes`` (no libffi at build time, some minimal images)
    still runs the worker: turning dumps off is best effort, so a missing ``ctypes``
    skips the ``prctl`` step instead of ending the child before it decodes."""
    probe = textwrap.dedent(
        f"""
        import importlib.util, sys
        sys.modules["ctypes"] = None  # import ctypes now raises ImportError
        spec = importlib.util.spec_from_file_location("w", {str(decoder_child.WORKER)!r})
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        module.prepare_child()
        print("returned")
        """
    )
    assert _run(probe) == "returned"
