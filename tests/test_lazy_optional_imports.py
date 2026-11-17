"""Importing archivey does not import the optional packages that re-enable the GIL.

On a free-threaded CPython, importing an extension module that has not declared
free-thread support re-enables the GIL for the whole process. pyppmd, inflate64, brotli
and rapidgzip are such modules, so ``codecs/deps.py`` finds them without importing them and
imports each one only when a stream needs it (``LazyOptional``). These tests run a
fresh interpreter, because this pytest process has imported them already.
"""

from __future__ import annotations

import bz2
import importlib.util
import io
import logging
import os
import subprocess
import sys
import sysconfig
import textwrap
from pathlib import Path

import pytest

from archivey.exceptions import ResourceLimitError
from archivey.internal.config import AcceleratorMode, StreamConfig
from archivey.internal.streams import codecs
from tests.conftest import has_package, importorskip

_GIL_REENABLING = ("pyppmd", "inflate64", "brotli", "rapidgzip")

_PROBE = textwrap.dedent(
    """
    import sys
    import archivey
    from archivey import list_supported_formats

    list_supported_formats()
    print("imported=" + ",".join(m for m in {names!r} if m in sys.modules))
    print(sys._is_gil_enabled() if hasattr(sys, "_is_gil_enabled") else "n/a")
    """
)


def test_import_and_format_listing_do_not_import_gil_reenabling_packages() -> None:
    # ``find_spec``, not ``has_package``: the claim is that archivey never imports
    # these, which holds for an installed package it does not use (under PyPy) too.
    installed = [m for m in _GIL_REENABLING if importlib.util.find_spec(m)]
    if not installed:
        # The free-threaded CI job sets this on the step that installs them, so that
        # step cannot pass by skipping.
        if os.environ.get("ARCHIVEY_EXPECT_GIL_REENABLING_PACKAGES"):
            pytest.fail(f"none of {_GIL_REENABLING} is installed")
        pytest.skip(
            f"none of {_GIL_REENABLING} is installed; nothing to leave unimported"
        )
    proc = subprocess.run(
        [sys.executable, "-W", "ignore", "-c", _PROBE.format(names=_GIL_REENABLING)],
        capture_output=True,
        text=True,
        timeout=60,
        check=True,
    )
    imported, gil = proc.stdout.strip().splitlines()
    assert imported == "imported=", f"importing archivey {imported}"
    if sysconfig.get_config_var("Py_GIL_DISABLED"):
        assert gil == "False", "importing archivey re-enabled the GIL"


_DECODE_PROBE = textwrap.dedent(
    """
    import io, struct, sys
    from archivey.config import ProcessIsolation
    from archivey.internal.config import StreamConfig
    from archivey.internal.streams.codecs import Codec, CodecParams, open_codec_stream

    def read(codec, data, params, isolation):
        config = StreamConfig(process_isolation=isolation)
        with open_codec_stream(codec, io.BytesIO(data), params=params, config=config) as s:
            return s.read()

    native = ProcessIsolation.NATIVE_DECODERS
    payload = b"isolated " * 100
    # Encoded beforehand by the test.
    brotli_data, deflate64_data, ppmd_data = {brotli!r}, {deflate64!r}, {ppmd!r}
    assert read(Codec.DEFLATE64, deflate64_data, CodecParams(), native) == payload
    if brotli_data:
        assert read(Codec.BROTLI, brotli_data, CodecParams(), native) == payload
    if ppmd_data:
        params = CodecParams(
            properties=struct.pack("<BL", 6, 16 << 20),
            unpack_size=len(payload),
            pack_size=len(ppmd_data),
        )
        assert read(Codec.PPMD, ppmd_data, params, native) == payload
        # The default decodes every PPMd member in a child too.
        assert read(Codec.PPMD, ppmd_data, params, ProcessIsolation.KNOWN_CRASHES) == payload
    print("imported=" + ",".join(m for m in {names!r} if m in sys.modules))
    """
)


def test_isolated_decoders_are_not_imported_by_the_caller() -> None:
    """Under ``NATIVE_DECODERS`` brotli, inflate64 and pyppmd decode in a child and the
    caller never imports them; nor pyppmd by default (every PPMd member decodes in a
    child)."""
    inflate64 = importorskip("inflate64")

    payload = b"isolated " * 100
    deflater = inflate64.Deflater()
    deflate64_data = deflater.deflate(payload) + deflater.flush()
    brotli_data = b""
    if has_package("brotli"):
        import brotli

        brotli_data = brotli.compress(payload)
    ppmd_data = b""
    if has_package("pyppmd"):
        import pyppmd

        encoder = pyppmd.Ppmd7Encoder(6, 16 << 20)
        ppmd_data = encoder.encode(payload) + encoder.flush()
    probe = _DECODE_PROBE.format(
        brotli=brotli_data,
        deflate64=deflate64_data,
        ppmd=ppmd_data,
        names=_GIL_REENABLING,
    )
    proc = subprocess.run(
        [sys.executable, "-W", "ignore", "-c", probe],
        capture_output=True,
        text=True,
        timeout=120,
        check=False,
    )
    assert proc.returncode == 0, proc.stderr
    assert proc.stdout.strip() == "imported=", proc.stdout


def test_lazy_optional_looks_up_without_importing(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    lazy = codecs.deps.LazyOptional("archivey_no_such_package")
    assert not lazy.available()
    assert lazy.load() is None
    assert lazy.loaded() is None

    name = "archivey_lazy_optional_stub"
    (tmp_path / f"{name}.py").write_text("")
    monkeypatch.syspath_prepend(str(tmp_path))
    monkeypatch.delitem(sys.modules, name, raising=False)
    present = codecs.deps.LazyOptional(name)
    assert present.available()
    assert present.loaded() is None
    assert name not in sys.modules
    module = present.load()
    assert module is not None and module is sys.modules[name]
    assert present.loaded() is module


@pytest.fixture
def broken_package(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> str:
    """A package that ``find_spec`` finds and that raises when imported."""
    name = "archivey_broken_optional_stub"
    (tmp_path / name).mkdir()
    (tmp_path / name / "__init__.py").write_text(
        "raise OSError('libstdc++.so.6: cannot open shared object file')\n"
    )
    monkeypatch.syspath_prepend(str(tmp_path))
    return name


def test_lazy_optional_treats_a_failed_import_as_absent(
    broken_package: str, caplog: pytest.LogCaptureFixture
) -> None:
    lazy = codecs.deps.LazyOptional(broken_package)
    assert lazy.available()
    with caplog.at_level(logging.WARNING, logger="archivey.streams"):
        assert lazy.load() is None
        assert lazy.load() is None
    assert lazy.loaded() is None
    messages = [r.getMessage() for r in caplog.records]
    assert len(messages) == 1, messages
    assert "failed to import" in messages[0] and "libstdc++" in messages[0]


def test_bzip2_auto_falls_back_when_the_child_cannot_import_rapidgzip(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """rapidgzip's bzip2 decoder runs in a child process, so a rapidgzip that fails to
    import fails there, as a start failure: ``AUTO`` reads with the standard library and
    ``ON`` raises ``ResourceLimitError``. This process never imports it."""
    stub = tmp_path / "stub" / "rapidgzip"
    stub.mkdir(parents=True)
    (stub / "__init__.py").write_text(
        "raise ImportError('libstdc++.so.6: cannot open shared object file')\n"
    )
    monkeypatch.setenv("PYTHONPATH", str(stub.parent))
    monkeypatch.setattr(
        codecs.deps, "rapidgzip", codecs.deps.LazyOptional("rapidgzip", present=True)
    )
    monkeypatch.setattr(codecs.rapidgzip_select, "_child_fallback_warned", set())
    # The stub fails at import before any rapidgzip code runs, so PyPy, where archivey
    # otherwise never starts the child, takes the same path.
    monkeypatch.setattr(codecs.deps, "UNDER_PYPY", False)
    data = b"hello bzip2 " * 1000
    auto = StreamConfig(seekable=True)
    assert auto.use_indexed_bzip2 is AcceleratorMode.AUTO
    with codecs.open_codec_stream(
        codecs.Codec.BZIP2, io.BytesIO(bz2.compress(data)), config=auto
    ) as stream:
        assert stream.read() == data

    on = StreamConfig(seekable=True, use_indexed_bzip2=AcceleratorMode.ON)
    with pytest.raises(ResourceLimitError, match="cannot import rapidgzip"):
        codecs.open_codec_stream(
            codecs.Codec.BZIP2, io.BytesIO(bz2.compress(data)), config=on
        )
