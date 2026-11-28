"""Readers and codecs that will leave core are written on public names only.

The plugin plan moves 13 readers and seven stream codecs out of the ``archivey``
distribution. Before any of them moves, each is ported in place until its module
imports nothing from ``archivey.internal`` and reads no private attribute of an
archivey object, as a format written outside archivey would have to. This test is
the definition of done for a port: a module joins ``PUBLIC_ONLY_MODULES`` in the pull
request that ports it, and the test then keeps it there.

An import check alone is not enough. A reader can import only public names and still
reach into ``ReaderContext`` through ``context._nest``, which no outside package can
rely on. So the test checks both.
"""

from __future__ import annotations

import importlib
from pathlib import Path

import pytest

from tests.public_names import assert_only_public_archivey, foreign_private_reads

# The modules that use public names only. A ported module goes in here in the pull
# request that ports it; none comes out again.
PUBLIC_ONLY_MODULES = (
    "archivey.internal.backends.ar_reader",
    "archivey.internal.backends.cpio_reader",
    "archivey.internal.backends.rpm_reader",
    "archivey.internal.backends.xar_reader",
    "archivey.internal.backends.pkg_reader",
    "archivey.internal.backends.deb_reader",
)

# Modules that leave core in one package, as the plan's packages group them. A module
# may use what the others of its package define, private names too, since they ship
# and change together: pkg's reader extends xar's, and deb's salvage reuses ar's header
# search and confirmation.
SAME_PACKAGE = (
    (
        "archivey.internal.backends.xar_reader",
        "archivey.internal.backends.pkg_reader",
    ),
    (
        "archivey.internal.backends.ar_reader",
        "archivey.internal.backends.deb_reader",
    ),
)


def _siblings(module_name: str) -> tuple[str, ...]:
    for package in SAME_PACKAGE:
        if module_name in package:
            return tuple(m for m in package if m != module_name)
    return ()


def _source(module_name: str) -> Path:
    module_file = importlib.import_module(module_name).__file__
    assert module_file is not None, module_name
    return Path(module_file)


@pytest.mark.parametrize("module_name", PUBLIC_ONLY_MODULES)
def test_the_module_imports_only_public_names(module_name: str) -> None:
    assert_only_public_archivey(
        str(_source(module_name)), siblings=_siblings(module_name)
    )


@pytest.mark.parametrize("module_name", PUBLIC_ONLY_MODULES)
def test_the_module_reads_no_private_archivey_attribute(module_name: str) -> None:
    siblings = [_source(sibling) for sibling in _siblings(module_name)]
    assert foreign_private_reads(_source(module_name), siblings=siblings) == []


def test_the_list_holds_each_module_once() -> None:
    assert len(set(PUBLIC_ONLY_MODULES)) == len(PUBLIC_ONLY_MODULES)


def test_a_package_holds_only_ported_modules_each_in_one_package() -> None:
    """A sibling's names are allowed because the sibling is held to public names
    too; a module in no package's list, or in two, would let that slip."""
    grouped = [module for package in SAME_PACKAGE for module in package]
    assert len(set(grouped)) == len(grouped)
    assert set(grouped) <= set(PUBLIC_ONLY_MODULES)


def test_the_import_guard_admits_a_sibling_and_nothing_else_internal(
    tmp_path: Path,
) -> None:
    probe = tmp_path / "probe.py"
    probe.write_text(
        "from archivey.internal.backends.xar_reader import _HEADER, XarReader\n",
        encoding="utf-8",
    )
    assert_only_public_archivey(
        str(probe), siblings=("archivey.internal.backends.xar_reader",)
    )
    with pytest.raises(AssertionError):
        assert_only_public_archivey(
            str(probe), siblings=("archivey.internal.backends.cpio_reader",)
        )


def test_the_attribute_guard_admits_the_private_names_a_sibling_defines(
    tmp_path: Path,
) -> None:
    """pkg's reader reads ``self._context``, which xar's reader, its base, sets."""
    base = tmp_path / "base.py"
    base.write_text(
        "class Base:\n    def __init__(self, context):\n        self._context = context\n",
        encoding="utf-8",
    )
    probe = tmp_path / "probe.py"
    probe.write_text(
        "def f(reader, source):\n    return reader._context, source._origin\n",
        encoding="utf-8",
    )
    assert foreign_private_reads(probe, siblings=[base]) == [
        "probe.py:2 source._origin"
    ]
    assert foreign_private_reads(probe) == [
        "probe.py:2 reader._context",
        "probe.py:2 source._origin",
    ]


def test_the_import_guard_sees_an_internal_import(tmp_path: Path) -> None:
    probe = tmp_path / "probe.py"
    probe.write_text(
        "from archivey.internal.registry import get_registry\n", encoding="utf-8"
    )
    with pytest.raises(AssertionError):
        assert_only_public_archivey(str(probe))


def test_the_import_guard_sees_a_private_name_of_a_public_module(
    tmp_path: Path,
) -> None:
    probe = tmp_path / "probe.py"
    probe.write_text("from archivey.formats import _not_public\n", encoding="utf-8")
    with pytest.raises(AssertionError):
        assert_only_public_archivey(str(probe))


def test_the_attribute_guard_sees_a_read_of_a_core_private_attribute(
    tmp_path: Path,
) -> None:
    probe = tmp_path / "probe.py"
    probe.write_text(
        "def read(context, source):\n    context._nest()\n    return source._origin\n",
        encoding="utf-8",
    )
    assert foreign_private_reads(probe) == [
        "probe.py:2 context._nest",
        "probe.py:3 source._origin",
    ]


def test_the_attribute_guard_admits_the_modules_own_private_names(
    tmp_path: Path,
) -> None:
    """A module may use the private names it defines itself, on any of its own
    objects: rpm's member stream calls ``reader._next_entry`` on its reader."""
    probe = tmp_path / "probe.py"
    probe.write_text(
        "class _Reader:\n"
        "    _limit = 4\n"
        "    def __init__(self):\n"
        "        self._seen = set()\n"
        "    def _next_entry(self):\n"
        "        return self._limit, self.__class__\n"
        "def walk(reader: _Reader, context):\n"
        "    reader._seen.add(reader._next_entry())\n"
        "    return reader._limit, context._usage\n",
        encoding="utf-8",
    )
    assert foreign_private_reads(probe) == ["probe.py:9 context._usage"]


def test_the_attribute_guard_admits_the_named_tuple_api(tmp_path: Path) -> None:
    probe = tmp_path / "probe.py"
    probe.write_text(
        "def move(locator):\n    return locator._replace(offset=0)\n", encoding="utf-8"
    )
    assert foreign_private_reads(probe) == []


def test_the_attribute_guard_sees_a_write_to_a_core_private_attribute(
    tmp_path: Path,
) -> None:
    """A write onto another object is a dependency on its state, and does not make
    the name the module's own: later reads of it are still reported."""
    probe = tmp_path / "probe.py"
    probe.write_text(
        "def f(context, source):\n"
        "    context._nest = 1\n"
        "    source._origin += 1\n"
        "    return context._nest\n",
        encoding="utf-8",
    )
    assert foreign_private_reads(probe) == [
        "probe.py:2 context._nest",
        "probe.py:3 source._origin",
        "probe.py:4 context._nest",
    ]
