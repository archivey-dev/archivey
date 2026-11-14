"""``FormatPolicy(only_libraries=)``: the allowlist form of ``exclude_libraries=``.

``tests/test_exclude_libraries.py`` runs every behaviour test under both forms; this file
holds what only the allowlist has: its construction rules, ``allows_library``, and the
guard that every check reads the combined set.
"""

from __future__ import annotations

import ast
import copy
import pickle
from pathlib import Path

import pytest

from archivey import (
    AcceleratorMode,
    ArchiveyConfig,
    ArchiveyUsageError,
    ContainerFormat,
    FormatPolicy,
    OptionalLibrary,
)
from archivey.internal.format_adapter import registration_scope
from tests.test_format_api import _plugin_with
from tests.test_format_policy import StdlibZipPlugin

C = ContainerFormat
L = OptionalLibrary
_SRC = Path(__file__).resolve().parents[1] / "src" / "archivey"


def test_the_default_allows_every_package() -> None:
    policy = FormatPolicy()
    assert policy.only_libraries is None
    assert all(policy.allows_library(lib) for lib in L)


def test_an_empty_allowlist_turns_every_package_off() -> None:
    policy = FormatPolicy(only_libraries=set())
    assert policy.only_libraries == frozenset()
    assert not any(policy.allows_library(lib) for lib in L)


def test_names_and_values_are_accepted_and_stored_as_members() -> None:
    policy = FormatPolicy(only_libraries={L.PYPPMD, "brotli"})
    assert policy.only_libraries == frozenset({L.PYPPMD, L.BROTLI})
    assert policy.allows_library("pyppmd")
    assert policy.allows_library(L.BROTLI)
    assert not policy.allows_library("lz4")
    assert not policy.allows_library("lz4.block")


@pytest.mark.parametrize(
    ("value", "match"),
    [
        ({"pyppm"}, "Accepted: 'pyppmd'"),
        ({"zlib"}, "standard library codecs cannot be turned off"),
        ("pyppmd", "bare string"),
    ],
)
def test_a_wrong_entry_is_refused(value: object, match: str) -> None:
    with pytest.raises(ArchiveyUsageError, match=match) as info:
        FormatPolicy(only_libraries=value)  # type: ignore[arg-type]
    assert "only_libraries=" in str(info.value)


def test_a_package_in_both_lists_is_refused() -> None:
    with pytest.raises(ArchiveyUsageError, match="both only_libraries= and"):
        FormatPolicy(only_libraries={"lz4", "brotli"}, exclude_libraries={"lz4"})


def test_both_lists_combine() -> None:
    policy = FormatPolicy(only_libraries={"lz4"}, exclude_libraries={"brotli"})
    assert policy.allows_library("lz4")
    assert not policy.allows_library("brotli")
    assert not policy.allows_library("pyppmd")


def test_a_module_that_is_not_an_optional_library_is_allowed() -> None:
    policy = FormatPolicy(only_libraries=set())
    assert policy.allows_library("zlib")
    assert policy.allows_library("my_plugin_codec")


def test_allows_library_refuses_a_non_string_and_is_case_sensitive() -> None:
    policy = FormatPolicy(only_libraries=set())
    for value in (None, b"lz4", 3):
        with pytest.raises(ArchiveyUsageError, match="allows_library"):
            policy.allows_library(value)  # type: ignore[arg-type]
    assert not policy.allows_library("lz4")
    # An exact import name only: another spelling is not an OptionalLibrary.
    assert policy.allows_library("LZ4")


class _NeedsCrypto(StdlibZipPlugin):
    requires = ("cryptography",)


def test_a_named_replacement_the_allowlist_leaves_without_its_package_is_refused() -> (
    None
):
    # Construction checks a named plugin's ``requires`` against both lists, so this
    # fails if it is checked against ``exclude_libraries`` alone.
    with pytest.raises(ArchiveyUsageError, match="_NeedsCrypto, which requires"):
        FormatPolicy(replace={C.ZIP: _NeedsCrypto}, only_libraries=set())
    FormatPolicy(replace={C.ZIP: _NeedsCrypto}, only_libraries={L.CRYPTOGRAPHY})


def test_a_plugin_listed_in_only_without_its_allowlisted_package_is_refused() -> None:
    with registration_scope():
        plugin = _plugin_with("needy", requires=("cryptography",))
        with pytest.raises(ArchiveyUsageError, match="only= lists"):
            FormatPolicy(only={plugin.format.container}, only_libraries=set())
        FormatPolicy(only={plugin.format.container}, only_libraries={L.CRYPTOGRAPHY})


def test_the_allowlist_takes_part_in_equality_and_survives_pickle() -> None:
    policy = FormatPolicy(only_libraries={"lz4"})
    assert policy == FormatPolicy(only_libraries={L.LZ4})
    assert policy != FormatPolicy()
    assert hash(policy) == hash(FormatPolicy(only_libraries={"lz4"}))
    for clone in (pickle.loads(pickle.dumps(policy)), copy.deepcopy(policy)):
        assert clone == policy
        assert not clone.allows_library("brotli")
    assert "only_libraries" in repr(policy)
    assert "_libraries_off" not in repr(policy)


def test_no_check_reads_exclude_libraries_alone() -> None:
    # Every check reads the combined set, so ``only_libraries`` cannot be skipped by a
    # code path that asks for ``exclude_libraries`` only.
    offenders = []
    for path in _SRC.rglob("*.py"):
        if path.name == "format_policy.py":
            continue
        for node in ast.walk(ast.parse(path.read_text(encoding="utf-8"))):
            if isinstance(node, ast.Attribute) and node.attr == "exclude_libraries":
                offenders.append(f"{path.relative_to(_SRC)}:{node.lineno}")
    assert offenders == []


@pytest.mark.parametrize("param", ["exclude_libraries", "only_libraries"])
def test_library_policy_reads_a_generator_once(param: str) -> None:
    # A generator is an Iterable, as the signature says: it must not be used up by
    # the validation and reach the conversion empty.
    policy = FormatPolicy(**{param: (name for name in ["brotli"])})
    assert getattr(policy, param) == frozenset({OptionalLibrary.BROTLI})


def test_library_policy_refuses_a_bad_name_in_a_generator() -> None:
    with pytest.raises(ValueError, match="TYPO"):
        FormatPolicy(exclude_libraries=iter(["TYPO"]))


def test_config_conflict_with_the_library_policy_is_a_value_error() -> None:
    with pytest.raises(ValueError, match="turns rapidgzip off"):
        ArchiveyConfig(
            use_rapidgzip=AcceleratorMode.ON,
            formats=FormatPolicy(exclude_libraries={"rapidgzip"}),
        )
