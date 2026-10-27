"""The extra-bag overload list matches the keys backends actually write.

The ``str → object`` fallback accepts any misspelled key, so nothing in the
type itself keeps the register complete. This test is that guard:
``typing.get_overloads`` minus the fallback must equal the keys written under
``src/archivey/``. Deleting one known-key overload (the check used
``zip.compress_type``) turns it red. Test-only keys (``synthetic.header_len``)
stay on an allowlist.

Matching is by constructor, not local name, including constructors nested in
``if`` / ``for`` / ``with`` / ``try`` and functions defined inside those
blocks: a ``MemberExtra()`` bound to ``bag`` then ``bag["zip.foo"] = 1`` is a
member write, and ``info.extra[...]`` on an ``ArchiveInfo`` parameter is an
archive-info write. An unannotated ``.extra`` (``some_info.extra[...]``) is
known to name a bag but not which one: those keys are checked against both
registers together, not guessed as member. A ``MemberExtra(...)`` /
``ArchiveInfoExtra(...)`` whose first argument is not a dict literal raises,
rather than skipping the site.

The ``Known keys:`` bullets in each class docstring are the published copy
(``docs/formats.md`` points at them). Those keys and type strings must match
the overload register; adding an overload without its bullet turns it red.
"""

from __future__ import annotations

import ast
import re
import types
import typing
from pathlib import Path

import pytest

from archivey.types import (
    EXTRA_ALTERNATE_RAW_NAME,
    EXTRA_IS_FILE_COPY,
    EXTRA_IS_JUNCTION,
    EXTRA_IS_REPARSE_POINT,
    EXTRA_RAR_EXTRACT_VERSION,
    EXTRA_SIZE_MOD_2_32,
    EXTRA_SPECIAL_FILE_TYPE,
    ArchiveInfoExtra,
    MemberExtra,
)

REPO_SRC = Path(__file__).resolve().parents[1] / "src" / "archivey"
REPO_TESTS = Path(__file__).resolve().parents[0]

_CONST_KEYS = {
    "EXTRA_ALTERNATE_RAW_NAME": EXTRA_ALTERNATE_RAW_NAME,
    "EXTRA_IS_FILE_COPY": EXTRA_IS_FILE_COPY,
    "EXTRA_IS_JUNCTION": EXTRA_IS_JUNCTION,
    "EXTRA_IS_REPARSE_POINT": EXTRA_IS_REPARSE_POINT,
    "EXTRA_RAR_EXTRACT_VERSION": EXTRA_RAR_EXTRACT_VERSION,
    "EXTRA_SIZE_MOD_2_32": EXTRA_SIZE_MOD_2_32,
    "EXTRA_SPECIAL_FILE_TYPE": EXTRA_SPECIAL_FILE_TYPE,
}

# Written by tests, not by the library. See tests/test_codec_descriptor.py
# (`synthetic.header_len`), tests/test_data_model.py (open-bag example) and
# tests/test_plugins.py (a plugin's own `ArchiveInfo` key, `solid.blocks`).
_TEST_ONLY_EXTRA_KEYS = frozenset(
    {"synthetic.header_len", "third.party", "solid.blocks"}
)

_CTOR_KIND = {"MemberExtra": "member", "ArchiveInfoExtra": "info"}
_ANN_KIND = {
    "MemberExtra": "member",
    "ArchiveInfoExtra": "info",
    "ArchiveMember": "member_obj",
    "ArchiveInfo": "info_obj",
}

_KNOWN_KEY_BULLET = re.compile(
    r"^\s*\* ``(?P<key>[^`]+)`` \(``(?P<type>[^`]+)``\)",
    re.MULTILINE,
)


def _literal_keys(mapping_cls: type) -> set[str]:
    return set(_overload_key_types(mapping_cls))


def _type_as_doc(ann: object) -> str:
    """Render an annotation as the ``Known keys:`` bullets write it: bare class names.

    ``typing.get_type_hints`` resolves ``Mapping[str, str]`` to a ``collections.abc``
    generic alias, and ``str()`` of that alias is module-qualified on every Python
    (``collections.abc.Mapping[str, str]``). So the bare-name form is rebuilt from the
    origin and its args instead of taken from ``str()``. A union is not a generic
    alias; it falls through to ``str()``, which already renders ``int | None``.
    """
    if isinstance(ann, list):  # the parameter list of a Callable
        return "[" + ", ".join(_type_as_doc(arg) for arg in ann) + "]"
    origin = typing.get_origin(ann)
    if origin is typing.Literal:
        # A closed string set documents as ``"a" | "b"``, wrapped across lines
        # when long; the bullet reader collapses that whitespace.
        return " | ".join(f'"{value}"' for value in typing.get_args(ann))
    if isinstance(origin, type) and origin is not types.UnionType:
        args = ", ".join(
            "..." if arg is Ellipsis else _type_as_doc(arg)
            for arg in typing.get_args(ann)
        )
        return f"{origin.__name__}[{args}]"
    if isinstance(ann, type):
        return ann.__name__
    return str(ann)


def _overload_key_types(mapping_cls: type) -> dict[str, str]:
    keys: dict[str, str] = {}
    saw_fallback = False
    for fn in typing.get_overloads(mapping_cls.__getitem__):
        hints = typing.get_type_hints(fn)
        key_ann = hints.get("key")
        if key_ann is str:
            saw_fallback = True
            continue
        origin = typing.get_origin(key_ann)
        if origin is not typing.Literal:
            raise AssertionError(
                f"{mapping_cls.__name__} has unexpected key annotation {key_ann!r}"
            )
        ret = hints.get("return")
        if ret is None:
            raise AssertionError(
                f"{mapping_cls.__name__} overload for {key_ann!r} has no return type"
            )
        doc_type = _type_as_doc(ret)
        for arg in typing.get_args(key_ann):
            if isinstance(arg, str):
                keys[arg] = doc_type
    assert saw_fallback, f"{mapping_cls.__name__} is missing the str → object fallback"
    return keys


def _docstring_key_types(mapping_cls: type) -> dict[str, str]:
    doc = mapping_cls.__doc__
    if doc is None:
        raise AssertionError(f"{mapping_cls.__name__} has no docstring")
    marker = "Known keys:"
    idx = doc.find(marker)
    if idx < 0:
        raise AssertionError(
            f"{mapping_cls.__name__} docstring has no Known keys section"
        )
    found: dict[str, str] = {}
    for match in _KNOWN_KEY_BULLET.finditer(doc[idx + len(marker) :]):
        key = match.group("key")
        if key in found:
            raise AssertionError(f"{mapping_cls.__name__} docstring repeats {key!r}")
        found[key] = " ".join(match.group("type").split())
    if not found:
        raise AssertionError(f"{mapping_cls.__name__} Known keys: section is empty")
    return found


def _assert_doc_matches_overloads(mapping_cls: type) -> None:
    declared = _overload_key_types(mapping_cls)
    documented = _docstring_key_types(mapping_cls)
    if documented != declared:
        missing = sorted(set(declared) - set(documented))
        extra = sorted(set(documented) - set(declared))
        drifted = sorted(
            k for k in set(declared) & set(documented) if declared[k] != documented[k]
        )
        raise AssertionError(
            f"{mapping_cls.__name__} docstring keys != overloads; "
            f"missing bullets {missing}; extra bullets {extra}; "
            f"type drift {[(k, documented[k], declared[k]) for k in drifted]}"
        )


def _name_or_attr(node: ast.AST) -> str | None:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        return node.attr
    return None


def _call_ctor(func: ast.AST) -> str | None:
    name = _name_or_attr(func)
    return name if name in _CTOR_KIND else None


def _annotation_kind(node: ast.AST | None) -> str | None:
    if node is None:
        return None
    name = _name_or_attr(node)
    return _ANN_KIND.get(name) if name is not None else None


def _value_kind(node: ast.AST) -> str | None:
    if isinstance(node, ast.Call):
        ctor = _call_ctor(node.func)
        return _CTOR_KIND.get(ctor) if ctor is not None else None
    if isinstance(node, ast.IfExp):
        body = _value_kind(node.body)
        orelse = _value_kind(node.orelse)
        return body if body == orelse else body or orelse
    return None


_NESTED_SCOPE = (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)


def _bind_stmt(stmt: ast.stmt, bound: dict[str, str]) -> None:
    if isinstance(stmt, ast.Assign):
        kind = _value_kind(stmt.value)
        if kind is None:
            return
        for target in stmt.targets:
            if isinstance(target, ast.Name):
                bound[target.id] = kind
    elif (
        isinstance(stmt, ast.AnnAssign)
        and isinstance(stmt.target, ast.Name)
        and stmt.value is not None
    ):
        kind = _annotation_kind(stmt.annotation) or _value_kind(stmt.value)
        if kind is not None:
            bound[stmt.target.id] = kind


def _key_from_slice(node: ast.AST) -> str | None:
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value
    if isinstance(node, ast.Name) and node.id in _CONST_KEYS:
        return _CONST_KEYS[node.id]
    return None


def _keys_from_dict(node: ast.Dict) -> set[str]:
    keys: set[str] = set()
    for key in node.keys:
        if key is None:
            continue
        if isinstance(key, ast.Constant) and isinstance(key.value, str):
            keys.add(key.value)
        elif isinstance(key, ast.Name) and key.id in _CONST_KEYS:
            keys.add(_CONST_KEYS[key.id])
    return keys


def _collect_ctor_keys(
    node: ast.Call, path: Path, member: set[str], info: set[str]
) -> None:
    ctor = _call_ctor(node.func)
    if ctor is None:
        return
    bucket = member if ctor == "MemberExtra" else info
    if not node.args:
        if node.keywords:
            raise AssertionError(
                f"{path.as_posix()}: {ctor}(...) uses keyword arguments; "
                "the inventory guard cannot see its keys"
            )
        return
    arg0 = node.args[0]
    if not isinstance(arg0, ast.Dict) or node.keywords:
        raise AssertionError(
            f"{path.as_posix()}: {ctor}(...) first argument is not a dict "
            "literal; the inventory guard cannot see its keys"
        )
    bucket |= _keys_from_dict(arg0)


def _bucket_for_subscript(target: ast.AST, bound: dict[str, str]) -> str | None:
    if isinstance(target, ast.Name):
        kind = bound.get(target.id)
        if kind in {"member", "member_obj"}:
            return "member"
        if kind in {"info", "info_obj"}:
            return "info"
        return None
    if isinstance(target, ast.Attribute) and target.attr == "extra":
        owner = target.value
        if isinstance(owner, ast.Name):
            kind = bound.get(owner.id)
            if kind in {"info", "info_obj"}:
                return "info"
            if kind in {"member", "member_obj"}:
                return "member"
        # Unannotated ``.extra`` names a bag; we do not guess which. Checked
        # against both registers together so a valid archive-info key is not
        # reported as an undeclared member write.
        return "either"
    return None


def _fn_arg_bound(fn: ast.FunctionDef | ast.AsyncFunctionDef) -> dict[str, str]:
    bound: dict[str, str] = {}
    for arg in (*fn.args.posonlyargs, *fn.args.args, *fn.args.kwonlyargs):
        kind = _annotation_kind(arg.annotation)
        if kind is not None:
            bound[arg.arg] = kind
    return bound


def _bind_tree(node: ast.AST, bound: dict[str, str]) -> None:
    """Bind constructor names in this node, skipping nested function/class scopes."""
    if isinstance(node, ast.stmt):
        _bind_stmt(node, bound)
    if isinstance(node, ast.NamedExpr) and isinstance(node.target, ast.Name):
        kind = _value_kind(node.value)
        if kind is not None:
            bound[node.target.id] = kind
    for child in ast.iter_child_nodes(node):
        if isinstance(child, _NESTED_SCOPE):
            continue
        _bind_tree(child, bound)


def _written_keys_from_tree(
    tree: ast.AST, path: Path
) -> tuple[set[str], set[str], set[str]]:
    member: set[str] = set()
    info: set[str] = set()
    either: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Call):
            _collect_ctor_keys(node, path, member, info)

    def scan_scope(body: list[ast.stmt], bound: dict[str, str]) -> None:
        local = dict(bound)
        for stmt in body:
            _bind_tree(stmt, local)

        def walk_writes(node: ast.AST) -> None:
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                scan_scope(node.body, {**local, **_fn_arg_bound(node)})
                return
            if isinstance(node, ast.ClassDef):
                scan_scope(node.body, local)
                return
            if isinstance(node, ast.Subscript):
                key = _key_from_slice(node.slice)
                if key is not None:
                    bucket = _bucket_for_subscript(node.value, local)
                    if bucket == "info":
                        info.add(key)
                    elif bucket == "member":
                        member.add(key)
                    elif bucket == "either":
                        either.add(key)
            for child in ast.iter_child_nodes(node):
                walk_writes(child)

        for stmt in body:
            walk_writes(stmt)

    if isinstance(tree, ast.Module):
        scan_scope(tree.body, {})
    return member, info, either


def _written_keys_from_source(
    source: str, path: Path
) -> tuple[set[str], set[str], set[str]]:
    return _written_keys_from_tree(ast.parse(source), path)


def _written_keys(root: Path) -> tuple[set[str], set[str], set[str]]:
    member: set[str] = set()
    info: set[str] = set()
    either: set[str] = set()
    for path in root.rglob("*.py"):
        tree = ast.parse(path.read_text(encoding="utf-8"))
        written_member, written_info, written_either = _written_keys_from_tree(
            tree, path
        )
        member |= written_member
        info |= written_info
        either |= written_either
    return member, info, either


def _assert_overloads_match_writes(
    mapping_cls: type, written: set[str], either: set[str]
) -> None:
    declared = _literal_keys(mapping_cls)
    no_overload = written - declared
    unused = declared - written - (either & declared)
    if no_overload or unused:
        raise AssertionError(
            f"{mapping_cls.__name__}: writes with no overload "
            f"{sorted(no_overload)}; unused overloads {sorted(unused)}"
        )


def test_member_extra_overloads_match_src_writers() -> None:
    written, _, either = _written_keys(REPO_SRC)
    _assert_overloads_match_writes(MemberExtra, written, either)


def test_archive_info_extra_overloads_match_src_writers() -> None:
    _, written, either = _written_keys(REPO_SRC)
    _assert_overloads_match_writes(ArchiveInfoExtra, written, either)


def test_unannotated_extra_keys_are_in_some_register() -> None:
    declared = _literal_keys(MemberExtra) | _literal_keys(ArchiveInfoExtra)
    _, _, either = _written_keys(REPO_SRC)
    unknown = either - declared
    assert not unknown, f"unknown - declared {sorted(unknown)}"


def test_tests_do_not_invent_undeclared_extra_keys() -> None:
    declared = _literal_keys(MemberExtra) | _literal_keys(ArchiveInfoExtra)
    written_member, written_info, written_either = _written_keys(REPO_TESTS)
    unexpected = (
        (written_member | written_info | written_either)
        - declared
        - _TEST_ONLY_EXTRA_KEYS
    )
    assert not unexpected, (
        f"test-only extra keys missing from allowlist: {sorted(unexpected)}"
    )


def _is_final(annotation: ast.expr) -> bool:
    # Bare ``Final`` only: ``Final[str]`` widens the constant just like no annotation.
    return (isinstance(annotation, ast.Name) and annotation.id == "Final") or (
        isinstance(annotation, ast.Attribute) and annotation.attr == "Final"
    )


def _extra_key_constants(source: str, known_keys: set[str]) -> dict[str, bool]:
    """Every ``NAME = "<str>"`` in *source* that names an extra key, and if it is Final.

    Walks the whole tree, so a constant declared inside an ``if`` or ``try`` counts,
    and selects by the ``EXTRA_`` prefix *or* by a value that is a known key, so a
    constant named off-convention is still seen.
    """
    found: dict[str, bool] = {}
    for node in ast.walk(ast.parse(source)):
        if isinstance(node, ast.AnnAssign):
            targets, value, final = (
                [node.target],
                node.value,
                _is_final(node.annotation),
            )
        elif isinstance(node, ast.Assign):
            targets, value, final = node.targets, node.value, False
        else:
            continue
        if not (isinstance(value, ast.Constant) and isinstance(value.value, str)):
            continue
        for target in targets:
            if isinstance(target, ast.Name) and (
                target.id.startswith("EXTRA_") or value.value in known_keys
            ):
                found[target.id] = found.get(target.id, True) and final
    return found


def test_extra_key_constants_are_final_and_registered() -> None:
    # Without ``Final`` mypy widens the constant to ``str``, so
    # ``extra[EXTRA_FOO]`` falls through to the ``str → object`` overload.
    # _CONST_KEYS must also list every constant or its writes go unseen.
    known_keys = _literal_keys(MemberExtra) | _literal_keys(ArchiveInfoExtra)
    constants = _extra_key_constants(
        (REPO_SRC / "types.py").read_text(encoding="utf-8"), known_keys
    )
    not_final = sorted(name for name, final in constants.items() if not final)
    assert not not_final, f"extra-key constants not annotated Final: {not_final}"
    unlisted = sorted(set(constants) - set(_CONST_KEYS))
    assert not unlisted, f"types.py constants missing from _CONST_KEYS: {unlisted}"
    stale = sorted(set(_CONST_KEYS) - set(constants))
    assert not stale, f"_CONST_KEYS names constants types.py lacks: {stale}"
    unknown = sorted(set(_CONST_KEYS.values()) - known_keys)
    assert not unknown, f"extra-key constants with no overload: {unknown}"


def test_extra_key_constant_scan_sees_nested_and_off_prefix() -> None:
    source = (
        "from typing import Final\n"
        "if True:\n"
        "    EXTRA_NESTED = 'zip.nested'\n"
        "JUNCTION_KEY = 'is_junction'\n"
        "EXTRA_OK: Final = 'rar.extract_version'\n"
        "OTHER = 'unrelated'\n"
    )
    assert _extra_key_constants(source, {"is_junction"}) == {
        "EXTRA_NESTED": False,
        "JUNCTION_KEY": False,
        "EXTRA_OK": True,
    }


def test_docstring_keys_match_overloads() -> None:
    _assert_doc_matches_overloads(MemberExtra)
    _assert_doc_matches_overloads(ArchiveInfoExtra)


def test_docstring_guard_fails_if_bullet_missing() -> None:
    original = MemberExtra.__doc__
    assert original is not None
    MemberExtra.__doc__ = original.replace("* ``zip.compress_type`` (``int``)\n", "")
    try:
        with pytest.raises(AssertionError, match="zip.compress_type"):
            _assert_doc_matches_overloads(MemberExtra)
    finally:
        MemberExtra.__doc__ = original


def test_inventory_sees_renamed_local() -> None:
    member, info, either = _written_keys_from_source(
        "bag = MemberExtra()\nbag['zip.foo'] = 1\n",
        Path("probe.py"),
    )
    assert member == {"zip.foo"}
    assert not info
    assert not either

    member, info, either = _written_keys_from_source(
        "def f() -> None:\n    bag = MemberExtra()\n    bag['zip.foo'] = 1\n",
        Path("probe.py"),
    )
    assert member == {"zip.foo"}
    assert not info
    assert not either


def test_inventory_sees_bind_inside_block() -> None:
    # K16: a bag constructed inside if/for/with/try was invisible because
    # _bind_stmt only ran on the top-level statements of a scope.
    probes = (
        "def f(x):\n    if x:\n        bag = MemberExtra()\n        bag['zip.nested'] = 1\n",
        "def f():\n    for _ in ():\n        bag = MemberExtra()\n        bag['zip.nested'] = 1\n",
        "def f():\n    with open(__file__):\n        bag = MemberExtra()\n        bag['zip.nested'] = 1\n",
        "def f():\n    try:\n        bag = MemberExtra()\n        bag['zip.nested'] = 1\n    except Exception:\n        pass\n",
        "if True:\n    def f():\n        bag = MemberExtra()\n        bag['zip.nested'] = 1\n",
        "if (bag := MemberExtra()):\n    bag['zip.nested'] = 1\n",
    )
    for source in probes:
        member, info, either = _written_keys_from_source(source, Path("probe.py"))
        assert member == {"zip.nested"}, source
        assert not info, source
        assert not either, source


def test_inventory_classifies_archive_info_attribute() -> None:
    member, info, either = _written_keys_from_source(
        "def f(info: ArchiveInfo) -> None:\n    info.extra['7z.volume_count'] = 1\n",
        Path("probe.py"),
    )
    assert info == {"7z.volume_count"}
    assert "7z.volume_count" not in member
    assert not either


def test_inventory_unannotated_extra_is_either_bag() -> None:
    member, info, either = _written_keys_from_source(
        "some_info.extra['7z.volume_count'] = 1\n",
        Path("probe.py"),
    )
    assert either == {"7z.volume_count"}
    assert "7z.volume_count" not in member
    assert not info

    declared = _literal_keys(MemberExtra) | _literal_keys(ArchiveInfoExtra)
    member, info, either = _written_keys_from_source(
        "whatever.extra['bogus.key'] = 1\n",
        Path("probe.py"),
    )
    assert either == {"bogus.key"}
    assert either - declared == {"bogus.key"}
    assert not member
    assert not info


def test_inventory_rejects_non_literal_ctor() -> None:
    with pytest.raises(AssertionError, match="not a dict literal"):
        _written_keys_from_source("MemberExtra(collected)\n", Path("probe.py"))
