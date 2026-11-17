"""The dependency index that extraction's LinkWatch and the Debian reader share."""

from __future__ import annotations

from archivey.internal.dependency_index import DependencyIndex, IndexNode


def _record(index: DependencyIndex[str], link: str, *paths: tuple[str, ...]) -> None:
    nodes: list[IndexNode[str]] = []
    for path in paths:
        nodes.extend(index.path(path)[1:])
    index.record(link, nodes)


def _size(node: IndexNode[str]) -> int:
    return 1 + sum(_size(child) for child in node.children.values())


def test_dependents_are_the_links_that_looked_a_path_up() -> None:
    index: DependencyIndex[str] = DependencyIndex()
    _record(index, "l1", ("a", "b"))
    _record(index, "l2", ("a", "c"))
    assert index.dependents(("a",)) == ["l1", "l2"]
    assert index.dependents(("a", "b")) == ["l1"]
    assert index.dependents(("a", "x")) == []
    assert index.dependents(("z",)) == []


def test_a_new_record_replaces_the_old_one_and_frees_its_nodes() -> None:
    index: DependencyIndex[str] = DependencyIndex()
    _record(index, "l", ("a", "b", "c"))
    # The new walk keeps ``a`` and leaves ``a/b/c``: ``a`` stays in the tree, attached,
    # although the old record held it too.
    _record(index, "l", ("a", "d"))
    assert index.dependents(("a",)) == ["l"]
    assert index.dependents(("a", "b")) == []
    assert index.dependents(("a", "d")) == ["l"]
    assert _size(index.root) == 3


def test_forget_leaves_no_nodes_behind() -> None:
    index: DependencyIndex[str] = DependencyIndex()
    for round_ in range(100):
        _record(index, "l", ("a", f"route{round_}", "x"))
    _record(index, "other", ("a", "kept"))
    assert _size(index.root) == 5
    index.forget("l")
    assert _size(index.root) == 3
    assert index.dependents(("a",)) == ["other"]


def test_prune_keeps_a_start_node_a_link_looked_up() -> None:
    index: DependencyIndex[str] = DependencyIndex()
    _record(index, "l", ("a",))
    start = index.path(("a", "b", "c"))[-1]
    index.prune(start)
    assert _size(index.root) == 2
    assert index.dependents(("a",)) == ["l"]


def test_a_new_record_keeps_a_node_only_the_old_one_held() -> None:
    # ``a`` was held by the old record alone, and the new walk looks it up again:
    # letting the old record go first would detach ``a`` before the new one is added.
    index: DependencyIndex[str] = DependencyIndex()
    _record(index, "l", ("a", "b"))
    _record(index, "l", ("a",))
    assert index.dependents(("a",)) == ["l"]
    assert _size(index.root) == 2
