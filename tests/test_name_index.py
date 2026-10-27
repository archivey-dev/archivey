"""The listing's name index: one member per name, a list only for duplicates."""

from __future__ import annotations

import io
import warnings
import zipfile

import archivey


def _zip(names: list[str]) -> bytes:
    buf = io.BytesIO()
    with warnings.catch_warnings():
        warnings.simplefilter("ignore", UserWarning)  # zipfile warns on duplicates
        with zipfile.ZipFile(buf, "w") as zf:
            for i, name in enumerate(names):
                # A fixed timestamp: writestr(name) stamps the current time, so two
                # same-named members written across a 2-second DOS-time boundary
                # differ in `modified` and the equality the tests rely on fails.
                zf.writestr(zipfile.ZipInfo(name, (2020, 1, 1, 0, 0, 0)), f"{i}")
    return buf.getvalue()


def test_index_holds_duplicates_in_listing_order_and_drops_by_identity() -> None:
    with archivey.open_archive(io.BytesIO(_zip(["a", "b", "a", "a"]))) as reader:
        members = reader.members()
        first, second, third = (m for m in members if m.name == "a")
        assert first == second  # so removal by equality would take the wrong one
        held = reader._listed_named("a")
        assert len(held) == 3
        assert held[0] is first and held[1] is second and held[2] is third
        assert reader._last_by_exact_name("a") is third
        assert list(reader._listed_named("b")) == [members[1]]
        assert reader._listed_named("missing") == ()
        # A name listed once holds the member itself: no list object per member.
        assert reader._listed_by_name["b"] is members[1]

        # A member that is not in the entry leaves it as it is, list or not.
        entry = reader._listed_by_name["a"]
        reader._unindex_members("a", {id(members[1])})
        assert reader._listed_by_name["a"] is entry
        reader._unindex_members("b", {id(first)})
        assert reader._listed_by_name["b"] is members[1]

        reader._unindex_members("a", {id(second)})
        held = reader._listed_named("a")
        assert len(held) == 2 and held[0] is first and held[1] is third
        reader._unindex_members("a", {id(first)})
        assert reader._listed_by_name["a"] is third
        assert reader._last_by_exact_name("a") is third
        reader._unindex_members("a", {id(third)})
        assert reader._listed_named("a") == ()
        assert reader._last_by_exact_name("a") is None


def test_dropping_same_named_members_keeps_the_others_reachable() -> None:
    names = ["a", "b", "a", "a", "a", "c"]
    with archivey.open_archive(io.BytesIO(_zip(names))) as reader:
        members = reader.members()
        a1, a2, a3, a4 = (m for m in members if m.name == "a")
        reader._drop_listed([a1, a3, members[1]])
        held = reader._listed_named("a")
        assert len(held) == 2 and held[0] is a2 and held[1] is a4
        assert reader._last_by_exact_name("a") is a4
        assert reader._listed_named("b") == ()
        assert reader._last_by_exact_name("c") is members[5]
        # Down to one, the entry is the member again.
        reader._drop_listed([a2])
        assert reader._listed_by_name["a"] is a4


def test_dropping_every_member_of_a_shared_name_removes_the_entry() -> None:
    with archivey.open_archive(io.BytesIO(_zip(["a", "b", "a", "a"]))) as reader:
        members = reader.members()
        assert isinstance(reader._listed_by_name["a"], list)
        reader._drop_listed([m for m in members if m.name == "a"])
        assert "a" not in reader._listed_by_name
        assert reader._last_by_exact_name("b") is members[1]
