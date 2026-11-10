"""One rule for a hard link's target at extraction (maintainer decision, 2026-10-07).

A hard link's target must name an earlier member of the archive, and the member the
link gets its bytes from, the end of the hard-link chain, must not have been refused.
The target string gets no path check of its own: extraction links to the file that
member was written to, so the string never becomes a path. A link whose source the
policy refuses is refused too (``BLOCKED``), because otherwise the second pass would
write the refused member's bytes under the link's name. A refused link in the middle
of the chain does not refuse the links after it, and a hard link to a symlink is
written as that symlink and gets the symlink checks. A hard link to a symlink with no
target fails, whether or not the symlink was refused.
"""

from __future__ import annotations

import io
import os
import tarfile
from pathlib import Path
from typing import Any

import pytest

from archivey import (
    ExtractionPolicy,
    ExtractionResult,
    ExtractionStatus,
    OnError,
    open_archive,
    sanitize_names,
)
from archivey.exceptions import (
    ExtractionError,
    FilterRejectionError,
    LinkTargetNotFoundError,
)
from archivey.internal.filters import check_universal
from archivey.types import ArchiveMember, MemberType

_REFUSED = "Hardlink target was refused"
_MODES = pytest.mark.parametrize("streaming", [False, True], ids=["random", "stream"])
_POLICIES = pytest.mark.parametrize(
    "policy", list(ExtractionPolicy), ids=lambda p: p.name
)


def _tar(path: Path, entries: list[tuple[str, str | None]]) -> Path:
    """A tar of ``(name, linkname)`` entries: a regular file holding its own name
    when ``linkname`` is ``None``, a symlink to ``linkname`` after a ``sym:``
    prefix, else a hard link to ``linkname``."""
    with tarfile.open(path, "w", format=tarfile.GNU_FORMAT) as tf:
        for name, linkname in entries:
            info = tarfile.TarInfo(name)
            if linkname is None:
                data = name.encode()
                info.size = len(data)
                tf.addfile(info, io.BytesIO(data))
            elif linkname.startswith("sym:"):
                info.type = tarfile.SYMTYPE
                info.linkname = linkname.removeprefix("sym:")
                tf.addfile(info)
            else:
                info.type = tarfile.LNKTYPE
                info.linkname = linkname
                tf.addfile(info)
    return path


def _extract(
    path: Path,
    dest: Path,
    *,
    streaming: bool = False,
    **kwargs: Any,
) -> dict[str, ExtractionResult]:
    kwargs.setdefault("on_error", OnError.CONTINUE)
    if streaming:
        with open_archive(io.BytesIO(path.read_bytes()), streaming=True) as archive:
            report = archive.extract_all(dest, **{"on_blocked": "skip", **kwargs})
    else:
        with open_archive(path) as archive:
            report = archive.extract_all(dest, **{"on_blocked": "skip", **kwargs})
    return {result.member.name: result for result in report.results}


def _assert_refused(result: ExtractionResult, dest: Path) -> None:
    assert result.status is ExtractionStatus.BLOCKED, result.error
    assert isinstance(result.error, FilterRejectionError)
    assert result.error.message == _REFUSED
    assert not os.path.lexists(dest / result.member.name)


def _assert_refused_name(result: ExtractionResult) -> None:
    """Refused for its own name, not as a link to a refused member."""
    assert result.status is ExtractionStatus.BLOCKED, result.error
    assert isinstance(result.error, FilterRejectionError)
    assert result.error.message != _REFUSED


@_MODES
def test_a_hardlink_to_an_earlier_written_member_links_to_its_file(
    tmp_path: Path, streaming: bool
) -> None:
    path = _tar(tmp_path / "a.tar", [("a", None), ("hl", "a")])
    dest = tmp_path / "out"
    results = _extract(path, dest, streaming=streaming)
    assert results["hl"].status is ExtractionStatus.EXTRACTED, results["hl"].error
    assert (dest / "hl").read_bytes() == b"a"
    if os.name == "posix":
        assert os.path.samefile(dest / "a", dest / "hl")


@_MODES
def test_a_hardlink_to_a_later_member_still_fails(
    tmp_path: Path, streaming: bool
) -> None:
    path = _tar(tmp_path / "a.tar", [("hl", "a"), ("a", None)])
    dest = tmp_path / "out"
    results = _extract(path, dest, streaming=streaming)
    assert results["hl"].status is ExtractionStatus.FAILED
    assert isinstance(results["hl"].error, LinkTargetNotFoundError)
    assert results["a"].status is ExtractionStatus.EXTRACTED
    assert not os.path.lexists(dest / "hl")


@_MODES
@pytest.mark.parametrize(
    ("policy", "source"),
    [
        *((policy, "../x") for policy in ExtractionPolicy),
        *((policy, "d/../../x") for policy in ExtractionPolicy),
        (ExtractionPolicy.STRICT, "/x"),
    ],
    ids=lambda v: v.name if isinstance(v, ExtractionPolicy) else v,
)
def test_a_hardlink_to_a_refused_member_is_refused(
    tmp_path: Path, streaming: bool, policy: ExtractionPolicy, source: str
) -> None:
    """Before the rule, a link the target-string checks let through got the refused
    member's bytes from the second pass. Each link in a chain is refused."""
    path = _tar(tmp_path / "a.tar", [(source, None), ("hl", source), ("hl2", "hl")])
    dest = tmp_path / "out"
    results = _extract(path, dest, streaming=streaming, policy=policy)
    assert results[source].status is ExtractionStatus.BLOCKED
    _assert_refused(results["hl"], dest)
    _assert_refused(results["hl2"], dest)
    assert not (tmp_path / "x").exists()


@_MODES
def test_a_hardlink_to_an_excluded_refused_member_is_refused(
    tmp_path: Path, streaming: bool
) -> None:
    """A source the selector left out has no result; the policy's own checks on it
    as listed decide, through any number of links the selector also left out."""
    path = _tar(
        tmp_path / "a.tar", [("../x", None), ("h1", "../x"), ("h2", "h1"), ("ok", None)]
    )
    dest = tmp_path / "out"
    results = _extract(path, dest, streaming=streaming, members=["h2", "ok"])
    assert set(results) == {"h2", "ok"}
    _assert_refused(results["h2"], dest)
    assert results["ok"].status is ExtractionStatus.EXTRACTED


@_MODES
@_POLICIES
@pytest.mark.parametrize("members", [None, ["a", "h2"]], ids=["all", "no-middle"])
def test_a_hardlink_through_a_refused_middle_name_links_to_its_written_source(
    tmp_path: Path,
    streaming: bool,
    policy: ExtractionPolicy,
    members: list[str] | None,
) -> None:
    """``../h1`` is refused for its own name, but ``h2`` links against ``a``, the end
    of the chain, which this run wrote: the unsafe name is not used."""
    path = _tar(tmp_path / "a.tar", [("a", None), ("../h1", "a"), ("h2", "../h1")])
    dest = tmp_path / "out"
    results = _extract(path, dest, streaming=streaming, policy=policy, members=members)
    if members is None:
        _assert_refused_name(results["../h1"])
    assert results["h2"].status is ExtractionStatus.EXTRACTED, results["h2"].error
    assert (dest / "h2").read_bytes() == b"a"
    if os.name == "posix":
        assert os.path.samefile(dest / "a", dest / "h2")
    assert not (tmp_path / "h1").exists()


@pytest.mark.skipif(os.name == "nt", reason="needs POSIX symlinks")
@_MODES
def test_a_hardlink_to_a_refused_symlink_is_written_as_a_symlink(
    tmp_path: Path, streaming: bool
) -> None:
    """A hard link to a symlink is that symlink under another name: it copies no
    bytes, so the symlink checks decide, on the link's own name, not the refusal of
    the absolute ``/s`` it names."""
    path = _tar(tmp_path / "a.tar", [("t", None), ("/s", "sym:t"), ("hl", "/s")])
    dest = tmp_path / "out"
    results = _extract(path, dest, streaming=streaming, policy=ExtractionPolicy.STRICT)
    _assert_refused_name(results["/s"])
    assert results["hl"].status is ExtractionStatus.EXTRACTED, results["hl"].error
    assert os.readlink(dest / "hl") == "t"
    assert (dest / "hl").read_bytes() == b"t"


@pytest.mark.parametrize("symlink", ["/s", "s"], ids=["refused", "kept"])
@pytest.mark.parametrize("members", [None, ["t", "hl"]], ids=["all", "no-symlink"])
@pytest.mark.parametrize("listed", [True, False], ids=["listed", "fresh"])
def test_a_hardlink_to_a_targetless_symlink_fails_whether_or_not_it_was_refused(
    tmp_path: Path, symlink: str, members: list[str] | None, listed: bool
) -> None:
    """A symlink with no target (an empty ``linkname``) cannot be written as the
    link, and it copies no bytes, so a refusal of the symlink's own name does not
    refuse the link: the outcome is the same whether ``STRICT`` refuses the absolute
    ``/s`` or keeps ``s``. With the listing read first, the link's
    ``link_target_member`` is the symlink and the link fails as a link to a
    non-file; a fresh pass leaves it unset and the link is not found."""
    path = _tar(tmp_path / "a.tar", [("t", None), (symlink, "sym:"), ("hl", symlink)])
    dest = tmp_path / "out"
    with open_archive(path) as archive:
        if listed:
            archive.members()
        report = archive.extract_all(
            dest,
            policy=ExtractionPolicy.STRICT,
            members=members,
            on_error=OnError.CONTINUE,
            on_blocked="skip",
        )
    result = {r.member.name: r for r in report.results}["hl"]
    assert result.status is ExtractionStatus.FAILED, result.error
    if listed:
        assert type(result.error) is ExtractionError
        assert "is a symlink, not a regular file" in str(result.error)
    else:
        assert isinstance(result.error, LinkTargetNotFoundError)
    assert not os.path.lexists(dest / "hl")


@_MODES
@pytest.mark.parametrize(
    "members", [None, ["h"], ["m", "h"]], ids=["all", "only-h", "no-source"]
)
def test_a_refused_source_refuses_links_through_a_safe_middle_name(
    tmp_path: Path, streaming: bool, members: list[str] | None
) -> None:
    """The source ``../x`` is refused, selected or not, so every link whose chain
    ends there is refused, whatever the names in between."""
    path = _tar(tmp_path / "a.tar", [("../x", None), ("m", "../x"), ("h", "m")])
    dest = tmp_path / "out"
    results = _extract(path, dest, streaming=streaming, members=members)
    _assert_refused(results["h"], dest)
    if members is None or "m" in members:
        _assert_refused(results["m"], dest)
    assert not (tmp_path / "x").exists()


def test_a_hardlink_to_a_selector_excluded_member_is_materialized(
    tmp_path: Path,
) -> None:
    path = _tar(tmp_path / "a.tar", [("a", None), ("hl", "a")])
    dest = tmp_path / "out"
    results = _extract(path, dest, members=["hl"])
    assert results["hl"].status is ExtractionStatus.EXTRACTED, results["hl"].error
    assert (dest / "hl").read_bytes() == b"a"
    assert not os.path.lexists(dest / "a")


def test_a_hardlink_to_a_filter_excluded_member_is_materialized(
    tmp_path: Path,
) -> None:
    path = _tar(tmp_path / "a.tar", [("a", None), ("hl", "a")])
    dest = tmp_path / "out"
    results = _extract(path, dest, filter=lambda m: None if m.name == "a" else m)
    assert results["hl"].status is ExtractionStatus.EXTRACTED, results["hl"].error
    assert (dest / "hl").read_bytes() == b"a"
    assert not os.path.lexists(dest / "a")


def test_a_streaming_hardlink_to_an_excluded_member_still_fails(
    tmp_path: Path,
) -> None:
    path = _tar(tmp_path / "a.tar", [("a", None), ("hl", "a")])
    dest = tmp_path / "out"
    results = _extract(path, dest, streaming=True, members=["hl"])
    assert results["hl"].status is ExtractionStatus.FAILED
    assert type(results["hl"].error) is ExtractionError


def test_a_filter_that_rewrites_a_hardlink_target_changes_nothing(
    tmp_path: Path,
) -> None:
    """The link follows the stored target name, whatever the filter returns."""
    path = _tar(tmp_path / "a.tar", [("a", None), ("b", None), ("hl", "a")])

    def retarget(member: ArchiveMember) -> ArchiveMember:
        if member.type is MemberType.HARDLINK:
            return member.replace(link_target="../../elsewhere")
        return member

    dest = tmp_path / "out"
    results = _extract(path, dest, filter=retarget)
    assert results["hl"].status is ExtractionStatus.EXTRACTED, results["hl"].error
    assert (dest / "hl").read_bytes() == b"a"


def test_a_filter_that_makes_the_source_unsafe_refuses_its_links(
    tmp_path: Path,
) -> None:
    """The run's own outcome for the source decides, filter included."""
    path = _tar(tmp_path / "a.tar", [("a", None), ("hl", "a")])

    def unsafe(member: ArchiveMember) -> ArchiveMember:
        return member.replace(name="../a") if member.name == "a" else member

    dest = tmp_path / "out"
    results = _extract(path, dest, filter=unsafe)
    assert results["a"].status is ExtractionStatus.BLOCKED
    _assert_refused(results["hl"], dest)


@_MODES
def test_a_filter_that_rescues_the_source_lets_its_links_through(
    tmp_path: Path, streaming: bool
) -> None:
    path = _tar(tmp_path / "a.tar", [("../x", None), ("hl", "../x")])
    dest = tmp_path / "out"
    results = _extract(path, dest, streaming=streaming, filter=sanitize_names)
    assert results["../x"].status is ExtractionStatus.EXTRACTED
    assert results["hl"].status is ExtractionStatus.EXTRACTED, results["hl"].error
    assert (dest / "hl").read_bytes() == b"../x"
    assert (dest / "x").read_bytes() == b"../x"


# Target spellings that look like paths. Each names an earlier member of that name,
# and the link gets what that member gets: refused where the member is, linked where
# the member is written (re-rooted under STANDARD and TRUSTED).
_ROOTED = ["/abs", "\\foo", "C:/x"]


@_MODES
@_POLICIES
@pytest.mark.parametrize("target", [*_ROOTED, "C:x"])
def test_a_hardlink_with_a_rooted_or_drive_target_gets_what_its_member_gets(
    tmp_path: Path, streaming: bool, policy: ExtractionPolicy, target: str
) -> None:
    path = _tar(tmp_path / "a.tar", [(target, None), ("hl", target)])
    dest = tmp_path / "out"
    results = _extract(path, dest, streaming=streaming, policy=policy)
    member, link = results[target], results["hl"]
    # A drive-relative `C:x` has no root to drop, so it is refused at every policy.
    if policy is ExtractionPolicy.STRICT or target not in _ROOTED:
        assert member.status is ExtractionStatus.BLOCKED
        _assert_refused(link, dest)
    else:
        assert member.status is ExtractionStatus.EXTRACTED, member.error
        assert link.status is ExtractionStatus.EXTRACTED, link.error
        assert (dest / "hl").read_bytes() == target.encode()


@_POLICIES
@pytest.mark.parametrize("target", [*_ROOTED, "C:x"])
def test_a_hardlink_to_a_rescued_rooted_or_drive_member_extracts(
    tmp_path: Path, policy: ExtractionPolicy, target: str
) -> None:
    """``sanitize_names`` writes the member under a safe name, so its link extracts
    at every policy; the link's own target string plays no part."""
    path = _tar(tmp_path / "a.tar", [(target, None), ("hl", target)])
    dest = tmp_path / "out"
    results = _extract(path, dest, policy=policy, filter=sanitize_names)
    assert results[target].status is ExtractionStatus.EXTRACTED, results[target].error
    assert results["hl"].status is ExtractionStatus.EXTRACTED, results["hl"].error
    assert (dest / "hl").read_bytes() == target.encode()


@_POLICIES
@pytest.mark.parametrize("target", [*_ROOTED, "C:x", "../x"])
def test_a_hardlink_whose_target_names_no_member_is_not_found(
    tmp_path: Path, policy: ExtractionPolicy, target: str
) -> None:
    """No member, nothing to link to: a failure, not a refusal of the string."""
    path = _tar(tmp_path / "a.tar", [("a", None), ("hl", target)])
    dest = tmp_path / "out"
    results = _extract(path, dest, policy=policy)
    assert results["hl"].status is ExtractionStatus.FAILED
    assert isinstance(results["hl"].error, LinkTargetNotFoundError)


@pytest.mark.parametrize(
    "target", ["../../etc/passwd", "C:x", "\\foo", "//host/share", "/abs", "x\x00y"]
)
def test_check_universal_does_not_read_a_hardlink_target(
    tmp_path: Path, target: str
) -> None:
    member = ArchiveMember(
        type=MemberType.HARDLINK, name="hl", raw_name=b"hl", link_target=target
    )
    check_universal(member, tmp_path)
