"""Every exception class archivey exports survives ``pickle`` and ``copy``.

An error raised in a worker process crosses back to the caller pickled, so its type,
message and attributes must come through intact. (``ArchiveMember``'s hashing contract
lives in ``test_data_model.py``.)
"""

from __future__ import annotations

import copy
import inspect
import pickle

import pytest

import archivey
import archivey.exceptions as exceptions_module
from archivey.diagnostics import (
    Diagnostic,
    DiagnosticCode,
    EmptyArchiveContext,
)
from archivey.exceptions import (
    ArchiveyError,
    ArchiveyUsageError,
    DiagnosticRaisedError,
    LinkTargetNotFoundError,
    LinkTargetNotFoundReason,
)
from archivey.types import ArchiveFormat, ContainerFormat, StreamFormat


def _diagnostic() -> Diagnostic:
    return Diagnostic(
        occurrence_id="0" * 32,
        code=DiagnosticCode.EMPTY_ARCHIVE,
        message="Archive listed no members",
        context=EmptyArchiveContext(archive_name="x.zip", format="zip"),
    )


def _is_archivey_exception(value: object) -> bool:
    return isinstance(value, type) and issubclass(
        value, (ArchiveyError, ArchiveyUsageError)
    )


_EXCEPTION_CLASSES = sorted(
    {
        value
        for name in archivey.__all__
        if _is_archivey_exception(value := getattr(archivey, name))
    }
    # Unexported: the usage errors a wrong argument raises (DR-15). A caller can still
    # receive one from a worker process, so they must round-trip like the rest.
    | {exceptions_module._UsageTypeError, exceptions_module._UsageValueError},
    key=lambda cls: cls.__name__,
)


def _instance(cls: type[BaseException]) -> BaseException:
    # A control byte in the message, so a rebuild that re-escapes shows up.
    message = "bad \x1b[2K name"
    if issubclass(cls, ArchiveyUsageError):
        return cls(message)
    kwargs: dict[str, object] = {
        "archive_name": "a.zip",
        "member_name": "m\x1b",
        "link_target": "t",
        "source_format": ArchiveFormat.ZIP,
    }
    if issubclass(cls, DiagnosticRaisedError):
        kwargs["diagnostic"] = _diagnostic()
    else:
        kwargs["format_unconfirmed"] = True
    if issubclass(cls, LinkTargetNotFoundError):
        kwargs["reason"] = LinkTargetNotFoundReason.NOT_RECORDED
    return cls(message, **kwargs)


def test_sweep_covers_every_exception_class() -> None:
    # Exported classes plus the known unexported ones must be exactly the classes
    # ``archivey.exceptions`` defines, so a class added on either side joins the sweep.
    defined = {
        cls
        for _, cls in inspect.getmembers(exceptions_module, _is_archivey_exception)
        if cls.__module__ == exceptions_module.__name__
    }
    assert set(_EXCEPTION_CLASSES) == defined


@pytest.mark.parametrize("cls", _EXCEPTION_CLASSES, ids=lambda cls: cls.__name__)
@pytest.mark.parametrize(
    "roundtrip",
    [
        pytest.param(lambda exc: pickle.loads(pickle.dumps(exc)), id="pickle"),
        pytest.param(copy.copy, id="copy"),
        pytest.param(copy.deepcopy, id="deepcopy"),
    ],
)
def test_exception_roundtrips(cls: type[BaseException], roundtrip) -> None:
    original = _instance(cls)
    restored = roundtrip(original)
    assert type(restored) is cls
    assert restored.args == original.args
    assert str(restored) == str(original)
    assert vars(restored) == vars(original)


def test_diagnostic_raised_error_keeps_its_diagnostic_across_pickle() -> None:
    original = _instance(DiagnosticRaisedError)
    assert isinstance(original, DiagnosticRaisedError)
    restored = pickle.loads(pickle.dumps(original))
    assert restored.diagnostic == original.diagnostic
    assert restored.raw_message == original.raw_message == "bad \x1b[2K name"
    assert restored.message == original.message == "bad \\x1b[2K name"


def test_archive_format_from_strings_holds_enum_members() -> None:
    """A hand-built string pair behaves like the named format, not only compares equal.

    The code that decides behaviour tests ``container is ContainerFormat.RAW_STREAM``,
    and a bare ``str`` never is the member, so an unconverted pair took the other branch.
    """
    fmt = ArchiveFormat("raw_stream", "gz")
    assert fmt.container is ContainerFormat.RAW_STREAM
    assert fmt.stream is StreamFormat.GZIP
    assert fmt == ArchiveFormat.GZ
    assert fmt.file_extension() == "gz"


def test_archive_format_unknown_spelling_raises_at_construction() -> None:
    with pytest.raises(ArchiveyUsageError, match="ContainerFormat"):
        ArchiveFormat("nope", StreamFormat.GZIP)  # type: ignore[arg-type]
    with pytest.raises(ArchiveyUsageError, match="StreamFormat"):
        ArchiveFormat(ContainerFormat.RAW_STREAM, "nope")  # type: ignore[arg-type]


def test_archive_format_refuses_a_foreign_enum_as_container() -> None:
    with pytest.raises(ArchiveyUsageError, match="ContainerFormat"):
        ArchiveFormat(StreamFormat.GZIP, StreamFormat.GZIP)  # type: ignore[arg-type]
